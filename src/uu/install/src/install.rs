// This file is part of the uutils coreutils package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

// spell-checker:ignore (ToDO) rwxr sourcepath targetpath Isnt uioerror

mod backup_mode;
mod config;
mod error;
mod mode;
mod parse;

use file_diff::diff;
use filetime::{set_file_times, FileTime};
use uucore::display::Quotable;
use uucore::error::{FromIo, UResult, UUsageError};
use uucore::fs::dir_strip_dot_for_creation;
use uucore::perms::{wrap_chown, Verbosity, VerbosityLevel};
use uucore::{backup_control, show, show_error, show_if_err};

use crate::config::Settings;
use crate::parse::{parse, parse_gid, parse_uid};
use clap::Command;
use config::MainFunction;
use error::InstallError;
use libc::{getegid, geteuid};
use std::fs;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::prelude::OsStrExt;
use std::path::{Path, PathBuf, MAIN_SEPARATOR};
use std::process;

pub fn uu_app() -> Command {
    Command::new("install")
}

/// Main install utility function, called from main.rs.
///
/// Returns a program return code.
///
#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let (settings, paths) = parse(args)?;

    if settings.preserve_timestamps && settings.compare {
        return Err(
            InstallError::MutuallyExclusive("--compare (-C)", "--preserve-timestamps").into(),
        );
    }
    if settings.strip && settings.compare {
        return Err(InstallError::MutuallyExclusive("--compare (-C)", "--strip").into());
    }

    match settings.main_function {
        MainFunction::Directory => directory(&paths, &settings),
        MainFunction::Standard => standard(paths, &settings),
    }
}

/// Creates directories.
///
/// GNU man pages describe this functionality as creating 'all components of
/// the specified directories'.
///
/// Returns a Result type with the Err variant containing the error message.
///
fn directory(paths: &[PathBuf], b: &Settings) -> UResult<()> {
    if paths.is_empty() {
        Err(InstallError::DirNeedsArg().into())
    } else {
        for path in paths.iter().map(Path::new) {
            // if the path already exist, don't try to create it again
            if !path.exists() {
                // Special case to match GNU's behavior:
                // install -d foo/. should work and just create foo/
                // std::fs::create_dir("foo/."); fails in pure Rust
                // See also mkdir.rs for another occurrence of this
                let path_to_create = dir_strip_dot_for_creation(path);
                // Differently than the primary functionality
                // (MainFunction::Standard), the directory functionality should
                // create all ancestors (or components) of a directory
                // regardless of the presence of the "-D" flag.
                //
                // NOTE: the GNU "install" sets the expected mode only for the
                // target directory. All created ancestor directories will have
                // the default mode. Hence it is safe to use fs::create_dir_all
                // and then only modify the target's dir mode.
                if let Err(e) = fs::create_dir_all(path_to_create.as_path())
                    .map_err_context(|| path_to_create.as_path().maybe_quote().to_string())
                {
                    show!(e);
                    continue;
                }

                if b.verbose {
                    println!("creating directory {}", path_to_create.quote());
                }
            }

            if mode::chmod(path, b.mode).is_err() {
                // Error messages are printed by the mode::chmod function!
                uucore::error::set_exit_code(1);
                continue;
            }

            show_if_err!(chown_optional_user_group(path, b));
        }
        // If the exit code was set, or show! has been called at least once
        // (which sets the exit code as well), function execution will end after
        // this return.
        Ok(())
    }
}

/// Test if the path is a new file path that can be
/// created immediately
fn is_new_file_path(path: &Path) -> bool {
    !path.exists()
        && (path.parent().map(Path::is_dir).unwrap_or(true)
            || path.parent().unwrap().as_os_str().is_empty()) // In case of a simple file
}

/// Test if the path is an existing directory or ends with a trailing separator.
///
/// Returns true, if one of the conditions above is met; else false.
///
#[cfg(unix)]
fn is_potential_directory_path(path: &Path) -> bool {
    let separator = MAIN_SEPARATOR as u8;
    path.as_os_str().as_bytes().last() == Some(&separator) || path.is_dir()
}

#[cfg(not(unix))]
fn is_potential_directory_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.ends_with(MAIN_SEPARATOR) || path_str.ends_with('/') || path.is_dir()
}

/// Perform an install, given a list of paths and behavior.
///
/// Returns a Result type with the Err variant containing the error message.
///
#[allow(clippy::cognitive_complexity)]
fn standard(mut paths: Vec<PathBuf>, b: &Settings) -> UResult<()> {
    // first check that paths contains at least one element
    if paths.is_empty() {
        return Err(UUsageError::new(1, "missing file operand"));
    }

    // get the target from either "-t foo" param or from the last given paths argument
    let target: PathBuf = if let Some(path) = &b.target_dir {
        path.into()
    } else {
        let last_path: PathBuf = paths.pop().unwrap();

        // paths has to contain more elements
        if paths.is_empty() {
            return Err(UUsageError::new(
                1,
                format!(
                    "missing destination file operand after '{}'",
                    last_path.to_str().unwrap()
                ),
            ));
        }

        last_path
    };

    let sources = &paths.iter().map(PathBuf::from).collect::<Vec<_>>();

    if b.create_leading {
        // if -t is used in combination with -D, create whole target because it does not include filename
        let to_create: Option<&Path> = if b.target_dir.is_some() {
            Some(target.as_path())
        // if source and target are filenames used in combination with -D, create target's parent
        } else if !(sources.len() > 1 || is_potential_directory_path(&target)) {
            target.parent()
        } else {
            None
        };

        if let Some(to_create) = to_create {
            if !to_create.exists() {
                if b.verbose {
                    let mut result = PathBuf::new();
                    // When creating directories with -Dv, show directory creations step by step
                    for part in to_create.components() {
                        result.push(part.as_os_str());
                        if !result.is_dir() {
                            // Don't display when the directory already exists
                            println!("install: creating directory {}", result.quote());
                        }
                    }
                }

                if let Err(e) = fs::create_dir_all(to_create) {
                    return Err(InstallError::CreateDirFailed(to_create.to_path_buf(), e).into());
                }
            }
        }
    }

    if sources.len() > 1 || is_potential_directory_path(&target) {
        copy_files_into_dir(sources, &target, b)
    } else {
        let source = sources.first().unwrap();

        if source.is_dir() {
            return Err(InstallError::OmittingDirectory(source.clone()).into());
        }

        if target.is_file() || is_new_file_path(&target) {
            copy(source, &target, b)
        } else {
            Err(InstallError::InvalidTarget(target).into())
        }
    }
}

/// Copy some files into a directory.
///
/// Prints verbose information and error messages.
/// Returns a Result type with the Err variant containing the error message.
///
/// # Parameters
///
/// _files_ must all exist as non-directories.
/// _target_dir_ must be a directory.
///
fn copy_files_into_dir(files: &[PathBuf], target_dir: &Path, b: &Settings) -> UResult<()> {
    if !target_dir.is_dir() {
        return Err(InstallError::TargetDirIsntDir(target_dir.to_path_buf()).into());
    }
    for sourcepath in files {
        if let Err(err) = sourcepath
            .metadata()
            .map_err_context(|| format!("cannot stat {}", sourcepath.quote()))
        {
            show!(err);
            continue;
        }

        if sourcepath.is_dir() {
            let err = InstallError::OmittingDirectory(sourcepath.clone());
            show!(err);
            continue;
        }

        let mut targetpath = target_dir.to_path_buf();
        let filename = sourcepath.components().last().unwrap();
        targetpath.push(filename);

        show_if_err!(copy(sourcepath, &targetpath, b));
    }
    // If the exit code was set, or show! has been called at least once
    // (which sets the exit code as well), function execution will end after
    // this return.
    Ok(())
}

/// Handle incomplete user/group parings for chown.
///
/// Returns a Result type with the Err variant containing the error message.
///
/// # Parameters
///
/// _path_ must exist.
///
/// # Errors
///
/// If the owner or group are invalid or copy system call fails, we print a verbose error and
/// return an empty error value.
///
fn chown_optional_user_group(path: &Path, b: &Settings) -> UResult<()> {
    if b.owner_id.is_some() || b.group_id.is_some() {
        let meta = match fs::metadata(path) {
            Ok(meta) => meta,
            Err(e) => return Err(InstallError::MetadataFailed(e).into()),
        };

        // GNU coreutils doesn't print chown operations during install with verbose flag.
        let verbosity = Verbosity {
            groups_only: b.owner_id.is_none(),
            level: VerbosityLevel::Normal,
        };

        match wrap_chown(
            path,
            &meta,
            b.owner_id.as_deref().map(parse_uid).transpose()?,
            b.group_id.as_deref().map(parse_gid).transpose()?,
            false,
            verbosity,
        ) {
            Ok(msg) if b.verbose && !msg.is_empty() => println!("chown: {msg}"),
            Ok(_) => {}
            Err(e) => return Err(InstallError::ChownFailed(path.to_path_buf(), e).into()),
        }
    }

    Ok(())
}

/// Perform backup before overwriting.
///
/// # Parameters
///
/// * `to` - The destination file path.
/// * `b` - The behavior configuration.
///
/// # Returns
///
/// Returns an Option containing the backup path, or None if backup is not needed.
///
fn perform_backup(to: &Path, b: &Settings) -> UResult<Option<PathBuf>> {
    if to.exists() {
        if b.verbose {
            println!("removed {}", to.quote());
        }
        let backup_path = backup_control::get_backup_path(b.backup_mode.into(), to, &b.suffix);
        if let Some(ref backup_path) = backup_path {
            // TODO!!
            if let Err(err) = fs::rename(to, backup_path) {
                return Err(
                    InstallError::BackupFailed(to.to_path_buf(), backup_path.clone(), err).into(),
                );
            }
        }
        Ok(backup_path)
    } else {
        Ok(None)
    }
}

/// Copy a file from one path to another.
///
/// # Parameters
///
/// * `from` - The source file path.
/// * `to` - The destination file path.
///
/// # Returns
///
/// Returns an empty Result or an error in case of failure.
///
fn copy_file(from: &Path, to: &Path) -> UResult<()> {
    if from.as_os_str() == "/dev/null" {
        /* workaround a limitation of fs::copy
         * https://github.com/rust-lang/rust/issues/79390
         */
        if let Err(err) = File::create(to) {
            return Err(
                InstallError::InstallFailed(from.to_path_buf(), to.to_path_buf(), err).into(),
            );
        }
    } else if let Err(err) = fs::copy(from, to) {
        return Err(InstallError::InstallFailed(from.to_path_buf(), to.to_path_buf(), err).into());
    }
    Ok(())
}

/// Strip a file using an external program.
///
/// # Parameters
///
/// * `to` - The destination file path.
/// * `b` - The behavior configuration.
///
/// # Returns
///
/// Returns an empty Result or an error in case of failure.
///
fn strip_file(to: &Path, b: &Settings) -> UResult<()> {
    match process::Command::new(&b.strip_program).arg(to).output() {
        Ok(o) => {
            if !o.status.success() {
                // Follow GNU's behavior: if strip fails, removes the target
                let _ = fs::remove_file(to);
                return Err(InstallError::StripProgramFailed(
                    String::from_utf8(o.stderr).unwrap_or_default(),
                )
                .into());
            }
        }
        Err(e) => {
            // Follow GNU's behavior: if strip fails, removes the target
            let _ = fs::remove_file(to);
            return Err(InstallError::StripProgramFailed(e.to_string()).into());
        }
    }
    Ok(())
}

/// Set ownership and permissions on the destination file.
///
/// # Parameters
///
/// * `to` - The destination file path.
/// * `b` - The behavior configuration.
///
/// # Returns
///
/// Returns an empty Result or an error in case of failure.
///
fn set_ownership_and_permissions(to: &Path, b: &Settings) -> UResult<()> {
    // Silent the warning as we want to the error message
    #[allow(clippy::question_mark)]
    if mode::chmod(to, b.mode).is_err() {
        return Err(InstallError::ChmodFailed(to.to_path_buf()).into());
    }

    chown_optional_user_group(to, b)?;

    Ok(())
}

/// Preserve timestamps on the destination file.
///
/// # Parameters
///
/// * `from` - The source file path.
/// * `to` - The destination file path.
///
/// # Returns
///
/// Returns an empty Result or an error in case of failure.
///
fn preserve_timestamps(from: &Path, to: &Path) -> UResult<()> {
    let meta = match fs::metadata(from) {
        Ok(meta) => meta,
        Err(e) => return Err(InstallError::MetadataFailed(e).into()),
    };

    let modified_time = FileTime::from_last_modification_time(&meta);
    let accessed_time = FileTime::from_last_access_time(&meta);

    match set_file_times(to, accessed_time, modified_time) {
        Ok(_) => Ok(()),
        Err(e) => {
            show_error!("{}", e);
            Ok(())
        }
    }
}

/// Copy one file to a new location, changing metadata.
///
/// Returns a Result type with the Err variant containing the error message.
///
/// # Parameters
///
/// _from_ must exist as a non-directory.
/// _to_ must be a non-existent file, whose parent directory exists.
///
/// # Errors
///
/// If the copy system call fails, we print a verbose error and return an empty error value.
///
fn copy(from: &Path, to: &Path, b: &Settings) -> UResult<()> {
    if b.compare && !need_copy(from, to, b)? {
        return Ok(());
    }
    // Declare the path here as we may need it for the verbose output below.
    let backup_path = perform_backup(to, b)?;

    copy_file(from, to)?;

    #[cfg(not(windows))]
    if b.strip {
        strip_file(to, b)?;
    }

    set_ownership_and_permissions(to, b)?;

    if b.preserve_timestamps {
        preserve_timestamps(from, to)?;
    }

    if b.verbose {
        print!("{} -> {}", from.quote(), to.quote());
        match backup_path {
            Some(path) => println!(" (backup: {})", path.quote()),
            None => println!(),
        }
    }

    Ok(())
}

/// Return true if a file is necessary to copy. This is the case when:
///
/// - _from_ or _to_ is nonexistent;
/// - either file has a sticky bit or set\[ug\]id bit, or the user specified one;
/// - either file isn't a regular file;
/// - the sizes of _from_ and _to_ differ;
/// - _to_'s owner differs from intended; or
/// - the contents of _from_ and _to_ differ.
///
/// # Parameters
///
/// _from_ and _to_, if existent, must be non-directories.
///
/// # Errors
///
/// Crashes the program if a nonexistent owner or group is specified in _b_.
///
fn need_copy(from: &Path, to: &Path, b: &Settings) -> UResult<bool> {
    let from_meta = match fs::metadata(from) {
        Ok(meta) => meta,
        Err(_) => return Ok(true),
    };
    let to_meta = match fs::metadata(to) {
        Ok(meta) => meta,
        Err(_) => return Ok(true),
    };

    // setuid || setgid || sticky
    let extra_mode: u32 = 0o7000;
    // setuid || setgid || sticky || permissions
    let all_modes: u32 = 0o7777;

    if b.mode & extra_mode != 0
        || from_meta.mode() & extra_mode != 0
        || to_meta.mode() & extra_mode != 0
    {
        return Ok(true);
    }
    if b.mode != to_meta.mode() & all_modes {
        return Ok(true);
    }

    if !from_meta.is_file() || !to_meta.is_file() {
        return Ok(true);
    }

    if from_meta.len() != to_meta.len() {
        return Ok(true);
    }

    // TODO: if -P (#1809) and from/to contexts mismatch, return true.

    if let Some(owner_id) = b.owner_id.as_deref().map(parse_uid).transpose()? {
        if owner_id != to_meta.uid() {
            return Ok(true);
        }
    } else if let Some(group_id) = b.group_id.as_deref().map(parse_gid).transpose()? {
        if group_id != to_meta.gid() {
            return Ok(true);
        }
    } else {
        #[cfg(not(target_os = "windows"))]
        unsafe {
            if to_meta.uid() != geteuid() || to_meta.gid() != getegid() {
                return Ok(true);
            }
        }
    }

    if !diff(from.to_str().unwrap(), to.to_str().unwrap()) {
        return Ok(true);
    }

    Ok(false)
}
