// This file is part of the uutils coreutils package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

// spell-checker:ignore (ToDO) ugoa cmode

use crate::parse::parse;
use crate::settings::Settings;
use clap::Command;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
#[cfg(not(windows))]
use uucore::error::FromIo;
use uucore::error::{UResult, USimpleError};
#[cfg(not(windows))]
use uucore::mode;
use uucore::show_if_err;
use uucore::{display::Quotable, fs::dir_strip_dot_for_creation};

static DEFAULT_PERM: u32 = 0o777;

mod parse;
mod settings;

#[cfg(windows)]
fn get_mode(_matches: &ArgMatches, _mode_had_minus_prefix: bool) -> Result<u32, String> {
    Ok(DEFAULT_PERM)
}

#[cfg(not(windows))]
fn get_mode(settings: &Settings) -> Result<u32, String> {
    let mut new_mode = DEFAULT_PERM;

    if let Some(m) = &settings.mode {
        for mode in m.split(',') {
            if mode.chars().any(|c| c.is_ascii_digit()) {
                new_mode = mode::parse_numeric(new_mode, m, true)?;
            } else {
                new_mode = mode::parse_symbolic(new_mode, mode, mode::get_umask(), true)?;
            }
        }
        Ok(new_mode)
    } else {
        // If no mode argument is specified return the mode derived from umask
        Ok(!mode::get_umask() & 0o0777)
    }
}

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let (settings, dirs) = parse(args)?;

    // Linux-specific options, not implemented
    // opts.optflag("Z", "context", "set SELinux security context" +
    // " of each created directory to CTX"),

    match get_mode(&settings) {
        Ok(mode) => exec(dirs, &settings, mode),
        Err(f) => Err(USimpleError::new(1, f)),
    }
}

pub fn uu_app() -> Command {
    Command::new(uucore::util_name())
}

/// Create the list of new directories
fn exec(dirs: Vec<OsString>, settings: &Settings, mode: u32) -> UResult<()> {
    for dir in dirs {
        let path_buf = PathBuf::from(dir);
        let path = path_buf.as_path();

        show_if_err!(mkdir(path, settings, mode));
    }
    Ok(())
}

/// Create directory at a given `path`.
///
/// ## Options
///
/// * `recursive` --- create parent directories for the `path`, if they do not
///     exist.
/// * `mode` --- file mode for the directories (not implemented on windows).
/// * `verbose` --- print a message for each printed directory.
///
/// ## Trailing dot
///
/// To match the GNU behavior, a path with the last directory being a single dot
/// (like `some/path/to/.`) is created (with the dot stripped).
pub fn mkdir(path: &Path, settings: &Settings, mode: u32) -> UResult<()> {
    // Special case to match GNU's behavior:
    // mkdir -p foo/. should work and just create foo/
    // std::fs::create_dir("foo/."); fails in pure Rust
    let path_buf = dir_strip_dot_for_creation(path);
    let path = path_buf.as_path();

    create_dir(path, settings, false)?;
    chmod(path, mode)
}

#[cfg(any(unix, target_os = "redox"))]
fn chmod(path: &Path, mode: u32) -> UResult<()> {
    use std::fs::{set_permissions, Permissions};
    use std::os::unix::fs::PermissionsExt;

    let mode = Permissions::from_mode(mode);

    set_permissions(path, mode)
        .map_err_context(|| format!("cannot set permissions {}", path.quote()))
}

#[cfg(windows)]
fn chmod(_path: &Path, _mode: u32) -> UResult<()> {
    // chmod on Windows only sets the readonly flag, which isn't even honored on directories
    Ok(())
}

// `is_parent` argument is not used on windows
#[allow(unused_variables)]
fn create_dir(path: &Path, settings: &Settings, is_parent: bool) -> UResult<()> {
    if path.exists() && !settings.parents {
        return Err(USimpleError::new(
            1,
            format!("{}: File exists", path.display()),
        ));
    }
    if path == Path::new("") {
        return Ok(());
    }

    if settings.parents {
        match path.parent() {
            Some(p) => create_dir(p, settings, true)?,
            None => {
                USimpleError::new(1, "failed to create whole tree");
            }
        }
    }
    match std::fs::create_dir(path) {
        Ok(()) => {
            if settings.verbose {
                println!(
                    "{}: created directory {}",
                    uucore::util_name(),
                    path.quote()
                );
            }
            #[cfg(not(windows))]
            if is_parent {
                // directories created by -p have permission bits set to '=rwx,u+wx',
                // which is umask modified by 'u+wx'
                chmod(path, (!mode::get_umask() & 0o0777) | 0o0300)?;
            }
            Ok(())
        }
        Err(_) if path.is_dir() => Ok(()),
        Err(e) => Err(e.into()),
    }
}
