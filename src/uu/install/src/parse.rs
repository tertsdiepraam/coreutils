use crate::backup_mode::BackupMode;
use crate::config::{MainFunction, Settings};
use crate::error::InstallError;
use crate::mode;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use uucore::entries::{grp2gid, usr2uid};
use uutils_args::{Arguments, Options, Value, ValueResult};

pub struct Mode(u32);
impl Value for Mode {
    fn from_value(mode: &OsStr) -> ValueResult<Self> {
        let Some(mode) = mode.to_str() else {
            return Err(InstallError::InvalidMode(mode.to_string_lossy().to_string()).into());
        };

        // TODO: remove considering_dir parameter (@tertsdiepraam)
        match mode::parse(mode, false) {
            Ok(m) => Ok(Self(m)),
            Err(_) => Err(InstallError::InvalidMode(mode.to_string()).into()),
        }
    }
}

pub fn parse_gid(group: &str) -> Result<u32, InstallError> {
    match grp2gid(group) {
        Ok(g) => Ok(g),
        Err(_) => {
            if let Ok(i) = group.parse() {
                return Ok(i);
            }
            Err(InstallError::InvalidGroup(group.to_string()))
        }
    }
}

pub fn parse_uid(user: &str) -> Result<u32, InstallError> {
    match usr2uid(user) {
        Ok(u) => Ok(u),
        Err(_) => {
            if let Ok(i) = user.parse() {
                return Ok(i);
            }

            Err(InstallError::InvalidUser(user.to_string()))
        }
    }
}

#[derive(Arguments)]
#[arguments(file = "install.md")]
enum Arg {
    /// make a backup of each existing destination file
    #[arg("-b", "--backup[=CONTROL]", value=BackupMode::Existing)]
    Backup(BackupMode),

    /// (ignored)
    #[arg("-c")]
    C,

    /// compare each pair of source and destination files, and in some cases, do not modify the destination at all
    #[arg("-C", "--compare")]
    Compare,

    /// treat all arguments as directory names. create all components of the specified directories
    #[arg("-d", "--directory")]
    Directory,

    /// create all leading components of DEST except the last, then copy SOURCE to DEST
    #[arg("-D")]
    CreateLeading,

    /// unsupported (TODO) (implies verbose)
    #[arg("--debug")]
    Debug,

    /// set group ownership, instead of process's current group
    #[arg("-g GROUP", "--group=GROUP")]
    Group(String),

    /// set group ownership, instead of process's current group
    #[arg("-m MODE", "--mode=MODE", value = Mode(0o755))]
    Mode(Mode),

    /// set ownership (super-user only)
    #[arg("-o OWNER", "--owner=OWNER")]
    Owner(String),

    /// apply access/modification times of SOURCE files to corresponding destination files
    #[arg("-p", "--preserve-timestamps")]
    PreserveTimestamps,

    /// strip symbol tables (no action Windows)
    #[arg("-s", "--strip")]
    Strip,

    /// program used to strip binaries (no action Windows)
    #[arg("--strip-program=PROGRAM")]
    StripProgram(PathBuf),

    /// program used to strip binaries (no action Windows)
    #[arg("-S SUFFIX", "--suffix=SUFFIX")]
    Suffix(String),

    /// move all SOURCE arguments into DIRECTORY
    #[arg("-t DIRECTORY", "--target-directory=DIRECTORY")]
    TargetDirectory(PathBuf),

    /// (unimplemented) treat DEST as a normal file
    #[arg("-T", "--no-target-directory")]
    NoTargetDirectory,

    /// explain what is being done
    #[arg("-v", "--verbose")]
    Verbose,

    /// "(unimplemented) preserve security context"
    #[arg("--preserve-context")]
    PreserveContext,

    /// (unimplemented) set security context of files and directories
    #[arg("-Z", "--context[=CTX]", value=None)]
    Context(Option<OsString>),
}

impl Options<Arg> for Settings {
    fn apply(&mut self, arg: Arg) {
        match arg {
            Arg::Backup(b) => self.backup_mode = b,
            Arg::C => {}
            Arg::Compare => self.compare = true,
            Arg::Directory => self.main_function = MainFunction::Directory,
            Arg::CreateLeading => self.create_leading = true,
            Arg::Debug => {
                self.verbose = true;
                unimplemented!()
            }
            Arg::Group(g) => self.group_id = Some(g),
            Arg::Mode(m) => self.mode = m.0,
            Arg::Owner(u) => self.owner_id = Some(u),
            Arg::PreserveTimestamps => self.preserve_timestamps = true,
            Arg::Strip => self.strip = true,
            Arg::StripProgram(p) => self.strip_program = p,
            Arg::Suffix(s) => self.suffix = s,
            Arg::TargetDirectory(t) => self.target_dir = Some(t),
            Arg::NoTargetDirectory => unimplemented!(),
            Arg::Verbose => self.verbose = true,
            Arg::PreserveContext => unimplemented!(),
            Arg::Context(_) => unimplemented!(),
        }
    }
}

pub fn parse(
    args: impl IntoIterator<Item = OsString> + 'static,
) -> Result<(Settings, Vec<PathBuf>), uutils_args::Error> {
    let (s, operands) = Settings::default().try_parse(args)?;

    Ok((s, operands.into_iter().map(PathBuf::from).collect()))
}

#[cfg(test)]
mod tests {
    use crate::backup_mode::BackupMode;
    use crate::config::{MainFunction, Settings};
    use crate::parse::parse;
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn parse_strings(
        args: impl IntoIterator<Item = &'static str> + 'static,
    ) -> (Settings, Vec<PathBuf>) {
        parse(args.into_iter().map(OsString::from)).unwrap()
    }

    #[test]
    fn test_backup() {
        assert_eq!(
            parse_strings(["install", "-b", "a", "b"]).0,
            Settings {
                backup_mode: BackupMode::Existing,
                ..Default::default()
            }
        );
        assert_eq!(
            parse_strings(["install", "--backup", "a", "b"]).0,
            Settings {
                backup_mode: BackupMode::Existing,
                ..Default::default()
            }
        );
        assert_eq!(
            parse_strings(["install", "a", "b"]).0,
            Settings {
                backup_mode: BackupMode::None,
                ..Default::default()
            }
        );
        assert_eq!(
            parse_strings(["install", "--backup=existing", "a", "b"]).0,
            Settings {
                backup_mode: BackupMode::Existing,
                ..Default::default()
            }
        );
        assert_eq!(
            parse_strings(["install", "--backup=t", "a", "b"]).0,
            Settings {
                backup_mode: BackupMode::Numbered,
                ..Default::default()
            }
        );
    }

    #[test]
    pub fn test_c_ignored() {
        parse_strings("install -c a b".split(' '));
    }

    #[test]
    pub fn test_compare() {
        assert_eq!(
            parse_strings("install -C a b".split(' ')).0,
            Settings {
                compare: true,
                ..Default::default()
            }
        );
        assert_eq!(
            parse_strings("install --compare a b".split(' ')).0,
            Settings {
                compare: true,
                ..Default::default()
            }
        );
        assert_eq!(
            parse_strings("install a b".split(' ')).0,
            Settings {
                compare: false,
                ..Default::default()
            }
        );
    }

    #[test]
    pub fn test_directory() {
        assert_eq!(
            parse_strings("install -d a b".split(' ')).0,
            Settings {
                main_function: MainFunction::Directory,
                ..Default::default()
            }
        );
        assert_eq!(
            parse_strings("install --directory a b".split(' ')).0,
            Settings {
                main_function: MainFunction::Directory,
                ..Default::default()
            }
        );
        assert_eq!(
            parse_strings("install a b".split(' ')).0,
            Settings {
                main_function: MainFunction::Standard,
                ..Default::default()
            }
        );
    }

    #[test]
    pub fn test_create_leading() {
        assert_eq!(
            parse_strings("install -D a b".split(' ')).0,
            Settings {
                create_leading: true,
                ..Default::default()
            }
        );
        assert_eq!(
            parse_strings("install a b".split(' ')).0,
            Settings {
                create_leading: false,
                ..Default::default()
            }
        );
    }

    #[test]
    pub fn test_group() {
        assert_eq!(
            parse_strings("install a b".split(' ')).0,
            Settings {
                group_id: None,
                ..Default::default()
            }
        );
        assert_eq!(
            parse_strings("install -g 0 a b".split(' ')).0,
            Settings {
                group_id: Some("0".to_string()),
                ..Default::default()
            }
        );
        assert_eq!(
            parse_strings("install --group=10 a b".split(' ')).0,
            Settings {
                group_id: Some("10".to_string()),
                ..Default::default()
            }
        );
    }
}
