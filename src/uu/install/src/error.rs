use std::error::Error;
use std::fmt::Display;
use std::path::PathBuf;
use uucore::display::Quotable;
use uucore::error::UError;
use uucore::error::UIoError;
use uucore::uio_error;

#[derive(Debug)]
pub enum InstallError {
    DirNeedsArg(),
    CreateDirFailed(PathBuf, std::io::Error),
    ChmodFailed(PathBuf),
    ChownFailed(PathBuf, String),
    InvalidTarget(PathBuf),
    TargetDirIsntDir(PathBuf),
    BackupFailed(PathBuf, PathBuf, std::io::Error),
    InstallFailed(PathBuf, PathBuf, std::io::Error),
    StripProgramFailed(String),
    MetadataFailed(std::io::Error),
    InvalidUser(String),
    InvalidGroup(String),
    InvalidMode(String),
    OmittingDirectory(PathBuf),
    MutuallyExclusive(&'static str, &'static str),
}

impl UError for InstallError {
    fn code(&self) -> i32 {
        1
    }

    fn usage(&self) -> bool {
        matches!(self, Self::MutuallyExclusive(_, _))
    }
}

impl Error for InstallError {}

impl Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirNeedsArg() => {
                write!(
                    f,
                    "{} with -d requires at least one argument.",
                    uucore::util_name()
                )
            }
            Self::CreateDirFailed(dir, e) => {
                Display::fmt(&uio_error!(e, "failed to create {}", dir.quote()), f)
            }
            Self::ChmodFailed(file) => write!(f, "failed to chmod {}", file.quote()),
            Self::ChownFailed(file, msg) => write!(f, "failed to chown {}: {}", file.quote(), msg),
            Self::InvalidTarget(target) => write!(
                f,
                "invalid target {}: No such file or directory",
                target.quote()
            ),
            Self::TargetDirIsntDir(target) => {
                write!(f, "target {} is not a directory", target.quote())
            }
            Self::BackupFailed(from, to, e) => Display::fmt(
                &uio_error!(e, "cannot backup {} to {}", from.quote(), to.quote()),
                f,
            ),
            Self::InstallFailed(from, to, e) => Display::fmt(
                &uio_error!(e, "cannot install {} to {}", from.quote(), to.quote()),
                f,
            ),
            Self::StripProgramFailed(msg) => write!(f, "strip program failed: {msg}"),
            Self::MetadataFailed(e) => Display::fmt(&uio_error!(e, ""), f),
            Self::InvalidUser(user) => write!(f, "invalid user: {}", user.quote()),
            Self::InvalidGroup(group) => write!(f, "invalid group: {}", group.quote()),
            Self::OmittingDirectory(dir) => write!(f, "omitting directory {}", dir.quote()),
            Self::InvalidMode(mode) => write!(f, "invalid mode {}", mode.quote()),
            Self::MutuallyExclusive(a, b) => {
                write!(f, "options {} and {} are mutually exclusive", a, b)
            }
        }
    }
}
