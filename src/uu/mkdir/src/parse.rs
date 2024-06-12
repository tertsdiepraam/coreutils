use crate::settings::Settings;
use std::ffi::OsString;
use uutils_args::{Arguments, Options};

#[derive(Arguments)]
#[arguments(file = "mkdir.md")]
enum Arg {
    #[arg("-m MODE", "--mode=MODE")]
    Mode(String),

    /// Print a message for each printed directory
    #[arg("-v", "--verbose")]
    Verbose,

    /// Make parent directories as needed
    #[arg("-p", "--parents")]
    Parents,
}

impl Options<Arg> for Settings {
    fn apply(&mut self, arg: Arg) {
        match arg {
            Arg::Verbose => self.verbose = true,
            Arg::Parents => self.parents = true,
            Arg::Mode(m) => self.mode = Some(m),
        }
    }
}

pub fn parse(
    args: impl IntoIterator<Item = OsString> + 'static,
) -> Result<(Settings, Vec<OsString>), uutils_args::Error> {
    Settings::default().try_parse(args)
}
