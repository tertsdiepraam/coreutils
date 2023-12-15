use crate::settings::Settings;
use std::ffi::OsString;
use uutils_args::{Arguments, Options};

#[derive(Arguments)]
#[arguments(file = "id.md")]
enum Arg {
    /// Display the process audit user ID and other process audit properties,
    /// which requires privilege (not available on Linux).
    #[arg("-A", "--audit")]
    Audit,

    /// Display only the effective user ID as a number.
    #[arg("-u", "--user")]
    User,

    /// Display only the effective group ID as a number.
    #[arg("-g", "--group")]
    Group,

    /// Display only the different group IDs as white-space separated numbers, in no particular order.
    #[arg("-G", "--groups")]
    Groups,

    /// Make the output human-readable. Each display is on a separate line.
    #[arg("-P", "--human-readable")]
    HumanReadable,

    /// Display the name of the user or group ID for the -G, -g and -u options instead of the number.
    /// If any of the ID numbers cannot be mapped into names, the number will be displayed as usual.
    #[arg("-n", "--name")]
    Name,

    /// Display the id as a password file entry.
    #[arg("-P", "--password")]
    Password,

    /// Display the real ID for the -G, -g and -u options instead of the effective ID.
    #[arg("-r", "--real")]
    Real,

    /// Delimit entries with NUL characters, not whitespace;
    /// not permitted in default format
    #[arg("-z", "--zero")]
    Zero,

    /// print only the security context of the process.
    ///
    /// Only enabled when compiled with selinux support.
    #[arg("-Z", "--context")]
    Context,
}

impl Options<Arg> for Settings {
    fn apply(&mut self, arg: Arg) {
        match arg {
            Arg::Audit => self.audit = true,
            Arg::User => self.user = true,
            Arg::Group => self.group = true,
            Arg::Groups => self.groups = true,
            Arg::HumanReadable => self.human_readable = true,
            Arg::Name => self.display_name = true,
            Arg::Password => self.password = true,
            Arg::Real => self.real = true,
            Arg::Zero => self.zero = true,
            Arg::Context => self.context = true,
        }
    }
}

pub fn parse(
    args: impl IntoIterator<Item = OsString> + 'static,
) -> Result<(Settings, Vec<OsString>), uutils_args::Error> {
    Settings::default().try_parse(args)
}
