use uucore::line_ending::LineEnding;

pub struct Settings {
    pub display_name: bool,   // --name
    pub human_readable: bool, // --human-readable

    pub user: bool,     // --user
    pub group: bool,    // --group
    pub groups: bool,   // --groups
    pub real: bool,     // --real
    pub zero: bool,     // --zero
    pub context: bool,  // --context
    pub password: bool, // --password

    pub audit: bool,

    pub selinux_supported: bool,
    // The behavior for calling GNU's `id` and calling GNU's `id $USER` is similar but different.
    // * The SELinux context is only displayed without a specified user.
    // * The `getgroups` system call is only used without a specified user, this causes
    //   the order of the displayed groups to be different between `id` and `id $USER`.
    //
    // Example:
    // $ strace -e getgroups id -G $USER
    // 1000 10 975 968
    // +++ exited with 0 +++
    // $ strace -e getgroups id -G
    // getgroups(0, NULL)                      = 4
    // getgroups(4, [10, 968, 975, 1000])      = 4
    // 1000 10 968 975
    // +++ exited with 0 +++
    pub user_specified: bool,
}

impl Settings {
    /// "default format" is when none of '-ugG' was used
    pub fn default_format(&self) -> bool {
        !(self.user || self.group || self.groups)
    }

    pub fn delimiter(&self) -> String {
        if self.zero {
            '\0'.to_string()
        } else {
            ' '.to_string()
        }
    }

    pub fn line_ending(&self) -> LineEnding {
        LineEnding::from_zero_flag(self.zero)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            display_name: false,
            human_readable: false,
            user: false,
            group: false,
            groups: false,
            real: false,
            zero: false,
            context: false,
            password: false,
            audit: false,
            selinux_supported: {
                #[cfg(feature = "selinux")]
                {
                    selinux::kernel_support() != selinux::KernelSupport::Unsupported
                }
                #[cfg(not(feature = "selinux"))]
                {
                    false
                }
            },
            user_specified: false,
        }
    }
}
