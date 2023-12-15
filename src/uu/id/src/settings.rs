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
        }
    }
}
