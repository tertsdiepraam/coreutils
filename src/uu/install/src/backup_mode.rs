use uutils_args::Value;

/// Available backup modes.
///
/// The mapping of the backup modes to the CLI arguments is annotated on the
/// enum variants.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Value)]
pub enum BackupMode {
    /// Argument 'none', 'off'
    #[value("none", "off")]
    None,
    /// Argument 'simple', 'never'
    #[value("simple", "never")]
    Simple,
    /// Argument 'numbered', 't'
    #[value("numbered", "t")]
    Numbered,
    /// Argument 'existing', 'nil'
    #[value("existing", "nil")]
    Existing,
}

// TODO: remove this conversion entirely by moving this to uu_core
#[allow(clippy::from_over_into)]
impl Into<uucore::backup_control::BackupMode> for BackupMode {
    fn into(self) -> uucore::backup_control::BackupMode {
        match self {
            Self::None => uucore::backup_control::BackupMode::NoBackup,
            Self::Simple => uucore::backup_control::BackupMode::SimpleBackup,
            Self::Numbered => uucore::backup_control::BackupMode::NumberedBackup,
            Self::Existing => uucore::backup_control::BackupMode::ExistingBackup,
        }
    }
}
