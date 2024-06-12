use crate::backup_mode::BackupMode;
use std::env;
use std::path::PathBuf;

#[allow(dead_code)]
#[derive(PartialEq, Debug)]
pub struct Settings {
    pub main_function: MainFunction,
    pub mode: u32,
    pub backup_mode: BackupMode,
    pub suffix: String,
    pub owner_id: Option<String>,
    pub group_id: Option<String>,
    pub verbose: bool,
    pub preserve_timestamps: bool,
    pub compare: bool,
    pub strip: bool,
    pub strip_program: PathBuf,
    pub create_leading: bool,
    pub target_dir: Option<PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            main_function: MainFunction::Standard,
            mode: 0o755,
            backup_mode: BackupMode::None,
            compare: false,
            strip: false,
            owner_id: None,
            group_id: None,
            strip_program: "strip".into(),

            /// TODO: put something like this in uu_core backup_control
            suffix: env::var("SIMPLE_BACKUP_SUFFIX").unwrap_or_else(|_| "~".to_owned()),
            verbose: false,
            preserve_timestamps: false,
            create_leading: false,
            target_dir: None,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum MainFunction {
    /// Create directories
    Directory,
    /// Install files to locations (primary functionality)
    Standard,
}
