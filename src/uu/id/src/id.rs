// This file is part of the uutils coreutils package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

// spell-checker:ignore (ToDO) asid auditid auditinfo auid cstr egid emod euid getaudit getlogin gflag nflag pline rflag termid uflag gsflag zflag cflag

// README:
// This was originally based on BSD's `id`
// (noticeable in functionality, usage text, options text, etc.)
// and synced with:
//  http://ftp-archive.freebsd.org/mirror/FreeBSD-Archive/old-releases/i386/1.0-RELEASE/ports/shellutils/src/id.c
//  http://www.opensource.apple.com/source/shell_cmds/shell_cmds-118/id/id.c
//
// * This was partially rewritten in order for stdout/stderr/exit_code
//   to be conform with GNU coreutils (8.32) test suite for `id`.
//
// * This supports multiple users (a feature that was introduced in coreutils 8.31)
//
// * This passes GNU's coreutils Test suite (8.32)
//   for "tests/id/uid.sh" and "tests/id/zero/sh".
//
// * Option '--zero' does not exist for BSD's `id`, therefore '--zero' is only
//   allowed together with other options that are available on GNU's `id`.
//
// * Help text based on BSD's `id` manpage and GNU's `id` manpage.
//
// * This passes GNU's coreutils Test suite (8.32) for "tests/id/context.sh" if compiled with
//   `--features feat_selinux`. It should also pass "tests/id/no-context.sh", but that depends on
//   `uu_ls -Z` being implemented and therefore fails at the moment
//

use crate::libc::gid_t;
use crate::parse::parse;
use clap::Command;
use settings::Settings;
use std::ffi::CStr;
use uucore::display::Quotable;
use uucore::entries::{self, Group, Locate, Passwd};
use uucore::error::{set_exit_code, USimpleError};
use uucore::error::{UError, UResult};
pub use uucore::libc;
use uucore::libc::{getlogin, uid_t};
use uucore::process::{getegid, geteuid, getgid, getuid};
use uucore::show_error;

mod parse;
mod settings;

macro_rules! cstr2cow {
    ($v:expr) => {
        unsafe { CStr::from_ptr($v).to_string_lossy() }
    };
}

struct Ids {
    uid: u32,  // user id
    gid: u32,  // group id
    euid: u32, // effective uid
    egid: u32, // effective gid
}

fn check_settings(settings: &Settings, num_users_specified: usize) -> UResult<()> {
    if (settings.display_name || settings.real) && settings.default_format() && !settings.context {
        return Err(USimpleError::new(
            1,
            "cannot print only names or real IDs in default format",
        ));
    }
    if settings.zero && settings.default_format() && !settings.context {
        // NOTE: GNU test suite "id/zero.sh" needs this stderr output:
        return Err(USimpleError::new(
            1,
            "option --zero not permitted in default format",
        ));
    }
    if num_users_specified > 0 && settings.context {
        return Err(USimpleError::new(
            1,
            "cannot print security context when user specified",
        ));
    }

    if settings.user && settings.group {
        return Err(USimpleError::new(
            1,
            "--user (-u) conflicts with --group (-g)",
        ));
    }

    if settings.groups {
        for (name, set) in [
            ("--group (-g)", settings.group),
            ("--user (-u)", settings.user),
            ("--context (-Z)", settings.context),
            ("--human-readable (-P)", settings.human_readable),
            ("--password (-p)", settings.password),
            ("--audit (-A)", settings.audit),
        ] {
            if set {
                return Err(USimpleError::new(
                    1,
                    format!("--groups (-G) conflicts with {name}"),
                ));
            }
        }
    }

    if settings.audit {
        for (name, set) in [
            ("--group (-g)", settings.group),
            ("--user (-u)", settings.user),
            ("--human-readable (-P)", settings.human_readable),
            ("--password (-p)", settings.password),
            ("--groups (-G)", settings.groups),
            ("--zero (-z)", settings.zero),
        ] {
            if set {
                return Err(USimpleError::new(
                    1,
                    format!("--audit (-A) conflicts with {name}"),
                ));
            }
        }
    }

    if settings.context {
        for (name, set) in [
            ("--group (-g)", settings.group),
            ("--user (-u)", settings.user),
        ] {
            if set {
                return Err(USimpleError::new(
                    1,
                    format!("--context (-C) conflicts with {name}"),
                ));
            }
        }
    }

    Ok(())
}

fn handle_context(settings: &Settings) -> UResult<()> {
    if settings.selinux_supported {
        // print SElinux context and exit
        #[cfg(all(any(target_os = "linux", target_os = "android"), feature = "selinux"))]
        if let Ok(context) = selinux::SecurityContext::current(false) {
            let bytes = context.as_bytes();
            print!(
                "{}{}",
                String::from_utf8_lossy(bytes),
                settings.line_ending()
            );
        } else {
            // print error because `cflag` was explicitly requested
            return Err(USimpleError::new(1, "can't get process context"));
        }

        Ok(())
    } else {
        Err(USimpleError::new(
            1,
            "--context (-Z) works only on an SELinux-enabled kernel",
        ))
    }
}

struct GetPasswordError;

/// gets the password. Also has a side effect of setting an exit code when not found.
/// Should be used with care. If Err() is returned, usually you should continue to the
/// next user.
fn get_password(user: &str) -> Result<Passwd, GetPasswordError> {
    match Passwd::locate(user) {
        Ok(p) => Ok(p),
        Err(_) => {
            show_error!("{}: no such user", user.quote());
            set_exit_code(1);
            Err(GetPasswordError)
        }
    }
}

/// Returns None when getting a password failed.
fn get_user_info(
    user: Option<&str>,
    settings: &Settings,
) -> Result<(uid_t, gid_t, Vec<gid_t>), GetPasswordError> {
    Ok(if let Some(user) = user {
        let password = get_password(user)?;
        (password.uid, password.gid, password.belongs_to())
    } else {
        (
            if settings.real { getuid() } else { geteuid() },
            if settings.real { getgid() } else { getegid() },
            Vec::new(),
        )
    })
}

fn process_user(
    uid: uid_t,
    gid: gid_t,
    belongs_to: Vec<gid_t>,
    settings: &Settings,
    num_users_specified: usize,
) {
    if settings.group {
        print!(
            "{}",
            if settings.display_name {
                entries::gid2grp(gid).unwrap_or_else(|_| {
                    show_error!("cannot find name for group ID {}", gid);
                    set_exit_code(1);
                    gid.to_string()
                })
            } else {
                gid.to_string()
            }
        );
    }

    if settings.user {
        print!(
            "{}",
            if settings.display_name {
                entries::uid2usr(uid).unwrap_or_else(|_| {
                    show_error!("cannot find name for user ID {}", uid);
                    set_exit_code(1);
                    uid.to_string()
                })
            } else {
                uid.to_string()
            }
        );
    }

    let groups = entries::get_groups_gnu(Some(gid)).unwrap();

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
    let groups = if num_users_specified == 0 {
        groups.clone()
    } else {
        belongs_to
    };

    if settings.groups {
        print!(
            "{}{}",
            groups
                .iter()
                .map(|&id| {
                    if settings.display_name {
                        entries::gid2grp(id).unwrap_or_else(|_| {
                            show_error!("cannot find name for group ID {}", id);
                            set_exit_code(1);
                            id.to_string()
                        })
                    } else {
                        id.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(&settings.delimiter()),
            // NOTE: this is necessary to pass GNU's "tests/id/zero.sh":
            if settings.zero && num_users_specified > 1 {
                "\0"
            } else {
                ""
            }
        );
    }

    if settings.default_format() {
        id_print(
            &Ids {
                uid,
                gid,
                euid: geteuid(),
                egid: getegid(),
            },
            &groups,
            num_users_specified,
        );
    }
    print!("{}", settings.line_ending());
}

fn handle_bsd_specific_options(
    user: Option<&str>,
    settings: &Settings,
) -> Result<(), GetPasswordError> {
    // GNU's `id` does not support the flags: -p/-P/-A.
    if settings.password {
        // BSD's `id` ignores all but the first specified user
        if let Some(first_user) = user {
            pline(Some(get_password(first_user)?.uid));
        } else {
            // if no user is given
            pline(None);
        }
    } else if settings.human_readable {
        // BSD's `id` ignores all but the first specified user
        if let Some(first_user) = user {
            pretty(Some(get_password(first_user)?));
        } else {
            // if no user is given
            pretty(None);
        }
    } else if settings.audit {
        // BSD's `id` ignores specified users
        auditid();
    }

    Ok(())
}

#[uucore::main]
#[allow(clippy::cognitive_complexity)]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let (settings, users) = parse(args)?;

    let users: Vec<String> = users
        .into_iter()
        .map(|i| {
            Ok(i.to_str()
                .ok_or(USimpleError::new(
                    1,
                    format!("invalid utf8: {}", i.to_string_lossy()),
                ))?
                .to_string())
        })
        .collect::<Result<_, Box<dyn UError>>>()?;
    let num_users_specified = users.len();

    check_settings(&settings, num_users_specified)?;

    if settings.context {
        handle_context(&settings)?;
    }

    // BSD's `id` ignores all but the first specified user
    if let Err(GetPasswordError) =
        handle_bsd_specific_options(users.get(0).map(|i| i.as_str()), &settings)
    {
        return Ok(());
    }

    if num_users_specified == 0 {
        let Ok((uid, gid, belongs_to)) = get_user_info(None, &settings) else {
            return Ok(());
        };

        process_user(uid, gid, belongs_to, &settings, num_users_specified);
    } else {
        for user in &users {
            let Ok((uid, gid, belongs_to)) = get_user_info(Some(user.as_str()), &settings) else {
                continue;
            };

            process_user(uid, gid, belongs_to, &settings, num_users_specified);
        }
    }

    Ok(())
}

pub fn uu_app() -> Command {
    Command::new(uucore::util_name())
}

fn pretty(possible_pw: Option<Passwd>) {
    if let Some(p) = possible_pw {
        print!("uid\t{}\ngroups\t", p.name);
        println!(
            "{}",
            p.belongs_to()
                .iter()
                .map(|&gr| entries::gid2grp(gr).unwrap())
                .collect::<Vec<_>>()
                .join(" ")
        );
    } else {
        let login = cstr2cow!(getlogin() as *const _);
        let rid = getuid();
        if let Ok(p) = Passwd::locate(rid) {
            if login == p.name {
                println!("login\t{login}");
            }
            println!("uid\t{}", p.name);
        } else {
            println!("uid\t{rid}");
        }

        let eid = getegid();
        if eid == rid {
            if let Ok(p) = Passwd::locate(eid) {
                println!("euid\t{}", p.name);
            } else {
                println!("euid\t{eid}");
            }
        }

        let rid = getgid();
        if rid != eid {
            if let Ok(g) = Group::locate(rid) {
                println!("euid\t{}", g.name);
            } else {
                println!("euid\t{rid}");
            }
        }

        println!(
            "groups\t{}",
            entries::get_groups_gnu(None)
                .unwrap()
                .iter()
                .map(|&gr| entries::gid2grp(gr).unwrap())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
}

#[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
fn pline(possible_uid: Option<uid_t>) {
    let uid = possible_uid.unwrap_or_else(getuid);
    let pw = Passwd::locate(uid).unwrap();

    println!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        pw.name,
        pw.user_passwd.unwrap_or_default(),
        pw.uid,
        pw.gid,
        pw.user_access_class.unwrap_or_default(),
        pw.passwd_change_time,
        pw.expiration,
        pw.user_info.unwrap_or_default(),
        pw.user_dir.unwrap_or_default(),
        pw.user_shell.unwrap_or_default()
    );
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "openbsd"))]
fn pline(possible_uid: Option<uid_t>) {
    let uid = possible_uid.unwrap_or_else(getuid);
    let pw = Passwd::locate(uid).unwrap();

    println!(
        "{}:{}:{}:{}:{}:{}:{}",
        pw.name,
        pw.user_passwd.unwrap_or_default(),
        pw.uid,
        pw.gid,
        pw.user_info.unwrap_or_default(),
        pw.user_dir.unwrap_or_default(),
        pw.user_shell.unwrap_or_default()
    );
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "openbsd"))]
fn auditid() {}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "openbsd")))]
fn auditid() {
    use std::mem::MaybeUninit;

    let mut auditinfo: MaybeUninit<audit::c_auditinfo_addr_t> = MaybeUninit::uninit();
    let address = auditinfo.as_mut_ptr();
    if unsafe { audit::getaudit(address) } < 0 {
        println!("couldn't retrieve information");
        return;
    }

    // SAFETY: getaudit wrote a valid struct to auditinfo
    let auditinfo = unsafe { auditinfo.assume_init() };

    println!("auid={}", auditinfo.ai_auid);
    println!("mask.success=0x{:x}", auditinfo.ai_mask.am_success);
    println!("mask.failure=0x{:x}", auditinfo.ai_mask.am_failure);
    println!("termid.port=0x{:x}", auditinfo.ai_termid.port);
    println!("asid={}", auditinfo.ai_asid);
}

fn id_print(ids: &Ids, groups: &[u32], num_users_specified: usize) {
    let Ids {
        uid,
        gid,
        euid,
        egid,
    } = *ids;

    print!(
        "uid={}({})",
        uid,
        entries::uid2usr(uid).unwrap_or_else(|_| {
            show_error!("cannot find name for user ID {}", uid);
            set_exit_code(1);
            uid.to_string()
        })
    );
    print!(
        " gid={}({})",
        gid,
        entries::gid2grp(gid).unwrap_or_else(|_| {
            show_error!("cannot find name for group ID {}", gid);
            set_exit_code(1);
            gid.to_string()
        })
    );
    if num_users_specified == 0 && (euid != uid) {
        print!(
            " euid={}({})",
            euid,
            entries::uid2usr(euid).unwrap_or_else(|_| {
                show_error!("cannot find name for user ID {}", euid);
                set_exit_code(1);
                euid.to_string()
            })
        );
    }
    if num_users_specified == 0 && (egid != gid) {
        print!(
            " egid={}({})",
            euid,
            entries::gid2grp(egid).unwrap_or_else(|_| {
                show_error!("cannot find name for group ID {}", egid);
                set_exit_code(1);
                egid.to_string()
            })
        );
    }
    print!(
        " groups={}",
        groups
            .iter()
            .map(|&gr| format!(
                "{}({})",
                gr,
                entries::gid2grp(gr).unwrap_or_else(|_| {
                    show_error!("cannot find name for group ID {}", gr);
                    set_exit_code(1);
                    gr.to_string()
                })
            ))
            .collect::<Vec<_>>()
            .join(",")
    );

    #[cfg(all(any(target_os = "linux", target_os = "android"), feature = "selinux"))]
    if settings.selinux_supported
        && !settings.user_specified
        && std::env::var_os("POSIXLY_CORRECT").is_none()
    {
        // print SElinux context (does not depend on "-Z")
        if let Ok(context) = selinux::SecurityContext::current(false) {
            let bytes = context.as_bytes();
            print!(" context={}", String::from_utf8_lossy(bytes));
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "openbsd")))]
mod audit {
    use super::libc::{c_int, c_uint, dev_t, pid_t, uid_t};

    pub type au_id_t = uid_t;
    pub type au_asid_t = pid_t;
    pub type au_event_t = c_uint;
    pub type au_emod_t = c_uint;
    pub type au_class_t = c_int;
    pub type au_flag_t = u64;

    #[repr(C)]
    pub struct au_mask {
        pub am_success: c_uint,
        pub am_failure: c_uint,
    }
    pub type au_mask_t = au_mask;

    #[repr(C)]
    pub struct au_tid_addr {
        pub port: dev_t,
    }
    pub type au_tid_addr_t = au_tid_addr;

    #[repr(C)]
    pub struct c_auditinfo_addr {
        pub ai_auid: au_id_t,         // Audit user ID
        pub ai_mask: au_mask_t,       // Audit masks.
        pub ai_termid: au_tid_addr_t, // Terminal ID.
        pub ai_asid: au_asid_t,       // Audit session ID.
        pub ai_flags: au_flag_t,      // Audit session flags
    }
    pub type c_auditinfo_addr_t = c_auditinfo_addr;

    extern "C" {
        pub fn getaudit(auditinfo_addr: *mut c_auditinfo_addr_t) -> c_int;
    }
}
