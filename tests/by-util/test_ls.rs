use crate::common::util::*;

extern crate regex;
use self::regex::Regex;

use std::thread::sleep;
use std::time::Duration;

#[cfg(not(windows))]
extern crate libc;
#[cfg(not(windows))]
use self::libc::umask;
#[cfg(not(windows))]
use std::sync::Mutex;

#[cfg(not(windows))]
lazy_static! {
    static ref UMASK_MUTEX: Mutex<()> = Mutex::new(());
}

#[test]
fn test_ls_ls() {
    new_ucmd!().succeeds();
}

#[test]
fn test_ls_i() {
    new_ucmd!().arg("-i").succeeds();
    new_ucmd!().arg("-il").succeeds();
}

#[test]
fn test_ls_a() {
    let scene = TestScenario::new(util_name!());
    let at = &scene.fixtures;
    at.touch(".test-1");

    let result = scene.ucmd().run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    assert!(!result.stdout.contains(".test-1"));
    assert!(!result.stdout.contains(".."));

    let result = scene.ucmd().arg("-a").run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    assert!(result.stdout.contains(".test-1"));
    assert!(result.stdout.contains(".."));

    let result = scene.ucmd().arg("-A").run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    assert!(result.stdout.contains(".test-1"));
    assert!(!result.stdout.contains(".."));
}

#[test]
fn test_ls_columns() {
    let scene = TestScenario::new(util_name!());
    let at = &scene.fixtures;
    at.touch(&at.plus_as_string("test-columns-1"));
    at.touch(&at.plus_as_string("test-columns-2"));

    // Columns is the default
    let result = scene.ucmd().run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);

    #[cfg(not(windows))]
    assert_eq!(result.stdout, "test-columns-1\ntest-columns-2\n");
    #[cfg(windows)]
    assert_eq!(result.stdout, "test-columns-1  test-columns-2\n");

    for option in &["-C", "--format=columns"] {
        let result = scene.ucmd().arg(option).run();
        println!("stderr = {:?}", result.stderr);
        println!("stdout = {:?}", result.stdout);
        assert!(result.success);
        #[cfg(not(windows))]
        assert_eq!(result.stdout, "test-columns-1\ntest-columns-2\n");
        #[cfg(windows)]
        assert_eq!(result.stdout, "test-columns-1  test-columns-2\n");
    }
}

#[test]
fn test_ls_long() {
    #[cfg(not(windows))]
    let last;
    #[cfg(not(windows))]
    {
        let _guard = UMASK_MUTEX.lock();
        last = unsafe { umask(0) };

        unsafe {
            umask(0o002);
        }
    }

    let scene = TestScenario::new(util_name!());
    let at = &scene.fixtures;
    at.touch(&at.plus_as_string("test-long"));

    for arg in &["-l", "--long", "--format=long", "--format=verbose"] {
        let result = scene.ucmd().arg(arg).arg("test-long").succeeds();
        println!("stderr = {:?}", result.stderr);
        println!("stdout = {:?}", result.stdout);
        #[cfg(not(windows))]
        assert!(result.stdout.contains("-rw-rw-r--"));

        #[cfg(windows)]
        assert!(result.stdout.contains("---------- 1 somebody somegroup"));
    }

    #[cfg(not(windows))]
    {
        unsafe {
            umask(last);
        }
    }
}

#[test]
fn test_ls_long_formats() {
    let scene = TestScenario::new(util_name!());
    let at = &scene.fixtures;
    at.touch(&at.plus_as_string("test-long-formats"));

    // Regex for three names, so all of author, group and owner
    let re_three = Regex::new(r"[xrw-]{9} \d ([_a-z][-0-9_a-z]+ ){3}").unwrap();

    // Regex for two names, either:
    // - group and owner
    // - author and owner
    // - author and group
    let re_two = Regex::new(r"[xrw-]{9} \d ([_a-z][-0-9_a-z]+ ){2}").unwrap();

    // Regex for one name: author, group or owner
    let re_one = Regex::new(r"[xrw-]{9} \d [_a-z][-0-9_a-z]+ ").unwrap();

    // Regex for no names.
    // Names cannot start with a number, so the second \d will only match the file size
    let re_zero = Regex::new(r"[xrw-]{9} \d \d").unwrap();

    let result = scene
        .ucmd()
        .arg("-l")
        .arg("--author")
        .arg("test-long-formats")
        .run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(re_three.is_match(&result.stdout));

    let result = scene
        .ucmd()
        .arg("-l1")
        .arg("--author")
        .arg("test-long-formats")
        .run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(re_three.is_match(&result.stdout));

    for arg in &[
        "-l", // only group and owner
        "-g --author", // only author and group
        "-o --author", // only author and owner
        "-lG --author", // only author and owner
        "-l --no-group --author", // only author and owner
    ] {
        let result = scene
            .ucmd()
            .args(&arg.split(" ").collect::<Vec<_>>())
            .arg("test-long-formats")
            .succeeds();
        println!("stderr = {:?}", result.stderr);
        println!("stdout = {:?}", result.stdout);
        assert!(re_two.is_match(&result.stdout));
    }

    for arg in &[
        "-g", // only group
        "-gl", // only group
        "-o", // only owner
        "-ol", // only owner
        "-oG", // only owner
        "-lG", // only owner
        "-l --no-group", // only owner
        "-gG --author", // only author
    ] {
        let result = scene
            .ucmd()
            .args(&arg.split(" ").collect::<Vec<_>>())
            .arg("test-long-formats")
            .succeeds();
        println!("stderr = {:?}", result.stderr);
        println!("stdout = {:?}", result.stdout);
        assert!(re_one.is_match(&result.stdout));
    }

    for arg in &[
        "-og",
        "-ogl",
        "-lgo",
        "-gG",
        "-g --no-group",
        "-og --no-group",
        "-og --format=long",
        "-ogCl",
        "-og --format=vertical -l",
        "-og1",
        "-og1l",
    ] {
        let result = scene
            .ucmd()
            .args(&arg.split(" ").collect::<Vec<_>>())
            .arg("test-long-formats")
            .succeeds();
        println!("stderr = {:?}", result.stderr);
        println!("stdout = {:?}", result.stdout);
        assert!(re_zero.is_match(&result.stdout));
    }
}

#[test]
fn test_ls_oneline() {
    let scene = TestScenario::new(util_name!());
    let at = &scene.fixtures;
    at.touch(&at.plus_as_string("test-oneline-1"));
    at.touch(&at.plus_as_string("test-oneline-2"));

    // Bit of a weird situation: in the tests oneline and columns have the same output,
    // except on Windows.
    for option in &["-1", "--format=single-column"] {
        let result = scene.ucmd().arg(option).run();
        println!("stderr = {:?}", result.stderr);
        println!("stdout = {:?}", result.stdout);
        assert!(result.success);
        assert_eq!(result.stdout, "test-oneline-1\ntest-oneline-2\n");
    }
}

#[test]
fn test_ls_deref() {
    let scene = TestScenario::new(util_name!());
    let at = &scene.fixtures;
    let path_regexp = r"(.*)test-long.link -> (.*)test-long(.*)";
    let re = Regex::new(path_regexp).unwrap();

    at.touch(&at.plus_as_string("test-long"));
    at.symlink_file("test-long", "test-long.link");
    assert!(at.is_symlink("test-long.link"));

    let result = scene
        .ucmd()
        .arg("-l")
        .arg("--color=never")
        .arg("test-long")
        .arg("test-long.link")
        .run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    assert!(re.is_match(&result.stdout.trim()));

    let result = scene
        .ucmd()
        .arg("-L")
        .arg("--color=never")
        .arg("test-long")
        .arg("test-long.link")
        .run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    assert!(!re.is_match(&result.stdout.trim()));
}

#[test]
fn test_ls_order_size() {
    let scene = TestScenario::new(util_name!());
    let at = &scene.fixtures;

    at.touch("test-1");
    at.append("test-1", "1");

    at.touch("test-2");
    at.append("test-2", "22");
    at.touch("test-3");
    at.append("test-3", "333");
    at.touch("test-4");
    at.append("test-4", "4444");

    let result = scene.ucmd().arg("-al").run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);

    let result = scene.ucmd().arg("-S").run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    #[cfg(not(windows))]
    assert_eq!(result.stdout, "test-4\ntest-3\ntest-2\ntest-1\n");
    #[cfg(windows)]
    assert_eq!(result.stdout, "test-4  test-3  test-2  test-1\n");

    let result = scene.ucmd().arg("-S").arg("-r").run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    #[cfg(not(windows))]
    assert_eq!(result.stdout, "test-1\ntest-2\ntest-3\ntest-4\n");
    #[cfg(windows)]
    assert_eq!(result.stdout, "test-1  test-2  test-3  test-4\n");
}

#[test]
fn test_ls_long_ctime() {
    let scene = TestScenario::new(util_name!());
    let at = &scene.fixtures;

    at.touch("test-long-ctime-1");
    let result = scene.ucmd().arg("-lc").succeeds();

    // Should show the time on Unix, but question marks on windows.
    #[cfg(unix)]
    assert!(result.stdout.contains(":"));
    #[cfg(not(unix))]
    assert!(result.stdout.contains("???"));
}

#[test]
fn test_ls_order_time() {
    let scene = TestScenario::new(util_name!());
    let at = &scene.fixtures;

    at.touch("test-1");
    at.append("test-1", "1");
    sleep(Duration::from_millis(100));
    at.touch("test-2");
    at.append("test-2", "22");
    sleep(Duration::from_millis(100));
    at.touch("test-3");
    at.append("test-3", "333");
    sleep(Duration::from_millis(100));
    at.touch("test-4");
    at.append("test-4", "4444");
    sleep(Duration::from_millis(100));

    // Read test-3, only changing access time
    at.read("test-3");

    // Set permissions of test-2, only changing ctime
    std::fs::set_permissions(
        at.plus_as_string("test-2"),
        at.metadata("test-2").permissions(),
    )
    .unwrap();

    let result = scene.ucmd().arg("-al").run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);

    // ctime was changed at write, so the order is 4 3 2 1
    let result = scene.ucmd().arg("-t").run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    #[cfg(not(windows))]
    assert_eq!(result.stdout, "test-4\ntest-3\ntest-2\ntest-1\n");
    #[cfg(windows)]
    assert_eq!(result.stdout, "test-4  test-3  test-2  test-1\n");

    let result = scene.ucmd().arg("-tr").run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    #[cfg(not(windows))]
    assert_eq!(result.stdout, "test-1\ntest-2\ntest-3\ntest-4\n");
    #[cfg(windows)]
    assert_eq!(result.stdout, "test-1  test-2  test-3  test-4\n");

    // 3 was accessed last in the read
    // So the order should be 2 3 4 1
    let result = scene.ucmd().arg("-tu").run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    #[cfg(not(windows))]
    assert_eq!(result.stdout, "test-3\ntest-4\ntest-2\ntest-1\n");

    // Access time does not seem to be set on Windows on read call
    // so the order is 4 3 2 1
    #[cfg(windows)]
    assert_eq!(result.stdout, "test-4  test-3  test-2  test-1\n");

    // test-2 had the last ctime change when the permissions were set
    // So the order should be 2 4 3 1
    #[cfg(unix)]
    {
        let result = scene.ucmd().arg("-tc").run();
        println!("stderr = {:?}", result.stderr);
        println!("stdout = {:?}", result.stdout);
        assert!(result.success);
        assert_eq!(result.stdout, "test-2\ntest-4\ntest-3\ntest-1\n");
    }
}

#[test]
fn test_ls_non_existing() {
    new_ucmd!().arg("doesntexist").fails();
}

#[test]
fn test_ls_files_dirs() {
    let scene = TestScenario::new(util_name!());
    let at = &scene.fixtures;
    at.mkdir("a");
    at.mkdir("a/b");
    at.mkdir("a/b/c");
    at.mkdir("z");
    at.touch(&at.plus_as_string("a/a"));
    at.touch(&at.plus_as_string("a/b/b"));

    scene.ucmd().arg("a").succeeds();
    scene.ucmd().arg("a/a").succeeds();
    scene.ucmd().arg("a").arg("z").succeeds();

    let result = scene.ucmd().arg("doesntexist").fails();
    // Doesn't exist
    assert!(result
        .stderr
        .contains("error: 'doesntexist': No such file or directory"));

    let result = scene.ucmd().arg("a").arg("doesntexist").fails();
    // One exists, the other doesn't
    assert!(result
        .stderr
        .contains("error: 'doesntexist': No such file or directory"));
    assert!(result.stdout.contains("a:"));
}

#[test]
fn test_ls_recursive() {
    let scene = TestScenario::new(util_name!());
    let at = &scene.fixtures;
    at.mkdir("a");
    at.mkdir("a/b");
    at.mkdir("a/b/c");
    at.mkdir("z");
    at.touch(&at.plus_as_string("a/a"));
    at.touch(&at.plus_as_string("a/b/b"));

    scene.ucmd().arg("a").succeeds();
    scene.ucmd().arg("a/a").succeeds();
    let result = scene
        .ucmd()
        .arg("--color=never")
        .arg("-R")
        .arg("a")
        .arg("z")
        .succeeds();

    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    #[cfg(not(windows))]
    assert!(result.stdout.contains("a/b:\nb"));
    #[cfg(windows)]
    assert!(result.stdout.contains("a\\b:\nb"));
}

#[cfg(unix)]
#[test]
fn test_ls_ls_color() {
    let scene = TestScenario::new(util_name!());
    let at = &scene.fixtures;
    at.mkdir("a");
    at.mkdir("a/nested_dir");
    at.mkdir("z");
    at.touch(&at.plus_as_string("a/nested_file"));
    at.touch("test-color");

    let a_with_colors = "\x1b[01;34ma\x1b[0m";
    let z_with_colors = "\x1b[01;34mz\x1b[0m";
    let nested_dir_with_colors = "\x1b[01;34mnested_dir\x1b[0m";

    // Color is disabled by default
    let result = scene.ucmd().succeeds();
    assert!(!result.stdout.contains(a_with_colors));
    assert!(!result.stdout.contains(z_with_colors));

    // Color should be enabled
    let result = scene.ucmd().arg("--color").succeeds();
    assert!(result.stdout.contains(a_with_colors));
    assert!(result.stdout.contains(z_with_colors));

    // Color should be enabled
    let result = scene.ucmd().arg("--color=always").succeeds();
    assert!(result.stdout.contains(a_with_colors));
    assert!(result.stdout.contains(z_with_colors));

    // Color should be disabled
    let result = scene.ucmd().arg("--color=never").succeeds();
    assert!(!result.stdout.contains(a_with_colors));
    assert!(!result.stdout.contains(z_with_colors));

    // Nested dir should be shown and colored
    let result = scene.ucmd().arg("--color").arg("a").succeeds();
    assert!(result.stdout.contains(nested_dir_with_colors));

    // Color has no effect
    let result = scene
        .ucmd()
        .arg("--color=always")
        .arg("a/nested_file")
        .succeeds();
    assert!(result.stdout.contains("a/nested_file\n"));

    // No output
    let result = scene.ucmd().arg("--color=never").arg("z").succeeds();
    assert_eq!(result.stdout, "");
}

#[cfg(not(any(target_vendor = "apple", target_os = "windows")))] // Truncate not available on mac or win
#[test]
fn test_ls_human_si() {
    let scene = TestScenario::new(util_name!());
    let file1 = "test_human-1";
    let result = scene
        .cmd("truncate")
        .arg("-s")
        .arg("+1000")
        .arg(file1)
        .run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);

    let result = scene.ucmd().arg("-hl").arg(file1).run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    assert!(result.stdout.contains(" 1000 "));

    let result = scene.ucmd().arg("-l").arg("--si").arg(file1).run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    assert!(result.stdout.contains(" 1.0k "));

    scene
        .cmd("truncate")
        .arg("-s")
        .arg("+1000k")
        .arg(file1)
        .run();

    let result = scene.ucmd().arg("-hl").arg(file1).run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    assert!(result.stdout.contains(" 1001K "));

    let result = scene.ucmd().arg("-l").arg("--si").arg(file1).run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    assert!(result.stdout.contains(" 1.1M "));

    let file2 = "test-human-2";
    let result = scene
        .cmd("truncate")
        .arg("-s")
        .arg("+12300k")
        .arg(file2)
        .run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    let result = scene.ucmd().arg("-hl").arg(file2).run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    // GNU rounds up, so we must too.
    assert!(result.stdout.contains(" 13M "));

    let result = scene.ucmd().arg("-l").arg("--si").arg(file2).run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    // GNU rounds up, so we must too.
    assert!(result.stdout.contains(" 13M "));

    let file3 = "test-human-3";
    let result = scene
        .cmd("truncate")
        .arg("-s")
        .arg("+9999")
        .arg(file3)
        .run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);

    let result = scene.ucmd().arg("-hl").arg(file3).run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    assert!(result.stdout.contains(" 9.8K "));

    let result = scene.ucmd().arg("-l").arg("--si").arg(file3).run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    assert!(result.stdout.contains(" 10k "));
}

#[cfg(windows)]
#[test]
fn test_ls_hidden_windows() {
    let scene = TestScenario::new(util_name!());
    let at = &scene.fixtures;
    let file = "hiddenWindowsFileNoDot";
    at.touch(file);
    // hide the file
    scene
        .cmd("attrib")
        .arg("+h")
        .arg("+S")
        .arg("+r")
        .arg(file)
        .run();
    let result = scene.ucmd().run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    let result = scene.ucmd().arg("-a").run();
    println!("stderr = {:?}", result.stderr);
    println!("stdout = {:?}", result.stdout);
    assert!(result.success);
    assert!(result.stdout.contains(file));
}
