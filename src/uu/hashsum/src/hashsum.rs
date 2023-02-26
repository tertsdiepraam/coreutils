//  * This file is part of the uutils coreutils package.
//  *
//  * (c) Alex Lyon <arcterus@mail.com>
//  * (c) Vsevolod Velichko <torkvemada@sorokdva.net>
//  * (c) Gil Cottle <gcottle@redtown.org>
//  *
//  * For the full copyright and license information, please view the LICENSE
//  * file that was distributed with this source code.

// spell-checker:ignore (ToDO) algo, algoname, regexes, nread, nonames

use clap::builder::ValueParser;
use clap::crate_version;
use clap::ArgAction;
use clap::{Arg, Command};
use regex::Regex;
use std::cmp::Ordering;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{stdin, BufRead, BufReader, Read};
use std::iter;
use std::iter::Sum;
use std::num::ParseIntError;
use std::path::Path;
use uucore::error::{FromIo, UError, UResult};
use uucore::sum::{
    Blake2b, Blake3, Md5, Sha1, Sha224, Sha256, Sha384, Sha3_224, Sha3_256, Sha3_384, Sha3_512,
    Sha512, Shake128, Shake256, SumAlgorithm,
};
use uucore::{crash, display::Quotable, show_warning};

const NAME: &str = "hashsum";

struct Options {
    binary: bool,
    check: bool,
    tag: bool,
    nonames: bool,
    status: bool,
    quiet: bool,
    strict: bool,
    warn: bool,
}

#[allow(clippy::cognitive_complexity)]
fn hashsum_with_algo<'a>(
    algorithm: &str,
    bits: Option<usize>,
    options: Options,
    files: impl IntoIterator<Item = &'a Path>,
) -> UResult<()> {
    match algorithm {
        "md5sum" => hashsum(Md5, options, files),
        "sha1sum" => hashsum(Sha1, options, files),
        "sha224sum" => hashsum(Sha224, options, files),
        "sha256sum" => hashsum(Sha256, options, files),
        "sha384sum" => hashsum(Sha384, options, files),
        "sha512sum" => hashsum(Sha512, options, files),
        "b2sum" => hashsum(Blake2b, options, files),
        "b3sum" => hashsum(Blake3, options, files),
        "sha3sum" => match bits {
            Some(224) => hashsum(Sha3_224, options, files),
            Some(256) => hashsum(Sha3_256, options, files),
            Some(384) => hashsum(Sha3_384, options, files),
            Some(512) => hashsum(Sha3_512, options, files),
            Some(_) => crash!(
                1,
                "Invalid output size for SHA3 (expected 224, 256, 384, or 512)"
            ),
            None => crash!(1, "--bits required for SHA3"),
        },
        "sha3-224sum" => hashsum(Sha3_224, options, files),
        "sha3-256sum" => hashsum(Sha3_256, options, files),
        "sha3-384sum" => hashsum(Sha3_384, options, files),
        "sha3-512sum" => hashsum(Sha3_512, options, files),
        "shake128sum" => match bits {
            Some(bits) => hashsum(Shake128 { bits }, options, files),
            None => crash!(1, "--bits required for SHAKE-128"),
        },
        "shake256sum" => match bits {
            Some(bits) => hashsum(Shake256 { bits }, options, files),
            None => crash!(1, "--bits required for SHAKE-256"),
        },
        _ => crash!(1, "Invalid algorithm {algorithm}"),
    }
}

// TODO: return custom error type
fn parse_bit_num(arg: &str) -> Result<usize, ParseIntError> {
    arg.parse()
}

#[uucore::main]
pub fn uumain(mut args: impl uucore::Args) -> UResult<()> {
    // if there is no program name for some reason, default to "hashsum"
    let program = args.next().unwrap_or_else(|| OsString::from(NAME));
    let binary_name = Path::new(&program)
        .file_name()
        .unwrap_or_else(|| OsStr::new(NAME))
        .to_string_lossy();

    let args = iter::once(program.clone()).chain(args);

    // Default binary in Windows, text mode otherwise
    let binary_flag_default = cfg!(windows);

    let command = uu_app(&binary_name);

    let matches = command.try_get_matches_from(args)?;

    let algorithm = match matches.try_get_one::<String>("algorithm") {
        // If it is defined in clap::Command, then it's required, so unwrap is fine
        Ok(a) => a.unwrap(),
        Err(_) => binary_name.as_ref(),
    };

    let binary = if matches.get_flag("binary") {
        true
    } else if matches.get_flag("text") {
        false
    } else {
        binary_flag_default
    };
    let check = matches.get_flag("check");
    let tag = matches.get_flag("tag");
    let nonames = *matches
        .try_get_one("no-names")
        .unwrap_or(None)
        .unwrap_or(&false);
    let status = matches.get_flag("status");
    let quiet = matches.get_flag("quiet") || status;
    let strict = matches.get_flag("strict");
    let warn = matches.get_flag("warn") && !status;
    let bits = matches
        .try_get_one::<usize>("bits")
        .unwrap_or_default()
        .map(|&u| u);

    let opts = Options {
        binary,
        check,
        tag,
        nonames,
        status,
        quiet,
        strict,
        warn,
    };

    match matches.get_many::<OsString>("FILE") {
        Some(files) => hashsum_with_algo(algorithm, bits, opts, files.map(|f| Path::new(f))),
        None => hashsum_with_algo(algorithm, bits, opts, iter::once(Path::new("-"))),
    }
}

// hashsum is handled differently in build.rs, therefore this is not the same
// as in other utilities.
fn uu_app(binary_name: &str) -> Command {
    match binary_name {
        // These all support the same options.
        "md5sum" | "sha1sum" | "sha224sum" | "sha256sum" | "sha384sum" | "sha512sum" | "b2sum" => {
            clap_command(false, false, false)
        }
        // These have never been part of GNU Coreutils, but can function with the same
        // options as md5sum.
        "sha3-224sum" | "sha3-256sum" | "sha3-384sum" | "sha3-512sum" => {
            clap_command(false, false, false)
        }
        // These have never been part of GNU Coreutils, and require an additional --bits
        // option to specify their output size.
        "sha3sum" | "shake128sum" | "shake256sum" => clap_command(false, true, false),
        // b3sum has never been part of GNU Coreutils, and has a --no-names option in
        // addition to the b2sum options.
        "b3sum" => clap_command(false, false, true),
        // We're probably just being called as `hashsum`, so give them everything.
        _ => clap_command(true, true, true),
    }
}

fn clap_command(algorithm: bool, bits: bool, no_names: bool) -> Command {
    #[cfg(windows)]
    const BINARY_HELP: &str = "read in binary mode (default)";
    #[cfg(not(windows))]
    const BINARY_HELP: &str = "read in binary mode";
    #[cfg(windows)]
    const TEXT_HELP: &str = "read in text mode";
    #[cfg(not(windows))]
    const TEXT_HELP: &str = "read in text mode (default)";

    let mut cmd = Command::new(uucore::util_name())
        .version(crate_version!())
        .about("Compute and check message digests.")
        .infer_long_args(true);

    if algorithm {
        cmd = cmd.arg(Arg::new("algorithm"))
    }

    // COMMON arguments
    cmd = cmd
        .arg(
            Arg::new("binary")
                .short('b')
                .long("binary")
                .help(BINARY_HELP)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("check")
                .short('c')
                .long("check")
                .help("read hashsums from the FILEs and check them")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("tag")
                .long("tag")
                .help("create a BSD-style checksum")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("text")
                .short('t')
                .long("text")
                .help(TEXT_HELP)
                .conflicts_with("binary")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .help("don't print OK for each successfully verified file")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("status")
                .short('s')
                .long("status")
                .help("don't output anything, status code shows success")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("strict")
                .long("strict")
                .help("exit non-zero for improperly formatted checksum lines")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("warn")
                .short('w')
                .long("warn")
                .help("warn about improperly formatted checksum lines")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("FILE")
                .index(1)
                .action(ArgAction::Append)
                .value_name("FILE")
                .value_hint(clap::ValueHint::FilePath)
                .value_parser(ValueParser::os_string()),
        );

    if bits {
        // Needed for variable-length output sums (e.g. SHAKE)
        cmd = cmd.arg(
            Arg::new("bits")
                .long("bits")
                .help("set the size of the output (only for SHAKE)")
                .value_name("BITS")
                // XXX: should we actually use validators?  they're not particularly efficient
                .value_parser(parse_bit_num),
        );
    }

    if no_names {
        cmd = cmd.arg(
            Arg::new("no-names")
                .long("no-names")
                .help("Omits filenames in the output (option not present in GNU/Coreutils)")
                .action(ArgAction::SetTrue),
        );
    }

    cmd
}

#[derive(Debug)]
enum HashsumError {
    InvalidRegex,
    InvalidFormat,
}

impl Error for HashsumError {}
impl UError for HashsumError {}

impl std::fmt::Display for HashsumError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::InvalidRegex => write!(f, "invalid regular expression"),
            Self::InvalidFormat => Ok(()),
        }
    }
}

#[allow(clippy::cognitive_complexity)]
fn hashsum<'a, I, A: SumAlgorithm>(algo: A, options: Options, files: I) -> UResult<()>
where
    I: IntoIterator<Item = &'a Path>,
{
    let mut bad_format = 0;
    let mut failed_cksum = 0;
    let mut failed_open_file = 0;
    let binary_marker = if options.binary { "*" } else { " " };
    for filename in files {
        let filename = Path::new(filename);

        let stdin_buf;
        let file_buf;
        let file = BufReader::new(if filename == OsStr::new("-") {
            stdin_buf = stdin();
            Box::new(stdin_buf) as Box<dyn Read>
        } else {
            file_buf =
                File::open(filename).map_err_context(|| "failed to open file".to_string())?;
            Box::new(file_buf) as Box<dyn Read>
        });
        if options.check {
            // Set up Regexes for line validation and parsing
            //
            // First, we compute the number of bytes we expect to be in
            // the digest string. If the algorithm has a variable number
            // of output bits, then we use the `+` modifier in the
            // regular expression, otherwise we use the `{n}` modifier,
            // where `n` is the number of bytes.
            let bytes = algo.output_bits() / 4;
            let modifier = if bytes > 0 {
                format!("{{{bytes}}}")
            } else {
                "+".to_string()
            };
            let gnu_re = Regex::new(&format!(
                r"^(?P<digest>[a-fA-F0-9]{modifier}) (?P<binary>[ \*])(?P<fileName>.*)",
            ))
            .map_err(|_| HashsumError::InvalidRegex)?;
            let bsd_re = Regex::new(&format!(
                r"^{algorithm} \((?P<fileName>.*)\) = (?P<digest>[a-fA-F0-9]{digest_size})",
                algorithm = A::NAME,
                digest_size = modifier,
            ))
            .map_err(|_| HashsumError::InvalidRegex)?;

            let buffer = file;
            for (i, maybe_line) in buffer.lines().enumerate() {
                let line = match maybe_line {
                    Ok(l) => l,
                    Err(e) => return Err(e.map_err_context(|| "failed to read file".to_string())),
                };
                let (ck_filename, sum, binary_check) = match gnu_re.captures(&line) {
                    Some(caps) => (
                        caps.name("fileName").unwrap().as_str(),
                        caps.name("digest").unwrap().as_str().to_ascii_lowercase(),
                        caps.name("binary").unwrap().as_str() == "*",
                    ),
                    None => match bsd_re.captures(&line) {
                        Some(caps) => (
                            caps.name("fileName").unwrap().as_str(),
                            caps.name("digest").unwrap().as_str().to_ascii_lowercase(),
                            true,
                        ),
                        None => {
                            bad_format += 1;
                            if options.strict {
                                return Err(HashsumError::InvalidFormat.into());
                            }
                            if options.warn {
                                show_warning!(
                                    "{}: {}: improperly formatted {} checksum line",
                                    filename.maybe_quote(),
                                    i + 1,
                                    A::NAME
                                );
                            }
                            continue;
                        }
                    },
                };
                let f = match File::open(ck_filename) {
                    Err(_) => {
                        failed_open_file += 1;
                        println!(
                            "{}: {}: No such file or directory",
                            uucore::util_name(),
                            ck_filename
                        );
                        println!("{ck_filename}: FAILED open or read");
                        continue;
                    }
                    Ok(file) => file,
                };
                let ckf = BufReader::new(Box::new(f) as Box<dyn Read>);
                let (real_sum, _size) = algo
                    .sum(ckf, binary_check)
                    .map_err_context(|| "failed to read input".to_string())?;

                let real_sum = uucore::sum::SumOutput::fmt(&real_sum);

                // FIXME: Filenames with newlines should be treated specially.
                // GNU appears to replace newlines by \n and backslashes by
                // \\ and prepend a backslash (to the hash or filename) if it did
                // this escaping.
                // Different sorts of output (checking vs outputting hashes) may
                // handle this differently. Compare carefully to GNU.
                // If you can, try to preserve invalid unicode using OsStr(ing)Ext
                // and display it using uucore::display::print_verbatim(). This is
                // easier (and more important) on Unix than on Windows.
                if sum == real_sum {
                    if !options.quiet {
                        println!("{ck_filename}: OK");
                    }
                } else {
                    if !options.status {
                        println!("{ck_filename}: FAILED");
                    }
                    failed_cksum += 1;
                }
            }
        } else {
            let (sum, size) = algo
                .sum(file, options.binary)
                .map_err_context(|| "failed to read input".to_string())?;

            println!("{}", algo.format(options.tag, sum, size, Some(filename)));
        }
    }
    if !options.status {
        match bad_format.cmp(&1) {
            Ordering::Equal => show_warning!("{} line is improperly formatted", bad_format),
            Ordering::Greater => show_warning!("{} lines are improperly formatted", bad_format),
            Ordering::Less => {}
        };
        if failed_cksum > 0 {
            show_warning!("{} computed checksum did NOT match", failed_cksum);
        }
        match failed_open_file.cmp(&1) {
            Ordering::Equal => show_warning!("{} listed file could not be read", failed_open_file),
            Ordering::Greater => {
                show_warning!("{} listed files could not be read", failed_open_file);
            }
            Ordering::Less => {}
        }
    }

    Ok(())
}
