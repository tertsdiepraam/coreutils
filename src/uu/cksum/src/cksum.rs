// This file is part of the uutils coreutils package.
//
// (c) Michael Gehring <mg@ebfe.org>
//
//  For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

// spell-checker:ignore (ToDO) fname, algo
use clap::{crate_version, Arg, Command};
use std::fs::File;
use std::io::{stdin, Read};
use std::path::{Path, PathBuf};
use uucore::display::Quotable;
use uucore::{
    error::{FromIo, UResult},
    format_usage,
    sum::{Blake2b, Md5, Sha1, Sha224, Sha256, Sha384, Sha512, Sm3, SumAlgorithm, BSD, CRC, SYSV},
};
use uucore::{show, show_if_err};

const USAGE: &str = "{} [OPTIONS] [FILE]...";
const ABOUT: &str = "Print CRC and size for each file";

fn cksum_with_algorithm<'a>(
    algo_str: &str,
    paths: Option<impl IntoIterator<Item = &'a Path>>,
) -> UResult<()> {
    match algo_str {
        "sysv" => cksum(SYSV, paths),
        "bsd" => cksum(BSD, paths),
        "crc" => cksum(CRC, paths),
        "md5" => cksum(Md5, paths),
        "sha1" => cksum(Sha1, paths),
        "sha224" => cksum(Sha224, paths),
        "sha256" => cksum(Sha256, paths),
        "sha384" => cksum(Sha384, paths),
        "sha512" => cksum(Sha512, paths),
        "blake2b" => cksum(Blake2b, paths),
        "sm3" => cksum(Sm3, paths),
        _ => unreachable!("unknown algorithm: clap should have prevented this case"),
    }
}

fn cksum<'a>(
    algo: impl SumAlgorithm,
    paths: Option<impl IntoIterator<Item = &'a Path>>,
) -> UResult<()> {
    match paths {
        Some(paths) => {
            for path in paths {
                show_if_err!(cksum_path(&algo, path));
            }
            Ok(())
        }
        None => cksum_reader(&algo, stdin(), None),
    }
}

fn cksum_path(algo: &impl SumAlgorithm, path: &Path) -> UResult<()> {
    if path == Path::new("-") {
        cksum_reader(algo, stdin(), None)
    } else {
        let file =
            File::open(path).map_err_context(|| format!("could not open file {}", path.quote()))?;
        cksum_reader(algo, file, Some(path))
    }
}

fn cksum_reader(algo: &impl SumAlgorithm, reader: impl Read, path: Option<&Path>) -> UResult<()> {
    let (sum, size) = algo.sum(reader)?;
    println!("{}", algo.format(true, sum, size, path));

    Ok(())
}

mod options {
    pub static FILE: &str = "file";
    pub static ALGORITHM: &str = "algorithm";
}

const ALGORITHM_HELP_DESC: &str =
    "DIGEST determines the digest algorithm and default output format:\n\
\n\
-a=sysv:    (equivalent to sum -s)\n\
-a=bsd:     (equivalent to sum -r)\n\
-a=crc:     (equivalent to cksum)\n\
-a=md5:     (equivalent to md5sum)\n\
-a=sha1:    (equivalent to sha1sum)\n\
-a=sha224:  (equivalent to sha224sum)\n\
-a=sha256:  (equivalent to sha256sum)\n\
-a=sha384:  (equivalent to sha384sum)\n\
-a=sha512:  (equivalent to sha512sum)\n\
-a=blake2b: (equivalent to b2sum)\n\
-a=sm3:     (only available through cksum)\n";

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let args = args.collect_ignore();

    let mut matches = uu_app().try_get_matches_from(args)?;

    let algo_str: String = matches
        .remove_one::<String>(options::ALGORITHM)
        .unwrap_or("crc".into());

    let paths = matches
        .get_many::<PathBuf>(options::FILE)
        .map(|iter| iter.map(AsRef::as_ref));

    cksum_with_algorithm(&algo_str, paths)
}

pub fn uu_app() -> Command {
    Command::new(uucore::util_name())
        .version(crate_version!())
        .about(ABOUT)
        .override_usage(format_usage(USAGE))
        .infer_long_args(true)
        .arg(
            Arg::new(options::FILE)
                .hide(true)
                .action(clap::ArgAction::Append)
                .value_hint(clap::ValueHint::FilePath)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new(options::ALGORITHM)
                .long(options::ALGORITHM)
                .short('a')
                .help("select the digest type to use. See DIGEST below")
                .value_name("ALGORITHM")
                .value_parser([
                    "sysv", "bsd", "crc", "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
                    "blake2b", "sm3",
                ]),
        )
        .after_help(ALGORITHM_HELP_DESC)
}
