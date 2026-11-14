//! WASI entry point: stdin JSON in, stdout JSON out. Non-zero exit on malformed input.

use std::io::{Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read stdin: {e}");
        return ExitCode::from(2);
    }
    match acceptance_verifier_wasm::run(&input) {
        Ok(out) => {
            let mut stdout = std::io::stdout();
            if writeln!(stdout, "{out}").is_err() {
                return ExitCode::from(3);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
