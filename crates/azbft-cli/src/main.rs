#![forbid(unsafe_code)]

use azbft_devnet::{run_devnet, DevnetConfig};
use azbft_verifier::{decode_transcript, encode_transcript, verify_transcript};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "azbft", version, about = "Local AZBFT devnet and proof tools")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run deterministic in-memory devnet scenarios.
    Devnet {
        #[command(subcommand)]
        command: DevnetCommand,
    },
    /// Verify a transcript without opening any network connection.
    Verify { path: PathBuf },
    /// Inspect one verified finalized block by height.
    Inspect {
        path: PathBuf,
        #[arg(long)]
        height: u64,
    },
}

#[derive(Subcommand)]
enum DevnetCommand {
    /// Run the real consensus core and write a proof transcript.
    Run {
        #[arg(long, default_value_t = 4)]
        validators: usize,
        #[arg(long)]
        blocks: u64,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Devnet {
            command:
                DevnetCommand::Run {
                    validators,
                    blocks,
                    seed,
                    output,
                },
        } => {
            let transcript = run_devnet(DevnetConfig {
                validators,
                blocks,
                seed,
            })
            .map_err(|error| error.to_string())?;
            verify_transcript(&transcript).map_err(|error| error.to_string())?;
            let bytes = encode_transcript(&transcript).map_err(|error| error.to_string())?;
            fs::write(&output, bytes)
                .map_err(|error| format!("cannot write {}: {error}", output.display()))?;
            println!(
                "wrote {} finalized blocks to {}",
                transcript.finalized.len(),
                output.display()
            );
        }
        Command::Verify { path } => {
            let transcript = load(&path)?;
            let summary = verify_transcript(&transcript).map_err(|error| error.to_string())?;
            println!(
                "verified {} finalized blocks, heights {}..={}, tip={:?}",
                summary.finalized_blocks,
                summary.first_height,
                summary.last_height,
                summary.last_block_id
            );
        }
        Command::Inspect { path, height } => {
            let transcript = load(&path)?;
            verify_transcript(&transcript).map_err(|error| error.to_string())?;
            let record = transcript
                .finalized
                .iter()
                .find(|record| record.block.height == height)
                .ok_or_else(|| format!("height {height} is not present in the transcript"))?;
            println!(
                "height={} round={} block_id={:?} application_commitment={:?}",
                record.block.height,
                record.block.round.0,
                record.block.id(),
                record.application_commitment
            );
        }
    }
    Ok(())
}

fn load(path: &PathBuf) -> Result<azbft_devnet::DevnetTranscript, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    decode_transcript(&bytes).map_err(|error| error.to_string())
}
