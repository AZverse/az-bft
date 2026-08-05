use azbft_devnet::build_fixture_set;
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let output = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("usage: generate_conformance <new-output-directory>")?;
    if arguments.next().is_some() {
        return Err("usage: generate_conformance <new-output-directory>".into());
    }
    if output.exists() {
        return Err(format!("refusing to overwrite existing path {}", output.display()).into());
    }

    fs::create_dir_all(&output)?;
    for artifact in build_fixture_set()? {
        let path = output.join(artifact.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, artifact.bytes)?;
        println!("wrote {}", path.display());
    }
    Ok(())
}
