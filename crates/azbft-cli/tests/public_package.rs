use std::fs;
use std::path::Path;

#[test]
fn public_package_has_required_identity_boundary_and_license_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");

    for name in [
        "LICENSE",
        "NOTICE",
        "PROVENANCE.md",
        "THIRD_PARTY.md",
        "README.md",
        "STATUS.md",
    ] {
        assert!(root.join(name).is_file(), "missing {name}");
    }

    let readme = fs::read_to_string(root.join("README.md")).expect("read README");
    assert!(
        readme.contains("AZBFT is the BFT consensus engine powering the permissioned AZ Layer 1.")
    );
    assert!(readme.contains("Production transport is not included in this repository."));
    assert!(readme.contains("v0.1.0-alpha"));

    let status = fs::read_to_string(root.join("STATUS.md")).expect("read STATUS");
    assert!(status.contains("Alpha release"));
    assert!(status.contains("Jailed-validator state is not carried in checkpoints"));
    assert!(status.contains("Equivocation evidence persistence is a host responsibility"));
}
#[test]
fn crypto_host_and_test_api_require_opt_in_features() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let crypto = root.join("crates/azbft-crypto");

    let manifest = fs::read_to_string(crypto.join("Cargo.toml")).expect("read crypto manifest");
    assert!(manifest.contains("default = []"));
    assert!(manifest.contains("host-extensions = []"));
    assert!(manifest.contains("insecure-test-keys = []"));

    let domain = fs::read_to_string(crypto.join("src/domain.rs")).expect("read domains");
    assert!(
        domain
            .matches("#[cfg(feature = \"host-extensions\")]")
            .count()
            >= 6
    );

    for source in ["src/keypair.rs", "src/bls.rs"] {
        let text = fs::read_to_string(crypto.join(source)).expect("read key source");
        assert!(text.contains("feature = \"insecure-test-keys\""));
        let without_doc_prefix = text.replace("///", " ");
        let normalized = without_doc_prefix
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(normalized.contains("must never be used for production keys"));
    }
}
#[test]
fn consensus_scheme_documentation_matches_the_implemented_boundary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");

    let state =
        fs::read_to_string(root.join("crates/azbft-core/src/state.rs")).expect("read state");
    let bls =
        fs::read_to_string(root.join("crates/azbft-crypto/src/bls.rs")).expect("read BLS source");
    let cert =
        fs::read_to_string(root.join("crates/azbft-types/src/cert.rs")).expect("read cert source");

    assert!(state.contains("QC forming scheme"));
    assert!(state.contains("Compatibility constructors form secp256k1 QCs"));
    assert!(state.contains("Timeout votes and TCs always use secp256k1"));
    assert!(bls.contains("BLS aggregate signatures are wired into QC formation"));
    assert!(!bls.contains("not wired into QC / cert formation"));
    assert!(cert.contains("QC forming scheme"));
}

fn path_identifies_monad_vendor_tree(path: &Path) -> bool {
    let inspected = if path.extension().is_some() {
        path.parent().unwrap_or(path)
    } else {
        path
    };
    let mut parent_is_vendor_root = false;

    for component in inspected.components() {
        let Some(component) = component.as_os_str().to_str() else {
            parent_is_vendor_root = false;
            continue;
        };
        let component = component.to_ascii_lowercase();
        if component == "monad-bft"
            || component == "monad_bft"
            || (parent_is_vendor_root && component.starts_with("monad"))
        {
            return true;
        }
        parent_is_vendor_root = matches!(
            component.as_str(),
            "vendor" | "vendors" | "submodules" | "third_party"
        );
    }

    false
}

fn cargo_references_monad(text: &str) -> bool {
    text.lines().any(|line| {
        line.split('#')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("monad")
    })
}

fn rust_references_monad_code(text: &str) -> bool {
    text.lines().any(|line| {
        let code = line.split("//").next().unwrap_or("").trim();
        if code.is_empty() {
            return false;
        }

        code.contains("use monad_")
            || code.contains("extern crate monad_")
            || code
                .split(|character: char| {
                    !(character.is_ascii_alphanumeric() || character == '_' || character == ':')
                })
                .filter_map(|token| token.split_once("::").map(|(crate_name, _)| crate_name))
                .any(|crate_name| crate_name.starts_with("monad_"))
    })
}

fn rust_contains_gpl_program_header(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    text.contains("gnu general public license") || text.contains("this program is free software")
}

fn contains_forbidden_monad_code_coupling(relative_path: &Path, text: &str) -> bool {
    if path_identifies_monad_vendor_tree(relative_path) {
        return true;
    }

    let file_name = relative_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if matches!(file_name, "Cargo.toml" | "Cargo.lock") {
        return cargo_references_monad(text);
    }

    relative_path
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("rs")
        && (rust_references_monad_code(text) || rust_contains_gpl_program_header(text))
}

fn assert_public_repository_has_no_monad_code_coupling(root: &Path, dir: &Path) {
    for entry in fs::read_dir(dir).expect("read public repository directory") {
        let path = entry.expect("read public repository entry").path();
        let relative_path = path.strip_prefix(root).unwrap_or(&path);

        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if matches!(name, ".git" | "target") {
                continue;
            }
            assert!(
                !path_identifies_monad_vendor_tree(relative_path),
                "{} identifies a forbidden Monad vendor or submodule tree",
                relative_path.display()
            );
            assert_public_repository_has_no_monad_code_coupling(root, &path);
            continue;
        }

        if path.ends_with("crates/azbft-cli/tests/public_package.rs") {
            continue;
        }

        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let is_rust = path.extension().and_then(|extension| extension.to_str()) == Some("rs");
        if !is_rust && !matches!(file_name, "Cargo.toml" | "Cargo.lock") {
            continue;
        }

        let text = fs::read_to_string(&path).expect("read public repository source");
        assert!(
            !contains_forbidden_monad_code_coupling(relative_path, &text),
            "{} contains forbidden Monad code coupling",
            relative_path.display()
        );
    }
}

#[test]
fn monad_disclosure_is_allowed_but_code_coupling_is_rejected() {
    assert!(!contains_forbidden_monad_code_coupling(
        Path::new("PROVENANCE.md"),
        "Monad-BFT is a separate GPL-3.0 project.",
    ));
    assert!(contains_forbidden_monad_code_coupling(
        Path::new("Cargo.toml"),
        "consensus = { package = \"monad-consensus\", git = \"https://github.com/category-labs/monad-bft\" }",
    ));
    assert!(contains_forbidden_monad_code_coupling(
        Path::new("src/lib.rs"),
        "use monad_consensus::State;",
    ));
    assert!(contains_forbidden_monad_code_coupling(
        Path::new("vendor/monad-bft/src/lib.rs"),
        "pub struct State;",
    ));
    assert!(contains_forbidden_monad_code_coupling(
        Path::new("src/lib.rs"),
        "This program is free software: you can redistribute it and/or modify it.",
    ));
}

#[test]
fn public_provenance_discloses_monad_reference_boundary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let provenance = fs::read_to_string(root.join("PROVENANCE.md")).expect("read provenance");

    for required in [
        "Monad-BFT",
        "GPL-3.0",
        "does not declare a dependency on, link to, vendor, or distribute Monad-BFT source code",
        "does not claim a clean-room development process",
    ] {
        assert!(
            provenance.contains(required),
            "PROVENANCE.md must disclose: {required}"
        );
    }
}
#[test]
fn public_repository_has_no_monad_code_coupling() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    assert_public_repository_has_no_monad_code_coupling(root, root);
}

#[test]
fn public_release_infrastructure_is_versioned_and_complete() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let normalize = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");

    let readme = fs::read_to_string(root.join("README.md")).expect("read README");
    assert!(readme.contains("## Project documentation"));
    for target in [
        "spec/v0.1.0-alpha/README.md",
        "STATUS.md",
        "ROADMAP.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "RELEASES.md",
        "CHANGELOG.md",
        "PROVENANCE.md",
    ] {
        let link_target = format!("]({target})");
        assert!(
            readme.contains(&link_target),
            "README.md must link to {target}"
        );
    }

    for name in [
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "RELEASES.md",
        "ROADMAP.md",
        "SECURITY.md",
        "spec/v0.1.0-alpha/README.md",
        "spec/v0.1.0-alpha/protocol.md",
        "spec/v0.1.0-alpha/host-interface.md",
        "spec/v0.1.0-alpha/encoding.md",
        "spec/v0.1.0-alpha/recovery-and-reconfiguration.md",
        "fixtures/v0.1.0-alpha/README.md",
        ".github/workflows/ci.yml",
    ] {
        assert!(root.join(name).is_file(), "missing release artifact {name}");
    }

    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
    assert!(manifest.contains("version = \"0.1.0-alpha\""));

    for crate_name in [
        "azbft-cli",
        "azbft-core",
        "azbft-crypto",
        "azbft-devnet",
        "azbft-safety",
        "azbft-types",
        "azbft-verifier",
    ] {
        let path = root.join("crates").join(crate_name).join("Cargo.toml");
        let manifest = fs::read_to_string(path).expect("read crate manifest");
        assert!(
            manifest.contains("publish = false"),
            "{crate_name} must remain excluded from crates.io publication"
        );
    }

    let security = fs::read_to_string(root.join("SECURITY.md")).expect("read SECURITY");
    assert!(security.contains("private vulnerability reporting"));
    assert!(security.contains("Do not open a public issue"));

    let contributing =
        fs::read_to_string(root.join("CONTRIBUTING.md")).expect("read contributing policy");
    let contributing = normalize(&contributing);
    assert!(contributing.contains("External pull requests are not accepted for v0.1.0-alpha"));
    assert!(contributing.contains("private vulnerability reporting"));
    assert!(contributing.contains("contribution licensing"));
    assert!(contributing.contains("code of conduct"));
    assert!(contributing.contains("maintainer governance"));

    let roadmap = fs::read_to_string(root.join("ROADMAP.md")).expect("read roadmap");
    let roadmap = normalize(&roadmap);
    for required in [
        "Public alpha release",
        "Beta protocol assurance",
        "Mainnet readiness",
        "Quint or TLA+",
        "Twins",
        "network partition and heal",
        "message duplication, reordering and delay",
        "Host recovery conformance",
        "jailed-validator and consumed-evidence state",
        "timeout certificates also use BLS",
        "independent security assessment",
    ] {
        assert!(
            roadmap.contains(required),
            "ROADMAP.md must include: {required}"
        );
    }
    for forbidden in ["downstream private integration", "exact release commit"] {
        assert!(
            !roadmap.contains(forbidden),
            "ROADMAP.md must not expose internal version policy: {forbidden}"
        );
    }

    let status = fs::read_to_string(root.join("STATUS.md")).expect("read STATUS");
    let status = normalize(&status);
    assert!(status.contains("Consumed-evidence state is not carried in checkpoints"));

    let releases = fs::read_to_string(root.join("RELEASES.md")).expect("read releases");
    let releases = normalize(&releases);
    assert!(releases.contains("participant source-origin confirmation"));
    assert!(releases.contains("exact public revisions and review time ranges"));
    assert!(releases.contains("A public tag identifies only the source tree in this repository"));
    assert!(releases
        .contains("It does not communicate deployment, integration, or operator rollout status"));
    for forbidden in [
        "downstream AZ integration",
        "exact release commit",
        "version used by the chain",
    ] {
        assert!(
            !releases.contains(forbidden),
            "RELEASES.md must not expose internal version policy: {forbidden}"
        );
    }
    assert!(releases.contains("GitHub Actions passes from the public remote"));
    assert!(releases.contains("signed annotated tag"));
    assert!(releases.contains("v0.1.0-alpha"));

    let spec = fs::read_to_string(root.join("spec/v0.1.0-alpha/README.md"))
        .expect("read specification index");
    assert!(spec.contains("Normative scope"));
    assert!(spec.contains("Host responsibility"));

    let fixtures = fs::read_to_string(root.join("fixtures/v0.1.0-alpha/README.md"))
        .expect("read fixture documentation");
    assert!(fixtures.contains("must never be used for production keys"));
    assert!(fixtures.contains("finality-valid.azbft"));
    assert!(fixtures.contains("finality-invalid-qc.azbft"));

    let workflow =
        fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("read CI workflow");
    for command in [
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings",
        "cargo doc --workspace --all-features --no-deps --locked",
        "RUSTDOCFLAGS: -D warnings",
        "cargo check --workspace --locked",
        "cargo test --workspace --locked",
        "cargo check -p azbft-crypto --no-default-features",
        "cargo test -p azbft-crypto --features host-extensions,insecure-test-keys",
        "cargo test -p azbft-cli --test public_package",
        "git clone --no-local",
    ] {
        assert!(workflow.contains(command), "CI is missing `{command}`");
    }
}
