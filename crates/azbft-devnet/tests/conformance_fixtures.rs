use azbft_devnet::build_fixture_set;
use std::fs;
use std::path::Path;

#[test]
fn committed_conformance_fixtures_match_the_deterministic_builder() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let fixture_root = root.join("fixtures/v0.1.0-alpha");

    let artifacts = build_fixture_set().expect("build deterministic fixture set");
    assert!(!artifacts.is_empty());
    for artifact in artifacts {
        let committed = fs::read(fixture_root.join(artifact.relative_path))
            .unwrap_or_else(|error| panic!("read {}: {error}", artifact.relative_path));
        assert_eq!(
            committed, artifact.bytes,
            "{} drifted",
            artifact.relative_path
        );
    }
}
