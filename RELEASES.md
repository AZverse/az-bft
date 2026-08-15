# Release Policy

AZBFT publishes source releases of the transport-neutral consensus core.

## Versioning

Cargo packages use Semantic Versioning. Git tags add a `v` prefix. For the first
alpha, all workspace crates use `0.1.0-alpha` and the corresponding annotated
tag is `v0.1.0-alpha`.

Before `1.0.0`, the public Rust API, canonical encoding and protocol behavior
may change. A release that changes canonical bytes, a hash/signature preimage,
certificate validation, safety rules or finality MUST:

1. update `CHANGELOG.md`;
2. add or update a versioned directory under `spec/`;
3. publish regenerated conformance fixtures;
4. explain compatibility and migration consequences.

The project does not publish these crates to crates.io in this release.
A public tag identifies only the source tree in this repository. It does not
communicate deployment, integration, or operator rollout status.

## Alpha release checklist

The release owner MUST confirm all of the following before creating the public
tag:

- [ ] The participant source-origin confirmation is completed by every original
  implementation participant. The record includes exact public revisions and
  review time ranges for implementation references, whether any third-party
  source was copied, translated line by line or structurally rewritten, and
  whether any unpublished patch was used.
- [ ] Any newly identified design or source references are reflected truthfully
  in `PROVENANCE.md` and the internal provenance record.
- [ ] GitHub private vulnerability reporting is enabled for the public
  repository and `SECURITY.md` points to the active private channel.
- [ ] Cargo versions, changelog, specification directory, fixtures and proposed
  tag all identify `v0.1.0-alpha` consistently.
- [ ] The public remote exists and GitHub Actions passes from the public remote
  using a clean checkout with the locked dependency graph.
- [ ] The release owner creates a signed annotated tag for `v0.1.0-alpha`.
- [ ] Conformance fixtures regenerate byte-for-byte and the offline verifier
  accepts the valid transcript and rejects the corrupted transcript.
- [ ] Commit author and committer metadata use the approved project identity and
  contain no assistant attribution or personal email address.
- [ ] The release owner has reviewed and approved the final diff, annotated tag
  message and public repository description.

A local candidate commit is not a release. Creating a remote, pushing, merging
or tagging requires a separate owner instruction.

## Supported release line

Only the latest alpha source release receives best-effort fixes. Security or
correctness fixes may require a coordinated incompatible upgrade while the
protocol remains pre-mainnet and pre-stable.
