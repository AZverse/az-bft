# Security Policy

## Supported versions

| Version | Support |
|---|---|
| `0.1.0-alpha` | Best-effort alpha security fixes |
| Older or untagged snapshots | Not supported |

AZBFT is alpha software for protocol evaluation and integration development.
It is not a production node distribution. The public repository excludes
production networking, execution clients, validator admission, operator
configuration, deployment topology and real validator credentials.

## Reporting a vulnerability

Use the public repository's GitHub **private vulnerability reporting** form:
open the repository's **Security** tab and select **Report a vulnerability**.
Include affected commit or tag, impact, reproduction steps, relevant artifacts
and a safe way to coordinate follow-up.

Do not open a public issue, discussion or pull request for an undisclosed
vulnerability. Do not include real validator keys, private endpoints,
credentials or private-chain configuration in a report.

Private vulnerability reporting MUST be enabled before the repository is made
public. If the private form is not available, wait for the project owner to
activate the channel rather than disclosing the issue publicly.

## Scope and response

Reports about consensus safety, certificate verification, canonical encoding,
crash-safety state, checkpoint validation, reconfiguration authorization,
finality transcripts or the offline verifier are in scope.

Production transport, execution clients and private deployment systems are not
distributed here and must be reported through their owning private channels.
The alpha project provides no response-time or bounty guarantee. Maintainers
will acknowledge actionable reports privately, reproduce them against a named
version, coordinate a fix and disclose only after affected users have a safe
upgrade path.
