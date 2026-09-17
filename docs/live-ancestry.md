# Certified live ancestry import

`ConsensusCore::import_live_ancestors` imports at most 64 same-epoch ordinary
blocks, parent first, authenticated by a QC over the final block and each
child's parent QC. The first parent must be available and certified. When a
committed frontier exists, that parent must be the frontier or its descendant.
The host must trim committed prefixes before calling this API. At an empty
epoch root, only the exact genesis certificate is accepted.

Validation covers IDs, certificate quorum signatures and rounds, parent links,
height/time continuity, authors and epochs before any insertion. Reconfiguration
blocks and their immediate children are intentionally excluded from this first
version; use the existing committed-history/ECC recovery path for transitions.

Successful import changes only the block tree. It emits no command, advances no
round or high QC, and does not change safety watermarks. The host then retries
the waiting authenticated proposal through normal consensus handling. This API
does not establish finality or license execution of uncommitted blocks.

`live_ancestors(target, limit)` exposes a bounded parent-first tree lookup for a
host's recovery server. A short response means only that the remaining parent
was not in this tree. The host owns protocol negotiation, byte limits, peer
selection, retries, payload verification, deduplication and memory retention.

This change is a prerequisite, not a complete network recovery implementation.
End-to-end recovery requires the host transport and driver integration.
