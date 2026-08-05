# Canonical Encoding and Cryptography

## Integer and byte order

All protocol structures use Borsh canonical encoding. Fixed-width integers use
Borsh little-endian encoding. Vector lengths and enum discriminants follow
Borsh. Struct fields are encoded in declaration order. Implementations MUST NOT
substitute JSON, platform-native layout or unordered-map iteration in a signed
or hashed preimage.

`Hash` is 32 bytes, `NodeId` is 20 bytes and `Round` is a Borsh-encoded `u64`.
A `NodeId` is the first 20 bytes of `BLAKE3(secp256k1_public_key_bytes)`.

## Identifiers and inner digests

For a Borsh-serializable value `x`:

```text
blake3_id(x) = BLAKE3(BORSH(x))
block_id     = blake3_id(Block)
vote_digest  = blake3_id((block_id, round))
timeout_digest = blake3_id((epoch, round))
```

The block identifier therefore commits to header version, height, timestamp,
epoch, round, parent QC, payload hash, author and optional reconfiguration.

## Signing domains

Consensus signing uses a one-byte stable domain tag:

| Domain | Tag |
|---|---:|
| Vote | 1 |
| Timeout | 2 |
| Proposal | 3 |
| Reconfiguration | 5 |
| Application hash | 6 |

Tags 4, 7 and 8 are reserved Host-extension domains and are absent unless the
`host-extensions` feature is explicitly enabled.

The domain-separated digest is:

```text
signing_digest(domain, message) = BLAKE3(domain_tag || message)
```

secp256k1 signatures are deterministic ECDSA signatures over that 32-byte
prehash. BLS signatures use BLS12-381 min-pk with signatures in G2 and apply the
same domain-separated message bytes through the implementation's fixed ciphersuite.

## Signed preimages

- Proposal: `BORSH(Proposal)` in the Proposal domain.
- Vote and QC contribution: the 32 raw bytes of `vote_digest(block_id, round)`
  in the Vote domain.
- Timeout and TC contribution: the 32 raw bytes of
  `timeout_digest(epoch, round)` in the Timeout domain.
- Reconfiguration: the canonical next validator set and epoch, plus the jail
  record when present, in the Reconfiguration domain.
- Application-hash statements: their canonical statement bytes in the
  Application-hash domain.

A signature from one domain MUST NOT verify in another domain.

## Certificate encoding

`AggSig` is a Borsh enum:

- discriminant `0`: `Secp`, a strictly ascending list of distinct
  `(NodeId, signature_bytes)` entries;
- discriminant `1`: `Bls`, one 96-byte compressed aggregate signature and a
  strictly ascending distinct signer list.

QC verification selects the scheme from this encoded variant and requires
quorum stake. A BLS member public key is a 48-byte compressed key and its
proof-of-possession is a 96-byte signature. A missing or invalid PoP prevents
validator-set adoption.

`v0.1.0-alpha` timeout votes and TCs are always secp256k1. Changing the TC scheme
or any canonical bytes above requires a versioned compatibility disclosure.

## Header version

Blocks in this specification use `header_version = 2`. Receivers reject other
versions. Height must increment exactly; timestamps must increase, must not
advance more than 60,000 ms from their parent, and on the live path must not be
more than 5,000 ms ahead of the receiver wall clock.
