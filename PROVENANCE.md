# Provenance

AZBFT is developed by AZVerses. Its protocol design is informed by openly
published Byzantine fault-tolerant consensus research, public cryptographic
standards, and the implementation references disclosed below.

## Public protocol and cryptographic references

- Maofan Yin, Dahlia Malkhi, Michael K. Reiter, Guy Golan Gueta, and Ittai Abraham, [HotStuff: BFT Consensus with Linearity and Responsiveness](https://arxiv.org/abs/1803.05069).
- Rati Gelashvili, Lefteris Kokoris-Kogias, Alberto Sonnino, Alexander Spiegelman, and Zhuolun Xiang, [Jolteon and Ditto: Network-Adaptive Efficient Consensus with Asynchronous Fallback](https://arxiv.org/abs/2106.10362).
- Dan Boneh, Manu Drijvers, and Gregory Neven, [BLS Signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).
- Ethereum Foundation, [EIP-2333: BLS12-381 Key Generation](https://eips.ethereum.org/EIPS/eip-2333).

## Monad-BFT reference boundary

During development, publicly available
[Monad-BFT](https://github.com/category-labs/monad-bft) documentation and source
implementation were reviewed and compared as architectural and behavioral
references, including its sans-I/O organization around events, state
transitions, and commands. Monad-BFT is a separate project published under
[GPL-3.0](https://github.com/category-labs/monad-bft/blob/master/LICENSE).

This repository does not declare a dependency on, link to, vendor, or distribute Monad-BFT source code. Apache-2.0 applies to the code and other
materials contained in this repository.

This statement records development references and the current repository
boundary. It does not claim a clean-room development process and is not a
legal opinion.

Third-party libraries are used under the licenses recorded in
[THIRD_PARTY.md](THIRD_PARTY.md).
