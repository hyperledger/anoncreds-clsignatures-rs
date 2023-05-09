# CL Signatures Rust

CL Signatures, cryptographic signatures with efficient protocols are a form of
digital signature invented by [Jan Camenisch] and [Anna Lysyanskaya] (papers:
[2001], [2003], [2004]). In addition to being secure digital signatures, they
need to allow for the efficient implementation of two protocols:

- A protocol for computing a digital signature in a secure two-party computation protocol.
- A protocol for proving knowledge of a digital signature in a zero-knowledge protocol.

In applications, the first protocol allows a signer to possess the signing key
to issue a signature to a user (the signature owner) without learning all the
messages being signed or the complete signature.

The second protocol allows the signature owner to prove that he has a signature
on many messages without revealing the signature and only a (possibly) empty
subset of the messages.

CL Signatures are the basis of [Hyperledger AnonCreds v1.0] and the implementation in this repository
is used in the [Hyperledger AnonCreds Rust implementation].

This implementation of CL Signatures was initially in the [Hyperledger Ursa]
project.

[Jan Camenisch]: https://en.wikipedia.org/wiki/Jan_Camenisch
[Anna Lysyanskaya]: https://en.wikipedia.org/wiki/Anna_Lysyanskaya
[2001]: https://eprint.iacr.org/2001/019.pdf
[2003]: https://citeseerx.ist.psu.edu/document?repid=rep1&type=pdf&doi=764e89025d68eda8010732285add5a4296f4e0ae
[2004]: https://cs.brown.edu/~alysyans/papers/cl04.pdf
[Hyperledger AnonCreds v1.0]: https://hyperledger.github.io/anoncreds-spec/
[Hyperledger AnonCreds Rust implementation]: https://github.com/hyperledger/anoncreds-rs
[Hyperledger Ursa]: https://github.com/hyperledger/ursa

## Rust Crate

This crate implements a version of the CL signature scheme.

To start, all that is needed is to add this to your `Cargo.toml`.

```toml
[dependencies]
anoncreds-clsignatures = "0.1"
```

For an example of using this crate, see the [Hyperledger AnonCreds Rust
implementation] repository.
