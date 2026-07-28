# Vendored pageant 0.2.0

This directory is the crates.io `pageant` 0.2.0 source from upstream commit
`f6b9e6479664696db4cd9c507c6725c1ab7c8aeb` in
`warp-tech/russh/pageant`, licensed Apache-2.0.

Sloosh carries one source change in `src/interface.rs`: an edition-2024
let-chain is expressed as nested `if` statements. The published crate declares
Rust 1.85 but the let-chain syntax was stabilized later; the equivalent form
keeps Sloosh's MSRV while preserving both Pageant transports. Remove the patch
when an upstream release passes `cargo +1.85.0 check`.
