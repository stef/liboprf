# liboprf

This library implements the basic OPRF(ristretto255, SHA-512) variant
from the IRTF CFRG Draft: https://github.com/cfrg/draft-irtf-cfrg-voprf/

Additionally it implements a threshold OPRF variant based on
https://eprint.iacr.org/2017/363 by Krawczyk et al. which is
compatible with the CFRG OPRF(ristretto255, SHA-512) variant.

For the threshold OPRF this library also provides distributed
key-generation (DKG) implementation that is based on a trusted
party handling the broadcasts necessary for the DKG, this is
based on the JF-DKG (fig 1.) a variant on Pedersens DKG from
the paper "Secure Distributed Key Generation for Discrete-Log
Based Cryptosystems" by R. Gennaro, S. Jarecki, H. Krawczyk,
and T.  Rabin.

Additionally a python wrapper is provided, which can be installed
using `pip install pyoprf`

This library depends on libsodium.
