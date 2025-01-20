# liboprf

This library implements the basic OPRF(ristretto255, SHA-512) variant
from the IRTF CFRG Draft: https://github.com/cfrg/draft-irtf-cfrg-voprf/

Additionally it implements a threshold OPRF variant based on
https://eprint.iacr.org/2017/363 by Krawczyk et al. which is
compatible with the CFRG OPRF(ristretto255, SHA-512) variant.

Furthermore it also implements the 3hashTDH from
https://eprint.iacr.org/2024/1455 "Threshold PAKE with Security
against Compromise of all Servers" by Gu, Jarecki, Kedzior, Nazarian,
Xu. This too is compatible with the CFRG OPRF(ristretto255, SHA-512)
variant.

For the threshold OPRF this library also provides distributed
key-generation (DKG) implementation that is based on a trusted
party handling the broadcasts necessary for the DKG, this is
based on the JF-DKG (fig 1.) a variant on Pedersens DKG from
the paper "Secure Distributed Key Generation for Discrete-Log
Based Cryptosystems" by R. Gennaro, S. Jarecki, H. Krawczyk,
and T. Rabin.

In order to update a threshold OPRF instantiation this library contains
the multi-party multiplication is based on Fig. 2 from R. Gennaro,
M. O. Rabin, and T. Rabin. "Simplified VSS and fact-track multiparty
computations with applications to threshold cryptography" In
B. A. Coan and Y. Afek, editors, 17th ACM PODC, pages 101–111. ACM,
June / July 1998.

Additionally a python wrapper is provided, which can be installed
using `pip install pyoprf`

This library depends on libsodium.

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund
established by [NLnet](https://nlnet.nl) with financial support from the
European Commission's [Next Generation Internet](https://ngi.eu) program. Learn
more at the [NLnet project page](https://nlnet.nl/project/ThresholdOPRF).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)
