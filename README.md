# liboprf

## Overview

liboprf is a library for Oblivious Pseudorandom Functions (OPRFs), including support for Threshold OPRFs. It is designed to make advanced cryptographic protocols easy to integrate across applications.

## What is an OPRF?

An Oblivious Pseudorandom Function (OPRF) is a two-party cryptographic primitive involving a sender and receiver who jointly compute a function, `F`, in such a way that:
- The sender holds a secret key `k`
- The receiver provides an input `x`
- The receiver learns `F(k, x)` but nothing about `k`
- The sender learns nothing about `x` or `F(k, x)`

OPRFs are the foundation for many privacy-preserving protocols including:
- Password-based authentication without exposing passwords
- Private set intersection, which allows two parties to find the intersection of their private sets without revealing the full sets
- Privacy-preserving information retrieval, allowing users to get specific information from a database without revealing what information is being retrieved

## Features

### Basic OPRF
liboprf implements the basic OPRF(ristretto255, SHA-512) variant from the [IRTF CFRG Draft](https://github.com/cfrg/draft-irtf-cfrg-voprf/), "Oblivious Pseudorandom Functions (OPRFs) using Prime-Order Groups".

### Threshold OPRF
liboprf implements a threshold OPRF variant based on [Krawczyk et al. (2017)](https://eprint.iacr.org/2017/363) which is compatible with the [CFRG OPRF(ristretto255, SHA-512) variant](#basic-oprf). A threshold implementation distributes trust among multiple servers, requiring a minimum number (threshold) to cooperate for operation. It uses Distributed Key Generation (DKG) protocols, as described below, to distribute secret key shares among multiple servers. 

### 3hashTDH
This library also implements the 3hashTDH from [Gu, Jarecki, Kedzior, Nazarian, Xu (2024)](https://eprint.iacr.org/2024/1455) "Threshold PAKE with Security against Compromise of all Servers". This implementation is compatible with the aforementioned [IRTF CFRG OPRF(ristretto255, SHA-512)](#basic-oprf) variant.

### Distributed Key Generation (DKG)
For the [threshold OPRF](#threshold-oprf), liboprf provides:

- **Trusted Party DKG**: An implementation based on Joint Feldman DKG (JF-DKG) from the paper "[Secure Distributed Key Generation for Discrete-Log Based Cryptosystems](https://link.springer.com/article/10.1007/s00145-006-0347-3)" by R. Gennaro, S. Jarecki, Hugo Krawczyk & T. Rabin.

- **Semi-trusted DKG**: Implements Fast-Track Joint Verifiable Secret Sharing (FT-Joint-DL-VSS) described in R. Gennaro, M. O. Rabin, and T. Rabin, "[Simplified VSS and fast-track multiparty computations with applications to threshold cryptography](https://dl.acm.org/doi/10.1145/277697.277716)" In B. A. Coan and Y. Afek, editors, 17th ACM PODC, pages 101–111. ACM, June/July 1998.

### Threshold OPRF Updates
To update a threshold OPRF instantiation, liboprf contains multi-party multiplication described in R. Gennaro, M. O. Rabin, and T. Rabin, "[Simplified VSS and fast-track multiparty computations with applications to threshold cryptography](https://dl.acm.org/doi/10.1145/277697.277716)" In B. A. Coan and Y. Afek, editors, 17th ACM PODC, pages 101–111. ACM, June/July 1998.

## Installation

### Dependencies
- **libsodium**: You must install [libsodium](https://github.com/jedisct1/libsodium) first. libsodium is a cryptographic library that provides a range of cryptographic operations including encryption, decryption, digital signatures, and secure password hashing.
- **pkgconf**: Needed for building the library.

### Building from source

```bash
git clone https://github.com/stef/liboprf.git
cd liboprf/src
make
sudo make install
```

### Python Wrapper
A Python wrapper, `pyoprf`, is provided. Look at [its README](/python/README.md) for installation and usage instructions. 


## Funding

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund
established by [NLnet](https://nlnet.nl) with financial support from the
European Commission's [Next Generation Internet](https://ngi.eu) program. Learn
more at the [NLnet project page](https://nlnet.nl/project/ThresholdOPRF).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)
