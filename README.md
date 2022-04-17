* liboprf

This library implements the basic OPRF(ristretto255, SHA-512) variant
from the IRTF CFRG Draft: https://github.com/cfrg/draft-irtf-cfrg-voprf/

Additionally it implements a threshold OPRF based on the above in
combination with Daan Sprenkels excellent sss library
https://github.com/dsprenkels/sss.

Besides dsprenkels sss this library also depends on libsodium.
