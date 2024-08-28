#!/usr/bin/env python3

import json, sys
from itertools import zip_longest # for Python 3.x

def split_by_n(iterable, n):
    return zip_longest(*[iter(iterable)]*n, fillvalue='')

# src: ht
vectors = """
{
	"groupDST": "48617368546f47726f75702d4f50524656312d002d72697374726574746f3235352d534841353132",
	"hash": "SHA512",
	"identifier": "ristretto255-SHA512",
	"keyInfo": "74657374206b6579",
	"mode": 0,
	"seed": "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
	"skSm": "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e",
	"vectors": [
	  {
		"Batch": 1,
		"Blind": "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
		"BlindedElement": "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c",
		"EvaluationElement": "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e",
		"Input": "00",
		"Output": "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6"
	  },
	  {
		"Batch": 1,
		"Blind": "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
		"BlindedElement": "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418",
		"EvaluationElement": "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25",
		"Input": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
		"Output": "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73"
	  }
	]
}
"""

def toC(k, v):
  print(f"#define {k.lower()}_len {len(v)//2}")
  print(
      f"const uint8_t {k.lower()}[{k.lower()}_len] = {{\n   %s}};\n" % ",\n   ".join(
          (", ".join((c for c in line if c)) for line in split_by_n(
              (f"0x{x[0]}{x[1]}" for x in split_by_n(v,2))
              ,8))
      ))

vex = json.loads(vectors)
print("// this file has been automatically generated using testvecs2h.py")

if sys.argv[1] == 'cfrg_oprf_test_vectors.h':
   # run this if there is a change in the values of the test vectors
   # ./testvecs2h.py >cfrg_oprf_test_vectors.h

   print("#ifndef cfrg_test_vectors_h\n#define cfrg_test_vectors_h\n")
   print("#include <stdint.h>\n")

   toC("sks", vex['skSm'])

   for tc in range(2):
       for k, v in vex['vectors'][tc].items():
           if k == "Batch": continue
           print(f"#define tc{tc}_{k.lower()}_len {len(v)//2}")
           print(
               f"const uint8_t tc{tc}_{k.lower()}[tc{tc}_{k.lower()}_len] = {{\n   %s}};\n" % ",\n   ".join(
                   (", ".join((c for c in line if c)) for line in split_by_n(
                       (f"0x{x[0]}{x[1]}" for x in split_by_n(v,2))
                       ,8))
               ))

elif sys.argv[1] == 'cfrg_oprf_test_vector_decl.h':
   # only run this code below if there is a change in the keys of the test vectors
   # ./testvecs2h.py >cfrg_oprf_test_vector_decl.h

   print("#ifndef cfrg_test_vector_decl_h\n#define cfrg_test_vector_decl_h\n")
   print("#include <stdint.h>\n")
   for tc in range(2):
      for k, v in vex['vectors'][tc].items():
         if k == "Batch": continue
         print(f"#define tc{tc}_{k.lower()}_len {len(v)//2}")
         print(f"extern const uint8_t tc{tc}_{k.lower()}[tc{tc}_{k.lower()}_len];\n")
else:
    sys.exit(-1)

print("""
#if(TC==0)
    #define input                 tc0_input
    #define input_len             tc0_input_len
    #define blind_registration    tc0_blind
    #define blind_login           tc0_blind
    #define blind_len             tc0_blind_len
    #define blinded_element       tc0_blindedelement
    #define blindedelement_len    tc0_blindedelement_len
    #define evaluationelement     tc0_evaluationelement
    #define evaluationelement_len tc0_evaluationelement_len
    #define output                tc0_output
    #define output_len            tc0_output_len
#else
    #define input                 tc1_input
    #define input_len             tc1_input_len
    #define blind_registration    tc1_blind
    #define blind_login           tc1_blind
    #define blind_len             tc1_blind_len
    #define blinded_element       tc1_blindedelement
    #define blindedelement_len    tc1_blindedelement_len
    #define evaluationelement     tc1_evaluationelement
    #define evaluationelement_len tc1_evaluationelement_len
    #define output                tc1_output
    #define output_len            tc1_output_len
#endif""")
print("#endif")
