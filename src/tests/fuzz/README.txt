fuzz tp-dkg using AFL++

to fuzz step x (x:=1..9) of the TP run

   STEP=x make clean fuzz

to fuzz using asan

   STEP=x make clean fuzz-asan

to fuzz the peers step x:

   STEP=x make clean fuzz-peer

to fuzz using asan:

   STEP=x make clean fuzz-asan-peer

note: for some fuzz targets there cannot be any complaints
