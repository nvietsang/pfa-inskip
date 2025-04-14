## Compile source files

The `faultingsbox` folder contains the C files of the AES implementation extracted from [MbedTLS](https://github.com/Mbed-TLS/mbedtls/tree/v3.6.1).

In `faultingsbox/main.c`, the following macro enables the fault simulation:

```C
#define INJECT_FAULT
```

To compile:

```sh
cd faultingsbox && make && ..
```

## Collect (faulty) ciphertexts:

```sh
./faultingsbox/main
```

By default, 5000 ciphertexts will be collected. The ciphertexts will be written into `faultingsbox/cpts.txt`. 

## Key recovery:

To perform the key recovery on the collected ciphertexts:

```sh
python3 keyrecovery.py
```

## Visualization

To visualize the occurrence frequency of a ciphertext byte, say 15:

```sh
python3 visualize.py --byte-index 15
```