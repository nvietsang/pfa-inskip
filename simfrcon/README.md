## Source files

The `faultingrcon` folder contains the C files of the AES implementation extracted from [MbedTLS](https://github.com/Mbed-TLS/mbedtls/tree/v3.6.1).

In `faultingrcon/main.c`, the following macro enables the fault simulation:

```C
#define INJECT_FAULT
```

## Collect correct ciphertexts:

Disable the macro of fault simulation and compile:

```sh
cd faultingrcon && make && ..
```

Then collect correct ciphertexts

```sh
./faultingrcon/main
```

By default, 3 ciphertexts will be collected. The ciphertexts will be written into `faultingrcon/ccpts.txt`.

## Collect faulty ciphertexts:

Enable the macro of fault simulation and compile:

```sh
cd faultingrcon && make && ..
```

Then collect correct ciphertexts

```sh
./faultingrcon/main
```

By default, 3 ciphertexts will be collected. The ciphertexts will be written into `faultingrcon/fcpts.txt`. 

## Key recovery:

To perform the key recovery on the collected ciphertexts:

```sh
python3 keyrecovery.py
```