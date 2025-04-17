# EXPFRCON

This folder contains the source code for the experiment of PFA with a fault in the round constant generation.

The experiment is conducted using a ChipWhisperer Lite integrated with a 32-bit STM32F303 target.

## Compile the source code

```sh
cd simpleserial-glitch && make -j && ..
```

## Insert clock glitch and collect ciphertexts

Note that the attack requires to collect 3 pairs of correct-faulty ciphertexts. We assume that the 3 correct ones are already collected in `ccpts.txt`. The following script is to insert a clock glitch and collect the 3 faulty ones:

```sh
python3 run.py
```

This script does the following tasks:

- Transfer the binary code to the target
- Request the first encryption, before which the round constants are generated
- Request 3 ciphertexts, then verify whether the expected fault has occurred
    - If yes, recover the key 
    - If no, reset and try with different glitch parameter
