# EXPFSBOX

This folder contains the source code for the experiment of PFA with a fault in the S-box generation.

The experiment is conducted using a ChipWhisperer Lite integrated with a 32-bit STM32F303 target.

## Compile the source code

```sh
cd simpleserial-glitch && make -j && ..
```

## Insert clock glitch and collect ciphertexts

```sh
python3 run.py
```

This script does the following tasks:

- Transfer the binary code to the target
- Request the first encryption, before which the S-box is generated
- Request $N$ ciphertexts, then verify whether the expected fault has occurred

## Analyze ciphertexts

To visualize $c_{min}$ and $c_{max}$:

```sh
python3 visualize.py
```

## Key recovery

```sh
python3 keyrecovery.py
```