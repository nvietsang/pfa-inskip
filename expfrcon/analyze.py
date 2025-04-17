# Constants
RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]  # Round constants for key expansion

# S-Box (Substitution box)
SBOX = [
    # 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def inverse_key_schedule(key):
    assert len(key) == 16
    Nr = 10

    # Round 0
    round_keys = list(key[:])
    
    # Round ri: 1-10
    for ri in range(Nr-1, -1, -1):
        new_round_key = []

        new_round_key.append(round_keys[ 0] ^ round_keys[ 4])
        new_round_key.append(round_keys[ 1] ^ round_keys[ 5])
        new_round_key.append(round_keys[ 2] ^ round_keys[ 6])
        new_round_key.append(round_keys[ 3] ^ round_keys[ 7])

        new_round_key.append(round_keys[ 4] ^ round_keys[ 8])
        new_round_key.append(round_keys[ 5] ^ round_keys[ 9])
        new_round_key.append(round_keys[ 6] ^ round_keys[10])
        new_round_key.append(round_keys[ 7] ^ round_keys[11])

        new_round_key.append(round_keys[ 8] ^ round_keys[12])
        new_round_key.append(round_keys[ 9] ^ round_keys[13])
        new_round_key.append(round_keys[10] ^ round_keys[14])
        new_round_key.append(round_keys[11] ^ round_keys[15])


        # RotWord
        c0 = new_round_key[ 9]
        c1 = new_round_key[10]
        c2 = new_round_key[11]
        c3 = new_round_key[ 8]

        # SubWord
        c0 = SBOX[c0]
        c1 = SBOX[c1]
        c2 = SBOX[c2]
        c3 = SBOX[c3]

        # XOR
        c0 ^= round_keys[0]
        c1 ^= round_keys[1]
        c2 ^= round_keys[2]
        c3 ^= round_keys[3]

        # Rcon
        c0 ^= RCON[ri]

        # New round key
        new_round_key = [c0, c1, c2, c3] + new_round_key
        round_keys = new_round_key + round_keys
    
    return round_keys

def keyrecover(fcpts, ccpts, N=3):
    assert N == len(ccpts)
    assert N == len(fcpts)

    ciph_pairs = [p for p in zip(ccpts, fcpts)]
    recovered_key = [None] * 16
    delta = [None] * 3
    # (12, 9)
    count = 0
    for g12 in range(256):
        for g09 in range(256):
            is_g12_g09_good = True
            for i in range(N):
                vc12 = INV_SBOX[ciph_pairs[i][0][12] ^ g12]
                vc09 = INV_SBOX[ciph_pairs[i][0][ 9] ^ g09]
                vf12 = INV_SBOX[ciph_pairs[i][1][12] ^ g12]
                vf09 = INV_SBOX[ciph_pairs[i][1][ 9] ^ g09]
                
                d12 = vc12 ^ vf12
                d09 = vc09 ^ vf09

                if d12 != xtime(d09):
                    is_g12_g09_good = False
                    break

            if is_g12_g09_good:
                count += 1
                recovered_key[12] = g12
                recovered_key[ 9] = g09

    if count != 1:
        print(f"Not unique candidate: {count}")
        return False
    print(recovered_key)

    # (6, delta1)
    count = 0
    k09 = recovered_key[9]
    for g06 in range(256):
        for delta1 in range(256):
            is_g06_delta1_good = True
            for i in range(N):
                vc09 = INV_SBOX[ciph_pairs[i][0][9] ^ k09]
                vc06 = INV_SBOX[ciph_pairs[i][0][6] ^ g06]
                vf09 = INV_SBOX[ciph_pairs[i][1][9] ^ k09]
                vf06 = INV_SBOX[ciph_pairs[i][1][6] ^ g06 ^ delta1]

                d09 = vc09 ^ vf09
                d06 = vc06 ^ vf06

                if d09 != d06:
                    is_g06_delta1_good = False
                    break
            
            if is_g06_delta1_good:
                count += 1
                recovered_key[6] = g06
                delta[1] = delta1

    if count != 1:
        print(f"Not unique candidate: {count}")
        return False
    print(recovered_key)
    print(delta)

    # (3, delta2)
    count = 0
    k09 = recovered_key[9]
    for g03 in range(256):
        for delta2 in range(256):
            is_g03_delta2_good = True
            for i in range(N):
                vc09 = INV_SBOX[ciph_pairs[i][0][9] ^ k09]
                vc03 = INV_SBOX[ciph_pairs[i][0][3] ^ g03]
                vf09 = INV_SBOX[ciph_pairs[i][1][9] ^ k09]
                vf03 = INV_SBOX[ciph_pairs[i][1][3] ^ g03 ^ delta2]

                d09 = vc09 ^ vf09
                d03 = vc03 ^ vf03

                if d03 != delta2 ^ (xtime(d09) ^ d09):
                    is_g03_delta2_good = False
                    break

            if is_g03_delta2_good:
                count += 1
                recovered_key[3] = g03
                delta[2] = delta2

    if count != 1:
        print(f"Not unique candidate: {count}")
        return False
    print(recovered_key)
    print(delta)

    # (5, 15)
    count = 0
    for g05 in range(256):
        for g15 in range(256):
            is_g05_g15_good = True
            for i in range(N):
                vc05 = INV_SBOX[ciph_pairs[i][0][ 5] ^ g05]
                vc15 = INV_SBOX[ciph_pairs[i][0][15] ^ g15]
                vf05 = INV_SBOX[ciph_pairs[i][1][ 5] ^ g05]
                vf15 = INV_SBOX[ciph_pairs[i][1][15] ^ g15]

                d05 = vc05 ^ vf05
                d15 = vc15 ^ vf15

                if d15 != delta[2] ^ (xtime(d05) ^ d05):
                    is_g05_g15_good = False
                    break

            if is_g05_g15_good:
                count += 1
                recovered_key[ 5] = g05
                recovered_key[15] = g15

    if count != 1:
        print(f"Not unique candidate: {count}")
        return False
    print(recovered_key)
    print(delta)

    # (8, delta0)
    count = 0
    g05 = recovered_key[5]
    for g08 in range(256):
        for delta0 in range(256):
            is_g08_delta0_good = True
            for i in range(N):
                vc05 = INV_SBOX[ciph_pairs[i][0][5] ^ g05]
                vc08 = INV_SBOX[ciph_pairs[i][0][8] ^ g08]
                vf05 = INV_SBOX[ciph_pairs[i][1][5] ^ g05]
                vf08 = INV_SBOX[ciph_pairs[i][1][8] ^ g08]

                d05 = vc05 ^ vf05
                d08 = vc08 ^ vf08

                if d08 != delta0 ^ xtime(d05):
                    is_g08_delta0_good = False
                    break

            if is_g08_delta0_good:
                count += 1
                recovered_key[8] = g08
                delta[0] = delta0

    if count != 1:
        print(f"Not unique candidate: {count}")
        return False
    print(recovered_key)
    print(delta)

    # (5, 2)
    count = 0
    g05 = recovered_key[5]
    for g02 in range(256):
        is_g05_g02_good = True
        for i in range(N):
            vc05 = INV_SBOX[ciph_pairs[i][0][5] ^ g05]
            vc02 = INV_SBOX[ciph_pairs[i][0][2] ^ g02]
            vf05 = INV_SBOX[ciph_pairs[i][1][5] ^ g05]
            vf02 = INV_SBOX[ciph_pairs[i][1][2] ^ g02 ^ delta[1]]

            d05 = vc05 ^ vf05
            d02 = vc02 ^ vf02

            if d02 != d05:
                is_g05_g02_good = False
                break

        if is_g05_g02_good:
            count += 1
            recovered_key[2] = g02

    if count != 1:
        print(f"Not unique candidate: {count}")
        return False
    print(recovered_key)
    print(delta)

    # (1, 4)
    count = 0
    for g01 in range(256):
        for g04 in range(256):
            is_g01_g04_good = True
            for i in range(N):
                vc01 = INV_SBOX[ciph_pairs[i][0][1] ^ g01]
                vc04 = INV_SBOX[ciph_pairs[i][0][4] ^ g04]
                vf01 = INV_SBOX[ciph_pairs[i][1][1] ^ g01]
                vf04 = INV_SBOX[ciph_pairs[i][1][4] ^ g04 ^ delta[0]]

                d01 = vc01 ^ vf01
                d04 = vc04 ^ vf04

                if d04 != xtime(d01):
                    is_g01_g04_good = False
                    break

            if is_g01_g04_good:
                count += 1
                recovered_key[1] = g01
                recovered_key[4] = g04

    if count != 1:
        print(f"Not unique candidate: {count}")
        return False
    print(recovered_key)
    print(delta)

    # (11, 14)
    count = 0
    for g11 in range(256):
        for g14 in range(256):
            is_g11_g14_good = True
            for i in range(N):
                vc11 = INV_SBOX[ciph_pairs[i][0][11] ^ g11]
                vc14 = INV_SBOX[ciph_pairs[i][0][14] ^ g14]
                vf11 = INV_SBOX[ciph_pairs[i][1][11] ^ g11 ^ delta[2]]
                vf14 = INV_SBOX[ciph_pairs[i][1][14] ^ g14 ^ delta[1]]

                d11 = vc11 ^ vf11
                d14 = vc14 ^ vf14

                if d11 != delta[2] ^ (xtime(d14) ^ d14):
                    is_g11_g14_good = False
                    break

            if is_g11_g14_good:
                count += 1
                recovered_key[11] = g11
                recovered_key[14] = g14

    if count != 1:
        print(f"Not unique candidate: {count}")
        return False
    print(recovered_key)
    print(delta)

    # (0, 13)
    count = 0
    for g00 in range(256):
        for g13 in range(256):
            is_g00_g13_good = True
            for i in range(N):
                vc00 = INV_SBOX[ciph_pairs[i][0][ 0] ^ g00]
                vc13 = INV_SBOX[ciph_pairs[i][0][13] ^ g13]
                vf00 = INV_SBOX[ciph_pairs[i][1][ 0] ^ g00 ^ delta[0]]
                vf13 = INV_SBOX[ciph_pairs[i][1][13] ^ g13]

                d00 = vc00 ^ vf00
                d13 = vc13 ^ vf13

                if d00 != delta[0] ^ xtime(d13):
                    is_g00_g13_good = False
                    break

            if is_g00_g13_good:
                count += 1
                recovered_key[ 0] = g00
                recovered_key[13] = g13

    if count != 1:
        print(f"Not unique candidate: {count}")
        return False
    print(recovered_key)
    print(delta)

    # (7, 10)
    count = 0
    for g07 in range(256):
        for g10 in range(256):
            is_g07_g10_good = True
            for i in range(N):
                vc07 = INV_SBOX[ciph_pairs[i][0][ 7] ^ g07]
                vc10 = INV_SBOX[ciph_pairs[i][0][10] ^ g10]
                vf07 = INV_SBOX[ciph_pairs[i][1][ 7] ^ g07]
                vf10 = INV_SBOX[ciph_pairs[i][1][10] ^ g10 ^ delta[1]]

                d07 = vc07 ^ vf07
                d10 = vc10 ^ vf10

                if d07 != delta[2] ^ (xtime(d10) ^ d10):
                    is_g07_g10_good = False
                    break

            if is_g07_g10_good:
                count += 1
                recovered_key[ 7] = g07
                recovered_key[10] = g10

    if count != 1:
        print(f"Not unique candidate: {count}")
        return False
    print(recovered_key)
    print(delta)

    print("Last round key:")
    for v in recovered_key: print(f"{v:02x} ", end="")
    print()

    print("Master key")
    round_keys = inverse_key_schedule(recovered_key)
    for i in range(16): 
        print(f"{round_keys[i]:02x} ", end="")
    print()
    return True