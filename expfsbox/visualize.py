from matplotlib import pyplot as plt
import numpy as np
import argparse

def visualize_distribution(path_to_file, j, step=10):
    with open(path_to_file, "r") as f: cpts = f.readlines()
    cpts = [bytes.fromhex(c.strip()) for c in cpts]
    N = len(cpts)
    print(f"There are {N} ciphertexts")

    counter = np.zeros((16,256), dtype=np.uint32)
    assert N % step == 0
    probs = np.zeros((N//step,16,256), dtype=np.float32)
    for i in range(N):
        n = i+1
        for j in range(16):
            counter[j][cpts[i][j]] += 1
        if n % step == 0:
            for j in range(16):
                for v in range(256):
                    probs[n//step-1,j,v] = counter[j,v] / n

    cmax = np.argmax(probs[N//step-1,j,:])
    cmin = np.argmin(probs[N//step-1,j,:])
    print(f"cmax = {cmax}")
    print(f"cmin = {cmin}")
    xrange = [x+step for x in range(0,N,step)]
    already_labeled = False
    for v in range(256):
        if v == cmax: plt.plot(xrange, probs[:,j,v], color="red", label=r"$c^{max}_j$")
        elif v == cmin: plt.plot(xrange, probs[:,j,v], color="blue", label=r"$c^{min}_j$")
        elif not already_labeled: 
            plt.plot(xrange, probs[:,j,v], color="lightgray", label=r"others")
            already_labeled = True
        else: plt.plot(xrange, probs[:,j,v], color="lightgray")

    plt.ylim((-0.0005, 0.013))
    plt.xlabel("Number of ciphertexts")
    plt.ylabel("Frequency")
    plt.legend()
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--path-to-file', 
                        dest='path_to_file', 
                        type=str, 
                        default="cpts.txt",
                        help='Path to the ciphertext file')
    parser.add_argument('-j', 
                        dest='j', 
                        type=int, 
                        default=15,
                        help='index of the ciphertext byte, in [0,15]')

    config = parser.parse_args()

    visualize_distribution(config.path_to_file, config.j)