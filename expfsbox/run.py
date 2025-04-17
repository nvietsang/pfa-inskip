from matplotlib import pyplot as plt
import chipwhisperer as cw
import time
import os
import numpy as np

def reboot_flush(scope, target):            
    scope.io.nrst = False
    time.sleep(0.05)
    scope.io.nrst = "high_z"
    time.sleep(0.05)
    #Flush garbage too
    target.flush()

def check_good_fault(N=3000, threshold=5):
    cpts = np.zeros((N,16), np.uint8)
    for i in range(N):
        print(f"Encrypting for checking good fault: {i:4d}")
        plt = bytearray(os.urandom(16))
        target.simpleserial_write('a', plt)
        time.sleep(0.1)
        response = target.simpleserial_read_witherrors('r', 16, glitch_timeout=10, timeout=50)
        if response['valid'] is False:
            gc.add('reset')
        else:
            cpt = list(bytes(response['payload']))
            cpts[i] = cpt

    counter = np.zeros((16,256), dtype=np.uint32)
    for i in range(N):
        for j in range(16):
            counter[j][cpts[i][j]] += 1

    cmin = np.zeros(16, dtype=np.uint8)
    cmax = np.zeros(16, dtype=np.uint8)
    f_counter = np.zeros(256, dtype=np.uint8)

    for j in range(16):
        cmin[j] = np.argmin(counter[j])
        cmax[j] = np.argmax(counter[j])
        f = cmin[j]^cmax[j]
        f_counter[f] += 1  
        print(f"j = {j:2d}: (cmin, cmax) = ({cmin[j]:3d}, {cmax[j]:3d}), f = {cmin[j]^cmax[j]}")

    print(f"The same fault appears at {np.max(f_counter)} ciphertext bytes!")
    if np.max(f_counter) >= threshold:
        f = open("cpts.txt", "w")
        for i in range(N):
            cpt = bytes(list(cpts[i])).hex().zfill(32)
            f.write(cpt + "\n")
        f.close()
        return True
    else:
        return False


if __name__ == "__main__":
    PLATFORM = "CWLITEARM"
    scope = cw.scope()

    # SS_VER == "SS_VER_2_1":
    target_type = cw.targets.SimpleSerial2
    target = cw.target(scope, target_type)
    print("INFO: Found ChipWhisperer😍")

    # CWLITEARM
    prog = cw.programmers.STM32FProgrammer
    scope.default_setup()

    fw_path = f"simpleserial-glitch/simpleserial-glitch-{PLATFORM}.hex"
    cw.program_target(scope, prog, fw_path)
    target.reset_comms()

    # BEGIN GLITCH CONFIG
    scope.cglitch_setup()
    gc = cw.GlitchController(groups=["success", "reset", "normal"], 
                             parameters=["width", "offset", "ext_offset"])
    gc.display_stats()

    # scope.glitch.clk_src = "clkgen" 
    # scope.glitch.output = "clock_xor"
    # scope.glitch.trigger_src = "ext_single"
    # scope.io.hs2 = "glitch"

    gc.set_range("width", 1.6, 3.6)
    gc.set_range("offset", -4, -2)
    gc.set_range("ext_offset", 0, 100)
    gc.set_global_step(0.4)
    gc.set_step("ext_offset", 1)
    scope.glitch.repeat = 1

    reboot_flush(scope, target)
    scope.adc.timeout = 1
    # END GLITCH CONFIG
    
    indata = bytearray([0x01]*16)
    is_sbox_faulted = False    

    # BEGIN GLITCH
    for glitch_setting in gc.glitch_values():
        print(f"O = {glitch_setting[1]}, W = {glitch_setting[0]}, E = {glitch_setting[2]}")
        scope.glitch.offset = glitch_setting[1]
        scope.glitch.width = glitch_setting[0]
        scope.glitch.ext_offset = glitch_setting[2]

        if scope.adc.state:
            print("[RESET] Trigger still high!")
            gc.add("reset")
            reboot_flush(scope, target)

        # Send the first plaintext and trigger glitch
        scope.arm()
        target.simpleserial_write('a', indata)
        ret = scope.capture()

        if ret:
            print("[RESET] Timeout, no trigger!")
            gc.add("reset")
            reboot_flush(scope, target)
        else:
            response = target.simpleserial_read_witherrors('r', 16, glitch_timeout=10, timeout=50)
            if response['valid'] is False:
                gc.add('reset')
                reboot_flush(scope, target)
            else:
                is_good_fault = check_good_fault()
                if is_good_fault:
                    print("Good fault")
                    break
                else:
                    print("Fault is not good. Try a different fault!")
                    gc.add("reset")
                    reboot_flush(scope, target)
            
    scope.dis()
    target.dis()
    print("Done :) Good bye!")