from analyze import keyrecover
import chipwhisperer as cw
import time
import os

def reboot_flush(scope, target):            
    scope.io.nrst = False
    time.sleep(0.05)
    scope.io.nrst = "high_z"
    time.sleep(0.05)
    #Flush garbage too
    target.flush()

def check_good_fault(plts, ccpts, N=3):
    fcpts = []
    for i in range(N):
        print(f"Encrypting for recovery: {i:4d}")
        plt = bytearray(plts[i])
        target.simpleserial_write('a', plt)
        time.sleep(0.1)
        response = target.simpleserial_read_witherrors('r', 16, glitch_timeout=10, timeout=50)
        if response['valid'] is False:
            gc.add('reset')
        else:
            cpt = bytes(response['payload'])
            fcpts.append(list(cpt))
    
    is_recovered = keyrecover(fcpts, ccpts)
    if is_recovered:
        fcpts_file = "fcpts.txt"
        with open(fcpts_file, "w") as f: pass
        f = open(fcpts_file, "a")
        for i in range(N):
            cpt = bytes(fcpts[i]).hex().zfill(32)
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

    gc.set_range("width", 1.6, 3.6)
    gc.set_range("offset", -3.6, -2)
    gc.set_range("ext_offset", 70, 100)
    gc.set_global_step(0.4)
    gc.set_step("ext_offset", 1)
    scope.glitch.repeat = 1

    reboot_flush(scope, target)
    scope.adc.timeout = 1
    # END GLITCH CONFIG
    
    with open("plts.txt", "r") as f: plts = f.readlines()
    with open("ccpts.txt", "r") as f: ccpts = f.readlines()
    plts = [list(bytes.fromhex(p.strip())) for p in plts]
    ccpts = [list(bytes.fromhex(c.strip())) for c in ccpts]

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

        # Send first plaintext and trigger glitch
        scope.arm()
        target.simpleserial_write('a', bytearray([0x01]*16))
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
                rcon = list(response['payload'])
                print("Rcon: ", end="")
                for v in rcon: print(f"{v:02x} ", end="")
                print()

                is_goodfault = check_good_fault(plts, ccpts)
                if is_goodfault:
                    print("Good fault! Finish!")
                    break
                else:
                    print("Fault is not good! Try again with a new fault!")
                    reboot_flush(scope, target)
            
    scope.dis()
    target.dis()
    print("Done :) Good bye!")