from sys import exit as sys_exit

from goodix import Device
from goodix.dev_5110 import (change_psk, check_firmware, check_psk,
                             erase_firmware, flash_firmware, init_device)


def print_warning(text: str) -> None:
    decorator = "#" * len(max(text.split("\n"), key=len))
    print(f"\033[31;5m{decorator}\n{text}\n{decorator}\033[0m")


def main(product: int) -> int:
    print_warning("This program might break your device.\n"
                  "Consider that it will flash the device firmware.\n"
                  "Continue at your own risk.\n"
                  "But don't hold us responsible if your device is broken!")

    if input("Type \"I understand, and I agree\" to continue: "
            ) == "I understand, and I agree":

        previous_firmware = None
        while True:
            device = Device(product)

            init_device(device)

            firmware = check_firmware(device)

            valid_psk = check_psk(device)

            if firmware == previous_firmware:
                print("Unchanged firmware: Abort")
                return -1

            previous_firmware = firmware

            if firmware == 0:
                if not valid_psk:
                    erase_firmware(device)
                    continue

                print("All is good!")
                return 0

            if firmware == 1:
                erase_firmware(device)
                continue

            if firmware == 2:
                if not valid_psk:
                    change_psk(device)

                    if not check_psk(device):
                        print("Invalid PSK: Abort")
                        return -1

                flash_firmware(device)
                continue

            print("Invalid firmware: Abort")
            print_warning("Please consider that removing this security "
                          "is a very bad idea!")
            return -1

    print("Abort")
    return 1


if __name__ == "__main__":
    sys_exit(main(0x5110))
