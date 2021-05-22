from time import sleep
from goodix import Device


def valid_psk(_) -> bool:
    return False


def main():
    print("#####     /!\\  This program might break your device. "
          "Be sure to have the device 27c6:5110.  /!\\     #####\n"
          "#####  /!\\  Continue at your own risk but don't hold us "
          "responsible if your device is broken!  /!\\  #####")

    answer = ""
    ## Please be careful when uncommenting the following line! ##
    # answer = "I understand, and I agree"

    if not answer:
        answer = input("Type \"I understand, and I agree\" to continue: ")

    if answer == "I understand, and I agree":
        device = Device(0x27c6, 0x5110)
        device.nop()
        device.enable_chip()
        device.nop()

        firmware = device.firmware_version()

        psk_ok = False
        for _ in range(2):
            if valid_psk(device.preset_psk_read_r()):
                psk_ok = True
                break

        sleep(1)

        device.read_from_mem(0, 10)

        sleep(1)

        # if firmware == "GF_ST411SEC_APP_12109":
        #     if psk_ok:
        #         print("TLS request connection")  # TODO TLS request connection

        #     else:
        #         device.mcu_erase_app()

        # elif firmware == "MILAN_ST411SEC_IAP_12101":
        #     if not psk_ok:
        #         print("Write PSK")  # TODO Write PSK

        #     print("Flash firmware")  # TODO Flash firmware

        # else:
        #     raise ValueError("Invalid firmware. Abort.\n"
        #                      "#####  /!\\  Please consider that removing this "
        #                      "security is a very bad idea  /!\\  #####")

    else:
        print("Abort. You are right to have chosen this option!")


if __name__ == "__main__":
    main()
