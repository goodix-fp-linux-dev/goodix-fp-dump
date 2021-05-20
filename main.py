from goodix import Device


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
        print(device.firmware_version())
        print(device.preset_psk_read_r())
        device.mcu_erase_app()

    else:
        print("Abort. You are right to have chosen this option!")


if __name__ == "__main__":
    main()
