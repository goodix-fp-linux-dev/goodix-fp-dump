import goodix


def main():
    print(
        "#####      /!\  This program might break your device be sure to have the device 27c6:5110.  /!\     #####\n\
#####  /!\  Continue at your own risk but don't hold us responsible if your device is broken!  /!\  #####"
    )

    answer = ""
    answer = "I understand, and I agree"  ## Please be careful when uncommenting this line! ##

    if not answer:
        answer = input("Type \"I understand, and I agree\" to continue: ")

    if answer == "I understand, and I agree":
        device = goodix.Device(0x27c6, 0x5110)
        device.nop()
        device.enable_chip()


#         while True:
#             dev = goodix.GoodixDevice(0x27c6, 0x5110)
#             dev.nop()
#             dev.enable_chip()
#             dev.nop()

#             ## Please don't touch the following lines! ##
#             firmware = dev.get_firmware_version()
#             print(f"Firmware version: {firmware}")
#             if firmware == "GF_ST411SEC_APP_12117":
#                 dev.mcu_erase_app()
#             else:
#                 raise ValueError(
#                     f"Invalid firmware. Current: {firmware}. Valid: GF_ST411SEC_APP_12117. Abort.\n\
#     #####     /!\  Please consider that removing this security in the code is\
#  a very bad idea!  /!\     #####")
#             #############################################
#             break

    else:
        print("Abort. You are right to have chosen this option!")

if __name__ == "__main__":
    main()
