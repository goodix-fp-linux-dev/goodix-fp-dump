from goodix import Device


def check_psk(psk: bytes) -> bool:
    print(psk.hex())
    return False


print("##################################################\n"
      "This program might break your device.\n"
      "Consider that it will flash the device firmware.\n"
      "Be sure to have the device 27c6:55b4.\n"
      "Continue at your own risk.\n"
      "But don't hold us responsible if your device is broken!\n"
      "##################################################")

ANSWER = ""
##################################################
# Please be careful when uncommenting this line!
# ANSWER = "I understand, and I agree"
##################################################

if not ANSWER:
    ANSWER = input("Type \"I understand, and I agree\" to continue: ")

if ANSWER == "I understand, and I agree":
    while True:
        device = Device(0x27c6, 0x55b4)
        device.nop()
        device.enable_chip()
        device.nop()

        firmware = device.firmware_version()

        print(firmware)

        valid_psk = False
        for _ in range(2):
            if check_psk(device.preset_psk_read_r(bytes.fromhex("070002bb"))):
                valid_psk = True
                break

        if firmware == "GF3268_RTSEC_APP_10037":
            if not valid_psk:
                device.mcu_erase_app()
                device.wait_disconnect()
                continue

            print("All good!")
            break

        elif firmware == "GF3268_RTSEC_APP_10032":
            device.mcu_erase_app()
            device.wait_disconnect()

        elif firmware == "MILAN_RTSEC_IAP_10027":
            if not valid_psk:
                print("Need to Write PSK")

            ##################################################
            # Carfull! If you change the firmware you also need to change the data
            # parameter at device.update_firmware()
            firmware_file = open("GF3268_RTSEC_APP_10037.bin", "rb")
            ##################################################

            while True:
                offset = firmware_file.tell()
                data = firmware_file.read(256)

                # device.write_firmware(offset, data)
                print(f"device.write_firmware({offset}, {data})")

                if len(data) < 256:
                    break

            length = firmware_file.tell()
            firmware_file.close()

            # device.update_firmware(0, length, bytes.fromhex("e3c7b724"))
            print(f"device.update_firmware({0}, {length})")

            # device.reset(False, True)
            print(f"device.reset({False}, {True})")
            # device.wait_disconnect()
            print("device.wait_disconnect()")
            break

        else:
            raise ValueError(
                "Invalid firmware. Abort.\n"
                "##################################################\n"
                "Please consider that removing this security is a very bad idea!\n"
                "##################################################")

else:
    print("Abort. You have chosen the right option!")
