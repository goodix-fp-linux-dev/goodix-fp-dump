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
        device = Device(0x55b4, 0)
        device.nop()
        device.enable_chip()
        device.nop()

        firmware = device.firmware_version()

        print(firmware)

        VALID_PSK = False
        for _ in range(2):
            if check_psk(device.preset_psk_read_r(0xbb020007)):
                VALID_PSK = True
                break

        if firmware == "GF3268_RTSEC_APP_10037":
            if not VALID_PSK:
                device.mcu_erase_app()
                device.wait_disconnect()
                continue

            print("All good!")
            break

        if "GF3268_RTSEC_APP_100" in firmware:
            device.mcu_erase_app()
            device.wait_disconnect()

        elif "MILAN_RTSEC_IAP_100" in firmware:
            if not VALID_PSK:
                print("Need to Write PSK")

            ##################################################
            # Carfull! If you change the firmware you also need to change the
            # data parameter at device.update_firmware()
            firmware_file = open("GF3268_RTSEC_APP_10037.bin", "rb")
            ##################################################

            while True:
                offset = firmware_file.tell()
                data = firmware_file.read(256)

                device.write_firmware(offset, data)

                if len(data) < 256:
                    break

            length = firmware_file.tell()
            firmware_file.close()

            device.update_firmware(
                0, length,
                bytes.fromhex(
                    "053488f2f747163684ba92d8c070ea3b8d7cf4fe55a503b2c190838e57bc779d93245c3a"
                ))

            # device.reset(False, True)
            print(f"device.reset({False}, {True})")
            # device.wait_disconnect()
            print("device.wait_disconnect()")
            break

        else:
            raise ValueError(
                "Invalid firmware. Abort.\n"
                "##################################################\n"
                "Please consider that removing this security "
                "is a very bad idea!\n"
                "##################################################")

else:
    print("Abort. You have chosen the right option!")
