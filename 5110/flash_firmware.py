from goodix import Device

PSK = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")
PSK_WB = bytes.fromhex(
    "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000001c849b9831e694c"
    "b3ef601ff3e13c3c040000004000000054006800690073002000690073002000"
    "74006800650020006400650073006300720069007000740069006f006e002000"
    "73007400720069006e0067002e0000001066000000010000200000003ff07b38"
    "3d00fb003592b4c8fa6aab2e17a172409ad745d3b6464274a662df1500000000"
    "0e80000000020000200000003cd09ee49c63e336c144d125842ae92ad50b53cf"
    "8dfd104971475b74f90d9d833000000064c19ffff8280ec919533bfb5f7bf3b4"
    "18632c4544c66d3af8341a4f24ac7cdeafbe52d2d03848d5e70bc7fe3ce0f295"
    "4000000070583734b732ceed6aae6df5338908931d73baafb96950af4fd8d546"
    "da11f7a18c86b8fb06bc6a96247840f884e354e24128e61739991717fa1c6e91"
    "60960399d7b9450b7c3547b1030001bb60000000ec35ae3abb45ed3f12c4751f"
    "1e5c2cc05b3c5452e9104d9f2a3118644f37a04b6fd66b1d97cf80f1345f76c8"
    "4f03ff30bb51bf308f2a9875c41e6592cd2a2f9e60809b17b5316037b69bb2fa"
    "5d4c8ac31edb3394046ec06bbdacc57da6a756c5")
PMK_HASH = bytes.fromhex(
    "00030002bb20000000ba1a86037c1d3c71c3af344955bd69a9a9861d9e911fa2"
    "4985b677e8dbd72d43")


def check_psk(psk: bytes) -> bool:
    print(psk)
    return psk == PMK_HASH


print("##################################################\n"
      "This program might break your device.\n"
      "Consider that it will flash the device firmware.\n"
      "Be sure to have the device 27c6:5110 or 27c6:5117.\n"
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
        device = Device(0x5110, 1)
        device.nop()
        device.enable_chip()
        device.nop()

        firmware = device.firmware_version()

        VALID_PSK = False
        for _ in range(2):
            if check_psk(device.preset_psk_read_r(0xbb020003)):
                VALID_PSK = True
                break

        if firmware == "GF_ST411SEC_APP_12109":
            if not VALID_PSK:
                device.mcu_erase_app()
                device.wait_disconnect()
                continue

            print("All good!")
            break

        if "GF_ST411SEC_APP_121" in firmware:
            device.mcu_erase_app()
            device.wait_disconnect()

        elif "MILAN_ST411SEC_IAP_121" in firmware:
            if not VALID_PSK:
                device.preset_psk_write_r(0xbb010002, 332, PSK_WB)

            ##################################################
            # Carfull! If you change the firmware you also need to change the
            # data parameter at device.update_firmware()
            firmware_file = open("GF_ST411SEC_APP_12109.bin", "rb")
            ##################################################

            while True:
                offset = firmware_file.tell()
                data = firmware_file.read(1008)

                device.write_firmware(offset, data)

                if len(data) < 1008:
                    break

            length = firmware_file.tell()
            firmware_file.close()

            device.update_firmware(0, length, bytes.fromhex("e3c7b724"))

            device.reset(False, True)
            device.wait_disconnect()

        else:
            raise ValueError(
                "Invalid firmware. Abort.\n"
                "##################################################\n"
                "Please consider that removing this security "
                "is a very bad idea!\n"
                "##################################################")

else:
    print("Abort. You have chosen the right option!")
