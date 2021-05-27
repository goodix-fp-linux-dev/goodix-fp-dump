from sys import exit as sys_exit

from goodix import Device


def check_psk(psk: bytes) -> bool:
    return psk == bytes.fromhex(
        "00030002bb200000004745386fd9edc90dc10d2150d07809ceb32e969f80b6d963a97b425ceeb69799"
    )


print("##################################################\n"
      "This program might break your device.\n"
      "Consider that it will flash the device firmware.\n"
      "Be sure to have the device 27c6:5110.\n"
      "Continue at your own risk.\n"
      "But don't hold us responsible if your device is broken!\n"
      "##################################################\n")

ANSWER = ""
##################################################
# Please be careful when uncommenting this line!
# ANSWER = "I understand, and I agree"
##################################################

if not ANSWER:
    ANSWER = input("Type \"I understand, and I agree\" to continue: ")

if ANSWER == "I understand, and I agree":
    device = Device(0x27c6, 0x5110)
    device.nop()
    device.enable_chip()
    device.nop()

    firmware = device.firmware_version()

    print(firmware)

    valid_psk = False
    for _ in range(2):
        if check_psk(device.preset_psk_read_r(bytes.fromhex("030002bb"))):
            valid_psk = True
            break

    if firmware == "GF_ST411SEC_APP_12109":
        if not valid_psk:
            device.mcu_erase_app()
            sys_exit()

        print("All good!")

    elif firmware == "GF_ST411SEC_APP_12117":
        device.mcu_erase_app()
        sys_exit()

    elif firmware == "MILAN_ST411SEC_IAP_12101":
        if not valid_psk:
            device.preset_psk_write_r(
                bytes.fromhex("020001bb"), 332,
                bytes.fromhex(
                    "01000000d08c9ddf0115d1118c7a00c04fc297eb010000001632f79f9db1db40bb6f18511c57c59904000000400000005400680069007300200069007300200074006800650020006400650073006300720069007000740069006f006e00200073007400720069006e0067002e0000001066000000010000200000002a2e5a0b50e0e171920150c472b381050d6496e7c31d9c1932ceb89edd50bb7a000000000e8000000002000020000000bd306777413513399b5d04b7a9f51643f19acae70a4688ac86e3373401d4221230000000de58863c3299bad9ddd14ffa7599291960513ce383d8bd1424b646eb02836bdbe0f77fc1c648e31d149f7099f3c806a74000000031807f5160b6f1f2dc0f0c368ab7ecf5b810c975d64f075b1e3d22927cf5c9eaef9bbf08d92e067bf2a3e3d596e64f65d55e8cff233dd38ed8a813b7862aa49fb24fbb7f4dfdf1ca030001bb60000000ec35ae3abb45ed3f12c4751f1e5c2cc085382cd3def23442578f800ca13267610a88d2f4c6677412c8ff044cf69d250e80bf32bcf024fddc041ca10b6cd928c77130b7d1a4a88af2f747f2e94e8620e31b837a3a8a80fbbd193fdfe67187a758"
                ))

        ##################################################
        # Carfull! If you change the firmware you also need to change the data
        # parameter at device.update_firmware()
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

        sys_exit()

    else:
        raise ValueError(
            "Invalid firmware. Abort.\n"
            "##################################################\n"
            "Please consider that removing this security is a very bad idea!\n"
            "##################################################\n")

else:
    print("Abort. You have chosen the right option!")
