from goodix import Device

VENDOR = 0x27c6
PRODUCT = 0x5110
INTERFACE = 1

print("##################################################\n"
      "This program should be safe.\n"
      "But please consider that it will try to use a firmware command.\n"
      "Continue at your own risk but don't hold us "
      "responsible if your device is broken!\n"
      "##################################################")

if input("Type \"I understand, and I agree\" to continue: "
         ) == "I understand, and I agree":

    device = Device(VENDOR, PRODUCT, INTERFACE)

    firmware = device.firmware_version()

    reply = device.read_firmware(0, 1)

    print("##################################################\n"
          f"Firmware version: \"{firmware}\"\n"
          f"Received {reply}")

    if len(reply) == 1:
        print("The 0xf2 command seems to work on the device")
    print("##################################################")

else:
    print("Abort.")
