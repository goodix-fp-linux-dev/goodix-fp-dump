from goodix import Device

SENSOR_HEIGHT = 80
SENSOR_WIDTH = 88


def unpack_data_to_16bit(data):
    assert (len(data) % 6) == 0

    out = []
    for i in range(0, len(data), 6):
        chunk = data[i:i + 6]
        o1 = ((chunk[0] & 0xf) << 8) + chunk[1]
        o2 = (chunk[3] << 4) + (chunk[0] >> 4)
        o3 = ((chunk[5] & 0xf) << 8) + chunk[2]
        o4 = (chunk[4] << 4) + (chunk[5] >> 4)
        out += [o1, o2, o3, o4]
    return out


def save_as_16bit_le(unpacked_values, suffix=""):
    unpacked_data = []

    for value in unpacked_values:
        value = value << 4
        upper = (value >> 8) & 0xff
        lower = value & 0xff
        # Write single bytes in little-endian order
        unpacked_data.append(lower)
        unpacked_data.append(upper)

    fout = open("image_16bitLE%s.data" % suffix, 'wb+')
    fout.write(bytearray(unpacked_data))
    fout.close()


def save_pgm(unpacked_values, suffix=""):
    fout = open('unpacked_image%s.pgm' % suffix, 'w+')
    fout.write('P2\n')
    height = SENSOR_HEIGHT
    width = SENSOR_WIDTH
    fout.write("%d %d\n" % (width, height))

    fout.write("4095\n")

    for value in unpacked_values:
        fout.write("%d\n" % value)

    fout.close()


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

    if device.firmware_version() == "GF_ST411SEC_APP_12109":
        device.setup()

        device.mcu_get_image()

        data = bytes()

        for i in range(0x180090e9, 0x1800ba29, 960):
            data += device.read_firmware(i, 960)

        unpack = unpack_data_to_16bit(data)
        save_as_16bit_le(unpack)
        save_pgm(unpack)

    else:
        raise ValueError("Invalid firmware. Abort.\n"
                         "#####  /!\\  Please consider that removing this "
                         "security is a very bad idea  /!\\  #####")

else:
    print("Abort. You have chosen the right option!")
