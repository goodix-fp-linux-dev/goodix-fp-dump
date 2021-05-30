import matplotlib.pyplot as plt
import numpy as np

from goodix import Device

SENSOR_HEIGHT = 80
SENSOR_WIDTH = 64

firstRun = True
calibPattern = []


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

    cropped_data = []
    for lineNr in range(0, SENSOR_HEIGHT):
        cropped_data.extend(unpacked_values[lineNr * 88:(lineNr * 88) + 64])

    counter = 0
    for value in cropped_data:
        fout.write("%d\n" % (calibPattern[counter] - value))
        counter += 1

    fout.close()


def plot_pgm(suffix=""):
    data = readpgm('unpacked_image%s.pgm' % suffix)
    plt.clf()
    plt.imshow(np.reshape(data[0], data[1]))
    plt.show(block=False)
    plt.pause(0.0000001)


def save_calib(unpacked_values):
    global calibPattern
    for lineNr in range(0, SENSOR_HEIGHT):
        calibPattern.extend(unpacked_values[lineNr * 88:(lineNr * 88) + 64])


def readpgm(name):
    with open(name) as f:
        lines = f.readlines()

    # Ignores commented lines
    for l in list(lines):
        if l[0] == '#':
            lines.remove(l)

    # Makes sure it is ASCII format (P2)
    assert lines[0].strip() == 'P2'

    # Converts data to a list of integers
    data = []
    for line in lines[1:]:
        data.extend([int(c) for c in line.split()])

    return (np.array(data[3:]), (data[1], data[0]), data[2])


print("##################################################\n"
      "This program might break your device.\n"
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
    device = Device(0x27c6, 0x5110)
    device.nop()
    device.enable_chip()
    device.nop()

    if device.firmware_version() == "GF_ST411SEC_APP_12109":
        device.setup()
        while True:
            device.mcu_get_image()
            data = bytes()

            for i in range(0x180090e9, 0x1800ba29, 960):
                data += device.read_firmware(i, 960)

            unpack = unpack_data_to_16bit(data)
            #save_as_16bit_le(unpack)
            if firstRun == True:
                save_calib(unpack)
                firstRun = False
            else:
                save_pgm(unpack)
                plot_pgm()
            #sleep(1)

    else:
        raise ValueError(
            "Invalid firmware. Abort.\n"
            "##################################################\n"
            "Please consider that removing this security is a very bad idea!\n"
            "##################################################")

else:
    print("Abort. You have chosen the right option!")
