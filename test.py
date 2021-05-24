f = open("dump1.txt")

fff = bytes.fromhex(f.read().replace("\n", ""))

SENSOR_HEIGHT = 170
SENSOR_WIDTH = 88


# unpacks packed 12 bit values.
# FROM 01 23 45 67 89 ab
# TO   0x123, 0x670, 0xb45, 0x89a
def unpack_data_to_16bit(data):
    # 6 bytes are needed to represent 4 16-bit values
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


# saves unpacked values as pgm file
def save_pgm(unpacked_values, suffix=""):
    fout = open('unpacked_image%s.pgm' % suffix, 'w+')
    fout.write('P2\n')
    height = SENSOR_HEIGHT
    width = SENSOR_WIDTH
    fout.write("%d %d\n" % (width, height))

    # 16bpp data, but only 12bit actual value
    fout.write("4095\n")

    for value in unpacked_values:
        fout.write("%d\n" % value)

    fout.close()


# rtehetrh = unpack_data_to_16bit(fff[36701:-5])
rtehetrh = unpack_data_to_16bit(fff[36701:-3])
save_as_16bit_le(rtehetrh)
save_pgm(rtehetrh)

f.close
