#!/usr/bin/env python3
#
# pseudo_colors - convert a 16bpp little-endian grayscale image to pseudo colors
#
# Copyright 2019, Collabora Ltd
# Author: Antonio Ospite <antonio.ospite@collabora.com>
#
# SPDX-License-Identifier: LGPL-2.1-or-later

import colorsys
import struct
import sys


# Hardcode image size for now
WIDTH = 108
HEIGHT= 88

# data has 12bpp precision scale hue values to that
MAX_VALUE = (1 << 12) - 1


def pseudo_color(value):
        hue = value / MAX_VALUE

        # scale hue to be between 0 and 120
        hue /= (360 / 120)
        rgb_color = colorsys.hsv_to_rgb(hue, 1, 1)

        r, g, b = (int(c * 255) for c in rgb_color)

        return r, g, b


# data is an array of 16-bit elements
# the output is an array of rgb values
def convert_to_pseudo_colors(data):
    rgb_data = []

    for value in data:
        r, g, b = pseudo_color(value)
        rgb_data.append(r)
        rgb_data.append(g)
        rgb_data.append(b)

    return rgb_data


def save_pnm(rgb_data, filename):
    fout = open(filename, 'w+')
    fout.write('P3\n')
    fout.write("%d %d\n" % (WIDTH, HEIGHT))
    fout.write("255\n")

    for c in rgb_data:
        fout.write("%d\n" % c)

    fout.close()


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: %s <datafile> [<suffix>]\n" % sys.argv[0])
        return 1

    try:
        suffix = "_" + sys.argv[2]
    except IndexError:
        suffix = ""

    fin = open(sys.argv[1], 'rb')
    buf = fin.read()
    fin.close()

    # work with unpacked 16bpp data
    #assert (len(buf) == WIDTH * HEIGHT * 2)

    # each data element is two bytes in little-endian order
    gray16_data_len = len(buf) // 2
    data_fmt = "<%dH" % gray16_data_len
    gray16_data = struct.unpack_from(data_fmt, buf)

    rgb_data = convert_to_pseudo_colors(gray16_data)

    save_pnm(rgb_data,  "rgb_image%s.pnm" % suffix)

    fout = open("rgb_image%s.bin" % suffix, 'wb+')
    fout.write(bytearray(rgb_data))
    fout.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
