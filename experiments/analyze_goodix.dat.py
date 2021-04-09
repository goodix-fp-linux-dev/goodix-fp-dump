#!/usr/bin/env python3
#
# analyze_doodix.dat - parse the goodix.dat file created by the Windows driver
#
# Copyright 2019, Collabora Ltd
# Author: Antonio Ospite <antonio.ospite@collabora.com>
#
# SPDX-License-Identifier: LGPL-2.1-or-later

import crcmod
import struct
import sys


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: %s <datafile>\n" % sys.argv[0])
        return 1

    fin = open(sys.argv[1], 'rb')
    buf = fin.read()
    fin.close()

    # CRC is on the last 4 bytes, in little-endian format
    data_crc = struct.unpack_from('<I', buf[-4:])[0]

    # The algorithm used is CRC-32/MPEG-2
    crc32_func = crcmod.predefined.mkCrcFun('crc-32-mpeg')
    calc_crc = crc32_func(buf[:-4])

    print(hex(data_crc))
    print(hex(calc_crc))

    assert data_crc == calc_crc

    return 0


if __name__ == "__main__":
    sys.exit(main())
