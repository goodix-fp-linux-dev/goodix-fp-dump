#!/usr/bin/env python3
#
# decode_image_data - extract payload and unpack data from an image packet
#
# Copyright 2019, Collabora Ltd
# Author: Antonio Ospite <antonio.ospite@collabora.com>
#
# SPDX-License-Identifier: LGPL-2.1-or-later

import struct
import sys

import crcmod


# Hardcode image size for now
WIDTH = 108
HEIGHT = 88


# The data passed is the raw image packet received from a Goodix fingerprint
# reader, e.g. the Leftover Capture Data of a USB URB in a Wireshark capture.
def extract_payload(data):
    assert len(data) >= 4
    assert data[0] == 0x20

    payload_size = struct.unpack_from('<H', data[1:3])[0]

    assert payload_size > 0

    payload = bytearray()

    # first chunk
    offset = 3
    remaining = payload_size - 1  # skip checksum byte

    # the first chunk can also be the last one
    if remaining < 64 - 3:
        payload += data[offset:offset + remaining]
        return payload

    # first of multiple chunks
    chunk_size = 64 - 3

    payload += data[offset:offset + chunk_size]
    offset += chunk_size + 1  # skip the next continuation byte
    remaining -= chunk_size

    # copy most of the data, skipping the continuation bytes
    chunk_size = 64 - 1
    while remaining >= chunk_size:
        payload += data[offset:offset + chunk_size]
        offset += chunk_size + 1  # skip the next continuation byte
        remaining -= chunk_size

    # copy the last chunk
    payload += data[offset:offset + remaining]

    return payload


# data is 12-bit packed, unpack it to 16-bit elements
def unpack_data_to_16bit(data):
    # 3 bytes are needed to represent 2 16-bit values
    assert (len(data) % 3) == 0

    mask = (1 << 12) - 1
    num_values = len(data) // (12 / 8)

    i = 0
    offset = 0
    unpacked_values = []

    while i < num_values:
        tmp_buffer = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]

        value1 = (tmp_buffer >> 12) & mask
        unpacked_values.append(value1)

        value2 = tmp_buffer & mask
        unpacked_values.append(value2)

        i += 2
        offset += 3

    return unpacked_values


def save_as_16bit_le(unpacked_values, suffix=""):
    unpacked_data = []

    for value in unpacked_values:
        upper = (value >> 8) & 0xff
        lower = value & 0xff
        # Write single bytes in little-endian order
        unpacked_data.append(lower)
        unpacked_data.append(upper)

    fout = open("unpacked_image%s.bin" % suffix, 'wb+')
    fout.write(bytearray(unpacked_data))
    fout.close()


def save_pgm(unpacked_values, suffix=""):
    fout = open('unpacked_image%s.pgm' % suffix, 'w+')
    fout.write('P2\n')
    fout.write("%d %d\n" % (WIDTH, HEIGHT))

    # 16bpp data
    fout.write("4095\n")

    for value in unpacked_values:
        fout.write("%d\n" % value)

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

    payload = extract_payload(buf)

    fout = open("payload%s.bin" % suffix, 'wb+')
    fout.write(bytearray(payload))
    fout.close()

    # According to the Windows driver the first 5 bytes are to be skipped
    # (probably some header), and the last 4 bytes too as they should be a crc.
    image_data = payload[5:-4]

    assert len(image_data) == WIDTH * HEIGHT * 3 / 2

    fout = open("image_data%s.bin" % suffix, 'wb+')
    fout.write(bytearray(image_data))
    fout.close()

    # CRC is on the last 4 bytes, but it is in a mixed endian scheme.
    # Swap two big endian 16-bit values
    data_crc = \
            struct.unpack_from('>H', payload[-2:])[0] << 16 | \
            struct.unpack_from('>H', payload[-4:])[0]

    # The algorithm used is CRC-32/MPEG-2
    crc32_func = crcmod.predefined.mkCrcFun('crc-32-mpeg')
    calc_crc = crc32_func(image_data)

    #print(hex(data_crc))
    #print(hex(calc_crc))

    assert data_crc == calc_crc

    unpacked_values = unpack_data_to_16bit(image_data)

    assert len(unpacked_values) == WIDTH * HEIGHT

    save_pgm(unpacked_values, suffix)
    save_as_16bit_le(unpacked_values, suffix)

    return 0


if __name__ == "__main__":
    sys.exit(main())
