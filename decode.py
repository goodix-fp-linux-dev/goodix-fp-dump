import struct
import sys


def decode_packet(packet):
    packet_type = hex(packet[0])
    print(f"Type: {packet_type}")

    # if packet_type != hex(0xa0):
    #     raise ValueError(
    #         "Invalid packet type (This packet might be a continuation packet of the preceding packets)"
    #     )

    size = struct.unpack_from("<H", packet, 1)[0]
    print(f"Payload size: {size}")

    checksum = hex(packet[3])
    print(f"Checksum: {checksum}")

    calculated_checksum = hex(sum(packet[:3]) & 0xff)
    print(f"Calculated checksum: {calculated_checksum}")

    if checksum != calculated_checksum:
        raise ValueError(
            "Invalid header checksum (This packet might be a continuation packet of the preceding packets)"
        )

    payload = packet[4:4 + size]
    print(f"Payload: {payload.hex()}")

    payload_length = len(payload)
    print(f"Payload length: {payload_length}")

    if size != payload_length:
        raise ValueError(
            "Invalid payload length (The payload might be split in multiples packets following this packet)"
        )

    return payload


def decode_payload(payload):
    print(f"Command: {hex(payload[0])}")

    size = struct.unpack_from("<H", payload, 1)[0]
    print(f"Data size: {size-1}")

    data = payload[3:size + 2]
    print(f"Data: {data.hex()}")

    data_length = len(data)
    print(f"Data length: {data_length}")

    if size - 1 != data_length:
        raise ValueError(
            "Invalid data length (The payload might be split in multiples packets following this packet)"
        )

    checksum = hex(payload[size + 2])
    print(f"Checksum: {checksum}")

    calculated_checksum = hex(0xaa - sum(payload[:size + 2]) & 0xff)
    print(f"Calculated checksum: {calculated_checksum}")

    if checksum != calculated_checksum:
        raise ValueError(
            "Invalid payload checksum (The payload might be corrupted)")

    return data


def main():
    for arg in sys.argv[1:]:
        print("#" * len(arg))
        print(arg)
        print("#" * len(arg))

        print()
        payload = decode_packet(bytes.fromhex(arg))

        print()
        decode_payload(payload)


if __name__ == "__main__":
    main()
