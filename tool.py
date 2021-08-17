from socket import socket
from time import sleep
from typing import List

from goodix import (FLAGS_TRANSPORT_LAYER_SECURITY, Device, check_message_pack,
                    encode_message_pack)


def warning(text: str) -> str:
    decorator = "#" * len(max(text.split("\n"), key=len))
    return f"\033[31;5m{decorator}\n{text}\n{decorator}\033[0m"


def decode_image(data: bytes) -> List[int]:
    image = []
    for i in range(0, len(data), 6):
        chunk = data[i:i + 6]

        image.append(((chunk[0] & 0xf) << 8) + chunk[1])
        image.append((chunk[3] << 4) + (chunk[0] >> 4))
        image.append(((chunk[5] & 0xf) << 8) + chunk[2])
        image.append((chunk[4] << 4) + (chunk[5] >> 4))

    return image


def write_pgm(image: List[int], width: int, height: int, filename: str) -> None:
    file = open(filename, "w")

    file.write(f"P2\n{height} {width}\n4095\n")
    file.write("\n".join(map(str, image)))

    file.close()


def connect_device(device: Device, tls_client: socket) -> None:
    tls_client.sendall(device.request_tls_connection())

    device.protocol.write(
        encode_message_pack(tls_client.recv(1024),
                            FLAGS_TRANSPORT_LAYER_SECURITY))

    tls_client.sendall(
        check_message_pack(device.protocol.read(),
                           FLAGS_TRANSPORT_LAYER_SECURITY))
    tls_client.sendall(
        check_message_pack(device.protocol.read(),
                           FLAGS_TRANSPORT_LAYER_SECURITY))
    tls_client.sendall(
        check_message_pack(device.protocol.read(),
                           FLAGS_TRANSPORT_LAYER_SECURITY))

    device.protocol.write(
        encode_message_pack(tls_client.recv(1024),
                            FLAGS_TRANSPORT_LAYER_SECURITY))

    sleep(0.01)  # Important otherwise an USBTimeout error occur
