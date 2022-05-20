import socket
import time

import goodix


def warning(text: str):
    decorator = "#" * len(max(text.split("\n"), key=len))
    return f"\033[31;5m{decorator}\n{text}\n{decorator}\033[0m"


def connect_device(device: goodix.Device, tls_client: socket.socket):
    tls_client.sendall(device.request_tls_connection())

    device.protocol.write(
        goodix.encode_message_pack(tls_client.recv(1024),
                                   goodix.FLAGS_TRANSPORT_LAYER_SECURITY))

    tls_client.sendall(
        goodix.check_message_pack(device.protocol.read(),
                                  goodix.FLAGS_TRANSPORT_LAYER_SECURITY))
    tls_client.sendall(
        goodix.check_message_pack(device.protocol.read(),
                                  goodix.FLAGS_TRANSPORT_LAYER_SECURITY))
    tls_client.sendall(
        goodix.check_message_pack(device.protocol.read(),
                                  goodix.FLAGS_TRANSPORT_LAYER_SECURITY))

    device.protocol.write(
        goodix.encode_message_pack(tls_client.recv(1024),
                                   goodix.FLAGS_TRANSPORT_LAYER_SECURITY))

    time.sleep(0.01)  # Important otherwise an USBTimeout error occur


def decode_image(data: bytes):
    image: list[int] = []
    for i in range(0, len(data), 6):
        chunk = data[i:i + 6]

        image.append(((chunk[0] & 0xf) << 8) + chunk[1])
        image.append((chunk[3] << 4) + (chunk[0] >> 4))
        image.append(((chunk[5] & 0xf) << 8) + chunk[2])
        image.append((chunk[4] << 4) + (chunk[5] >> 4))

    return image


def write_pgm(image: list[int], width: int, height: int, filename: str):
    file = open(filename, "w")

    file.write(f"P2\n{height} {width}\n4095\n")
    file.write("\n".join(map(str, image)))

    file.close()
