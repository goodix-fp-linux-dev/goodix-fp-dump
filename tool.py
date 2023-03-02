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


def write_pgm(image: list[int], width: int, height: int, path: str):
    img_str = ""
    print(f"image: {width} x {height}, length: {len(image)}")
    for i in range(len(image)):
        if (i % height) == 0:
            img_str += "\n"
        img_str += "%4d" % image[i] + " "

    file = open(path, "w")
    file.write(f"P2\n{height} {width}\n4095\n")
    file.write("\n" + img_str)

def read_pgm(path: str):
    with open(path, "r") as file:
        data = file.readlines()

    # It isn't compliant with PGM spec, but can read files produced
    # by write_pgm()
    header = data[0].split()
    if header[0] != "P2":
        return None
    dimensions = data[1].split()
    (width, height) = (int(dimensions[0]), int(dimensions[1]))
    depth = int(data[2].split()[0])
    image = []
    for line in data[3:]:
        for num in line.split():
            image.append(int(num))

    return (width, height, depth, image)
