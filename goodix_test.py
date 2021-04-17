import time
import usb.core
import usb.util
import struct
import subprocess
import matplotlib.pyplot as plt
import numpy as np
import sys
import socket

DEBUG = True
EXPECTED_FW = b"GF3206_RTSEC_APP_10056\x00"
PSK = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")
PSK_WB = bytes.fromhex(
    "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5"
)
PMK_HASH = bytes.fromhex(
    "81b8ff490612022a121a9449ee3aad2792f32b9f3141182cd01019945ee50361")

SENSOR_WIDTH = 64
SENSOR_HEIGHT = 80


# connect to the fingerprint reader via USB
def connectDevice():
    global IN, OUT
    # find our device
    dev = usb.core.find(idVendor=0x27c6, idProduct=0x5110)

    # was it found?
    if dev is None:
        raise ValueError('Device not found')

    # reset device
    dev.reset()

    cfg = dev.configurations()

    print("device configs:")
    print(cfg)

    print("We only have one, print its interfaces")
    # set the active configuration. With no arguments, the first
    # configuration will be the active one
    cfg = cfg[0]
    dev.set_configuration(cfg)
    # cfg = dev.get_active_configuration()

    print(cfg.interfaces())
    print("Again, only one. Lets view its endpoints")
    intf = cfg.interfaces()[1]

    print(intf)
    OUT = intf[0]
    IN = intf[1]
    assert usb.util.endpoint_direction(
        OUT.bEndpointAddress) == usb.util.ENDPOINT_OUT
    assert usb.util.endpoint_direction(
        IN.bEndpointAddress) == usb.util.ENDPOINT_IN


# example how to replay raw bytes. unused.
def get_fw_version():
    print("Getting FW Version")
    fwhex = "a00600a6a803000000ff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    OUT.write(bytes.fromhex(fwhex))

    # read ack
    res = bytes(IN.read(100))
    print("Received " + res.hex())

    # read fw version
    res = bytes(IN.read(100))
    print("Received " + res.hex())


# pads byte array with zeros, so that its length is a multiple of 64
def padTo64(data):
    if len(data) % 64:
        data = data + b"\x00" * (64 - len(data) % 64)
    return data


# sends a command to the device and waits for reply_count replies, which it returns.
def sendcmd(cmd, reply_count):
    if DEBUG: print("sending command " + cmd.hex())
    cmd = padTo64(cmd)

    for i in range(0, len(cmd), 64):
        OUT.write(cmd[i:i + 64])

    res = []
    # read reply_count replies
    for i in range(reply_count):
        rsp = bytes(IN.read(20000, timeout=10000))
        res.append(rsp)
        if DEBUG: print("Received " + rsp.hex())

    return res


# sends a TLS command to the device and waits for reply_count replies, which it returns.
def sendtls(payload, reply_count):
    # add header first.
    header = b"\xB0"
    header += struct.pack("<h", len(payload))
    header += bytes((sum(header) & 0xff, ))  # checksum of header is simple sum

    cmd = padTo64(header + payload)
    if DEBUG: print("sending tls " + cmd.hex())

    for i in range(0, len(cmd), 64):
        OUT.write(cmd[i:i + 64])

    res = []
    # read reply_count replies
    for i in range(reply_count):
        rsp = bytes(IN.read(20000, timeout=1000))
        res.append(rsp)
        if DEBUG: print("Received " + rsp.hex())

    return res


def construct_cmd_payload(cmd, data):
    payload = bytes((cmd, ))

    targetlen = len(data) + 1  # includes checksum byte
    payload += struct.pack("<h", targetlen)
    payload += data

    chksum = 0xaa - sum(payload) & 0xff
    payload += bytes((chksum, ))

    # payload has to be wrapped in usb protocol thingy
    usbheader = bytes((0xa0, ))
    usbheader += struct.pack("<h", len(payload))
    usbheader += bytes(
        (sum(usbheader) & 0xff, ))  # checksum of wrapper is simple sum

    return usbheader + payload


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


# opens a tls connection to the device. First checks the pre shared key (psk).
# If it is not all zero, change it to all zero.
# spawns an openssl server in the background to handle the tls connection.
def initConnection():
    global tlsserver, tlsclient

    # print("send nop")
    # sendcmd(construct_cmd_payload(0x00, bytes.fromhex("00000000")), 1)

    print("Getting FW Version")
    _, fw = sendcmd(construct_cmd_payload(0xa8, bytes.fromhex("0000")), 2)
    print(fw)
    fw = fw[7:-1]
    if fw == EXPECTED_FW:
        print("Found expected firmware!", fw)
    else:
        print("Unexpected Firmware found! Trying anyways..", fw)

    print("PresetPskReadR")
    rsps = sendcmd(
        construct_cmd_payload(0xe4, bytes.fromhex("070002bb00000000")), 2)
    pmk_hash = rsps[-1][16:-1]

    print(rsps)

    print(pmk_hash)

    print(PMK_HASH)

    # if pmk_hash != PMK_HASH:
    #     print("Chip has wrong PSK. Updating..")

    #     print("Write PSKID")
    #     rsps = sendcmd(
    #         construct_cmd_payload(
    #             0xe0,
    #             bytes.fromhex("""
    #         020001bb
    #         0e000000
    #         4141414142424242434343434444
    #         """.replace("\n", ""))), 2)

    #     print("Write PSK")
    #     rsps = sendcmd(
    #         construct_cmd_payload(
    #             0xe0,
    #             bytes.fromhex("""
    #         030001bb
    #         60000000
    #         """.replace("\n", "")) + PSK_WB), 2)
    # else:
    #     print("Chip already uses our PSK!")

    # start TLS server
    tlsserver = subprocess.Popen(
        "openssl s_server -nocert -psk 0000000000000000000000000000000000000000000000000000000000000000 -port 4433 -quiet"
        .split(" "),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    time.sleep(0.1)

    print("request TLS connect. FP will send client hello back.")
    rsps = sendcmd(construct_cmd_payload(0xD0, bytes.fromhex("0000")), 2)
    client_hello = rsps[-1][4:]

    print(client_hello.hex())

    print("connecting...")
    s = socket.socket()
    tlsclient = s
    s.connect(("localhost", 4433))
    s.sendall(client_hello)
    server_hello = s.recv(1024)
    print("got server_hello + server_hello_done as ", server_hello.hex())

    rsps = sendtls(server_hello, 3)
    # [client_key_exchange, change_cipher_spec, enc_handshake_msg] = rsps
    for m in rsps:
        s.sendall(m[4:])

    server_handshake = s.recv(1024)
    sendtls(server_handshake, 0)

    print("Device initialization and TLS connection complete!")


def someInitWindowsDoes():
    print("Reset")
    sendcmd(construct_cmd_payload(0xa2, bytes.fromhex("0514")), 2)

    print("read reg")
    sendcmd(construct_cmd_payload(0x82, bytes.fromhex("0000000400")), 2)

    # print("send nop")
    # sendcmd(construct_cmd_payload(0x00, bytes.fromhex("00000000")), 1)

    print("read otp")
    sendcmd(construct_cmd_payload(0xa6, bytes.fromhex("0000")), 2)

    # print("pov image check")
    # sendcmd(construct_cmd_payload(0xd6, bytes.fromhex("0000")), 2)

    print("mcu download chip config")
    sendcmd(
        construct_cmd_payload(
            0x90,
            bytes.fromhex(
                "301160712c9d2cc91ce518fd00fd00fd03ba000080ca0006008400beb28600c5b98800b5ad8a009d958c0000be8e0000c5900000b59200009d940000af960000bf980000b69a0000a7d2000000d4000000d6000000d800000012000304d0000000700000007200785674003412200010402a0102002200012024003200800001045c000001560030485800020032000802660000027c000038820080152a0182032200012024001400800001045c00000156000c245800050032000802660000027c000038820080162a0108005c008000540000016200380464001000660000027c0001382a0108005c0000015200080054000001660000027c00013800e858"
            )), 2)

    print("setDrvState")
    sendcmd(construct_cmd_payload(0xc4, bytes.fromhex("0100")), 1)

    # print("mcuGetPovImage")
    # sendcmd(construct_cmd_payload(0xd2, bytes.fromhex("0000")), 2)

    print("mcuSwitchToFdtMode")
    sendcmd(
        construct_cmd_payload(
            0x36,
            bytes.fromhex("0d0180a08093809b80948090808f8094808b808a8083")), 2)


def waitForFinger():
    print("mcuSwitchToFdtDown")
    sendcmd(
        construct_cmd_payload(
            0x32,
            bytes.fromhex("0c0180b980b480b580af80b480ac80b280a780ab80a5")), 2)


def getImage():
    s = tlsclient

    print("McuGetImage")
    rsps = sendcmd(construct_cmd_payload(0x20, bytes.fromhex("0100")), 2)
    # answer is of type 0xb2, which has 4+9 bytes header (contrary to 4 bytes for 0xb0)
    tls_image = rsps[-1][13:]
    s.send(tls_image)

    # read image data
    image = tlsserver.stdout.read(14788)
    if b"error" in image or len(image) != 14788:
        print("Image: ", image, image.hex())

    image, chksum = image[:-4], image[-4:]

    # dump image columns as hex.
    #for i, off in enumerate(range(0, len(image), 168//2)):
    #    print(i, '\t', image[off:off+168//2].hex())

    if DEBUG:
        with open("out.data", "wb") as f:
            f.write(image)

    unpacked = unpack_data_to_16bit(image)

    return unpacked


def readInLoop():
    fig = None
    plt.ion()
    for i in range(1000):
        print(i)
        unpacked = getImage()
        # continue # 16 fps when not plotting, 10 fps when plotting.

        data = np.flipud(
            np.array(unpacked).reshape(
                (SENSOR_HEIGHT, SENSOR_WIDTH)).transpose())

        if not fig:
            fig = plt.imshow(data)
            plt.show()
        else:
            # exit if window closed
            if not plt.get_fignums():
                break
            fig.set_data(data)
            plt.draw()

        plt.pause(0.001)


def main():
    connectDevice()
    exit()
    someInitWindowsDoes()  # not needed?
    initConnection()

    try:
        waitForFinger()

        if len(sys.argv) > 1 and sys.argv[1] == "capture":
            print("getImage")
            unpacked = getImage()
            save_as_16bit_le(unpacked)
            save_pgm(unpacked)
        else:
            print("readInLoop")
            readInLoop()
    except Exception as e:
        print(e)

    # exit tls server
    tlsclient.close()
    tlsserver.terminate()


main()
