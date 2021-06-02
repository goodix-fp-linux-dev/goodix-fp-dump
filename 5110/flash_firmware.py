from socket import socket
from subprocess import PIPE, Popen, STDOUT
from time import sleep, time
from crcmod.predefined import mkCrcFun

from goodix import Device, FLAGS_MESSAGE_PROTOCOL, FLAGS_TRANSPORT_LAYER_SECURITY, Message, MessagePack

SENSOR_HEIGHT = 88
SENSOR_WIDTH = 80

PSK = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")
PSK_WB = bytes.fromhex(
    "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000001c849b9831e694c"
    "b3ef601ff3e13c3c040000004000000054006800690073002000690073002000"
    "74006800650020006400650073006300720069007000740069006f006e002000"
    "73007400720069006e0067002e0000001066000000010000200000003ff07b38"
    "3d00fb003592b4c8fa6aab2e17a172409ad745d3b6464274a662df1500000000"
    "0e80000000020000200000003cd09ee49c63e336c144d125842ae92ad50b53cf"
    "8dfd104971475b74f90d9d833000000064c19ffff8280ec919533bfb5f7bf3b4"
    "18632c4544c66d3af8341a4f24ac7cdeafbe52d2d03848d5e70bc7fe3ce0f295"
    "4000000070583734b732ceed6aae6df5338908931d73baafb96950af4fd8d546"
    "da11f7a18c86b8fb06bc6a96247840f884e354e24128e61739991717fa1c6e91"
    "60960399d7b9450b7c3547b1030001bb60000000ec35ae3abb45ed3f12c4751f"
    "1e5c2cc05b3c5452e9104d9f2a3118644f37a04b6fd66b1d97cf80f1345f76c8"
    "4f03ff30bb51bf308f2a9875c41e6592cd2a2f9e60809b17b5316037b69bb2fa"
    "5d4c8ac31edb3394046ec06bbdacc57da6a756c5")
PMK_HASH = bytes.fromhex(
    "ba1a86037c1d3c71c3af344955bd69a9a9861d9e911fa24985b677e8dbd72d43")


def check_psk(psk: bytes) -> bool:
    print(psk)
    return psk == PMK_HASH


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


# saves unpacked values as pgm file
def save_pgm(unpacked_values, suffix=""):
    fout = open('unpacked_image%s.pgm' % suffix, 'w+')
    fout.write('P2\n')
    width = SENSOR_HEIGHT
    height = SENSOR_WIDTH
    fout.write("%d %d\n" % (width, height))

    # 16bpp data, but only 12bit actual value
    fout.write("4095\n")

    for value in unpacked_values:
        fout.write("%d\n" % value)

    fout.close()


print("##################################################\n"
      "This program might break your device.\n"
      "Consider that it will flash the device firmware.\n"
      "Be sure to have the device 27c6:5110 or 27c6:5117.\n"
      "Continue at your own risk.\n"
      "But don't hold us responsible if your device is broken!\n"
      "##################################################")

ANSWER = ""
##################################################
# Please be careful when uncommenting this line!
ANSWER = "I understand, and I agree"
##################################################

if not ANSWER:
    ANSWER = input("Type \"I understand, and I agree\" to continue: ")

if ANSWER == "I understand, and I agree":
    while True:
        device = Device(0x5110, 1)
        device.nop()
        device.enable_chip()
        device.nop()

        firmware = device.firmware_version()

        VALID_PSK = False
        for _ in range(2):
            if check_psk(device.preset_psk_read_r(0xbb020003)):
                VALID_PSK = True
                break

        if firmware == "GF_ST411SEC_APP_12109":
            if not VALID_PSK:
                device.mcu_erase_app()
                device.wait_disconnect()
                continue

            device.reset()

            #####

            device.write_message_pack(
                MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
                            data=bytes.fromhex("82060000000004001e")))
            sleep(0.1)

            device.write_message_pack(
                MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
                            data=bytes.fromhex("a60300000001")))
            sleep(0.1)

            device.reset()

            device.write_message_pack(
                MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
                            data=bytes.fromhex("700300140023")))
            sleep(0.1)

            device.write_message_pack(
                MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
                            data=bytes.fromhex("800600002002780b7f")))
            sleep(0.1)

            device.write_message_pack(
                MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
                            data=bytes.fromhex("800600003602b90033")))
            sleep(0.1)

            device.write_message_pack(
                MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
                            data=bytes.fromhex("800600003802b70033")))
            sleep(0.1)

            device.write_message_pack(
                MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
                            data=bytes.fromhex("800600003a02b70031")))
            sleep(0.1)

            device.write_message_pack(
                MessagePack(
                    flags=FLAGS_MESSAGE_PROTOCOL,
                    data=bytes.fromhex(
                        "900101701160712c9d2cc91ce518fd00fd00fd03ba000180"
                        "ca000400840015b3860000c4880000ba8a0000b28c0000aa"
                        "8e0000c19000bbbb9200b1b1940000a8960000b698000000"
                        "9a000000d2000000d4000000d6000000d800000050000105"
                        "d0000000700000007200785674003412200010402a010204"
                        "2200012024003200800001005c0080005600042058000302"
                        "32000c02660003007c000058820080152a01820322000120"
                        "24001400800001005c000001560004205800030232000c02"
                        "660003007c0000588200801f2a0108005c00800054001001"
                        "6200040364001900660003007c0001582a0108005c000001"
                        "5200080054000001660003007c00015800892e6f")))
            sleep(0.1)

            device.write_message_pack(
                MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
                            data=bytes.fromhex("9403006400af")))
            sleep(0.1)

            device.write_message_pack(
                MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
                            data=bytes.fromhex("9403006400af")))
            sleep(0.1)

            #####

            tls_server = Popen([
                'openssl', 's_server', '-nocert', '-psk',
                PSK.hex(), '-port', '4433', '-quiet'
            ],
                               stdout=PIPE,
                               stderr=STDOUT)

            client_hello = device.request_tls_connection()

            print(client_hello.hex(" "))

            tls_client = socket()
            tls_client.connect(("localhost", 4433))
            tls_client.sendall(client_hello)
            server_hello = tls_client.recv(1024)

            print(server_hello.hex(" "))

            device.write_message_pack(
                MessagePack(flags=FLAGS_TRANSPORT_LAYER_SECURITY,
                            data=server_hello))

            start = time()
            messages = device.read_message_pack(
                start,
                lambda message: message.flags >= FLAGS_TRANSPORT_LAYER_SECURITY
                and len(message.data) >= message.length, 3)

            for message in messages:
                tls_client.sendall(message.data)

            server_handshake = tls_client.recv(1024)

            device.write_message_pack(
                MessagePack(flags=FLAGS_TRANSPORT_LAYER_SECURITY,
                            data=server_handshake))

            # device.tls_successfully_established()

            #####

            device.write_message_pack(
                MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
                            data=bytes.fromhex("ae020055a5")))
            sleep(0.1)

            device.write_message_pack(
                MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
                            data=bytes.fromhex(
                                "360f000d01afafbfbfa4a4b8b8a8a8b7b705")))
            sleep(0.1)

            # device.write_message_pack(
            #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
            #                 data=bytes.fromhex("500300010056")))
            # sleep(0.1)

            device.write_message_pack(
                MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
                            data=bytes.fromhex(
                                "360f000d0180af80c080a480b780a780b630")))
            sleep(0.1)

            device.write_message_pack(
                MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
                            data=bytes.fromhex("82060000820002009e")))
            sleep(0.1)

            #####

            print("Put your finger on the sensor")

            sleep(5)

            img = device.mcu_get_image()

            tls_client.send(img)
            image = tls_server.stdout.read(10573)

            unpacked = unpack_data_to_16bit(image[8:-5])

            save_pgm(unpacked)

            tls_client.close()
            tls_server.terminate()

            break

        if "GF_ST411SEC_APP_121" in firmware:
            device.mcu_erase_app()
            device.wait_disconnect()

        elif firmware == "MILAN_ST411SEC_IAP_12101":
            if not VALID_PSK:
                device.preset_psk_write_r(0xbb010002, 332, PSK_WB)

            firmware_file = open("GF_ST411SEC_APP_12109.bin", "rb")

            while True:
                offset = firmware_file.tell()
                data = firmware_file.read(1008)

                device.write_firmware(offset, data)

                if len(data) < 1008:
                    break

            length = firmware_file.tell()
            firmware_file.seek(0)

            device.update_firmware(
                0, length,
                mkCrcFun("crc-32-mpeg")(firmware_file.read()))

            firmware_file.close()

            device.reset(False, True)
            device.wait_disconnect()

        else:
            raise ValueError(
                "Invalid firmware. Abort.\n"
                "##################################################\n"
                "Please consider that removing this security "
                "is a very bad idea!\n"
                "##################################################")

else:
    print("Abort. You have chosen the right option!")
