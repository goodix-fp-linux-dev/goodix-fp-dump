# from sys import exit as sys_exit

# from goodix import Device
# from goodix.dev_5110 import check_firmware, check_psk, init_device

# SENSOR_HEIGHT = 88
# SENSOR_WIDTH = 80

# # device.reset()

# # #####

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# #                 data=bytes.fromhex("82060000000004001e")))
# # sleep(0.1)

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# #                 data=bytes.fromhex("a60300000001")))
# # sleep(0.1)

# # device.reset()

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# #                 data=bytes.fromhex("700300140023")))
# # sleep(0.1)

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# #                 data=bytes.fromhex("800600002002780b7f")))
# # sleep(0.1)

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# #                 data=bytes.fromhex("800600003602b90033")))
# # sleep(0.1)

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# #                 data=bytes.fromhex("800600003802b70033")))
# # sleep(0.1)

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# #                 data=bytes.fromhex("800600003a02b70031")))
# # sleep(0.1)

# # device.write_message_pack(
# #     MessagePack(
# #         flags=FLAGS_MESSAGE_PROTOCOL,
# #         data=bytes.fromhex(
# #             "900101701160712c9d2cc91ce518fd00fd00fd03ba000180"
# #             "ca000400840015b3860000c4880000ba8a0000b28c0000aa"
# #             "8e0000c19000bbbb9200b1b1940000a8960000b698000000"
# #             "9a000000d2000000d4000000d6000000d800000050000105"
# #             "d0000000700000007200785674003412200010402a010204"
# #             "2200012024003200800001005c0080005600042058000302"
# #             "32000c02660003007c000058820080152a01820322000120"
# #             "24001400800001005c000001560004205800030232000c02"
# #             "660003007c0000588200801f2a0108005c00800054001001"
# #             "6200040364001900660003007c0001582a0108005c000001"
# #             "5200080054000001660003007c00015800892e6f")))
# # sleep(0.1)

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# #                 data=bytes.fromhex("9403006400af")))
# # sleep(0.1)

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# #                 data=bytes.fromhex("9403006400af")))
# # sleep(0.1)

# # #####

# # tls_server = Popen([
# #     'openssl', 's_server', '-nocert', '-psk',
# #     PSK.hex(), '-port', '4433', '-quiet'
# # ],
# #                    stdout=PIPE,
# #                    stderr=STDOUT)

# # client_hello = device.request_tls_connection()

# # print(client_hello.hex(" "))

# # tls_client = socket()
# # tls_client.connect(("localhost", 4433))
# # tls_client.sendall(client_hello)
# # server_hello = tls_client.recv(1024)

# # print(server_hello.hex(" "))

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_TRANSPORT_LAYER_SECURITY,
# #                 data=server_hello))

# # start = time()
# # messages = device.read_message_pack(
# #     start,
# #     lambda message: message.flags >= FLAGS_TRANSPORT_LAYER_SECURITY
# #     and len(message.data) >= message.length, 3)

# # for message in messages:
# #     tls_client.sendall(message.data)

# # server_handshake = tls_client.recv(1024)

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_TRANSPORT_LAYER_SECURITY,
# #                 data=server_handshake))

# # # device.tls_successfully_established()

# # #####

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# #                 data=bytes.fromhex("ae020055a5")))
# # sleep(0.1)

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# #                 data=bytes.fromhex(
# #                     "360f000d01afafbfbfa4a4b8b8a8a8b7b705")))
# # sleep(0.1)

# # # device.write_message_pack(
# # #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# # #                 data=bytes.fromhex("500300010056")))
# # # sleep(0.1)

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# #                 data=bytes.fromhex(
# #                     "360f000d0180af80c080a480b780a780b630")))
# # sleep(0.1)

# # device.write_message_pack(
# #     MessagePack(flags=FLAGS_MESSAGE_PROTOCOL,
# #                 data=bytes.fromhex("82060000820002009e")))
# # sleep(0.1)

# # #####

# # print("Put your finger on the sensor")

# # sleep(5)

# # img = device.mcu_get_image()

# # tls_client.send(img)
# # image = tls_server.stdout.read(10573)

# # unpacked = unpack_data_to_16bit(image[8:-5])

# # save_pgm(unpacked)

# # tls_client.close()
# # tls_server.terminate()

# def main(product: int) -> int:
#     device = Device(product)

#     init_device(device)

#     firmware = check_firmware(device)

#     valid_psk = check_psk(device)

#     if not firmware:
#         print("Invalid firmware: Abort")
#         return -1

#     if not valid_psk:
#         print("Invalid PSK: Abort")
#         return -1

#     device.reset()

#     return 0

# if __name__ == "__main__":
#     sys_exit(main(0x5110))
