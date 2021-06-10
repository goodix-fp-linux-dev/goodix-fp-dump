from struct import pack as encode
from struct import unpack as decode
from sys import version_info
from time import sleep, time
from typing import Literal, Optional, Tuple

from usb.control import get_status
from usb.core import Device as USBDevice
from usb.core import USBError, USBTimeoutError, find
from usb.legacy import (CLASS_DATA, DT_CONFIG, ENDPOINT_IN, ENDPOINT_OUT,
                        ENDPOINT_TYPE_BULK, RECIP_DEVICE, REQ_GET_DESCRIPTOR,
                        TYPE_STANDARD)
from usb.util import (build_request_type, endpoint_direction, endpoint_type,
                      find_descriptor)

# TODO Add some documentation
# TODO Create a class with write and read method to be able to add SPI device

if version_info < (3, 8):
    raise SystemError("This program require Python 3.8 or newer")

FLAGS_MESSAGE_PROTOCOL: Literal[0xa0] = 0xa0
FLAGS_TRANSPORT_LAYER_SECURITY: Literal[0xb0] = 0xb0

COMMAND_NOP: Literal[0x00] = 0x00
COMMAND_MCU_GET_IMAGE: Literal[0x20] = 0x20
COMMAND_ENABLE_CHIP: Literal[0x96] = 0x96
COMMAND_RESET: Literal[0xa2] = 0xa2
COMMAND_MCU_ERASE_APP: Literal[0xa4] = 0xa4
COMMAND_FIRMWARE_VERSION: Literal[0xa8] = 0xa8
COMMAND_ACK: Literal[0xb0] = 0xb0
COMMAND_REQUEST_TLS_CONNECTION: Literal[0xd0] = 0xd0
COMMAND_TLS_SUCCESSFULLY_ESTABLISHED: Literal[0xd4] = 0xd4
COMMAND_PRESET_PSK_WRITE_R: Literal[0xe0] = 0xe0
COMMAND_PRESET_PSK_READ_R: Literal[0xe4] = 0xe4
COMMAND_WRITE_FIRMWARE: Literal[0xf0] = 0xf0
COMMAND_READ_FIRMWARE: Literal[0xf2] = 0xf2
COMMAND_CHECK_FIRMWARE: Literal[0xf4] = 0xf4


def encode_command(cmd0: int, cmd1: int, cmd_lsb: bool = False) -> int:
    if not 0x0 <= cmd0 <= 0xf:
        raise ValueError("Invalid command")

    if not 0x0 <= cmd1 <= 0x7:
        raise ValueError("Invalid command")

    return cmd0 << 4 | cmd1 << 1 | (0x1 if cmd_lsb else 0x0)


def decode_command(command: int) -> Tuple[int, int, bool]:
    if not 0x0 <= command <= 0xff:
        raise ValueError("Invalid command")

    return command >> 4 & 0xf, command >> 1 & 0x7, command & 0x1 == 0x1


def encode_message_pack(data: bytes,
                        flags: int = FLAGS_MESSAGE_PROTOCOL,
                        length: Optional[int] = None) -> bytes:
    if length is None:
        length = len(data)

    payload = b""
    payload += encode("<B", flags)
    payload += encode("<H", length)
    payload += encode("<B", sum(payload) & 0xff)
    payload += data

    return payload


def decode_message_pack(payload: bytes) -> Tuple[bytes, int, int]:
    length = decode("<H", payload[1:3])[0]

    if sum(payload[0:3]) & 0xff != payload[3]:
        raise ValueError("Invalid payload")

    return payload[4:4 + length], payload[0], length


def check_message_pack(payload: bytes,
                       flags: int = FLAGS_MESSAGE_PROTOCOL) -> bytes:
    payload = decode_message_pack(payload)
    if payload[1] != flags or len(payload[0]) < payload[2]:
        raise ValueError("Invalid message pack")

    return payload[0]


def encode_message_protocol(data: bytes,
                            command: int,
                            length: Optional[int] = None) -> bytes:
    if length is None:
        length = len(data)

    payload = b""
    payload += encode("<B", command)
    payload += encode("<H", length + 1)
    payload += data
    payload += encode("<B", 0xaa - sum(payload) & 0xff)

    return payload


def decode_message_protocol(payload: bytes) -> Tuple[bytes, int, int]:
    length = decode("<H", payload[1:3])[0]

    if 0xaa - sum(payload[0:2 + length]) & 0xff != payload[2 + length]:
        raise ValueError("Invalid payload")

    return payload[3:2 + length], payload[0], length - 1


def check_message_protocol(payload: bytes, command: int) -> bytes:
    payload = decode_message_protocol(payload)
    if payload[1] != command or len(payload[0]) < payload[2]:
        raise ValueError("Invalid message protocol")

    return payload[0]


def encode_ack(command: int, configured: bool = True) -> bytes:
    return encode("<B", command) + encode(
        "<B", (0x1 if not configured else 0x0) << 1 | 0x1)


def decode_ack(payload: bytes) -> Tuple[int, bool]:
    if not payload[1] & 0x1:
        raise ValueError("Invalid payload")

    return payload[0], not payload[1] >> 1 & 0x1


def check_ack(payload: bytes, command: int) -> bool:
    payload = decode_ack(payload)
    if payload[0] != command:
        raise ValueError("Invalid ack")

    return payload[1]


class Device:
    def __init__(self, product: int, timeout: Optional[float] = 5) -> None:
        print(f"__init__(product={product}, timeout={timeout})")

        if timeout is not None:
            timeout += time()

        while True:
            device = find(idVendor=0x27c6, idProduct=product)

            if device is not None:
                try:
                    if get_status(device) == 0x0001:
                        break

                except USBError as error:
                    if (error.backend_error_code != -1
                            and error.backend_error_code != -4):
                        raise error

            if timeout is not None and time() > timeout:
                if device is None:
                    raise USBTimeoutError("Device not found", -5, 19)

                raise USBTimeoutError("Invalid device state", -12, 131)

            sleep(0.01)

        self.device: USBDevice = device

        print(f"Found Goodix device: \"{self.device.product}\" "
              f"from \"{self.device.manufacturer}\" "
              f"on bus {self.device.bus} "
              f"address {self.device.address}.")

        self.device.ctrl_transfer(
            build_request_type(ENDPOINT_IN, TYPE_STANDARD, RECIP_DEVICE),
            REQ_GET_DESCRIPTOR,
            DT_CONFIG << 8,
            data_or_wLength=0xff
        )  # Not necessary but premit to the Goodix plugin for Wireshark to work

        interface = find_descriptor(self.device.get_active_configuration(),
                                    bInterfaceClass=CLASS_DATA)

        if interface is None:
            raise USBError("Interface data not found", -5, 6)

        print(f"Found interface data: {interface.bInterfaceNumber}")

        endpoint_in = find_descriptor(
            interface,
            custom_match=lambda endpoint: endpoint_direction(
                endpoint.bEndpointAddress) == ENDPOINT_IN and endpoint_type(
                    endpoint.bmAttributes) == ENDPOINT_TYPE_BULK)

        if endpoint_in is None:
            raise USBError("Endpoint in not found", -5, 6)

        self.endpoint_in: int = endpoint_in.bEndpointAddress
        print(f"Found endpoint in: {hex(self.endpoint_in)}")

        endpoint_out = find_descriptor(
            interface,
            custom_match=lambda endpoint: endpoint_direction(
                endpoint.bEndpointAddress) == ENDPOINT_OUT and endpoint_type(
                    endpoint.bmAttributes) == ENDPOINT_TYPE_BULK)

        if endpoint_out is None:
            raise USBError("Endpoint out not found", -5, 6)

        self.endpoint_out: int = endpoint_out.bEndpointAddress
        print(f"Found endpoint out: {hex(self.endpoint_out)}")

        # Empty device reply buffer (Current patch while waiting for a fix)
        self.empty_buffer()

    def empty_buffer(self) -> None:
        try:
            while True:
                self.read(timeout=0.1)

        except USBTimeoutError as error:
            if error.backend_error_code == -7:
                return

            raise error

    def write(self, payload: bytes, timeout: Optional[float] = 1) -> None:
        timeout = 0 if timeout is None else round(timeout * 1000)

        length = len(payload)
        if length % 0x40:
            payload += b"\x00" * (0x40 - length % 0x40)

        for i in range(0, length, 0x40):
            self.device.write(self.endpoint_out, payload[i:i + 0x40], timeout)

    def read(self, size: int = 0x2000, timeout: Optional[float] = 1) -> bytes:
        timeout = 0 if timeout is None else round(timeout * 1000)

        return self.device.read(self.endpoint_in, size, timeout).tobytes()

    def wait_disconnect(self, timeout: Optional[float] = 5) -> None:
        if timeout is not None:
            timeout += time()

        while True:
            try:
                get_status(self.device)

            except USBError as error:
                if (error.backend_error_code == -1
                        or error.backend_error_code == -4):
                    break

                raise error

            if timeout is not None and time() > timeout:
                raise USBTimeoutError("Device is still connected", -7, 110)

            sleep(0.01)

    def nop(self) -> None:
        print("nop()")

        self.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00\x00\x00", COMMAND_NOP)))

        try:
            message = self.read(timeout=0.1)

        except USBTimeoutError as error:
            if error.backend_error_code == -7:
                return

            raise error

        check_ack(
            check_message_protocol(check_message_pack(message), COMMAND_ACK),
            COMMAND_NOP)

    def mcu_get_image(self) -> bytes:
        print("mcu_get_image()")

        self.write(
            encode_message_pack(
                encode_message_protocol(b"\x01\x00", COMMAND_MCU_GET_IMAGE)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_MCU_GET_IMAGE)

        return check_message_pack(self.read() + self.read(0x1000),
                                  FLAGS_TRANSPORT_LAYER_SECURITY)

    def enable_chip(self, enable: bool = True) -> None:
        print(f"enable_chip(enable={enable})")

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<B", 0x1 if enable else 0x0) + b"\x00",
                    COMMAND_ENABLE_CHIP)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_ENABLE_CHIP)

    def reset(self,
              reset_sensor: bool = True,
              soft_reset_mcu: bool = False) -> Optional[int]:
        print(f"reset(reset_sensor={reset_sensor}, "
              f"soft_reset_mcu={soft_reset_mcu})")

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<B", (0x1 if reset_sensor else 0x0) |
                           (0x1 if soft_reset_mcu else 0x0) << 1) + b"\x14",
                    COMMAND_RESET)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_RESET)

        if soft_reset_mcu:
            return None

        message = check_message_protocol(check_message_pack(self.read()),
                                         COMMAND_RESET)

        if len(message) != 3:
            raise SystemError("Invalid response length")

        if message[0] != 0x01:
            raise SystemError("Invalid response")

        return decode("<H", message[1:3])[0]

    def mcu_erase_app(self) -> None:
        print("mcu_erase_app()")

        self.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00", COMMAND_MCU_ERASE_APP)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_MCU_ERASE_APP)

    def firmware_version(self) -> str:
        print("firmware_version()")

        self.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00",
                                        COMMAND_FIRMWARE_VERSION)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_FIRMWARE_VERSION)

        return check_message_protocol(check_message_pack(
            self.read()), COMMAND_FIRMWARE_VERSION).rstrip(b"\x00").decode()

    def request_tls_connection(self) -> bytes:
        print("request_tls_connection()")

        self.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00",
                                        COMMAND_REQUEST_TLS_CONNECTION)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK),
            COMMAND_REQUEST_TLS_CONNECTION)

        return check_message_pack(self.read(), FLAGS_TRANSPORT_LAYER_SECURITY)

    def tls_successfully_established(self) -> None:
        print("tls_successfully_established()")

        self.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00",
                                        COMMAND_TLS_SUCCESSFULLY_ESTABLISHED)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK),
            COMMAND_TLS_SUCCESSFULLY_ESTABLISHED)

    def preset_psk_write_r(self, address: int, length: int,
                           data: bytes) -> None:
        print(f"preset_psk_write_r(address={address}, length={length}, "
              f"data={data})")

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<I", address) + encode("<I", length) + data,
                    COMMAND_PRESET_PSK_WRITE_R)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_PRESET_PSK_WRITE_R)

        message = check_message_protocol(check_message_pack(self.read()),
                                         COMMAND_PRESET_PSK_WRITE_R)

        if len(message) > 2:
            raise SystemError("Invalid response length")

        if message[0] != 0x00:
            raise SystemError("Invalid response")

    def preset_psk_read_r(self, address: int, length: int = 0) -> bytes:
        print(f"preset_psk_read_r(address={address}, length={length})")

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<I", address) + encode("<I", length),
                    COMMAND_PRESET_PSK_READ_R)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_PRESET_PSK_READ_R)

        message = check_message_protocol(check_message_pack(self.read()),
                                         COMMAND_PRESET_PSK_READ_R)

        length = len(message)
        if length < 9:
            raise SystemError("Invalid response length")

        psk_length = decode("<I", message[5:9])[0]
        if length - 9 < psk_length:
            raise SystemError("Invalid response length")

        if message[0] != 0x00 or decode("<I", message[1:5])[0] != address:
            raise SystemError("Invalid response")

        return message[9:9 + psk_length]

    def write_firmware(self, offset: int, data: bytes) -> None:
        print(f"write_firmware(offset={offset}, data={data})")

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<I", offset) + encode("<I", len(data)) + data,
                    COMMAND_WRITE_FIRMWARE)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_WRITE_FIRMWARE)

        message = check_message_protocol(check_message_pack(self.read()),
                                         COMMAND_WRITE_FIRMWARE)

        if len(message) != 2:
            raise SystemError("Invalid response length")

        if message[0] != 0x01:
            raise SystemError("Invalid response")

    def read_firmware(self, offset: int, length: int) -> bytes:
        print(f"read_firmware(offset={offset}, length={length})")

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<I", offset) + encode("<I", length),
                    COMMAND_READ_FIRMWARE)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_READ_FIRMWARE)

        message = check_message_protocol(check_message_pack(self.read()),
                                         COMMAND_READ_FIRMWARE)
        if len(message) != length:
            raise SystemError("Invalid response length")

        return message

    def check_firmware(self,
                       offset: int,
                       length: int,
                       checksum: int,
                       data: Optional[bytes] = None) -> None:
        print(f"update_firmware(offset={offset}, length={length}, "
              f"checksum={checksum}, data={data})")

        if data is None:
            data = b""

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<I", offset) + encode("<I", length) +
                    encode("<I", checksum) + data, COMMAND_CHECK_FIRMWARE)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_CHECK_FIRMWARE)

        message = check_message_protocol(check_message_pack(self.read()),
                                         COMMAND_CHECK_FIRMWARE)

        if len(message) != 2:
            raise SystemError("Invalid response length")

        if message[0] != 0x01:
            raise SystemError("Invalid response")
