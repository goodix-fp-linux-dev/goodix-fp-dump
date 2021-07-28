from struct import pack as encode
from struct import unpack as decode
from sys import version_info
from time import sleep, time
from typing import List, Literal, Optional, Tuple, Union

from usb.control import get_status
from usb.core import Device as USBDevice
from usb.core import USBError, USBTimeoutError, find
from usb.legacy import (CLASS_DATA, CLASS_VENDOR_SPEC, ENDPOINT_IN,
                        ENDPOINT_OUT, ENDPOINT_TYPE_BULK)
from usb.util import endpoint_direction, endpoint_type, find_descriptor

if version_info < (3, 8):
    raise SystemError("This program require Python 3.8 or newer")

FLAGS_MESSAGE_PROTOCOL: Literal[0xa0] = 0xa0
FLAGS_TRANSPORT_LAYER_SECURITY: Literal[0xb0] = 0xb0

COMMAND_NOP: Literal[0x00] = 0x00
COMMAND_MCU_GET_IMAGE: Literal[0x20] = 0x20
COMMAND_MCU_SWITCH_TO_FDT_DOWN: Literal[0x32] = 0x32
COMMAND_MCU_SWITCH_TO_FDT_UP: Literal[0x34] = 0x34
COMMAND_MCU_SWITCH_TO_FDT_MODE: Literal[0x36] = 0x36
COMMAND_NAV_0: Literal[0x50] = 0x50
COMMAND_MCU_SWITCH_TO_IDLE_MODE: Literal[0x70] = 0x70
COMMAND_WRITE_SENSOR_REGISTER: Literal[0x80] = 0x80
COMMAND_READ_SENSOR_REGISTER: Literal[0x82] = 0x82
COMMAND_UPLOAD_CONFIG_MCU: Literal[0x90] = 0x90
COMMAND_SET_POWERDOWN_SCAN_FREQUENCY: Literal[0x94] = 0x94
COMMAND_ENABLE_CHIP: Literal[0x96] = 0x96
COMMAND_RESET: Literal[0xa2] = 0xa2
COMMAND_MCU_ERASE_APP: Literal[0xa4] = 0xa4
COMMAND_READ_OTP: Literal[0xa6] = 0xa6
COMMAND_FIRMWARE_VERSION: Literal[0xa8] = 0xa8
COMMAND_QUERY_MCU_STATE: Literal[0xae] = 0xae
COMMAND_ACK: Literal[0xb0] = 0xb0
COMMAND_REQUEST_TLS_CONNECTION: Literal[0xd0] = 0xd0
COMMAND_TLS_SUCCESSFULLY_ESTABLISHED: Literal[0xd4] = 0xd4
COMMAND_PRESET_PSK_WRITE_R: Literal[0xe0] = 0xe0
COMMAND_PRESET_PSK_READ_R: Literal[0xe4] = 0xe4
COMMAND_WRITE_FIRMWARE: Literal[0xf0] = 0xf0
COMMAND_READ_FIRMWARE: Literal[0xf2] = 0xf2
COMMAND_CHECK_FIRMWARE: Literal[0xf4] = 0xf4
COMMAND_GET_IAP_VERSION: Literal[0xf6] = 0xf6


def encode_command(cmd0: int, cmd1: int) -> int:
    return cmd0 << 4 | cmd1 << 1


def decode_command(command: int) -> Tuple[int, int]:
    if command & 0x1:
        raise ValueError("Invalid command")

    return command >> 4 & 0xf, command >> 1 & 0x7


def encode_message_pack(payload: bytes,
                        flags: int = FLAGS_MESSAGE_PROTOCOL,
                        length: Optional[int] = None) -> bytes:
    if length is None:
        length = len(payload)

    data = b""
    data += encode("<B", flags)
    data += encode("<H", length)
    data += encode("<B", sum(data) & 0xff)
    data += payload

    return data


def decode_message_pack(data: bytes) -> Tuple[bytes, int, int]:
    length = decode("<H", data[1:3])[0]

    if sum(data[0:3]) & 0xff != data[3]:
        raise ValueError("Invalid data")

    return data[4:4 + length], data[0], length


def check_message_pack(data: bytes,
                       flags: int = FLAGS_MESSAGE_PROTOCOL) -> bytes:
    data = decode_message_pack(data)
    if data[1] != flags or len(data[0]) < data[2]:
        raise ValueError("Invalid message pack")

    return data[0]


def encode_message_protocol(payload: bytes,
                            command: int,
                            length: Optional[int] = None,
                            checksum: bool = True) -> bytes:
    if length is None:
        length = len(payload)

    data = b""
    data += encode("<B", command)
    data += encode("<H", length + 1)
    data += payload
    data += encode("<B", 0xaa - sum(data) & 0xff if checksum else 0x88)

    return data


def decode_message_protocol(data: bytes,
                            checksum: bool = True) -> Tuple[bytes, int, int]:
    length = decode("<H", data[1:3])[0]

    if checksum:
        if data[2 + length] != 0xaa - sum(data[0:2 + length]) & 0xff:
            raise ValueError("Invalid data")

    elif data[2 + length] != 0x88:
        raise ValueError("Invalid data")

    return data[3:2 + length], data[0], length - 1


def check_message_protocol(data: bytes,
                           command: int,
                           checksum: bool = True) -> bytes:
    data = decode_message_protocol(data, checksum)
    if data[1] != command or len(data[0]) < data[2]:
        raise ValueError("Invalid message protocol")

    return data[0]


def decode_ack(data: bytes) -> Tuple[int, bool]:
    if not data[1] & 0x1:
        raise ValueError("Invalid data")

    return data[0], data[1] & 0x2 == 0x2


def check_ack(data: bytes, command: int) -> bool:
    data = decode_ack(data)
    if data[0] != command:
        raise ValueError("Invalid ack")

    return data[1]


def decode_image(data: bytes) -> List[int]:
    image = []
    for i in range(0, len(data), 6):
        chunk = data[i:i + 6]

        image.append(((chunk[0] & 0xf) << 8) + chunk[1])
        image.append((chunk[3] << 4) + (chunk[0] >> 4))
        image.append(((chunk[5] & 0xf) << 8) + chunk[2])
        image.append((chunk[4] << 4) + (chunk[5] >> 4))

    return image


def decode_mcu_state(
        data: bytes) -> Tuple[int, bool, bool, bool, int, int, int, int, int]:
    return data[0], data[1] & 0x1 == 0x1, data[
        1] & 0x2 == 0x2, data[1] & 0x4 == 0x4, data[2] >> 4, data[9], decode(
            "<H", data[10:11]), data[12], data[13]


class Device:

    def __init__(self, product: int, timeout: Optional[float] = 5) -> None:
        print(f"__init__({product}, {timeout})")

        if timeout is not None:
            timeout += time()

        while True:
            device = find(idVendor=0x27c6, idProduct=product)

            if device is not None:
                try:
                    get_status(device)
                    break

                except USBError as error:
                    if (error.backend_error_code != -1 and
                            error.backend_error_code != -4):
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

        interface_data = find_descriptor(
            self.device.get_active_configuration(),
            custom_match=lambda interface: interface.bInterfaceClass ==
            CLASS_DATA or interface.bInterfaceClass == CLASS_VENDOR_SPEC)

        if interface_data is None:
            raise USBError("Interface data not found", -5, 6)

        print(f"Found interface data: {interface_data.bInterfaceNumber}")

        endpoint_in = find_descriptor(
            interface_data,
            custom_match=lambda endpoint: endpoint_direction(
                endpoint.bEndpointAddress) == ENDPOINT_IN and endpoint_type(
                    endpoint.bmAttributes) == ENDPOINT_TYPE_BULK)

        if endpoint_in is None:
            raise USBError("Endpoint in not found", -5, 6)

        self.endpoint_in: int = endpoint_in.bEndpointAddress
        print(f"Found endpoint in: {hex(self.endpoint_in)}")

        endpoint_out = find_descriptor(
            interface_data,
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
        print("empty_buffer()")

        try:
            while True:
                self.read(timeout=0.1)

        except USBTimeoutError as error:
            if error.backend_error_code == -7:
                return

            raise error

    def write(self, data: bytes, timeout: Optional[float] = 1) -> None:
        timeout = 0 if timeout is None else round(timeout * 1000)

        length = len(data)
        if length % 0x40:
            data += b"\x00" * (0x40 - length % 0x40)

        for i in range(0, length, 0x40):
            self.device.write(self.endpoint_out, data[i:i + 0x40], timeout)

    def read(self, size: int = 0x2000, timeout: Optional[float] = 1) -> bytes:
        timeout = 0 if timeout is None else round(timeout * 1000)

        return self.device.read(self.endpoint_in, size, timeout).tobytes()

    def wait_disconnect(self, timeout: Optional[float] = 5) -> None:
        print(f"wait_disconnect({timeout})")

        if timeout is not None:
            timeout += time()

        while True:
            try:
                get_status(self.device)

            except USBError as error:
                if (error.backend_error_code == -1 or
                        error.backend_error_code == -4):
                    break

                raise error

            if timeout is not None and time() > timeout:
                raise USBTimeoutError("Device is still connected", -7, 110)

            sleep(0.01)

    def nop(self) -> None:
        print("nop()")

        self.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00\x00\x00",
                                        COMMAND_NOP,
                                        checksum=False)))

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

    def mcu_switch_to_fdt_down(self, mode: bytes) -> bytes:
        print(f"mcu_switch_to_fdt_down({mode})")

        self.write(
            encode_message_pack(
                encode_message_protocol(mode, COMMAND_MCU_SWITCH_TO_FDT_DOWN)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_MCU_SWITCH_TO_FDT_DOWN)

        message = check_message_protocol(
            check_message_pack(self.read(timeout=None)),
            COMMAND_MCU_SWITCH_TO_FDT_DOWN)

        if len(message) != 16:
            raise SystemError("Invalid response length")

        return message

    def mcu_switch_to_fdt_up(self, mode: bytes) -> bytes:
        print(f"mcu_switch_to_fdt_up({mode})")

        self.write(
            encode_message_pack(
                encode_message_protocol(mode, COMMAND_MCU_SWITCH_TO_FDT_UP)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_MCU_SWITCH_TO_FDT_UP)

        message = check_message_protocol(
            check_message_pack(self.read(timeout=None)),
            COMMAND_MCU_SWITCH_TO_FDT_UP)

        if len(message) != 16:
            raise SystemError("Invalid response length")

        return message

    def mcu_switch_to_fdt_mode(self, mode: bytes) -> bytes:
        print(f"mcu_switch_to_fdt_mode({mode})")

        self.write(
            encode_message_pack(
                encode_message_protocol(mode, COMMAND_MCU_SWITCH_TO_FDT_MODE)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_MCU_SWITCH_TO_FDT_MODE)

        message = check_message_protocol(check_message_pack(self.read()),
                                         COMMAND_MCU_SWITCH_TO_FDT_MODE)

        if len(message) != 16:
            raise SystemError("Invalid response length")

        return message

    def nav_0(self) -> bytes:
        print("nav_0()")

        self.write(
            encode_message_pack(
                encode_message_protocol(b"\x01\x00", COMMAND_NAV_0)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_NAV_0)

        return check_message_protocol(check_message_pack(self.read()),
                                      COMMAND_NAV_0, False)

    def mcu_switch_to_idle_mode(self, sleep_time: int) -> None:
        print(f"mcu_switch_to_idle_mode({sleep_time})")

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<B", sleep_time) + b"\x00",
                    COMMAND_MCU_SWITCH_TO_IDLE_MODE)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK),
            COMMAND_MCU_SWITCH_TO_IDLE_MODE)

    def write_sensor_register(self, address: Union[int, List[int]],
                              value: Union[bytes, List[bytes]]) -> None:
        print(f"write_sensor_register({address}, {value})")
        if isinstance(address, int):
            if not isinstance(value, bytes):
                raise ValueError("Invalid value")

            message = b"\x00" + encode("<H", address) + value

        else:
            if isinstance(value, bytes):
                raise ValueError("Invalid value")

            length = len(address)
            if len(value) != length:
                raise ValueError("Invalid value")

            message = b""
            message += b"\x01"
            for i in length:
                if len(value[i]) != 2:
                    raise ValueError("Invalid value")

                message += encode("<H", address[i])
                message += value[i]

        self.write(
            encode_message_pack(
                encode_message_protocol(message,
                                        COMMAND_WRITE_SENSOR_REGISTER)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_WRITE_SENSOR_REGISTER)

    def read_sensor_register(self, address: Union[int, List[int]],
                             length: int) -> Union[bytes, List[bytes]]:
        print(f"read_sensor_register({address}, {length})")

        if isinstance(address, int):
            message = b"\x00" + encode("<H", address) + encode("<B", length)

        else:
            if length != 2:
                raise ValueError("Invalid length")

            message = b""
            message += b"\x01"
            for value in address:
                message += encode("<H", value)
            message += encode("<B", length)

        self.write(
            encode_message_pack(
                encode_message_protocol(message, COMMAND_READ_SENSOR_REGISTER)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_READ_SENSOR_REGISTER)

        message = check_message_protocol(check_message_pack(self.read()),
                                         COMMAND_READ_SENSOR_REGISTER)

        if isinstance(address, int):
            if len(message) != length:
                raise SystemError("Invalid response length")

            return message

        length = len(message) - 1
        if length != len(address) * 2:
            raise SystemError("Invalid response length")

        value = []
        for i in range(0, length, 2):
            value.append(message[i:i + 2])

        return value

    def upload_config_mcu(self, config: bytes) -> None:
        print(f"upload_config_mcu({config})")

        self.write(
            encode_message_pack(
                encode_message_protocol(config, COMMAND_UPLOAD_CONFIG_MCU)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_UPLOAD_CONFIG_MCU)

        message = check_message_protocol(check_message_pack(self.read()),
                                         COMMAND_UPLOAD_CONFIG_MCU)

        if len(message) != 2:
            raise SystemError("Invalid response length")

        if message[0] != 0x01:
            raise SystemError("Invalid response")

    def set_powerdown_scan_frequency(self,
                                     powerdown_scan_frequency: int) -> None:
        print(f"set_powerdown_scan_frequency({powerdown_scan_frequency})")

        self.write(
            encode_message_pack(
                encode_message_protocol(encode("<H", powerdown_scan_frequency),
                                        COMMAND_SET_POWERDOWN_SCAN_FREQUENCY)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK),
            COMMAND_SET_POWERDOWN_SCAN_FREQUENCY)

        message = check_message_protocol(check_message_pack(self.read()),
                                         COMMAND_SET_POWERDOWN_SCAN_FREQUENCY)

        if len(message) != 2:
            raise SystemError("Invalid response length")

        if message[0] != 0x01:
            raise SystemError("Invalid response")

    def enable_chip(self, enable: bool) -> None:
        print(f"enable_chip({enable})")

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<B", 0x1 if enable else 0x0) + b"\x00",
                    COMMAND_ENABLE_CHIP)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_ENABLE_CHIP)

    def reset(self, reset_sensor: bool, soft_reset_mcu: bool,
              sleep_time: int) -> Optional[int]:
        print(f"reset({reset_sensor}, {soft_reset_mcu}, {sleep_time})")

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<B", (0x1 if reset_sensor else 0x0) |
                           (0x1 if soft_reset_mcu else 0x0) << 1 |
                           (0x1 if reset_sensor else 0x0) << 2) +
                    encode("<B", sleep_time), COMMAND_RESET)))

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

    def mcu_erase_app(self, sleep_time: int) -> None:
        print(f"mcu_erase_app({sleep_time})")

        self.write(
            encode_message_pack(
                encode_message_protocol(b"\x00" + encode("<B", sleep_time),
                                        COMMAND_MCU_ERASE_APP)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_MCU_ERASE_APP)

    def read_otp(self) -> bytes:
        print("read_otp()")

        self.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00", COMMAND_READ_OTP)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_READ_OTP)

        return check_message_protocol(check_message_pack(self.read()),
                                      COMMAND_READ_OTP)

    def firmware_version(self) -> str:
        print("firmware_version()")

        self.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00", COMMAND_FIRMWARE_VERSION)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_FIRMWARE_VERSION)

        return check_message_protocol(check_message_pack(
            self.read()), COMMAND_FIRMWARE_VERSION).split(b"\x00")[0].decode()

    def query_mcu_state(self) -> bytes:
        print("query_mcu_state()")

        self.write(
            encode_message_pack(
                encode_message_protocol(b"\x55", COMMAND_QUERY_MCU_STATE)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_QUERY_MCU_STATE)

        message = check_message_protocol(check_message_pack(self.read()),
                                         COMMAND_QUERY_MCU_STATE)

        if len(message) != 0x10:
            raise SystemError("Invalid response length")

        return message

    def request_tls_connection(self) -> bytes:
        print("request_tls_connection()")

        self.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00",
                                        COMMAND_REQUEST_TLS_CONNECTION)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_REQUEST_TLS_CONNECTION)

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

    def preset_psk_write_r(self, flags: int, length: int,
                           payload: bytes) -> None:
        print(f"preset_psk_write_r({flags}, {length}, {payload})")

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<I", flags) + encode("<I", length) + payload,
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

    def preset_psk_read_r(self, flags: int, length: int) -> bytes:
        print(f"preset_psk_read_r({flags}, {length})")

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<I", flags) + encode("<I", length),
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

        if message[0] != 0x00 or decode("<I", message[1:5])[0] != flags:
            raise SystemError("Invalid response")

        return message[9:9 + psk_length]

    def write_firmware(self, offset: int, payload: bytes) -> None:
        print(f"write_firmware({offset}, {payload})")

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<I", offset) + encode("<I", len(payload)) + payload,
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
        print(f"read_firmware({offset}, {length})")

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

    def check_firmware(self, offset: int, length: int, checksum: int,
                       hmac: Optional[bytes]) -> None:
        print(f"update_firmware({offset}, {length}, {checksum}, {hmac})")

        if hmac is None:
            hmac = b""

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<I", offset) + encode("<I", length) +
                    encode("<I", checksum) + hmac, COMMAND_CHECK_FIRMWARE)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_CHECK_FIRMWARE)

        message = check_message_protocol(check_message_pack(self.read()),
                                         COMMAND_CHECK_FIRMWARE)

        if len(message) != 2:
            raise SystemError("Invalid response length")

        if message[0] != 0x01:
            raise SystemError("Invalid response")

    def get_iap_version(self, length: int) -> str:
        print(f"get_iap_version({length})")

        self.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<B", length) + b"\x00", COMMAND_GET_IAP_VERSION)))

        check_ack(
            check_message_protocol(check_message_pack(self.read()),
                                   COMMAND_ACK), COMMAND_GET_IAP_VERSION)

        message = check_message_protocol(check_message_pack(self.read()),
                                         COMMAND_GET_IAP_VERSION)

        if len(message) != length:
            raise SystemError("Invalid response length")

        return message.split(b"\x00")[0].decode()
