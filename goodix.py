from struct import pack as encode
from struct import unpack as decode
from sys import version_info
from typing import List, Literal, Optional, Tuple, Union

from usb.core import USBTimeoutError

from protocol import Protocol

if version_info < (3, 8):
    raise SystemError("This program require Python 3.8 or newer")

FLAGS_MESSAGE_PROTOCOL: Literal[0xa0] = 0xa0
FLAGS_TRANSPORT_LAYER_SECURITY: Literal[0xb0] = 0xb0
FLAGS_TRANSPORT_LAYER_SECURITY_DATA: Literal[0xb2] = 0xb2

COMMAND_NOP: Literal[0x00] = 0x00
COMMAND_MCU_GET_IMAGE: Literal[0x20] = 0x20
COMMAND_MCU_SWITCH_TO_FDT_DOWN: Literal[0x32] = 0x32
COMMAND_MCU_SWITCH_TO_FDT_UP: Literal[0x34] = 0x34
COMMAND_MCU_SWITCH_TO_FDT_MODE: Literal[0x36] = 0x36
COMMAND_NAV_0: Literal[0x50] = 0x50
COMMAND_MCU_SWITCH_TO_SLEEP_MODE: Literal[0x60] = 0x60
COMMAND_MCU_SWITCH_TO_IDLE_MODE: Literal[0x70] = 0x70
COMMAND_WRITE_SENSOR_REGISTER: Literal[0x80] = 0x80
COMMAND_READ_SENSOR_REGISTER: Literal[0x82] = 0x82
COMMAND_UPLOAD_CONFIG_MCU: Literal[0x90] = 0x90
COMMAND_SWITCH_TO_SLEEP_MODE: Literal[0x92] = 0x92
COMMAND_SET_POWERDOWN_SCAN_FREQUENCY: Literal[0x94] = 0x94
COMMAND_ENABLE_CHIP: Literal[0x96] = 0x96
COMMAND_RESET: Literal[0xa2] = 0xa2
COMMAND_MCU_ERASE_APP: Literal[0xa4] = 0xa4
COMMAND_READ_OTP: Literal[0xa6] = 0xa6
COMMAND_FIRMWARE_VERSION: Literal[0xa8] = 0xa8
COMMAND_SET_POV_CONFIG: Literal[0xac] = 0xac
COMMAND_QUERY_MCU_STATE: Literal[0xae] = 0xae
COMMAND_ACK: Literal[0xb0] = 0xb0
COMMAND_SET_DRV_STATE: Literal[0xc4] = 0xc4
COMMAND_REQUEST_TLS_CONNECTION: Literal[0xd0] = 0xd0
COMMAND_MCU_GET_POV_IMAGE: Literal[0xd2] = 0xd2
COMMAND_TLS_SUCCESSFULLY_ESTABLISHED: Literal[0xd4] = 0xd4
COMMAND_POV_IMAGE_CHECK: Literal[0xd6] = 0xd6
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

    def __init__(self,
                 product: int,
                 protocol: Protocol,
                 timeout: Optional[float] = 5) -> None:
        print(f"__init__({product}, {protocol}, {timeout})")

        self.protocol: Protocol = protocol(0x27c6, product, timeout)

        # FIXME Empty device reply buffer (Current patch while waiting for a fix)
        self.empty_buffer()

    def empty_buffer(self) -> None:
        print("empty_buffer()")

        try:
            while True:
                self.protocol.read(timeout=0.1)

        except USBTimeoutError as error:
            if error.backend_error_code == -7:
                return

            raise error

    def disconnect(self, timeout: Optional[float] = 5) -> None:
        print("disconnect()")

        self.protocol.disconnect(timeout)

    def nop(self) -> None:
        print("nop()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00\x00\x00",
                                        COMMAND_NOP,
                                        checksum=False)))

        try:
            message = self.protocol.read(timeout=0.1)

        except USBTimeoutError as error:
            if error.backend_error_code == -7:
                return

            raise error

        check_ack(
            check_message_protocol(check_message_pack(message), COMMAND_ACK),
            COMMAND_NOP)

    def mcu_get_image(self, payload: bytes, flags: int) -> bytes:
        print("mcu_get_image()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(payload, COMMAND_MCU_GET_IMAGE)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_MCU_GET_IMAGE)

        return check_message_pack(self.protocol.read(), flags)

    def mcu_switch_to_fdt_down(self, mode: bytes,
                               reply: bool) -> Optional[bytes]:
        print(f"mcu_switch_to_fdt_down({mode}, {reply})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(mode, COMMAND_MCU_SWITCH_TO_FDT_DOWN)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_MCU_SWITCH_TO_FDT_DOWN)

        if not reply:
            return None

        return check_message_protocol(
            check_message_pack(self.protocol.read(timeout=None)),
            COMMAND_MCU_SWITCH_TO_FDT_DOWN)

    def mcu_switch_to_fdt_up(self, mode: bytes) -> bytes:
        print(f"mcu_switch_to_fdt_up({mode})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(mode, COMMAND_MCU_SWITCH_TO_FDT_UP)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_MCU_SWITCH_TO_FDT_UP)

        return check_message_protocol(
            check_message_pack(self.protocol.read(timeout=None)),
            COMMAND_MCU_SWITCH_TO_FDT_UP)

    def mcu_switch_to_fdt_mode(self, mode: bytes,
                               reply: bool) -> Optional[bytes]:
        print(f"mcu_switch_to_fdt_mode({mode}, {reply})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(mode, COMMAND_MCU_SWITCH_TO_FDT_MODE)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_MCU_SWITCH_TO_FDT_MODE)

        if not reply:
            return None

        return check_message_protocol(check_message_pack(self.protocol.read()),
                                      COMMAND_MCU_SWITCH_TO_FDT_MODE)

    def nav_0(self) -> bytes:
        print("nav_0()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x01\x00", COMMAND_NAV_0)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_NAV_0)

        return check_message_protocol(check_message_pack(self.protocol.read()),
                                      COMMAND_NAV_0, False)

    def mcu_switch_to_sleep_mode(self) -> None:
        print("mcu_switch_to_sleep_mode()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x01\x00",
                                        COMMAND_MCU_SWITCH_TO_SLEEP_MODE)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK),
            COMMAND_MCU_SWITCH_TO_SLEEP_MODE)

    def mcu_switch_to_idle_mode(self, sleep_time: int) -> None:
        print(f"mcu_switch_to_idle_mode({sleep_time})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<B", sleep_time) + b"\x00",
                    COMMAND_MCU_SWITCH_TO_IDLE_MODE)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
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

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(message,
                                        COMMAND_WRITE_SENSOR_REGISTER)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
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

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(message, COMMAND_READ_SENSOR_REGISTER)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_READ_SENSOR_REGISTER)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()),
            COMMAND_READ_SENSOR_REGISTER)

        if isinstance(address, int):
            if len(message) < length:
                raise SystemError("Invalid response length")

            return message

        length = len(message) - 1
        if length < len(address) * 2:
            raise SystemError("Invalid response length")

        value = []
        for i in range(0, length, 2):
            value.append(message[i:i + 2])

        return value

    def upload_config_mcu(self, config: bytes) -> bool:
        print(f"upload_config_mcu({config})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(config, COMMAND_UPLOAD_CONFIG_MCU)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_UPLOAD_CONFIG_MCU)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_UPLOAD_CONFIG_MCU)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0] == 0x01

    def switch_to_sleep_mode(self, number: int):
        print(f"switch_to_sleep_mode({number})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(encode("<B", number),
                                        COMMAND_SWITCH_TO_SLEEP_MODE)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_SWITCH_TO_SLEEP_MODE)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()),
            COMMAND_SWITCH_TO_SLEEP_MODE)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0] == 0x1

    def set_powerdown_scan_frequency(self,
                                     powerdown_scan_frequency: int) -> bool:
        print(f"set_powerdown_scan_frequency({powerdown_scan_frequency})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(encode("<H", powerdown_scan_frequency),
                                        COMMAND_SET_POWERDOWN_SCAN_FREQUENCY)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK),
            COMMAND_SET_POWERDOWN_SCAN_FREQUENCY)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()),
            COMMAND_SET_POWERDOWN_SCAN_FREQUENCY)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0] == 0x01

    def enable_chip(self, enable: bool) -> None:
        print(f"enable_chip({enable})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<B", 0x1 if enable else 0x0) + b"\x00",
                    COMMAND_ENABLE_CHIP)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_ENABLE_CHIP)

    def reset(self, reset_sensor: bool, soft_reset_mcu: bool,
              sleep_time: int) -> Optional[Tuple[bool, Optional[int]]]:
        print(f"reset({reset_sensor}, {soft_reset_mcu}, {sleep_time})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<B", (0x1 if reset_sensor else 0x0) |
                           (0x1 if soft_reset_mcu else 0x0) << 1 |
                           (0x1 if reset_sensor else 0x0) << 2) +
                    encode("<B", sleep_time), COMMAND_RESET)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_RESET)

        if soft_reset_mcu:
            return None

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_RESET)

        length = len(message)
        if length < 1:
            raise SystemError("Invalid response length")

        if message[0] != 0x01:
            return False, None

        if length < 3:
            raise SystemError("Invalid response length")

        return True, decode("<H", message[1:3])[0]

    def mcu_erase_app(self, sleep_time: int) -> None:
        print(f"mcu_erase_app({sleep_time})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00" + encode("<B", sleep_time),
                                        COMMAND_MCU_ERASE_APP)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_MCU_ERASE_APP)

    def read_otp(self) -> bytes:
        print("read_otp()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00", COMMAND_READ_OTP)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_READ_OTP)

        return check_message_protocol(check_message_pack(self.protocol.read()),
                                      COMMAND_READ_OTP)

    def firmware_version(self) -> str:
        print("firmware_version()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00", COMMAND_FIRMWARE_VERSION)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_FIRMWARE_VERSION)

        return check_message_protocol(
            check_message_pack(self.protocol.read()),
            COMMAND_FIRMWARE_VERSION).split(b"\x00")[0].decode()

    def set_pov_config(self, config: bytes) -> None:
        print(f"set_pov_config({config})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(config, COMMAND_SET_POV_CONFIG)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_SET_POV_CONFIG)

    def query_mcu_state(self, payload: bytes, reply: bool) -> Optional[bytes]:
        print(f"query_mcu_state({payload}, {reply})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(payload, COMMAND_QUERY_MCU_STATE)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_QUERY_MCU_STATE)

        if not reply:
            return None

        return check_message_protocol(check_message_pack(self.protocol.read()),
                                      COMMAND_QUERY_MCU_STATE)

    def set_drv_state(self) -> None:
        print("set_drv_state()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x01\x00", COMMAND_SET_DRV_STATE)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_SET_DRV_STATE)

    def request_tls_connection(self) -> bytes:
        print("request_tls_connection()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00",
                                        COMMAND_REQUEST_TLS_CONNECTION)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_REQUEST_TLS_CONNECTION)

        return check_message_pack(self.protocol.read(),
                                  FLAGS_TRANSPORT_LAYER_SECURITY)

    def mcu_get_pov_image(self) -> int:
        print("mcu_get_pov_image()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00",
                                        COMMAND_MCU_GET_POV_IMAGE)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_MCU_GET_POV_IMAGE)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_MCU_GET_POV_IMAGE)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0]

    def tls_successfully_established(self) -> None:
        print("tls_successfully_established()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00",
                                        COMMAND_TLS_SUCCESSFULLY_ESTABLISHED)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK),
            COMMAND_TLS_SUCCESSFULLY_ESTABLISHED)

    def pov_image_check(self) -> int:
        print("pov_image_check()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00", COMMAND_POV_IMAGE_CHECK)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_POV_IMAGE_CHECK)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_POV_IMAGE_CHECK)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0]

    def preset_psk_write(self,
                         flags: int,
                         payload: bytes,
                         length: Optional[int] = None,
                         offset: Optional[int] = None,
                         pre_flags: Optional[bytes] = None) -> bool:
        # TODO support multiples writes
        print(f"preset_psk_write({flags}, {payload}, {length}, {offset}, "
              f"{pre_flags})")

        if length is None or offset is None:
            if length is not None or offset is not None:
                raise ValueError("Invalid length or offset")

        data = (b"" if pre_flags is None else pre_flags) + encode(
            "<I", flags) + encode("<I", len(payload)) + payload
        if length is not None:
            total_length = len(data)
            if offset + length > total_length:
                raise ValueError("Invalid payload, length or offset")

            data = encode("<I", total_length) + encode("<I", length) + encode(
                "<I", offset) + data[offset:offset + length]

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(data, COMMAND_PRESET_PSK_WRITE_R)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_PRESET_PSK_WRITE_R)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()),
            COMMAND_PRESET_PSK_WRITE_R)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0] == 0x00

    def preset_psk_read(
        self,
        flags: int,
        length: Optional[int] = None,
        offset: Optional[int] = None
    ) -> Tuple[bool, Optional[int], Optional[bytes]]:
        print(f"preset_psk_read({flags}, {length}, {offset})")

        if (length is None or offset is None) and (length is not None or
                                                   offset is not None):
            raise ValueError("Invalid length or offset")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    (b"" if length is None else encode("<I", length)) +
                    (b"" if offset is None else encode("<I", offset)) +
                    encode("<I", flags) + encode("<I", 0),
                    COMMAND_PRESET_PSK_READ_R)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_PRESET_PSK_READ_R)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_PRESET_PSK_READ_R)

        message_length = len(message)
        if message_length < 1:
            raise SystemError("Invalid response length")

        if message[0] != 0x00:
            return False, None, None

        if message_length < 9:
            raise SystemError("Invalid response length")

        psk_length = decode("<I", message[5:9])[0]
        if message_length - 9 < psk_length:
            raise SystemError("Invalid response length")

        return True, decode("<I", message[1:5])[0], message[9:9 + psk_length]

    def write_firmware(self,
                       offset: int,
                       payload: bytes,
                       number: Optional[int] = None) -> bool:
        print(f"write_firmware({offset}, {payload}, {number})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<I", offset) + encode("<I", len(payload)) +
                    (b"" if number is None else encode("<I", number)) + payload,
                    COMMAND_WRITE_FIRMWARE)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_WRITE_FIRMWARE)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_WRITE_FIRMWARE)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0] == 0x01

    def read_firmware(self, offset: int, length: int) -> bytes:
        print(f"read_firmware({offset}, {length})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<I", offset) + encode("<I", length),
                    COMMAND_READ_FIRMWARE)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_READ_FIRMWARE)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_READ_FIRMWARE)
        if len(message) < length:
            raise SystemError("Invalid response length")

        return message[:length]

    def check_firmware(self,
                       offset: Optional[int] = None,
                       length: Optional[int] = None,
                       checksum: Optional[int] = None,
                       hmac: Optional[bytes] = None) -> bool:
        print(f"update_firmware({offset}, {length}, {checksum}, {hmac})")

        if offset is None or length is None or checksum is None:
            if offset is not None or length is not None or checksum is not None:
                raise ValueError("Invalid offset, length or checksum")

        if offset is None and hmac is None:
            raise ValueError("Invalid offset, length, checksum or hmac")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    (b"" if offset is None else encode("<I", offset) +
                     encode("<I", length) + encode("<I", checksum)) +
                    (b"" if hmac is None else hmac), COMMAND_CHECK_FIRMWARE)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_CHECK_FIRMWARE)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_CHECK_FIRMWARE)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0] == 0x01

    def get_iap_version(self, length: int) -> str:
        print(f"get_iap_version({length})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    encode("<B", length) + b"\x00", COMMAND_GET_IAP_VERSION)))

        check_ack(
            check_message_protocol(check_message_pack(self.protocol.read()),
                                   COMMAND_ACK), COMMAND_GET_IAP_VERSION)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_GET_IAP_VERSION)

        if len(message) < length:
            raise SystemError("Invalid response length")

        return message.split(b"\x00")[0].decode()
