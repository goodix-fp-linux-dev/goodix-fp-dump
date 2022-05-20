import struct

import usb

import protocol

FLAGS_MESSAGE_PROTOCOL = 0xa0
FLAGS_TRANSPORT_LAYER_SECURITY = 0xb0
FLAGS_TRANSPORT_LAYER_SECURITY_DATA = 0xb2

COMMAND_NOP = 0x00
COMMAND_MCU_GET_IMAGE = 0x20
COMMAND_MCU_SWITCH_TO_FDT_DOWN = 0x32
COMMAND_MCU_SWITCH_TO_FDT_UP = 0x34
COMMAND_MCU_SWITCH_TO_FDT_MODE = 0x36
COMMAND_NAV = 0x50
COMMAND_MCU_SWITCH_TO_SLEEP_MODE = 0x60
COMMAND_MCU_SWITCH_TO_IDLE_MODE = 0x70
COMMAND_WRITE_SENSOR_REGISTER = 0x80
COMMAND_READ_SENSOR_REGISTER = 0x82
COMMAND_UPLOAD_CONFIG_MCU = 0x90
COMMAND_SWITCH_TO_SLEEP_MODE = 0x92
COMMAND_SET_POWERDOWN_SCAN_FREQUENCY = 0x94
COMMAND_ENABLE_CHIP = 0x96
COMMAND_RESET = 0xa2
COMMAND_MCU_ERASE_APP = 0xa4
COMMAND_READ_OTP = 0xa6
COMMAND_FIRMWARE_VERSION = 0xa8
COMMAND_SET_POV_CONFIG = 0xac
COMMAND_QUERY_MCU_STATE = 0xae
COMMAND_ACK = 0xb0
COMMAND_SET_DRV_STATE = 0xc4
COMMAND_REQUEST_TLS_CONNECTION = 0xd0
COMMAND_MCU_GET_POV_IMAGE = 0xd2
COMMAND_TLS_SUCCESSFULLY_ESTABLISHED = 0xd4
COMMAND_POV_IMAGE_CHECK = 0xd6
COMMAND_PRESET_PSK_WRITE_R = 0xe0
COMMAND_PRESET_PSK_READ_R = 0xe4
COMMAND_WRITE_FIRMWARE = 0xf0
COMMAND_READ_FIRMWARE = 0xf2
COMMAND_CHECK_FIRMWARE = 0xf4
COMMAND_GET_IAP_VERSION = 0xf6


def encode_command(cmd0: int, cmd1: int):
    return cmd0 << 4 | cmd1 << 1


def decode_command(command: int):
    if command & 0x1:
        raise ValueError("Invalid command")

    return command >> 4 & 0xf, command >> 1 & 0x7


def encode_message_pack(payload: bytes,
                        flags: int = FLAGS_MESSAGE_PROTOCOL,
                        length: int | None = None):
    if length is None:
        length = len(payload)

    data = b""
    data += struct.pack("<B", flags)
    data += struct.pack("<H", length)
    data += struct.pack("<B", sum(data) & 0xff)
    data += payload

    return data


def decode_message_pack(data: bytes):
    length: int = struct.unpack("<H", data[1:3])[0]

    if sum(data[0:3]) & 0xff != data[3]:
        raise ValueError("Invalid data")

    return data[4:4 + length], data[0], length


def check_message_pack(data: bytes, flags: int = FLAGS_MESSAGE_PROTOCOL):
    data_decoded = decode_message_pack(data)
    if data_decoded[1] != flags or len(data_decoded[0]) < data_decoded[2]:
        raise ValueError("Invalid message pack")

    return data_decoded[0]


def encode_message_protocol(payload: bytes,
                            command: int,
                            length: int | None = None,
                            checksum: bool = True):
    if length is None:
        length = len(payload)

    data = b""
    data += struct.pack("<B", command)
    data += struct.pack("<H", length + 1)
    data += payload
    data += struct.pack("<B", 0xaa - sum(data) & 0xff if checksum else 0x88)

    return data


def decode_message_protocol(data: bytes, checksum: bool = True):
    length: int = struct.unpack("<H", data[1:3])[0]

    if checksum:
        if data[2 + length] != 0xaa - sum(data[0:2 + length]) & 0xff:
            raise ValueError("Invalid data")

    elif data[2 + length] != 0x88:
        raise ValueError("Invalid data")

    return data[3:2 + length], data[0], length - 1


def check_message_protocol(data: bytes, command: int, checksum: bool = True):
    data_decoded = decode_message_protocol(data, checksum)
    if data_decoded[1] != command or len(data_decoded[0]) < data_decoded[2]:
        raise ValueError("Invalid message protocol")

    return data_decoded[0]


def decode_ack(data: bytes):
    if not data[1] & 0x1:
        raise ValueError("Invalid data")

    return data[0], data[1] & 0x2 == 0x2


def check_ack(data: bytes, command: int):
    data_decoded = decode_ack(data)
    if data_decoded[0] != command:
        raise ValueError("Invalid ack")

    return data_decoded[1]


def decode_mcu_state(data: bytes):
    return data[0], data[1] & 0x1 == 0x1, data[1] & 0x2 == 0x2, data[
        1] & 0x4 == 0x4, data[2] >> 4, data[9], struct.unpack(
            "<H", data[10:11]), data[12], data[13]


class Device:

    def __init__(self,
                 product: int,
                 proto: protocol.Protocol,
                 timeout: float | None = 5):
        print(f"__init__({product}, {proto}, {timeout})")

        self.protocol: protocol.Protocol = proto(0x27c6, product, timeout)

        # FIXME Empty device's reply buffer
        # (Current patch while waiting for a fix)
        if isinstance(self.protocol, protocol.USBProtocol):
            self.empty_buffer()

    def empty_buffer(self):
        print("empty_buffer()")

        try:
            while True:
                self.protocol.read(timeout=0.1)

        except usb.core.USBTimeoutError as error:
            if error.backend_error_code == -7:
                return

            raise error

    def disconnect(self, timeout: float | None = 5):
        print("disconnect()")

        self.protocol.disconnect(timeout)

    def nop(self):
        print("nop()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00\x00\x00",
                                        COMMAND_NOP,
                                        checksum=False)))

        try:
            message = self.protocol.read(timeout=0.1)

        except usb.core.USBTimeoutError as error:
            if error.backend_error_code == -7:
                return

            raise error

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(check_message_pack(message),
                                       COMMAND_ACK), COMMAND_NOP)

    def mcu_get_image(self, payload: bytes, flags: int):
        print("mcu_get_image()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(payload, COMMAND_MCU_GET_IMAGE)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_MCU_GET_IMAGE)

        return check_message_pack(self.protocol.read(), flags)

    def mcu_switch_to_fdt_down(self, mode: bytes, reply: bool):
        print(f"mcu_switch_to_fdt_down({mode}, {reply})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(mode, COMMAND_MCU_SWITCH_TO_FDT_DOWN)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_MCU_SWITCH_TO_FDT_DOWN)

        if not reply:
            return None

        return check_message_protocol(
            check_message_pack(self.protocol.read(timeout=None)),
            COMMAND_MCU_SWITCH_TO_FDT_DOWN)

    def mcu_switch_to_fdt_up(self, mode: bytes):
        print(f"mcu_switch_to_fdt_up({mode})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(mode, COMMAND_MCU_SWITCH_TO_FDT_UP)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_MCU_SWITCH_TO_FDT_UP)

        return check_message_protocol(
            check_message_pack(self.protocol.read(timeout=None)),
            COMMAND_MCU_SWITCH_TO_FDT_UP)

    def mcu_switch_to_fdt_mode(self, mode: bytes, reply: bool):
        print(f"mcu_switch_to_fdt_mode({mode}, {reply})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(mode, COMMAND_MCU_SWITCH_TO_FDT_MODE)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_MCU_SWITCH_TO_FDT_MODE)

        if not reply:
            return None

        return check_message_protocol(check_message_pack(self.protocol.read()),
                                      COMMAND_MCU_SWITCH_TO_FDT_MODE)

    def nav(self):
        print("nav()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x01\x00", COMMAND_NAV)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_NAV)

        return check_message_protocol(check_message_pack(self.protocol.read()),
                                      COMMAND_NAV, False)

    def mcu_switch_to_sleep_mode(self):
        print("mcu_switch_to_sleep_mode()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x01\x00",
                                        COMMAND_MCU_SWITCH_TO_SLEEP_MODE)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_MCU_SWITCH_TO_SLEEP_MODE)

    def mcu_switch_to_idle_mode(self, sleep_time: int):
        print(f"mcu_switch_to_idle_mode({sleep_time})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    struct.pack("<B", sleep_time) + b"\x00",
                    COMMAND_MCU_SWITCH_TO_IDLE_MODE)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_MCU_SWITCH_TO_IDLE_MODE)

    def write_sensor_register(self, address: int | list[int],
                              value: bytes | list[bytes]):
        print(f"write_sensor_register({address}, {value})")
        if isinstance(address, int):
            if not isinstance(value, bytes):
                raise ValueError("Invalid value")

            message = b"\x00" + struct.pack("<H", address) + value

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

                message += struct.pack("<H", address[i])
                message += value[i]

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(message,
                                        COMMAND_WRITE_SENSOR_REGISTER)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_WRITE_SENSOR_REGISTER)

    def read_sensor_register(self, address: int | list[int], length: int):
        print(f"read_sensor_register({address}, {length})")

        if isinstance(address, int):
            message = b"\x00" + struct.pack("<H", address) + struct.pack(
                "<B", length)

        else:
            if length != 2:
                raise ValueError("Invalid length")

            message = b""
            message += b"\x01"
            for value in address:
                message += struct.pack("<H", value)
            message += struct.pack("<B", length)

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(message,
                                        COMMAND_READ_SENSOR_REGISTER)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_READ_SENSOR_REGISTER)

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

        return [message[i:i + 2] for i in range(0, length, 2)]

    def upload_config_mcu(self, config: bytes):
        print(f"upload_config_mcu({config})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(config, COMMAND_UPLOAD_CONFIG_MCU)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_UPLOAD_CONFIG_MCU)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()),
            COMMAND_UPLOAD_CONFIG_MCU)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0] == 0x01

    def switch_to_sleep_mode(self, number: int):
        print(f"switch_to_sleep_mode({number})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(struct.pack("<B", number),
                                        COMMAND_SWITCH_TO_SLEEP_MODE)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_SWITCH_TO_SLEEP_MODE)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()),
            COMMAND_SWITCH_TO_SLEEP_MODE)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0] == 0x1

    def set_powerdown_scan_frequency(self, powerdown_scan_frequency: int):
        print(f"set_powerdown_scan_frequency({powerdown_scan_frequency})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    struct.pack("<H", powerdown_scan_frequency),
                    COMMAND_SET_POWERDOWN_SCAN_FREQUENCY)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_SET_POWERDOWN_SCAN_FREQUENCY)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()),
            COMMAND_SET_POWERDOWN_SCAN_FREQUENCY)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0] == 0x01

    def enable_chip(self, enable: bool):
        print(f"enable_chip({enable})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    struct.pack("<B", 0x1 if enable else 0x0) + b"\x00",
                    COMMAND_ENABLE_CHIP)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_ENABLE_CHIP)

    def reset(self, reset_sensor: bool, soft_reset_mcu: bool, sleep_time: int):
        print(f"reset({reset_sensor}, {soft_reset_mcu}, {sleep_time})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    struct.pack("<B", (0x1 if reset_sensor else 0x0) |
                                (0x1 if soft_reset_mcu else 0x0) << 1 |
                                (0x1 if reset_sensor else 0x0) << 2) +
                    struct.pack("<B", sleep_time), COMMAND_RESET)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_RESET)

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

        number: int = struct.unpack("<H", message[1:3])[0]
        return True, number

    def mcu_erase_app(self, sleep_time: int, reply: bool):
        print(f"mcu_erase_app({sleep_time}, {reply})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    b"\x00" + struct.pack("<B", sleep_time),
                    COMMAND_MCU_ERASE_APP)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_MCU_ERASE_APP)

        if not reply:
            return None

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_MCU_ERASE_APP)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0] == 0x01

    def read_otp(self):
        print("read_otp()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00", COMMAND_READ_OTP)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_READ_OTP)

        return check_message_protocol(check_message_pack(self.protocol.read()),
                                      COMMAND_READ_OTP)

    def firmware_version(self):
        print("firmware_version()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00",
                                        COMMAND_FIRMWARE_VERSION)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_FIRMWARE_VERSION)

        return check_message_protocol(
            check_message_pack(self.protocol.read()),
            COMMAND_FIRMWARE_VERSION).split(b"\x00")[0].decode()

    def set_pov_config(self, config: bytes):
        print(f"set_pov_config({config})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(config, COMMAND_SET_POV_CONFIG)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_SET_POV_CONFIG)

    def query_mcu_state(self, payload: bytes, reply: bool):
        print(f"query_mcu_state({payload}, {reply})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(payload, COMMAND_QUERY_MCU_STATE)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_QUERY_MCU_STATE)

        if not reply:
            return None

        return check_message_protocol(check_message_pack(self.protocol.read()),
                                      COMMAND_QUERY_MCU_STATE)

    def set_drv_state(self):
        print("set_drv_state()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x01\x00", COMMAND_SET_DRV_STATE)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_SET_DRV_STATE)

    def request_tls_connection(self):
        print("request_tls_connection()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00",
                                        COMMAND_REQUEST_TLS_CONNECTION)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_REQUEST_TLS_CONNECTION)

        return check_message_pack(self.protocol.read(),
                                  FLAGS_TRANSPORT_LAYER_SECURITY)

    def mcu_get_pov_image(self):
        print("mcu_get_pov_image()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00",
                                        COMMAND_MCU_GET_POV_IMAGE)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_MCU_GET_POV_IMAGE)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()),
            COMMAND_MCU_GET_POV_IMAGE)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0]

    def tls_successfully_established(self):
        print("tls_successfully_established()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00",
                                        COMMAND_TLS_SUCCESSFULLY_ESTABLISHED)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_TLS_SUCCESSFULLY_ESTABLISHED)

    def pov_image_check(self):
        print("pov_image_check()")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(b"\x00\x00", COMMAND_POV_IMAGE_CHECK)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_POV_IMAGE_CHECK)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_POV_IMAGE_CHECK)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0]

    def preset_psk_write(self,
                         flags: int,
                         payload: bytes,
                         length: int | None = None,
                         offset: int | None = None,
                         pre_flags: bytes | None = None):
        # TODO support multiples writes
        print(f"preset_psk_write({flags}, {payload}, {length}, {offset}, "
              f"{pre_flags})")

        if length is None or offset is None:
            if length is not None or offset is not None:
                raise ValueError("Invalid length or offset")

        data = (b"" if pre_flags is None else pre_flags) + struct.pack(
            "<I", flags) + struct.pack("<I", len(payload)) + payload
        if length is not None:
            total_length = len(data)
            if offset + length > total_length:
                raise ValueError("Invalid payload, length or offset")

            data = struct.pack(
                "<I", total_length) + struct.pack("<I", length) + struct.pack(
                    "<I", offset) + data[offset:offset + length]

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(data, COMMAND_PRESET_PSK_WRITE_R)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_PRESET_PSK_WRITE_R)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()),
            COMMAND_PRESET_PSK_WRITE_R)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0] == 0x00

    def preset_psk_read(self,
                        flags: int,
                        length: int | None = None,
                        offset: int | None = None):
        print(f"preset_psk_read({flags}, {length}, {offset})")

        if (length is None or offset is None) and (length is not None
                                                   or offset is not None):
            raise ValueError("Invalid length or offset")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    (b"" if length is None else struct.pack("<I", length)) +
                    (b"" if offset is None else struct.pack("<I", offset)) +
                    struct.pack("<I", flags) + struct.pack("<I", 0),
                    COMMAND_PRESET_PSK_READ_R)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_PRESET_PSK_READ_R)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()),
            COMMAND_PRESET_PSK_READ_R)

        message_length = len(message)
        if message_length < 1:
            raise SystemError("Invalid response length")

        if message[0] != 0x00:
            return False, None, None

        if message_length < 9:
            raise SystemError("Invalid response length")

        psk_length = struct.unpack("<I", message[5:9])[0]
        if message_length - 9 < psk_length:
            raise SystemError("Invalid response length")

        flags = struct.unpack("<I", message[1:5])[0]
        return True, flags, message[9:9 + psk_length]

    def write_firmware(self,
                       offset: int,
                       payload: bytes,
                       number: int | None = None):
        print(f"write_firmware({offset}, {payload}, {number})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    struct.pack("<I", offset) +
                    struct.pack("<I", len(payload)) +
                    (b"" if number is None else struct.pack("<I", number)) +
                    payload, COMMAND_WRITE_FIRMWARE)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_WRITE_FIRMWARE)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_WRITE_FIRMWARE)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0] == 0x01

    def read_firmware(self, offset: int, length: int):
        print(f"read_firmware({offset}, {length})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    struct.pack("<I", offset) + struct.pack("<I", length),
                    COMMAND_READ_FIRMWARE)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_READ_FIRMWARE)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_READ_FIRMWARE)
        if len(message) < length:
            raise SystemError("Invalid response length")

        return message[:length]

    def check_firmware(self,
                       offset: int | None = None,
                       length: int | None = None,
                       checksum: int | None = None,
                       hmac: bytes | None = None):
        print(f"update_firmware({offset}, {length}, {checksum}, {hmac})")

        if offset is None or length is None or checksum is None:
            if offset is not None or length is not None or checksum is not None:
                raise ValueError("Invalid offset, length or checksum")

        if offset is None and hmac is None:
            raise ValueError("Invalid offset, length, checksum or hmac")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    (b"" if offset is None else struct.pack("<I", offset) +
                     struct.pack("<I", length) + struct.pack("<I", checksum)) +
                    (b"" if hmac is None else hmac), COMMAND_CHECK_FIRMWARE)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_CHECK_FIRMWARE)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_CHECK_FIRMWARE)

        if len(message) < 1:
            raise SystemError("Invalid response length")

        return message[0] == 0x01

    def get_iap_version(self, length: int):
        print(f"get_iap_version({length})")

        self.protocol.write(
            encode_message_pack(
                encode_message_protocol(
                    struct.pack("<B", length) + b"\x00",
                    COMMAND_GET_IAP_VERSION)))

        if isinstance(self.protocol, protocol.USBProtocol):
            check_ack(
                check_message_protocol(
                    check_message_pack(self.protocol.read()), COMMAND_ACK),
                COMMAND_GET_IAP_VERSION)

        message = check_message_protocol(
            check_message_pack(self.protocol.read()), COMMAND_GET_IAP_VERSION)

        if len(message) < length:
            raise SystemError("Invalid response length")

        return message.split(b"\x00")[0].decode()
