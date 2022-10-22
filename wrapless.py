import dataclasses
import enum
import logging
import struct

import crccheck
import Crypto.Hash.HMAC
import Crypto.Hash.SHA256
import Crypto.Cipher.AES
import usb

import protocol

USB_CHUNK_SIZE = 0x40
FIRMWARE_CHUNK_SIZE = 0x400


@dataclasses.dataclass
class Message:
    _category: int
    _command: int
    _payload: bytes

    @property
    def category(self):
        return self._category

    @category.setter
    def category(self, category):
        assert category <= 0xF
        self._category = category

    @property
    def command(self):
        return self._command

    @command.setter
    def command(self, command):
        assert command <= 0x7
        self._command = command

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, payload):
        assert len(payload) <= 0xFFFF
        self._payload = payload


class FingerDetectionOperation(enum.Enum):
    DOWN = 1
    UP = 2
    MANUAL = 3


@dataclasses.dataclass
class OptionByte:
    WriteProtect: bytes
    MainSecurity: bool
    FlashSecurity: bool

class Device:

    def __init__(self, product: int, proto, timeout: float | None = 5):
        logging.debug(f"__init__({product}, {proto}, {timeout})")

        self.protocol: protocol.Protocol = proto(0x27C6, product, timeout)
        self.gtls_context: GTLSContext | None = None

        # FIXME Empty device reply buffer
        # (Current patch while waiting for a fix)
        self._empty_buffer()

    def _empty_buffer(self):
        logging.debug("_empty_buffer()")

        try:
            while True:
                self.protocol.read(timeout=0.1)

        except usb.core.USBTimeoutError as error:
            if error.backend_error_code == -7:
                return

            raise error

    def _recv_next_chunk(self, timeout: float | None):
        for _ in range(10):
            chunk = self.protocol.read(USB_CHUNK_SIZE, timeout=timeout)
            if chunk:
                return chunk
        raise Exception("Too many empty reads")

    def _recv_message_from_device(
        self,
        timeout: float | None,
    ):
        data = self._recv_next_chunk(timeout)
        logging.debug(f"Received chunk from device: {data.hex(' ')}")

        command_byte = data[0]
        message_size = struct.unpack("<H", data[1:3])[0]

        while len(data) - 1 < message_size:
            chunk = self._recv_next_chunk(timeout)
            logging.debug(f"Received chunk from device: {chunk.hex(' ')}")

            contd_command_byte = chunk[0]
            if contd_command_byte & 1 == 0 or contd_command_byte & 0xFE != command_byte:
                raise Exception("Wrong continued chunk")

            data += chunk[1:]

        category = command_byte >> 4
        command = (command_byte & 0xF) >> 1
        data = data[:message_size + 3]

        msg_checksum = data[-1]
        data = data[:-1]
        if msg_checksum != 0x88:
            checksum = 0xAA - sum(data) & 0xFF
            if msg_checksum != checksum:
                raise Exception(
                    f"Wrong checksum, "
                    f"expected: {hex(checksum)}, received: {hex(msg_checksum)}"
                )

        payload = data[3:]

        message = Message(category, command, payload)

        logging.info(f"Received message from device: {message}")

        return message

    def _check_ack(self, command_byte: int, timeout: float):
        message = self._recv_message_from_device(timeout)

        if message.category != 0xB:
            raise Exception("Not an ACK message")

        if message.command != 0:
            raise Exception("ACK should not have commands")

        if command_byte != message.payload[0]:
            raise Exception("ACK wrong command")

        logging.info(f"Received ACK for {hex(command_byte)}")

    def _send_message_to_device(
        self,
        message: Message,
        use_checksum: bool,
        ack_timeout: float,
    ):
        command_byte = message.category << 4 | message.command << 1

        data = struct.pack("<B", command_byte)
        data += struct.pack("<H", len(message.payload) + 1)
        data += message.payload
        checksum = 0xAA - sum(data) & 0xFF if use_checksum else 0x88
        data += struct.pack("<B", checksum)

        logging.info(f"Sending message: {data.hex(' ')}")

        is_first = True
        while data:
            if is_first:
                chunk = data[:USB_CHUNK_SIZE]
                data = data[USB_CHUNK_SIZE:]
                is_first = False
            else:
                chunk = struct.pack("<B", command_byte | 1)
                chunk += data[:USB_CHUNK_SIZE - 1]
                data = data[USB_CHUNK_SIZE - 1:]
            assert len(chunk) <= USB_CHUNK_SIZE

            logging.debug(f"Sending chunk: {chunk.hex(' ')}")
            self.protocol.write(chunk)

        self._check_ack(command_byte, ack_timeout)

    def ping(self):
        logging.debug("ping()")
        self._send_message_to_device(Message(0, 0, b"\x00\x00"), True, 0.5)

    def read_firmware_version(self):
        logging.debug("firmware_version()")
        self._send_message_to_device(Message(0xA, 4, b"\x00\x00"), True, 0.5)

        message = self._recv_message_from_device(2)
        if message.category != 0xA or message.command != 4:
            raise Exception("Not a firmware version reply")

        return message.payload.split(b"\x00")[0].decode()

    def reset(self, reset_type: int, irq_status: bool):
        logging.debug("reset()")
        if reset_type == 0:
            msg = 0b001
            if irq_status:
                msg |= 0b100
            msg |= 20 << 8
        elif reset_type == 1:
            msg = 0b010
            msg |= 50 << 8
        elif reset_type == 2:
            msg = 0b011
        else:
            raise Exception(f"Invalid reset type: {reset_type}")

        request = Message(0xA, 1, msg.to_bytes(length=2, byteorder="little"))
        self._send_message_to_device(request, True, 0.5)

        if reset_type != 0 or not irq_status:
            return None

        reply = self._recv_message_from_device(1)
        if reply.category != 0xA or reply.command != 1:
            raise Exception("Not a reset reply")

        irq_status_val = int.from_bytes(reply.payload, byteorder="little")
        logging.debug(f"irq_status: {irq_status_val:#x}")
        return irq_status_val

    def _production_read(self, read_type: int):
        request = Message(0xE, 2, struct.pack("<L", read_type))
        self._send_message_to_device(request, True, 0.5)

        reply = self._recv_message_from_device(1)
        if reply.category != 0xE or reply.command != 2:
            raise Exception("Not a production read reply")

        payload = reply.payload

        if payload[0] != 0:
            raise Exception("Production read MCU failed")
        payload = payload[1:]

        msg_read_type = struct.unpack("<L", payload[:4])[0]
        payload = payload[4:]
        if read_type != msg_read_type:
            raise Exception(
                f"Wrong read type in reply, "
                f"expected: {hex(read_type)}, received: {hex(msg_read_type)}")

        payload_size = struct.unpack("<L", payload[:4])[0]
        payload = payload[4:]
        if payload_size != len(payload):
            raise Exception(f"Payload does not match reported size: "
                            f"{payload_size} != {len(payload)}")

        return payload

    def _production_write(self, data_type: int, data: bytes):
        payload = struct.pack("<L", data_type)
        payload += struct.pack("<L", len(data))  # Header size excluded
        payload += data

        self._send_message_to_device(Message(0xE, 1, payload), True, 0.5)

        reply = self._recv_message_from_device(1)
        if reply.category != 0xE or reply.command != 1:
            raise Exception("Not a production write reply")

        if reply.payload[0] != 0:
            raise Exception("Production write MCU failed")

    def _recv_mcu(self, read_type):
        logging.debug("recv_mcu()")

        message = self._recv_message_from_device(2)
        if message.category != 0xD or message.command != 1:
            raise Exception("Not a GTLS handshake message")

        payload = message.payload

        msg_read_type = struct.unpack("<L", payload[:4])[0]
        if read_type != msg_read_type:
            raise Exception(
                f"Wrong read type in reply, "
                f"expected: {hex(read_type)}, received: {hex(msg_read_type)}")

        payload_size = struct.unpack("<L", payload[4:8])[0]
        if payload_size != len(payload):
            raise Exception(f"Payload does not match reported size: "
                            f"{payload_size} != {len(payload)}")

        return payload[8:]

    def _send_mcu(self, data_type, data: bytes):
        logging.debug("send_mcu()")

        payload = struct.pack("<L", data_type)
        payload += struct.pack("<L", len(data) + 8)  # Header size included
        payload += data

        self._send_message_to_device(Message(0xD, 1, payload), True, 0.5)

    def read_sealed_psk(self):
        logging.debug("read_sealed_psk()")
        return self._production_read(0xB001)

    def write_sealed_psk(self, sealed_psk: bytes):
        logging.debug("writing_sealed_psk()")
        return self._production_write(0xB001, sealed_psk)

    def write_psk_white_box(self, psk_white_box: bytes):
        logging.debug("write_psk_white_box()")
        self._production_write(0xB002, psk_white_box)

    def read_psk_hash(self):
        logging.debug("read_psk_hash()")
        return self._production_read(0xB003)

    def establish_gtls_connection(self, psk):
        logging.debug("establish_gtls_connection()")
        self.gtls_context = GTLSContext(psk, self)
        self.gtls_context.establish_connection()

    def read_data(self, addr: int, read_size: int, timeout: float):
        request = b"\x00"
        request += struct.pack("<H", addr)
        request += struct.pack("<H", read_size)

        self._send_message_to_device(Message(0x8, 0x1, request), True, 0.5)

        reply = self._recv_message_from_device(timeout)
        if reply.category != 0x8 or reply.command != 0x1:
            raise Exception("Not a register read message")

        return reply.payload

    def read_otp(self, timeout: float):
        self._send_message_to_device(Message(0xA, 0x3, b"\x00\x00"), True, 0.5)

        reply = self._recv_message_from_device(timeout)
        if reply.category != 0xA or reply.command != 0x3:
            raise Exception("Not a register read message")

        return reply.payload

    def upload_config(self, config: bytes, timeout: float):
        logging.debug("Uploading configuration")

        self._send_message_to_device(Message(0x9, 0, config), True, 0.5)

        reply = self._recv_message_from_device(timeout)
        if reply.category != 0x9 or reply.command != 0:
            raise Exception("Not a config message")

        result = int.from_bytes(reply.payload, byteorder="little")
        if result != 1:
            raise Exception("Upload configuration failed")

    def execute_fdt_operation(self,
                              fdt_op: FingerDetectionOperation,
                              fdt_base: bytes,
                              timeout: float = 0):
        if fdt_op == FingerDetectionOperation.DOWN:
            assert len(fdt_base) == 24
            op_code = 0xC
            ack_timeout = timeout
        elif fdt_op == FingerDetectionOperation.UP:
            assert len(fdt_base) == 24
            op_code = 0xE
            ack_timeout = timeout
        elif fdt_op == FingerDetectionOperation.MANUAL:
            assert len(fdt_base) == 25
            op_code = fdt_base[0]
            fdt_base = fdt_base[1:]
            ack_timeout = 0.5

        payload = op_code.to_bytes(length=1, byteorder="little")
        payload += int.to_bytes(1, length=1, byteorder="little")  # always 1
        payload += fdt_base
        self._send_message_to_device(Message(0x3, fdt_op.value, payload), True,
                                     ack_timeout)

        if fdt_op != FingerDetectionOperation.MANUAL:
            return None

        fdt_data, _ = self._get_finger_detection_data(fdt_op, timeout)
        return fdt_data

    def wait_for_fdt_event(self,
                           fdt_op: FingerDetectionOperation,
                           timeout: float | None = None):
        return self._get_finger_detection_data(fdt_op, timeout)

    def _get_finger_detection_data(self, fdt_op: FingerDetectionOperation,
                                   timeout: float | None):
        reply = self._recv_message_from_device(timeout)
        if reply.category != 0x3 or reply.command != fdt_op.value:
            raise Exception("Not a finger detection reply")

        payload = reply.payload

        if len(payload) != 28:
            raise Exception("Finger detection payload wrong length")

        irq_status = int.from_bytes(payload[:2], byteorder="little")
        payload = payload[2:]
        logging.debug(f"IRQ status: {irq_status:#x}")

        touch_flag = int.from_bytes(payload[:2], byteorder="little")
        payload = payload[2:]
        logging.debug(f"Touch flag: {touch_flag:#x}")

        return payload, touch_flag

    def get_image(self, request: bytes, timeout: float):
        assert len(request) == 4

        self._send_message_to_device(Message(0x2, 0, request), True, 0.5)

        message = self._recv_message_from_device(timeout)
        if message.category != 0x2 or message.command != 0:
            raise Exception("Not an image message")

        if self.gtls_context is None or not self.gtls_context.is_connected():
            raise Exception("Invalid GTLS connection state")

        data: bytes = self.gtls_context.decrypt_sensor_data(message.payload)
        return data

    def set_sleep_mode(self, timeout: float):
        self._send_message_to_device(
            Message(0x6, 0, int.to_bytes(1, length=2, byteorder="little")),
            True,
            timeout,
        )

    def ec_control(self, power: str, timeout: float):
        if power == "on":
            control_val = 1
        elif power == "off":
            control_val = 0
        else:
            raise ValueError

        self._send_message_to_device(
            Message(0xA, 7,
                    control_val.to_bytes(1, byteorder="little") * 2 + b"\x00"),
            True,
            timeout,
        )

        reply = self._recv_message_from_device(500)
        if reply.category != 0xA or reply.command != 7:
            raise Exception("Not an EC control reply")

        if int.from_bytes(reply.payload, byteorder="little") != 1:
            raise Exception("EC control failed")

    def clear_flash(self, clear_flash_delay: int):
        self._send_message_to_device(
            Message(
                0xA, 2, b"\x00" + clear_flash_delay.to_bytes(1, byteorder="little")
            ),
            True,
            500,
        )

    def read_firmware(self, addr: int, size: int) -> bytes:
        assert size < 0x7FFF

        if addr > 0xFFFF:
            if addr % 0x400 != 0:
                raise ValueError
            addr = addr // 0x400
            size |= 1 << 0xF

        msg = struct.pack("<H", addr)
        msg += struct.pack("<H", size)
        self._send_message_to_device(
            Message(0xF, 1, msg),
            True,
            500,
        )

        reply = self._recv_message_from_device(5000)
        if reply.category != 0xF or reply.command != 1:
            raise Exception("Not a firmware read reply")

        return reply.payload

    def read_option_byte(self):
        msg = b"\x01"
        self._send_message_to_device(
            Message(0xF, 4, msg),
            True,
            500,
        )

        reply = self._recv_message_from_device(5000)
        if reply.category != 0xF or reply.command != 4:
            raise Exception("Not an option byte read reply")

        if len(reply.payload) != 0x18:
            raise Exception("Wrong option byte length")

        payload = reply.payload

        write_protect = payload[:0x10]
        payload = payload[0x10:]

        main_security = int.from_bytes(payload[:0x4], byteorder="little")
        option_protect = int.from_bytes(payload[0x4:], byteorder="little")

        return OptionByte(write_protect, bool(main_security), bool(option_protect))

    def update_firmware(self, firmware: bytes):
        assert len(firmware) < 0x10000

        sent_bytes = 0
        sent_chunks = 0
        while sent_bytes < len(firmware):
            firmware_chunk = firmware[sent_bytes : sent_bytes + FIRMWARE_CHUNK_SIZE]

            msg = struct.pack("<H", sent_bytes)
            msg += struct.pack("<H", len(firmware_chunk))
            msg += firmware_chunk

            self._send_message_to_device(
                Message(0xF, 0, msg),
                True,
                500,
            )

            reply = self._recv_message_from_device(5000)
            if reply.category != 0xF or reply.command != 0:
                raise Exception("Not a firmware update reply")

            sent_bytes += len(firmware_chunk)
            sent_chunks += 1

        firmware_len = len(firmware)
        firmware_crc = crccheck.crc.Crc32Mpeg2.calc(firmware)
        msg = b"\x00" * 2
        msg += struct.pack("<H", firmware_len & 0xFFFF)
        msg += firmware_crc.to_bytes(4, byteorder="little")
        msg += b"\x01"
        msg += struct.pack("<H", (firmware_len >> 0x10) & 0xFFFF)

        self._send_message_to_device(
            Message(0xF, 2, msg),
            True,
            500,
        )

        reply = self._recv_message_from_device(1000)
        if reply.category != 0xF or reply.command != 2:
            raise Exception("Not a firmware checksum reply")

        if reply.payload[0] == 0:
            raise Exception("Firmware checksum not correct")

        self.reset(1, False)


class GTLSContext:
    def __init__(self, psk: bytes, device: Device):
        self.state = 0
        self.client_random: bytes | None = None
        self.server_random: bytes | None = None
        self.client_identity: bytes | None = None
        self.server_identity: bytes | None = None
        self.symmetric_key: bytes | None = None
        self.symmetric_iv: bytes | None = None
        self.hmac_key: bytes | None = None
        self.hmac_client_counter_init: int | None = None
        self.hmac_server_counter_init: int | None = None
        self.hmac_client_counter: int | None = None
        self.hmac_server_counter: int | None = None
        self.psk = psk
        self.device = device

    def _client_hello_step(self):
        if self.state >= 2:
            raise Exception(f"Cannot send client hello, state: {self.state}")

        self.client_random = Crypto.Random.get_random_bytes(0x20)
        logging.debug(f"client_random: {self.client_random.hex(' ')}")

        self.device._send_mcu(0xFF01, self.client_random)
        self.state = 2

    def _server_identity_step(self):
        if self.state != 2:
            raise Exception(
                f"Cannot receive server identity, state: {self.state}")

        data = self.device._recv_mcu(0xFF02)
        if len(data) != 0x40:
            raise Exception("Wrong payload size")

        self.server_random = data[:0x20]
        logging.debug(f"server_random: {self.server_random.hex(' ')}")
        self.server_identity = data[0x20:]
        logging.debug(f"server_identity: {self.server_identity.hex(' ')}")

        session_key = _derive_session_key(
            self.psk, self.client_random + self.server_random, 0x44)

        self.symmetric_key = session_key[:0x10]
        logging.debug(f"symmetric_key: {self.symmetric_key.hex(' ')}")
        session_key = session_key[0x10:]

        self.symmetric_iv = session_key[:0x10]
        logging.debug(f"symmetric_iv: {self.symmetric_iv.hex(' ')}")
        session_key = session_key[0x10:]

        self.hmac_key = session_key[:0x20]
        logging.debug(f"hmac_key: {self.hmac_key.hex(' ')}")
        session_key = session_key[0x20:]

        self.hmac_client_counter_init = struct.unpack("<H", session_key[:2])[0]
        logging.debug(
            f"hmac_client_counter_init: {self.hmac_client_counter_init}")
        session_key = session_key[2:]

        self.hmac_server_counter_init = struct.unpack("<H", session_key[:2])[0]
        logging.debug(
            f"hmac_server_counter_init: {self.hmac_server_counter_init}")
        session_key = session_key[2:]

        assert not session_key

        self.client_identity = Crypto.Hash.HMAC.HMAC(
            self.hmac_key, self.client_random + self.server_random,
            Crypto.Hash.SHA256).digest()
        logging.debug(f"client_identity: {self.client_identity.hex(' ')}")

        if self.server_identity != self.client_identity:
            raise Exception("Session key not derived correctly")

        self.device._send_mcu(0xFF03, self.client_identity + b"\xee" * 4)
        self.state = 4

    def _server_done_step(self):
        if self.state != 4:
            raise Exception(f"Cannot receive server done, state: {self.state}")

        data = self.device._recv_mcu(0xFF04)
        result = struct.unpack("<L", data)[0]
        if result != 0:
            raise Exception(f"Wrong handshake result reported: {result}")

        self.hmac_client_counter = self.hmac_client_counter_init
        self.hmac_server_counter = self.hmac_server_counter_init
        self.state = 5

    def establish_connection(self):
        logging.info("Starting GTLS handshake")
        self._client_hello_step()
        self._server_identity_step()
        self._server_done_step()
        logging.info("GTLS handshake successful")

    def is_connected(self):
        return self.state == 5

    def decrypt_sensor_data(self, encrypted_message):
        data_type = struct.unpack("<L", encrypted_message[:4])[0]
        if data_type != 0xAA01:
            raise Exception("Unexpected data type")

        msg_length = struct.unpack("<L", encrypted_message[4:8])[0]
        if msg_length != len(encrypted_message):
            raise Exception("Length mismatch")

        encrypted_payload = encrypted_message[8:-0x20]
        payload_hmac = encrypted_message[-0x20:]
        logging.debug(f"HMAC for encrypted payload: {payload_hmac.hex(' ')}")

        gea_encrypted_data = b""
        for block_idx in range(15):
            if block_idx % 2 == 0:
                if block_idx == 0:
                    gea_encrypted_data += encrypted_payload[:0x3A7]
                    encrypted_payload = encrypted_payload[0x3A7:]
                elif block_idx == 14:
                    assert len(gea_encrypted_data) == 0x3A7 + 0x3F0 * 13
                    gea_encrypted_data += encrypted_payload
                else:
                    gea_encrypted_data += encrypted_payload[:0x3F0]
                    encrypted_payload = encrypted_payload[0x3F0:]
            else:
                cipher = Crypto.Cipher.AES.new(self.symmetric_key,
                                               Crypto.Cipher.AES.MODE_CBC,
                                               iv=self.symmetric_iv)
                gea_encrypted_data += cipher.decrypt(encrypted_payload[:0x3F0])
                encrypted_payload = encrypted_payload[0x3F0:]

        hmac_data = struct.pack("<L", self.hmac_server_counter)
        hmac_data += gea_encrypted_data[-0x400:]
        computed_hmac = Crypto.Hash.HMAC.HMAC(self.hmac_key, hmac_data,
                                              Crypto.Hash.SHA256).digest()

        if computed_hmac != payload_hmac:
            raise Exception("HMAC verification failed")
        logging.debug("Encrypted payload HMAC verified")

        self.hmac_server_counter = (self.hmac_server_counter + 1) & 0xFFFFFFFF
        logging.debug(
            f"HMAC server counter is now: {self.hmac_server_counter}")

        if len(gea_encrypted_data) < 5:
            raise Exception("Encrypted payload too short")
        # The first five bytes are always discarded (alignment?)
        gea_encrypted_data = gea_encrypted_data[5:]

        msg_gea_crc = decode_u32(gea_encrypted_data[-4:])
        gea_encrypted_data = gea_encrypted_data[:-4]
        logging.debug(f"GEA data CRC: {hex(msg_gea_crc)}")

        computed_gea_crc = crccheck.crc.Crc32Mpeg2.calc(gea_encrypted_data)
        if computed_gea_crc != msg_gea_crc:
            raise Exception("CRC check failed")
        logging.debug("GEA data CRC verified")

        gea_key = self.symmetric_key[:4]
        logging.debug(f"GEA key: {gea_key.hex(' ')}")

        return _gea_decrypt(gea_key, gea_encrypted_data)


def _derive_session_key(psk, random_data: bytes, session_key_length: int):
    seed = b"master secret" + random_data

    session_key = b""
    A = seed
    while len(session_key) < session_key_length:
        A = Crypto.Hash.HMAC.HMAC(psk, A, Crypto.Hash.SHA256).digest()
        session_key += Crypto.Hash.HMAC.HMAC(psk, A + seed,
                                             Crypto.Hash.SHA256).digest()

    data: bytes = session_key[:session_key_length]
    return data


def decode_u32(data: bytes):
    assert len(data) == 4
    return data[0] * 0x100 + data[1] + data[2] * 0x1000000 + data[3] * 0x10000


def _gea_decrypt(key, encrypted_data):
    key = struct.unpack("<L", key)[0]

    decrypted_data = b""
    for data_idx in range(0, len(encrypted_data), 2):
        uVar3 = (key >> 1 ^ key) & 0xFFFFFFFF
        uVar2 = (((((((
            (key >> 0xF & 0x2000 | key & 0x1000000) >> 1 | key & 0x20000) >> 2
                      | key & 0x1000) >> 3 | (key >> 7 ^ key) & 0x80000) >> 1 |
                    (key >> 0xF ^ key) & 0x4000) >> 2 | key & 0x2000) >> 2
                  | uVar3 & 0x40 | key & 0x20) >> 1 |
                 (key >> 9 ^ key << 8) & 0x800 | (key >> 0x14 ^ key * 2) & 4 |
                 (key * 8 ^ key >> 0x10) & 0x4000 |
                 (key >> 2 ^ key >> 0x10) & 0x80 |
                 (key << 6 ^ key >> 7) & 0x100 | (key & 0x100) << 7)
        uVar2 = uVar2 & 0xFFFFFFFF
        uVar1 = key & 0xFFFF
        key = ((key ^
                (uVar3 >> 0x14 ^ key) >> 10) << 0x1F | key >> 1) & 0xFFFFFFFF

        input_element = struct.unpack("<H",
                                      encrypted_data[data_idx:data_idx + 2])[0]
        stream_val = (
            (uVar2 >> 8) & 0xFFFF) + (uVar2 & 0xFF | uVar1 & 1) * 0x100
        decrypted_data += struct.pack("<H", input_element ^ stream_val)

    assert len(encrypted_data) == len(decrypted_data)
    return decrypted_data
