protocol = Proto("goodix", "Goodix Fingerprint Sensor Message Protocol")

cmd0_field = ProtoField.uint8("goodix.cmd0", "Command 0", base.HEX, nil, 0xf0)
cmd1_field = ProtoField.uint8("goodix.cmd1", "Command 1", base.HEX, nil, 0x0e)
contd_field = ProtoField.bool("goodix.contd", "Continued", 8, nil, 0x1)
length_field = ProtoField.uint16("goodix.length", "Length", base.DEC)
checksum_field = ProtoField.uint8("goodix.checksum", "Checksum", base.HEX)

ack_config = ProtoField.bool("goodix.ack.has_no_config", "MCU has no config", 2, nil, 0x02)
ack_true = ProtoField.bool("goodix.ack.true", "Always True", 2, nil, 0x01)
ack_cmd = ProtoField.uint8("goodix.ack.cmd", "ACK Command", base.HEX)
success = ProtoField.bool("goodix.success", "Success")
failed = ProtoField.bool("goodix.failed", "Failed")
power_isolate = ProtoField.uint8("goodix.ec_control.power_isolate", "Power isolate", base.HEX)
remote_wakeup = ProtoField.uint8("goodix.ec_control.remote_wakeup", "Remote wakeup", base.HEX)

version = ProtoField.string("goodix.version", "Version")
enable_chip = ProtoField.bool("goodix.enable_chip", "Enable chip")
sleep_time = ProtoField.uint8("goodix.sleep_time", "Sleep time")
read_length = ProtoField.uint8("goodix.read_length", "Length")

reset_sensor = ProtoField.bool("goodix.reset.sensor", "Reset Sensor", 8, nil, 0x01)
reset_mcu = ProtoField.bool("goodix.reset.mcu", "Soft Reset MCU", 8, nil, 0x02)
reset_reply_irq = ProtoField.bool("goodix.reset.reply_irq", "Reply with IRQ", 8, nil, 0x04)
reset_irq_status = ProtoField.uint16("goodix.reset.irq_status", "IRQ Status", base.HEX)

register_multiple = ProtoField.bool("goodix.register.multiple", "Multiple Addresses")
register_address = ProtoField.uint16("goodix.register.address", "Base Address", base.HEX)

psk_msg_type = ProtoField.uint32("goodix.psk_msg.type", "PSK message type", base.RANGE_STRING,
    {{0xb001, 0xb001, "SGX Sealed PSK"}, {0xb002, 0xb002, "Encrypted-Signed PSK"}, {0xb003, 0xb003, "PSK SHA256 Hash"}})
psk_msg_length = ProtoField.uint32("goodix.psk_msg.length", "PSK message length", base.UNIT_STRING, {" bytes"})
psk_msg_content = ProtoField.bytes("goodix.psk_msg.content", "PSK message content", base.SPACE)

gtls_type = ProtoField.uint32("goodix.gtls.type", "TLS Handshake message type", base.RANGE_STRING,
    {{0xff01, 0xff01, "Client hello (client_random)"},
     {0xff02, 0xff02, "Server identity (server_random | server_identity)"},
     {0xff03, 0xff03, "Client done (client_identity | 0xeeeeeeee)"},
     {0xff04, 0xff04, "Server done"}})
gtls_length = ProtoField.uint32("goodix.gtls.length", "TLS Handshake message length", base.UNIT_STRING, {" bytes"})
gtls_content = ProtoField.bytes("goodix.gtls.content", "TLS Handshake content", base.SPACE)

image_type = ProtoField.uint32("goodix.image.type", "Image message type", base.HEX)
image_length = ProtoField.uint32("goodix.image.length", "Image message length", base.UNIT_STRING, {" bytes"})
image_content = ProtoField.bytes("goodix.image.content", "Image message content", base.SPACE)

fdt_irq_status = ProtoField.uint16("goodix.fdt.irq_status", "Milan FDT IRQ status")
fdt_touchflag = ProtoField.uint16("goodix.fdt.touchflag", "FDT touchflag")
fdt_content = ProtoField.bytes("goodix.fdt.content", "FDT message content", base.SPACE)

firmware_offset = ProtoField.uint32("goodix.firmware.offset", "Firmware Offset")
firmware_length = ProtoField.uint32("goodix.firmware.length", "Firmware Lenght")
firmware_checksum = ProtoField.uint32("goodix.firmware.checksum", "Firmware Checksum")

powerdown_scan_frequency = ProtoField.uint16("goodix.powerdown_scan_frequency", "Powerdown Scan Frequecy")

config_sensor_chip = ProtoField.uint8("goodix.config_sensor_chip", "Sensor Chip", base.RANGE_STRING,
    {{0x00, 0x00, "GF3208"}, {0x01, 0x01, "GF3288"}, {0x02, 0x02, "GF3266"}}, 0xf0)

mode = ProtoField.uint8("goodix.mode", "Mode", base.RANGE_STRING,
    {{0x01, 0x01, "Image, NAV or Sleep"}, {0x0c, 0x0c, "FDT Down"}, {0xd, 0xd, "FDT Manual"}, {0x0e, 0x0e, "FDT Up"},
     {0x10, 0xf0, "FF"}})
base_type = ProtoField.uint8("goodix.base_type", "Base Type")

protocol.fields = {pack_flags, cmd0_field, cmd1_field, contd_field, length_field, checksum_field, ack_cmd, ack_true, ack_config,
                   success, failed, power_isolate, remote_wakeup, version, enable_chip, sleep_time,
                   reset_sensor, reset_mcu, reset_reply_irq, reset_irq_status,
                   register_multiple, register_address, read_length, powerdown_scan_frequency, config_sensor_chip, mode,
                   base_type, psk_msg_type, psk_msg_length, psk_msg_content, gtls_type, gtls_length, gtls_content,
                   image_type, image_length, image_content, firmware_offset, firmware_length, firmware_checksum,
                   fdt_irq_status, fdt_touchflag, fdt_content}

function extract_cmd0_cmd1(cmd)
    return bit.rshift(cmd, 4), bit.rshift(cmd % 16, 1)
end

function get_cmd_name(cmd)
    cmd0, cmd1 = extract_cmd0_cmd1(cmd)

    if commands[cmd0][cmd1] ~= nil then
        return commands[cmd0][cmd1].name
    else
        return string.format("%s.%x", commands[cmd0].category_name, cmd1)
    end
end

commands = {
    [0x0] = { -- Correct
        category_name = "PING",

        [0x0] = {
            name = "Ping",
            dissect_command = function(tree, buf)
            end
        }
    },
    [0x2] = { -- Correct
        category_name = "IMA",

        [0] = {
            name = "MCU Get Image",
            dissect_command = function(tree, buf)
                tree:add_le(mode, buf(0, 1))
                tree:add_le(base_type, buf(1, 1))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(image_type, buf(0, 4))
                tree:add_le(image_length, buf(4, 4))
                tree:add(image_content, buf(8))
            end
        }
    },
    [0x3] = { -- Correct
        category_name = "FDT",

        [1] = {
            name = "MCU Switch To Fdt Down",
            dissect_command = function(tree, buf)
                tree:add_le(mode, buf(0, 1))
                tree:add_le(base_type, buf(1, 1))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(fdt_irq_status, buf(0, 2))
                tree:add_le(fdt_touchflag, buf(2, 2))
                tree:add(fdt_content, buf(4))
            end
        },
        [2] = {
            name = "MCU Switch To Fdt Up",
            dissect_command = function(tree, buf)
                tree:add_le(mode, buf(0, 1))
                tree:add_le(base_type, buf(1, 1))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(fdt_irq_status, buf(0, 2))
                tree:add_le(fdt_touchflag, buf(2, 2))
                tree:add(fdt_content, buf(4))
            end
        },
        [3] = {
            name = "MCU Switch To Fdt Mode",
            dissect_command = function(tree, buf)
                tree:add_le(mode, buf(0, 1))
                tree:add_le(base_type, buf(1, 1))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(fdt_irq_status, buf(0, 2))
                tree:add(fdt_content, buf(4))
            end
        }
    },
    [0x4] = {
        category_name = "FF",

        [0] = {
            name = "FF",
            dissect_command = function(tree, buf)
                tree:add_le(mode, buf(0, 1))
                tree:add_le(base_type, buf(1, 1))
            end,
            dissect_reply = function(tree, buf)
            end
        }
    },
    [0x5] = {
        category_name = "NAV",

        [0] = {
            name = "NAV",
            dissect_command = function(tree, buf)
                tree:add_le(mode, buf(0, 1))
                tree:add_le(base_type, buf(1, 1))
            end,
            dissect_reply = function(tree, buf)
            end
        }
    },
    [0x6] = {
        category_name = "SLE",

        [0] = {
            name = "MCU Switch To Sleep Mode",
            dissect_command = function(tree, buf)
                tree:add_le(mode, buf(0, 1))
                tree:add_le(base_type, buf(1, 1))
            end,
            dissect_reply = function(tree, buf)
            end
        }
    },
    [0x7] = {
        category_name = "IDL",

        [0] = {
            name = "MCU Switch To Idle Mode",
            dissect_command = function(tree, buf)
                tree:add_le(sleep_time, buf(0, 1))
                tree:add_le(base_type, buf(1, 1))
            end,
            dissect_reply = function(tree, buf)
            end
        }
    },
    [0x8] = { -- Correct
        category_name = "REG",

        [0] = {
            name = "Write Sensor Register",
            dissect_command = function(tree, buf)
                tree:add_le(register_multiple, buf(0, 1))
                tree:add_le(register_address, buf(1, 2))
            end
        },
        [1] = {
            name = "Read Sensor Register",
            dissect_command = function(tree, buf)
                tree:add_le(register_multiple, buf(0, 1))
                tree:add_le(register_address, buf(1, 2))
                tree:add_le(read_length, buf(3, 2)):append_text(" bytes")
            end,
            dissect_reply = function(tree, buf)
            end
        }
    },
    [0x9] = {
        category_name = "CHIP",

        [0] = { -- Correct
            name = "Set chip config",
            dissect_command = function(tree, buf)
                tree:add_le(config_sensor_chip, buf(0, 1))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
            end
        },
        [1] = {
            name = "Switch To Sleep Mode",
            dissect_command = function(tree, buf)
                tree:add_le(number, buf(0, 1))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
            end
        },
        [2] = {
            name = "Set Powerdown Scan Frequency",
            dissect_command = function(tree, buf)
                tree:add_le(powerdown_scan_frequency, buf(0, 2))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
            end
        },
        [3] = {
            name = "Enable Chip",
            dissect_command = function(tree, buf)
                tree:add_le(enable_chip, buf(0, 1))
            end
        }
    },
    [0xa] = { -- Correct
        category_name = "OTHER",

        [0] = {
            name = "Set SPI prescaler",
            dissect_command = function(tree, buf)
                -- byte[0]: SPI clock prescaler
                -- byte[1]: 0 -> get, 1 -> set
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
                -- byte[1]: SPI clock prescaler
            end
        },
        [1] = {
            name = "Reset",
            dissect_command = function(tree, buf)
                tree:add_le(reset_sensor, buf(0, 1))
                tree:add_le(reset_mcu, buf(0, 1))
                tree:add_le(reset_reply_irq, buf(0, 1))
                tree:add_le(sleep_time, buf(1, 1))
            end,
            dissect_reply = function(tree, buf)
                -- byte[0]: event happened
                -- byte[1:3]: IRQ (only if event happened)
            end
        },
        [2] = {
            name = "Delete APP firmware info",
            dissect_command = function(tree, buf)
                tree:add_le(sleep_time, buf(1, 1))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
            end
        },
        [3] = {
            name = "Read OTP",
            dissect_command = function(tree, buf)
            end,
            dissect_reply = function(tree, buf)
                -- byte[0:0x20]: OTP
            end
        },
        [4] = {
            name = "Firmware Version",
            dissect_command = function(tree, buf)
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(version, buf())
            end
        },
        [5] = {
            name = "SPI send",
            dissect_command = function(tree, buf)
                -- byte[0]: value to send
                -- byte[1]: sleep time
            end,
            dissect_reply = function(tree, buf)
            end
        },
        [6] = {
            name = "Flash OTP",
            dissect_command = function(tree, buf)
                -- byte[0:0x20]: OTP
                -- byte[0x20:0x24]: OTP mask
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
            end
        },
        [7] = {
            name = "EC control",
            dissect_command = function(tree, buf)
                tree:add_le(power_isolate, buf(0, 1))
                tree:add_le(remote_wakeup, buf(1, 1))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
            end
        }
    },
    [0xb] = {
        category_name = "MSG",

        [0] = {
            name = "Ack",
            dissect_reply = function(tree, buf)
                tree:add_le(ack_true, buf(1, 1))
                tree:add_le(ack_config, buf(1, 1))
                tree:add_le(ack_cmd, buf(0, 1)):append_text(" (" .. get_cmd_name(buf(0, 1):le_uint()) .. ")")
            end
        }
    },
    [0xc] = {
        category_name = "NOTI",

        [0] = {
            name = "ESD Happened", -- Electro Static Discharge?
            dissect_reply = function(tree, buf)
                -- byte[0:2]: IRQ
            end
        },
        [1] = {
            name = "Wake up",
            dissect_reply = function(tree, buf)
                -- byte[0:2]: IRQ
            end
        },
        [2] = {
            name = "Press Power Button",
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
            end
        },
    },
    [0xd] = { -- Correct
        category_name = "TLSHANDSHAKE",

        [1] = {
            name = "TLS handshake",
            dissect_command = function(tree, buf)
                tree:add_le(gtls_type, buf(0, 4))
                tree:add_le(gtls_length, buf(4, 4))
                tree:add(gtls_content, buf(8))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(gtls_type, buf(0, 4))
                tree:add_le(gtls_length, buf(4, 4))
                tree:add(gtls_content, buf(8))
            end
        },
    },
    [0xe] = { -- Correct
        category_name = "PROD",

        [1] = {
            name = "PSK setup write",
            dissect_command = function(tree, buf)
                tree:add_le(psk_msg_type, buf(0, 4))
                tree:add_le(psk_msg_length, buf(4, 4))
                tree:add(psk_msg_content, buf(8))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(failed, buf(0, 1))
            end
        },
        [2] = {
            name = "PSK setup read",
            dissect_command = function(tree, buf)
                tree:add_le(psk_msg_type, buf(0, 4))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(failed, buf(0, 1))
                tree:add_le(psk_msg_type, buf(1, 4))
                tree:add_le(psk_msg_length, buf(5, 4))
                tree:add(psk_msg_content, buf(9))
            end
        }
    },
    [0xf] = { -- Correct
        category_name = "FLASH",

        [0] = {
            name = "Write Firmware",
            dissect_command = function(tree, buf)
                -- byte[0:2]: write base
                -- byte[2:4]: write size (< 0x8000), bit 0xF: base * 0x400
                -- byte[4:]: data to write
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
            end
        },
        [1] = {
            name = "Read Firmware",
            dissect_command = function(tree, buf)
                -- byte[0:2]: read base
                -- byte[2:4]: read size (< 0x8000), bit 0xF: base * 0x400
            end,
            dissect_reply = function(tree, buf)
                -- byte[:]: read reply
            end
        },
        [2] = {
            name = "Verify and Protect/Enable Firmware",
            dissect_command = function(tree, buf)
                -- byte[0:2]: check base
                -- byte[2:4]: size_1
                -- byte[4:8]: crc32
                -- byte[8]: enable write protection
                -- byte[9:10]: size_2
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
            end
        },
        [3] = {
            name = "Erase Option Byte",
            dissect_command = function(tree, buf)
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
            end
        },
        [4] = {
            name = "Get/Program Option Byte",
            dissect_command = function(tree, buf)
                -- byte[0]: 0 - program option byte, 1 - get option byte
                -- byte[1:0x19]: option byte (optional)
            end,
            dissect_reply = function(tree, buf)
                -- byte[0]: 1 - success (in IAP firmware) (optional)
                -- byte[1]: 0 - success (in APP firmware - BUG) (optional)
                -- byte[0:0x18] option byte (optional)
            end
        }
    }
}

function protocol.init()
    state_map = ByteArray.new()
    total_bytes = 0
    missing_bytes = 0
    cache = {}
end

function protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then
        return
    end

    pinfo.cols.protocol = "Goodix"

    local subtree = tree:add(protocol, buffer(), "Goodix Message Protocol")

    from_host = pinfo.src == Address.ip("1.1.1.1") or tostring(pinfo.src) == "host"
    cmd_val = buffer(0, 1):le_uint()
    packet_is_cont = bit.band(cmd_val, 1) > 0

    subtree:add_le(cmd0_field, buffer(0, 1))
    subtree:add_le(cmd1_field, buffer(0, 1))
    subtree:add_le(contd_field, buffer(0, 1))

    if from_host then
        summary = "Command: " .. get_cmd_name(cmd_val)
    else
        summary = "Reply: " .. get_cmd_name(cmd_val)
    end

    if packet_is_cont then
        if cache[pinfo.number] ~= nil then
            missing_bytes = cache[pinfo.number].missing_bytes
            total_bytes = cache[pinfo.number].total_bytes
        else
            cache[pinfo.number] = {}
            cache[pinfo.number].missing_bytes = missing_bytes
            cache[pinfo.number].total_bytes = total_bytes
        end

        local msg_length = missing_bytes
        local packet_length = buffer():len() - 1

        if msg_length > packet_length then
            local packet_subtree = subtree:add(protocol, buffer(1, packet_length))
            packet_subtree.text = "Data " .. packet_length .. " of " .. total_bytes - 1 .. " bytes"
            pinfo.cols.info = summary .. " cont."
            missing_bytes = missing_bytes - packet_length
            state_map:append(buffer(1):bytes())
            return
        else
            local packet_subtree = subtree:add(protocol, buffer(1, msg_length - 1))
            packet_subtree.text = "Data " .. msg_length - 1 .. " of " .. total_bytes - 1 .. " bytes"
            pinfo.cols.info = summary .. " end"
            state_map:append(buffer(1, msg_length):bytes())

            if cache[pinfo.number].buf == nil then
                cache[pinfo.number].buf = state_map
            end

            msg_buffer = ByteArray.tvb(cache[pinfo.number].buf, "Message")
            missing_bytes = 0
            missing_bytes = 0
            state_map = ByteArray.new()
            total_bytes = 0
        end

    else
        local msg_length = buffer(1, 2):le_uint()
        local packet_length = buffer():len() - 3

        if msg_length > packet_length then
            local packet_subtree = subtree:add(protocol, buffer(3, packet_length))
            packet_subtree.text = "Data " .. packet_length .. " of " .. msg_length - 1 .. " bytes"
            pinfo.cols.info = summary .. " start"
            missing_bytes = msg_length - packet_length
            total_bytes = msg_length
            state_map = buffer():bytes()
            return
        else

            local packet_subtree = subtree:add(protocol, buffer(3, msg_length - 1))
            packet_subtree.text = "Data " .. msg_length - 1 .. " of " .. msg_length - 1 .. " bytes"
            pinfo.cols.info = summary
            msg_buffer = buffer
        end
    end
    local msg_length = msg_buffer(1, 2):le_uint()
    subtree:add_le(length_field, msg_buffer(1, 2)):append_text(" bytes (including checksum)")
    subtree:add_le(checksum_field, msg_buffer(3 + msg_length - 1, 1))

    body_buffer = msg_buffer(3, msg_length - 1):tvb()

    local cmd_subtree = subtree:add(protocol, body_buffer())

    cmd0_val, cmd1_val = extract_cmd0_cmd1(cmd_val)

    if from_host then
        if commands[cmd0_val][cmd1_val] ~= nil then
            commands[cmd0_val][cmd1_val].dissect_command(cmd_subtree, body_buffer)
        end
    else
        if commands[cmd0_val][cmd1_val] ~= nil then
            commands[cmd0_val][cmd1_val].dissect_reply(cmd_subtree, body_buffer)
        end
    end
    cmd_subtree.text = summary
end

usb_table = DissectorTable.get("usb.bulk")
usb_table:add(0x000a, protocol)
usb_table:add(0x00ff, protocol)
usb_table:add(0xffff, protocol)
