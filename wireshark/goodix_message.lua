protocol = Proto("goodix", "Goodix Fingerprint Sensor Message Protocol")

cmd0_field = ProtoField.uint8("goodix.cmd0", "Command 0", base.HEX, nil, 0xF0)
cmd1_field = ProtoField.uint8("goodix.cmd1", "Command 1", base.HEX, nil, 0x0E)
length_field = ProtoField.uint16("goodix.length", "Length", base.DEC)
checksum_field = ProtoField.uint8("goodix.checksum", "Checksum", base.HEX)

ack_config = ProtoField.bool("goodix.ack.has_no_config", "MCU has no config", 2, nil, 0x02)
ack_true = ProtoField.bool("goodix.ack.true", "Always True", 2, nil, 0x01)
ack_cmd = ProtoField.uint8("goodix.ack.cmd", "ACK Command", base.HEX)
success = ProtoField.bool("goodix.success", "Success")
failed = ProtoField.bool("goodix.failed", "Failed")

version = ProtoField.string("goodix.version", "Version")
enable_chip = ProtoField.bool("goodix.enable_chip", "Enable chip")
sleep_time = ProtoField.uint8("goodix.sleep_time", "Sleep time")
read_length = ProtoField.uint8("goodix.read_length", "Length")

mcu_state_image = ProtoField.bool("goodix.mcu_state.is_image_valid", "Is Image Valid", 8, nil, 0x01) -- Meaning unknown
mcu_state_tls = ProtoField.bool("goodix.mcu_state.is_tls_connected", "Is Tls Connected", 8, nil, 0x02)
mcu_state_spi = ProtoField.bool("goodix.mcu_state.is_spi_send", "Is Spi Send", 8, nil, 0x04) -- Meaning unknown
mcu_state_locked = ProtoField.bool("goodix.mcu_state.is_locked", "Is Locked", 8, nil, 0x08) -- Meaning unknown

reset_sensor = ProtoField.bool("goodix.reset.sensor", "Reset Sensor", 8, nil, 0x01)
reset_mcu = ProtoField.bool("goodix.reset.mcu", "Soft Reset MCU", 8, nil, 0x02)
reset_number = ProtoField.uint16("goodix.reset.number", "Sensor Reset Number")

register_multiple = ProtoField.bool("goodix.register.multiple", "Multiple Addresses")
register_address = ProtoField.uint16("goodix.register.address", "Base Address", base.HEX)

psk_flags = ProtoField.uint32("goodix.psk.flags", "PSK Flags", base.HEX)
psk_length = ProtoField.uint32("goodix.psk.length", "PSK Lenght")

firmware_offset = ProtoField.uint32("goodix.firmware.offset", "Firmware Offset")
firmware_length = ProtoField.uint32("goodix.firmware.length", "Firmware Lenght")
firmware_checksum = ProtoField.uint32("goodix.firmware.checksum", "Firmware Checksum")

powerdown_scan_frequency = ProtoField.uint16("goodix.powerdown_scan_frequency", "Powerdown Scan Frequecy")

config_sensor_chip = ProtoField.uint8("goodix.config_sensor_chip", "Sensor Chip", base.RANGE_STRING,
    {{0, 0, "GF3208"}, {1, 1, "GF3288"}, {2, 2, "GF3266"}}, 0xF0)

protocol.fields = {pack_flags, cmd0_field, cmd1_field, length_field, checksum_field, ack_cmd, ack_true, ack_config,
                   success, failed, version, enable_chip, sleep_time, mcu_state_image, mcu_state_tls, mcu_state_spi,
                   mcu_state_locked, reset_sensor, reset_mcu, reset_number, register_multiple, register_address,
                   read_length, powerdown_scan_frequency, config_sensor_chip, psk_flags, psk_length, firmware_offset,
                   firmware_length, firmware_checksum}

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
    [0x0] = {
        category_name = "NOP",
        [0x0] = {
            name = "nop",
            dissect_command = function(tree, buf)
            end
        }
    },
    [0x2] = {
        category_name = "IMA",

        [0] = {
            name = "MCU Get Image",
            dissect_command = function(tree, buf)
            end,
            dissect_reply = function(tree, buf)
            end
        }

    },
    [0x3] = {
        category_name = "FDT",

        [1] = {
            name = "MCU Switch To Fdt Down",
            dissect_command = function(tree, buf)
            end,
            dissect_reply = function(tree, buf)
            end
        },
        [2] = {
            name = "MCU Switch To Fdt Up",
            dissect_command = function(tree, buf)
            end,
            dissect_reply = function(tree, buf)
            end
        },
        [3] = {
            name = "MCU Switch To Fdt Mode",
            dissect_command = function(tree, buf)
            end,
            dissect_reply = function(tree, buf)
            end
        }
    },
    [0x4] = {
        category_name = "FF"
    },
    [0x5] = {
        category_name = "NAV"
    },
    [0x6] = {
        category_name = "SLE",
        [0] = {
            name = "MCU Switch To Sleep Mode",
            dissect_command = function(tree, buf)
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
            end,
            dissect_reply = function(tree, buf)
            end
        }
    },
    [0x8] = {
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
                tree:add_le(read_length, buf(3, 1)):append_text(" bytes")
            end,
            dissect_reply = function(tree, buf)
            end
        }
    },
    [0x9] = {
        category_name = "CHIP",

        [0] = {
            name = "Upload Config MCU Download Chip Config",
            dissect_command = function(tree, buf)
                tree:add_le(config_sensor_chip, buf(0, 1))
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
    [0xA] = {
        category_name = "OTHER",

        [1] = {
            name = "Reset",
            dissect_command = function(tree, buf)
                tree:add_le(reset_sensor, buf(0, 1))
                tree:add_le(reset_mcu, buf(0, 1))
                tree:add_le(sleep_time, buf(1, 1))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
                tree:add_le(reset_number, buf(1, 2))
            end
        },
        [2] = {
            name = "MCU Erase App",
            dissect_command = function(tree, buf)
                tree:add_le(sleep_time, buf(1, 1))
            end,
            dissect_reply = function(tree, buf)
            end
        },
        [3] = {
            name = "Read OTP",
            dissect_command = function(tree, buf)
            end,
            dissect_reply = function(tree, buf)
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
        [6] = {
            name = "Set Pov Cfg",
            dissect_command = function(tree, buf)
            end,
            dissect_reply = function(tree, buf)
            end
        },
        [7] = {
            name = "Query MCU State",
            dissect_command = function(tree, buf)
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(mcu_state_image, buf(1, 1))
                tree:add_le(mcu_state_tls, buf(1, 1))
                tree:add_le(mcu_state_spi, buf(1, 1))
                tree:add_le(mcu_state_locked, buf(1, 1))
            end
        }
    },
    [0xB] = {
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
    [0xC] = {
        category_name = "NOTI",

        [2] = {
            name = "Set Drv State",
            dissect_command = function(tree, buf)
            end,
            dissect_reply = function(tree, buf)
            end
        },
        [3] = {
            name = "MCU Set Led State",
            dissect_command = function(tree, buf)
            end,
            dissect_reply = function(tree, buf)
            end
        }

    },
    [0xD] = {
        category_name = "TLSCONN",

        [0] = {
            name = "Request TLS Connection",
            dissect_command = function(tree, buf)
            end
        },
        [1] = {
            name = "Resend Image data? MCU Get Pov Image",
            dissect_command = function(tree, buf)
                -- Seemingly gives the same response over TLS as sending Ima.0 does,
                -- but without reading a new image from the sensor. Not seen used,
                -- untested.
            end,
            dissect_reply = function(tree, buf)
            end
        },
        [2] = {
            name = "TLS Successfully Established",
            dissect_command = function(tree, buf)
            end
        },

        [3] = {
            name = "Pov Image Check",
            dissect_command = function(tree, buf)
            end,
            dissect_reply = function(tree, buf)
            end
        }
    },
    [0xE] = {
        category_name = "PROD",
        [0] = {
            name = "Preset Psk Write R",
            dissect_command = function(tree, buf)
                tree:add_le(psk_flags, buf(0, 4))
                tree:add_le(psk_length, buf(4, 4))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(failed, buf(0, 1))
            end
        },
        [2] = {
            name = "Preset Psk Read R",
            dissect_command = function(tree, buf)
                tree:add_le(psk_flags, buf(0, 4))
                tree:add_le(psk_length, buf(4, 4))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(failed, buf(0, 1))
                tree:add_le(psk_flags, buf(1, 4))
                tree:add_le(psk_length, buf(5, 4))
            end
        }
    },
    [0xF] = {
        category_name = "UPFW",
        [0] = {
            name = "Write Firmware",
            dissect_command = function(tree, buf)
                tree:add_le(firmware_offset, buf(0, 4))
                tree:add_le(firmware_length, buf(4, 4))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
            end
        },
        [1] = {
            name = "Read Firmware",
            dissect_command = function(tree, buf)
                tree:add_le(firmware_offset, buf(0, 4))
                tree:add_le(firmware_length, buf(4, 4))
            end,
            dissect_reply = function(tree, buf)
            end
        },
        [2] = {
            name = "Check Firmware",
            dissect_command = function(tree, buf)
                tree:add_le(firmware_offset, buf(0, 4))
                tree:add_le(firmware_length, buf(4, 4))
                tree:add_le(firmware_checksum, buf(8, 4))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(success, buf(0, 1))
            end
        },
        [3] = {
            name = "Get IAP Version",
            dissect_command = function(tree, buf)
                tree:add_le(read_length, buf(0, 1))
            end,
            dissect_reply = function(tree, buf)
                tree:add_le(version, buf())
            end
        }
    }
}

function protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then
        return
    end

    pinfo.cols.protocol = "Goodix"

    local subtree = tree:add(protocol, buffer(), "Goodix Message Protocol")

    body_buffer = buffer(3, buffer:len() - 4):tvb()

    subtree:add_le(cmd0_field, buffer(0, 1))
    subtree:add_le(cmd1_field, buffer(0, 1))
    local length_bytes = buffer(1, 2)
    subtree:add_le(length_field, length_bytes):append_text(" bytes (including checksum)")
    subtree:add_le(checksum_field, buffer(3 + length_bytes:le_uint() - 1, 1))

    from_host = pinfo.src == Address.ip("1.1.1.1") or tostring(pinfo.src) == "host"

    local cmd_subtree = subtree:add(protocol, body_buffer())

    cmd_val = buffer(0, 1):le_uint()
    cmd0_val, cmd1_val = extract_cmd0_cmd1(cmd_val)

    if from_host then
        summary = "Command: " .. get_cmd_name(cmd_val)

        if commands[cmd0_val][cmd1_val] ~= nil then
            commands[cmd0_val][cmd1_val].dissect_command(cmd_subtree, body_buffer)
        end
    else
        summary = "Reply: " .. get_cmd_name(cmd_val)

        if commands[cmd0_val][cmd1_val] ~= nil then
            commands[cmd0_val][cmd1_val].dissect_reply(cmd_subtree, body_buffer)
        end
    end

    cmd_subtree.text = summary
    pinfo.cols.info = summary
end

DissectorTable.get("tls.port"):add(1, protocol)
DissectorTable.get("tls.port"):add(1, protocol)

DissectorTable.get("usb.protocol"):add_for_decode_as(protocol)
DissectorTable.get("usb.product"):add_for_decode_as(protocol)
DissectorTable.get("usb.device"):add_for_decode_as(protocol)

goodix_pack = Proto("goodix.pack", "Goodix Fingerprint USB Package")
goodix_pack_flags = ProtoField.uint8("goodix.pack.flags", "Flags", base.HEX)
goodix_pack_length = ProtoField.uint16("goodix.pack.length", "Length", base.DEC)
goodix_pack_ckecksum = ProtoField.uint8("goodix.pack.checksum", "Checksum", base.HEX)

function goodix_pack.init()
    state_map = 0
    missing_bytes = 0
    cache = {}
end

goodix_pack.fields = {goodix_pack_flags, goodix_pack_length, goodix_pack_ckecksum}

function goodix_pack.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then
        return
    end

    pinfo.cols.protocol = "Goodix Pack"

    local subtree = tree:add(goodix_pack, buffer(), "Goodix Message Pack")

    local ccache = cache[pinfo.number]

    if ccache == nil then
        if missing_bytes > 0 then
            pinfo.cols.info = string.format("Goodix Pack Reassembly, missing %d bytes", missing_bytes)
            state_map = state_map .. buffer:bytes()
            if buffer:len() < missing_bytes then
                missing_bytes = missing_bytes - buffer:len()
                cache[pinfo.number] = {
                    complete = 0,
                    missing = missing_bytes
                }
                return
            else
                new_buffer = ByteArray.tvb(state_map)(0):tvb("Reassembled TVB")
                cache[pinfo.number] = {
                    complete = 1,
                    content = state_map
                }
                state_map = 0
                missing_bytes = 0
            end
        else
            new_buffer = buffer
            cache[pinfo.number] = {
                complete = 1
            }
        end
    else
        if ccache.complete and ccache.content then
            new_buffer = ByteArray.tvb(ccache.content)(0):tvb("Reassembled TVB")
        else
            new_buffer = buffer
        end
    end

    buffer = new_buffer

    flags_byte = buffer(0, 1)
    subtree:add_le(goodix_pack_flags, flags_byte)
    length_bytes = buffer(1, 2)
    subtree:add_le(goodix_pack_length, length_bytes):append_text(" bytes")
    ckecksum_byte = buffer(3, 1)
    subtree:add_le(goodix_pack_ckecksum, ckecksum_byte)

    local flags_int = flags_byte:le_uint()
    local length_int = length_bytes:le_uint()

    pinfo.cols.info = string.format("Goodix Pack 0x%x %d", flags_int, buffer:len())

    if flags_int == 0xa0 or flags_int == 0xb0 then
        if length_int + 4 > buffer:len() then
            state_map = buffer:bytes()
            missing_bytes = length_int - (buffer:len() - 4)

            pinfo.cols.info = string.format("Goodix Pack Fragment Start 0x%x %d", flags_int, buffer:len())
            return
        end
    elseif ccache.complete == 0 then
        pinfo.cols.info = string.format("Goodix Pack Fragment Continue %d, %d", buffer:len(), ccache.missing)
        return
    end

    if flags_int == 0xa0 then
        body_buffer = buffer(4, length_int):tvb()
        second_dissector = Dissector.get("goodix")
        second_dissector:call(body_buffer, pinfo, subtree)
    elseif flags_int == 0xb0 then
        Dissector.get("tls"):call(buffer(4, length_int):tvb(), pinfo, tree)
    elseif flags_int == 0xb2 then
        Dissector.get("tls"):call(buffer(4 + 9, length_int - 9):tvb(), pinfo, tree)
    else
        body_buffer = buffer(4, buffer:len() - 4):tvb()
        cmd_subtree = subtree:add(goodix_pack, body_buffer())
        pinfo.cols.info = string.format("Goodix Pack Unknown 0x%x", flags_int)

    end

end

usb_table = DissectorTable.get("usb.bulk")

usb_table:add(0xff, goodix_pack)

usb_table:add(0x0a, goodix_pack)
