protocol = Proto("goodix",  "Goodix Fingerprint Sensor Message Protocol")

cmd0_field = ProtoField.uint8("goodix.cmd0", "Cmd0", base.HEX, nil, 0xF0)
cmd1_field = ProtoField.uint8("goodix.cmd1", "Cmd1", base.HEX, nil, 0x0E)
cmd_lsb = ProtoField.bool("goodix.cmd_lsb", "Cmd LSB", 8, nil, 0x01) -- Always false afaik, but dissecting just in case.
len = ProtoField.uint16("goodix.len", "Length", base.DEC)
cksum = ProtoField.uint8("goodix.cksum", "Checksum", base.HEX)

ack_config = ProtoField.bool("goodix.ack_config", "Need Configuration", 2, nil, 0x02)
ack_true = ProtoField.bool("goodix.ack_true", "Always True", 2, nil, 0x01)
ack_cmd = ProtoField.uint8("goodix.ack_cmd", "Acked Command", base.HEX)
firmware_version = ProtoField.string("goodix.firmware_version", "Firmware Version")
enabled = ProtoField.bool("goodix.enabled", "Enabled")

mcu_state_image = ProtoField.bool("goodix.mcu_state.is_image_valid", "Is Image Valid", 8, nil, 0x01) -- Meaning unknown
mcu_state_tls = ProtoField.bool("goodix.mcu_state.is_tls_connected", "Is Tls Connected", 8, nil, 0x02)
mcu_state_spi = ProtoField.bool("goodix.mcu_state.is_spi_send", "Is Spi Send", 8, nil, 0x04) -- Meaning unknown
mcu_state_locked = ProtoField.bool("goodix.mcu_state.is_locked", "Is Locked", 8, nil, 0x08) -- Meaning unknown
mcu_state_sensor_crc32_valid = ProtoField.bool("goodix.mcu_state.sensor_crc32_valid", "Correct CRC32 On The Last Image From The Sensor")

reset_flag_sensor = ProtoField.bool("goodix.reset_flag.sensor", "Reset Sensor", 8, nil, 0x01)
reset_flag_mcu = ProtoField.bool("goodix.reset_flag.mcu", "Soft Reset MCU", 8, nil, 0x02)
reset_flag_sensor_copy = ProtoField.bool("goodix.reset_flag.sensor_copy", "Reset Sensor (copy)", 8, nil, 0x04) -- Driver always sets this at the same time as reset_flag.sensor, firmware ignores this one

sensor_reset_success = ProtoField.bool("goodix.sensor_reset_success", "Sensor Reset Success") -- False if a timeout occours getting a response from the sensor
sensor_reset_number = ProtoField.uint16("goodix.sensor_reset_number", "Sensor Reset Number") -- Contents unknown, but it's a LE short sent if the sensor reset succeeds

reg_multiple = ProtoField.bool("goodix.reg.multiple", "Multiple Addresses") -- Only false is used by driver, no dissection implemented for true
reg_address = ProtoField.uint16("goodix.reg.addr", "Base Address", base.HEX)
reg_len = ProtoField.uint8("goodix.reg.len", "Length")

psk_address  = ProtoField.uint32("goodix.psk_address", "PSK Address")
psk_length  = ProtoField.uint32("goodix.psk_length", "PSK Lenght")

firmware_offset  = ProtoField.uint32("goodix.firmware_offset", "Firmware Offset")
firmware_lenght  = ProtoField.uint32("goodix.firmware_lenght", "Firmware Lenght")
firmware_checksum  = ProtoField.uint32("goodix.firmware_checksum", "Firmware Checksum")

pwrdown_scan_freq = ProtoField.uint16("goodix.powerdown_scan_frequency", "Powerdown Scan Frequecy")

config_sensor_chip = ProtoField.uint8("goodix.config_sensor_chip", "Sensor Chip", base.RANGE_STRING, {
                                         {0, 0, "GF3208"},
                                         {1, 1, "GF3288"},
                                         {2, 2, "GF3266"},
}, 0xF0)

protocol.fields = {
   pack_flags, cmd0_field, cmd1_field, cmd_lsb, len, cksum,
   ack_cmd, ack_true, ack_config,
   firmware_version,
   enabled,
   mcu_state_image, mcu_state_tls, mcu_state_spi, mcu_state_locked, mcu_state_sensor_crc32_valid,
   reset_flag_sensor, reset_flag_mcu, reset_flag_sensor_copy,
   sensor_reset_success, sensor_reset_number,
   reg_multiple, reg_address, reg_len,
   pwrdown_scan_freq,
   config_sensor_chip,
   psk_address, psk_length,
   firmware_offset, firmware_lenght, firmware_checksum,
}

function extract_cmd0_cmd1(cmd)
   return bit.rshift(cmd, 4), bit.rshift(cmd%16, 1)
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
            -- This packet has a fixed, non-standard checksum of 0x88
            -- Its purpose is unknown -- REd firmware does nothing when it recieves one.
         end,
      }
   },
   [0x2] = {
      category_name = "IMA",

      [0] = {
         name = "MCU Get Image",
         dissect_command = function(tree, buf)  end,
         dissect_reply = function(tree, buf)  end,
      }

   },
   [0x3] = {
      category_name = "FDT",

      [1] = {
         name = "MCU Switch To Fdt Down",
         dissect_command = function(tree, buf)  end,
         dissect_reply = function(tree, buf)  end,
      },
      [2] = {
         name = "MCU Switch To Fdt Up",
         dissect_command = function(tree, buf)  end,
         dissect_reply = function(tree, buf)  end,
      },
      [3] = {
         name = "MCU Switch To Fdt Mode",
         dissect_command = function(tree, buf)  end,
         dissect_reply = function(tree, buf)  end,
      }
   },
   [0x4] = {
      category_name = "FF",
   },
   [0x5] = {
      category_name = "NAV",
   },
   [0x6] = {
      category_name = "SLE",
      [0] = {
         name = "MCU Switch To Sleep Mode",
         dissect_command = function(tree, buf)  end,
         dissect_reply = function(tree, buf)  end,
      }
   },
   [0x7] = {
      category_name = "IDL",

      [0] = {
         name = "MCU Switch To Idle Mode",
         dissect_command = function(tree, buf)  end,
         dissect_reply = function(tree, buf)  end,
      }
   },
   [0x8] = {
      category_name = "REG",
      [1] = {
         name = "Read Sensor Register",
         dissect_command = function(tree, buf)
            tree:add_le(reg_multiple, buf(0, 1))
            tree:add_le(reg_address, buf(1, 2))
            tree:add_le(reg_len, buf(3, 1)):append_text(" bytes")
         end,
         dissect_reply = function(tree, buf)
            -- Reply is just the bytes requested
         end,
      },
   },
   [0x9] = {
      category_name = "CHIP",
      -- Operations on the sensor chip (not the MCU)

      [0] = {
         name = "Upload Config MCU Download Chip Config",
         dissect_command = function(tree, buf)
            tree:add_le(config_sensor_chip, buf(0, 1))
         end,
         dissect_reply = function(tree, buf)
         end,
      },
      [2] = {
         name = "Set Powerdown Scan Frequency",
         dissect_command = function(tree, buf)
            -- I believe this is for a feature (POV/persistance of vision) where the sensor continues scanning while the laptop is asleep, and sends it to the laptop once it wakes up
            tree:add_le(pwrdown_scan_freq, buf(0, 2)) -- Units unknown, though mine is 100, so ms would make sense?
         end,
         dissect_reply = function(tree, buf)
            -- TODO check
         end,
      },
      [3] = {
         name = "Enable Chip",
         dissect_command = function(tree, buf)
            tree:add_le(enabled, buf(0, 1))
         end,
      },
   },
   [0xA] = {
      category_name = "OTHER",

      [1] = {
         name = "Reset",
         dissect_command = function(tree, buf)
            tree:add_le(reset_flag_sensor, buf(0, 1))
            tree:add_le(reset_flag_mcu, buf(0, 1))
            tree:add_le(reset_flag_sensor_copy, buf(0, 1))
         end,
         dissect_reply = function(tree, buf)
            tree:add_le(sensor_reset_success, buf(0, 1))
            tree:add_le(sensor_reset_number, buf(1, 2))
         end,
      },
      [2] = {
         name = "MCU Erase App",
         dissect_command = function(tree, buf)  end,
         dissect_reply = function(tree, buf)  end,
      },
      [3] = {
         name = "Read OTP",
         -- I believe OTP refers to one-time-programmable memory, which is written with calibration values at the factory
         dissect_command = function(tree, buf)
            -- Request is empty
         end,
         dissect_reply = function(tree, buf)
            -- The OTP (32 bytes for my sensor model, I believe it differs with others)
         end,

      },
      [4] = {
         name = "Firmware Version",
         dissect_command = function(tree, buf)
         end,
         dissect_reply = function(tree, buf)
            tree:add_le(firmware_version, buf())
         end,
      },
      [6] = {
         name = "Set Pov Cfg",
         dissect_command = function(tree, buf)  end,
         dissect_reply = function(tree, buf)  end,
      },
      [7] = {
         name = "Query MCU State",
         dissect_command = function(tree, buf)
            -- TODO what's the the 0x55
         end,
         dissect_reply = function(tree, buf)
            tree:add_le(mcu_state_image, buf(0, 1))
            tree:add_le(mcu_state_tls, buf(0, 1))
            tree:add_le(mcu_state_spi, buf(0, 1))
            tree:add_le(mcu_state_locked, buf(0, 1))
            -- tree:add_le(mcu_state_sensor_crc32_valid, buf(3, 1))
         end,
      },
   },
   [0xB] = {
      category_name = "MSG",

      [0] = {
         name = "Ack",
         dissect_reply = function(tree, buf)
            tree:add_le(ack_true, buf(1, 1))
            tree:add_le(ack_config, buf(1, 1)) -- commands 0-5 (inclusive) are ignored if this is true.
            tree:add_le(ack_cmd, buf(0, 1)):append_text(" (" .. get_cmd_name(buf(0,1):le_uint()) .. ")")
         end,
      },
   },
   [0xC] = {
      category_name = "NOTI",

      [2] = {
         name = "Set Drv State",
         dissect_command = function(tree, buf)  end,
         dissect_reply = function(tree, buf)  end,
      },
      [3] = {
         name = "MCU Set Led State",
         dissect_command = function(tree, buf)  end,
         dissect_reply = function(tree, buf)  end,
      }

   },
   [0xD] = {
      category_name = "TLSCONN",

      [0] = {
         name = "Request TLS Connection",
         dissect_command = function(tree, buf)
            -- No args.
            -- MCU doesn't do a normal reply (except the ack), but it triggers it to send a TLS Client Hello as a V2 encrypted packet

            -- Until sending "TLS Successfully Established", any messages other than TLSCONN.* and "Query MCU State" are ignored.
         end,
      },
      [1] = {
         name = "Resend Image data? MCU Get Pov Image",
         dissect_command = function(tree, buf)
            -- Seemingly gives the same response over TLS as sending Ima.0 does,
            -- but without reading a new image from the sensor. Not seen used,
            -- untested.
         end,
         dissect_reply = function(tree, buf)  end,
      },
      [2] = {
         name = "TLS Successfully Established",
         dissect_command = function(tree, buf)
            -- No args, no reply.
         end,
      },

      [3] = {
         name = "Pov Image Check",
         dissect_command = function(tree, buf)  end,
         dissect_reply = function(tree, buf)  end,
      },
   },
   [0xE] = {
      category_name = "PROD",
      [0] = {
         name = "Preset Psk Write R",
         dissect_command = function(tree, buf)
            tree:add_le(psk_address, buf(0, 4))
            tree:add_le(psk_length, buf(4, 4))
         end,
         dissect_reply = function(tree, buf)  end,
      },
      [2] = {
         name = "Preset Psk Read R",
         dissect_command = function(tree, buf)
            tree:add_le(psk_address, buf(0, 4))
            tree:add_le(psk_length, buf(4, 4))
         end,
         dissect_reply = function(tree, buf)
            tree:add_le(psk_address, buf(1, 4))
            tree:add_le(psk_length, buf(5, 4))
         end,
      }
   },
   [0xF] = {
      category_name = "UPFW",
      [0] = {
         name = "Update Firmware",
         dissect_command = function(tree, buf)
            tree:add_le(firmware_offset, buf(0, 4))
            tree:add_le(firmware_lenght, buf(4, 4))
         end,
         dissect_reply = function(tree, buf)  end,
      },
      [1] = {
         name = "Read Firmware",
         dissect_command = function(tree, buf)
            tree:add_le(firmware_offset, buf(0, 4))
            tree:add_le(firmware_lenght, buf(4, 4))
         end,
         dissect_reply = function(tree, buf)  end,
      },
      [2] = {
         name = "Check Firmware",
         dissect_command = function(tree, buf)
            tree:add_le(firmware_offset, buf(0, 4))
            tree:add_le(firmware_lenght, buf(4, 4))
            tree:add_le(firmware_checksum, buf(8, 4))
         end,
         dissect_reply = function(tree, buf)  end,
      },
      [3] = {
         name = "Get IAP Version",
         dissect_command = function(tree, buf)  end,
         dissect_reply = function(tree, buf)  end,
      }
   }
}



function protocol.dissector(buffer, pinfo, tree)
   length = buffer:len()
   if length == 0 then return end

   pinfo.cols.protocol = "Goodix"

   local subtree = tree:add(protocol, buffer(), "Goodix Message Protocol")

   body_buf = buffer(3, buffer:len()-4):tvb()

   subtree:add_le(cmd0_field, buffer(0,1))
   subtree:add_le(cmd1_field, buffer(0,1))
   subtree:add_le(cmd_lsb, buffer(0,1))
   local lenb = buffer(1,2)
   subtree:add_le(len, lenb):append_text(" bytes (including checksum)")
   subtree:add_le(cksum, buffer(3+lenb:le_uint()-1,1))

   from_host = pinfo.src == Address.ip("1.1.1.1") or tostring(pinfo.src) == "host"


   local cmd_subtree = subtree:add(protocol, body_buf())

   cmd_val = buffer(0, 1):le_uint()
   cmd0_val, cmd1_val = extract_cmd0_cmd1(cmd_val)

   if from_host then
      summary = "Command: " .. get_cmd_name(cmd_val)

      if commands[cmd0_val][cmd1_val] ~= nil then
         commands[cmd0_val][cmd1_val].dissect_command(cmd_subtree, body_buf)
      end
   else
      summary = "Reply: " .. get_cmd_name(cmd_val)

      if commands[cmd0_val][cmd1_val] ~= nil then
         commands[cmd0_val][cmd1_val].dissect_reply(cmd_subtree, body_buf)
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





goodixpack = Proto("GoodixPack",  "Goodix Fingerprint USB Package")
gpack_flags = ProtoField.uint8("goodixpack.flags", "Flags", base.HEX)
gpack_len = ProtoField.uint16("goodixpack.len", "Length", base.DEC)
gpack_cksum = ProtoField.uint8("goodixpack.chsum", "Checksum", base.HEX)
-- gpack_cmd = ProtoField.bytes("goodixpack.cmd", "Command", base.HEX)



-- fragmentation is annoying USB does not support reassembly. https://stackoverflow.com/questions/38630416/wireshark-lua-dissector-reassembly-dissector-not-called-with-previous-tvbs-da
function goodixpack.init()
    stateMap = 0 -- actually, Bytes()
    missing_bytes = 0
    cache = {} -- cache reassembly results
end

goodixpack.fields = {
   gpack_flags, gpack_len, gpack_cksum
}
-- local pack_table = DissectorTable.new("goodixpack", "goodixpack", ftypes.UINT32, base.DEC, p_parent)

function goodixpack.dissector(buffer, pinfo, tree)
   length = buffer:len()
   if length == 0 then return end

   pinfo.cols.protocol = "GPack"

   local subtree = tree:add(goodixpack, buffer(), "Goodix Message Pack")

   -- see if we have seen this packet before. only run reassembly when we have not.
   local ccache = cache[pinfo.number]

   -- first time we see the package, fill cache
   if ccache == nil then
      if missing_bytes > 0 then
         -- if we are currenyly in reassembly, packets do not have header!
         pinfo.cols.info = string.format("Goodix Pack Reassembly, missing %d bytes", missing_bytes)
         stateMap = stateMap .. buffer:bytes()
         if buffer:len() < missing_bytes then
            -- we are still missing bytes
            missing_bytes = missing_bytes - buffer:len()
            cache[pinfo.number] = {complete=0, missing=missing_bytes} -- 1
            return
         else
            -- we now have enough bytes. reassemble buffer.
            newbuf = ByteArray.tvb(stateMap)(0):tvb("reassembled tvb")
            cache[pinfo.number] = {complete=1, content=stateMap}
            stateMap = 0
            missing_bytes = 0
         end
      else
         newbuf = buffer
         cache[pinfo.number] = {complete=1}
      end
   else
      -- we have seen package before, load ccache.

      if ccache.complete and ccache.content then
         -- last packet in chain, with content set. set buffer accordingly.
         newbuf = ByteArray.tvb(ccache.content)(0):tvb("reassembled tvb")
      else
         -- not last packet, keep buffer as is
         newbuf = buffer
      end
   end

   buffer = newbuf

   flagsb = buffer(0,1)
   subtree:add_le(gpack_flags, flagsb)
   lenb = buffer(1,2)
   subtree:add_le(gpack_len, lenb):append_text(" bytes")
   cksumb = buffer(3,1)
   subtree:add_le(gpack_cksum, cksumb):append_text(" *untested, sum of other three bytes*")

   -- local cmd_subtree = subtree:add(goodixpack, body_buf())

   local flagsint = flagsb:le_uint()
   local lenint = lenb:le_uint()

   -- set info before subdisector, so it can overwrite if it wants to
   -- the missing_bytes output will only make sense on first run! afterwards cached results throw it off.
   pinfo.cols.info = string.format("Goodix Pack 0x%x %d, %d", flagsint, buffer:len(), 0)

   -- reassemble packets only for a0 and b0, as they contain length.
   if flagsint == 0xa0 or flagsint == 0xb0 then
      -- test if the command fits in our current buffer
      if lenint + 4 > buffer:len() then
         -- it does not fit. save current buffer, remember how many bytes are missing.
         stateMap = buffer:bytes()
         missing_bytes = lenint - (buffer:len() - 4)

         -- return early
         pinfo.cols.info = string.format("Goodix Pack Fragment Start 0x%x %d", flagsint, buffer:len())
         return
      end
   elseif ccache.complete == 0 then
         -- fragment continues, return early
         pinfo.cols.info = string.format("Goodix Pack Fragment Continue 0x%x %d, %d, %d", flagsint, buffer:len(), ccache.complete, ccache.missing)
         return
   end

   -- if we reach this point, reassembly is done.
   -- guaranteed to have header + enough data in buffer.

   if flagsint == 0xa0 then
         body_buf = buffer(4, lenint):tvb()
         second_dissector = Dissector.get("goodix")
         -- pktinfo.private.the_value = 42
         second_dissector:call(body_buf, pinfo, subtree)
      --else
         --body_buf = buffer(4, buffer:len() - 4):tvb()
         --cmd_subtree = subtree:add(goodixpack, body_buf())
         --cmd_subtree.text = "WARNING: split packet not handled"
      --   pinfo.cols.info = string.format("GoodixPack 0x%x SPLIT", flagsint)
      --end
   elseif flagsint == 0xb0 then
      Dissector.get("tls"):call(buffer(4, lenint):tvb(), pinfo, tree)
   elseif flagsint == 0xb2 then
      Dissector.get("tls"):call(buffer(4+9, lenint-9):tvb(), pinfo, tree)
   else
      -- unknown protocol
      body_buf = buffer(4, buffer:len() - 4):tvb()
      cmd_subtree = subtree:add(goodixpack, body_buf())
      pinfo.cols.info = string.format("Goodix Pack UNKNOWN 0x%x %s", flagsint, ccache.state)

   end

end

usb_table = DissectorTable.get("usb.bulk")
-- this is the vendor specific class, which is how the usb.bulk table is arranged.
usb_table:add(0xff, goodixpack)

-- for whatever reason :5110 uses 0x0a as device class oO
usb_table:add(0x0a, goodixpack)
