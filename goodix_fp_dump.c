/*
 * goodix_fp_dump - dump data from the Goodix HTK32 fingerprint reader
 *
 * Copyright 2019, Collabora Ltd
 * Author: Antonio Ospite <antonio.ospite@collabora.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <libusb-1.0/libusb.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define debug(...) fprintf(stderr, __VA_ARGS__)
#define error(...) fprintf(stderr, __VA_ARGS__)
#define warning(...) fprintf(stderr, __VA_ARGS__)

struct goodix_fp_usb_device_descriptor
{
	uint16_t vendor_id;
	uint16_t product_id;
	uint8_t configuration;
	uint8_t output_endpoint;
	uint8_t input_endpoint;
};

static const struct goodix_fp_usb_device_descriptor supported_devices[] = {
	{
		/* found on ASUS ZenBook S UX391FA AH001T */
		.vendor_id = 0x27c6,
		.product_id = 0x5201,
		.configuration = 1,
		.output_endpoint = 0x03,
		.input_endpoint = 0x81,
	},
	{
		/* found on Dell XPS 13 9370/9380 */
		.vendor_id = 0x27c6,
		.product_id = 0x5385,
		.configuration = 1,
		.output_endpoint = 0x03,
		.input_endpoint = 0x81,
	},
	{
		/* found on Dell XPS 13 9570 */
		.vendor_id = 0x27c6,
		.product_id = 0x5395,
		.configuration = 1,
		.output_endpoint = 0x03,
		.input_endpoint = 0x81,
	},
	{
		/* found on Teclast F6 Pro */
		.vendor_id = 0x27c6,
		.product_id = 0x5740,
		.configuration = 1,
		.output_endpoint = 0x03,
		.input_endpoint = 0x81,
	},
	{
		/* found on Lenovo Yoga 730 13IWL-81JR */
		.vendor_id = 0x27c6,
		.product_id = 0x5584,
		.configuration = 1,
		.output_endpoint = 0x01,
		.input_endpoint = 0x82,
	},
	{
		/* found on Lenovo Flex 81SS */
		.vendor_id = 0x27c6,
		.product_id = 0x55b4,
		.configuration = 1,
		.output_endpoint = 0x01,
		.input_endpoint = 0x82,
	},
	{
		/* found on Dell G3 3579, Dell G3 3779, and Dell Inspiron 7577 */
		.vendor_id = 0x27c6,
		.product_id = 0x5301,
		.configuration = 1,
		.output_endpoint = 0x03,
		.input_endpoint = 0x81,
	},
	{
		/* found on Dell G5 (2019) */
		.vendor_id = 0x27c6,
		.product_id = 0x530c,
		.configuration = 1,
		.output_endpoint = 0x01,
		.input_endpoint = 0x83,
	},
	{
		/* found on HUAWEI MateBook D 15 AMD */
		.vendor_id = 0x27c6,
		.product_id = 0x5110,
		.configuration = 1,
		.output_endpoint = 0x01,
		.input_endpoint = 0x81,
	},

};

struct _goodix_fp_device
{
	libusb_device_handle *usb_device;
	const struct goodix_fp_usb_device_descriptor *desc;
};

typedef struct _goodix_fp_device goodix_fp_device;

/*
 * The device expects numeric values as little-endian.
 *
 * XXX Proper endianness conversion is needed if the code is run on big-endian systems.
 */
typedef union
{
	uint8_t data[64];
	struct __attribute__((packed))
	{
		uint8_t type;
		uint16_t payload_size;
		uint8_t payload[61];
	} fields;
	struct
	{
		uint8_t type;
		uint8_t payload[63];
	} continuation;
} goodix_fp_out_packet;

typedef union
{
	uint8_t data[32768];
	struct __attribute__((packed))
	{
		uint8_t type;
		uint16_t payload_size;
		uint8_t payload[32765];
	} fields;
	struct __attribute__((packed))
	{
		uint8_t type;
		uint16_t payload_size;
		uint8_t reply_to;
		uint8_t status;
		uint8_t checksum;
	} reply_packet;
} goodix_fp_in_packet;

typedef enum
{
	GOODIX_FP_PACKET_TYPE_REPLY = 0xb0,
	GOODIX_FP_PACKET_TYPE_FIRMWARE_VERSION = 0xa8,
	GOODIX_FP_PACKET_TYPE_RESET = 0xa2,
	GOODIX_FP_PACKET_TYPE_CHIP_REG_READ = 0x82,
	GOODIX_FP_PACKET_TYPE_OTP = 0xa6,
	GOODIX_FP_PACKET_TYPE_HANDSHAKE = 0xd2,
	GOODIX_FP_PACKET_TYPE_PSK = 0xe4,
	GOODIX_FP_PACKET_TYPE_CONFIG = 0x90,
} goodix_fp_packet_type;

static void debug_dump_buffer(const char *message, uint8_t *buffer, int len)
{
	int i;

	if (buffer == NULL || len <= 0)
	{
		debug("Invalid or empty buffer\n");
		return;
	}

	debug("\n");
	if (message)
		debug("%s\n", message);

	for (i = 0; i < len; i++)
	{
		debug("%02hhX%c", buffer[i], (((i + 1) % 16) && (i < len - 1)) ? ' ' : '\n');
	}
	debug("\n");
}

static void debug_dump_buffer_to_file(const char *filename, uint8_t *buffer, int len)
{
	FILE *fp;

	if (buffer == NULL || len <= 0)
		return;

	fp = fopen(filename, "wb");
	if (fp == NULL)
	{
		perror(filename);
		return;
	}

	fwrite(buffer, 1, len, fp);
	fclose(fp);
}

#ifdef TRACE
#define trace debug
#define trace_dump_buffer debug_dump_buffer

static void trace_out_packet(goodix_fp_out_packet *packet)
{
	trace("\n");
	trace("out packet\n");
	trace("type: 0x%02hhx %d\n", packet->fields.type, packet->fields.type);
	if (packet->fields.type % 2)
		trace("continuation packet\n");
	else
		trace("size: 0x%02hx %d\n", packet->fields.payload_size, packet->fields.payload_size);
}

static void trace_in_packet(goodix_fp_in_packet *packet)
{
	trace("in packet\n");
	trace("type: 0x%02hhx %d\n", packet->fields.type, packet->fields.type);
	trace("size: 0x%02hx %d\n", packet->fields.payload_size, packet->fields.payload_size);
	trace("\n");
}
#else
#define trace(...) \
	do             \
	{              \
	} while (0)
static void trace_dump_buffer(const char *message, uint8_t *buffer, int len)
{
	(void)message;
	(void)buffer;
	(void)len;
}

static void trace_out_packet(goodix_fp_out_packet *packet)
{
	(void)packet;
}
static void trace_in_packet(goodix_fp_in_packet *packet)
{
	(void)packet;
}
#endif

static int usb_send_data(libusb_device_handle *dev, uint8_t endpoint,
						 uint8_t *buffer, int len)
{
	int ret;
	int transferred;

	trace_dump_buffer("sending -->", buffer, len);

	transferred = 0;
	ret = libusb_bulk_transfer(dev, endpoint, buffer, len, &transferred, 0);
	if (ret != 0 || transferred != len)
	{
		error("%s. Transferred: %d (expected %u)\n",
			  libusb_error_name(ret), transferred, len);
		return ret;
	}

	return 0;
}

static int usb_read_data(libusb_device_handle *dev, uint8_t endpoint,
						 uint8_t *buffer, int len)
{
	int ret;
	int transferred;

	transferred = 0;
	debug("###########################################################\n");
	ret = libusb_bulk_transfer(dev, endpoint, buffer, len, &transferred, 0);
	debug("###########################################################\n");
	if (ret != 0)
	{
		error("%s. Transferred: %d (expected %u)\n",
			  libusb_error_name(ret), transferred, len);
		return ret;
	}

	debug("len: %d, transferred: %d\n", len, transferred);

	trace_dump_buffer("<-- received", buffer, transferred);

	return transferred;
}

static int usb_claim_interfaces(libusb_device_handle *dev, int configuration)
{
	libusb_device *usb_device;
	struct libusb_config_descriptor *config_desc;
	int num_interfaces;
	int ret;
	int i;

	usb_device = libusb_get_device(dev);
	if (usb_device == NULL)
		return -ENODEV;

	ret = libusb_get_config_descriptor_by_value(usb_device, configuration, &config_desc);
	if (ret < 0)
		goto out;

	num_interfaces = config_desc->bNumInterfaces;
	libusb_free_config_descriptor(config_desc);

	for (i = 0; i < num_interfaces; i++)
	{
		ret = libusb_claim_interface(dev, i);
		if (ret < 0)
		{
			fprintf(stderr, "libusb_claim_interface failed: %s\n",
					libusb_error_name(ret));
			fprintf(stderr, "Cannot claim interface %d\n", i);
			goto release_claimed_interfaces;
		}
	}

	return 0;

release_claimed_interfaces:
	while (--i >= 0)
	{
		int release_ret = libusb_release_interface(dev, i);
		if (release_ret < 0)
		{
			fprintf(stderr, "libusb_release_interface failed: %s\n",
					libusb_error_name(release_ret));
			fprintf(stderr, "Warning: could not release interface: %d\n", i);
			/* move on and try releasing the remaining interfaces */
		}
	}

out:
	return ret;
}

static int usb_release_interfaces(libusb_device_handle *dev, int configuration)
{
	libusb_device *usb_device;
	struct libusb_config_descriptor *config_desc;
	int ret;
	int i;

	usb_device = libusb_get_device(dev);
	if (usb_device == NULL)
		return -ENODEV;

	ret = libusb_get_config_descriptor_by_value(usb_device, configuration, &config_desc);
	if (ret < 0)
		goto out;

	for (i = 0; i < config_desc->bNumInterfaces; i++)
	{
		ret = libusb_release_interface(dev, i);
		if (ret < 0)
		{
			fprintf(stderr, "libusb_release_interface failed: %s\n",
					libusb_error_name(ret));
			fprintf(stderr, "Warning: could not release interface: %d\n", i);
			/* move on and try releasing the remaining interfaces */
		}
	}

	libusb_free_config_descriptor(config_desc);
out:
	return ret;
}

/*
 * Long payloads have some bytes on the 64 bytes boundary of the packet which
 * have to be skipped when copying data.
 */
static int extract_payload(goodix_fp_in_packet packet, uint8_t *response, uint8_t *checksum)
{
	uint8_t *src;
	uint8_t *dst;
	int chunk_size;
	int remaining;
	unsigned int continuation_packets;

	if (packet.fields.payload_size == 0)
	{
		error("Invalid payload size, it cannot be 0\n");
		return -1;
	}

	/* first chunk */
	continuation_packets = 0;
	src = packet.fields.payload;
	dst = response;
	remaining = packet.fields.payload_size - 1; /* skip checksum byte */

	/* the first chunk can also be the last one */
	if (remaining < 64 - 3)
		goto last_chunk;

	/* first of multiple chunks */
	chunk_size = 64 - 3;
	memcpy(dst, src, chunk_size);
	src += chunk_size + 1; /* skip the next continuation byte */
	dst += chunk_size;
	remaining -= chunk_size;

	/* copy most of the data, skipping the continuation bytes */
	chunk_size = 64 - 1;
	while (remaining >= chunk_size)
	{
		continuation_packets++;
		memcpy(dst, src, chunk_size);
		src += chunk_size + 1; /* skip the next continuation byte */
		dst += chunk_size;
		remaining -= chunk_size;
	}

	/* copy the last chunk */
	continuation_packets++;
last_chunk:
	memcpy(dst, src, remaining);

	*checksum = packet.fields.payload[packet.fields.payload_size - 1 + continuation_packets];
	return 0;
}

static uint8_t calc_checksum(uint8_t packet_type, uint8_t *payload, uint16_t payload_size)
{
	unsigned int i;
	uint8_t sum;

	sum = packet_type;
	sum += (payload_size + 1) & 0xff;
	sum += (payload_size + 1) >> 8;
	for (i = 0; i < payload_size; i++)
		sum += payload[i];

	return (uint8_t)(0xaa - sum);
}

static int send_payload(goodix_fp_device *dev,
						goodix_fp_packet_type packet_type,
						uint8_t *request, uint16_t request_size)
{
	int ret;
	uint8_t *src;
	uint8_t *dst;
	int remaining;
	int chunk_size;
	uint8_t checksum;
	goodix_fp_out_packet packet = {
		.data = {0}};

	checksum = calc_checksum(packet_type, request, request_size);

	/* first packet */
	packet.fields.type = packet_type;
	packet.fields.payload_size = request_size + 1; /* extra checkum byte */

	src = request;
	dst = packet.fields.payload;
	remaining = request_size;

	/* the first packet can also be the last one */
	if (remaining < 64 - 3)
	{
		packet.fields.payload[remaining] = checksum;
		goto send_last_packet;
	}

	/* first of multiple packets */
	chunk_size = 64 - 3;
	memcpy(dst, src, chunk_size);

	trace_out_packet(&packet);
	ret = usb_send_data(dev->usb_device, dev->desc->output_endpoint,
						packet.data, sizeof(packet.data));
	if (ret < 0)
		goto out;

	remaining -= chunk_size;
	src += chunk_size;

	/* continuation packets */
	packet.continuation.type = packet_type + 1;

	dst = packet.continuation.payload;
	chunk_size = 64 - 1;
	while (remaining >= chunk_size)
	{
		memcpy(dst, src, chunk_size);

		trace_out_packet(&packet);
		ret = usb_send_data(dev->usb_device, dev->desc->output_endpoint,
							packet.data, sizeof(packet.data));
		if (ret < 0)
			goto out;

		src += chunk_size;
		remaining -= chunk_size;
	}

	/* last continuation packet */
	packet.continuation.payload[remaining] = checksum;

send_last_packet:
	memcpy(dst, src, remaining);

	trace_out_packet(&packet);
	ret = usb_send_data(dev->usb_device, dev->desc->output_endpoint,
						packet.data, sizeof(packet.data));
	if (ret < 0)
		goto out;

out:

	return ret;
}

static int send_packet_full(goodix_fp_device *dev,
							goodix_fp_packet_type packet_type,
							uint8_t *request, uint16_t request_size,
							uint8_t *response, uint16_t *response_size,
							bool verify_data_checksum)
{
	goodix_fp_out_packet packet = {
		.fields = {
			.type = packet_type,
			/* the extra byte is for the checkum */
			.payload_size = request_size + 1,
			.payload = {0}}};
	goodix_fp_in_packet reply = {
		.data = {0}};
	int ret;
	uint8_t response_checksum;
	uint8_t expected_checksum;

	ret = send_payload(dev, packet_type, request, request_size);
	if (ret < 0)
		goto out;

	ret = usb_read_data(dev->usb_device, dev->desc->input_endpoint,
						reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != GOODIX_FP_PACKET_TYPE_REPLY)
	{
		error("Invalid reply to packet %02x\n", packet.fields.type);
		ret = -1;
		goto out;
	}

	response_checksum = reply.fields.payload[reply.fields.payload_size - 1];
	expected_checksum = calc_checksum(reply.fields.type,
									  reply.fields.payload,
									  reply.fields.payload_size - 1);

	if (response_checksum != expected_checksum)
	{
		error("Invalid checksum for reply packet %02x\n", packet.fields.type);
		ret = -1;
		goto out;
	}

	if (reply.reply_packet.reply_to != packet.fields.type)
	{
		error("Unexpected reply to packet %02x (got %02x)\n", packet.fields.type, reply.reply_packet.reply_to);
		ret = -1;
		goto out;
	}

	if (reply.reply_packet.status != 0x1)
		warning("Unexpected status for packet %02x (expected 0x01, got 0x%02x)\n", packet.fields.type, reply.reply_packet.status);

	if (response)
	{
		ret = usb_read_data(dev->usb_device, dev->desc->input_endpoint,
							reply.data, sizeof(reply.data));
		if (ret < 0)
			goto out;

		trace_in_packet(&reply);

		if (reply.fields.type != packet_type)
		{
			error("Invalid input packet %02x (got: %02x)\n", packet_type, reply.fields.type);
			ret = -1;
			goto out;
		}

		/* extract the payload, it may contain continuation bytes */
		ret = extract_payload(reply, response, &response_checksum);
		if (ret < 0)
			goto out;

		if (verify_data_checksum)
		{
			expected_checksum = calc_checksum(reply.fields.type,
											  response,
											  reply.fields.payload_size - 1);
		}
		else
		{
			expected_checksum = 0x88;
		}

		if (response_checksum != expected_checksum)
		{
			error("Invalid checksum for input packet %02x\n", reply.fields.type);
			ret = -1;
			goto out;
		}

		*response_size = reply.fields.payload_size - 1;
	}

	ret = 0;

out:
	return ret;
}

/* Usually packets do not need to change the verify_data_checksum parameter. */
static int send_packet(goodix_fp_device *dev,
					   goodix_fp_packet_type packet_type,
					   uint8_t *request, uint16_t request_size,
					   uint8_t *response, uint16_t *response_size)
{
	return send_packet_full(dev, packet_type, request, request_size, response, response_size, true);
}

/* Simple packets are those without a particular request buffer. */
static int send_packet_simple(goodix_fp_device *dev,
							  goodix_fp_packet_type packet_type,
							  uint8_t *response, uint16_t *response_size)
{
	uint8_t payload[2] = {0};

	return send_packet(dev, packet_type, payload, sizeof(payload), response, response_size);
}

static int get_msg_00_change_mode_start(goodix_fp_device *dev)
{
	uint8_t payload[2] = {0};

	return send_packet(dev, 0x00, payload, sizeof(payload), NULL, NULL);
}

static int get_msg_a8_firmware_version(goodix_fp_device *dev)
{
	int ret;
	char firmware_version[64] = "";
	uint16_t string_len;

	ret = send_packet_simple(dev, GOODIX_FP_PACKET_TYPE_FIRMWARE_VERSION,
							 (uint8_t *)firmware_version, &string_len);
	if (ret < 0)
		goto out;

	printf("Firmware version: %s\n", firmware_version);
out:
	return ret;
}

static int get_msg_a2_reset(goodix_fp_device *dev)
{
	int ret;
	uint8_t payload[2] = {0x05, 0x14};
	uint8_t response[32768] = {0};
	uint16_t response_size = 0;

	ret = send_packet(dev, GOODIX_FP_PACKET_TYPE_RESET,
					  payload, sizeof(payload),
					  response, &response_size);
	if (ret < 0)
		goto out;

	debug_dump_buffer("0xa2 response: ", response, response_size);

out:
	return ret;
}

static void swap_each_2_bytes(uint8_t *buffer, uint16_t len)
{
	unsigned int i;
	uint8_t tmp;

	if (len < 2)
		return;

	for (i = 0; i < len; i += 2)
	{
		tmp = buffer[i];
		buffer[i] = buffer[i + 1];
		buffer[i + 1] = tmp;
	}
}

static int get_msg_82_chip_reg_read(goodix_fp_device *dev, uint16_t reg_start, uint16_t reg_size, uint8_t *response, uint16_t *response_size)
{
	int ret;
	uint8_t chip_reg_read_payload[4] = {0};

	/* The first two bytes are the register start position as big-endian. */
	chip_reg_read_payload[0] = (reg_start >> 8) & 0xff;
	chip_reg_read_payload[1] = reg_start & 0xff;

	/* The remaining two bytes are the result size as big-endian. */
	chip_reg_read_payload[2] = (reg_size >> 8) & 0xff;
	chip_reg_read_payload[3] = reg_size & 0xff;

	debug_dump_buffer("0x82 payload: ", chip_reg_read_payload, sizeof(chip_reg_read_payload));

	ret = send_packet(dev, GOODIX_FP_PACKET_TYPE_CHIP_REG_READ, chip_reg_read_payload, sizeof(chip_reg_read_payload), response, response_size);
	if (ret < 0)
		goto out;

	if (reg_size != *response_size)
	{
		ret = -EINVAL;
		error("Unexpected response size (expected: %d, got: %d)", reg_size, *response_size);
		goto out;
	}

	debug_dump_buffer("0x82 response: ", response, *response_size);

	/*
	 * Swap each 2 bytes because the response seems to be in some
	 * mixed-endian order.
	 */
	swap_each_2_bytes(response, *response_size);

out:
	return ret;
}

static int get_msg_82_chip_reg_read_chip_id(goodix_fp_device *dev, uint32_t *chip_id)
{
	int ret;
	uint8_t response[32768] = {0};
	uint16_t response_size = 0;

	ret = get_msg_82_chip_reg_read(dev, 0, 4, response, &response_size);
	if (ret < 0)
		goto out;

	/* After swapping every 2 bytes, values are now in little-endian order */
	/* XXX Proper endianness conversion is needed if the code is run on big-endian systems. */
	*chip_id = 0;
	*chip_id |= response[0];
	*chip_id |= response[1] << 8;
	*chip_id |= response[2] << 16;
	*chip_id |= response[3] << 24;

	/* Discard the least significant byte to get the chip_id */
	*chip_id >>= 8;

	debug("ChipId: 0x%04x\n\n", *chip_id);

out:
	return ret;
}

static int get_msg_a6_otp(goodix_fp_device *dev)
{
	int ret;
	uint8_t otp[32];
	uint16_t otp_size;

	ret = send_packet_simple(dev, GOODIX_FP_PACKET_TYPE_OTP,
							 otp, &otp_size);
	if (ret < 0)
		goto out;
	debug_dump_buffer("OTP:", otp, otp_size);
	debug_dump_buffer_to_file("payload_otp.bin", otp, otp_size);
out:
	return ret;
}

static int get_msg_e4_psk(goodix_fp_device *dev)
{
	int ret;
	uint8_t request_psk[4] = "\x01\xb0\x00\x00";
	uint8_t request_hash[4] = "\x03\xb0\x00\x00";
	uint8_t psk[601] = {0};
	uint16_t psk_size;
	uint8_t hash[41] = {0};
	uint16_t hash_size;

	ret = send_packet(dev, GOODIX_FP_PACKET_TYPE_PSK,
					  request_psk, sizeof(request_psk),
					  psk, &psk_size);
	if (ret < 0)
		goto out;

	/*
	 * The PSK response contains one leading byte representing an error
	 * code, followed by Type-Length-Value data.
	 *
	 * The TLV structure is as follows.
	 *
	 * The Type field is uint32_t (little-endian):
	 *   - 0x0000b001 means PSK
	 *   - 0x0000b003 means HASH
	 *
	 * The Length field is uint32_t (little-endian):
	 *   - 0x00000250 for the PSK
	 *   - 0x00000020 for the HASH
	 *
	 * Then the data follows:
	 *   - for the PSK this is a sgx_sealed_data_t
	 *     https://software.intel.com/en-us/sgx-sdk-dev-reference-sgx-sealed-data-t
	 *   - for the HASH it should be 32 bytes representing a sha256 hash
	 *     of something from the PSK, after unsealing the data
	 */
	debug_dump_buffer("PSK:", psk, psk_size);
	debug_dump_buffer_to_file("payload_psk.bin", psk, psk_size);

	ret = send_packet(dev, GOODIX_FP_PACKET_TYPE_PSK,
					  request_hash, sizeof(request_hash),
					  hash, &hash_size);
	if (ret < 0)
		goto out;

	debug_dump_buffer("HASH:", hash, hash_size);
	debug_dump_buffer_to_file("payload_hash.bin", hash, hash_size);

out:
	return ret;
}

/* some negotiation happens with packet d2 */
static int get_msg_d2_handshake(goodix_fp_device *dev)
{
	int ret;
	unsigned int i;
	uint8_t client_hello[8 + 32] = "\x01\xff\x00\x00\x28\x00\x00\x00";
	uint8_t server_identity[8 + 64] = {0};
	uint16_t server_identity_size = 0;
	uint8_t client_reply[8 + 32 + 4] = "\x03\xff\x00\x00\x2c\x00\x00\x00";
	uint8_t server_done[8 + 4] = {0};
	uint16_t server_done_size = 0;

	/* Use a constant secret for now */
	for (i = 0; i < 32; i++)
		client_hello[i + 8] = 0;

	debug_dump_buffer_to_file("client_random.bin", client_hello + 8, 32);

	ret = send_packet(dev,
					  GOODIX_FP_PACKET_TYPE_HANDSHAKE,
					  client_hello, sizeof(client_hello),
					  server_identity, &server_identity_size);
	if (ret < 0)
		goto out;

	debug_dump_buffer_to_file("server_random1.bin", server_identity + 8, 32);
	debug_dump_buffer_to_file("server_random2.bin", server_identity + 8 + 32, 32);

	debug_dump_buffer("server_identity:", server_identity, server_identity_size);

	/* Client reply is not constant, it depends on the server identity.  */

	/* copy the server key into the reply packet */
	memcpy(client_reply + 8, server_identity + 8 + 32, 32);

	/* add some constant bytes */
	memcpy(client_reply + 8 + 32, "\xee\xee\xee\xee", 4);

	ret = send_packet(dev,
					  GOODIX_FP_PACKET_TYPE_HANDSHAKE,
					  client_reply, sizeof(client_reply),
					  server_done, &server_done_size);
	if (ret < 0)
		goto out;

	debug_dump_buffer("server_done:", server_done, server_done_size);

	/* If we pass this point negotiation succeeded */
	trace("Hurrah!\n");

out:
	return ret;
}

static int get_msg_90_config(goodix_fp_device *dev, uint16_t chip_id)
{
	int ret;
	uint8_t config_2202[256] = "\x08\x11\x54\x65\x24\x89\x24\xad\x1c\xc9\x1c\xe5\x04\xe9\x04\xed"
							   "\x13\xba\x00\x01\x00\xca\x00\x07\x00\x84\x00\x80\x81\x86\x00\x80"
							   "\x8c\x88\x00\x80\x97\x8a\x00\x80\xb0\x8c\x00\x80\x86\x8e\x00\x80"
							   "\x8c\x90\x00\x80\xa0\x92\x00\x80\xb3\x94\x00\x80\x84\x96\x00\x80"
							   "\x88\x98\x00\x80\xa0\x9a\x00\x80\xb8\x56\x00\x08\x28\x58\x00\x48"
							   "\x00\x70\x00\x01\x00\x72\x00\x78\x56\x74\x00\x34\x12\x26\x00\x00"
							   "\x12\xd0\x00\x00\x00\x20\x01\x02\x04\x20\x00\x10\x40\x22\x00\x01"
							   "\x20\x24\x00\x32\x00\x80\x00\x01\x04\x5c\x00\x80\x00\x28\x02\x00"
							   "\x00\x2a\x02\x00\x00\x82\x00\x80\x15\x20\x01\x82\x04\x20\x00\x10"
							   "\x40\x22\x00\x01\x20\x24\x00\x14\x00\x80\x00\x01\x04\x5c\x00\x00"
							   "\x01\x28\x02\x00\x00\x2a\x02\x00\x00\x82\x00\x80\x1a\x20\x01\x08"
							   "\x04\x22\x00\x10\x08\x80\x00\x01\x00\x5c\x00\x80\x00\x28\x02\x00"
							   "\x00\x2a\x02\x00\x00\x82\x00\x80\x15\x20\x01\x08\x04\x5c\x00\xf0"
							   "\x00\x50\x00\x01\x05\x52\x00\x08\x00\x54\x00\x10\x01\x28\x02\x00"
							   "\x00\x2a\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
							   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x66\x2f";
	uint8_t config_220c[256] = "\x40\x11\x6c\x7d\x28\xa5\x28\xcd\x1c\xe9\x10\xf9\x00\xf9\x00\xf9"
							   "\x00\x04\x02\x00\x00\x08\x00\x11\x11\xba\x00\x01\x80\xca\x00\x07"
							   "\x00\x84\x00\xbe\xb2\x86\x00\xc5\xb9\x88\x00\xb5\xad\x8a\x00\x9d"
							   "\x95\x8c\x00\x00\xbe\x8e\x00\x00\xc5\x90\x00\x00\xb5\x92\x00\x00"
							   "\x9d\x94\x00\x00\xaf\x96\x00\x00\xbf\x98\x00\x00\xb6\x9a\x00\x00"
							   "\xa7\x30\x00\x6c\x1c\x50\x00\x01\x05\xd0\x00\x00\x00\x70\x00\x00"
							   "\x00\x72\x00\x78\x56\x74\x00\x34\x12\x26\x00\x00\x12\x20\x00\x10"
							   "\x40\x12\x00\x03\x04\x02\x02\x16\x21\x2c\x02\x0a\x03\x2a\x01\x02"
							   "\x00\x22\x00\x01\x20\x24\x00\x32\x00\x80\x00\x05\x04\x5c\x00\x00"
							   "\x01\x56\x00\x28\x20\x58\x00\x01\x00\x32\x00\x24\x02\x82\x00\x80"
							   "\x0c\x20\x02\x88\x0d\x2a\x01\x92\x07\x22\x00\x01\x20\x24\x00\x14"
							   "\x00\x80\x00\x05\x04\x5c\x00\x9b\x00\x56\x00\x08\x20\x58\x00\x03"
							   "\x00\x32\x00\x08\x04\x82\x00\x80\x12\x20\x02\xf8\x0c\x2a\x01\x18"
							   "\x04\x5c\x00\x9b\x00\x54\x00\x00\x01\x62\x00\x09\x03\x64\x00\x18"
							   "\x00\x82\x00\x80\x0c\x20\x02\xf8\x0c\x2a\x01\x18\x04\x5c\x00\x9b"
							   "\x00\x52\x00\x08\x00\x54\x00\x00\x01\x00\x00\x00\x00\x00\x50\x5e";
	uint8_t *config;
	uint16_t config_size;
	uint8_t response[32768] = {0};
	uint16_t response_size = 0;

	switch (chip_id)
	{
	case 0x2202:
		config = config_2202;
		config_size = sizeof(config_2202);
		break;
	case 0x220c:
		config = config_220c;
		config_size = sizeof(config_220c);
		break;
	default:
		error("Unknown chip id 0x%04x", chip_id);
		ret = -EINVAL;
		goto out;
	}

	debug_dump_buffer("config:", config, config_size);

	ret = send_packet(dev, GOODIX_FP_PACKET_TYPE_CONFIG,
					  config, config_size,
					  response, &response_size);
	if (ret < 0)
		goto out;

	debug_dump_buffer("0x90 response:", response, response_size);

out:
	return ret;
}

static int get_msg_36(goodix_fp_device *dev)
{
	int ret;
	uint8_t request[26] = "\x0d\x01"
						  "\x97\x97\xa1\xa1\x9b\x9b\x92\x92\x96\x96\xa4\xa4"
						  "\x9d\x9d\x95\x95\x94\x94\xa1\xa1\x9c\x9c\x8e\x8e";
	uint8_t response[32768] = {0};
	uint16_t response_size = 0;

	ret = send_packet(dev, 0x36, request, sizeof(request), response, &response_size);
	if (ret < 0)
		goto out;

	debug_dump_buffer("0x36 response: ", response, response_size);

out:
	return ret;
}

/* this is probably the message to get an image, together with 36 */
static int get_msg_20(goodix_fp_device *dev, uint16_t chip_id)
{
	int ret;
	uint8_t request_2202[2] = "\x01\x00";
	uint8_t request_220c[4] = "\x01\x06\xcf\x00";
	uint8_t *request;
	uint16_t request_size;
	uint8_t response[32768] = {0};
	uint16_t response_size = 0;

	switch (chip_id)
	{
	case 0x2202:
		request = request_2202;
		request_size = sizeof(request_2202);
		break;
	case 0x220c:
		request = request_220c;
		request_size = sizeof(request_220c);
		break;
	default:
		error("Unknown chip id 0x%04x", chip_id);
		ret = -EINVAL;
		goto out;
	}

	ret = send_packet_full(dev, 0x20,
						   request, request_size,
						   response, &response_size, false);
	if (ret < 0)
		goto out;

	debug_dump_buffer_to_file("payload_image.bin", response, response_size);

out:
	return ret;
}

#if 0

/* maybe some shutdown message */
static int get_msg_60(goodix_fp_device *dev)
{}

/* maybe some shutdown message */
static int get_msg_ae(goodix_fp_device *dev)
{}

/* maybe some shutdown message */
static int get_msg_32(goodix_fp_device *dev)
{}

#endif

static int init_device_2202(goodix_fp_device *dev)
{
	int ret;

	ret = get_msg_a6_otp(dev);
	if (ret < 0)
	{
		error("Error, cannot get OTP: %d\n", ret);
		goto out;
	}

	ret = get_msg_90_config(dev, 0x2202);
	if (ret < 0)
	{
		error("Error, cannot set config: %d\n", ret);
		goto out;
	}

	ret = get_msg_36(dev);
	if (ret < 0)
	{
		error("Error, cannot get message 0x36: %d\n", ret);
		goto out;
	}

	ret = get_msg_20(dev, 0x2202);
	if (ret < 0)
	{
		error("Error, cannot get message 0x20: %d\n", ret);
		goto out;
	}

out:
	return ret;
}

static int init_device_220c(goodix_fp_device *dev)
{
	int ret;

	ret = get_msg_a6_otp(dev);
	if (ret < 0)
	{
		error("Error, cannot get OTP: %d\n", ret);
		goto out;
	}

	ret = get_msg_e4_psk(dev);
	if (ret < 0)
	{
		error("Error, cannot get message 0xe4: %d\n", ret);
		goto out;
	}

	ret = get_msg_d2_handshake(dev);
	if (ret < 0)
	{
		error("Error, cannot perform handshake: %d\n", ret);
		goto out;
	}

	ret = get_msg_90_config(dev, 0x220c);
	if (ret < 0)
	{
		error("Error, cannot set config: %d\n", ret);
		goto out;
	}

	ret = get_msg_36(dev);
	if (ret < 0)
	{
		error("Error, cannot get message 0x36: %d\n", ret);
		goto out;
	}

	ret = get_msg_20(dev, 0x220c);
	if (ret < 0)
	{
		error("Error, cannot get message 0x20: %d\n", ret);
		goto out;
	}

out:
	return ret;
}

static int init(goodix_fp_device *dev)
{
	int ret;
	uint32_t chip_id;

#if 0
	uint8_t buffer[32768] = {0};

	/* XXX some devices do not like these USB control transfers */
	ret = libusb_control_transfer(dev->usb_device,
								  LIBUSB_ENDPOINT_IN |
									  LIBUSB_REQUEST_TYPE_VENDOR |
									  LIBUSB_RECIPIENT_DEVICE,
								  1, 0, 4, buffer, 16, 0);
	if (ret != 16)
	{
		error("Error, control message 1: %d\n", ret);
		goto out;
	}
	trace_dump_buffer("<-- received", buffer, ret);

	ret = libusb_control_transfer(dev->usb_device,
								  LIBUSB_ENDPOINT_IN |
									  LIBUSB_REQUEST_TYPE_VENDOR |
									  LIBUSB_RECIPIENT_DEVICE,
								  1, 0, 4, buffer, 64, 0);
	if (ret != 64)
	{
		error("Error, control message 2: %d\n", ret);
		goto out;
	}
	trace_dump_buffer("<-- received", buffer, ret);

#endif
	ret = get_msg_00_change_mode_start(dev);
	if (ret < 0)
	{
		error("Error, cannot change mode to 0x00: %d\n", ret);
		goto out;
	}

	ret = get_msg_a8_firmware_version(dev);
	if (ret < 0)
	{
		error("Error, cannot get Firmware version: %d\n", ret);
		goto out;
	}

	ret = get_msg_a2_reset(dev);
	if (ret < 0)
	{
		error("Error, cannot perform reset: %d\n", ret);
		goto out;
	}

	ret = get_msg_82_chip_reg_read_chip_id(dev, &chip_id);
	if (ret < 0)
	{
		error("Error, cannot get chip id: %d\n", ret);
		goto out;
	}

	switch (chip_id)
	{
	case 0x220c:
		return init_device_220c(dev);
	case 0x2202:
		return init_device_2202(dev);
	case 0x2207:
	case 0x2208:
		error("Unsupported device type 0x%04x", chip_id);
		ret = -ENOTSUP;
		goto out;
	default:
		error("Unknown device type 0x%04x", chip_id);
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

static int goodix_fp_init(void)
{
	int ret;

	ret = libusb_init(NULL);
	if (ret < 0)
	{
		fprintf(stderr, "libusb_init failed: %s\n",
				libusb_error_name(ret));
		goto out;
	}

#if defined(LIBUSB_API_VERSION) && (LIBUSB_API_VERSION >= 0x01000106)
	libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, 3);
#else
	libusb_set_debug(NULL, 3);
#endif

out:
	return ret;
}

static void goodix_fp_shutdown(void)
{
	libusb_exit(NULL);
}

/* dev is only populated when the function returns 0 */
static int goodix_fp_device_open(goodix_fp_device **dev)
{
	libusb_device **list;
	libusb_device_handle *usb_dev;
	goodix_fp_device *new_dev;
	ssize_t num_devices;
	int current_configuration;
	int ret;
	int i;

	num_devices = libusb_get_device_list(NULL, &list);
	if (num_devices < 0)
	{
		ret = -ENODEV;
		goto out;
	}

	new_dev = NULL;
	for (i = 0; i < num_devices; i++)
	{
		struct libusb_device_descriptor desc;
		unsigned int j;

		ret = libusb_get_device_descriptor(list[i], &desc);
		if (ret < 0)
			continue;

		for (j = 0; j < ARRAY_SIZE(supported_devices); j++)
		{
			if (desc.idVendor == supported_devices[j].vendor_id &&
				desc.idProduct == supported_devices[j].product_id)
			{

				ret = libusb_open(list[i], &usb_dev);
				if (ret < 0)
				{
					fprintf(stderr, "libusb_open failed: %s\n", libusb_error_name(ret));
					goto out;
				}

				new_dev = malloc(sizeof(*new_dev));
				if (new_dev == NULL)
				{
					ret = -ENOMEM;
					goto out;
				}
				new_dev->usb_device = usb_dev;
				new_dev->desc = &supported_devices[j];

				/* only support the first device on the system */
				goto done;
			}
		}
	}
	if (new_dev == NULL)
	{
		fprintf(stderr, "Cannot find any device to open\n");
		ret = -ENODEV;
		goto out;
	}
done:

#if 1
	/* in case the device starts to act up */
	libusb_reset_device(usb_dev);
#endif

	current_configuration = -1;
	ret = libusb_get_configuration(usb_dev, &current_configuration);
	if (ret < 0)
	{
		fprintf(stderr, "libusb_get_configuration failed: %s\n",
				libusb_error_name(ret));
		goto out_libusb_close;
	}

	if (current_configuration != new_dev->desc->configuration)
	{
		ret = libusb_set_configuration(usb_dev, new_dev->desc->configuration);
		if (ret < 0)
		{
			fprintf(stderr, "libusb_set_configuration failed: %s\n",
					libusb_error_name(ret));
			fprintf(stderr, "Cannot set configuration %d\n",
					new_dev->desc->configuration);
			goto out_libusb_close;
		}
	}

	libusb_set_auto_detach_kernel_driver(usb_dev, 1);

	/* Claim all interfaces, the cdc_acm driver may be bound to them. */
	ret = usb_claim_interfaces(usb_dev, new_dev->desc->configuration);
	if (ret < 0)
		goto out_libusb_close;

	/*
	 * Checking that the configuration has not changed, as suggested in
	 * http://libusb.sourceforge.net/api-1.0/caveats.html
	 */
	current_configuration = -1;
	ret = libusb_get_configuration(usb_dev, &current_configuration);
	if (ret < 0)
	{
		fprintf(stderr, "libusb_get_configuration after claim failed: %s\n",
				libusb_error_name(ret));
		goto out_release_interfaces;
	}

	if (current_configuration != new_dev->desc->configuration)
	{
		fprintf(stderr, "libusb configuration changed (expected: %d, current: %d)\n",
				new_dev->desc->configuration, current_configuration);
		ret = -EINVAL;
		goto out_release_interfaces;
	}

	*dev = new_dev;
	ret = 0;
	goto out;

out_release_interfaces:
	usb_release_interfaces(usb_dev, new_dev->desc->configuration);
out_libusb_close:
	free(new_dev);
	libusb_close(usb_dev);

out:
	libusb_free_device_list(list, 1);
	return ret;
}

static void goodix_fp_device_close(goodix_fp_device *dev)
{
	usb_release_interfaces(dev->usb_device, dev->desc->configuration);
	libusb_close(dev->usb_device);
	free(dev);
}

int main(void)
{
	goodix_fp_device *dev;
	int ret;

	ret = goodix_fp_init();
	if (ret < 0)
		goto out;

	ret = goodix_fp_device_open(&dev);
	if (ret < 0)
		goto out_shutdown;

	// ret = init(dev);

	////////////////////////////////////

	unsigned char data[64] = "\xa0\x06\x00\xa6\x20\x03\x00\x01\x00\x86\x00\x00\x00\x00\x00\x00"
							 "\xd0\xeb\x1a\xcf\x4f\x01\x00\x00\x50\x01\x18\xcf\x4f\x01\x00\x00"
							 "\x00\x00\x00\x00\x00\x00\x00\x00\x2b\x1f\x36\xfb\xfe\x7f\x00\x00"
							 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

	int actual_length;

	// actual_length = 0;
	// ret = libusb_bulk_transfer(dev->usb_device, dev->desc->output_endpoint, data, 64, &actual_length, 0);
	// debug("%s\n", libusb_error_name(ret));

	actual_length = 0;
	ret = libusb_bulk_transfer(dev->usb_device, dev->desc->input_endpoint, data, 64, &actual_length, 0);
	debug("%s\n", libusb_error_name(ret));

	// ret = libusb_bulk_transfer(dev->usb_device, dev->desc->output_endpoint, NULL, 0, &actual_length, 0);
	// debug("%s\n", libusb_error_name(ret));

	////////////////////////////////////

	goodix_fp_device_close(dev);

out_shutdown:
	goodix_fp_shutdown();
out:
	return ret;
}
