#include <time.h>
#include <stdio.h>
#include <libusb-1.0/libusb.h>

#define VENDOR_ID 0x27c6
#define PRODUCT_ID 0x5110

char *now()
{
    static char buffer[26];

    time_t timer = time(NULL);
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", localtime(&timer));

    return buffer;
}

#define error(error, errcode) fprintf(stderr, "[%s] (ERROR) %s: %s\n%s\n", now(), error, libusb_error_name(errcode), libusb_strerror(errcode))
#define warning(warning, errcode) fprintf(stderr, "[%s] (WARNING) %s: %s\n%s\n", now(), warning, libusb_error_name(errcode), libusb_strerror(errcode))
#define debug(debug, ...) fprintf(stderr, "[%s] (DEBUG) " debug "\n", now(), __VA_ARGS__)
#define info(info) fprintf(stderr, "[%s] (INFO) " info "\n", now())

static int transfer_nb = 0;

int goodix_init()
{
    info("goodix_init()");

    int errcode;

    errcode = libusb_init(NULL);
    if (errcode != LIBUSB_SUCCESS)
    {
        error("Failed to init libusb", errcode);
        return errcode;
    }

    errcode = libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_INFO);
    if (errcode != LIBUSB_SUCCESS)
        warning("Failed to set option", errcode);

    return LIBUSB_SUCCESS;
}

void goodix_exit()
{
    info("goodix_exit()");

    libusb_exit(NULL);
}

int goodix_open(uint16_t vendor_id, uint16_t product_id, libusb_device_handle **dev_handle)
{
    info("goodix_open()");

    int errcode;

    *dev_handle = libusb_open_device_with_vid_pid(NULL, vendor_id, product_id);
    if (!*dev_handle)
    {
        errcode = LIBUSB_ERROR_NOT_FOUND;
        error("Failed to open device", errcode);
        return errcode;
    }

    return LIBUSB_SUCCESS;
}

void goodix_close(libusb_device_handle *dev_handle)
{
    info("goodix_close()");

    libusb_close(dev_handle);
}

int goodix_claim(libusb_device_handle *dev_handle)
{
    info("goodix_claim()");

    int errcode;

    errcode = libusb_set_auto_detach_kernel_driver(dev_handle, 1);
    if (errcode != LIBUSB_SUCCESS)
        warning("Failed to set auto detach kernel driver", errcode);

    errcode = libusb_claim_interface(dev_handle, 1);
    if (errcode != LIBUSB_SUCCESS)
        error("Failed to claim interface", errcode);

    return errcode;
}

void goodix_release(libusb_device_handle *dev_handle)
{
    info("goodix_release()");

    int errcode;

    errcode = libusb_release_interface(dev_handle, 1);
    if (errcode != LIBUSB_SUCCESS)
        warning("Failed to release interface", errcode);
}

void LIBUSB_CALL goodix_callback(struct libusb_transfer *transfer)
{
    info("goodix_callback()");

    debug("Transferred %d/%d bytes", transfer->actual_length, transfer->length);

    if (transfer->status != LIBUSB_TRANSFER_COMPLETED)
        error("Failed to transfer", transfer->status);
    else
        info("Transfer done");

    transfer_nb--;
}

int goodix_create_transfer(struct libusb_transfer **transfer,
                           libusb_device_handle *dev_handle,
                           unsigned char endpoint,
                           unsigned char *buffer,
                           int length,
                           unsigned int timeout)
{
    info("goodix_create_transfer()");

    int errcode;

    *transfer = libusb_alloc_transfer(0);

    if (!*transfer)
    {
        errcode = LIBUSB_TRANSFER_ERROR;
        error("Failed to alloc transfer", errcode);
        return errcode;
    }

    libusb_fill_bulk_transfer(*transfer, dev_handle, endpoint, buffer, length, goodix_callback, NULL, timeout);

    return LIBUSB_SUCCESS;
}

void goodix_free_transfer(struct libusb_transfer *transfer)
{
    info("goodix_free_transfer()");

    libusb_free_transfer(transfer);
}

int goodix_submit_transfer(struct libusb_transfer *transfer)
{
    info("goodix_submit_transfer()");

    int errcode;

    errcode = libusb_submit_transfer(transfer);
    if (errcode != LIBUSB_SUCCESS)
    {
        error("Failed to submit transfer", errcode);
        return errcode;
    }

    transfer_nb++;

    return LIBUSB_SUCCESS;
}

void goodix_cancel_transfer(struct libusb_transfer *transfer)
{
    info("goodix_cancel_transfer()");

    int errcode;

    errcode = libusb_cancel_transfer(transfer);
    if (errcode != LIBUSB_SUCCESS)
    {
        warning("Failed to cancel transfer", errcode);
        return;
    }

    transfer_nb--;
}

int goodix_handle_events()
{
    info("goodix_handle_events()");

    int errcode;

    while (transfer_nb)
    {
        errcode = libusb_handle_events_completed(NULL, NULL);
        if (errcode != LIBUSB_SUCCESS)
        {
            error("Failed to handle events", errcode);
            return errcode;
        }
    }

    return LIBUSB_SUCCESS;
}

int main()
{
    info("main()");

    int errcode, actual_length;
    libusb_device_handle *dev_handle;
    struct libusb_transfer *transfer;

    errcode = goodix_init();
    if (errcode != LIBUSB_SUCCESS)
        return errcode;

    errcode = goodix_open(VENDOR_ID, PRODUCT_ID, &dev_handle);
    if (errcode != LIBUSB_SUCCESS)
        goto exit;

    errcode = goodix_claim(dev_handle);
    if (errcode != LIBUSB_SUCCESS)
        goto close;

    errcode = goodix_create_transfer(&transfer, dev_handle, 0x81, NULL, 0, 1000);
    if (errcode != LIBUSB_SUCCESS)
        goto release;

    errcode = goodix_submit_transfer(transfer);
    if (errcode != LIBUSB_SUCCESS)
        goto free;

    errcode = goodix_handle_events();
    if (errcode != LIBUSB_SUCCESS)
        goodix_cancel_transfer(transfer);

free:
    goodix_free_transfer(transfer);

release:
    goodix_release(dev_handle);

close:
    goodix_close(dev_handle);

exit:
    goodix_exit();

    return errcode;
}
