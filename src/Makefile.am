## Process this file with automake to produce Makefile.in

## Created by Anjuta

AM_CPPFLAGS = \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_SRC_DIR=\""$(srcdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\"

AM_CFLAGS =\
	 -Wall\
	 -g -lpthread

bin_PROGRAMS = adbd

adbd_SOURCES = \
	fdevent.c          \
	sockets.c          \
	services.c         \
	transport.c        \
	transport_usb.c    \
	usb_linux_client.c \
	file_sync_service.c \
	adb.c

adbd_LDFLAGS = 

adbd_LDADD = 

