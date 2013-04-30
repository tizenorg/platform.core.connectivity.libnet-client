CPPFLAGS = $(DBUS_CFLAGS) $(GLIB_CFLAGS) $(DLOG_CFLAGS) $(VCONF_CFLAGS)
CPPFLAGS += -Wall

ACLOCAL_AMFLAGS = -I m4

####################################################################################
#
# 				network client library
#
####################################################################################

lib_LTLIBRARIES = libnetwork.la

CPPFLAGS += -DEXPORT_API="__attribute__((visibility(\"default\")))" -DPREFIX=\"$(PREFIX)\" -DVITA_FEATURE

libnetwork_la_SOURCES = \
			src/network-wifi-intf.c \
			src/network-cm-intf.c \
			src/network-profile-intf.c \
			src/network-dbus-request.c \
			src/network-internal.c \
			src/network-signal-handler.c

libnetwork_la_CFLAGS = \
              -I$(srcdir)/include \
              -I$(srcdir)/include/wifi \
              -I$(srcdir)/include/profile \
              -I$(srcdir)/include/common \
              -I$(srcdir)/src/include

libnetwork_la_CFLAGS += $(CPPFLAGS)

libnetwork_la_LIBADD =  \
			 $(DBUS_LIBS) $(GLIB_LIBS) $(VCONF_LIBS) \
			 $(GTHREAD_LIBS) $(DLOG_LIBS) -lpthread -lrt

includelibnetworkdir = $(includedir)/network

includelibnetwork_HEADERS =  include/common/network-cm-intf.h \
			include/common/network-cm-error.h \
			include/profile/network-pm-intf.h \
			include/profile/network-pm-wlan.h \
			include/profile/network-pm-config.h \
			include/wifi/network-wifi-intf.h

libnetwork_la_CFLAGS += $(AM_FLAGS)

pcfiles = network.pc

%.pc: %.pc
	cp $< $@

pkgconfigdir   = $(libdir)/pkgconfig

pkgconfig_DATA = $(pcfiles)
