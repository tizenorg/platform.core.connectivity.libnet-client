#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AM_INIT_AUTOMAKE(src, 1.0)
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_LN_S

LT_INIT

# Checks for moduels.
PKG_CHECK_MODULES(DLOG, dlog)
AC_SUBST(DLOG_CFLAGS)
AC_SUBST(DLOG_LIBS)

PKG_CHECK_MODULES(VCONF, vconf)
AC_SUBST(VCONF_CFLAGS)
AC_SUBST(VCONF_LIBS)

PKG_CHECK_MODULES(GLIB, glib-2.0)
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(GTHREAD, gthread-2.0)
AC_SUBST(GTHREAD_CFLAS)
AC_SUBST(GTHREAD_LIBS)

PKG_CHECK_MODULES(DBUS, dbus-glib-1)
AC_SUBST(DBUS_CFLAS)
AC_SUBST(DBUS_LIBS)

PKG_CHECK_MODULES(GIO, gio-2.0)
AC_SUBST(GIO_CFLAS)
AC_SUBST(GIO_LIBS)

if (!test $ARCH = "arm"); then
	AM_CONDITIONAL(ARM_BUILD, false)
else
	AM_CONDITIONAL(ARM_BUILD, true)
fi

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h malloc.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([getcwd gettimeofday memset mkdir socket dup2 gettimeofday inet_ntoa memset select socket strcasecmp strchr strerror strncasecmp strrchr strstr strtoul])

AC_CONFIG_FILES(
		[Makefile]
		[network.pc]
		)

AC_OUTPUT
