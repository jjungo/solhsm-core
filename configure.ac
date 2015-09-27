#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([solhsm-core], [0.9], [j.jungo@gmail.com])
AM_INIT_AUTOMAKE(hsm-core, 0.9)
AC_CONFIG_SRCDIR(src)
AC_CONFIG_HEADERS(config.h)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([crypto], [PEM_read_bio_RSAPrivateKey], [], [
    echo "crypto is required for this program"
    exit -1])
AC_CHECK_LIB([czmq], [zctx_new], [], [
    echo "czmq is required for this program"
    exit -1])
AC_CHECK_LIB([sqlite3], [sqlite3_open], [], [
    echo "sqlite3 is required for this program"
    exit -1])
AC_CHECK_LIB([ssl], [PEM_read_bio_RSAPrivateKey], [], [
    echo "libssl is required for this program"
    exit -1])
AC_CHECK_LIB([zmq], [zsocket_new], [], [
    echo "zmq is required for this program"
    exit -1])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_CHECK_HEADER_STDBOOL
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
