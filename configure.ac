#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

AC_ARG_ENABLE([cli-mode],
    [AS_HELP_STRING([--enable-cli-mode],
    [Enable the CLI mode])],
    [cli_mode=$enableval], [cli_mode=no])
AM_CONDITIONAL([CLI_MODE], [test "x$cli_mode" = "xyes"])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
cxxflags_save="$CXXFLAGS"
AC_PROG_CXX()
CXXFLAGS="$cxxflags_save"
CXXFLAGS="-O3"
AC_PROG_LN_S

# Checks for libraries
#AC_CHECK_LIB([dl], [main])
#AC_CHECK_LIB([pthread], [main])
#AC_CHECK_LIB([z], [main])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([fdatasync floor gethostbyname gethostname gettimeofday iswprint localtime_r memchr memset mkdir munmap pow rmdir select socket sqrt strchr strdup strerror strrchr strstr strtol strtoul strtoull])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
