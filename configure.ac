dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([nrghash],[1.23.0])
AC_PROG_CC
AC_PROG_CXX

AC_CANONICAL_TARGET

AC_CONFIG_MACRO_DIR([m4])

dnl Initialize automake
AM_INIT_AUTOMAKE([foreign])

dnl this allows us specify individual liking flags for each target
AM_PROG_CC_C_O

dnl Initialize Libtool
LT_INIT


#AX_CXX_COMPILE_STDCXX([11], [noext], [mandatory], [nodefault])


dnl Check for boost libs
AX_BOOST_BASE
AX_BOOST_SYSTEM
AX_BOOST_FILESYSTEM
AX_BOOST_UNIT_TEST_FRAMEWORK
BOOST_LIBS="$BOOST_LDFLAGS $BOOST_SYSTEM_LIB $BOOST_FILESYSTEM_LIB"
LIBS="$BOOST_LIBS $LIBS"
CPPFLAGS="$BOOST_CPPFLAGS"
CXXFLAGS="$BOOST_CXXFLAGS -O3 -std=c++11 -Wall -Wextra -Werror -Wno-unused-function"
CCFLAGS="$BOOST_CCFLAGS -O3 -Wall -Wextra -Werror -Wno-unused-function"


AC_CONFIG_FILES(Makefile
                test/Makefile
                libnrghash/Makefile
                include/Makefile)
AC_OUTPUT

