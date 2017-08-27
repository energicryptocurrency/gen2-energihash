dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(egihash, 1.0)
AC_PROG_CC
AC_PROG_CXX

AC_CANONICAL_SYSTEM

AC_CONFIG_MACRO_DIR([m4])

dnl Initialize automake
AM_INIT_AUTOMAKE

dnl this allows us specify individual liking flags for each target
AM_PROG_CC_C_O 

dnl Initialize Libtool
LT_INIT


#AX_CXX_COMPILE_STDCXX([11], [noext], [mandatory], [nodefault])


dnl Check for boost libs
AX_BOOST_BASE
AX_BOOST_SYSTEM
AX_BOOST_FILESYSTEM
AX_BOOST_PROGRAM_OPTIONS
AX_BOOST_THREAD
AX_BOOST_CHRONO
AX_BOOST_UNIT_TEST_FRAMEWORK
BOOST_LIBS="$BOOST_LDFLAGS $BOOST_SYSTEM_LIB $BOOST_FILESYSTEM_LIB $BOOST_PROGRAM_OPTIONS_LIB $BOOST_THREAD_LIB $BOOST_CHRONO_LIB"
LIBS="$BOOST_LIBS $LIBS"
CPPFLAGS="$CPPFLAGS $BOOST_CPPFLAGS"
CXXFLAGS="$CXXFLAGS $BOOST_CXXFLAGS -std=c++11 -Wall -Wextra -Werror -Wno-unused-function"



AC_CONFIG_FILES(Makefile
                test/Makefile
                libegihash/Makefile
                include/Makefile)
AC_OUTPUT

