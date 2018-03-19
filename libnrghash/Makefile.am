#######################################
# The list of libraries we are building seperated by spaces.
# The 'lib_' indicates that these build products will be installed
# in the $(libdir) directory. For example /usr/lib
lib_LTLIBRARIES = libnrghash.la

#######################################
# Build information for each library

# Sources for libnrghash
libnrghash_la_SOURCES = nrghash.cpp keccak-tiny.c

# Linker options libTestProgram
libnrghash_la_LDFLAGS = 

# Compiler options. Here we are adding the include directory
# to be searched for headers included in the source code.
libnrghash_la_CPPFLAGS = -I$(top_srcdir)/include -D__STDC_WANT_LIB_EXT1__=1 -DUSE_SECURE_MEMZERO 
