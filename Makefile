CC=clang-4.0
CXX=clang++-4.0
CFLAGS=-g -O0 -fsanitize=address -m64 -D__STDC_WANT_LIB_EXT1__=1 -DUSE_SECURE_MEMZERO -Wall -Wextra -Werror -Wno-unused-function -Wno-unused-const-variable
LDFLAGS=-m64 -std=c++11 -fsanitize=address
#CFLAGS=-O3 -m64 -D__STDC_WANT_LIB_EXT1__=1 -DUSE_SECURE_MEMZERO -Wall -Wextra -Werror -Wno-unused-function -Wno-unused-const-variable
#LDFLAGS=-m64 -std=c++11
CXXFLAGS=$(CFLAGS) -std=c++11
OBJECTS=main.o egihash.o keccak-tiny.o

%.o: %.c
	$(CC) $(CFLAGS) -std=c11 -c -o $@ $<

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

all: $(OBJECTS)
	$(CXX) $(LDFLAGS) -o egihash $(OBJECTS)

clean:
	rm -rf $(OBJECTS) egihash
