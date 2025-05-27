CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -g -D_FILE_OFFSET_BITS=64 -I/usr/include/jsoncpp
LDFLAGS = -lfuse -ljsoncpp

TARGET = memfs
SRC = main.cpp memfs.cpp memfs_ops.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o memfs.img