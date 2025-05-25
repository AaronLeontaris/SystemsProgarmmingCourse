CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -g
LDFLAGS = -lfuse

TARGET = memfs

SRC = main.cpp memfs.cpp memfs_ops.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o