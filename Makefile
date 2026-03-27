NVCC = nvcc
CXX = g++

NVCC_FLAGS = -O3 -rdc=true -arch=native
CXX_FLAGS = -O3

TARGET = crack

OBJS = crack.o md5.o sha1.o defs.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(NVCC) $(NVCC_FLAGS) $(OBJS) -o $(TARGET)

crack.o: crack.cpp crack.h
	$(CXX) $(CXX_FLAGS) -c crack.cpp -o crack.o

md5.o: md5.cu md5.cuh crack.h
	$(NVCC) $(NVCC_FLAGS) -c md5.cu -o md5.o

sha1.o: sha1.cu sha1.cuh crack.h
	$(NVCC) $(NVCC_FLAGS) -c sha1.cu -o sha1.o

defs.o: defs.cu defs.cuh
	$(NVCC) $(NVCC_FLAGS) -c defs.cu -o defs.o

clean:
	rm -f $(OBJS) $(TARGET)

md5: $(TARGET)
	./$(TARGET) md5 7815696ecbf1c96e6894b779456d330e 3

sha1: $(TARGET)
	./$(TARGET) sha1 f10e2821bbbea527ea02200352313bc059445190 3