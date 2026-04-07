NVCC = nvcc
CXX = g++

NVCC_FLAGS = -O3 -rdc=true -arch=native
CXX_FLAGS = -O3

COMMON_OBJS = defs.o
ALL_OBJS = crack.o md5.o sha1.o $(COMMON_OBJS)

all: crack

# Combined binary for both MD5 and SHA1
crack: $(ALL_OBJS)
	$(NVCC) $(NVCC_FLAGS) $(ALL_OBJS) -o crack

crack.o: crack.cpp crack.h
	$(CXX) $(CXX_FLAGS) -c crack.cpp -o crack.o

# Seprate binaries for MD5 and SHA1
md5: crack_md5.o md5.o $(COMMON_OBJS)
	$(NVCC) $(NVCC_FLAGS) crack_md5.o md5.o $(COMMON_OBJS) -o md5

crack_md5.o: crack.cpp crack.h
	$(CXX) $(CXX_FLAGS) -DONLY_MD5 -c crack.cpp -o crack_md5.o

sha1: crack_sha1.o sha1.o $(COMMON_OBJS)
	$(NVCC) $(NVCC_FLAGS) crack_sha1.o sha1.o $(COMMON_OBJS) -o sha1

crack_sha1.o: crack.cpp crack.h
	$(CXX) $(CXX_FLAGS) -DONLY_SHA1 -c crack.cpp -o crack_sha1.o

# Kernels
md5.o: md5.cu md5.cuh crack.h
	$(NVCC) $(NVCC_FLAGS) -c md5.cu -o md5.o

sha1.o: sha1.cu sha1.cuh crack.h
	$(NVCC) $(NVCC_FLAGS) -c sha1.cu -o sha1.o

defs.o: defs.cu defs.cuh
	$(NVCC) $(NVCC_FLAGS) -c defs.cu -o defs.o

# Utils
clean:
	rm -f *.o crack crack_md5 crack_sha1 md5 sha1

run_combined: crack
	./crack md5 7815696ecbf1c96e6894b779456d330e 3
	./crack sha1 f10e2821bbbea527ea02200352313bc059445190 3

run_md5: md5
	./md5 md5 7815696ecbf1c96e6894b779456d330e 3

run_sha1: sha1
	./sha1 sha1 f10e2821bbbea527ea02200352313bc059445190 3