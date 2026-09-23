# Paths
BUILD_DIR = build
SRC_DIR = .
# uNeurai library
LIB_DIR = ../src

# Tools
ifeq ($(OS),Windows_NT)
TOOLCHAIN_PREFIX ?= x86_64-w64-mingw32-
MKDIR_P = mkdir
RM_R = rmdir /s /q
else
TOOLCHAIN_PREFIX ?= 
MKDIR_P = mkdir -p
RM_R = rm -r
endif

# compilers
CC := $(TOOLCHAIN_PREFIX)gcc
CXX := $(TOOLCHAIN_PREFIX)g++

# uNeurai sources
CXX_SOURCES += $(wildcard $(LIB_DIR)/*.cpp)
C_SOURCES += $(wildcard $(LIB_DIR)/utility/trezor/*.c) \
			$(wildcard $(LIB_DIR)/utility/*.c) \
			$(wildcard $(LIB_DIR)/*.c) \
			$(wildcard $(SRC_DIR)/*.c)

# Optional ML-DSA-44 backend. The PQ key/signing code is ESP32-only; to build
# and run it on the host too, point MLDSA_DIR at the src/ folder of the
# mldsa-esp32 library (https://github.com/NeuraiProject/mldsa-esp32):
#     make run MLDSA_DIR=/path/to/mldsa-esp32/src
# The ESP32 TRNG is replaced by pq_host/randombytes_host.c and the objects go
# to build/pq so they never mix with the default (PQ-less) build.
ifneq ($(MLDSA_DIR),)
BUILD_DIR = build/pq
PQ_FLAGS = -DUNEURAI_ENABLE_PQ -DARDUINO_ARCH_ESP32 -I$(MLDSA_DIR)
MLDSA_SOURCES = $(filter-out $(MLDSA_DIR)/randombytes.c $(MLDSA_DIR)/mldsa65_build.c $(MLDSA_DIR)/mldsa87_build.c, \
			$(wildcard $(MLDSA_DIR)/*.c)) \
			$(wildcard $(MLDSA_DIR)/fips202/*.c)
C_SOURCES += $(SRC_DIR)/pq_host/randombytes_host.c
endif

# include lib path, don't use mbed or arduino config (-DUSE_STDONLY)
CFLAGS = -I$(LIB_DIR) -g
CPPFLAGS = -I$(LIB_DIR) -DUSE_STDONLY -DUXNA_TEST -g $(PQ_FLAGS)

OBJS = $(patsubst $(SRC_DIR)/%, $(BUILD_DIR)/src/%.o, \
		$(patsubst $(LIB_DIR)/%, $(BUILD_DIR)/lib/%.o, \
		$(C_SOURCES) $(CXX_SOURCES))) \
		$(patsubst $(MLDSA_DIR)/%, $(BUILD_DIR)/mldsa/%.o, $(MLDSA_SOURCES))

vpath %.cpp $(SRC_DIR)
vpath %.cpp $(LIB_DIR)
vpath %.c $(SRC_DIR)
vpath %.c $(LIB_DIR)

TESTS=$(wildcard $(SRC_DIR)/*.cpp)
TESTOBJS=$(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/test/%.cpp.o, $(TESTS))
TESTBINS=$(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.test, $(TESTS))


.PHONY: clean all run

all: $(TESTBINS)

run: $(TESTBINS)
	for test in $(TESTBINS); do echo $$test; ./$$test ; done

# keep object files
.SECONDARY: $(OBJS) $(TESTOBJS)

# lib c sources
$(BUILD_DIR)/lib/%.c.o: %.c
	$(MKDIR_P) $(dir $@)
	$(CC) -c $(CFLAGS) $< -o $@

# lib cpp sources
$(BUILD_DIR)/lib/%.cpp.o: %.cpp
	$(MKDIR_P) $(dir $@)
	$(CXX) -c $(CPPFLAGS) $< -o $@

# optional ML-DSA-44 backend sources
$(BUILD_DIR)/mldsa/%.c.o: $(MLDSA_DIR)/%.c
	$(MKDIR_P) $(dir $@)
	$(CC) -c -O2 -I$(MLDSA_DIR) $< -o $@

# lib c sources
$(BUILD_DIR)/src/%.c.o: %.c
	$(MKDIR_P) $(dir $@)
	$(CC) -c $(CFLAGS) $< -o $@

# test cpp sources
$(BUILD_DIR)/test/%.cpp.o: %.cpp
	$(MKDIR_P) $(dir $@)
	$(CXX) -c $(CPPFLAGS) $< -o $@

$(BUILD_DIR)/%.test: $(BUILD_DIR)/test/%.cpp.o $(OBJS)
	$(CXX) $< $(OBJS) $(CPPFLAGS) -o $@

clean:
	$(RM_R) $(BUILD_DIR)
