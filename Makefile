.PHONY: directories
.PHONY: clean

LD_FLAGS=-lpthread -lpq
	CFLAGS=-g3 -c -Iinc -I/usr/include/postgresql/ -DDEBUG_MSG
SRC_DIR=src
BUILD_DIR=build
C_FILES=$(wildcard $(SRC_DIR)/*.c)
CPP_FILES=$(wildcard $(SRC_DIR)/*.cpp)
OBJ_FILES=$(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(C_FILES))
OBJ_FILES+=$(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(CPP_FILES))

TARGET=$(BUILD_DIR)/magic-cookie

all: directories $(TARGET)

directories:
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJ_FILES)
	$(CROSS_COMPILE)g++ -o $(TARGET) $(OBJ_FILES) $(LD_FLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CROSS_COMPILE)gcc $(CFLAGS) $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CROSS_COMPILE)g++ $(CFLAGS) $< -o $@

clean:
	rm -rf $(BUILD_DIR)/*.o $(TARGET)
