CC			:= gcc
CXX			:= gcc
CFLAGS		:= -Wall -Werror -g

BUILD_DIR	:= ./build
SRC_DIR		:= ./src

SRCS		:= $(shell find $(SRC_DIR) -name "*.c")
OBJS		:= $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

TARGET		:= $(BUILD_DIR)/conn_track

GLIB_INCLUDE = $(shell pkg-config --cflags glib-2.0)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(GLIB_INCLUDE) -o $(TARGET) $(OBJS) -lpcap -lglib-2.0

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(GLIB_INCLUDE) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)