CC ?= cc

SRC := \
	src/pam_pin.c \
	src/options.c \
	src/pin_store.c \
	src/boot_state.c \
	src/crypto.c

OBJ := $(SRC:.c=.o)

CFLAGS ?= -O2 -pipe
CFLAGS += -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
CFLAGS += -Wall -Wextra -Wformat -Wformat-security -Werror
CFLAGS += -D_GNU_SOURCE

LDFLAGS ?=
LDFLAGS += -shared -Wl,-z,relro,-z,now

LDLIBS += -lpam -lpam_misc -lcrypt

TARGET := pam_pin.so

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
