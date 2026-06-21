CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2 -std=c11 -Iinclude -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
LDFLAGS ?= -lsqlite3

SRCS = src/main.c \
       src/config.c \
       src/db.c \
       src/store.c \
       src/response.c \
       src/handlers.c \
       src/http.c \
       src/json.c \
       src/util.c \
       src/network.c

OBJS = $(SRCS:.c=.o)
TARGET = cloudtse

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
