CC = cc
CFLAGS = -w -O2 -Iinclude
LDFLAGS = -lsodium -s

SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)
BIN = sigil

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

sigil: $(OBJ)
	$(CC) $(OBJ) -o sigil $(LDFLAGS)

clean:
	rm -f src/*.o sigil

.PHONY: all build install clean uninstall purge

all: build install clean

install: $(OBJ)
	mkdir -p $(BINDIR)
	cp sigil $(BINDIR)/
	chmod 755 $(BINDIR)/$(BIN)

uninstall:
	rm -f $(BINDIR)/$(BIN)

purge: clean uninstall

