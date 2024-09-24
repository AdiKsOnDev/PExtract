# Compiler and flags
CC := gcc
CFLAGS := -Wall -g -O3 -mconsole

# Directories
ROOTDIR := .
SRCDIR := src
BUILDDIR := build
BINDIR := bin
INCDIR := include
LIBDIR := lib

# Default target
bin/pextract.exe: build/%.o
	@echo "Linking..."
	@if not exist $(BINDIR) mkdir $(BINDIR)
	@echo "$(CC) $^ -o $(TARGET) -L lib/ -limagehlp"
	$(CC) $^ -o $(TARGET) -I include/ -L lib/ -limagehlp

# Build object files from src directory
build/%.o: src/%.c
	@echo "Building..."
	@if not exist $(BUILDDIR) mkdir $(BUILDDIR)
	@echo "$(CC) $(CFLAGS) -I include/ -L lib/ -limagehlp -c -o $(TARGET)"
	$(CC) $(CFLAGS) -I include/ -L lib/ -limagehlp -c -o $@ $^

# Clean build files
clean:
	@echo "Cleaning..."
	@echo "$(RM) -r build/ bin/pextract.exe"
	$(RM) -r build/ bin/pextract.exe

.PHONY: clean
