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

OBJECTS := $(wildcard build/*.o)

# Default target
bin/pextract.exe: $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $(TARGET) -limagehlp

# Build object files from src directory
build/%.o: src/%.c
	$(CC) $(CFLAGS) -I include/ -L lib/ -limagehlp -c -o $@ $^

# Clean build files
clean:
	@echo "Cleaning..."
	@echo "$(RM) -r build/ bin/pextract.exe"
	$(RM) -r build/ bin/pextract.exe
