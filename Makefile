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

# Target binary
TARGET := $(BINDIR)/pextract.exe

# Source and object files
ROOT_SOURCES := $(wildcard $(ROOTDIR)/*.c)
SRC_SOURCES := $(shell dir /S /B $(SRCDIR)\*.c)
SOURCES := $(SRC_SOURCES) $(ROOT_SOURCES)
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))

# Default target
$(TARGET): $(OBJECTS)
	@echo "Linking..."
	@if not exist $(BINDIR) mkdir $(BINDIR)
	@echo "$(CC) $^ -o $(TARGET) -L lib/ -lcapstone -limagehlp"
	$(CC) $^ -o $(TARGET) -L lib/ -lcapstone -limagehlp

# Build object files from root directory
$(BUILDDIR)/%.o: $(ROOTDIR)/%.c
	@echo "Building..."
	@if not exist $(BUILDDIR) mkdir $(BUILDDIR)
	@echo "$(CC) $(CFLAGS) -I include/ -I include/capstone -L lib/ -lcapstone -limagehlp -c -o $(TARGET)"
	$(CC) $(CFLAGS) -I include/ -I include/capstone -L lib/ -lcapstone -limagehlp -c -o $@ $^

# Build object files from src directory
$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@echo "Building..."
	@if not exist $(BUILDDIR) mkdir $(BUILDDIR)
	@echo "$(CC) $(CFLAGS) -I include/ -I include/capstone -L lib/ -lcapstone -limagehlp -c -o $(TARGET)"
	$(CC) $(CFLAGS) -I include/ -I include/capstone -L lib/ -lcapstone -limagehlp -c -o $@ $^

# Clean build files
clean:
	@echo "Cleaning..."
	@echo "$(RM) -r $(BUILDDIR) $(BINDIR)/pextract.exe"
	$(RM) -r $(BUILDDIR) $(BINDIR)/pextract.exe

.PHONY: clean
