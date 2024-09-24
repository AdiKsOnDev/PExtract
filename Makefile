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

OBJECTS := $(wildcard $(BUILDDIR)/*.o)

# Default target
bin/pextract.exe: $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ -L $(LIBDIR) -limagehlp

# Build object files from src directory
$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I $(INCDIR) -c -o $@ $<

# Clean build files
clean:
	@echo "Cleaning..."
	$(RM) -r $(BUILDDIR) bin/pextract.exe
