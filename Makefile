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

# Target
TARGET := $(BINDIR)/pextract.exe

# Source and object files
SRCEXT := c
ROOT_SOURCES := $(wildcard $(ROOTDIR)/*.$(SRCEXT))
SRC_SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
SOURCES := $(ROOT_SOURCES) $(SRC_SOURCES)
OBJECTS := $(patsubst $(ROOTDIR)/%,$(BUILDDIR)/%,$(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o)))

# Libraries and includes
LIB := -L $(LIBDIR) -lcapstone -limagehlp
INC := -I $(INCDIR)

# Default target
$(TARGET): $(OBJECTS)
	@echo " Linking..."
	@if not exist $(BINDIR) mkdir $(BINDIR)
	@echo " $(CC) $(OBJECTS) -o $(TARGET) $(LIB)"
	$(CC) $(OBJECTS) -o $(TARGET) $(LIB)

# Build object files from root directory
$(BUILDDIR)/%.o: $(ROOTDIR)/%.$(SRCEXT)
	@echo " Building $<..."
	@if not exist $(BUILDDIR) mkdir $(BUILDDIR)
	@echo " $(CC) $(CFLAGS) $(INC) -c -o $@ $<"
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

# Build object files from src directory
$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@echo " Building $<..."
	@if not exist $(BUILDDIR) mkdir $(BUILDDIR)
	@echo " $(CC) $(CFLAGS) $(INC) -c -o $@ $<"
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

# Clean build files
clean:
	@echo " Cleaning..."
	@echo " $(RM) -r $(BUILDDIR) $(BINDIR)/pextract.exe"
	$(RM) -r $(BUILDDIR) $(BINDIR)/pextract.exe

.PHONY: clean
