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
TARGET := $(BINDIR)/pextract

# Source and object files
SRCEXT := c
ROOT_SOURCES := $(wildcard $(ROOTDIR)/*.$(SRCEXT))
SRC_SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
SOURCES := $(ROOT_SOURCES) $(SRC_SOURCES)
OBJECTS := $(patsubst $(ROOTDIR)/%,$(BUILDDIR)/%,$(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o)))

# Libraries and includes
LIB := -L $(LIBDIR) -lcapstone
INC := -I $(INCDIR)

# OS-specific settings
ifeq ($(OS),Windows_NT)
    LIB += -limagehlp
endif

# Default target
$(TARGET): $(OBJECTS)
	@echo " Linking..."
	@mkdir -p $(BINDIR)
	@echo " $(CC) $(OBJECTS) -o $(TARGET) $(LIB)"
	$(CC) $(OBJECTS) -o $(TARGET) $(LIB)

# Build object files from root directory
$(BUILDDIR)/%.o: $(ROOTDIR)/%.$(SRCEXT)
	@echo " Building $<..."
	@mkdir -p $(BUILDDIR)
	@echo " $(CC) $(CFLAGS) $(INC) -c -o $@ $<"
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

# Build object files from src directory
$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@echo " Building $<..."
	@mkdir -p $(BUILDDIR)
	@echo " $(CC) $(CFLAGS) $(INC) -c -o $@ $<"
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

# Clean build files
clean:
	@echo " Cleaning..."
	@echo " $(RM) -r $(BUILDDIR) $(BINDIR)/pextract"
	$(RM) -r $(BUILDDIR) $(BINDIR)/pextract

.PHONY: clean
