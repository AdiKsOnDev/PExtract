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
SRC_SOURCES := $(shell dir /S /B $(SRCDIR)\*.c)
SOURCES := $(SRC_SOURCES) $(ROOT_SOURCES)
OBJECTS := $(patsubst $(ROOTDIR)/%,$(BUILDDIR)/%,$(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o)))

# Libraries and includes
LIB := -L $(LIBDIR) -lcapstone -limagehlp
INC := -I $(INCDIR) -I $(INCDIR)/capstone

# Default target
$(TARGET): $(OBJECTS)
	@echo " Linking..."
	@if not exist $(BINDIR) mkdir $(BINDIR)
	@echo " $(CC) $^ -o $(TARGET) $(LIB)"
	$(CC) $^ -o $(TARGET) $(LIB)

# Build object files from root directory
$(BUILDDIR)/%.o: $(ROOTDIR)/%.$(SRCEXT)
	@echo " Building..."
	@if not exist $(BUILDDIR) mkdir $(BUILDDIR)
	@echo " $(CC) $(CFLAGS) $(INC) -c -o $@ $<"
	$(CC) $(CFLAGS) $(INC) $(LIB) -c -o $(TARGET)

# Build object files from src directory
$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@echo " Building..."
	@if not exist $(BUILDDIR) mkdir $(BUILDDIR)
	@echo " $(CC) $(CFLAGS) $(INC) -c -o $@ $<"
	$(CC) $(CFLAGS) $(INC) $(LIB) -c -o $(TARGET)

# Clean build files
clean:
	@echo " Cleaning..."
	@echo " $(RM) -r $(BUILDDIR) $(BINDIR)/pextract.exe"
	$(RM) -r $(BUILDDIR) $(BINDIR)/pextract.exe

.PHONY: clean
