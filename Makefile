# Compiler and flags
CC := gcc
CFLAGS := -Wall -g -O3 -mconsole

# Directories
SRCDIR := src
BUILDDIR := build
BINDIR := bin
INCDIR := include
LIBDIR := lib

# Target
TARGET := $(BINDIR)/pextract

# Source and object files
SRCEXT := c
SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))

# Libraries and includes
LIB := -L $(LIBDIR) -lcapstone -limagehlp
INC := -I $(INCDIR)

# Default target
$(TARGET): $(OBJECTS)
	@echo " Linking..."
	@mkdir -p $(BINDIR)
	@echo " $(CC) $(OBJECTS) -o $(TARGET) $(LIB)"
	$(CC) $(OBJECTS) -o $(TARGET) $(LIB)

# Build object files
$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@echo " Building..."
	@mkdir -p $(BUILDDIR)
	@echo " $(CC) $(CFLAGS) $(INC) -c -o $@ $<"
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

# Clean build files
clean:
	@echo " Cleaning..."
	@echo " $(RM) -r $(BUILDDIR) $(BINDIR)/pextract"
	$(RM) -r $(BUILDDIR) $(BINDIR)/pextract

.PHONY: clean
