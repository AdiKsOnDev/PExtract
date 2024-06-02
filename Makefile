CC := gcc
SRCDIR := src
BUILDDIR := build
BINDIR := bin
TARGET := $(BINDIR)/pextract
SRCEXT := c
SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))
CFLAGS := -Wall -g -O3
LIB := -L lib -lcapstone -limagehlp
INC := -I include

$(TARGET): $(OBJECTS)
	@echo " Linking..."
	@mkdir -p $(BINDIR)
	@echo " $(CC) $(OBJECTS) -o $(TARGET) $(LIB)"
	$(CC) $(OBJECTS) -o $(TARGET) $(LIB)

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@echo " Building..."
	@mkdir -p $(BUILDDIR)
	@echo " $(CC) $(CFLAGS) $(INC) -c -o $@ $<"
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean:
	@echo " Cleaning..."
	@echo " $(RM) -r $(BUILDDIR) $(BINDIR)/pextract"
	$(RM) -r $(BUILDDIR) $(BINDIR)/pextract

.PHONY: clean
