CXX      := g++
CXXFLAGS := -std=c++17 -O3 -Wall -Wextra -I/usr/include/eigen3
LIBS     := -lpcap -lpthread

TARGET  := beamcannon
SRCDIR  := src
OBJDIR  := build

SRCS := $(wildcard $(SRCDIR)/*.cpp)
OBJS := $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(SRCS))

.PHONY: all clean install

all: $(OBJDIR) $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	@echo "[+] Built: $(TARGET)"

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET)

install: all
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)
	@echo "[+] Installed to /usr/local/bin/$(TARGET)"
