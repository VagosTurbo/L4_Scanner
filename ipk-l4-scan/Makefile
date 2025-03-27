# Compiler and flags
CSC = dotnet
BUILD_FLAGS = build -c Release
PUBLISH_FLAGS = publish -c Release -r linux-x64 --self-contained true -o .

# Target executable name
TARGET = ipk-l4-scan

# Output directory
OUT_DIR = bin/Release/net9.0/linux-x64/publish

.PHONY: all clean build publish

all: $(TARGET)

$(TARGET): clean
	$(CSC) $(PUBLISH_FLAGS)

build:
	$(CSC) $(BUILD_FLAGS)

publish: $(TARGET)

clean:
	rm -rf bin/ obj/
	rm -f $(TARGET)
	rm -f *.dll *.pdb *.runtimeconfig.json *.deps.json *.so createdump

run: $(TARGET)
	sudo ./$(TARGET) 