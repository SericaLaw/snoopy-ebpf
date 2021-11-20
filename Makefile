TARGET := runsnoopy
TARGET_BPF := snoopy.bpf.o

GO_SRC := *.go
BPF_SRC := snoopy/snoopy.bpf.c

LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_DIST_DIR := $(abspath ./libbpf/dist)
LIBBPF_HEADERS := $(LIBBPF_DIST_DIR)/libbpf/usr/include
LIBBPF_OBJ := $(LIBBPF_DIST_DIR)/libbpf/libbpf.a

$(LIBBPF_DIST_DIR):
	mkdir -p $@

$(LIBBPF_SRC):
	test -d $(LIBBPF_SRC) || (echo "missing libbpf source - maybe do 'git submodule init && git submodule update'" ; false)

$(LIBBPF_HEADERS) $(LIBBPF_HEADERS)/bpf $(LIBBPF_HEADERS)/linux: | $(OUT_DIR) $(LIBBPF_SRC)
	cd $(LIBBPF_SRC) && $(MAKE) install_headers install_uapi_headers DESTDIR=$(abspath $(LIBBPF_DIST_DIR))/libbpf

$(LIBBPF_OBJ): | $(LIBBPF_DIST_DIR) $(LIBBPF_SRC)
	cd $(LIBBPF_SRC) && $(MAKE) OBJDIR=$(abspath $(LIBBPF_DIST_DIR))/libbpf BUILD_STATIC_ONLY=1

.PHONY: all
all: $(LIBBPF_HEADERS) $(LIBBPF_OBJ) $(TARGET) $(TARGET_BPF)

go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_OBJ)"
$(TARGET): $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ)
	$(go_env) go build -o $(TARGET)

$(TARGET_BPF): $(BPF_SRC) $(LIBBPF_HEADERS)
	clang \
		-O2 -c -target bpf \
		-o $@ $<

.PHONY: clean
clean:
	go clean
