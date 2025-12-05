KDIR       := /usr/src/kernel-6.18.0

KIMG       := $(KDIR)/arch/x86/boot/bzImage

BOOTDIR    := /boot
KVER       := 6.18.0-get-pid-info

TARGET_IMG  := $(BOOTDIR)/vmlinuz-$(KVER)

PATCH       := patch.diff

TEST_SRC := src/test.c
TEST_BIN := test

all: copy patch_kernel build install reboot

tester: $(TEST_BIN)

$(TEST_BIN): $(TEST_SRC)
	gcc -Wall -Wextra -Werror -Iinclude $< -o $@

copy:
	cp src/get_pid_info.c  $(KDIR)/kernel/get_pid_info.c
	cp include/pid_info.h  $(KDIR)/include/uapi/linux/pid_info.h

patch_kernel:
	git -C $(KDIR) apply $(PWD)/patch.diff || true

build:
	$(MAKE) -C $(KDIR)

install:
	$(MAKE) -C $(KDIR) modules_install
	cp $(KIMG)  $(TARGET_IMG)

reboot:
	/sbin/reboot

clean:
	rm -f $(TEST_BIN)

.PHONY: all tester copy patch_kernel build install reboot clean
