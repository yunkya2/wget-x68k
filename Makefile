#
# Copyright (c) 2026 Yuichi Nakamura (@yunkya2)
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

TARGET := wget.x

all: $(TARGET)

CROSS_COMPILE ?= m68k-xelf-
USE_SSL ?= 1

CC = $(CROSS_COMPILE)gcc
LD = $(CC)

GIT_REPO_VERSION=$(shell git describe --tags --always)

CFLAGS = -Wall -O3 -g $(INC) $(DEFS) -MMD -MP
CFLAGS += -DGIT_REPO_VERSION=\"$(GIT_REPO_VERSION)\"
CFLAGS += -DUSE_SSL=$(USE_SSL)
LDFLAGS = $(LIBS)
LIBS = -lsocket

AXTLS_DIR = axtls
AXTLS_INCLUDE = axtls-include

INC += -I. -I$(AXTLS_INCLUDE) -I$(AXTLS_DIR)/ssl -I$(AXTLS_DIR)/crypto
DEFS += -DCONFIG_M68K_ASM

SRCS := wget.c

$(AXTLS_DIR)/%.o: CFLAGS += -Wno-all

SRCS += $(addprefix $(AXTLS_DIR)/, \
	ssl/asn1.c \
	ssl/loader.c \
	ssl/tls1.c \
	ssl/tls1_svr.c \
	ssl/tls1_clnt.c \
	ssl/x509.c \
	crypto/aes.c \
	crypto/bigint.c \
	crypto/crypto_misc.c \
	crypto/hmac.c \
	crypto/md5.c \
	crypto/rsa.c \
	crypto/sha1.c \
	crypto/sha256.c \
)

OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJS)
	$(LD) -o $@ $^ $(LDFLAGS)

linux unix:
	$(MAKE) CROSS_COMPILE= LIBS= DEFS=-UCONFIG_M68K_ASM

clean:
	-rm -f $(OBJS) $(DEPS) $(TARGET) $(TARGET).elf

-include $(DEPS)

.PHONY: all clean linux unix
