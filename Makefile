#
# Copyright (c) 2023 deadcafe.beef@gmail.com All rights reserved.
#
# Unauthorized inspection, duplication, utilization or modification
# of this file is prohibited.  Other related documents, whether
# explicitly marked or implied, may also fall under this copyright.
# Distribution of information obtained from this file and other related
# documents to a third party is not permitted under any circumstances.
#

export LC_ALL=C

export ROOT=$(CURDIR)
export BUILD_DIR=output/dpdk-app
export OUTPUT=$(ROOT)/../../$(BUILD_DIR)

export RTE_SDK=$(ROOT)/../../output/_packages/dpdk/devel/usr/share/dpdk
export RTE_TARGET=x86_64-native-linuxapp-gcc
export RTE_OUTPUT=$(OUTPUT)

export CPU_LDFLAGS = -L$(ROOT)/../../output/_packages/dpdk/devel/usr/lib64

OPT_FLAGS ?= -g -O3
export OPT_FLAGS

DPDK_CONFIG=x86_64-native-linuxapp-gcc

JX ?= -j4

#
# build options
#
.PHONY:	all clean

all:	app

clean:	clean-engine clean-app


#
# Engine
#
.PHONY:	engine clean-engine

engine:
	$(MAKE) $(JX) -C engine all

clean-engine:
	$(MAKE) $(JX) -C engine clean

#
# App
#
.PHONY:	app clean-app

app:	engine
	$(MAKE) $(JX) -C app all

clean-app:
	$(MAKE) $(JX) -C app clean
