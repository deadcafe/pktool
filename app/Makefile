#
# Copyright (c) 2023 deadcafe.beef@gmail.com All rights reserved.
#
# Unauthorized inspection, duplication, utilization or modification
# of this file is prohibited.  Other related documents, whether
# explicitly marked or implied, may also fall under this copyright.
# Distribution of information obtained from this file and other related
# documents to a third party is not permitted under any circumstances.
#

ifeq ($(origin ROOT),undefined)
ROOT=..

all:
	$(MAKE) -C $(ROOT)

clean:
	$(MAKE) -C $(ROOT) clean-app

else
##############################################################################
# from top dir
##############################################################################
include $(RTE_SDK)/mk/rte.vars.mk

export CONFIG_RTE_LIBRTE_MLX4_PMD=n
export CONFIG_RTE_LIBRTE_MLX5_PMD=n

TARGET := pkttool

APP = $(TARGET)

DC_CPPFLAGS=			\
	-I.			\
	-I$(ROOT)/compat	\
	-I$(ROOT)/engine	\
	-D_GNU_SOURCE		\
	-DDPDK_DIRECT_AP	\
	-D__FastPath__

DC_CFLAGS=	\
	$(OPT_FLAGS) -std=gnu11 -Werror -Wall -W -Wunused -mrtm -mhle

LDLIBS = -lpapi -L$(OUTPUT)/engine/lib -leng

CPPFLAGS += $(DC_CPPFLAGS)
CFLAGS += $(DC_CFLAGS)

SRCS-y := 		\
	global_db.c	\
	task_null.c	\
	task_busy.c	\
	task_rx.c	\
	task_tx.c	\
	task_cmd.c	\
	cmd_perf.c	\
	task_hash.c	\
	task_toeplitz.c	\
	fp-upf_pf-flow.c \
	main.c

#thread_usage.c	\

include $(RTE_SDK)/mk/rte.extapp.mk

##############################################################################
endif
