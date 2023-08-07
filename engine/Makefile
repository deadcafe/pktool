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
	$(MAKE) -C $(ROOT) clean-engine

else
##############################################################################
# from top dir
##############################################################################
include $(RTE_SDK)/mk/rte.vars.mk
#export RTE_OUTPUT=$(OUTPUT)/engine
#export EXTRA_LDFLAGS=


LIB := libeng.a

DC_CPPFLAGS=			\
	-I.			\
	-I$(ROOT)/compat	\
	-D_GNU_SOURCE

DC_CFLAGS=	\
	$(OPT_FLAGS) -std=gnu11 -Werror -Wall -Wextra -Wunused

CPPFLAGS += $(DC_CPPFLAGS)
CFLAGS += $(DC_CFLAGS)

SRCS-y := 		\
	linenoise.c	\
	task_if.c	\
	eng_conf.c	\
	eng_thread.c	\
	eng_mbuf.c	\
	eng_port.c	\
	eng_addon.c	\
	eng_pdump.c	\
	eng_log.c	\
	eng_cmd.c	\
	eng_cli.c	\
	eng_timer.c

#	task_rps.c	\

include $(RTE_SDK)/mk/rte.extlib.mk

##############################################################################
endif
