/*
 * Copyright (c) 2023 deadcafe.beef@gmail.com All Rights Reserved.
 *
 * Unauthorized inspection, duplication, utilization or modification
 * of this file is prohibited.  Other related documents, whether
 * explicitly marked or implied, may also fall under this copyright.
 * Distribution of information obtained from this file and other related
 * documents to a third party is not permitted under any circumstances.
 */

#include <errno.h>

#include <eng_thread.h>
#include <eng_addon.h>
#include <eng_cmd.h>

#include "app_modules.h"
#include "global_db.h"
#include "task_perf.h"

static int
PerfTaskInit(struct eng_conf_db_s *conf __rte_unused,
             struct eng_thread_s *th __rte_unused,
             struct eng_task_s *task __rte_unused)
{
    return 0;
}

static unsigned
PerfTaskEntry(struct eng_thread_s *th __rte_unused,
              struct eng_task_s *task,
              uint64_t now __rte_unused)
{
        
}

static const struct eng_addon_s Addon = {
    .name       = "TkPerf",
    .task_init  = PerfTaskInit,
    .task_entry = PerfTaskEntry,
};

static struct eng_addon_constructor_s AddonConstructor = {
    .addon = &Addon,
};

void
app_task_cmd_register(void)
{
    eng_addon_register(&AddonConstructor);
}
