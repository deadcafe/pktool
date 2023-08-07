/*
 * Copyright (c) 2023 deadcafe.beef@gmail.com All Rights Reserved.
 *
 * Unauthorized inspection, duplication, utilization or modification
 * of this file is prohibited.  Other related documents, whether
 * explicitly marked or implied, may also fall under this copyright.
 * Distribution of information obtained from this file and other related
 * documents to a third party is not permitted under any circumstances.
 */

#ifndef _TASK_BUSY_H_
#define _TASK_BUSY_H_

extern void
app_task_busy_register(void);


enum busy_type_e {
    TYPE_SPINLOCK,
    TYPE_CAS,
    TYPE_ATOMIC,
    TYPE_HLE,
    TYPE_RTM,
};

extern int
app_task_busy_set_type(enum busy_type_e);

extern void
app_task_busy_set_nb(unsigned);

#endif /* !_TASK_BUSY_H_ */
