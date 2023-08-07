/*
 * Copyright (c) 2023 deadcafe.beef@gmail.com All Rights Reserved.
 *
 * Unauthorized inspection, duplication, utilization or modification
 * of this file is prohibited.  Other related documents, whether
 * explicitly marked or implied, may also fall under this copyright.
 * Distribution of information obtained from this file and other related
 * documents to a third party is not permitted under any circumstances.
 */

#ifndef _GLOBALDB_H_
#define _GLOBALDB_H_

extern int
app_global_db_init(void);

extern int
app_global_db_add_task(const struct eng_task_s *task);


#endif /* !_GLOBALDB_H_ */
