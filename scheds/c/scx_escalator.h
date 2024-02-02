#ifndef __SCX_EXAMPLE_ESCALATOR_H
#define __SCX_EXAMPLE_ESCALATOR_H

enum {
	MAX_TASKS		= 8192,
};

struct scx_escalator_enqueued_task {
	int			pid;
};

#endif /* __SCX_EXAMPLE_ESCALATOR_H */
