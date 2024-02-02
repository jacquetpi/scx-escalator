/* SPDX-License-Identifier: GPL-2.0 */
/*
 * An escalator scheduler.
 *
 * By default, it operates as a escalator global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;
const volatile bool switch_partial;

struct user_exit_info uei;

#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

s32 BPF_STRUCT_OPS(escalator_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags){
	return 0;
}

void BPF_STRUCT_OPS(escalator_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);	/* count global queueing */
	scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
		
}

void BPF_STRUCT_OPS(escalator_dispatch, s32 cpu, struct task_struct *prev)
{
	if (cpu>0)
		return;
	scx_bpf_consume(SCX_DSQ_GLOBAL);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(escalator_init)
{
	scx_bpf_switch_all();
	return 0;
}

void BPF_STRUCT_OPS(escalator_exit, struct scx_exit_info *ei)
{
	uei_record(&uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops escalator_ops = {
	.select_cpu		= (void *)escalator_select_cpu,
	.enqueue		= (void *)escalator_enqueue,
	.dispatch		= (void *)escalator_dispatch,
	.init			= (void *)escalator_init,
	.exit			= (void *)escalator_exit,
	.name			= "escalator",
};
