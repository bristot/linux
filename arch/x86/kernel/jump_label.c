// SPDX-License-Identifier: GPL-2.0
/*
 * jump label x86 support
 *
 * Copyright (C) 2009 Jason Baron <jbaron@redhat.com>
 *
 */
#include <linux/jump_label.h>
#include <linux/memory.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/cpu.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <asm/kprobes.h>
#include <asm/alternative.h>
#include <asm/text-patching.h>

#ifdef HAVE_JUMP_LABEL

union jump_code_union {
	char code[JUMP_LABEL_NOP_SIZE];
	struct {
		char jump;
		int offset;
	} __attribute__((packed));
};

static void bug_at(unsigned char *ip, int line)
{
	/*
	 * The location is not an op that we were expecting.
	 * Something went wrong. Crash the box, as something could be
	 * corrupting the kernel.
	 */
	pr_crit("jump_label: Fatal kernel bug, unexpected op at %pS [%p] (%5ph) %d\n", ip, ip, ip, line);
	BUG();
}

static void inline __jump_label_enabling_check(struct jump_entry *entry,
					 enum jump_label_type type,
					 int init)
{
	const unsigned char default_nop[] = { STATIC_KEY_INIT_NOP };
	const unsigned char *ideal_nop = ideal_nops[NOP_ATOMIC5];

	if (init) {
		/*
		 * Jump label is enabled for the first time.
		 * So we expect a default_nop...
		 */
		if (unlikely(memcmp((void *)entry->code, default_nop, 5)
			     != 0))
			bug_at((void *)entry->code, __LINE__);
	} else {
		/*
		 * ...otherwise expect an ideal_nop. Otherwise
		 * something went horribly wrong.
		 */
		if (unlikely(memcmp((void *)entry->code, ideal_nop, 5)
			     != 0))
			bug_at((void *)entry->code, __LINE__);
	}
}

static void inline  __jump_label_disabling_check(struct jump_entry *entry,
					 enum jump_label_type type,
					 int init)
{
	union jump_code_union code;
	const unsigned char default_nop[] = { STATIC_KEY_INIT_NOP };

	/*
	 * We are disabling this jump label. If it is not what
	 * we think it is, then something must have gone wrong.
	 * If this is the first initialization call, then we
	 * are converting the default nop to the ideal nop.
	 */
	if (init) {
		if (unlikely(memcmp((void *)entry->code, default_nop, 5) != 0))
			bug_at((void *)entry->code, __LINE__);
	} else {
		code.jump = 0xe9;
		code.offset = entry->target -
			(entry->code + JUMP_LABEL_NOP_SIZE);
		if (unlikely(memcmp((void *)entry->code, &code, 5) != 0))
			bug_at((void *)entry->code, __LINE__);
	}
}

static void __jump_label_set_jump_code(struct jump_entry *entry,
				     enum jump_label_type type,
				     int init,
				     union jump_code_union *code)
{
	if (type == JUMP_LABEL_JMP) {
		__jump_label_enabling_check(entry, type, init);

		code->jump = 0xe9;
		code->offset = entry->target - (entry->code + JUMP_LABEL_NOP_SIZE);
	} else {
		__jump_label_disabling_check(entry, type, init);
		memcpy(code, ideal_nops[NOP_ATOMIC5], JUMP_LABEL_NOP_SIZE);
	}
}

static void __ref __jump_label_transform(struct jump_entry *entry,
					 enum jump_label_type type,
					 void *(*poker)(void *, const void *, size_t),
					 int init)
{
	union jump_code_union code;

	if (early_boot_irqs_disabled)
		poker = text_poke_early;

	__jump_label_set_jump_code(entry, type, init, &code);

	/*
	 * Make text_poke_bp() a default fallback poker.
	 *
	 * At the time the change is being done, just ignore whether we
	 * are doing nop -> jump or jump -> nop transition, and assume
	 * always nop being the 'currently valid' instruction
	 *
	 */
	if (poker)
		(*poker)((void *)entry->code, &code, JUMP_LABEL_NOP_SIZE);
	else
		text_poke_bp((void *)entry->code, &code, JUMP_LABEL_NOP_SIZE,
			     (void *)entry->code + JUMP_LABEL_NOP_SIZE);
}

void arch_jump_label_transform(struct jump_entry *entry,
			       enum jump_label_type type)
{
	mutex_lock(&text_mutex);
	__jump_label_transform(entry, type, NULL, 0);
	mutex_unlock(&text_mutex);
}

LIST_HEAD(batch_list);

void arch_jump_label_transform_queue(struct jump_entry *entry,
				     enum jump_label_type type)
{
	struct text_to_poke *tp;

	/*
	 * Batch mode disabled at boot time.
	 */
	if (early_boot_irqs_disabled) {
		arch_jump_label_transform(entry, type);
		return;
	}

	tp = kzalloc(sizeof(struct text_to_poke), GFP_KERNEL);
	BUG_ON(!tp);

	tp->opcode = kzalloc(sizeof(union jump_code_union), GFP_KERNEL);
	BUG_ON(!tp->opcode);

	__jump_label_set_jump_code(entry, type, 0, tp->opcode);
	tp->addr = (void *) entry->code;
	tp->len = JUMP_LABEL_NOP_SIZE;
	tp->handler = (void *) entry->code + JUMP_LABEL_NOP_SIZE;

	list_add_tail(&tp->list, &batch_list);
}

void arch_jump_label_transform_apply(void)
{
	struct text_to_poke *tp, *next;

	if (early_boot_irqs_disabled)
		return;

	mutex_lock(&text_mutex);
	text_poke_bp_list(&batch_list);
	mutex_unlock(&text_mutex);

	list_for_each_entry_safe(tp, next, &batch_list, list) {
		list_del(&tp->list);
		kfree(tp->opcode);
		kfree(tp);
	}
}

static enum {
	JL_STATE_START,
	JL_STATE_NO_UPDATE,
	JL_STATE_UPDATE,
} jlstate __initdata_or_module = JL_STATE_START;

__init_or_module void arch_jump_label_transform_static(struct jump_entry *entry,
				      enum jump_label_type type)
{
	/*
	 * This function is called at boot up and when modules are
	 * first loaded. Check if the default nop, the one that is
	 * inserted at compile time, is the ideal nop. If it is, then
	 * we do not need to update the nop, and we can leave it as is.
	 * If it is not, then we need to update the nop to the ideal nop.
	 */
	if (jlstate == JL_STATE_START) {
		const unsigned char default_nop[] = { STATIC_KEY_INIT_NOP };
		const unsigned char *ideal_nop = ideal_nops[NOP_ATOMIC5];

		if (memcmp(ideal_nop, default_nop, 5) != 0)
			jlstate = JL_STATE_UPDATE;
		else
			jlstate = JL_STATE_NO_UPDATE;
	}
	if (jlstate == JL_STATE_UPDATE)
		__jump_label_transform(entry, type, text_poke_early, 1);
}

#endif
