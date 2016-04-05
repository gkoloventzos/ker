/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * Derived from arch/arm/kvm/handle_exit.c:
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/esr.h>
#include <asm/kvm_coproc.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_psci.h>

#define CREATE_TRACE_POINTS
#include "trace.h"

typedef int (*exit_handle_fn)(struct kvm_vcpu *, struct kvm_run *);
extern bool enable_trap_stats;

static const char* trap_stat_names[TRAP_STAT_NR] = {
       [TRAP_HVC] = "TRAP HVC",
       [TRAP_WFX] = "TRAP WFX",
       [TRAP_IO_KERNEL] = "TRAP IO_KERNEL",
       [TRAP_IO_USER] = "TRAP IO_USER",
       [TRAP_IRQ] = "TRAP IRQ",
       [TRAP_TOTAL] = "TRAP TOTAL",
       [TRAP_GUEST] = "TRAP GUEST",
	[TRAP_EL2] = "TRAP EL2",
	[TRAP_NON_VCPU] = "TRAP NON-VCPU",
};

static void print_vcpu_trap_stats(struct kvm_vcpu *vcpu)
{
       int i;

       printk("vcpu id %d\n", vcpu->vcpu_id);
       for (i = 0; i < TRAP_STAT_NR; i++)
		printk("%s CYCLE %lu number: %lu\n",
                               trap_stat_names[i],
                               vcpu->stat.trap_stat[i]
				vcpu->stat.trap_number[i]);
	printk("TRAP IN %lu\n", vcpu->stat.hvsr_top_cc);
	printk("TRAP BACK %lu\n", vcpu->stat.hvsr_back_cc);
}

static void print_all_vcpu_trap_stats(struct kvm_vcpu *vcpu)
{
       struct kvm_vcpu *v;
       int r;

       kvm_for_each_vcpu(r, v, vcpu->kvm)
               print_vcpu_trap_stats(v);
}


static int handle_hvc(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int ret;
       uint32_t tmp;

       vcpu->stat.prev_trap_type = TRAP_HVC;
       /*
        * Enable cycle counter for Xen - we choose to be compatible but rely
        * on running measurement guests under perf on the KVM host.
        */
       if (*vcpu_reg(vcpu, 0) == 0x4b000001) {

               asm volatile(   "mrs %0, PMCR_EL0\n"
                               "orr %0, %0, #1\n"
                               "orr %0, %0, #(1 << 2)\n"
                               "bic %0, %0, #(1 << 3)\n"
                               "msr PMCR_EL0, %0\n"
                               "mov %0, #0b11111\n"
                               "msr PMSELR_EL0, %0\n"
                               "isb \n"
                               "mrs %0, PMXEVTYPER_EL0\n"
                               "orr %0, %0, #(1 << 27)\n"
                               "bic %0, %0, #(3 << 30)\n"
                               "bic %0, %0, #(3 << 28)\n"
                               "msr PMXEVTYPER_EL0, %0\n"
                               "mrs %0, PMCNTENSET_EL0\n"
                               "orr %0, %0, #(1 << 31)\n"
                               "msr PMCNTENSET_EL0, %0\n"
                               : "=r" (tmp));
               isb();

               return 1;
       }

       /* NOOP hvc call to measure hypercall turn-around time */
       if (*vcpu_reg(vcpu, 0) == 0x4b000000) {
               return 1;
	}
	else if (*vcpu_reg(vcpu, 0) == 0x20000) {
               *vcpu_reg(vcpu, 0) = vcpu->stat.hvsr_top_cc;
               return 1;
	} else if (*vcpu_reg(vcpu, 0) == 0x30000) {
               return 1;
	}
       /* Trap stat enable */
       if (*vcpu_reg(vcpu, 0) == 0x10000) {
               init_trap_stats(vcpu);
		isb();
               enable_trap_stats = true;
               return 1;
       }

       /* Trap stat disable & print out stats */
       if (*vcpu_reg(vcpu, 0) == 0x11000) {
               enable_trap_stats = false;
		isb();
               print_all_vcpu_trap_stats(vcpu);
               return 1;
       }

	trace_kvm_hvc_arm64(*vcpu_pc(vcpu), vcpu_get_reg(vcpu, 0),
			    kvm_vcpu_hvc_get_imm(vcpu));

	ret = kvm_psci_call(vcpu);
	if (ret < 0) {
		kvm_inject_undefined(vcpu);
		return 1;
	}

	return ret;
}

static int handle_smc(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	kvm_inject_undefined(vcpu);
	return 1;
}

/**
 * kvm_handle_wfx - handle a wait-for-interrupts or wait-for-event
 *		    instruction executed by a guest
 *
 * @vcpu:	the vcpu pointer
 *
 * WFE: Yield the CPU and come back to this vcpu when the scheduler
 * decides to.
 * WFI: Simply call kvm_vcpu_block(), which will halt execution of
 * world-switches and schedule other host processes until there is an
 * incoming IRQ or FIQ to the VM.
 */
static int kvm_handle_wfx(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	vcpu->stat.prev_trap_type = TRAP_WFX;
	if (kvm_vcpu_get_hsr(vcpu) & ESR_ELx_WFx_ISS_WFE) {
		trace_kvm_wfx_arm64(*vcpu_pc(vcpu), true);
		kvm_vcpu_on_spin(vcpu);
	} else {
		trace_kvm_wfx_arm64(*vcpu_pc(vcpu), false);
		kvm_vcpu_block(vcpu);
	}

	kvm_skip_instr(vcpu, kvm_vcpu_trap_il_is32bit(vcpu));

	return 1;
}

/**
 * kvm_handle_guest_debug - handle a debug exception instruction
 *
 * @vcpu:	the vcpu pointer
 * @run:	access to the kvm_run structure for results
 *
 * We route all debug exceptions through the same handler. If both the
 * guest and host are using the same debug facilities it will be up to
 * userspace to re-inject the correct exception for guest delivery.
 *
 * @return: 0 (while setting run->exit_reason), -1 for error
 */
static int kvm_handle_guest_debug(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	u32 hsr = kvm_vcpu_get_hsr(vcpu);
	int ret = 0;

	run->exit_reason = KVM_EXIT_DEBUG;
	run->debug.arch.hsr = hsr;

	switch (hsr >> ESR_ELx_EC_SHIFT) {
	case ESR_ELx_EC_WATCHPT_LOW:
		run->debug.arch.far = vcpu->arch.fault.far_el2;
		/* fall through */
	case ESR_ELx_EC_SOFTSTP_LOW:
	case ESR_ELx_EC_BREAKPT_LOW:
	case ESR_ELx_EC_BKPT32:
	case ESR_ELx_EC_BRK64:
		break;
	default:
		kvm_err("%s: un-handled case hsr: %#08x\n",
			__func__, (unsigned int) hsr);
		ret = -1;
		break;
	}

	return ret;
}

static exit_handle_fn arm_exit_handlers[] = {
	[ESR_ELx_EC_WFx]	= kvm_handle_wfx,
	[ESR_ELx_EC_CP15_32]	= kvm_handle_cp15_32,
	[ESR_ELx_EC_CP15_64]	= kvm_handle_cp15_64,
	[ESR_ELx_EC_CP14_MR]	= kvm_handle_cp14_32,
	[ESR_ELx_EC_CP14_LS]	= kvm_handle_cp14_load_store,
	[ESR_ELx_EC_CP14_64]	= kvm_handle_cp14_64,
	[ESR_ELx_EC_HVC32]	= handle_hvc,
	[ESR_ELx_EC_SMC32]	= handle_smc,
	[ESR_ELx_EC_HVC64]	= handle_hvc,
	[ESR_ELx_EC_SMC64]	= handle_smc,
	[ESR_ELx_EC_SYS64]	= kvm_handle_sys_reg,
	[ESR_ELx_EC_IABT_LOW]	= kvm_handle_guest_abort,
	[ESR_ELx_EC_DABT_LOW]	= kvm_handle_guest_abort,
	[ESR_ELx_EC_SOFTSTP_LOW]= kvm_handle_guest_debug,
	[ESR_ELx_EC_WATCHPT_LOW]= kvm_handle_guest_debug,
	[ESR_ELx_EC_BREAKPT_LOW]= kvm_handle_guest_debug,
	[ESR_ELx_EC_BKPT32]	= kvm_handle_guest_debug,
	[ESR_ELx_EC_BRK64]	= kvm_handle_guest_debug,
};

static exit_handle_fn kvm_get_exit_handler(struct kvm_vcpu *vcpu)
{
	u32 hsr = kvm_vcpu_get_hsr(vcpu);
	u8 hsr_ec = hsr >> ESR_ELx_EC_SHIFT;

	if (hsr_ec >= ARRAY_SIZE(arm_exit_handlers) ||
	    !arm_exit_handlers[hsr_ec]) {
		kvm_err("Unknown exception class: hsr: %#08x -- %s\n",
			hsr, esr_get_class_string(hsr));
		BUG();
	}

	return arm_exit_handlers[hsr_ec];
}

/*
 * Return > 0 to return to guest, < 0 on error, 0 (and set exit_reason) on
 * proper exit to userspace.
 */
int handle_exit(struct kvm_vcpu *vcpu, struct kvm_run *run,
		       int exception_index)
{
	exit_handle_fn exit_handler;

	switch (exception_index) {
	case ARM_EXCEPTION_IRQ:
		return 1;
	case ARM_EXCEPTION_TRAP:
		/*
		 * See ARM ARM B1.14.1: "Hyp traps on instructions
		 * that fail their condition code check"
		 */
		if (!kvm_condition_valid(vcpu)) {
			kvm_skip_instr(vcpu, kvm_vcpu_trap_il_is32bit(vcpu));
			return 1;
		}

		exit_handler = kvm_get_exit_handler(vcpu);

		return exit_handler(vcpu, run);
	default:
		kvm_pr_unimpl("Unsupported exception type: %d",
			      exception_index);
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		return 0;
	}
}
