/*
 * Measure cycles to perform various operations as an ARM(64) VM guest
 *
 * Copyright (C) 2015 Columbia University
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
 *
 *
 * This code is not meant for upstream but as a testig framework for measuring
 * performance of ARM(64) hypervisors, such as KVM and Xen.
 *
 * Requirements:
 *  - The host must allow direct or emulated access to the cycle counter and
 *    set the cycle counter to count in NS-EL1 and NS-EL2.  Direct hardware
 *    access is strongly recommended for meaningful results.
 *
 *  - The host provisions a NOOP hypercall.  Current method relies on placing
 *    a predefined value in r0/x0 when doing an HVC call.  See the HVC_
 *    defines below.
 */
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/kvm_host.h>
#include <linux/virt_test.h>
#include <linux/proc_fs.h>
#include <asm/io.h>
#include <asm/hypervisor.h>
#include <asm/xen/hypercall.h>

#define HVC_NOOP		0x4b000000
#define HVC_CCNT_ENABLE		0x4b000001
#define HVC_VMSWITCH_SEND	0x4b000010
#define HVC_VMSWITCH_RCV	0x4b000020
#define HVC_VMSWITCH_DONE	0x4b000030
#define HVC_IOLATENCY_END	0x4b000040
#define TRAP_MEASURE_START	0x10000
#define TRAP_MEASURE_END	0x11000

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
static void *mmio_read_user_addr;
static void *vgic_dist_addr;
static void *vgic_cpu_addr;
#endif

volatile int cpu1_ipi_ack;
extern int simpleif_request_dummy(void);

#ifndef CONFIG_ARM64
#ifdef CONFIG_ARM
__asm__(".arch_extension	virt");
#endif
#endif


#define GOAL (1ULL << 28)
#define for_each_test(_iter, _tests, _tmp) \
	for (_tmp = 0, _iter = _tests; \
	     _tmp < ARRAY_SIZE(_tests); \
	     _tmp++, _iter++)

#define CYCLE_COUNT(c1, c2) \
	((c1) > (c2)) ? 0 : (c2) - (c1)

#define PROCFS_MAX_SIZE 128
#define MAX_MSG_LEN 512

//#define FOR_XEN

u64 inline call_hyp(void *hypfn)
{
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	return kvm_call_hyp(hypfn);
#elif defined(CONFIG_X86_64)
#ifndef FOR_XEN
	unsigned long b, c, d;
	asm volatile ("vmcall" : "+hypfn"(hypfn), "=b"(b), "=c"(c), "=d"(d));
#else
	_hypercall2(long, dummy_hyp, 0, 0);
#endif
#endif
	/* We don't really use the return value on x86 */
	return 0;
}

static __always_inline volatile unsigned long read_cc(void)
{
	unsigned long cc;
#ifdef CONFIG_ARM64
	isb();
	asm volatile("mrs %0, PMCCNTR_EL0" : "=r" (cc) ::);
	isb();
#elif defined(CONFIG_ARM)
	asm volatile("mrc p15, 0, %[reg], c9, c13, 0": [reg] "=r" (cc));
#elif defined(CONFIG_X86_64)
	rdtscll(cc);
#endif
	return cc;
}

static noinline void __noop(void)
{
}

static __always_inline volatile unsigned long read_cc_before(void)
{
        unsigned long cc;
#ifdef CONFIG_ARM64
        isb();
        asm volatile("mrs %0, PMCCNTR_EL0" : "=r" (cc) ::);
        isb();
#elif defined(CONFIG_ARM)
        asm volatile("mrc p15, 0, %[reg], c9, c13, 0": [reg] "=r" (cc));
#elif defined(CONFIG_X86_64)
        asm volatile ("CPUID\n\t"::: "%rax", "%rbx", "%rcx", "%rdx");
        asm volatile ( "RDTSC\n\t"
                        "shl $0x20, %%rdx\n\t"
                        "or %%rax, %%rdx\n\t"
                        "mov %%rdx, %0\n\t"
                        : "=r" (cc)
                        :: "%rax", "%rbx", "%rcx", "%rdx");
#endif
        return cc;
}

static __always_inline volatile unsigned long read_cc_after(void)
{
        unsigned long cc;
#ifdef CONFIG_ARM64
        isb();
        asm volatile("mrs %0, PMCCNTR_EL0" : "=r" (cc) ::);
        isb();
#elif defined(CONFIG_ARM)
        asm volatile("mrc p15, 0, %[reg], c9, c13, 0": [reg] "=r" (cc));
#elif defined(CONFIG_X86_64)
        asm volatile (
                        "mov %%cr0, %%rax\n\t"
                        "mov %%rax, %%cr0\n\t"
                        "RDTSC\n\t"
                        "shl $0x20, %%rdx\n\t"
                        "or %%rax, %%rdx\n\t"
                        "mov %%rdx, %0\n\t"
                        : "=r" (cc)
                        :: "%rax", "%rdx");
#endif
        return cc;
}

#define GICC_EOIR		0x00000010
extern void smp_send_virttest(int cpu);

void send_and_wait_ipi(void)
{
	int cpu;
	unsigned long timeout = 1U << 28;

	cpu1_ipi_ack = 0;
	for_each_online_cpu(cpu) {
		if (cpu == smp_processor_id())
			continue;
		else {
			smp_send_virttest(cpu);
			break;
		}
	}
	while (!cpu1_ipi_ack && timeout--);

	if (!cpu1_ipi_ack)
		pr_warn("ipi received failed\n");

	return;
}

static unsigned long ipi_test(void)
{
	unsigned long ret, cc_before, cc_after;
	unsigned long flags;

	local_irq_save(flags);
	cc_before = read_cc_before();
	send_and_wait_ipi();
	cc_after = read_cc_after();
	local_irq_restore(flags);
	ret = CYCLE_COUNT(cc_before, cc_after);

	return ret;

}

static unsigned long hvc_test(void)
{
	unsigned long ret, cc_before, cc_after;
	unsigned long flags;

	local_irq_save(flags);
	cc_before = read_cc_before();
	call_hyp((void*)HVC_NOOP);
	cc_after = read_cc_after();
	local_irq_restore(flags);
	ret = CYCLE_COUNT(cc_before, cc_after);

	return ret;
}

static unsigned long noop_test(void)
{
	unsigned long ret, cc_before, cc_after;
	unsigned long flags;

	local_irq_save(flags);
	cc_before = read_cc_before();
	__noop();
	cc_after = read_cc_after();
	local_irq_restore(flags);
	ret = CYCLE_COUNT(cc_before, cc_after);

	return ret;
}

static unsigned long mmio_user(void)
{
	unsigned long ret, cc_before, cc_after;

	cc_before = read_cc_before();
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	readl(mmio_read_user_addr + 0x8); // MMIO USER
#elif defined(CONFIG_X86_64)
	inl(0x1234);
#endif
	cc_after = read_cc_after();
	ret = CYCLE_COUNT(cc_before, cc_after);
	return ret;
}


static unsigned long mmio_kernel(void)
{
	unsigned long ret, cc_before, cc_after;
	unsigned long flags;

	local_irq_save(flags);
	cc_before = read_cc_before();
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	readl(vgic_dist_addr + 0x8); /* GICD_IIDR */
#elif defined(CONFIG_X86_64)
	//val = apic_read(APIC_ID);
	inb(0x4d0);
#endif
	cc_after = read_cc_after();
	local_irq_restore(flags);
	ret = CYCLE_COUNT(cc_before, cc_after);

	return ret;
}

static unsigned long eoi_test(void)
{
	unsigned long ret, cc_before, cc_after;
	u32 val;

	unsigned long flags;
	val = 1023;
	local_irq_save(flags);
	cc_before = read_cc_before();
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	writel(val, vgic_cpu_addr + GICC_EOIR);
#elif defined(CONFIG_X86_64)
	apic_write(APIC_EOI, APIC_EOI_ACK);
#endif
	cc_after = read_cc_after();
	local_irq_restore(flags);
	ret = CYCLE_COUNT(cc_before, cc_after);

	return ret;
}

static unsigned long trap_out_test(void)
{
	unsigned long flags;
	unsigned long trap_out = 0;
	unsigned long before_hvc= 0, soh = 0, after_hvc = 0;
#ifdef CONFIG_ARM64
	unsigned long eoh = 0; /* end of hyp */
#endif

	before_hvc = 0, soh = 0, after_hvc = 0;
	local_irq_save(flags);
#ifdef CONFIG_ARM64
	asm volatile(
			"mov x0, #0x10000\n\t"
			"isb\n\t"
			"mrs x3 , PMCCNTR_EL0\n\t"
			"isb\n\t"
			"hvc #0\n\t"
			"isb\n\t"
			"mrs x2 , PMCCNTR_EL0\n\t"
			"isb\n\t"
			"mov %[before_hvc], x3\n\t"
			"mov %[soh], x1\n\t"
			"mov %[eoh], x4\n\t"
			"mov %[after_hvc], x2\n\t":
			[before_hvc] "=r" (before_hvc),
			[soh] "=r" (soh),
			[after_hvc] "=r" (after_hvc),
			[eoh] "=r" (eoh): :
			"x0", "x1", "x2", "x3", "x4");
#elif defined(CONFIG_ARM)
	asm volatile(
			"mov r0, #0x4c000000\n\t"
			"mrc p15, 0, r3, c9, c13, 0\n\t"
			"hvc #0\n\t"
			"mrc p15, 0, r2, c9, c13, 0\n\t"
			"mov %[before_hvc], r3\n\t"
			"mov %[soh], r1\n\t"
			"mov %[after_hvc], r2\n\t":
			[before_hvc] "=r" (before_hvc),
			[soh] "=r" (soh),
			[after_hvc] "=r" (after_hvc): :
			"r0", "r1", "r2", "r3");
#elif defined(CONFIG_X86_64)
	call_hyp((void*)HVC_NOOP);
	asm volatile("mov %%rdx, %0": "=r" (soh));
	after_hvc = read_cc_after();
#endif
	local_irq_restore(flags);
	trap_out = after_hvc - soh;

	return trap_out;
}


static unsigned long trap_in_test(void)
{
	unsigned long flags;
	unsigned long trap_in = 0;
	unsigned long cc0 = 0, cc1 = 0, cc2 = 0;

	cc0 = 0, cc1 = 0, cc2 = 0;

	local_irq_save(flags);
#ifdef CONFIG_ARM64
	asm volatile(
			"mov x0, #0x10000\n\t"
			"isb\n\t"
			"mrs x3 , PMCCNTR_EL0\n\t"
			"isb\n\t"
			"hvc #0\n\t"
			"isb\n\t"
			"mrs x2 , PMCCNTR_EL0\n\t"
			"isb\n\t"
			"mov %[cc0], x3\n\t"
			"mov %[cc1], x1\n\t"
			"mov %[cc2], x2\n\t":
			[cc0] "=r" (cc0),
			[cc1] "=r" (cc1),
			[cc2] "=r" (cc2): :
			"x0", "x1", "x2", "x3");
#elif defined(CONFIG_ARM)
	asm volatile(
			"mov r0, #0x4c000000\n\t"
			"mrc p15, 0, r3, c9, c13, 0\n\t"
			"hvc #0\n\t"
			"mrc p15, 0, r2, c9, c13, 0\n\t"
			"mov %[cc0], r3\n\t"
			"mov %[cc1], r1\n\t"
			"mov %[cc2], r2\n\t":
			[cc0] "=r" (cc0),
			[cc1] "=r" (cc1),
			[cc2] "=r" (cc2): :
			"r0", "r1", "r2", "r3");
#elif defined(CONFIG_X86_64)
	cc0 = read_cc_before();
	call_hyp((void*)HVC_NOOP);
	asm volatile("mov %%rdx, %0": "=r" (cc1));
#endif
	local_irq_restore(flags);

	trap_in = cc1 - cc0;

	return trap_in;
}

static unsigned long vmswitch_send_test(void)
{
	unsigned long ret, cc_before, cc_after;
	unsigned long flags;

	local_irq_save(flags);
	cc_before = read_cc_before();
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	ret = kvm_call_hyp((void*)HVC_VMSWITCH_SEND, cc_before);
#elif defined(CONFIG_X86_64)
#ifndef FOR_XEN
	ret = kvm_hypercall1(HVC_VMSWITCH_SEND, cc_before);
#else
	ret = _hypercall2(long, dummy_hyp, HVC_VMSWITCH_SEND, cc_before);
#endif
#endif
	if (ret)
		kvm_err("Sending HVC VM switch measure error: %ld\n", (long)ret);
	cc_after = read_cc_after();
	local_irq_restore(flags);
	ret = CYCLE_COUNT(cc_before, cc_after);

	return ret;
}

static unsigned long vmswitch_recv_test(void)
{
	unsigned long ret, cc_before, cc_after;
	unsigned long flags;

	local_irq_save(flags);
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	cc_before = call_hyp((void*)HVC_VMSWITCH_RCV);
#elif defined(CONFIG_X86_64)
#ifndef FOR_XEN
	cc_before = kvm_hypercall0(HVC_VMSWITCH_RCV);
#else
	cc_before = _hypercall2(long, dummy_hyp, HVC_VMSWITCH_RCV, 0);
#endif
#endif
	cc_after = read_cc_after();

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	call_hyp((void*)HVC_VMSWITCH_DONE);
#elif defined(CONFIG_X86_64)
#ifndef FOR_XEN
	kvm_hypercall0(HVC_VMSWITCH_DONE);
#else
	_hypercall2(long, dummy_hyp, HVC_VMSWITCH_DONE, 0);
#endif
#endif
	local_irq_restore(flags);
	ret = CYCLE_COUNT(cc_before, cc_after);

	return ret;
}

unsigned long cc_start, cc_end;
static unsigned long trap_profile_start(void)
{
	unsigned long ret = 0;
	trace_printk("started!\n");
	cc_start = read_cc_before();
	call_hyp((void*)TRAP_MEASURE_START);
	return ret;
}

static unsigned long trap_profile_end(void)
{
	unsigned long ret = 0;
	call_hyp((void*)TRAP_MEASURE_END);
	cc_end = read_cc_after();
	trace_printk("start: %lu, end: %lu, diff: %lu\n", cc_start, cc_end, cc_end - cc_start);
	trace_printk("ended!\n");
	return ret;
}

static unsigned long el2_exit_top(void)
{
	unsigned long cc, flags;

	local_irq_save(flags);
#ifdef CONFIG_ARM
	asm volatile(
			"mov x0, #0x20000\n\t"
			"hvc #0\n\t"
			"mov %[cc], x0\n\t":
			[cc] "=r" (cc)::
			"x0");
#else
	cc = 0;
#endif
	local_irq_restore(flags);
	return cc;
}

static unsigned long el2_exit_bot(void)
{
	unsigned long cc, flags;

	local_irq_save(flags);
#ifdef CONFIG_ARM
	asm volatile(
			"mov x0, #0x30000\n\t"
			"hvc #0\n\t"
			"mov %[cc], x0\n\t":
			[cc] "=r" (cc)::
			"x0", "x1");
#else
	cc = 0;
#endif
	local_irq_restore(flags);

	return cc;
}

static unsigned long io_latency(void)
{
	simpleif_request_dummy();
	return 1024*32;
}

static unsigned long io_latency_out(void)
{
#ifdef CONFIG_X86_64
	unsigned long ret, flags, cc_before, cc_after;

	local_irq_save(flags);
	cc_before = read_cc();
	apic_write(APIC_EFEAT, NULL);
	cc_after = kvm_hypercall0(HVC_IOLATENCY_END);
	ret = CYCLE_COUNT(cc_before, cc_after);
	local_irq_restore(flags);

	return ret;
#else
	return 0;
#endif
}

static unsigned long hvc_breakdown(void)
{
       unsigned long flags;
       unsigned long ret = 0;
       unsigned long cc0 = 0, cc1 = 0;

       local_irq_save(flags);
#ifdef CONFIG_ARM64
       asm volatile(
                       "mov x0, #0x10000\n\t"
                       "hvc #0\n\t"
                       "mov %[cc0], x1\n\t"
                       "mov %[cc1], x2\n\t":
                       [cc0] "=r" (cc0),
                       [cc1] "=r" (cc1)::
                       "x0", "x1", "x2");
#endif
       ret = cc1 - cc0;
       local_irq_restore(flags);

       return ret;
}

struct virt_test available_tests[] = {
	{ "hvc",		hvc_test	},
	{ "mmio_read_user",	mmio_user	},
	{ "mmio_read_vgic",	mmio_kernel	},
	{ "eoi",		eoi_test	},
	{ "noop_guest",		noop_test	},
	{ "ipi",		ipi_test	},
	{ "trap-in",		trap_in_test	},
	{ "trap-out",		trap_out_test	},
	{ "vmswitch_send",	vmswitch_send_test	},
	{ "vmswitch_recv",	vmswitch_recv_test	},
	{ "trap-profile-start", trap_profile_start      },
	{ "trap-profile-end",   trap_profile_end        },
	{ "el2-exit-top",	el2_exit_top	        },
	{ "el2-exit-bot",	el2_exit_bot	        },
	{ "io-latency-xen",	io_latency	},
	{ "io-latency-out-kvm",	io_latency_out	},
	{ "hvc-breakdown-xen",	hvc_breakdown	},
};

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
extern void *gic_data_dist_base_ex(void);
extern void *gic_data_cpu_base_ex(void);

static int init_mmio_test(void)
{
	int ret = 0;

	vgic_dist_addr = gic_data_dist_base_ex();
	if (!vgic_dist_addr) {
		ret = -ENODEV;
		goto out;
	}

	vgic_cpu_addr = gic_data_cpu_base_ex();
	if (!vgic_cpu_addr) {
		ret = -ENODEV;
		goto out;
	}

	/* TODO: Need to be more clever here, device tree ? */
	mmio_read_user_addr = ioremap(0x0a000000, 0x200);
	if (!mmio_read_user_addr) {
		pr_err("virt-test: ioremap failed\n");
		ret = -EFAULT;
	}
out:
	return ret;
}
#elif defined(CONFIG_X86_64)
static int init_mmio_test(void)
{
	int ret = 0;
	return ret;
}
#endif

static void loop_test(struct virt_test *test)
{
	unsigned long i, iterations = 32;
	unsigned long sample, cycles;
	unsigned long min = 0, max = 0, avg = 0;

	do {
		iterations *= 2;
		cycles = 0;

		for (i = 0; i < iterations; i++) {
			sample = test->test_fn();
			if (sample == 0) {
				/* If something went wrong or we had an
				 * overflow, don't count that sample */
				iterations--;
				i--;
				pr_warn("cycle count overflow: %lu\n", sample);

				continue;
			}
			cycles += sample;

			if (min == 0 || min > sample)
				min = sample;
			if (max < sample)
				max = sample;
		}

	} while (cycles < GOAL);

	//debug("%s exit %d cycles over %d iterations = %d\n",
	//       test->name, cycles, iterations, cycles / iterations);
	avg = cycles / iterations;
	trace_printk("virt-test %s\t%lu\t%lu\tmin:\t%lu\tmax:\t%lu\n",
	       test->name, avg, iterations, min, max);
}

static void run_test_once(struct virt_test *test)
{
	unsigned long sample;
	sample = test->test_fn();
	trace_printk("virt-test once %s\t%lu\n", test->name, sample);
}

static int arm_virt_unit_test(unsigned long op, bool once)
{
	struct virt_test *test;
	int i;

	if (op > ARRAY_SIZE(available_tests))
		return -EINVAL;

	if (op > 0) {
		test = &available_tests[op - 1];
		if (once)
			run_test_once(test);
		else
			loop_test(test);
	} else {
		for_each_test(test, available_tests, i) {
			test = &available_tests[i];
			loop_test(test);
			run_test_once(test);
		}
	}

	return 0;
}

static ssize_t __virttest_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *pos, bool once)
{
	int ret;
	unsigned long val;

	ret = kstrtoul_from_user(buffer, count, 10, &val);
	if (ret)
		return ret;

	ret = arm_virt_unit_test(val, once);
	if (ret)
		return ret;

	*pos += count;

	return ret ? ret : count;
}

static ssize_t virttest_write(struct file *file, const char __user *buffer,
		size_t count, loff_t *pos)
{
	return __virttest_write(file, buffer, count, pos, false);
}

static ssize_t virttest_once_write(struct file *file, const char __user *buffer,
		size_t count, loff_t *pos)
{
	return __virttest_write(file, buffer, count, pos, true);
}

static int virt_test_proc_show(struct seq_file *m, void *v)
{
	int i;
	struct virt_test *test;

	seq_printf(m, "Usage: echo <test_idx> > /proc/virttest\n\n");
	seq_printf(m, "Test Idx    Test Name\n");
	seq_printf(m, "---------------------\n");
	seq_printf(m, "       0    All tests\n");
	for_each_test(test, available_tests, i) {
		seq_printf(m, "     %3d    %s\n", i + 1, test->name);
	}

	return 0;
};

extern unsigned long iolat_cnt;
extern unsigned long iolat_sum;
extern unsigned long iolat_in_sum;
extern unsigned long iolat_out_sum;
extern unsigned long iolat_min;
extern unsigned long iolat_out_min;
extern unsigned long iolat_in_min;

static int iolat_show(struct seq_file *m, void *v) {
	seq_printf(m, "test cnt:\t%lu\n", iolat_cnt);
	seq_printf(m, "[Total ] min:\t%lu\tavg:\t%lu\n", iolat_min, iolat_sum/iolat_cnt);
	seq_printf(m, "[IO IN ] min:\t%lu\tavg:\t%lu\n", iolat_in_min, iolat_in_sum/iolat_cnt);
	seq_printf(m, "[IO OUT] min:\t%lu\tavg:\t%lu\n", iolat_out_min, iolat_out_sum/iolat_cnt);
	return 0;
}

static ssize_t iolat_reset(struct file *file, const char __user *buffer,
		size_t count, loff_t *pos) {
	int ret;
	unsigned long val;

	iolat_cnt = 0;
	iolat_sum = 0;
	iolat_in_sum = 0;
	iolat_out_sum = 0;
	iolat_min = ULLONG_MAX;
	iolat_in_min = ULLONG_MAX;
	iolat_out_min = ULLONG_MAX;
	ret = kstrtoul_from_user(buffer, count, 10, &val);
	if (ret)
		return ret;

	*pos += count;

	return ret ? ret : count;
}

static int virt_test_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, virt_test_proc_show, NULL);
}

static int iolat_open(struct inode *inode, struct file *file)
{
	return single_open(file, iolat_show, NULL);
}

static const struct file_operations virttest_proc_fops = {
	.owner = THIS_MODULE,
	.open = virt_test_proc_open,
	.read = seq_read,
	.write = virttest_write,
};

static const struct file_operations virttest_once_proc_fops = {
	.owner = THIS_MODULE,
	.open = virt_test_proc_open,
	.read = seq_read,
	.write = virttest_once_write,
};

static const struct file_operations virttest_iolat_fops = {
	.owner = THIS_MODULE,
	.open = iolat_open,
	.read = seq_read,
	.write = iolat_reset,
};

static int __init virt_test_init(void)
{
	int ret;

	/* Initialize MMIO regions we ned */
	ret = init_mmio_test();
	if (ret) {
		pr_err("virt-test: Failed to initialize mmio tests: %d\n", ret);
		return ret;
	}

	call_hyp((void*)HVC_CCNT_ENABLE);
	proc_create("virttest", 0, NULL, &virttest_proc_fops);
	proc_create("virttest_one", 0, NULL, &virttest_once_proc_fops);
	proc_create("iolat", 0, NULL, &virttest_iolat_fops);
	pr_info("virt-tests successfully initialized\n");
	return 0;
}
__initcall(virt_test_init);
