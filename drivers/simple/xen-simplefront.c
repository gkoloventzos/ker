#include <linux/interrupt.h>
#include <linux/hdreg.h>
#include <linux/cdrom.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/scatterlist.h>
#include <linux/bitmap.h>
#include <linux/list.h>

#include <xen/xen.h>
#include <xen/xenbus.h>
#include <xen/grant_table.h>
#include <xen/events.h>
#include <xen/page.h>
#include <xen/platform_pci.h>

#include <xen/interface/grant_table.h>
#include <xen/interface/io/simpleif.h>
#include <xen/interface/io/protocols.h>

#include <asm/xen/hypervisor.h>
#include <linux/kvm_host.h>

#define GRANT_INVALID_REF       0

#define SIMPLE_RING_SIZE __CONST_RING_SIZE(simpleif, PAGE_SIZE)


static __always_inline volatile unsigned long read_cc_before(void)
{
        unsigned long cc;
#ifdef CONFIG_ARM64
        isb();
	/* We read arch counter for I/O latency out to get synchronized counter across pcpus */
	asm volatile("mrs %0, CNTPCT_EL0" : "=r" (cc) ::);
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
	/* We read arch counter for I/O latency out to get synchronized counter across pcpus */
	asm volatile("mrs %0, CNTPCT_EL0" : "=r" (cc) ::);
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


unsigned long cc_before;
unsigned long cc_after;

struct simplefront_info
{
	struct xenbus_device 	*dev;
	int	ring_ref;
	struct simpleif_front_ring ring;
	unsigned int evtchn, irq;
};

#define HVC_TSC_OFFSET   0x4b000040
#define HVC_GET_BACKEND_TS   0x4b000050
#define HVC_SET_BACKEND_TS   0x4b000060

unsigned long iolat_cnt = 0;
unsigned long iolat_sum = 0;
unsigned long iolat_in_sum = 0;
unsigned long iolat_out_sum = 0;
unsigned long iolat_min = ULLONG_MAX;
unsigned long iolat_out_min = ULLONG_MAX;
unsigned long iolat_in_min = ULLONG_MAX;
static irqreturn_t simpleif_interrupt(int irq, void *dev_id)
{
	//long ret = 0;
	unsigned long diff;
	unsigned long backend_ts;
	//unsigned long num;
	cc_after = read_cc_after();

#ifdef CONFIG_X86_64
	 do {
		num = HVC_GET_BACKEND_TS;
		asm volatile (  "mov %[num], %%rax\n\t"
				"vmcall\n\t"
				"mov %%rdx, %[backend_ts]\n\t"
				: [backend_ts] "=r" (backend_ts)
				: [num] "r" (num)
				: "%rax", "%rdx");

	} while (backend_ts == 0);
	_hypercall2(long, dummy_hyp, HVC_SET_BACKEND_TS, 0);
#else
	do {
		backend_ts = kvm_call_hyp((void*) HVC_GET_BACKEND_TS);
	} while (backend_ts == 0);
	kvm_call_hyp((void*) HVC_SET_BACKEND_TS, 0);
#endif
	iolat_cnt += 1;
	diff = cc_after - cc_before;
	iolat_sum += diff;
	if (iolat_min > diff)
		iolat_min = diff;

	diff = backend_ts - cc_before;
	iolat_out_sum += diff;
	if (iolat_out_min > diff)
		iolat_out_min = diff;

	diff = cc_after - backend_ts;
	iolat_in_sum += diff;
	if (iolat_in_min > diff)
		iolat_in_min = diff;

	cc_before = 0;
	/* This is for sending data */
	/*
	struct blkfront_info *info = (struct blkfront_info *)dev_id;
	RING_IDX i, rp;
	int more_to_do;
	struct blkif_response *bret;

	rp = info->ring.sring->rsp_prod;
        rmb();
	i = info->ring.rep_cons;
	bret = RING_GET_RESPONSE(&info->ring, i);
	switch (bret->operation)
	{
		case 9:
			printk("jintack CONGRATS front notified with op 9\n");
		default:
			printk("jintack front notified but with %d\n", bret->operation);

	}

	info->ring.rsp_cons = i;
	info->ring.sring->rsp_event = i+1;
	RING_FINAL_CHECK_FOR_RESPONSES(&info->ring, more_to_do);

	if (more_to_do)
		printk("jintack more_to_do??\n");
	*/
	return IRQ_HANDLED;
}

static int setup_simplering(struct xenbus_device *dev,
                         struct simplefront_info *info)
{
	struct simpleif_sring *sring;
	int err;
	grant_ref_t gref[XENBUS_MAX_RING_GRANTS];

	info->ring_ref = GRANT_INVALID_REF;

	sring = (struct simpleif_sring *)__get_free_page(GFP_NOIO | __GFP_HIGH);
	if (!sring) {
		printk("jintack fail to alloc shared ring\n");
		xenbus_dev_fatal(dev, -ENOMEM, "allocating shared ring");
		return -ENOMEM;
	}

	SHARED_RING_INIT(sring);
	FRONT_RING_INIT(&info->ring, sring, PAGE_SIZE);
	err = xenbus_grant_ring(dev, info->ring.sring, 1, gref);
	if (err < 0) {
		free_page((unsigned long)sring);
		info->ring.sring = NULL;
		return err;
	}
	info->ring_ref = err;

	err = xenbus_alloc_evtchn(dev, &info->evtchn);
	if (err)
		return err;

	err = bind_evtchn_to_irqhandler(info->evtchn, simpleif_interrupt, 0,
			"simpleif", info);
	info->irq = err;

	return 0;
}

static int talk_to_simpleback(struct xenbus_device *dev,
                           struct simplefront_info *info)
{
	const char *message = NULL;
	struct xenbus_transaction xbt;
	int err;

	err = setup_simplering(dev, info);
	if (err <0) {
		printk("jintack fail to setup simple ring\n");
		return err;
	}

again:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		goto destroy_blkring;
	}

	printk("jintack: ring-ref is %u:\n", info->ring_ref);
	err = xenbus_printf(xbt, dev->nodename,
			"ring-ref", "%u", info->ring_ref);
	if (err) {
		message = "writing ring-ref";
		goto abort_transaction;
	}
	err = xenbus_printf(xbt, dev->nodename,
			"event-channel", "%u", info->evtchn);
	if (err) {
		message = "writing event-channel";
		goto abort_transaction;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err) {
		if (err == -EAGAIN)
			goto again;
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto destroy_blkring;
	}

abort_transaction:
	xenbus_transaction_end(xbt, 1);
	if (message)
		xenbus_dev_fatal(dev, err, "%s", message);
destroy_blkring:
	//blkif_free(info, 0);
	return err;



}

static int simplefront_probe(struct xenbus_device *dev,
                          const struct xenbus_device_id *id)
{
	struct simplefront_info *info;
	int err;

	printk("jintack %s is called. awesome\n", __func__);
	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating info structure");
		return -ENOMEM;
	}

	info->dev = dev;
	dev_set_drvdata(&dev->dev, info);

	err = talk_to_simpleback(dev, info);
	if (err) {
		kfree(info);
		dev_set_drvdata(&dev->dev, NULL);
		return err;
	}
	return 0;
}


static int simplefront_remove(struct xenbus_device *xbdev)
{
	return 0;
}

static int simplefront_resume(struct xenbus_device *dev)
{
	return 0;
}

struct xenbus_device *gdev;
int simpleif_request_dummy(void)
{
	struct xenbus_device *dev = gdev;
	struct simplefront_info *info = dev_get_drvdata(&dev->dev);
	struct simpleif_request *ring_req;
	int notify;
	//printk("jintack [front] Let's send a request\n");

	ring_req = RING_GET_REQUEST(&info->ring, info->ring.req_prod_pvt);
	ring_req->operation = 9;
	info->ring.req_prod_pvt++;

	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&info->ring, notify);
	if (cc_before) {
		/* wait until frontend gets interrupt and reset cc_before */
		return 0;
	}
	cc_before = read_cc_before();
	notify_remote_via_irq(info->irq);
	HYPERVISOR_sched_op(SCHEDOP_block, NULL);
	if (cc_before != 0)
		printk("%s, not woke up by backend\n", __func__);
	return 0;
}

/**
 * Callback received when the backend's state changes.
 */
static void simpleback_changed(struct xenbus_device *dev,
                            enum xenbus_state backend_state)
{
	struct simplefront_info *info = dev_get_drvdata(&dev->dev);
	int err;
	printk("jintack simpleback changed to state %d\n", backend_state);
	printk("jintack simplefront state is %d\n", dev->state);

	switch (backend_state) {


	case XenbusStateInitWait:
		err = xenbus_switch_state(info->dev, XenbusStateConnected);
		if (err) {
			xenbus_dev_fatal(dev, err, "%s: switching to Connected state",
					dev->nodename);
			printk("jintack front is NOT connected: %d\n", err);
		} else
			printk("jintack [front] IS connected\n");

		gdev = dev;
		break;

	case XenbusStateConnected:
		/* TODO: This should be a fuction which is visible to the kernel */
		simpleif_request_dummy();
		return;
	default:
		return;
	}

}

static int simplefront_is_ready(struct xenbus_device *dev)
{
	return 0;
}
static const struct xenbus_device_id simplefront_ids[] = {
        { "vsimple" },
        { "" }
};

static struct xenbus_driver simplefront_driver = {
        .ids  = simplefront_ids,
        .probe = simplefront_probe,
        .remove = simplefront_remove,
        .resume = simplefront_resume,
        .otherend_changed = simpleback_changed,
        .is_ready = simplefront_is_ready,
};

static int __init xlsimple_init(void)
{
        int ret;
	printk("jintack %s is called. awesome\n", __func__);

        if (!xen_domain())
                return -ENODEV;

	printk("jintack %s is called second. awesome\n", __func__);
        ret = xenbus_register_frontend(&simplefront_driver);
        if (ret) {
		printk("jintack %s is called fail. awesome\n", __func__);
                return ret;
        }

	printk("jintack %s is called success. awesome\n", __func__);

        return 0;
}
module_init(xlsimple_init);


static void __exit xlsimple_exit(void)
{
        xenbus_unregister_driver(&simplefront_driver);
}
module_exit(xlsimple_exit);

MODULE_DESCRIPTION("Xen virtual simple device frontend");
MODULE_LICENSE("GPL");
