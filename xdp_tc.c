#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* REFERENCES:
 * linux/tools/testing/selftests/bpf/progs/test_skb_ctx.c
 * linux/samples/bpf/xdp2skb_meta_kern.c
 * bpf-examples/tc-basic-classifier
 */

struct meta_info {
	__u8 mark;
} __attribute__((aligned(4)));

SEC("tc_mark")
int tc_mark_func(struct __sk_buff *skb)
{
	void *data      = (void *)(unsigned long)skb->data;
	void *data_meta = (void *)(unsigned long)skb->data_meta;
	struct meta_info *meta = data_meta;

	// Default priority
	skb->tc_classid = 0x10;

	// Check XDP gave us some data_meta
	if ((void*)(meta + 1) > data)
		return TC_ACT_OK;
        if (!meta->mark)
		return TC_ACT_OK;

	skb->mark = meta->mark;
	skb->priority = meta->mark;
	// High priority flow
	if (meta->mark >= 50)
		skb->tc_classid = 0x20;

	// bpf_printk("TC Mark detected [%d|%d]", skb->mark, skb->tc_classid);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
