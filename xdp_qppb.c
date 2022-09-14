#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* REFERENCES:
 * linux/samples/bpf/xdp_fwd_kernel.c
 * linux/samples/bpf/xdp_router_ipv4.bpf.c
 * xdp-tutorial/packet-solutions/xdp_prog_kern_03.c
 */

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

enum qppb_bgp_policy {
	BGP_POLICY_NONE = 0,
	BGP_POLICY_DST = 1,
	BGP_POLICY_SRC = 2,
	BGP_POLICY_MAX
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} qppb_mode_map SEC(".maps");

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XDP_ACTION_MAX);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_stats_map SEC(".maps");

struct lpm_key4 {
	__u32 prefixlen;
	__u32 src;
};

union lpm_key4_u {
	__u32 b32[2];
	__u8 b8[8];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 100);
	__type(key, struct lpm_key4);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dscp_map SEC(".maps");

static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	/* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
	 * CPU and XDP hooks runs under Softirq, which makes it safe to update
	 * without atomic operations.
	 */
	rec->rx_packets++;
	rec->rx_bytes += (ctx->data_end - ctx->data);

	return action;
}

/* Taken from include/net/dsfield.h */
static inline void ipv4_change_dsfield(struct iphdr *iph, __u8 mask, __u8 value)
{
        __u32 check = bpf_ntohs((__be16)iph->check);
	__u8 dsfield;

	dsfield = (iph->tos & mask) | value;
	check += iph->tos;
	if ((check+1) >> 16) check = (check+1) & 0xffff;
	check -= dsfield;
	check += check >> 16; /* adjust carry */
	iph->check = (__sum16)bpf_htons(check);
	iph->tos = dsfield;
}

SEC("xdp_qppb")
int xdp_qppb_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params;
	struct iphdr *iph = data + sizeof(struct ethhdr);
	struct ethhdr *eth = data;
	int rc, action = XDP_PASS;
	__u64 nh_off = sizeof(struct ethhdr);
	__u16 h_proto = eth->h_proto;
	__u32 iif = ctx->ingress_ifindex, *qppb_mkey;
	__u8 *mark, qppb_mode;
	union lpm_key4_u key4;

	if (data + nh_off > data_end)
		goto drop;
	if ((void*)(iph + 1) > data_end)
		goto drop;
	if (iph->ttl <= 1)
		goto skip;
	if (h_proto != bpf_htons(ETH_P_IP))
		goto skip;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.family	= AF_INET;
	fib_params.tos		= iph->tos;
	fib_params.l4_protocol	= iph->protocol;
	fib_params.sport	= 0;
	fib_params.dport	= 0;
	fib_params.tot_len	= bpf_ntohs(iph->tot_len);
	fib_params.ifindex	= iif;
	fib_params.ipv4_src	= iph->saddr;
	fib_params.ipv4_dst	= iph->daddr;

	qppb_mkey = bpf_map_lookup_elem(&qppb_mode_map, &fib_params.ifindex);
	qppb_mode = qppb_mkey ? *qppb_mkey : BGP_POLICY_NONE;
	if (qppb_mode == BGP_POLICY_NONE)
		goto skip;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS)
		goto out;

	key4.b32[0] = 32;
	switch (qppb_mode) {
		case BGP_POLICY_DST:
			key4.b8[4] = iph->daddr & 0xff;
			key4.b8[5] = (iph->daddr >> 8) & 0xff;
			key4.b8[6] = (iph->daddr >> 16) & 0xff;
			key4.b8[7] = (iph->daddr >> 24) & 0xff;
			break;
		case BGP_POLICY_SRC:
			key4.b8[4] = iph->saddr & 0xff;
			key4.b8[5] = (iph->saddr >> 8) & 0xff;
			key4.b8[6] = (iph->saddr >> 16) & 0xff;
			key4.b8[7] = (iph->saddr >> 24) & 0xff;
			break;
		default:
			goto out;
	}

	mark = bpf_map_lookup_elem(&dscp_map, &key4);
	if (!mark)
		goto out;

	// bpf_printk("Mark detected [%d]", *mark);
	ipv4_change_dsfield(iph, 0, *mark);
out:
	return xdp_stats_record_action(ctx, action);
drop:
	return xdp_stats_record_action(ctx, XDP_DROP);
skip:
	return action;
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
