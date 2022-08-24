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

#define PIN_NONE	0
#define PIN_OBJECT_NS	1
#define PIN_GLOBAL_NS	2
/*
 * REFERENCE: bpf-examples/traffic-pacing-edit/iproute2_compat.h
 * The tc tool (iproute2) use another ELF map layout than libbpf, see struct
 * bpf_elf_map from iproute2, but struct bpf_map_def from libbpf have same
 * binary layout until "flags". Thus, BPF-progs can use both if careful.
 */
struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};

#define XDP_LPM_KEY_SIZE (sizeof(struct bpf_lpm_trie_key) + sizeof(__u32))
struct bpf_elf_map SEC("maps") dscp_map = {
	.type       = BPF_MAP_TYPE_LPM_TRIE,
	.max_elem   = 100,
	.size_key   = XDP_LPM_KEY_SIZE,
	.size_value = sizeof(__u8),
	.pinning    = PIN_GLOBAL_NS,      //sys/fs/bpf/tc/globals/dscp_map
	.flags      = BPF_F_NO_PREALLOC,
};

enum qppb_bgp_policy {
	BGP_POLICY_NONE = 0,
	BGP_POLICY_DST = 1,
	BGP_POLICY_SRC = 2,
	BGP_POLICY_MAX
};

/* Association between iface id and the configured mode */
struct bpf_elf_map SEC("maps") qppb_mode_map = {
	.type       = BPF_MAP_TYPE_ARRAY,
	.max_elem   = 256,
	.size_key   = sizeof(__u32),
	.size_value = sizeof(__u32),
	.pinning    = PIN_GLOBAL_NS,      //sys/fs/bpf/tc/globals/qppb_mode_map
};

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

/* Keeps stats per (enum) xdp_action */
struct bpf_elf_map SEC("maps") xdp_stats_map = {
	.type       = BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key   = sizeof(__u32),
	.size_value = sizeof(struct datarec),
	.max_elem   = XDP_ACTION_MAX,
	.pinning    = PIN_OBJECT_NS,
};

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
	__u32 iif = ctx->ingress_ifindex;
	__u8 *mark, *qppb_mkey, qppb_mode;
	union {
		__u32 b32[2];
		__u8 b8[8];
	} key4;

	if (data + nh_off > data_end)
		goto drop;
	if ((void*)(iph + 1) > data_end)
		goto drop;
	if (iph->ttl <= 1)
		goto out;
	if (h_proto != bpf_htons(ETH_P_IP))
		goto out;

	// Using BGP_POLICY_DST by default, if xdp was attached
	qppb_mkey = bpf_map_lookup_elem(&qppb_mode_map, &iif);
	qppb_mode = qppb_mkey ? *qppb_mkey : BGP_POLICY_DST;
	if (qppb_mode == BGP_POLICY_NONE)
		goto out;

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

	bpf_printk("Mark detected [%d]", *mark);
	ipv4_change_dsfield(iph, 0, *mark);

out:
        /* bpf_printk("bpf fib lookup %d\n", action); */
	return xdp_stats_record_action(ctx, action);
drop:
	return xdp_stats_record_action(ctx, XDP_DROP);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
