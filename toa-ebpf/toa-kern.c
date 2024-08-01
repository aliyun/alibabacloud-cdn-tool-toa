/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2024, Alibaba Group Holding Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <sys/socket.h>
#include <string.h>
#include "toa.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct toa_info);
} sk_toa_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 10);
} toa_opcode_map SEC(".maps");

#define TOA_OPCODE_KEY          0
#define TOA_PORT_OPCODE_KEY     1

static inline __u8* search_toa_option(__u8 *data, void *data_end, __u8 opt_len,
								   __u8 optcode1, __u8 optcode2)
{
	__u8 optsize = 0;

	/* make ebpf verifier happy */
	opt_len = opt_len < 40 ? opt_len : 40;
	for (int i = 0; i < opt_len; i++) {
		if (optsize) {
			optsize--;
			continue;
		}

		if (data + i + 1 >= data_end)
			break;
		if (data[i] == TCPOPT_EOL)
			break;
		else if (data[i] == TCPOPT_NOP)
			continue;

		if (opt_len - i < 2 || opt_len - i < data[i+1] || data[i+1] < 2)
			/* Something is wrong in the received header.
			 * Follow the TCP stack's tcp_parse_options()
			 * and just bail here.
			 */
			break;

		if (optcode1 == data[i] || optcode2 == data[i])
			return data + i;

		optsize = data[i+1] - 1;
	}

	return NULL;
}

static inline void save_toa_to_sk_storage(__u8 *data, void *data_end, __u8 toa_opcode,
							__u8 toa_port_opcode, struct toa_info * toa_val) {
	union toa_opt *toa_opt;
	toa_opt = (union toa_opt *)data;
	if (data[0] == toa_opcode && data[1] == TOA_V4_LEN && 
			   data + TOA_V4_LEN <= data_end) {
		toa_val->cip = toa_opt->toa.ip;
		toa_val->ip_valid = 1;
	} else if (data[0] == toa_opcode && data[1] == TOA_V6_LEN && 
			   data + TOA_V6_LEN <= data_end) {
		memcpy(toa_val->cip6, toa_opt->toa_v6.ip, 16);
		toa_val->ip_valid = 1;
	} else if (data[0] == toa_port_opcode && data[1] == TOA_PORT_V4_LEN &&
			   data + TOA_PORT_V4_LEN <= data_end) {
		toa_val->cip = toa_opt->toa_port.ip;
		toa_val->cport = toa_opt->toa_port.port;
		toa_val->ip_valid = 1;
		toa_val->port_valid = 1;
	} else if (data[0] == toa_port_opcode && data[1] == TOA_PORT_V6_LEN &&
			   data + TOA_PORT_V6_LEN <= data_end) {
		memcpy(toa_val->cip6, toa_opt->toa_port_v6.ip, 16);
		toa_val->cport = toa_opt->toa_port_v6.port;
		toa_val->ip_valid = 1;
		toa_val->port_valid = 1;
	}
}

static inline void get_toa_opcode(__u8 *toa_opcode, __u8 *toa_port_opcode) {
	__u8 *val = NULL;
	__u32 key = 0;

	key = TOA_OPCODE_KEY;
	val = bpf_map_lookup_elem(&toa_opcode_map, &key);
	if (!val)
		return;

	if (*val)
		*toa_opcode = *val;

	key = TOA_PORT_OPCODE_KEY;
	val = bpf_map_lookup_elem(&toa_opcode_map, &key);
	if (!val)
		return;

	if (*val)
		*toa_port_opcode = *val;
} 

SEC("sockops")
int toa_parse(struct bpf_sock_ops *skops)
{
	__u8 *opt = NULL;
	__u8 optlen = 0;
	__u16 magic_code;
	union toa_opt *toa_opt = NULL;
	struct toa_info *toa_val = NULL;
	int rv = 0, save_syn;
	__u8 toa_opcode = TCPOPT_TOA, toa_port_opcode = TCPOPT_TOA_PORT;

	union {
		struct tcphdr th;
		__u8 data[60 + TOA_PORT_V6_LEN];
	} hdr = {};

	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_LISTEN_CB:
		save_syn = 1;
		bpf_setsockopt(skops, SOL_TCP, TCP_SAVE_SYN,
					&save_syn, sizeof(save_syn));
		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		if (!skops->sk)
			return 1;

		toa_val = bpf_sk_storage_get(&sk_toa_map, skops->sk, NULL,
									 BPF_SK_STORAGE_GET_F_CREATE);
		if (!toa_val)
			return 1;

		get_toa_opcode(&toa_opcode, &toa_port_opcode);
		rv = bpf_getsockopt(skops, SOL_TCP, TCP_BPF_SYN, &hdr, sizeof(hdr));
		if (rv > 0) {
			optlen = hdr.th.doff * 4 - sizeof(struct tcphdr);
			opt = search_toa_option(hdr.data + 20, hdr.data + 60, optlen,
								 toa_opcode, toa_port_opcode);
			if (opt) {
				/* bypass fastopen connect */
				if (*opt == TCPOPT_EXP &&  opt + 4 <= hdr.data + 60) {
					memcpy(&magic_code, opt + 2, 2);
					if (magic_code == TCPOPT_FASTOPEN_MAGIC)
						return 1;
				}
				save_toa_to_sk_storage(opt, hdr.data + 60, toa_opcode,
							  toa_port_opcode, toa_val);
			}
		}

		struct tcphdr* th = skops->skb_data;
		if (th + 1 > skops->skb_data_end)
			return 1;
		opt = (__u8 *)(th + 1);
		optlen = th->doff * 4 - sizeof(struct tcphdr);
		opt = search_toa_option(opt, skops->skb_data_end, optlen,
							 toa_opcode, toa_port_opcode);
		if (!opt)
			return 1;

		save_toa_to_sk_storage(opt, skops->skb_data_end, toa_opcode,
					  toa_port_opcode, toa_val);
		break;
	default:
		return 1;
	}
	return 1;
}

SEC("cgroup/getpeername4")
int toa_peername4(struct bpf_sock_addr *ctx)
{
	struct toa_info *toa_val = NULL;

	if (!ctx->sk)
		return 1;

	toa_val = bpf_sk_storage_get(&sk_toa_map, ctx->sk, NULL, 0);
	if (!toa_val)
		return 1;

	if (toa_val->ip_valid)
		ctx->user_ip4 = toa_val->cip;
	
	if (toa_val->port_valid)
		ctx->user_port = toa_val->cport;

	return 1;
}

SEC("cgroup/getpeername6")
int toa_peername6(struct bpf_sock_addr *ctx)
{
	struct toa_info *toa_val = NULL;

	if (!ctx->sk)
		return 1;

	toa_val = bpf_sk_storage_get(&sk_toa_map, ctx->sk, NULL, 0);
	if (!toa_val)
		return 1;

	if (toa_val->ip_valid) {
		ctx->user_ip6[0] = toa_val->cip6[0];
		ctx->user_ip6[1] = toa_val->cip6[1];
		ctx->user_ip6[2] = toa_val->cip6[2];
		ctx->user_ip6[3] = toa_val->cip6[3];
	}

	if (toa_val->port_valid)
		ctx->user_port = toa_val->cport;

	return 1;
}
