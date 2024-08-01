/*
 * Copyright (C) 2019-2024 Alibaba Group Holding Limited
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __TCP_TOA_H__
#define __TCP_TOA_H__

#define TOA_VERSION "2.0.0"

#ifdef TOA_DEBUG_ENABLE
#define TOA_DBG(msg...) do {			\
	printk(KERN_DEBUG "[DEBUG] TOA: " msg);	\
} while (0)
#else
#define TOA_DBG(msg...)
#endif

#define TOA_INFO(msg...) do {			\
	if (net_ratelimit())			\
		printk(KERN_INFO "TOA: " msg);	\
} while (0)

#define TCPOPT_TOA	28
#define TOA_IPV4	1
#define TOA_V4_LEN	7

struct toa_data {
	__u8 opcode;
	__u8 opsize;
	__u8 opversion;
	__be32 ip;
} __attribute__((packed));

enum toa_sock_flags {
	SOCK_TOA_IPV4 = 60,
};

/* statistics about toa in proc /proc/net/toa_stat */
enum {
	SYN_RECV_SOCK_TOA_CNT = 1,
	SYN_RECV_SOCK_NO_TOA_CNT,
	GETNAME_TOA_OK_CNT,
	GETNAME_TOA_MISMATCH_CNT,
	GETNAME_TOA_BYPASS_CNT,
	GETNAME_TOA_EMPTY_CNT,
	TOA_STAT_LAST
};

struct toa_stats_entry {
	char *name;
	int entry;
};

#define TOA_STAT_ITEM(_name, _entry) {	\
	.name = _name,			\
	.entry = _entry,		\
}

#define TOA_STAT_END {	\
	NULL,		\
	0,		\
}

struct toa_stat_mib {
	unsigned long mibs[TOA_STAT_LAST];
};

#define DEFINE_TOA_STAT(type, name)	\
	__typeof__(type) *name

#define TOA_INC_STATS(mib, field)	\
	(per_cpu_ptr(mib, smp_processor_id())->mibs[field]++)

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
#define req_wndclp (req->window_clamp)
#else
#define req_wndclp (req->rsk_window_clamp)
#endif

#endif
