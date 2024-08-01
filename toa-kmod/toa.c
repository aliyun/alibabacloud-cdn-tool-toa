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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/err.h>
#include <linux/time.h>
#include <linux/skbuff.h>
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <linux/fs.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/kallsyms.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <net/ipv6.h>
#include <net/transp_v6.h>
#include <net/route.h>

#include "toa.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#include <linux/kprobes.h>
static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};
#endif

/* statistics of toa in proc /proc/net/toa_stats */
struct toa_stats_entry toa_stats[] = {
	TOA_STAT_ITEM("syn_recv_sock_toa", SYN_RECV_SOCK_TOA_CNT),
	TOA_STAT_ITEM("syn_recv_sock_no_toa", SYN_RECV_SOCK_NO_TOA_CNT),
	TOA_STAT_ITEM("getname_toa_ok", GETNAME_TOA_OK_CNT),
	TOA_STAT_ITEM("getname_toa_mismatch", GETNAME_TOA_MISMATCH_CNT),
	TOA_STAT_ITEM("getname_toa_bypass", GETNAME_TOA_BYPASS_CNT),
	TOA_STAT_ITEM("getname_toa_empty", GETNAME_TOA_EMPTY_CNT),
	TOA_STAT_END
};

DEFINE_TOA_STAT(struct toa_stat_mib, ext_stats);

static struct proto *ptr_tcp_prot;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t ptr_kallsyms_lookup_name;

static struct proc_dir_entry *proc_toa_stat;

#define U32_MAX ((u32)~0U)

enum {
	TOA_NOT_FOUND,
	TOA_IPV4_FOUND,
};

/* parse TCP options in skb, try to get client ip, port
 * @param skb [in]  received skb, it should be a ack/get-ack packet.
 * @param in  [out] ipv4 addr if existed.
 * @return 0  nothing found.
 *         1  if ipv4 toa found.
 *         <0 error occurred.
 */
static int get_toa_data(struct sk_buff *skb, __be32 *in)
{
	struct tcphdr *th;
	int length;
	unsigned char *ptr;

	TOA_DBG("get_toa_data called\n");

	if (skb) {
		th = tcp_hdr(skb);
		length = (th->doff * 4) - sizeof(struct tcphdr);
		ptr = (unsigned char *) (th + 1);

		while (length > 0) {
			int opcode = *ptr++;
			int opsize;
			switch (opcode) {
			case TCPOPT_EOL:
				return TOA_NOT_FOUND;
			case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
				length--;
				continue;
			default:
				opsize = *ptr++;
				if (opsize < 2)	/* "silly options" */
					return TOA_NOT_FOUND;
				if (opsize > length)
					/* don't parse partial options */
					return TOA_NOT_FOUND;
				if (opcode == TCPOPT_TOA) {
					if (*ptr == TOA_IPV4 && opsize == TOA_V4_LEN && in) {
						memcpy(in, ptr + 1, sizeof(__be32));
						TOA_DBG("coded ip4 toa data: %pI4c\n", ptr + 1);
						return TOA_IPV4_FOUND;
					}
				}

				ptr += opsize - 2;
				length -= opsize;
			}
		}
	}
	return TOA_NOT_FOUND;
}

/* get client ip from socket
 * @param sock      [in]  the socket to getpeername() or getsockname()
 * @param uaddr     [out] the place to put client ip, port
 * @param uaddr_len [out] lenth of @uaddr
 * @param peer      [in]  if(peer), try to get remote address; if(!peer),
 *                        try to get local address
 * @return return what the original inet_getname() returns.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
static int inet_getname_toa(struct socket *sock, struct sockaddr *uaddr,
		int *uaddr_len, int peer)
#else
static int inet_getname_toa(struct socket *sock, struct sockaddr *uaddr,
		int peer)
#endif
{
	int retval = 0;
	struct sock *sk = sock->sk;
	struct sockaddr_in *sin = (struct sockaddr_in *) uaddr;
	struct toa_data *tdata;

	TOA_DBG("inet_getname_toa called, sk->sk_user_data is %p\n",
		sk->sk_user_data);

	/* call orginal one */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
	retval = inet_getname(sock, uaddr, uaddr_len, peer);
#else
	retval = inet_getname(sock, uaddr, peer);
#endif


	/* set our value if need */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
	if (!retval && sock_flag(sk, SOCK_TOA_IPV4) &&
#else
	if (retval > 0 && sock_flag(sk, SOCK_TOA_IPV4) &&
#endif
		sk->sk_user_data && peer) {
		if (sk->sk_family == AF_INET && sk->sk_type == SOCK_STREAM &&
		    sk->sk_prot == ptr_tcp_prot) {
			tdata = (struct toa_data*)&sk->sk_user_data;
			if (tdata->opcode == TCPOPT_TOA &&
			    tdata->opsize == TOA_V4_LEN &&
			    tdata->opversion == TOA_IPV4) {
				TOA_INC_STATS(ext_stats, GETNAME_TOA_OK_CNT);
				TOA_DBG("inet_getname_toa: set new sockaddr, ip "
					"%pI4c -> %pI4c\n",
					&sin->sin_addr.s_addr, &tdata->ip);
				sin->sin_addr.s_addr = tdata->ip;
			} else { /* sk_user_data doesn't belong to us */
				TOA_INC_STATS(ext_stats, GETNAME_TOA_MISMATCH_CNT);
			}
		} else {
			TOA_INC_STATS(ext_stats, GETNAME_TOA_BYPASS_CNT);
		}
	} else { /* no need to get client ip */
		TOA_INC_STATS(ext_stats, GETNAME_TOA_EMPTY_CNT);
	}

	return retval;
}

/* The three way handshake has completed - we got a valid synack -
 * now create the new socket.
 * We need to save toa data into the new socket.
 * @param sk  [out] the socket
 * @param skb [in]  the ack/ack-get packet
 * @param req [in]  the open request for this connection
 * @param dst [out] route cache entry
 * @return NULL if fail new socket if succeed.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static struct sock* tcp_v4_syn_recv_sock_toa(struct sock *sk, struct sk_buff *skb,
			struct request_sock *req, struct dst_entry *dst)
#else
static struct sock *tcp_v4_syn_recv_sock_toa(const struct sock *sk, struct sk_buff *skb,
			struct request_sock *req, struct dst_entry *dst,
			struct request_sock *req_unhash, bool *own_req)
#endif
{
	struct sock *newsock = NULL;
	struct tcp_sock *tp = tcp_sk(sk);
	struct toa_data tdata;
	__be32 ip = req_wndclp;
	void *ptr = NULL;

	TOA_DBG("tcp_v4_syn_recv_sock_toa called\n");

	if (tp->window_clamp)
		req_wndclp = tp->window_clamp;
	else
		req_wndclp = 0;

	/* copy from tcp_select_initial_window() */
	if (req_wndclp == 0)
		req_wndclp = 65535U << 14;

	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK)
		req_wndclp = min_t(u32, req_wndclp, tcp_full_space(sk));

	req_wndclp = min(65535U << inet_rsk(req)->rcv_wscale, req_wndclp);
	TOA_DBG("t4srst req: %p, tcp_wnd_clp: %u, wnd_clp: %u\n",
		req, tp->window_clamp, req_wndclp);

	WARN_ON_ONCE(!req_wndclp);

	/* call orginal one */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	newsock = tcp_v4_syn_recv_sock(sk, skb, req, dst);
#else
	newsock = tcp_v4_syn_recv_sock(sk, skb, req, dst, req_unhash, own_req);
#endif

	/* clear TOA flag */
	if (newsock)
		sock_reset_flag(newsock, SOCK_TOA_IPV4);

	/* set our value if need */
	if (newsock && newsock->sk_family == AF_INET &&
	    newsock->sk_type == SOCK_STREAM && newsock->sk_prot == ptr_tcp_prot &&
	    !newsock->sk_user_data) {
		if (ip != 65535U) {
			tdata.opcode = TCPOPT_TOA;
			tdata.opsize = TOA_V4_LEN;
			tdata.opversion = TOA_IPV4;
			tdata.ip = ip;
			memcpy(&ptr, &tdata, sizeof(struct toa_data));
			newsock->sk_user_data = ptr;
			sock_set_flag(newsock, SOCK_TOA_IPV4);
			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_TOA_CNT);
		} else {
			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_NO_TOA_CNT);
		}

		TOA_DBG("tcp_v4_syn_recv_sock_toa: set "
			"sk->sk_user_data to %p\n",
			newsock->sk_user_data);
	}
	return newsock;
}

static int tcp_v4_conn_request_toa(struct sock *sk, struct sk_buff *skb)
{
	struct request_sock *req, **prev;
	struct tcphdr *th = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	__be32 addr;
	int toa_found;
	int ret;

	TOA_DBG("tcp_v4_conn_request_toa called\n");

	/* call orginal one */
	ret = tcp_v4_conn_request(sk, skb);

	if (!ret && sk->sk_family == AF_INET && sk->sk_type == SOCK_STREAM &&
	    sk->sk_prot == ptr_tcp_prot) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		req = inet_csk_search_req(sk, &prev, th->source, iph->saddr, iph->daddr);
#else
		if (unlikely(!skb_dst(skb))) {
			TOA_INFO("There is not destination route entry in skb\n");
			return ret;
		}
		req = (struct request_sock *)inet_lookup_established(dev_net(skb_dst(skb)->dev),
											&tcp_hashinfo, iph->saddr, th->source,
											iph->daddr, th->dest, inet_iif(skb));
 #endif
		if (req) {
			TOA_DBG("t4crt req: %p, tcp_wnd_clp: %u, wnd_clp: %u\n",
				req, tcp_sk(sk)->window_clamp, req_wndclp);
			req_wndclp = 65535U;
			toa_found = get_toa_data(skb, &addr);
			if (toa_found == TOA_IPV4_FOUND)
				req_wndclp = addr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
			reqsk_put(req);
#endif
		}
	}

	return ret;
}

/* replace the functions with our functions */
static inline int hook_toa_functions(void)
{
	unsigned int level;
	pte_t *pte;
	bool pte_changed = false;

	/* hook inet_getname for ipv4 */
	struct proto_ops *inet_stream_ops_p =
			(struct proto_ops *)&inet_stream_ops;
	/* hook tcp_v4_syn_recv_sock for ipv4 */
	struct inet_connection_sock_af_ops *ipv4_specific_p =
			(struct inet_connection_sock_af_ops *)&ipv4_specific;

	pte = lookup_address((unsigned long )inet_stream_ops_p, &level);
	if (!pte)
		return 1;
	if (!(pte->pte & _PAGE_RW)) {
		pte->pte |= _PAGE_RW;
		pte_changed = true;
	}

	inet_stream_ops_p->getname = inet_getname_toa;
	TOA_INFO("CPU [%u] hooked inet_getname <%pK> --> <%pK>\n",
		smp_processor_id(), inet_getname,
		inet_stream_ops_p->getname);

	if (pte_changed) {
		pte->pte &= ~_PAGE_RW;
		pte_changed = false;
	}

	pte = lookup_address((unsigned long )ipv4_specific_p, &level);
	if (!pte)
		return 1;
	if (!(pte->pte & _PAGE_RW)) {
		pte->pte |= _PAGE_RW;
		pte_changed = true;
	}

	ipv4_specific_p->syn_recv_sock = tcp_v4_syn_recv_sock_toa;
	TOA_INFO("CPU [%u] hooked tcp_v4_syn_recv_sock <%pK> --> <%pK>\n",
		smp_processor_id(), tcp_v4_syn_recv_sock,
		ipv4_specific_p->syn_recv_sock);

	ipv4_specific_p->conn_request = tcp_v4_conn_request_toa;
	TOA_INFO("CPU [%u] hooked tcp_v4_conn_request <%pK> --> <%pK>\n",
		smp_processor_id(), tcp_v4_conn_request,
		ipv4_specific_p->conn_request);

	if (pte_changed) {
		pte->pte &= ~_PAGE_RW;
		pte_changed = false;
	}

	return 0;
}

/* replace the functions to original ones */
static int unhook_toa_functions(void)
{
	unsigned int level;
	pte_t *pte;
	bool pte_changed = false;

	/* unhook inet_getname for ipv4 */
	struct proto_ops *inet_stream_ops_p =
			(struct proto_ops *)&inet_stream_ops;
	/* unhook tcp_v4_syn_recv_sock for ipv4 */
	struct inet_connection_sock_af_ops *ipv4_specific_p =
			(struct inet_connection_sock_af_ops *)&ipv4_specific;

	pte = lookup_address((unsigned long )inet_stream_ops_p, &level);
	if (!pte)
		return 1;
	if (!(pte->pte & _PAGE_RW)) {
		pte->pte |= _PAGE_RW;
		pte_changed = true;
	}

	inet_stream_ops_p->getname = inet_getname;
	TOA_INFO("CPU [%u] unhooked inet_getname\n",
		 smp_processor_id());

	if (pte_changed) {
		pte->pte &= ~_PAGE_RW;
		pte_changed = false;
	}

	pte = lookup_address((unsigned long )ipv4_specific_p, &level);
	if (!pte)
		return 1;
	if (!(pte->pte & _PAGE_RW)) {
		pte->pte |= _PAGE_RW;
		pte_changed = true;
	}

	ipv4_specific_p->syn_recv_sock = tcp_v4_syn_recv_sock;
	TOA_INFO("CPU [%u] unhooked tcp_v4_syn_recv_sock\n",
		 smp_processor_id());

	ipv4_specific_p->conn_request = tcp_v4_conn_request;
	TOA_INFO("CPU [%u] unhooked tcp_v4_conn_request\n",
		 smp_processor_id());

	if (pte_changed) {
		pte->pte &= ~_PAGE_RW;
		pte_changed = false;
	}

	return 0;
}

/* statistics of toa in proc /proc/net/toa_stats */
static int toa_stats_show(struct seq_file *seq, void *v)
{
	int i, j, cpu_nr;

	/* print CPU first */
	seq_printf(seq, "                                  ");
	cpu_nr = num_possible_cpus();
	for (i = 0; i < cpu_nr; i++)
		if (cpu_online(i))
			seq_printf(seq, "CPU%d       ", i);
	seq_putc(seq, '\n');

	i = 0;
	while (NULL != toa_stats[i].name) {
		seq_printf(seq, "%-25s:", toa_stats[i].name);
		for (j = 0; j < cpu_nr; j++) {
			if (cpu_online(j)) {
				seq_printf(seq, "%10lu ",
				    *(((unsigned long *) per_cpu_ptr(
				       ext_stats, j)) + toa_stats[i].entry));
			}
		}
		seq_putc(seq, '\n');
		i++;
	}
	return 0;
}

static int toa_stats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, toa_stats_show, NULL);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
static const struct file_operations toa_stats_ops = {
	.owner = THIS_MODULE,
	.open = toa_stats_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#else
static const struct proc_ops toa_stats_ops = {
	.proc_open = toa_stats_seq_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
/* TOA module init and destory */
int kln_lookup(void *data, const char *name, struct module *mod,
			   unsigned long addr)
{
	if (!mod && !strcmp(name, "kallsyms_lookup_name")) {
		ptr_kallsyms_lookup_name = (void*)addr;
		return 1;
	}

	return 0;
}
#endif

static int toa_get_symbols(void){
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	kallsyms_on_each_symbol(kln_lookup, NULL);
#elif  LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
	ptr_kallsyms_lookup_name = kallsyms_lookup_name;
#else
	register_kprobe(&kp);
	ptr_kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif

	if (WARN_ON(!ptr_kallsyms_lookup_name)) {
		pr_err("ptr_kallsyms_lookup_name is NULL\n");
		return -EFAULT;
	}

#define GET_SYM(name, type) do {					\
	ptr_##name = (type)ptr_kallsyms_lookup_name(#name);		\
	if (!ptr_##name) {						\
		pr_err("tcp_toa: symbol " #name " not found\n");	\
		return -EFAULT;						\
	}								\
} while (0)

	GET_SYM(tcp_prot, struct proto*);
	return 0;
}

/* module init */
static int __init toa_init(void)
{
	int ret = 0;

	TOA_INFO("tcp_toa " TOA_VERSION " insmod\n");

	BUILD_BUG_ON(sizeof(((struct sock*)0)->sk_flags) < 8);

	if (toa_get_symbols())
		return -EFAULT;

	/* alloc statistics array for toa */
	ext_stats = alloc_percpu(struct toa_stat_mib);
	if (!ext_stats)
		return -ENOMEM;

	proc_toa_stat = proc_create("toa_stats", 0444, init_net.proc_net, &toa_stats_ops);
	if (!proc_toa_stat) {
		TOA_INFO("cannot create proc.\n");
		ret = -ENOMEM;
		goto free_stats;
	}

	/* hook funcs for parse and get toa */
	if (hook_toa_functions()) {
		TOA_INFO("cannot hook toa functions.\n");
		ret = -EFAULT;
		goto unhook;
	}

	TOA_INFO("tcp_toa loaded\n");
	return 0;

unhook:
	unhook_toa_functions();
	synchronize_net();
	remove_proc_entry("toa_stats", init_net.proc_net);

free_stats:
	if (ext_stats) {
		free_percpu(ext_stats);
		ext_stats = NULL;
	}

	return ret;
}

/* module cleanup */
static void __exit toa_exit(void)
{
	TOA_INFO("tcp_toa " TOA_VERSION " rmmod\n");

	unhook_toa_functions();
	synchronize_net();
	remove_proc_entry("toa_stats", init_net.proc_net);

	if (ext_stats) {
		free_percpu(ext_stats);
		ext_stats = NULL;
	}

	TOA_INFO("tcp_toa unloaded\n");
}

module_init(toa_init);
module_exit(toa_exit);

MODULE_DESCRIPTION("TOA(TCP Option Address) parser");
MODULE_LICENSE("GPL");
