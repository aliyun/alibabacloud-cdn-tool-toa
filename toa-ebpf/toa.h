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

#ifndef __TOA_H__
#define __TOA_H__

struct toa_info {
	__u8 ip_valid;
	__u8 port_valid;
	__be16 cport;
	union {
		__be32 cip;
		__be32 cip6[4];
	};
};

#pragma pack(1)
union toa_opt {
	struct toa {
		__u8 opcode;
		__u8 opsize;
		__u8 opversion;
		__be32 ip;
	} toa;
	struct toa_v6 {
		__u8 opcode;
		__u8 opsize;
		__u8 opversion;
		__be32 ip[4];
	} toa_v6;
	struct toa_port {
		__u8 opcode;
		__u8 opsize;
		__be16 port;
		__be32 ip;
	} toa_port;
	struct toa_port_v6 {
		__u8 opcode;
		__u8 opsize;
		__be16 port;
		__be32 ip[4];
	} toa_port_v6;
	__u8 data[20];
};
#pragma pack()

#define TCPOPT_EOL		 0
#define TCPOPT_NOP		 1
#define TCPOPT_TOA	     28
#define TCPOPT_TOA_PORT  254
#define TCPOPT_EXP		 254

#define TOA_V4_LEN	     7
#define TOA_V6_LEN       19

#define TOA_PORT_V4_LEN  8 
#define TOA_PORT_V6_LEN  20

#define TCPHDR_FIN       0x01
#define TCPHDR_SYN       0x02
#define TCPHDR_RST       0x04
#define TCPHDR_PSH       0x08
#define TCPHDR_ACK       0x10
#define TCPHDR_URG       0x20
#define TCPHDR_ECE       0x40
#define TCPHDR_CWR       0x80
#define TCPHDR_SYNACK    (TCPHDR_SYN | TCPHDR_ACK)

#define SOL_TCP          6

#define TCPOPT_FASTOPEN		34	/* Fast open (RFC7413) */
#define TCPOPT_FASTOPEN_MAGIC	0xF989

#endif /* __TOA_H__ */