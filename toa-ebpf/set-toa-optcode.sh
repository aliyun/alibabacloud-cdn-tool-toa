#!/bin/sh
# SPDX-License-Identifier: BSD 2-Clause license

tcp_opt_code[0]="TCPOPT_EOL"
tcp_opt_code[1]="TCPOPT_NOP"
tcp_opt_code[2]="TCPOPT_MSS"
tcp_opt_code[3]="TCPOPT_WINDOW"
tcp_opt_code[4]="TCPOPT_SACK_PERM"
tcp_opt_code[5]="TCPOPT_SACK"
tcp_opt_code[8]="TCPOPT_TIMESTAMP"
tcp_opt_code[19]="TCPOPT_MD5SIG"
tcp_opt_code[30]="TCPOPT_MPTCP"
tcp_opt_code[34]="TCPOPT_FASTOPEN"

print_help() {
    echo "Usage: $0 [OPTIONS] [ARGUMENTS]"
    echo
    echo "Options:"
    echo "  -h, --help      Show this help message and exit"
    echo "  -c1,            Specify toa optcode"
    echo "  -c2,            Specify toa port optcode"
    echo
    echo "Examples:"
    echo "  $0 -c1 28 -c2 254"
}

check_opt_code() {
    if [ "${tcp_opt_code[$1]}" ]; then
        echo "Error: opt code $1 conflicts with ${tcp_opt_code[$1]}"
        exit 1
    fi
}

if [ $# -eq 0 ]; then
    echo "No arguments provided. Use -h or --help for usage information."
    exit 1
fi

while [[ "$1" != "" ]]; do
    case $1 in
        -h | --help)
            print_help
            exit
            ;;
        -c1 )
            shift
            toa_opcode=$1
            ;;
        -c2 )
            shift
            toa_port_opcode=$1
            ;;
        *)
            echo "Unknown option: $1"
            print_help
            exit 1
            ;;
    esac
    shift
done

if [ "$toa_opcode" ]; then
    check_opt_code $toa_opcode
fi

if [ "$toa_port_opcode" ]; then
    check_opt_code $toa_port_opcode
fi

if [ "$toa_opcode" ]; then
    bpftool map update name toa_opcode_map key 0 0 0 0 value $toa_opcode any
fi

if [ "$toa_port_opcode" ]; then
    bpftool map update name toa_opcode_map key 1 0 0 0 value $toa_port_opcode any
fi
