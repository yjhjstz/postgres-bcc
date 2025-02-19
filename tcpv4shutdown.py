#!/usr/bin/python
#
# tcpv4shutdown	Trace TCP IPv4 shutdown()s.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpv4shutdown [-h] [-t] [-p PID]
#
# This is provided as a basic example of TCP connection & socket tracing.
#
# All IPv4 connection attempts are traced, even if they ultimately fail.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Oct-2015	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);
BPF_HASH(currsock2, u32, struct sock *);

int kprobe__tcp_shutdown(struct pt_regs *ctx, struct sock *sk, int how)
{
    u32 pid = bpf_get_current_pid_tgid();

    // stash the sock ptr for lookup on return
    currsock.update(&pid, &sk);

    return 0;
};

int kretprobe__tcp_shutdown(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;	// missed entry
    }

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&pid);
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u32 saddr = skp->__sk_common.skc_rcv_saddr;
    u32 daddr = skp->__sk_common.skc_daddr;
    u16 dport = skp->__sk_common.skc_dport;

    // output
    bpf_trace_printk("trace_tcp4shutdown %x %x %d\\n", saddr, daddr, ntohs(dport));

    currsock.delete(&pid);

    return 0;
}

int kprobe__tcp_close(struct pt_regs *ctx, struct sock *sk, int how)
{
    u32 pid = bpf_get_current_pid_tgid();

    // stash the sock ptr for lookup on return
    currsock2.update(&pid, &sk);

    return 0;
};

int kretprobe__tcp_close(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = currsock2.lookup(&pid);
    if (skpp == 0) {
        return 0;	// missed entry
    }

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock2.delete(&pid);
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u32 saddr = skp->__sk_common.skc_rcv_saddr;
    u32 daddr = skp->__sk_common.skc_daddr;
    u16 dport = skp->__sk_common.skc_dport;

    // output
    bpf_trace_printk("trace_tcp4close %x %x %d\\n", saddr, daddr, ntohs(dport));

    currsock2.delete(&pid);

    return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)

# header
print("%-6s %-6s %-12s %-16s %-16s %-4s" % ("TYPE", "PID", "COMM", "SADDR", "DADDR",
    "DPORT"))

def inet_ntoa(addr):
    dq = b''
    for i in range(0, 4):
        dq = dq + str(addr & 0xff).encode()
        if (i != 3):
            dq = dq + b'.'
        addr = addr >> 8
    return dq

# filter and format output
while 1:
    # Read messages from kernel pipe
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        (_tag, saddr_hs, daddr_hs, dport_s) = msg.split(b" ")
    except ValueError:
        # Ignore messages from other tracers
        continue
    except KeyboardInterrupt:
        exit()

    # Ignore messages from other tracers
    if task != b"postgres":
        continue

    if _tag.decode() == "trace_tcp4shutdown":
        printb(b"shutdown %-6d %-12.12s %-16s %-16s %-4s" % (pid, task,
            inet_ntoa(int(saddr_hs, 16)),
            inet_ntoa(int(daddr_hs, 16)),
            dport_s))
    elif _tag.decode() == "trace_tcp4close":
        printb(b"close %-6d %-12.12s %-16s %-16s %-4s" % (pid, task,
            inet_ntoa(int(saddr_hs, 16)),
            inet_ntoa(int(daddr_hs, 16)),
            dport_s))
    else:
        continue
