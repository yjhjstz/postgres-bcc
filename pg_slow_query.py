from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 start_ts;
    u64 end_ts;
    u32 pid;
    char query[256];
};

BPF_HASH(start, u32, struct data_t);
BPF_PERF_OUTPUT(events);

int trace_pg_parse_query_entry(struct pt_regs *ctx, const char *query_string) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    struct data_t data = {};
    data.start_ts = ts;
    data.pid = pid;
    bpf_probe_read_str(data.query, sizeof(data.query), query_string);

    start.update(&pid, &data);
    return 0;
}

int trace_pg_parse_query_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t *data_ptr = start.lookup(&pid);
    if (!data_ptr) {
        return 0;
    }

    struct data_t data = *data_ptr;
    data.end_ts = bpf_ktime_get_ns();

    events.perf_submit(ctx, &data, sizeof(data));
    start.delete(&pid);
    return 0;
}
"""

bpf = BPF(text=bpf_text)
bpf.attach_uprobe(
    name="/usr/local/gpdb/bin/postgres",
    sym="exec_simple_query",
    fn_name="trace_pg_parse_query_entry"
)
bpf.attach_uretprobe(
    name="/usr/local/gpdb/bin/postgres",
    sym="exec_simple_query",
    fn_name="trace_pg_parse_query_return"
)

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    duration_ms = (event.end_ts - event.start_ts) / 1e6
    print(f"{event.start_ts} {event.pid} {event.query.decode('utf-8', 'replace')} {duration_ms} ms")

bpf["events"].open_perf_buffer(print_event)

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break
