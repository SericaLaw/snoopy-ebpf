// +build ignore
#include "snoopy.bpf.h"

#define TASK_COMM_LEN 16
#define MAX_LOOP 128
#define MAX_STRING_SIZE 128

BPF_PERF_OUTPUT(execve_out)
BPF_PERF_OUTPUT(execveat_out)
BPF_HASH(config_map, u32, u32)

#define CONFIG_MAX_ARG 0
#define CONFIG_MAX_ENV 1

static __always_inline int get_config(u32 key) {
    u32 *config = bpf_map_lookup_elem(&config_map, &key);
    if (config == NULL)
        return 0;

    return *config;
}

#define DATA_ARG 0
#define DATA_ENV 1
#define DATA_RET 2

typedef struct event_data {
    u64 ts;

    u32 type;
    u32 pid;
    u32 tid;
    u32 uid;

    s64 ret;

    char comm[TASK_COMM_LEN];
    char payload[MAX_STRING_SIZE];
} event_data_t;

struct sys_enter_execve_args {
    unsigned long long unused;
    long syscall_nr;
    long filename;  // const char *
    long argv;  // const char *const *
    long envp;  // const char *const *
};

struct sys_enter_execveat_args {
    unsigned long long unused;
    long syscall_nr;
    long fd;
    long filename;
    long argv;
    long envp;
};

struct sys_exit_args {
    unsigned long long unused;
    long syscall_nr;
    long ret;
};

static __always_inline void init_context(event_data_t *data) {
    data->ts = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    data->tid = id;
    data->pid = id >> 32;
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__sys_enter_execve(struct sys_enter_execve_args *ctx) {
    event_data_t data = {};
    data.type = DATA_ARG;
    init_context(&data);

    const char *filename = ctx->filename;
    if (!filename) {
        return -1;
    }

    int size = bpf_probe_read_str(&data.payload, MAX_STRING_SIZE, filename);
    if (size > 0) {
        bpf_perf_event_output(ctx, &execve_out, BPF_F_CURRENT_CPU, &data, sizeof(data) - sizeof(data.payload) + size);
    } else {
        return -1;
    }

    const char *const * argv = ctx->argv;
    u32 max_arg = get_config(CONFIG_MAX_ARG);

    #pragma unroll
    for (int i = 1; i < max_arg && i < MAX_LOOP; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &argv[i]);
        if (!argp) {
            break;
        }
        int size = bpf_probe_read_str(&data.payload, MAX_STRING_SIZE, argp);
        if (size > 0) {
            bpf_perf_event_output(ctx, &execve_out, BPF_F_CURRENT_CPU, &data, sizeof(data) - sizeof(data.payload) + size);
        } else {
            break;
        }
    }

    data.type = DATA_ENV;
    const char *const * envp = ctx->envp;
    int max_env = get_config(CONFIG_MAX_ENV);

    #pragma unroll
    for (int i = 1; i < max_env && i < MAX_LOOP; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &envp[i]);
        if (!argp) {
            break;
        }
        int size = bpf_probe_read_str(&data.payload, MAX_STRING_SIZE, argp);
        if (size > 0) {
            bpf_perf_event_output(ctx, &execve_out, BPF_F_CURRENT_CPU, &data, sizeof(data) - sizeof(data.payload) + size);
        } else {
            break;
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__sys_exit_execve(struct sys_exit_args *ctx) {
    event_data_t data = {};
    data.type = DATA_RET;
    init_context(&data);

    data.ret = ctx->ret;
    bpf_perf_event_output(ctx, &execve_out, BPF_F_CURRENT_CPU, &data, sizeof(data) - sizeof(data.payload));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tracepoint__sys_enter_execveat(struct sys_enter_execveat_args *ctx) {
    event_data_t data = {};
    data.type = DATA_ARG;
    init_context(&data);

    const char *filename = ctx->filename;
    if (!filename) {
        return -1;
    }

    int size = bpf_probe_read_str(&data.payload, MAX_STRING_SIZE, filename);
    if (size > 0) {
        bpf_perf_event_output(ctx, &execveat_out, BPF_F_CURRENT_CPU, &data, sizeof(data) - sizeof(data.payload) + size);
    } else {
        return -1;
    }

    const char *const * argv = ctx->argv;
    u32 max_arg = get_config(CONFIG_MAX_ARG);

    #pragma unroll
    for (int i = 1; i < max_arg && i < MAX_LOOP; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &argv[i]);
        if (!argp) {
            break;
        }
        int size = bpf_probe_read_str(&data.payload, MAX_STRING_SIZE, argp);
        if (size > 0) {
            bpf_perf_event_output(ctx, &execveat_out, BPF_F_CURRENT_CPU, &data, sizeof(data) - sizeof(data.payload) + size);
        } else {
            break;
        }
    }

    data.type = DATA_ENV;
    const char *const * envp = ctx->envp;
    int max_env = get_config(CONFIG_MAX_ENV);

    #pragma unroll
    for (int i = 1; i < max_env && i < MAX_LOOP; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &envp[i]);
        if (!argp) {
            break;
        }
        int size = bpf_probe_read_str(&data.payload, MAX_STRING_SIZE, argp);
        if (size > 0) {
            bpf_perf_event_output(ctx, &execveat_out, BPF_F_CURRENT_CPU, &data, sizeof(data) - sizeof(data.payload) + size);
        } else {
            break;
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int tracepoint__sys_exit_execveat(struct sys_exit_args *ctx) {
    event_data_t data = {};
    data.type = DATA_RET;
    init_context(&data);

    data.ret = ctx->ret;
    bpf_perf_event_output(ctx, &execveat_out, BPF_F_CURRENT_CPU, &data, sizeof(data) - sizeof(data.payload));
    return 0;
}
