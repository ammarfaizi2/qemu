/*
 * qmon.so - a QEMU TCG introspection plugin.
 *
 * Exposes a tiny framed protocol over a unix socket so that an *external*
 * program can, against a running TCG guest, and without ptrace:
 *
 *   1. dump guest CPU registers              (READ_REGS)
 *   2. dump guest virtual / physical memory  (READ_VMEM / READ_PMEM)
 *   3. translate gva->gpa and list mappings  (XLATE / LIST_MAP)
 *   4. set a memory watchpoint + get events  (SET_WATCH -> EV_WATCH)
 *   5. set a %rip breakpoint + freeze/inspect (SET_BREAK -> EV_BREAK)
 *
 * Build out-of-tree: depends only on <qemu-plugin.h> and glib. See Makefile.
 *
 * Design note (important): qemu_plugin_read_register(),
 * qemu_plugin_read_memory_vaddr()/hwaddr() and qemu_plugin_translate_vaddr()
 * are only valid on the *vCPU thread, inside a callback*. The socket I/O runs
 * on its own pthread, so it cannot touch guest state directly. Instead it
 * enqueues a command that a vCPU-thread callback (the per-TB "pump", or the
 * stop-loop of a vCPU frozen at a breakpoint) executes and completes. Because
 * those reads happen at a TB-boundary safe point, the snapshots are consistent
 * (no torn reads, env fully synced).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * 
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <glib.h>
#include <qemu-plugin.h>

#include "probe_ylang.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* ------------------------------------------------------------------ */
/* Wire protocol                                                       */
/* ------------------------------------------------------------------ */
/* Every message is: u32 len (LE) followed by len payload bytes.       */
/* payload[0] is the message type, the rest is type specific.          */

enum {
    /* requests (client -> plugin) */
    REQ_PING       = 0x01,
    REQ_READ_REGS  = 0x10, /* u32 vcpu */
    REQ_READ_VMEM  = 0x11, /* u32 vcpu, u64 addr, u32 len */
    REQ_READ_PMEM  = 0x12, /* u32 vcpu, u64 addr, u32 len */
    REQ_XLATE      = 0x13, /* u32 vcpu, u64 addr */
    REQ_LIST_MAP   = 0x14, /* u32 vcpu */
    REQ_CONTEXT    = 0x15, /* u32 vcpu -> ring + sym(rip) + pid + comm */
    REQ_BACKTRACE  = 0x16, /* u32 vcpu, u32 max -> frames */
    REQ_SLIDE      = 0x17, /* () -> u8 calibrated, u64 kaslr text slide */
    REQ_YLANG_ENABLE = 0x18, /* u8 on -> enable/disable the ylang bridge */
    REQ_YLANG_WINDOW = 0x19, /* u8 on, u64 lo, u64 hi -> set/clear the %rip window */
    REQ_SET_BREAK  = 0x20, /* u64 addr */
    REQ_CLR_BREAK  = 0x21, /* u64 addr */
    REQ_SET_WATCH  = 0x22, /* u64 addr, u64 len, u8 rw (1=R,2=W,3=RW) */
    REQ_CLR_WATCH  = 0x23, /* u64 addr */
    REQ_RESOLVE    = 0x24, /* cstring name -> u64 runtime addr */
    REQ_SYM        = 0x25, /* u64 addr -> sym(addr) */
    REQ_CONTINUE   = 0x30, /* u32 vcpu (0xffffffff = all) */

    /* responses / events (plugin -> client) */
    RSP_OK         = 0x80, /* type-specific payload */
    RSP_ERR        = 0x81, /* u32 code, cstring msg */
    EV_BREAK       = 0xA0, /* u32 vcpu, u64 rip, u64 bp_addr, <context>, <backtrace> */
    EV_WATCH       = 0xA1, /* u32 vcpu, u64 rip, u64 addr, u8 store, u8 size, u64 val */

    /* sub-encodings reused by several messages:
     *   sym      = u8 namelen, name[namelen], u64 offset
     *   context  = u8 ring, sym(rip), u32 pid, u8 commlen, comm[commlen]
     *   backtrace= u32 nframes, nframes x { u64 addr, sym(addr) }
     */
};

#define QMON_MAX_FRAME (1u << 20)
#define QMON_REQ_TIMEOUT_US (2 * 1000 * 1000)   /* abandon if no vCPU services */
#define QMON_MAX_MAPS  8192
#define QMON_MAX_WALK  (1u << 22)               /* PTE-read budget for LIST_MAP */

/* ------------------------------------------------------------------ */
/* little-endian encode/decode helpers                                 */
/* ------------------------------------------------------------------ */

static void le32enc(uint8_t *p, uint32_t v)
{
    p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}
static void le64enc(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}
static uint32_t le32dec(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t le64dec(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

/* GByteArray builders */
static void p8(GByteArray *b, uint8_t v) { g_byte_array_append(b, &v, 1); }
static void p32(GByteArray *b, uint32_t v) { uint8_t t[4]; le32enc(t, v); g_byte_array_append(b, t, 4); }
static void p64(GByteArray *b, uint64_t v) { uint8_t t[8]; le64enc(t, v); g_byte_array_append(b, t, 8); }

/* request reader with bounds checking */
typedef struct {
    const uint8_t *p;
    size_t n, off;
    bool err;
} Rd;

static uint8_t g8(Rd *r)
{
    if (r->off + 1 > r->n) { r->err = true; return 0; }
    return r->p[r->off++];
}
static uint32_t g32(Rd *r)
{
    if (r->off + 4 > r->n) { r->err = true; return 0; }
    uint32_t v = le32dec(r->p + r->off); r->off += 4; return v;
}
static uint64_t g64(Rd *r)
{
    if (r->off + 8 > r->n) { r->err = true; return 0; }
    uint64_t v = le64dec(r->p + r->off); r->off += 8; return v;
}

/* ------------------------------------------------------------------ */
/* global state                                                        */
/* ------------------------------------------------------------------ */

/* command serviced on a vCPU thread (one in flight at a time) */
typedef struct {
    int type;
    uint32_t vcpu;
    uint64_t addr;
    uint32_t len;
    bool any_vcpu;          /* may be serviced by any vCPU */
    GByteArray *out;        /* RSP_OK payload built here */
    int status;             /* 0 = ok, !=0 = error */
    char err[96];
    bool claimed;
    bool done;
} Cmd;

static GMutex lock;             /* protects everything below */
static GCond done_cond;         /* signalled when an in-flight Cmd completes */
static GCond work_cond;         /* wakes a frozen vCPU's stop-loop */
static Cmd *g_inflight;

static GHashTable *bp_set;      /* key: gint64* gva -> membership */
static GArray *wp_list;         /* Watch[] */
static _Atomic int n_bp;        /* fast-path gate for bp_cb */
static _Atomic int n_wp;        /* fast-path gate for wp_cb */
static _Atomic int pending;     /* fast-path gate for the pump */

static bool *stopped;           /* per-vcpu: frozen in a breakpoint stop-loop */
static bool *continue_req;      /* per-vcpu: client asked to resume */
static int g_max_vcpus = 1;

static GArray *g_regs;          /* qemu_plugin_reg_descriptor[] (captured once) */
static bool g_regs_done;

static GMutex wlock;            /* serialises socket writes (RSP + events) */
static _Atomic int conn_fd = -1;
static char *g_sock_path;
static qemu_plugin_id_t g_id;
static bool feat_bp = true;     /* instrument insns for breakpoints */
static bool feat_wp = true;     /* instrument mem ops for watchpoints */

/*
 * ylang bridge (objective: one probe target per command).  When on, the per-TB
 * pump snapshots the guest registers and hands them to qemu_ylang_cpu_reg_dump()
 * so an external ylang uprobe can observe them.  Off by default (it adds a
 * register read-out per block).  ylang_lo/ylang_hi optionally gate the call to a
 * %rip window - the plugin-side analogue of a breakpoint address - so neither
 * the fill nor the uprobe fires for every block; unset means "every block".
 */
/* Toggled at load time (args) and at runtime (REQ_YLANG_*), read on the vCPU
 * thread in pump_cb -> atomic. The window bounds are two independent atomics; a
 * concurrent update can momentarily mix old-lo/new-hi, which only mis-filters a
 * single block. */
static _Atomic bool     feat_ylang;
static _Atomic uint64_t g_ylang_lo;
static _Atomic uint64_t g_ylang_hi = UINT64_MAX;

typedef struct {
    uint64_t addr;
    uint64_t len;
    uint8_t rw;                 /* 1=R, 2=W, 3=RW */
} Watch;

/* ------------------------------------------------------------------ */
/* socket I/O                                                          */
/* ------------------------------------------------------------------ */

static int read_n(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r == 0) { return 0; }
        if (r < 0) { if (errno == EINTR) { continue; } return -1; }
        p += r; n -= (size_t)r;
    }
    return 1;
}

static int write_n(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n) {
        ssize_t r = write(fd, p, n);
        if (r <= 0) { if (r < 0 && errno == EINTR) { continue; } return -1; }
        p += r; n -= (size_t)r;
    }
    return 0;
}

/* atomically write one framed message to the current connection */
static void send_frame(const uint8_t *payload, uint32_t len)
{
    int fd = atomic_load(&conn_fd);
    if (fd < 0) { return; }
    uint8_t hdr[4];
    le32enc(hdr, len);
    g_mutex_lock(&wlock);
    if (write_n(fd, hdr, 4) == 0) {
        write_n(fd, payload, len);
    }
    g_mutex_unlock(&wlock);
}

static void send_ba(GByteArray *b)
{
    send_frame(b->data, b->len);
}

static void reply_ok_empty(void)
{
    GByteArray *b = g_byte_array_new();
    p8(b, RSP_OK);
    send_ba(b);
    g_byte_array_free(b, TRUE);
}

static void reply_err(uint32_t code, const char *msg)
{
    GByteArray *b = g_byte_array_new();
    p8(b, RSP_ERR);
    p32(b, code);
    g_byte_array_append(b, (const uint8_t *)msg, strlen(msg) + 1);
    send_ba(b);
    g_byte_array_free(b, TRUE);
}

/* ------------------------------------------------------------------ */
/* register helpers (must run in vCPU context)                          */
/* ------------------------------------------------------------------ */

static struct qemu_plugin_register *find_reg(const char *name)
{
    if (!g_regs) { return NULL; }
    for (guint i = 0; i < g_regs->len; i++) {
        qemu_plugin_reg_descriptor *d =
            &g_array_index(g_regs, qemu_plugin_reg_descriptor, i);
        if (d->name && g_ascii_strcasecmp(d->name, name) == 0) {
            return d->handle;
        }
    }
    return NULL;
}

/* read a register as a little-endian u64 into a caller-provided buffer (reused
 * across many reads to avoid a per-register allocation on the hot path) */
static bool read_reg_into(GByteArray *b, const char *name, uint64_t *out)
{
    *out = 0;
    struct qemu_plugin_register *h = find_reg(name);
    if (!h) { return false; }
    g_byte_array_set_size(b, 0);
    if (!qemu_plugin_read_register(h, b)) { return false; }
    uint64_t v = 0;
    for (guint i = 0; i < b->len && i < 8; i++) {
        v |= (uint64_t)b->data[i] << (8 * i);
    }
    *out = v;
    return true;
}

/* read a register as a little-endian u64 (x86 control/general regs) */
static bool read_reg_u64(const char *name, uint64_t *out)
{
    GByteArray *b = g_byte_array_new();
    bool ok = read_reg_into(b, name, out);
    g_byte_array_free(b, TRUE);
    return ok;
}

/* ------------------------------------------------------------------ */
/* kernel symbols (System.map / kallsyms), BTF, unwinding, context     */
/* ------------------------------------------------------------------ */

#define QMON_THREAD_SIZE 16384
#define QMON_MAX_FRAMES  64

/* KASLR text slide is a multiple of 2 MB within the kernel randomization range. */
#define QMON_KASLR_STEP 0x200000ULL
#define QMON_KASLR_MAX  0x40000000ULL   /* 1 GiB search window */

typedef struct { uint64_t addr; char *name; } Ksym;

static Ksym    *g_ksyms;            /* sorted ascending by link-time addr */
static size_t   g_nksyms;
static char    *g_ksyms_path;
static char    *g_btf_path;
static uint64_t g_text_slide;       /* runtime = link-time + slide (KASLR) */
static uint64_t g_anchor_va;        /* link-time addr of linux_banner (slide anchor) */
static _Atomic int g_calibrated;    /* 1 once g_text_slide is known/valid */
static _Atomic unsigned long g_tick;   /* TB counter, throttles calibration */
static bool     g_slide_forced;     /* slide= passed -> skip auto-detection */
static uint64_t g_stext, g_etext;   /* link-time text bounds (0 if unknown) */
static uint64_t g_orc_ip_link;      /* link-time __start_orc_unwind_ip */
static uint64_t g_orc_link;         /* link-time __start_orc_unwind */
static size_t   g_orc_n;            /* number of ORC entries */
static bool     g_orc_ok;           /* kernel exposes ORC unwind tables */
static uint64_t g_current_off;      /* per-cpu offset of current_task */
static bool     g_have_current;
static long     g_comm_off = -1;    /* offsetof(task_struct, comm) */
static long     g_pid_off  = -1;    /* offsetof(task_struct, pid)  */

static int ksym_cmp(const void *a, const void *b)
{
    uint64_t x = ((const Ksym *)a)->addr, y = ((const Ksym *)b)->addr;
    return x < y ? -1 : x > y ? 1 : 0;
}

/* name for a runtime text address (bisect on link-time value) */
static const char *ksym_lookup(uint64_t rt_addr, uint64_t *off)
{
    if (!g_nksyms) { return NULL; }
    uint64_t key = rt_addr - g_text_slide;
    size_t lo = 0, hi = g_nksyms;       /* first index with addr > key */
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (g_ksyms[mid].addr <= key) { lo = mid + 1; } else { hi = mid; }
    }
    if (lo == 0) { return NULL; }
    const Ksym *s = &g_ksyms[lo - 1];
    if (off) { *off = key - s->addr; }
    return s->name;
}

/* link-time value of a named symbol (raw; no slide applied) */
static bool ksym_value(const char *name, uint64_t *out)
{
    for (size_t i = 0; i < g_nksyms; i++) {
        if (strcmp(g_ksyms[i].name, name) == 0) { *out = g_ksyms[i].addr; return true; }
    }
    return false;
}

/* runtime address of a (text) symbol, e.g. to set a breakpoint */
static bool ksym_resolve(const char *name, uint64_t *out)
{
    uint64_t v;
    if (!ksym_value(name, &v)) { return false; }
    *out = v + g_text_slide;
    return true;
}

static bool is_ktext(uint64_t rt_addr)
{
    if (g_etext <= g_stext) { return false; }
    uint64_t lt = rt_addr - g_text_slide;
    return lt >= g_stext && lt < g_etext;
}

/* parse "<hexaddr> <type> <name> [module]" lines (System.map / kallsyms) */
static void ksyms_load(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "qmon: cannot open ksyms %s\n", path); return; }
    size_t cap = 1 << 16, n = 0;
    Ksym *arr = g_new(Ksym, cap);
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = NULL;
        uint64_t addr = strtoull(line, &p, 16);
        if (p == line) { continue; }
        while (*p == ' ' || *p == '\t') { p++; }      /* to type */
        while (*p && *p != ' ' && *p != '\t') { p++; } /* past type */
        while (*p == ' ' || *p == '\t') { p++; }       /* to name */
        char *nm = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') { p++; }
        *p = 0;
        if (!*nm) { continue; }
        if (n == cap) { cap *= 2; arr = g_renew(Ksym, arr, cap); }
        arr[n].addr = addr;
        arr[n].name = g_strdup(nm);
        n++;
    }
    fclose(f);
    qsort(arr, n, sizeof(Ksym), ksym_cmp);
    g_ksyms = arr; g_nksyms = n;

    if (!ksym_value("_stext", &g_stext)) { (void)ksym_value("_text", &g_stext); }
    (void)ksym_value("_etext", &g_etext);
    /* current_task is per-CPU: its offset within the per-CPU area is its
     * System.map value minus __per_cpu_start (which is 0 on kernels that link
     * the percpu section at 0, e.g. 5.15, but non-zero on newer kernels). */
    g_have_current = ksym_value("current_task", &g_current_off);
    if (g_have_current) {
        uint64_t pcpu_start;
        if (ksym_value("__per_cpu_start", &pcpu_start)) {
            g_current_off -= pcpu_start;
        }
    }
    (void)ksym_value("linux_banner", &g_anchor_va);   /* KASLR slide anchor */

    /* ORC unwind tables (CONFIG_UNWINDER_ORC): if present, prefer ORC over the
     * frame-pointer chain for kernel backtraces. */
    uint64_t oip, oip_stop, orc;
    if (ksym_value("__start_orc_unwind_ip", &oip) &&
        ksym_value("__stop_orc_unwind_ip", &oip_stop) &&
        ksym_value("__start_orc_unwind", &orc) && oip_stop > oip) {
        g_orc_ip_link = oip;
        g_orc_link = orc;
        g_orc_n = (size_t)((oip_stop - oip) / 4);
        g_orc_ok = true;
    }

    char msg[200];
    g_snprintf(msg, sizeof(msg),
               "qmon: loaded %zu symbols from %s "
               "(stext=%#llx etext=%#llx current_task=%#llx)\n",
               n, path, (unsigned long long)g_stext,
               (unsigned long long)g_etext, (unsigned long long)g_current_off);
    qemu_plugin_outs(msg);
}

/* ---- minimal BTF reader: task_struct comm/pid byte offsets ---- */
struct btf_hdr_min {
    uint16_t magic; uint8_t version; uint8_t flags;
    uint32_t hdr_len, type_off, type_len, str_off, str_len;
};

static void btf_load(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { return; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < (long)sizeof(struct btf_hdr_min)) { fclose(f); return; }
    uint8_t *buf = g_malloc(sz);
    if (fread(buf, 1, sz, f) != (size_t)sz) { fclose(f); g_free(buf); return; }
    fclose(f);

    struct btf_hdr_min h;
    memcpy(&h, buf, sizeof(h));
    if (h.magic != 0xeB9F) { g_free(buf); return; }
    const uint8_t *types = buf + h.hdr_len + h.type_off;
    const uint8_t *tend  = types + h.type_len;
    const char   *strs   = (const char *)(buf + h.hdr_len + h.str_off);
    uint32_t str_len = h.str_len;

    const uint8_t *p = types;
    while (p + 12 <= tend) {
        uint32_t name_off = le32dec(p);
        uint32_t info     = le32dec(p + 4);
        uint32_t vlen = info & 0xffff;
        uint32_t kind = (info >> 24) & 0x1f;
        bool kflag = (info >> 31) & 1;
        const uint8_t *members = p + 12;
        size_t extra;
        switch (kind) {
        case 1:  extra = 4; break;                  /* INT */
        case 3:  extra = 12; break;                 /* ARRAY */
        case 4: case 5: extra = vlen * 12; break;   /* STRUCT/UNION */
        case 6:  extra = vlen * 8; break;           /* ENUM */
        case 13: extra = vlen * 8; break;           /* FUNC_PROTO */
        case 14: extra = 4; break;                  /* VAR */
        case 15: extra = vlen * 12; break;          /* DATASEC */
        case 17: extra = 4; break;                  /* DECL_TAG */
        case 19: extra = vlen * 12; break;          /* ENUM64 */
        default: extra = 0; break;
        }
        const char *tname = (name_off < str_len) ? strs + name_off : "";
        if (kind == 4 && strcmp(tname, "task_struct") == 0) {
            for (uint32_t m = 0; m < vlen; m++) {
                const uint8_t *mp = members + (size_t)m * 12;
                uint32_t mname  = le32dec(mp);
                uint32_t moff   = le32dec(mp + 8);
                uint32_t bitoff = kflag ? (moff & 0xffffff) : moff;
                const char *mn = (mname < str_len) ? strs + mname : "";
                if (strcmp(mn, "comm") == 0) { g_comm_off = bitoff / 8; }
                else if (strcmp(mn, "pid") == 0) { g_pid_off = bitoff / 8; }
            }
            break;
        }
        p = members + extra;
    }
    g_free(buf);

    char msg[128];
    g_snprintf(msg, sizeof(msg), "qmon: btf task_struct comm@%ld pid@%ld\n",
               g_comm_off, g_pid_off);
    qemu_plugin_outs(msg);
}

/* ---- guest-memory reads + symbol/context/backtrace encoders ---- */

static bool gmem_read(uint64_t va, void *dst, size_t n)
{
    GByteArray *b = g_byte_array_new();
    bool ok = qemu_plugin_read_memory_vaddr(va, b, n) && b->len >= n;
    if (ok) { memcpy(dst, b->data, n); }
    g_byte_array_free(b, TRUE);
    return ok;
}

static bool gmem_u64(uint64_t va, uint64_t *out)
{
    uint8_t t[8];
    if (!gmem_read(va, t, 8)) { return false; }
    *out = le64dec(t);
    return true;
}

static bool gmem_s32(uint64_t va, int32_t *out)
{
    uint8_t t[4];
    if (!gmem_read(va, t, 4)) { return false; }
    *out = (int32_t)le32dec(t);
    return true;
}

/* sym = u8 namelen, name, u64 offset (or namelen 0 + raw addr if unknown).
 * Only addresses inside kernel text are named (avoids attributing a user or
 * data address to the nearest kernel symbol). When text bounds are unknown,
 * fall back to an implausible-offset guard. */
static void put_sym(GByteArray *b, uint64_t addr)
{
    uint64_t off = 0;
    const char *nm = ksym_lookup(addr, &off);
    bool ok = nm && ((g_etext > g_stext) ? is_ktext(addr) : (off < 0x200000));
    uint8_t nl = ok ? (uint8_t)MIN(strlen(nm), 255) : 0;
    p8(b, nl);
    if (nl) { g_byte_array_append(b, (const uint8_t *)nm, nl); }
    p64(b, ok ? off : addr);
}

/* Auto-detect the KASLR slide via a content anchor: the linux_banner string
 * ("Linux version ...") moves with the kernel image, so it appears at
 * link-time(linux_banner) + slide only for the true slide.  Runs on a vCPU
 * thread in ring0 (kernel mappings present); one-shot, self-gating. */
static void try_calibrate_slide(void)
{
    static const char banner[] = "Linux version ";
    if (atomic_load(&g_calibrated) || g_slide_forced || !g_anchor_va) { return; }
    uint64_t cs = 0;
    read_reg_u64("cs", &cs);
    if ((cs & 3) != 0) { return; }              /* need a kernel CR3 (ring0) */
    for (uint64_t slide = 0; slide < QMON_KASLR_MAX; slide += QMON_KASLR_STEP) {
        char buf[sizeof(banner) - 1];
        if (gmem_read(g_anchor_va + slide, buf, sizeof(buf)) &&
            memcmp(buf, banner, sizeof(buf)) == 0) {
            g_text_slide = slide;
            atomic_store(&g_calibrated, 1);
            char m[96];
            g_snprintf(m, sizeof(m), "qmon: kaslr text slide = %#llx\n",
                       (unsigned long long)g_text_slide);
            qemu_plugin_outs(m);
            return;
        }
    }
}

/* context blob; must run on the vCPU thread with R_REGS */
static void build_context(GByteArray *out)
{
    try_calibrate_slide();
    uint64_t rip = 0, cs = 0, gsb = 0, kgsb = 0;
    read_reg_u64("rip", &rip);
    read_reg_u64("cs", &cs);
    read_reg_u64("gs_base", &gsb);
    if (!read_reg_u64("kernel_gs_base", &kgsb)) { read_reg_u64("k_gs_base", &kgsb); }

    uint8_t ring = (uint8_t)(cs & 3);
    p8(out, ring);
    put_sym(out, rip);

    uint32_t pid = 0;
    char comm[16];
    uint8_t commlen = 0;
    if (g_have_current && g_comm_off >= 0) {
        uint64_t pcpu = (ring == 0) ? gsb : kgsb;
        uint64_t task = 0;
        if (gmem_u64(pcpu + g_current_off, &task) && task) {
            uint32_t v;
            if (g_pid_off >= 0 && gmem_read(task + g_pid_off, &v, 4)) { pid = v; }
            char c[16];
            if (gmem_read(task + g_comm_off, c, 16)) {
                commlen = (uint8_t)strnlen(c, 16);
                memcpy(comm, c, commlen);
            }
        }
    }
    p32(out, pid);
    p8(out, commlen);
    if (commlen) { g_byte_array_append(out, (const uint8_t *)comm, commlen); }
}

/* frame-pointer (RBP) chain unwinder (CONFIG_FRAME_POINTER kernels) */
static void backtrace_fp(GArray *fr, uint64_t rip, uint64_t rsp, uint64_t rbp,
                         uint32_t max)
{
    uint64_t top = (rsp | (QMON_THREAD_SIZE - 1)) + 1;

    /* function-entry heuristic: caller's return addr is freshly at *rsp */
    uint64_t off = 0;
    const char *nm = ksym_lookup(rip, &off);
    if (nm && off == 0) {
        uint64_t r;
        if (gmem_u64(rsp, &r) && is_ktext(r)) { g_array_append_val(fr, r); }
    }

    uint64_t cur = rbp;
    while ((uint32_t)fr->len < max && cur >= rsp && cur < top) {
        uint64_t ret, nxt;
        if (!gmem_u64(cur + 8, &ret) || !gmem_u64(cur, &nxt)) { break; }
        if (!is_ktext(ret)) { break; }
        g_array_append_val(fr, ret);
        if (nxt <= cur) { break; }
        cur = nxt;
    }
}

/* ORC unwinder (CONFIG_UNWINDER_ORC) -- mirrors arch/x86/kernel/unwind_orc.c. */
enum {                                       /* arch/x86/include/asm/orc_types.h */
    ORC_REG_UNDEFINED = 0, ORC_REG_AX, ORC_REG_DX, ORC_REG_SP, ORC_REG_BP,
    ORC_REG_DI, ORC_REG_R10, ORC_REG_R13, ORC_REG_PREV_SP,
    ORC_REG_SP_INDIRECT, ORC_REG_BP_INDIRECT,
};
enum {
    ORC_TYPE_UNDEFINED = 0, ORC_TYPE_END_OF_STACK, ORC_TYPE_CALL,
    ORC_TYPE_REGS, ORC_TYPE_REGS_PARTIAL,
};
#define ORC_PTREGS_IP  128       /* offsetof(struct pt_regs, ip)  (x86_64) */
#define ORC_PTREGS_SP  152       /* offsetof(struct pt_regs, sp)  (x86_64) */
#define ORC_IRET_OFF   128       /* IRET_FRAME_OFFSET = offsetof(pt_regs, ip) */

typedef struct {
    int16_t sp_offset, bp_offset;
    uint8_t sp_reg, bp_reg, type, sig;
    bool found;
} OrcEntry;

/* Binary-search the self-relative ip table (in guest memory) for the rightmost
 * entry whose code address is <= ip, and decode its 6-byte orc_entry. */
static OrcEntry orc_find(uint64_t ip)
{
    OrcEntry e = {0};
    if (!g_orc_ok || g_orc_n == 0) { return e; }
    uint64_t ip_rt = g_orc_ip_link + g_text_slide;
    uint64_t orc_rt = g_orc_link + g_text_slide;
    long lo = 0, hi = (long)g_orc_n - 1, found = -1;
    while (lo <= hi) {
        long mid = lo + (hi - lo) / 2;
        uint64_t slot = ip_rt + (uint64_t)mid * 4;
        int32_t rel;
        if (!gmem_s32(slot, &rel)) { return e; }
        uint64_t orc_ip = slot + (int64_t)rel;      /* entries are self-relative */
        if (orc_ip <= ip) { found = mid; lo = mid + 1; } else { hi = mid - 1; }
    }
    if (found < 0) { return e; }
    uint8_t b[6];
    if (!gmem_read(orc_rt + (uint64_t)found * 6, b, 6)) { return e; }
    e.sp_offset = (int16_t)(b[0] | (b[1] << 8));
    e.bp_offset = (int16_t)(b[2] | (b[3] << 8));
    uint16_t f = (uint16_t)(b[4] | (b[5] << 8));
    e.sp_reg = f & 0xf;
    e.bp_reg = (f >> 4) & 0xf;
    e.type   = (f >> 8) & 0x7;
    e.sig    = (f >> 11) & 0x1;
    e.found  = true;
    return e;
}

static void backtrace_orc(GArray *fr, uint64_t rip, uint64_t rsp, uint64_t rbp,
                          uint32_t max)
{
    uint64_t ip = rip, sp = rsp, bp = rbp;
    bool sig = true;              /* breakpoint ip is "current" (like a regs frame) */

    while ((uint32_t)fr->len < max) {
        OrcEntry e = orc_find(sig ? ip : ip - 1);
        if (!e.found || e.type == ORC_TYPE_UNDEFINED ||
            e.type == ORC_TYPE_END_OF_STACK) {
            break;
        }
        sig = e.sig;

        /* previous frame's stack pointer (CFA) */
        uint64_t cfa;
        bool indirect = false;
        switch (e.sp_reg) {
        case ORC_REG_SP:          cfa = sp + e.sp_offset; break;
        case ORC_REG_BP:          cfa = bp + e.sp_offset; break;
        case ORC_REG_SP_INDIRECT: cfa = sp; indirect = true; break;
        case ORC_REG_BP_INDIRECT: cfa = bp + e.sp_offset; indirect = true; break;
        default: return;          /* AX/DX/DI/R10/R13 need regs -> stop cleanly */
        }
        if (indirect) {
            uint64_t v;
            if (!gmem_u64(cfa, &v)) { return; }
            cfa = v;
            if (e.sp_reg == ORC_REG_SP_INDIRECT) { cfa += e.sp_offset; }
        }

        uint64_t prev_sp = sp;
        switch (e.type) {
        case ORC_TYPE_CALL: {
            uint64_t r;
            if (!gmem_u64(cfa - 8, &r)) { return; }
            ip = r; sp = cfa;
            break;
        }
        case ORC_TYPE_REGS:                       /* full pt_regs at cfa */
            if (!gmem_u64(cfa + ORC_PTREGS_IP, &ip) ||
                !gmem_u64(cfa + ORC_PTREGS_SP, &sp)) { return; }
            break;
        case ORC_TYPE_REGS_PARTIAL: {             /* iret regs at cfa - IRET_OFF */
            uint64_t base = cfa - ORC_IRET_OFF;
            if (!gmem_u64(base + ORC_PTREGS_IP, &ip) ||
                !gmem_u64(base + ORC_PTREGS_SP, &sp)) { return; }
            break;
        }
        default: return;
        }

        /* previous frame's BP */
        switch (e.bp_reg) {
        case ORC_REG_PREV_SP: { uint64_t v; if (gmem_u64(cfa + e.bp_offset, &v)) { bp = v; } break; }
        case ORC_REG_BP:      { uint64_t v; if (gmem_u64(bp + e.bp_offset, &v)) { bp = v; } break; }
        default: break;       /* UNDEFINED: keep bp */
        }

        if (!is_ktext(ip)) { break; }             /* left kernel text (user boundary) */
        if (sp <= prev_sp) { break; }             /* loop prevention */
        g_array_append_val(fr, ip);
    }
}

/* backtrace blob; ORC when the kernel exposes ORC tables, else RBP chain.
 * vCPU thread + R_REGS. */
static void build_backtrace(GByteArray *out, uint32_t max)
{
    try_calibrate_slide();
    if (max == 0 || max > QMON_MAX_FRAMES) { max = QMON_MAX_FRAMES; }
    uint64_t rip = 0, rsp = 0, rbp = 0;
    read_reg_u64("rip", &rip);
    read_reg_u64("rsp", &rsp);
    read_reg_u64("rbp", &rbp);

    GArray *fr = g_array_new(FALSE, FALSE, sizeof(uint64_t));
    g_array_append_val(fr, rip);
    if (g_orc_ok) {
        backtrace_orc(fr, rip, rsp, rbp, max);
    } else {
        backtrace_fp(fr, rip, rsp, rbp, max);
    }

    p32(out, fr->len);
    for (guint i = 0; i < fr->len; i++) {
        uint64_t a = g_array_index(fr, uint64_t, i);
        p64(out, a);
        put_sym(out, a);
    }
    g_array_free(fr, TRUE);
}

/* ------------------------------------------------------------------ */
/* x86_64 page-table walk for LIST_MAP                                  */
/* ------------------------------------------------------------------ */

#define X86_ADDR_MASK 0x000ffffffffff000ULL

typedef struct {
    uint64_t gva, gpa, size;
    uint32_t flags;             /* 1=P 2=W 4=U 8=NX 16=large */
} Map;

typedef struct {
    GArray *maps;
    int levels;                 /* 4 or 5 */
    uint32_t budget;
    bool have_run;
    Map run;
} WalkCtx;

static uint64_t canon(uint64_t va, int levels)
{
    int bits = 12 + 9 * levels;             /* 48 or 57 */
    if (va & (1ULL << (bits - 1))) {
        va |= ~((1ULL << bits) - 1);
    }
    return va;
}

static void emit_map(WalkCtx *c, uint64_t gva, uint64_t gpa, uint64_t size,
                     uint32_t flags)
{
    if (c->have_run &&
        c->run.gva + c->run.size == gva &&
        c->run.gpa + c->run.size == gpa &&
        c->run.flags == flags) {
        c->run.size += size;                /* coalesce contiguous range */
        return;
    }
    if (c->have_run && c->maps->len < QMON_MAX_MAPS) {
        g_array_append_val(c->maps, c->run);
    }
    c->run.gva = gva; c->run.gpa = gpa; c->run.size = size; c->run.flags = flags;
    c->have_run = true;
}

static uint32_t pte_flags(uint64_t e, bool large)
{
    uint32_t f = 1;                         /* present */
    if (e & 0x2)  { f |= 2; }               /* writable */
    if (e & 0x4)  { f |= 4; }               /* user */
    if (e & (1ULL << 63)) { f |= 8; }       /* NX */
    if (large)    { f |= 16; }
    return f;
}

static void walk(WalkCtx *c, uint64_t table_phys, int level, uint64_t va_base)
{
    for (int i = 0; i < 512; i++) {
        if (c->budget == 0 || c->maps->len >= QMON_MAX_MAPS) { return; }
        c->budget--;

        GByteArray *b = g_byte_array_new();
        enum qemu_plugin_hwaddr_operation_result r =
            qemu_plugin_read_memory_hwaddr(table_phys + (uint64_t)i * 8, b, 8);
        uint64_t e = (r == QEMU_PLUGIN_HWADDR_OPERATION_OK && b->len >= 8)
                         ? le64dec(b->data) : 0;
        g_byte_array_free(b, TRUE);

        if (!(e & 1)) { continue; }         /* not present */

        int shift = 12 + 9 * (level - 1);
        uint64_t va = va_base | ((uint64_t)i << shift);
        bool large = (level <= 3) && (e & (1ULL << 7));
        bool leaf = (level == 1) || large;

        if (leaf) {
            uint64_t size = 1ULL << shift;
            uint64_t gpa = (e & X86_ADDR_MASK) & ~(size - 1);
            emit_map(c, canon(va, c->levels), gpa, size, pte_flags(e, large));
        } else {
            walk(c, e & X86_ADDR_MASK, level - 1, va);
        }
    }
}

static void do_list_map(Cmd *cmd)
{
    uint64_t cr0, cr3, cr4;
    if (!read_reg_u64("cr3", &cr3)) {
        cmd->status = 1;
        g_strlcpy(cmd->err, "cr3 not exposed by gdb reg set", sizeof(cmd->err));
        return;
    }
    read_reg_u64("cr0", &cr0);
    read_reg_u64("cr4", &cr4);

    GByteArray *out = cmd->out;
    p8(out, RSP_OK);

    if (!(cr0 & 0x80000000ULL)) {           /* paging off */
        p32(out, 0);
        return;
    }

    WalkCtx c = {0};
    c.maps = g_array_new(FALSE, FALSE, sizeof(Map));
    c.levels = (cr4 & (1ULL << 12)) ? 5 : 4;    /* CR4.LA57 */
    c.budget = QMON_MAX_WALK;
    walk(&c, cr3 & X86_ADDR_MASK, c.levels, 0);
    if (c.have_run && c.maps->len < QMON_MAX_MAPS) {
        g_array_append_val(c.maps, c.run);
    }

    p32(out, c.maps->len);
    for (guint i = 0; i < c.maps->len; i++) {
        Map *m = &g_array_index(c.maps, Map, i);
        p64(out, m->gva);
        p64(out, m->gpa);
        p64(out, m->size);
        p32(out, m->flags);
    }
    g_array_free(c.maps, TRUE);
}

/* ------------------------------------------------------------------ */
/* command execution (runs on a vCPU thread, R_REGS available)         */
/* ------------------------------------------------------------------ */

static void do_read_regs(Cmd *cmd)
{
    GByteArray *out = cmd->out;
    p8(out, RSP_OK);
    guint nregs = g_regs ? g_regs->len : 0;
    p32(out, nregs);
    GByteArray *val = g_byte_array_new();
    for (guint i = 0; i < nregs; i++) {
        qemu_plugin_reg_descriptor *d =
            &g_array_index(g_regs, qemu_plugin_reg_descriptor, i);
        g_byte_array_set_size(val, 0);
        bool ok = d->handle ? qemu_plugin_read_register(d->handle, val) : false;
        const char *nm = d->name ? d->name : "?";
        uint8_t nl = (uint8_t)MIN(strlen(nm), 255);
        p8(out, nl);
        g_byte_array_append(out, (const uint8_t *)nm, nl);
        uint8_t w = ok ? (uint8_t)MIN(val->len, 255) : 0;
        p8(out, w);
        if (w) { g_byte_array_append(out, val->data, w); }
    }
    g_byte_array_free(val, TRUE);
}

static void do_read_vmem(Cmd *cmd)
{
    GByteArray *d = g_byte_array_new();
    if (cmd->len && qemu_plugin_read_memory_vaddr(cmd->addr, d, cmd->len)) {
        p8(cmd->out, RSP_OK);
        p32(cmd->out, d->len);
        g_byte_array_append(cmd->out, d->data, d->len);
    } else {
        cmd->status = 1;
        g_strlcpy(cmd->err, "vaddr read failed", sizeof(cmd->err));
    }
    g_byte_array_free(d, TRUE);
}

static void do_read_pmem(Cmd *cmd)
{
    GByteArray *d = g_byte_array_new();
    enum qemu_plugin_hwaddr_operation_result r =
        cmd->len ? qemu_plugin_read_memory_hwaddr(cmd->addr, d, cmd->len)
                 : QEMU_PLUGIN_HWADDR_OPERATION_ERROR;
    if (r == QEMU_PLUGIN_HWADDR_OPERATION_OK) {
        p8(cmd->out, RSP_OK);
        p32(cmd->out, d->len);
        g_byte_array_append(cmd->out, d->data, d->len);
    } else {
        cmd->status = 1;
        g_snprintf(cmd->err, sizeof(cmd->err), "hwaddr read failed (%d)", r);
    }
    g_byte_array_free(d, TRUE);
}

static void do_xlate(Cmd *cmd)
{
    uint64_t hw = 0;
    if (qemu_plugin_translate_vaddr(cmd->addr, &hw)) {
        p8(cmd->out, RSP_OK);
        p64(cmd->out, hw);
    } else {
        cmd->status = 1;
        g_strlcpy(cmd->err, "translate failed (unmapped?)", sizeof(cmd->err));
    }
}

static void exec_cmd(Cmd *cmd)
{
    switch (cmd->type) {
    case REQ_READ_REGS: do_read_regs(cmd); break;
    case REQ_READ_VMEM: do_read_vmem(cmd); break;
    case REQ_READ_PMEM: do_read_pmem(cmd); break;
    case REQ_XLATE:     do_xlate(cmd);     break;
    case REQ_LIST_MAP:  do_list_map(cmd);  break;
    case REQ_CONTEXT:   p8(cmd->out, RSP_OK); build_context(cmd->out); break;
    case REQ_BACKTRACE: p8(cmd->out, RSP_OK); build_backtrace(cmd->out, cmd->len); break;
    default:
        cmd->status = 1;
        g_strlcpy(cmd->err, "bad command", sizeof(cmd->err));
        break;
    }
}

/* try to claim and run the in-flight command from this vCPU */
static void service_one(unsigned vcpu)
{
    Cmd *c = NULL;
    g_mutex_lock(&lock);
    if (g_inflight && !g_inflight->claimed && !g_inflight->done &&
        (g_inflight->any_vcpu || g_inflight->vcpu == vcpu)) {
        c = g_inflight;
        c->claimed = true;
    }
    g_mutex_unlock(&lock);

    if (!c) { return; }
    exec_cmd(c);
    g_mutex_lock(&lock);
    c->done = true;
    g_cond_broadcast(&done_cond);
    g_mutex_unlock(&lock);
}

/* ------------------------------------------------------------------ */
/* events + breakpoint freeze                                          */
/* ------------------------------------------------------------------ */

/* called from bp_cb (vCPU thread, R_REGS): event carries context + backtrace */
static void emit_break(unsigned vcpu, uint64_t rip, uint64_t bp)
{
    GByteArray *b = g_byte_array_new();
    p8(b, EV_BREAK); p32(b, vcpu); p64(b, rip); p64(b, bp);
    build_context(b);
    build_backtrace(b, QMON_MAX_FRAMES);
    send_ba(b);
    g_byte_array_free(b, TRUE);
}

static void emit_watch(unsigned vcpu, uint64_t rip, uint64_t addr,
                       uint8_t store, uint8_t size, uint64_t val)
{
    GByteArray *b = g_byte_array_new();
    p8(b, EV_WATCH); p32(b, vcpu); p64(b, rip); p64(b, addr);
    p8(b, store); p8(b, size); p64(b, val);
    send_ba(b);
    g_byte_array_free(b, TRUE);
}

/* freeze this vCPU until the client sends CONTINUE; service reads meanwhile */
static void block_until_continue(unsigned vcpu)
{
    g_mutex_lock(&lock);
    stopped[vcpu] = true;
    for (;;) {
        Cmd *c = NULL;
        bool cont = false;
        for (;;) {
            if (continue_req[vcpu]) { continue_req[vcpu] = false; cont = true; break; }
            if (g_inflight && !g_inflight->claimed && !g_inflight->done &&
                (g_inflight->any_vcpu || g_inflight->vcpu == vcpu)) {
                c = g_inflight; c->claimed = true; break;
            }
            g_cond_wait(&work_cond, &lock);
        }
        if (cont) { break; }
        g_mutex_unlock(&lock);
        exec_cmd(c);
        g_mutex_lock(&lock);
        c->done = true;
        g_cond_broadcast(&done_cond);
    }
    stopped[vcpu] = false;
    g_mutex_unlock(&lock);
}

/* ------------------------------------------------------------------ */
/* ylang bridge (objective 1: CPU register dump)                       */
/* ------------------------------------------------------------------ */

/*
 * Snapshot the current vCPU's registers into a qemu_cpu_state and hand it to the
 * ylang probe target.  Runs on the vCPU thread with R_REGS, so the read-out is
 * a consistent, TB-boundary snapshot.  QEMU's x86 gdb register set exposes
 * rax..r15, rip, eflags, the six segment selectors and cr0-cr4 (no APX eGPRs,
 * MSRs or debug regs); anything absent stays zero.
 */
static void ylang_emit_cpu_regs(unsigned int vcpu)
{
    struct qemu_cpu_state st;
    memset(&st, 0, sizeof(st));
    st.cpu_index = vcpu;

    /* Map each flat field to its gdb register name; missing regs stay zero
     * (e.g. the APX eGPRs r16-r31 aren't in QEMU's x86 gdb set). */
    const struct { const char *nm; uint64_t *p; } map[] = {
        { "rax", &st.rax }, { "rcx", &st.rcx }, { "rdx", &st.rdx }, { "rbx", &st.rbx },
        { "rsp", &st.rsp }, { "rbp", &st.rbp }, { "rsi", &st.rsi }, { "rdi", &st.rdi },
        { "r8",  &st.r8  }, { "r9",  &st.r9  }, { "r10", &st.r10 }, { "r11", &st.r11 },
        { "r12", &st.r12 }, { "r13", &st.r13 }, { "r14", &st.r14 }, { "r15", &st.r15 },
        { "rip", &st.rip }, { "eflags", &st.eflags },
        { "es",  &st.es  }, { "cs",  &st.cs  }, { "ss",  &st.ss  },
        { "ds",  &st.ds  }, { "fs",  &st.fs  }, { "gs",  &st.gs  },
        { "cr0", &st.cr0 }, { "cr2", &st.cr2 }, { "cr3", &st.cr3 },
        { "cr4", &st.cr4 }, { "cr8", &st.cr8 },
    };
    GByteArray *b = g_byte_array_new();
    for (size_t i = 0; i < G_N_ELEMENTS(map); i++) {
        read_reg_into(b, map[i].nm, map[i].p);
    }
    g_byte_array_free(b, TRUE);

    qemu_ylang_cpu_reg_dump(&st);
}

/* ------------------------------------------------------------------ */
/* instrumentation callbacks (vCPU threads)                            */
/* ------------------------------------------------------------------ */

static void pump_cb(unsigned int vcpu, void *udata)
{
    (void)udata;
    /* eager KASLR calibration, throttled so it isn't a per-TB cost */
    if (!atomic_load(&g_calibrated) && !g_slide_forced && g_anchor_va &&
        (atomic_fetch_add(&g_tick, 1) & 0x3fff) == 0) {
        try_calibrate_slide();
    }
    if (atomic_load(&feat_ylang)) {
        /* Cheap %rip pre-filter: read one register and only snapshot the full
         * set (and fire the uprobe) when rip is in the configured window. */
        uint64_t rip = 0;
        read_reg_u64("rip", &rip);
        if (rip >= atomic_load(&g_ylang_lo) && rip <= atomic_load(&g_ylang_hi)) {
            ylang_emit_cpu_regs(vcpu);
        }
    }
    if (atomic_load(&pending)) {
        service_one(vcpu);
    }
}

static void bp_cb(unsigned int vcpu, void *udata)
{
    if (atomic_load(&n_bp) == 0) { return; }
    uint64_t pc = (uint64_t)(uintptr_t)udata;
    g_mutex_lock(&lock);
    bool hit = g_hash_table_contains(bp_set, &pc);
    g_mutex_unlock(&lock);
    if (!hit) { return; }
    if (atomic_load(&conn_fd) < 0) { return; }      /* no client: don't hang */

    emit_break(vcpu, pc, pc);
    block_until_continue(vcpu);
}

static void wp_cb(unsigned int vcpu, qemu_plugin_meminfo_t info,
                  uint64_t vaddr, void *udata)
{
    (void)udata;
    if (atomic_load(&n_wp) == 0) { return; }
    uint32_t size = 1u << qemu_plugin_mem_size_shift(info);
    bool store = qemu_plugin_mem_is_store(info);
    uint8_t want = store ? 2 : 1;

    bool hit = false;
    g_mutex_lock(&lock);
    for (guint i = 0; i < wp_list->len; i++) {
        Watch *w = &g_array_index(wp_list, Watch, i);
        if ((w->rw & want) &&
            vaddr < w->addr + w->len && w->addr < vaddr + size) {
            hit = true;
            break;
        }
    }
    g_mutex_unlock(&lock);
    if (!hit) { return; }

    qemu_plugin_mem_value mv = qemu_plugin_mem_get_value(info);
    uint64_t val = 0;
    switch (mv.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8:   val = mv.data.u8;  break;
    case QEMU_PLUGIN_MEM_VALUE_U16:  val = mv.data.u16; break;
    case QEMU_PLUGIN_MEM_VALUE_U32:  val = mv.data.u32; break;
    case QEMU_PLUGIN_MEM_VALUE_U64:  val = mv.data.u64; break;
    case QEMU_PLUGIN_MEM_VALUE_U128: val = mv.data.u128.low; break;
    default: break;
    }
    uint64_t rip = 0;
    read_reg_u64("rip", &rip);
    emit_watch(vcpu, rip, vaddr, store, (uint8_t)size, val);
}

static void vcpu_init_cb(unsigned int vcpu, void *udata)
{
    (void)vcpu; (void)udata;
    g_mutex_lock(&lock);
    if (!g_regs_done) {
        g_regs = qemu_plugin_get_registers();   /* current vCPU; handles are shared */
        g_regs_done = true;
    }
    g_mutex_unlock(&lock);
}

static void tb_trans_cb(struct qemu_plugin_tb *tb, void *udata)
{
    (void)udata;
    /* the request pump: one cheap callback per executed block */
    qemu_plugin_register_vcpu_tb_exec_cb(tb, pump_cb,
                                         QEMU_PLUGIN_CB_R_REGS, NULL);

    if (!feat_bp && !feat_wp) { return; }

    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        if (feat_bp) {
            uint64_t va = qemu_plugin_insn_vaddr(insn);
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, bp_cb, QEMU_PLUGIN_CB_R_REGS, (void *)(uintptr_t)va);
        }
        if (feat_wp) {
            qemu_plugin_register_vcpu_mem_cb(
                insn, wp_cb, QEMU_PLUGIN_CB_R_REGS, QEMU_PLUGIN_MEM_RW, NULL);
        }
    }
}

/* ------------------------------------------------------------------ */
/* request handling (I/O thread)                                       */
/* ------------------------------------------------------------------ */

/* post a vCPU-context command and wait for a vCPU thread to run it */
static void run_vcpu_cmd(Cmd *cmd)
{
    cmd->out = g_byte_array_new();
    g_mutex_lock(&lock);
    g_inflight = cmd;
    atomic_store(&pending, 1);
    g_cond_broadcast(&work_cond);           /* wake any frozen vCPU */

    gint64 deadline = g_get_monotonic_time() + QMON_REQ_TIMEOUT_US;
    while (!cmd->done) {
        if (!g_cond_wait_until(&done_cond, &lock, deadline)) {
            if (!cmd->claimed) { break; }   /* nobody started it: abandon */
            /* claimed and in progress: wait a little longer, never UAF */
            deadline = g_get_monotonic_time() + 500 * 1000;
        }
    }
    bool timed_out = !cmd->done;
    g_inflight = NULL;
    atomic_store(&pending, 0);
    g_mutex_unlock(&lock);

    if (timed_out) {
        reply_err(2, "timeout: target vCPU not executing (idle/halted?)");
    } else if (cmd->status) {
        reply_err(1, cmd->err);
    } else {
        send_ba(cmd->out);
    }
    g_byte_array_free(cmd->out, TRUE);
}

static void add_bp(uint64_t addr)
{
    g_mutex_lock(&lock);
    if (!g_hash_table_contains(bp_set, &addr)) {
        gint64 *k = g_new(gint64, 1);
        *k = (gint64)addr;
        g_hash_table_insert(bp_set, k, GINT_TO_POINTER(1));
        atomic_store(&n_bp, (int)g_hash_table_size(bp_set));
    }
    g_mutex_unlock(&lock);
}

static void clr_bp(uint64_t addr)
{
    g_mutex_lock(&lock);
    g_hash_table_remove(bp_set, &addr);
    atomic_store(&n_bp, (int)g_hash_table_size(bp_set));
    g_mutex_unlock(&lock);
}

static void add_wp(uint64_t addr, uint64_t len, uint8_t rw)
{
    Watch w = { addr, len ? len : 1, rw ? rw : 3 };
    g_mutex_lock(&lock);
    g_array_append_val(wp_list, w);
    atomic_store(&n_wp, (int)wp_list->len);
    g_mutex_unlock(&lock);
}

static void clr_wp(uint64_t addr)
{
    g_mutex_lock(&lock);
    for (guint i = 0; i < wp_list->len; i++) {
        if (g_array_index(wp_list, Watch, i).addr == addr) {
            g_array_remove_index(wp_list, i);
            break;
        }
    }
    atomic_store(&n_wp, (int)wp_list->len);
    g_mutex_unlock(&lock);
}

static void do_continue(uint32_t vcpu)
{
    g_mutex_lock(&lock);
    for (int i = 0; i < g_max_vcpus; i++) {
        if ((vcpu == 0xffffffffu || (uint32_t)i == vcpu) && stopped[i]) {
            continue_req[i] = true;
        }
    }
    g_cond_broadcast(&work_cond);
    g_mutex_unlock(&lock);
}

static void handle_request(const uint8_t *buf, size_t len)
{
    Rd r = { buf, len, 0, false };
    uint8_t type = g8(&r);

    switch (type) {
    case REQ_PING:
        reply_ok_empty();
        break;
    case REQ_READ_REGS:
    case REQ_READ_VMEM:
    case REQ_READ_PMEM:
    case REQ_XLATE:
    case REQ_LIST_MAP:
    case REQ_CONTEXT:
    case REQ_BACKTRACE: {
        Cmd cmd = {0};
        cmd.type = type;
        cmd.vcpu = g32(&r);
        if (type == REQ_READ_VMEM || type == REQ_READ_PMEM) {
            cmd.addr = g64(&r);
            cmd.len = g32(&r);
            if (cmd.len > QMON_MAX_FRAME) { cmd.len = QMON_MAX_FRAME; }
        } else if (type == REQ_XLATE) {
            cmd.addr = g64(&r);
        } else if (type == REQ_BACKTRACE) {
            cmd.len = g32(&r);            /* max frames */
        }
        cmd.any_vcpu = (type == REQ_READ_PMEM);
        if (r.err) { reply_err(3, "short request"); break; }
        run_vcpu_cmd(&cmd);
        break;
    }
    case REQ_SET_BREAK: { uint64_t a = g64(&r); if (!r.err) { add_bp(a); reply_ok_empty(); } else { reply_err(3, "short"); } break; }
    case REQ_CLR_BREAK: { uint64_t a = g64(&r); if (!r.err) { clr_bp(a); reply_ok_empty(); } else { reply_err(3, "short"); } break; }
    case REQ_SET_WATCH: {
        uint64_t a = g64(&r), l = g64(&r); uint8_t rw = g8(&r);
        if (!r.err) { add_wp(a, l, rw); reply_ok_empty(); } else { reply_err(3, "short"); }
        break;
    }
    case REQ_CLR_WATCH: { uint64_t a = g64(&r); if (!r.err) { clr_wp(a); reply_ok_empty(); } else { reply_err(3, "short"); } break; }
    case REQ_CONTINUE:  { uint32_t v = g32(&r); if (!r.err) { do_continue(v); reply_ok_empty(); } else { reply_err(3, "short"); } break; }
    case REQ_YLANG_ENABLE: {
        uint8_t on = g8(&r);
        if (r.err) { reply_err(3, "short"); break; }
        atomic_store(&feat_ylang, on != 0);
        reply_ok_empty();
        break;
    }
    case REQ_YLANG_WINDOW: {
        uint8_t on = g8(&r); uint64_t lo = g64(&r), hi = g64(&r);
        if (r.err) { reply_err(3, "short"); break; }
        atomic_store(&g_ylang_lo, on ? lo : 0);
        atomic_store(&g_ylang_hi, on ? hi : UINT64_MAX);
        reply_ok_empty();
        break;
    }
    case REQ_SLIDE: {
        GByteArray *b = g_byte_array_new();
        p8(b, RSP_OK);
        p8(b, atomic_load(&g_calibrated) ? 1 : 0);
        p64(b, g_text_slide);
        send_ba(b); g_byte_array_free(b, TRUE);
        break;
    }
    case REQ_RESOLVE: {
        if (!g_slide_forced && !atomic_load(&g_calibrated)) {
            reply_err(6, "kaslr slide not calibrated yet (let the guest run)");
            break;
        }
        /* name = remaining payload (NUL-terminated by the client) */
        char *nm = g_strndup((const char *)(buf + r.off), len - r.off);
        uint64_t v;
        if (ksym_resolve(nm, &v)) {
            GByteArray *b = g_byte_array_new();
            p8(b, RSP_OK); p64(b, v);
            send_ba(b); g_byte_array_free(b, TRUE);
        } else {
            reply_err(5, "unknown symbol");
        }
        g_free(nm);
        break;
    }
    case REQ_SYM: {
        uint64_t a = g64(&r);
        if (r.err) { reply_err(3, "short"); break; }
        GByteArray *b = g_byte_array_new();
        p8(b, RSP_OK); put_sym(b, a);
        send_ba(b); g_byte_array_free(b, TRUE);
        break;
    }
    default:
        reply_err(4, "unknown request");
        break;
    }
}

/* on client disconnect: disarm everything and release frozen vCPUs */
static void connection_cleanup(void)
{
    g_mutex_lock(&lock);
    g_hash_table_remove_all(bp_set);
    g_array_set_size(wp_list, 0);
    atomic_store(&n_bp, 0);
    atomic_store(&n_wp, 0);
    for (int i = 0; i < g_max_vcpus; i++) {
        continue_req[i] = stopped[i];
    }
    g_cond_broadcast(&work_cond);
    g_mutex_unlock(&lock);
}

static void serve(int fd)
{
    atomic_store(&conn_fd, fd);
    for (;;) {
        uint8_t hdr[4];
        if (read_n(fd, hdr, 4) <= 0) { break; }
        uint32_t len = le32dec(hdr);
        if (len < 1 || len > QMON_MAX_FRAME) { break; }
        uint8_t *buf = g_malloc(len);
        if (read_n(fd, buf, len) <= 0) { g_free(buf); break; }
        handle_request(buf, len);
        g_free(buf);
    }
    atomic_store(&conn_fd, -1);
    connection_cleanup();
}

static void *io_thread_fn(void *arg)
{
    (void)arg;
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) { perror("qmon: socket"); return NULL; }

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    g_strlcpy(sa.sun_path, g_sock_path, sizeof(sa.sun_path));
    unlink(g_sock_path);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("qmon: bind"); close(lfd); return NULL;
    }
    if (listen(lfd, 1) < 0) {
        perror("qmon: listen"); close(lfd); return NULL;
    }
    {
        char msg[256];
        g_snprintf(msg, sizeof(msg), "qmon: listening on %s\n", g_sock_path);
        qemu_plugin_outs(msg);
    }

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) { continue; } break; }
        serve(cfd);
        close(cfd);
    }
    close(lfd);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* lifecycle                                                           */
/* ------------------------------------------------------------------ */

static void plugin_exit(void *udata)
{
    (void)udata;
    if (g_sock_path) { unlink(g_sock_path); }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    if (!info->system_emulation) {
        fprintf(stderr, "qmon: only supports full-system emulation\n");
        return -1;
    }

    g_sock_path = g_strdup("/tmp/qmon.sock");
    long comm_off_ovr = -1, pid_off_ovr = -1;
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) kv = g_strsplit(opt, "=", 2);
        if (g_strcmp0(kv[0], "sock") == 0 && kv[1]) {
            g_free(g_sock_path);
            g_sock_path = g_strdup(kv[1]);
        } else if (g_strcmp0(kv[0], "bp") == 0 && kv[1]) {
            qemu_plugin_bool_parse("bp", kv[1], &feat_bp);
        } else if (g_strcmp0(kv[0], "wp") == 0 && kv[1]) {
            qemu_plugin_bool_parse("wp", kv[1], &feat_wp);
        } else if (g_strcmp0(kv[0], "ylang") == 0 && kv[1]) {
            bool on = false;
            qemu_plugin_bool_parse("ylang", kv[1], &on);
            atomic_store(&feat_ylang, on);
        } else if (g_strcmp0(kv[0], "ylang_lo") == 0 && kv[1]) {
            atomic_store(&g_ylang_lo, g_ascii_strtoull(kv[1], NULL, 0));
        } else if (g_strcmp0(kv[0], "ylang_hi") == 0 && kv[1]) {
            atomic_store(&g_ylang_hi, g_ascii_strtoull(kv[1], NULL, 0));
        } else if (g_strcmp0(kv[0], "ksyms") == 0 && kv[1]) {
            g_free(g_ksyms_path); g_ksyms_path = g_strdup(kv[1]);
        } else if (g_strcmp0(kv[0], "btf") == 0 && kv[1]) {
            g_free(g_btf_path); g_btf_path = g_strdup(kv[1]);
        } else if (g_strcmp0(kv[0], "slide") == 0 && kv[1]) {
            if (g_strcmp0(kv[1], "auto") != 0) {   /* explicit value -> force it */
                g_text_slide = g_ascii_strtoull(kv[1], NULL, 0);
                g_slide_forced = true;
            }
        } else if (g_strcmp0(kv[0], "comm_off") == 0 && kv[1]) {
            comm_off_ovr = g_ascii_strtoull(kv[1], NULL, 0);
        } else if (g_strcmp0(kv[0], "pid_off") == 0 && kv[1]) {
            pid_off_ovr = g_ascii_strtoull(kv[1], NULL, 0);
        } else {
            fprintf(stderr, "qmon: ignoring unknown arg '%s'\n", opt);
        }
    }

    /* kernel symbols (for backtrace/context) + struct offsets */
    if (g_ksyms_path) { ksyms_load(g_ksyms_path); }
    btf_load(g_btf_path ? g_btf_path : "/sys/kernel/btf/vmlinux");
    if (comm_off_ovr >= 0) { g_comm_off = comm_off_ovr; }
    if (pid_off_ovr >= 0)  { g_pid_off  = pid_off_ovr; }
    if (g_slide_forced) { atomic_store(&g_calibrated, 1); }  /* slide= is authoritative */

    g_id = id;
    g_max_vcpus = info->system.max_vcpus > 0 ? info->system.max_vcpus : 1;
    stopped = g_new0(bool, g_max_vcpus);
    continue_req = g_new0(bool, g_max_vcpus);
    bp_set = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
    wp_list = g_array_new(FALSE, FALSE, sizeof(Watch));
    g_mutex_init(&lock);
    g_mutex_init(&wlock);
    g_cond_init(&done_cond);
    g_cond_init(&work_cond);

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    pthread_t th;
    if (pthread_create(&th, NULL, io_thread_fn, NULL) != 0) {
        fprintf(stderr, "qmon: pthread_create failed\n");
        return -1;
    }
    pthread_detach(th);
    return 0;
}
