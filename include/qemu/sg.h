#pragma once
#ifndef QEMU_SG_H
#define QEMU_SG_H
#endif

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <EGL/egl.h>
#include <GL/gl.h>
#include <EGL/eglext.h>
#include <xcb/xcb.h>
#include <xcb/sync.h>

/* Uncomment to enable debugging */
// #define COMMAND_DEBUG
#define GEM_DEBUG
// #define STAT_DEBUG

/* Syscall logging toggle */
extern int syscall_logging_enabled;

static void set_syscall_logging(int enable) { syscall_logging_enabled = enable ? 1 : 0; }

#ifdef COMMAND_DEBUG
#define log_sg(fmt, ...) \
    do { \
        if (syscall_logging_enabled) { \
            fprintf(stderr, "(qemu: COMMAND) "); \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
        } \
    } while (0)
#else
#define log_sg(fmt, ...) do {} while (0)
#endif

#ifdef GEM_DEBUG
#define log_gem(fmt, ...) \
    do { \
        fprintf(stderr, "(qemu: GEM) "); \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
    } while (0)
#else
#define log_gem(fmt, ...) do {} while (0)
#endif

#ifdef STAT_DEBUG
#define log_stat(fmt, ...) \
    do { \
        fprintf(stderr, "(qemu: STAT) "); \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
    } while (0)
#else
#define log_stat(fmt, ...) do {} while (0)
#endif

#define log_always(fmt, ...) \
    do { \
        fprintf(stderr, "(qemu) "); \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
    } while (0)


extern void* data_region_actual_address;
extern void* global_ram_address;
extern void* global_ram1_address;
extern void* global_ram2_address;
extern void* global_ram3_address;
typedef struct {
    volatile uint64_t magic;
    volatile uint64_t req_bit;
    volatile uint64_t p1;
    volatile uint64_t p2;
    volatile uint64_t p3;
    volatile uint64_t p4;
    volatile uint64_t p5;
    volatile uint64_t p6;
    volatile uint64_t p7;
    volatile uint64_t p8;
    volatile uint64_t p9;
    volatile uint64_t p10;
    volatile uint64_t ret;
} comm_page_t;

typedef struct buffer {
        struct gbm_bo *bo;
        int bo_fd;
        xcb_pixmap_t pixmap;
        EGLImageKHR image;
        GLuint tex;
        GLuint fbo;
        int shm_fence_fd;
        struct xshmfence *shm_fence;
        xcb_sync_fence_t sync_fence;
        GLuint rbo_depth;
    } check;

static const uint64_t LOG_MMAP_EVENT = 1;
static const  uint64_t SETUP_DATA = 0x2ULL;
static const  uint64_t GEM_ALLOCATION = 3;
static const  uint64_t FSTAT = 4;
static const  uint64_t IOCTL = 5;
static const  uint64_t OPEN = 6;
static const  uint64_t FCNTL = 7;
static const  uint64_t READLINK = 8;
static const  uint64_t NEWFSTAT = 9;
static const  uint64_t GETDENT = 10;
static const  uint64_t DUP = 11;
static const  uint64_t X11_SETUP = 12;
static const  uint64_t X11_PRESENT = 13;
static const  uint64_t CLOSE = 14;

/* Syscall logging toggles */
static const  uint64_t SYSCALL_LOGGING_ENABLE = 15;
static const  uint64_t SYSCALL_LOGGING_DISABLE = 16;


// Sizes
static const  size_t FIVETWELVE_MEGABYTE = 1024*1024*512;
// static const  size_t DATA_SIZE = FIVETWELVE_MEGABYTE*2; // 1G
static const  size_t DATA_SIZE = FIVETWELVE_MEGABYTE; // 1G
static const  size_t PAGE_SIZE    = 4*1024;

#define COMM_ADDR  0xf00000ULL
#define COMM_MAGIC 0x1234567812345678ULL

// static void* DATA_REGION = (void*)0x100008000ULL;
static void* DATA_REGION = (void*)0x100000000ULL;
static void* HUGEPAGE_DATA_REGION = (void*)0x200000000ULL;
static void* DATA_HOST_OFFSET = (void*)0x80000000ULL;

// This is different than where it appears in the guest.
// Qemu maps the ram region from 0x80000000 into the allocation to 0x100000000 in the guest AS
// static void* DATA_HOST_OFFSET = (void*)0x80008000ULL;

static void* UNMAP_DATA_MSG = (void*)0x1234567f1234567fULL;


void* mmap_listener(void* arg);

// #define WIDTH 1280
// #define HEIGHT 720
#define WIDTH 300
#define HEIGHT 300

#define sys_exec_vmexits 549
#define sys_sg_vmexits_printreset 550
#define I915_EXEC_ASYNC (1<<15)
#define LOG_BATCH_SIZE 100  // Number of entries to hold in memory before flushing

static inline uint64_t clock_gettime_ns(void)
{
    unsigned int lo, hi;
    asm volatile("lfence; rdtscp" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}

// Structure to hold our raw measurements
typedef struct {
    uint64_t req_type;
    int frame;
    uint64_t cycles;
    int ret;
    uint64_t flags;
} log_entry_t;

static void prefault_range(void *addr, size_t len) {
    char *p = addr;
    for (size_t off = 0; off < len; off += PAGE_SIZE)
        memset((void*)(p + off), 0, PAGE_SIZE);
}