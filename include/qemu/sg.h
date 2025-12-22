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
// #define SG_DEBUG

#ifdef SG_DEBUG
#define log_sg(fmt, ...) \
    do { \
        printf("[SG] +++++++++++++++\n"); \
        printf(fmt, ##__VA_ARGS__); \
        printf("\n[SG] +++++++++++++++\n"); \
    } while (0)
#else
#define log_sg(fmt, ...) do {} while (0)
#endif


extern void* data_region_actual_address;
extern void* global_ram_address;
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


// Sizes
static const  size_t ONE_MEGABYTE = 1024*1024*10;
static const  size_t FIVETWELVE_MEGABYTE = 1024*1024*512;
static const  size_t DATA_SIZE = FIVETWELVE_MEGABYTE*16; // 2G
static const  size_t PAGE_SIZE    = 4096;

#define COMM_ADDR  0xf00000ULL
#define COMM_MAGIC 0x1234567812345678ULL

static void* DATA_REGION = (void*)0x100008000ULL;
// This is different than where it appears in the guest.
// Qemu maps the ram region from 0x80000000 into the allocation to 0x100000000 in the guest AS
static void* DATA_HOST_OFFSET = (void*)0x80008000ULL;

static void* UNMAP_DATA_MSG = (void*)0x1234567f1234567fULL;


void* mmap_listener(void* arg);