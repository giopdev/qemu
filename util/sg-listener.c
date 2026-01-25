#define _GNU_SOURCE

#include "qemu/sg.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <xcb/dri3.h>
#include <xcb/present.h>
#include <xcb/sync.h>
#include <xcb/xcb.h>
#include <xcb/dri3.h>
#include <xcb/present.h>
#include <xcb/xfixes.h>
#include <X11/xshmfence.h>
#include <drm/drm.h>
#include <drm/i915_drm.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <GL/gl.h>
#include <stdio.h>
#include <gbm.h>
#include <gbm.h>
#include <stdint.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <drm/drm.h>

/* IOCTL logging */
static uint64_t ioctl_count = 0;
static uint64_t ioctl_total_ns = 0;
static uint64_t ioctl_max_ns = 0;
static uint64_t frame_count = 0;
static bool ioctl_logging_enabled = false;
#define IOCTL_STATS_MAX 64
typedef struct ioctl_stat {
  unsigned long request;
  uint64_t count;
  uint64_t total_ns;
  uint64_t max_ns;
  uint64_t last_fd;
} ioctl_stat;
static ioctl_stat ioctl_stats[IOCTL_STATS_MAX];
static size_t ioctl_stats_used = 0;
static uint64_t execbuffer2_last_flags = 0;
static uint32_t syncobj_wait_last_flags = 0;

static void print_syncobj_wait_flags(FILE *out, uint32_t flags) {
  if (flags == 0) {
    fprintf(out, "NONE\n");
    return;
  }

  bool first = true;
#define PRINT_SYNCOBJ_FLAG(flag)                                            \
  do {                                                                       \
    if (flags & (flag)) {                                                    \
      fprintf(out, "%s%s", first ? "" : "|", #flag);                    \
      first = false;                                                         \
    }                                                                        \
  } while (0)

  PRINT_SYNCOBJ_FLAG(DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL);
  PRINT_SYNCOBJ_FLAG(DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT);

  if (first)
    fprintf(out, "0x%x", flags);

  fprintf(out, "\n");

#undef PRINT_SYNCOBJ_FLAG
}

static void print_execbuffer2_flags(uint64_t flags) {
    if (flags == 0) {
        fprintf(stderr, "NONE");
        return;
    }

    bool first = true;
    #define PRINT_FLAG(flag)                                                     \
    do {                                                                       \
        if (flags & (flag)) {                                                    \
        fprintf(stderr, "%s%s", first ? "" : "|", #flag);                            \
        first = false;                                                         \
        }                                                                        \
    } while (0)

    PRINT_FLAG(I915_EXEC_RING_MASK);
    PRINT_FLAG(I915_EXEC_DEFAULT);
    PRINT_FLAG(I915_EXEC_RENDER);
    PRINT_FLAG(I915_EXEC_BSD);
    PRINT_FLAG(I915_EXEC_BLT);
    PRINT_FLAG(I915_EXEC_VEBOX);
    PRINT_FLAG(I915_EXEC_SECURE);
    PRINT_FLAG(I915_EXEC_NO_RELOC);
    PRINT_FLAG(I915_EXEC_HANDLE_LUT);
    PRINT_FLAG(I915_EXEC_BSD_MASK);
    PRINT_FLAG(I915_EXEC_RESOURCE_STREAMER);
    PRINT_FLAG(I915_EXEC_FENCE_ARRAY);
    PRINT_FLAG(I915_EXEC_FENCE_OUT);
    PRINT_FLAG(I915_EXEC_USE_EXTENSIONS);
    #ifdef I915_EXEC_NO_FENCE
    PRINT_FLAG(I915_EXEC_NO_FENCE);
    #endif
    PRINT_FLAG(I915_EXEC_BATCH_FIRST);
    PRINT_FLAG(I915_EXEC_FENCE_SUBMIT);
    #ifdef I915_EXEC_CAPTURE
    PRINT_FLAG(I915_EXEC_CAPTURE);
    #endif
    #ifdef I915_EXEC_DEBUG
    PRINT_FLAG(I915_EXEC_DEBUG);
    #endif

    if (first)
        fprintf(stderr, "0x%llx", (unsigned long long)flags);

    fprintf(stderr, "\n");

#undef PRINT_FLAG
}

static const char *i915_ioctl_name(unsigned long request) {
  switch (request) {
  case DRM_IOCTL_I915_GEM_EXECBUFFER:
    return "GEM_EXECBUFFER";
  case DRM_IOCTL_I915_GEM_EXECBUFFER2:
    return "GEM_EXECBUFFER2";
  case DRM_IOCTL_I915_GEM_EXECBUFFER2_WR:
    return "GEM_EXECBUFFER2_WR";
  case DRM_IOCTL_I915_GEM_CREATE:
    return "GEM_CREATE";
  case DRM_IOCTL_I915_GEM_CREATE_EXT:
    return "GEM_CREATE_EXT";
  case DRM_IOCTL_I915_GEM_SET_DOMAIN:
    return "GEM_SET_DOMAIN";
  case DRM_IOCTL_I915_GEM_GET_TILING:
    return "GEM_GET_TILING";
  case DRM_IOCTL_I915_GEM_SET_TILING:
    return "GEM_SET_TILING";
  case DRM_IOCTL_I915_GEM_BUSY:
    return "GEM_BUSY";
  case DRM_IOCTL_I915_GEM_MMAP:
    return "GEM_MMAP";
  case DRM_IOCTL_I915_GEM_MMAP_GTT:
    return "GEM_MMAP_GTT";
  case DRM_IOCTL_I915_GEM_MMAP_OFFSET:
    return "GEM_MMAP_OFFSET";
  case DRM_IOCTL_I915_GEM_PREAD:
    return "GEM_PREAD";
  case DRM_IOCTL_I915_GEM_PWRITE:
    return "GEM_PWRITE";
  case DRM_IOCTL_I915_GEM_THROTTLE:
    return "GEM_THROTTLE";
  case DRM_IOCTL_I915_GEM_CONTEXT_CREATE:
    return "GEM_CONTEXT_CREATE";
  case DRM_IOCTL_I915_GEM_CONTEXT_CREATE_EXT:
    return "GEM_CONTEXT_CREATE_EXT";
  case DRM_IOCTL_I915_GEM_CONTEXT_DESTROY:
    return "GEM_CONTEXT_DESTROY";
  case DRM_IOCTL_I915_GEM_CONTEXT_SETPARAM:
    return "GEM_CONTEXT_SETPARAM";
  case DRM_IOCTL_I915_GEM_CONTEXT_GETPARAM:
    return "GEM_CONTEXT_GETPARAM";
  case DRM_IOCTL_I915_GEM_USERPTR:
    return "GEM_USERPTR";
  case DRM_IOCTL_I915_GEM_WAIT:
    return "GEM_WAIT";
  case DRM_IOCTL_I915_GEM_SW_FINISH:
    return "GEM_SW_FINISH";
  case DRM_IOCTL_I915_GEM_GET_APERTURE:
    return "GEM_GET_APERTURE";
  case DRM_IOCTL_I915_GEM_SET_CACHING:
    return "GEM_SET_CACHING";
  case DRM_IOCTL_I915_GEM_GET_CACHING:
    return "GEM_GET_CACHING";
  case DRM_IOCTL_I915_REG_READ:
    return "REG_READ";
  case DRM_IOCTL_I915_GETPARAM:
    return "GETPARAM";
  case DRM_IOCTL_I915_SETPARAM:
    return "SETPARAM";
  case DRM_IOCTL_I915_GEM_MADVISE:
    return "GEM_MADVISE";
#ifdef DRM_IOCTL_SYNCOBJ_CREATE
  case DRM_IOCTL_SYNCOBJ_CREATE:
    return "SYNCOBJ_CREATE";
#endif
#ifdef DRM_IOCTL_SYNCOBJ_DESTROY
  case DRM_IOCTL_SYNCOBJ_DESTROY:
    return "SYNCOBJ_DESTROY";
#endif
#ifdef DRM_IOCTL_SYNCOBJ_WAIT
  case DRM_IOCTL_SYNCOBJ_WAIT:
    return "SYNCOBJ_WAIT";
#endif
#ifdef DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD
  case DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD:
    return "SYNCOBJ_HANDLE_TO_FD";
#endif
#ifdef DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE
  case DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE:
    return "SYNCOBJ_FD_TO_HANDLE";
#endif
#ifdef DRM_IOCTL_SYNCOBJ_RESET
  case DRM_IOCTL_SYNCOBJ_RESET:
    return "SYNCOBJ_RESET";
#endif
#ifdef DRM_IOCTL_SYNCOBJ_SIGNAL
  case DRM_IOCTL_SYNCOBJ_SIGNAL:
    return "SYNCOBJ_SIGNAL";
#endif
#ifdef DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT
  case DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT:
    return "SYNCOBJ_TIMELINE_WAIT";
#endif
#ifdef DRM_IOCTL_SYNCOBJ_QUERY
  case DRM_IOCTL_SYNCOBJ_QUERY:
    return "SYNCOBJ_QUERY";
#endif
#ifdef DRM_IOCTL_SYNCOBJ_EVENTFD
  case DRM_IOCTL_SYNCOBJ_EVENTFD:
    return "SYNCOBJ_EVENTFD";
#endif
#ifdef DRM_IOCTL_I915_GEM_PIN
  case DRM_IOCTL_I915_GEM_PIN:
    return "GEM_PIN";
#endif
#ifdef DRM_IOCTL_I915_GEM_UNPIN
  case DRM_IOCTL_I915_GEM_UNPIN:
    return "GEM_UNPIN";
#endif
#ifdef DRM_IOCTL_I915_GEM_ENTERVT
  case DRM_IOCTL_I915_GEM_ENTERVT:
    return "GEM_ENTERVT";
#endif
#ifdef DRM_IOCTL_I915_GEM_LEAVEVT
  case DRM_IOCTL_I915_GEM_LEAVEVT:
    return "GEM_LEAVEVT";
#endif
#ifdef DRM_IOCTL_I915_GEM_SET_EXEC_TIMEOUT
  case DRM_IOCTL_I915_GEM_SET_EXEC_TIMEOUT:
    return "GEM_SET_EXEC_TIMEOUT";
#endif
#ifdef DRM_IOCTL_I915_GEM_GET_EXEC_TIMEOUT
  case DRM_IOCTL_I915_GEM_GET_EXEC_TIMEOUT:
    return "GEM_GET_EXEC_TIMEOUT";
#endif
#ifdef DRM_IOCTL_I915_GEM_GETPARAM
  case DRM_IOCTL_I915_GEM_GETPARAM:
    return "GEM_GETPARAM";
#endif
#ifdef DRM_IOCTL_I915_GEM_SHMEM_CREATE
  case DRM_IOCTL_I915_GEM_SHMEM_CREATE:
    return "GEM_SHMEM_CREATE";
#endif
#ifdef DRM_IOCTL_I915_GEM_CONTEXT_RESET_STATS
  case DRM_IOCTL_I915_GEM_CONTEXT_RESET_STATS:
    return "GEM_CONTEXT_RESET_STATS";
#endif
#ifdef DRM_IOCTL_I915_ALLOC
  case DRM_IOCTL_I915_ALLOC:
    return "ALLOC";
#endif
#ifdef DRM_IOCTL_I915_FREE
  case DRM_IOCTL_I915_FREE:
    return "FREE";
#endif
#ifdef DRM_IOCTL_I915_INIT
  case DRM_IOCTL_I915_INIT:
    return "INIT";
#endif
#ifdef DRM_IOCTL_I915_FLUSH
  case DRM_IOCTL_I915_FLUSH:
    return "FLUSH";
#endif
#ifdef DRM_IOCTL_I915_BATCHBUFFER
  case DRM_IOCTL_I915_BATCHBUFFER:
    return "BATCHBUFFER";
#endif
#ifdef DRM_IOCTL_I915_IRQ_EMIT
  case DRM_IOCTL_I915_IRQ_EMIT:
    return "IRQ_EMIT";
#endif
#ifdef DRM_IOCTL_I915_IRQ_WAIT
  case DRM_IOCTL_I915_IRQ_WAIT:
    return "IRQ_WAIT";
#endif
#ifdef DRM_IOCTL_I915_SWAP
  case DRM_IOCTL_I915_SWAP:
    return "SWAP";
#endif
#ifdef DRM_IOCTL_I915_CLIP
  case DRM_IOCTL_I915_CLIP:
    return "CLIP";
#endif
#ifdef DRM_IOCTL_I915_GEM_CONTEXT_RESET_STATS
  case DRM_IOCTL_I915_GEM_CONTEXT_RESET_STATS:
    return "GEM_CONTEXT_RESET_STATS";
#endif
#ifdef DRM_IOCTL_I915_GEM_VM_CREATE
  case DRM_IOCTL_I915_GEM_VM_CREATE:
    return "GEM_VM_CREATE";
#endif
#ifdef DRM_IOCTL_I915_GEM_VM_DESTROY
  case DRM_IOCTL_I915_GEM_VM_DESTROY:
    return "GEM_VM_DESTROY";
#endif
#ifdef DRM_IOCTL_I915_GEM_VM_BIND
  case DRM_IOCTL_I915_GEM_VM_BIND:
    return "GEM_VM_BIND";
#endif
#ifdef DRM_IOCTL_I915_GEM_VM_UNBIND
  case DRM_IOCTL_I915_GEM_VM_UNBIND:
    return "GEM_VM_UNBIND";
#endif
  default:
    return NULL;
  }
}

static void print_ioctl_stats(void) {
    if (ioctl_count == 0) {
        log_stat("IOCTL stats: no ioctls recorded in this interval\n");
        return;
    }

    /* Convert totals to microseconds for reporting */
    double total_us = (double)ioctl_total_ns / 1000.0;
    double avg_us = total_us / (double)ioctl_count;
    double max_us = (double)ioctl_max_ns / 1000.0;

    log_stat("==== IOCTL STATS (last %lu frames) ===\n", (unsigned long)5000);
    log_stat("Total IOCTLs: %lu\n", (unsigned long)ioctl_count);
    log_stat("Total time: %.2f us\n", total_us);
    log_stat("Average time: %.2f us\n", avg_us);
    log_stat("Max time: %.2f us\n", max_us);
    log_stat("Per-request breakdown:\n");

    log_stat("last EXECBUFFER2 flags: 0x%llx => ",
        (unsigned long long)execbuffer2_last_flags);
    print_execbuffer2_flags(execbuffer2_last_flags);

    log_stat("last SYNCOBJ_WAIT flags: 0x%x => ", syncobj_wait_last_flags);
    print_syncobj_wait_flags(stderr, syncobj_wait_last_flags);

    for (size_t i = 0; i < ioctl_stats_used; ++i) {
        ioctl_stat *s = &ioctl_stats[i];
        const char *name = i915_ioctl_name(s->request);
    double total_req_us = (double)s->total_ns / 1000.0;
    double avg_req_us = (s->count ? (double)s->total_ns / (double)s->count / 1000.0 : 0.0);
    double max_req_us = (double)s->max_ns / 1000.0;
    if (name)
      log_stat("  %s: count=%llu, total=%.2f us, avg=%.2f us, max=%.2f us, last_fd=%llu\n",
           name,
           (unsigned long long)s->count,
           total_req_us,
           avg_req_us,
           max_req_us,
           (unsigned long long)s->last_fd);
    else
      log_stat("  0x%lx: count=%llu, total=%.2f us, avg=%.2f us, max=%.2f us, last_fd=%llu\n",
           (unsigned long)s->request,
           (unsigned long long)s->count,
           total_req_us,
           avg_req_us,
           max_req_us,
           (unsigned long long)s->last_fd);
    }

    log_stat( "====================================\n");
}

static ioctl_stat *get_ioctl_stat(unsigned long request) {
  for (size_t i = 0; i < ioctl_stats_used; ++i) {
    if (ioctl_stats[i].request == request)
      return &ioctl_stats[i];
  }

  if (ioctl_stats_used >= IOCTL_STATS_MAX)
    return NULL;

  ioctl_stat *slot = &ioctl_stats[ioctl_stats_used++];
  memset(slot, 0, sizeof(*slot));
  slot->request = request;
  return slot;
}

struct timespec ts;
void *data_region_actual_address = NULL;
typedef struct {
  uint64_t host_address;
  uint64_t guest_address;
} gem_slots_t;
gem_slots_t gem_slots = {0};

xcb_window_t win;
xcb_connection_t *conn;

static long mmap_freq = 0;
static long ioctl_freq = 0;
// static long frame_count = 0;
static double frame_latency = 0.0;
static double time_spent_in_ioctl = 0.0;
static double start_frame = 0.0;
static uint64_t execbuf_count = 0;

static check* bufs_persistent = NULL;
static pthread_mutex_t gem_slots_lock = PTHREAD_MUTEX_INITIALIZER;


void log_latency_buffered(uint64_t req_type,int frame_count, uint64_t start, uint64_t end, int ret, uint64_t flags) {
    static log_entry_t buffer[LOG_BATCH_SIZE];
    static int current_idx = 0;
    static FILE *fp = NULL;

    // 1. Always calculate the delta in memory (High Precision)
    buffer[current_idx].req_type = req_type;
    buffer[current_idx].frame = frame_count;
    buffer[current_idx].cycles = end - start;
    buffer[current_idx].ret = ret;
    buffer[current_idx].flags = flags;
    current_idx++;

    // 2. Only hit the disk when the buffer is full
    if (current_idx >= LOG_BATCH_SIZE) {
        if (!fp) {
            fp = fopen("./logs_ioctl", "a");
            if (!fp) return;
        }

        // Write all 100 entries at once
        for (int i = 0; i < LOG_BATCH_SIZE; i++) {
            if(buffer[i].flags)
                fprintf(fp, "IOCTL req: %lu; Frame: %d; cycles: %lu; ret: %d; flags: %lu;\n", 
                    buffer[i].req_type, buffer[i].frame, buffer[i].cycles, buffer[i].ret, buffer[i].flags);
            else
                fprintf(fp, "IOCTL req: %lu; Frame: %d; cycles: %lu; ret: %d \n", 
                    buffer[i].req_type, buffer[i].frame, buffer[i].cycles, buffer[i].ret);
        }

        // Flush to disk and reset buffer index
        fflush(fp);
        current_idx = 0;
    }
}

void wait_for_batch(int fd, uint32_t handle) {
    struct drm_i915_gem_wait wait = {
        .bo_handle = handle,
        .flags = 0,      // Reserved for future use
        .timeout_ns = -1 // Wait forever (or set a timeout in nanoseconds)
    };

    // Call the WAIT IOCTL (3222824052)
    if (ioctl(fd, DRM_IOCTL_I915_GEM_WAIT, &wait) < 0) {
        perror("GEM WAIT failed");
    }
}

static void create_pixmap_from_kbuf(check *bufs, int buf_index,
                                    uint32_t size_bytes, uint32_t stride) {
    /*
        [pid 111638] poll([{fd=7, events=POLLIN|POLLOUT}], 1, -1) = 1 ([{fd=7,
        revents=POLLIN|POLLOUT}]) [pid 111638] recvmsg(7, {msg_name=NULL,
        msg_namelen=0,
        msg_iov=[{iov_base="\f\0\3\0\0\0\300\4\0\0\0\0\200\2\340\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        iov_len=4096}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 32 [pid
        111638] writev(7,
        [{iov_base="\224\3\4\0\0\0\300\4\2\0\0\0\0\0\0\0b\0\3\0\4\0\0\0DRI3",
        iov_len=28}], 1) = 28 [pid 111638] poll([{fd=7, events=POLLIN}], 1, -1) = 1
        ([{fd=7, revents=POLLIN}]) [pid 111638] recvmsg(7, {msg_name=NULL,
        msg_namelen=0,
        msg_iov=[{iov_base="\0\3\4\0\2\0\0\0\3\0\224\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        iov_len=4096}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 32 [pid
        111638] poll([{fd=7, events=POLLIN}], 1, -1) = 1 ([{fd=7, revents=POLLIN}])
        [pid 111638] recvmsg(7, {msg_name=NULL, msg_namelen=0,
        msg_iov=[{iov_base="\1\0\5\0\0\0\0\0\1\225\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        iov_len=4096}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 32 [pid
        111638] poll([{fd=7, events=POLLIN|POLLOUT}], 1, -1) = 1 ([{fd=7,
        revents=POLLOUT}]) [pid 111638] sendmsg(7, {msg_name=NULL, msg_namelen=0,
        msg_iov=[{iov_base="\225\2\6\0\1\0\300\4\0\0\300\4\0\300\22\0\200\2\340\1\0\n\30
        ", iov_len=24}], msg_iovlen=1, msg_control=[{cmsg_len=20,
        cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, cmsg_data=[9]}],
        msg_controllen=20, msg_flags=0}, 0) = 24 [pid 111638] close(9)
    */
    /*
        XCB does not call the ioctl(5, DRM_IOCTL_PRIME_FD_TO_HANDLE,
        0x7ffee2ec01fc)
    */
    bufs[buf_index].pixmap = xcb_generate_id(conn);
    xcb_void_cookie_t cookie = xcb_dri3_pixmap_from_buffer(
        conn, bufs[buf_index].pixmap, win, size_bytes, WIDTH, HEIGHT, stride, 24,
        32, bufs[buf_index].bo_fd);
    
    // Takes ownership of the GPU buffer and hands over pixmap as the identifier
    xcb_flush(conn);
    xcb_generic_error_t *err = xcb_request_check(conn, cookie);
    if (err) {
        fprintf(stderr,
                "DRI3 pixmap_from_buffer failed:"
                " error_code=%u, major=%u, minor=%u\n",
                err->error_code, err->major_code, err->minor_code);
        free(err);
        return; // or handle the error however you need
    }
    log_always("PIXMAP: %d (index=%d)\n", bufs[buf_index].pixmap,
            buf_index);
}

static int create_xcb_fence(check *bufs, int buf_index) {
  /*
    [pid 111638] memfd_create("xshmfence", MFD_CLOEXEC|MFD_ALLOW_SEALING) = 9
    [pid 111638] ftruncate(9, 4)            = 0
    [pid 111638] mmap(NULL, 4, PROT_READ|PROT_WRITE, MAP_SHARED, 9, 0) =
    0x7a2aa2cbf000 [pid 111638] poll([{fd=7, events=POLLIN|POLLOUT}], 1, -1) =
    1 ([{fd=7, revents=POLLOUT}]) [pid 111638] sendmsg(7, {msg_name=NULL,
    msg_namelen=0, msg_iov=[{iov_base="\225\4\4\0\1\0\300\4\2\0\300\4\0\0\0\0",
    iov_len=16}], msg_iovlen=1, msg_control=[{cmsg_len=20,
    cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, cmsg_data=[9]}],
    msg_controllen=20, msg_flags=0}, 0) = 16 [pid 111638] close(9) = 0
  */

  /* Create an xshmfence and register it as an X sync fence for this pixmap */
  bufs[buf_index].shm_fence_fd = xshmfence_alloc_shm(); // ----- (1)
  if (bufs[buf_index].shm_fence_fd < 0) {
    perror("xshmfence_alloc_shm");
    return 1;
  }
  bufs[buf_index].shm_fence = xshmfence_map_shm(bufs[buf_index].shm_fence_fd);
  if (!bufs[buf_index].shm_fence) {
    fprintf(stderr, "xshmfence_map_shm failed\n");
    return 1;
  }
  xshmfence_reset(bufs[buf_index].shm_fence); // start unsignaled

  bufs[buf_index].sync_fence = xcb_generate_id(conn);

  xcb_void_cookie_t cookie = xcb_dri3_fence_from_fd_checked(
      conn, bufs[buf_index].pixmap, bufs[buf_index].sync_fence, 0,
      bufs[buf_index].shm_fence_fd);

  /*
    Logic:
    1: Gets the memfd from (1)
    2: Maps to our process using mmap (xshmfence_map_shm)
    3: identifier for the fence is sync_fence (X11 allocated)
    4: Transfers ownership of the fd to the X11. and closes the fd inside process.
  */
  xcb_flush(conn);

  xcb_generic_error_t *err = xcb_request_check(conn, cookie);
  if (err) {
    fprintf(stderr,
            "xcb_dri3_fence_from_fd failed: "
            "error_code=%u major=%u minor=%u\n",
            err->error_code, err->major_code, err->minor_code);

    free(err);

    // NOTE:
    // X11 owns shm_fence_fd only if the request succeeded.
    // If it failed, WE must close it.
    close(bufs[buf_index].shm_fence_fd);

    return 1;
  }

  log_always("XCB setup completed (index=%d)\n", buf_index);
  return 0; // adil: added a return value
}


void create_and_setup_xcb_window(){
    conn = xcb_connect(NULL, NULL);
    if (xcb_connection_has_error(conn)) { fprintf(stderr,"xcb_connect failed\n"); return; }
    xcb_screen_t *screen = (xcb_screen_t*)xcb_setup_roots_iterator(xcb_get_setup(conn)).data;
    win = xcb_generate_id(conn);
    uint32_t mask = XCB_CW_BACK_PIXEL | XCB_CW_EVENT_MASK;
    uint32_t values[2] = { screen->black_pixel, XCB_EVENT_MASK_EXPOSURE };
    xcb_create_window(conn, XCB_COPY_FROM_PARENT, win, screen->root,
                      0,0, WIDTH, HEIGHT, 0,
                      XCB_WINDOW_CLASS_INPUT_OUTPUT, screen->root_visual,
                    mask, values);
                      /* Set window title */
    const char *title = "XCB Demo Window";
    xcb_change_property(conn, XCB_PROP_MODE_REPLACE,
                        win, XCB_ATOM_WM_NAME, XCB_ATOM_STRING, 8,
                    strlen(title), title);
    xcb_map_window(conn, win);
    xcb_flush(conn);

    // ask for present complete events (optional)
    xcb_present_select_input(conn, win, XCB_PRESENT_EVENT_MASK_COMPLETE_NOTIFY, 0);

}

void setup_comm_data_regions(volatile comm_page_t *c) {
    while (c->magic != COMM_MAGIC) {
        usleep(1000);
    }
    log_always("COMM: 0x%llx\n",
            (unsigned long long)(uint64_t)(uintptr_t)c);
    log_always("COMM MAGIC: %p\n", (void *)*((uint64_t *)COMM_ADDR));

    volatile comm_page_t* d = (comm_page_t*)(uintptr_t)DATA_REGION;
    while (d->magic != 0x1234567812344678ULL) {
        usleep(1000);
    }
    data_region_actual_address = (void *)((uint64_t)global_ram_address);

    log_always("DATA MAGIC: %p\n", (void *)*((uint64_t *)DATA_REGION));
    log_always("DATA REGION: (guest=%p, host=%p)\n",
            (void*)(uint64_t)DATA_REGION, data_region_actual_address);

    while (*((uint64_t *)data_region_actual_address) != 0x1234567812344678ULL) {
        usleep(1000);
    }
    *((uint64_t *)data_region_actual_address) = 0x2;

    gem_slots.host_address = ((uint64_t)data_region_actual_address);
    gem_slots.guest_address = ((uint64_t)DATA_REGION);
    create_and_setup_xcb_window();
    log_always("XCB window created\n");

    c->ret = 0;
    __sync_synchronize();
    c->req_bit = 0;
}

extern void* mmap_listener(void* arg) {
    /* TODO: Is this really needed? */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(3, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    /* Setup the communications and data regions */
    volatile comm_page_t* c = (comm_page_t*)(uintptr_t)COMM_ADDR;
    setup_comm_data_regions(c);

    static void *curr_host_addr = NULL;
    static void *curr_guest_addr = NULL;

    /*
     * Event Processing loop
     */
    uint64_t ret;
    for (;;) {
        switch (c->req_bit) {
            case LOG_MMAP_EVENT:
                break;

            case GEM_ALLOCATION:
                uint64_t size = c->p2;
                log_gem("size: 0x%lx, host: 0x%lx, guest: 0x%lx\n", size, gem_slots.host_address, gem_slots.guest_address);

                // Unmapping previous mapping (and asserts)
                assert(gem_slots.host_address + size < data_region_actual_address + DATA_SIZE);
                assert(munmap(gem_slots.host_address, size) == 0);
                assert(munmap(gem_slots.guest_address, size) == 0);

                // Mapping on original offset
                void *retptr = mmap(gem_slots.host_address, c->p2 /*size*/, c->p3,
                                    c->p4 | MAP_SHARED | MAP_FIXED, c->p5, c->p6);
                if (retptr == MAP_FAILED) {
                    perror("[QEMU-HOST] MMAP failed for GEM_ALLOCATION!!!!!");
                    assert(retptr != MAP_FAILED);
                }
                assert(retptr == gem_slots.host_address);

                retptr = mmap(gem_slots.guest_address, c->p2 /*size*/, c->p3,
                                c->p4 | MAP_SHARED | MAP_FIXED, c->p5, c->p6);
                if (retptr == MAP_FAILED) {
                    perror("[QEMU-GUEST] MMAP failed for GEM_ALLOCATION!!!!!");
                    assert(ret != MAP_FAILED);
                }
                assert(retptr == gem_slots.guest_address);

                c->ret = (uint64_t)gem_slots.guest_address;
                pthread_mutex_lock(&gem_slots_lock);
                    gem_slots.host_address += PAGE_SIZE * (int)((PAGE_SIZE + size) / PAGE_SIZE);
                    gem_slots.guest_address += PAGE_SIZE * (int)((PAGE_SIZE + size) / PAGE_SIZE);
                pthread_mutex_unlock(&gem_slots_lock);
                
                __sync_synchronize();
                c->req_bit = 0;
                
                log_sg("mmap() returned: 0x%lx", c->ret);
                mmap_freq++;
                break;
            
            case FSTAT:
                log_sg("fstat() is called");
                ret = fstat(c->p1, (struct stat*) c->p2);
                c->ret = ret;
                log_sg("fstat() returned: %d", ret);

                __sync_synchronize();
                c->req_bit = 0;
                break; 
                
            case IOCTL: {
                uint64_t start,end;
                struct timespec start_ts;
                struct timespec end_ts;
                uint64_t req_type = _IOC_NR(c->p2);
                int already_done = 0;

                /* Log the time it takes for the IOCTLs */
                clock_gettime(CLOCK_MONOTONIC_RAW, &start_ts);
                ret = ioctl(c->p1, c->p2, (void *)c->p3);
                clock_gettime(CLOCK_MONOTONIC_RAW, &end_ts);

                uint64_t start_ns = (uint64_t)start_ts.tv_sec * 1000000000ULL +
                                    (uint64_t)start_ts.tv_nsec;
                uint64_t end_ns = (uint64_t)end_ts.tv_sec * 1000000000ULL +
                                    (uint64_t)end_ts.tv_nsec;
                uint64_t delta_ns = end_ns - start_ns;

                ioctl_count++;
                ioctl_total_ns += delta_ns;
                if (delta_ns > ioctl_max_ns)
                    ioctl_max_ns = delta_ns;

                /* track additional derived counters */
                ioctl_freq++;
                /* keep time_spent_in_ioctl in microseconds for consistency */
                time_spent_in_ioctl += (double)delta_ns / 1000.0; /* microseconds */

                      ioctl_stat *stat = get_ioctl_stat(c->p2);
                      if (stat) {
                        stat->count++;
                        stat->total_ns += delta_ns;
                        if (delta_ns > stat->max_ns)
                          stat->max_ns = delta_ns;
                        stat->last_fd = c->p1;
                      }

                if (c->p2 == DRM_IOCTL_I915_GEM_EXECBUFFER2 && c->p3) {
                    const struct drm_i915_gem_execbuffer2 *execbuf =
                        (const struct drm_i915_gem_execbuffer2 *)c->p3;
                    execbuffer2_last_flags = execbuf->flags;
                }

                if (c->p2 == DRM_IOCTL_SYNCOBJ_WAIT && c->p3) {
                    const struct drm_syncobj_wait *wait = (const struct drm_syncobj_wait *)c->p3;
                    syncobj_wait_last_flags = wait->flags;
                }

                c->ret = ret;
                __sync_synchronize();
                c->req_bit = 0;
                break;
            }

            case OPEN:
                log_sg("open() is called (%s)", (const char*) c->p1);
                ret = open((const char*) c->p1, c->p2, c->p3);
                if (ret < 0) {
                    fprintf(stderr, "[QEMU] open failed in sg-listener\n");
                    perror("open");
                }
                c->ret = ret;
                log_sg("open() returned: %d", ret);
                __sync_synchronize();
                c->req_bit = 0;
                break;

            case FCNTL:
                log_sg("fcntl() is called");
                ret = fcntl(c->p1, c->p2, c->p3);
                c->ret = ret;
                log_sg("fcntl() returned: %d", ret);
                __sync_synchronize();
                c->req_bit = 0;
                break;

            case READLINK:
                log_sg("readlink() is called");
                ret = readlink((const char*) c->p1, (const char*) c->p2, c->p3);
                c->ret = ret;
                log_sg("readlink() returned: %d", ret);
                __sync_synchronize();
                c->req_bit = 0;
                break;

            case NEWFSTAT:
                log_sg("newfstatat() is called");
                ret = fstatat(c->p1, (const char*) c->p2, (struct stat*) c->p3, c->p4);
                c->ret = ret;
                log_sg("newfstatat() returned: %d", ret);
                __sync_synchronize();
                c->req_bit = 0;
                break;

            case GETDENT:
                log_sg("getdent() is called");
                ret = syscall(SYS_getdents64, c->p1, c->p2, c->p3);
                c->ret = ret;
                log_sg("getdent() returned: %d", ret);
                __sync_synchronize();
                c->req_bit = 0;
                break;

            case DUP:
                log_sg("dup() is called");
                ret = dup(c->p1);
                c->ret = ret;
                log_sg("dup() returned: %d", ret);
                __sync_synchronize();
                c->req_bit = 0;
                break;

            case X11_SETUP:
                log_sg("X11_SETUP() is called");
                create_pixmap_from_kbuf((check*) c->p1, c->p2, c->p3, c->p4);
                create_xcb_fence((check*) c->p1, c->p2);
                log_sg("X11_SETUP() completed");
                __sync_synchronize();
                c->req_bit = 0;
                break;

            case X11_PRESENT:
                check *tmp_buf = (check *)c->p1;
                log_sg("X11_PRESENT() is called\n");
                // xshmfence_trigger(tmp_buf[c->p2].shm_fence);
                // xcb_sync_trigger_fence(conn, tmp_buf[c->p2].sync_fence);
                xcb_present_pixmap(conn, win, tmp_buf[c->p2].pixmap,
                                    0,                         // serial
                                    XCB_NONE,                  // valid
                                    XCB_NONE,                  // update
                                    0, 0,                      // x, y
                                    XCB_NONE,                  // target_crtc
                                    0, // wait_fence
                                    c->p3,                     // idle_fence
                                    0,                         // options
                                    0, 0, 0, // target_msc, divisor, remainder
                                    0,       // notifies_len
                                    NULL);  

                xcb_flush(conn);
                c->req_bit = 0;
                log_sg("X11_PRESENT() completed");
                frame_count++;

                if(frame_count%5000 == 0){
                    /* Print IOCTL statistics collected since last report and reset counters */
                    print_ioctl_stats();

                    /* Reset cumulative and per-request stats */
                    ioctl_count = 0;
                    ioctl_total_ns = 0;
                    ioctl_max_ns = 0;
                    ioctl_stats_used = 0;
                    execbuffer2_last_flags = 0;
                    syncobj_wait_last_flags = 0;
                    memset(ioctl_stats, 0, sizeof(ioctl_stats));

                    /* Reset runtime counters */
                    frame_latency = 0;
                    ioctl_freq = 0;
                    mmap_freq = 0;
                    time_spent_in_ioctl = 0;
                    execbuf_count = 0;
                }
                break;

            case CLOSE:
                log_sg("close() is called");
                close(c->p1);
                log_sg("close() completed");
                __sync_synchronize();
                c->req_bit = 0;
                // bufs_persistent = c->p1;
                break;

            default:
                // fprintf(stderr, "[QEMU] No such event:%llu", (unsigned long long)c->req_bit);
                break;
        }
    }
    return NULL;
}
