#include <stddef.h>
#define _GNU_SOURCE

#include "qemu/sg.h"
#include <GL/gl.h>
#include <X11/xshmfence.h>
#include <assert.h>
#include <drm/drm.h>
#include <drm/i915_drm.h>
#include <errno.h>
#include <fcntl.h>
#include <gbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>
#include <xcb/dri3.h>
#include <xcb/present.h>
#include <xcb/sync.h>
#include <xcb/xcb.h>
#include <xcb/xfixes.h>

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
static long frame_count = 0;
static double frame_latency = 0.0;
static double time_spent_in_ioctl = 0.0;
static double start_frame = 0.0;
static uint64_t execbuf_count = 0;

void log_latency_buffered(uint64_t req_type, int frame_count, uint64_t start,
                          uint64_t end, int ret, uint64_t flags) {
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
      if (!fp)
        return;
    }

    // Write all 100 entries at once
    for (int i = 0; i < LOG_BATCH_SIZE; i++) {
      if (buffer[i].flags)
        fprintf(
            fp,
            "IOCTL req: %lu; Frame: %d; cycles: %lu; ret: %d; flags: %lu;\n",
            buffer[i].req_type, buffer[i].frame, buffer[i].cycles,
            buffer[i].ret, buffer[i].flags);
      else
        fprintf(fp, "IOCTL req: %lu; Frame: %d; cycles: %lu; ret: %d \n",
                buffer[i].req_type, buffer[i].frame, buffer[i].cycles,
                buffer[i].ret);
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
static check *bufs_persistent = NULL;
static pthread_mutex_t gem_slots_lock = PTHREAD_MUTEX_INITIALIZER;
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
  // Takes the ownership of the GPU buffer. and hands over pixmap as the
  // identifier

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

  fprintf(stderr, "PIXMAP: %d for index: %d\n", bufs[buf_index].pixmap,
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
          4: Transfers ownership of the fd to the X11. and closes the fd inside
     process.

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

  fprintf(stderr, "All done from XCB side for index: %d\n", buf_index);
  return 0; // adil: added a return value
}

void create_and_setup_xcb_window() {
  conn = xcb_connect(NULL, NULL);
  if (xcb_connection_has_error(conn)) {
    fprintf(stderr, "xcb_connect failed\n");
    return;
  }
  xcb_screen_t *screen =
      (xcb_screen_t *)xcb_setup_roots_iterator(xcb_get_setup(conn)).data;
  win = xcb_generate_id(conn);
  uint32_t mask = XCB_CW_BACK_PIXEL | XCB_CW_EVENT_MASK;
  uint32_t values[2] = {screen->black_pixel, XCB_EVENT_MASK_EXPOSURE};
  xcb_create_window(conn, XCB_COPY_FROM_PARENT, win, screen->root, 0, 0, WIDTH,
                    HEIGHT, 0, XCB_WINDOW_CLASS_INPUT_OUTPUT,
                    screen->root_visual, mask, values);
  /* Set window title */
  const char *title = "XCB Demo Window";
  xcb_change_property(conn, XCB_PROP_MODE_REPLACE, win, XCB_ATOM_WM_NAME,
                      XCB_ATOM_STRING, 8, strlen(title), title);
  xcb_map_window(conn, win);
  xcb_flush(conn);
  // ask for present complete events (optional)
  xcb_present_select_input(conn, win, XCB_PRESENT_EVENT_MASK_COMPLETE_NOTIFY,
                           0);
}
void setup_data(comm_page_t *c) {
  log_sg("Data region addr: %p; Host Base address: %p\n", c->p10,
         global_ram_address);
  fflush(stderr);
  uint64_t data_start = c->p10;
  data_region_actual_address =
      (void *)((uint64_t)(-2 * 1024 * 1024 * 1024 /* Offset: Ref gio's diag */ +
                          data_start) +
               (uint64_t)global_ram_address);
  gem_slots.host_address = ((uint64_t)data_region_actual_address);
  gem_slots.guest_address = ((uint64_t)data_start);
  // sleep(10000000000);
  create_and_setup_xcb_window();
  c->ret = 0;
  c->req_bit = 0;
}

// ACTUAL STUFF I NEED
// /////////////////////////////////////////////////////
// /////////////////////////////////////////////////////
// /////////////////////////////////////////////////////
// /////////////////////////////////////////////////////
// /////////////////////////////////////////////////////
// /////////////////////////////////////////////////////
// /////////////////////////////////////////////////////
// /////////////////////////////////////////////////////
void evict_caches(void *addr, size_t len);
static inline uint64_t get_ticks(void);
uint64_t latmem_time_single(void *head, uint64_t loads);
void pin_to_core(int core);

#define TRASH_SIZE (32 * 1024 * 1024)
static char *global_trash_buffer;
static volatile uintptr_t latmem_sink;
size_t lat_mem_len = {0};
void *lat_mem_addr = {0};

void evict_caches(void *addr, size_t len) {
  char *cp = (char *)addr;
  for (size_t i = 0; i < len; i += 64) {
    __asm__ __volatile__("clflush (%0)" : : "r"(cp + i) : "memory");
  }

  if (global_trash_buffer) {
    volatile char sum = 0;
    for (size_t i = 0; i < TRASH_SIZE; i += 64) {
      sum += global_trash_buffer[i];
    }
    latmem_sink ^= sum;
  }
  __asm__ __volatile__("mfence" ::: "memory");
}

static inline uint64_t time_single_access(void **p_ptr) {
  uint64_t t0, t1;
  void *next_p;

  _mm_lfence();
  t0 = __rdtsc();
  _mm_lfence();

  next_p = *p_ptr;

  _mm_lfence();
  t1 = __rdtsc();
  _mm_lfence();

  latmem_sink ^= (uintptr_t)next_p;

  evict_caches(lat_mem_addr, lat_mem_len);
  return t1 - t0;
}

void pin_to_core(int core) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core, &cpuset);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) != 0) {
    perror("sched_setaffinity");
    exit(1);
  }
}

// LISTENER ------------------------------------------------
// ---------------------------------------------------------
extern void *mmap_listener(void *arg) {

  volatile comm_page_t *c = (comm_page_t *)(uintptr_t)COMM_ADDR;

  pin_to_core(0);
  while (c->magic != COMM_MAGIC) {
    usleep(1000);
  }
  global_trash_buffer = malloc(TRASH_SIZE);
  memset(global_trash_buffer, 0xAA, TRASH_SIZE);

  fprintf(stderr, "[QEMU] comm ready at 0x%llx\n",
          (unsigned long long)(uint64_t)(uintptr_t)c);

  static void *curr_host_addr = NULL;
  static void *curr_guest_addr = NULL;
  /*
   * Event Processing loop
   */
  uint64_t ret;
  for (;;) {
    switch (c->req_bit) {
    case 0:
      // no req
      break;
    case SET_LEN:
      lat_mem_addr = (void *)c->p1;
      lat_mem_len = (size_t)c->p2;
      c->req_bit = 0;
      break;
    case TIME_MEM:
      c->ret = time_single_access((void **)c->p1);
      c->req_bit = 0;
      break;
    default:
      // fprintf(stderr, "[QEMU] No such event:%llu", (unsigned long
      // long)c->req_bit);
      break;
    }
    // throttle_listener();
  }
  return NULL;
}
