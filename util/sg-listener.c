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
static check* bufs_persistent = NULL;
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
void setup_data(comm_page_t *c) {
  fprintf(stderr, "Data region addr: %p; Host Base address: %p\n", c->p10,
         global_ram_address);
  fflush(stderr);
//   uint64_t data_start = c->p10;
// //   data_region_actual_address =
// //       (void *)((uint64_t)(-2 * 1024 * 1024 * 1024 /* Offset: Ref gio's diag */ +
// //                           data_start) +
// //                (uint64_t)global_ram_address);
//   data_region_actual_address = (void *)((uint64_t)global_ram_address);
//   fprintf(stderr, "Data region actual addr: %p\n", data_region_actual_address);
//   fprintf(stderr, "Data region MAGIC: %p\n", (void *)*((uint64_t *)data_region_actual_address));

//   while (*((uint64_t *)data_region_actual_address) != COMM_MAGIC) {
//     usleep(1000);
//  }

//   gem_slots.host_address = ((uint64_t)data_region_actual_address);
//   gem_slots.guest_address = ((uint64_t)data_start);
//   // sleep(10000000000);
//   create_and_setup_xcb_window();
//   c->ret = 0;
//   c->req_bit = 0;
}

extern void* mmap_listener(void* arg) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(3, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    volatile comm_page_t* c = (comm_page_t*)(uintptr_t)COMM_ADDR;
    while (c->magic != COMM_MAGIC) {
        usleep(1000);
    }
    fprintf(stderr, "[QEMU] comm ready at 0x%llx\n",
            (unsigned long long)(uint64_t)(uintptr_t)c);
    fprintf(stderr, "COMM region MAGIC: %p\n", (void *)*((uint64_t *)COMM_ADDR));

    volatile comm_page_t* d = (comm_page_t*)(uintptr_t)DATA_REGION;
    while (d->magic != 0x1234567812344678ULL) {
        usleep(1000);
    }
    fprintf(stderr, "DATA region MAGIC: %p\n", (void *)*((uint64_t *)DATA_REGION));

    data_region_actual_address = (void *)((uint64_t)global_ram_address);
    fprintf(stderr, "Data region actual addr: %p\n", data_region_actual_address);
    fprintf(stderr, "Data region MAGIC: %p\n", (void *)*((uint64_t *)data_region_actual_address));

    while (*((uint64_t *)data_region_actual_address) != 0x1234567812344678ULL) {
        usleep(1000);
    }
    *((uint64_t *)data_region_actual_address) = 0x2;
    // memset(data_region_actual_address, 0, 64); // Clear the region

    gem_slots.host_address = ((uint64_t)data_region_actual_address);
    gem_slots.guest_address = ((uint64_t)DATA_REGION);
    create_and_setup_xcb_window();
    c->ret = 0;
    c->req_bit = 0;

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
                case SETUP_DATA:
                    setup_data(c);
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
                    c->req_bit = 0;
                    log_sg("mmap() returned: 0x%lx", c->ret);
                    mmap_freq++;
                    break;
                
                case FSTAT:
                    log_sg("fstat() is called");
                    ret = fstat(c->p1, (struct stat*) c->p2);
                    c->ret = ret;
                    log_sg("fstat() returned: %d", ret);
                    c->req_bit = 0;
                    break; 
                case IOCTL: {
                    uint64_t start,end;
                    uint64_t req_type = _IOC_NR(c->p2);
                    int already_done = 0;
                    // if (req_type == 195) {
                    //     struct drm_syncobj_wait *sw = (struct drm_syncobj_wait *)(c->p3);
                        
                    //     if (sw->timeout_nsec > 0) {
                    //         sw->timeout_nsec = 0; // Force non-blocking
                    //         start = clock_gettime_ns();

                    //         int poll_count = 0;
                    //         while (1) {
                    //             ret = ioctl(c->p1, c->p2, (void *)c->p3);
                    //             if (ret == 0) break;
                                
                    //             // Instead of one pause, do a small "sleep-like" spin 
                    //             // to let the GPU hardware work without being interrupted by the CPU
                    //             for(int i=0; i<200; i++) {
                    //                 asm volatile("pause" ::: "memory");
                    //             }
                    //             poll_count++;
                    //         }
                    //         end = clock_gettime_ns();
                    //         asm volatile("lfence" ::: "memory");
                    //         c->ret = ret;
                    //         c->req_bit = 0;
                    //         ioctl_freq++;
                    //         log_latency_buffered(req_type, frame_count, start, end, ret, 0);
                    //         break;
                            
                    //     }
                    // }


                    // Now you can use this handle for your test:
                    // wait_for_batch(fd, batch_handle);
                    // start = clock_gettime_ns();
                    // asm volatile("lfence" ::: "memory");
                    ret = ioctl(c->p1, c->p2, (void *)c->p3);
                    // asm volatile("lfence" ::: "memory");
                    // end = clock_gettime_ns();
                    // asm volatile("lfence" ::: "memory");

                    c->ret = ret;
                    ioctl_freq++;
                    // if(req_type == 195){
                    //     struct drm_syncobj_wait *eb = (struct drm_syncobj_wait *)(c->p3);
                    //     eb->timeout_nsec = 0;
                    //     // log_latency_buffered(req_type, frame_count, start, end, ret, eb->flags);
                    // }
                    // else
                    //     log_latency_buffered(req_type, frame_count, start, end, ret, 0);
                    c->req_bit = 0;
                    break;
                }

                case OPEN:
                    // log_sg("open() is called (%s)", (const char*) c->p1);
                    // fprintf(stderr, "[QEMU] filename address: %p %s\n", (void*) c->p1, (char*) c->p1);
                    ret = open((const char*) c->p1, c->p2, c->p3);
                    if (ret < 0) {
                        fprintf(stderr, "[QEMU] open failed in sg-listener\n");
                        perror("open");
                    }
                    fprintf(stderr, "[QEMU] open() fd: %d\n", ret);
                    c->ret = ret;
                    __sync_synchronize();
                    log_sg("open() returned: %d", ret);
                    c->req_bit = 0;
                    break;
                case FCNTL:
                    log_sg("fcntl() is called");
                    ret = fcntl(c->p1, c->p2, c->p3);
                    c->ret = ret;
                    log_sg("fcntl() returned: %d", ret);
                    c->req_bit = 0;
                    break;
                case READLINK:
                    log_sg("readlink() is called");
                    ret = readlink((const char*) c->p1, (const char*) c->p2, c->p3);
                    c->ret = ret;
                    log_sg("readlink() returned: %d", ret);
                    c->req_bit = 0;
                    break;  
                case NEWFSTAT:
                    log_sg("newfstatat() is called");
                    ret = fstatat(c->p1, (const char*) c->p2, (struct stat*) c->p3, c->p4);
                    c->ret = ret;
                    log_sg("newfstatat() returned: %d", ret);
                    c->req_bit = 0;
                    break;
                case GETDENT:
                    log_sg("getdent() is called");
                    ret = syscall(SYS_getdents64, c->p1, c->p2, c->p3);
                    c->ret = ret;
                    log_sg("getdent() returned: %d", ret);
                    c->req_bit = 0;
                    break;
                case DUP:
                    log_sg("dup() is called");
                    ret = dup(c->p1);
                    c->ret = ret;
                    log_sg("dup() returned: %d", ret);
                    c->req_bit = 0;
                    break;
                case X11_SETUP:
                    log_sg("X11_SETUP() is called");
                    create_pixmap_from_kbuf((check*) c->p1, c->p2, c->p3, c->p4);
                    create_xcb_fence((check*) c->p1, c->p2);
                    log_sg("X11_SETUP() completed");
                    c->req_bit = 0;
                    // bufs_persistent = c->p1;
                    break;
                case X11_PRESENT:
                    check *tmp_buf = (check *)c->p1;
                    log_sg("X11_PRESENT() is called\n");
                    //   xshmfence_trigger(tmp_buf[c->p2].shm_fence);
                    xcb_sync_trigger_fence(conn, tmp_buf[c->p2].sync_fence);
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
                    if (start_frame > 0){
                        clock_gettime(CLOCK_REALTIME, &ts);
                        double end_frame = (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
                        frame_latency += (end_frame - start_frame);
                    }
                    if(frame_count == 1){
                        mmap_freq = 0;
                        ioctl_freq = 0;
                        frame_latency = 0.0;
                        time_spent_in_ioctl = 0;
                    }
                    clock_gettime(CLOCK_REALTIME, &ts);
                    start_frame = (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
                    if(frame_count%5000 == 0){
                        fprintf(stderr, "------------------SG STATS-----------------------------\n");
                        fprintf(stderr, "Frame: %lu; MMAPs: %lu; IOCTLs: %lu; Frame latency: %f; IOCTL-Latency: %f VMEXITS: NaN\n", frame_count, mmap_freq, ioctl_freq, (double)frame_latency/5000.0, (double)time_spent_in_ioctl/(5000.0*1e6));
                        fprintf(stderr, "------------------SG STATS-----------------------------\n");
                        frame_latency = 0;
                        ioctl_freq = 0;
                        mmap_freq = 0;
                        time_spent_in_ioctl = 0;
                        fprintf(stderr,
                    "Frame %lu: execbuffers=%" PRIu64 "\n",
                    frame_count, execbuf_count);
                execbuf_count = 0;

                    }
                    break;
                case CLOSE:
                    log_sg("close() is called");
                    close(c->p1);
                    log_sg("close() completed");
                    c->req_bit = 0;
                    // bufs_persistent = c->p1;
                    break;
                default:
                    // fprintf(stderr, "[QEMU] No such event:%llu", (unsigned long long)c->req_bit);
                    break;
            }
        // throttle_listener();
        }
    return NULL;
}
