#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <assert.h>
#include "qemu/sg.h"
#include <sys/syscall.h>

#include <xcb/xcb.h>
#include <xcb/dri3.h>
#include <xcb/present.h>
#include <xcb/sync.h>

#include <xcb/dri3.h>
#include <xcb/present.h>
#include <xcb/xfixes.h>

#include <X11/xshmfence.h>
#include <drm/drm.h>
#include <drm/i915_drm.h>
#include <sys/ioctl.h>

void *data_region_actual_address = NULL;
#define NUMBER_OF_GEM_SLOTS 1024
typedef struct {
    void* host_address[NUMBER_OF_GEM_SLOTS];
    void* guest_address[NUMBER_OF_GEM_SLOTS];
    bool slot_occupied[NUMBER_OF_GEM_SLOTS];
} gem_slots_t;
gem_slots_t gem_slots = {0};

xcb_window_t win;
xcb_connection_t *conn;
#define WIDTH 1920
#define HEIGHT 1080
static void
dump_shader_bytes(const char *tag, const void *data)
{
    size_t n = 256;   // dump first 64 bytes
    const unsigned char *p = (const unsigned char*)data;

    fprintf(stderr, "%s: first %zu bytes:", tag, n);

    for (size_t i = 0; i < n; i++) {
        if (i % 16 == 0)
            fprintf(stderr, "\n%04zx: ", i);
        fprintf(stderr, "%02x ", p[i]);
    }
    fprintf(stderr, "\n\n");
}
static check* bufs_persistent = NULL;
static pthread_mutex_t gem_slots_lock = PTHREAD_MUTEX_INITIALIZER;
static void create_pixmap_from_kbuf(check* bufs, int buf_index, uint32_t size_bytes, uint32_t stride){
    /*
        [pid 111638] poll([{fd=7, events=POLLIN|POLLOUT}], 1, -1) = 1 ([{fd=7, revents=POLLIN|POLLOUT}])
        [pid 111638] recvmsg(7, {msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\f\0\3\0\0\0\300\4\0\0\0\0\200\2\340\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", iov_len=4096}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 32
        [pid 111638] writev(7, [{iov_base="\224\3\4\0\0\0\300\4\2\0\0\0\0\0\0\0b\0\3\0\4\0\0\0DRI3", iov_len=28}], 1) = 28
        [pid 111638] poll([{fd=7, events=POLLIN}], 1, -1) = 1 ([{fd=7, revents=POLLIN}])
        [pid 111638] recvmsg(7, {msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\0\3\4\0\2\0\0\0\3\0\224\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", iov_len=4096}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 32
        [pid 111638] poll([{fd=7, events=POLLIN}], 1, -1) = 1 ([{fd=7, revents=POLLIN}])
        [pid 111638] recvmsg(7, {msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\1\0\5\0\0\0\0\0\1\225\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", iov_len=4096}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 32
        [pid 111638] poll([{fd=7, events=POLLIN|POLLOUT}], 1, -1) = 1 ([{fd=7, revents=POLLOUT}])
        [pid 111638] sendmsg(7, {msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\225\2\6\0\1\0\300\4\0\0\300\4\0\300\22\0\200\2\340\1\0\n\30 ", iov_len=24}], msg_iovlen=1, msg_control=[{cmsg_len=20, cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, cmsg_data=[9]}], msg_controllen=20, msg_flags=0}, 0) = 24
        [pid 111638] close(9)
    */
    /*
        XCB does not call the ioctl(5, DRM_IOCTL_PRIME_FD_TO_HANDLE, 0x7ffee2ec01fc)
    */
    bufs[buf_index].pixmap = xcb_generate_id(conn);
    xcb_void_cookie_t cookie = xcb_dri3_pixmap_from_buffer(conn, bufs[buf_index].pixmap, win,
                                    size_bytes, WIDTH, HEIGHT,
                                    stride, 24, 32, bufs[buf_index].bo_fd); 
                                    //Takes the ownership of the GPU buffer. and hands over pixmap as the identifier
    
    xcb_flush(conn);

    xcb_generic_error_t *err =
    xcb_request_check(conn, cookie);

    if (err) {
        fprintf(stderr,
            "DRI3 pixmap_from_buffer failed:"
            " error_code=%u, major=%u, minor=%u\n",
            err->error_code,
            err->major_code,
            err->minor_code);
        free(err);
        return -1;   // or handle the error however you need
    }

    fprintf(stderr, "PIXMAP: %d for index: %d\n", bufs[buf_index].pixmap, buf_index);
}

static create_xcb_fence(check* bufs, int buf_index){
    /*
        [pid 111638] memfd_create("xshmfence", MFD_CLOEXEC|MFD_ALLOW_SEALING) = 9
        [pid 111638] ftruncate(9, 4)            = 0
        [pid 111638] mmap(NULL, 4, PROT_READ|PROT_WRITE, MAP_SHARED, 9, 0) = 0x7a2aa2cbf000
        [pid 111638] poll([{fd=7, events=POLLIN|POLLOUT}], 1, -1) = 1 ([{fd=7, revents=POLLOUT}])
        [pid 111638] sendmsg(7, {msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\225\4\4\0\1\0\300\4\2\0\300\4\0\0\0\0", iov_len=16}], msg_iovlen=1, msg_control=[{cmsg_len=20, cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, cmsg_data=[9]}], msg_controllen=20, msg_flags=0}, 0) = 16
        [pid 111638] close(9)                   = 0
                            
    */
    /* Create an xshmfence and register it as an X sync fence for this pixmap */
    bufs[buf_index].shm_fence_fd = xshmfence_alloc_shm(); // ----- (1)
    if (bufs[buf_index].shm_fence_fd < 0) { perror("xshmfence_alloc_shm"); return 1; }
    bufs[buf_index].shm_fence = xshmfence_map_shm(bufs[buf_index].shm_fence_fd);
    if (!bufs[buf_index].shm_fence) { fprintf(stderr,"xshmfence_map_shm failed\n"); return 1; }
    xshmfence_reset(bufs[buf_index].shm_fence); // start unsignaled

    bufs[buf_index].sync_fence = xcb_generate_id(conn);

    xcb_void_cookie_t cookie = xcb_dri3_fence_from_fd_checked(conn, bufs[buf_index].pixmap, bufs[buf_index].sync_fence, 0, bufs[buf_index].shm_fence_fd);

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

    fprintf(stderr, "All done from XCB side for index: %d\n", buf_index);

}
void prefault_range(void *addr, size_t len)
{
    char *p = addr;

    for (size_t off = 0; off < len; off += 4096)
        *(volatile char *)(p + off) = 1;
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

extern void* mmap_listener(void* arg) {
    comm_page_t* c = (comm_page_t*)(uintptr_t)COMM_ADDR;
    while (c->magic != COMM_MAGIC) {
        usleep(1000);
    }
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
                case LOG_MMAP_EVENT:
                    break;
                case SETUP_DATA:
                    /*
                     * Initialize gem_slots
                     * We intialize all slots to available
                     * and corresponding correct addresses for host and guest
                     */
                    data_region_actual_address = (void*)((uint64_t)DATA_HOST_OFFSET + (uint64_t)global_ram_address);
                    for(int i = 0; i < NUMBER_OF_GEM_SLOTS; i++){
                        gem_slots.host_address[i] = (void*)((uint64_t)data_region_actual_address + ((uint64_t)ONE_MEGABYTE * i));
                        gem_slots.guest_address[i] = (void*)((uint64_t)DATA_REGION + ((uint64_t)ONE_MEGABYTE * i));
                        gem_slots.slot_occupied[i] = false;
                    }
                    c->req_bit = 0;
                    create_and_setup_xcb_window();
                    break;
                case GEM_ALLOCATION:
                    log_sg("mmap() is called");
                    // Find an empty gem_slot
                    int chosenIndex = -1;
                    pthread_mutex_lock(&gem_slots_lock);
                    for(int i = 0; i < NUMBER_OF_GEM_SLOTS; i++)
                    {
                        if(!gem_slots.slot_occupied[i]){
                            gem_slots.slot_occupied[i] = true;
                            chosenIndex = i;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&gem_slots_lock);
                    assert(chosenIndex != -1); // did we find a free slot?
                    assert(c->p2 <= ONE_MEGABYTE);
                    assert(munmap(gem_slots.host_address[chosenIndex], ONE_MEGABYTE) == 0);
                    assert(munmap(gem_slots.guest_address[chosenIndex], ONE_MEGABYTE) == 0);
                    // Mapping on original offset
                    void * ret = mmap(gem_slots.host_address[chosenIndex], c->p2, c->p3, c->p4 | MAP_SHARED | MAP_FIXED, c->p5, c->p6);
                    if(ret == MAP_FAILED){
                        perror("[QEMU] MMAP failed for GEM_ALLOCATION!!!!!");
                        assert(ret != MAP_FAILED);
                    }
                    assert(ret == gem_slots.host_address[chosenIndex]);

                    // prefault_range(gem_slots.host_address[chosenIndex], c->p2);
                    // sleep(5);
                    // Duplicate mapping for alignment
                    ret = mmap(gem_slots.guest_address[chosenIndex], c->p2, c->p3, c->p4 | MAP_SHARED | MAP_FIXED, c->p5, c->p6);
                    if(ret == MAP_FAILED){
                        perror("[QEMU] MMAP failed for GEM_ALLOCATION!!!!!");
                        assert(ret != MAP_FAILED);
                    }
                    assert(ret == gem_slots.guest_address[chosenIndex]);
                    // prefault_range(gem_slots.guest_address[chosenIndex], c->p2);
                    // Set address for guest
                    c->ret = (uint64_t)gem_slots.guest_address[chosenIndex];
                    c->req_bit = 0;
                    break;
                
                case FSTAT:
                    log_sg("fstat() is called");
                    ret = fstat(c->p1, c->p2);
                    c->ret = ret;
                    log_sg("fstat() returned: %d", ret);
                    c->req_bit = 0;
                    break; 
                case IOCTL:
                    log_sg("ioctl(%ld, %ld, 0x%lx) is called", c->p1, c->p2, c->p3);
                    ret = ioctl(c->p1, c->p2, c->p3);
                    c->ret = ret;
                    log_sg("ioctl() returned: %d", ret);

                    c->req_bit = 0;
                    break; 
                case OPEN:
                    log_sg("open() is called");
                    ret = open(c->p1, c->p2, c->p3);
                    c->ret = ret;
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
                    ret = readlink(c->p1, c->p2, c->p3);
                    c->ret = ret;
                    log_sg("readlink() returned: %d", ret);
                    c->req_bit = 0;
                    break;  
                case NEWFSTAT:
                    log_sg("newfstatat() is called");
                    ret = fstatat(c->p1, c->p2, c->p3, c->p4);
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
                    create_pixmap_from_kbuf(c->p1, c->p2, c->p3, c->p4);
                    create_xcb_fence(c->p1, c->p2);
                    log_sg("X11_SETUP() completed");
                    c->req_bit = 0;
                    // bufs_persistent = c->p1;
                    break;
                case X11_PRESENT:
                    check *tmp_buf = c->p1;
                    // fprintf(stderr, "[HOST PRESENT] cur=%d bo=%p fd=%d\n",
                    //     c->p2, tmp_buf[c->p2].bo, tmp_buf[c->p2].bo_fd);
                    log_sg("X11_PRESENT() is called %d\n", tmp_buf[c->p2].bo_fd);
                    // sleep(2000);
                    xcb_present_pixmap(conn, win, tmp_buf[c->p2].pixmap,
                            0,           // serial
                            XCB_NONE,    // valid
                            XCB_NONE,    // update
                            0, 0,        // x, y
                            XCB_NONE,    // target_crtc
                            tmp_buf[c->p2].sync_fence,  // wait_fence
                            c->p3,               // idle_fence
                            0,           // options
                            0, 0, 0,     // target_msc, divisor, remainder
                            0,           // notifies_len
                            NULL);       // notifies

                    xcb_flush(conn);
                    // fprintf(stderr, "fd %d first 32 bytes: \n", tmp_buf[c->p2].bo_fd);

                    // uint8_t *p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, 273, 0);
                    // if (p == MAP_FAILED) perror("mmap");
                    
                    // for (int i = 0; i < 128; i++)
                    //     printf("%02x ", p[i]);
                    // printf("\n");

                    // p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, 274, 0);
                    // if (p == MAP_FAILED) perror("mmap");
                    
                    // for (int i = 0; i < 128; i++)
                    //     printf("%02x ", p[i]);
                    // printf("\n");
                    // sleep(20000000);


                    c->req_bit = 0;
                    log_sg("X11_PRESENT() completed");
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
        
        }
    return NULL;
}
