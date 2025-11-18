/*
 * Support for RAM backed by mmaped host memory.
 *
 * Copyright (c) 2015 Red Hat, Inc.
 *
 * Authors:
 *  Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#ifdef CONFIG_LINUX
#include <linux/mman.h>
#else  /* !CONFIG_LINUX */
#define MAP_SYNC              0x0
#define MAP_SHARED_VALIDATE   0x0
#endif /* CONFIG_LINUX */

#include "qemu/osdep.h"
#include "qemu/mmap-alloc.h"
#include "qemu/host-utils.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"

#define HUGETLBFS_MAGIC       0x958458f6

#ifdef CONFIG_LINUX
#include <sys/vfs.h>
#include <linux/magic.h>
#endif

static const size_t LOW_OFFSET_INTO_MEMORY = 0x100000ULL;           // 1MB
static const void *VIRTUAL_ADDRESS_LOW = (void*)0x100000ULL;        // 1MB
static const size_t HIGH_OFFSET_INTO_MEMORY = 0x80000000ULL;        // 2GB
static const void *VIRTUAL_ADDRESS_HIGH = (void*)0x100000000ULL;    // 4GB
void* global_ram_address = NULL;

/*
 * Giovanni - mmap listener code
 */
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

void* data_region_actual_address = NULL;

// Must be set when gpu fd is given
int drm_file_descriptor = -1;

typedef struct {
    volatile uint64_t magic;
    volatile uint32_t req;
    volatile uint32_t resp;
    volatile uint64_t evt;
    volatile uint64_t addr;
    volatile uint64_t length;
    volatile uint32_t prot;
    volatile uint32_t flags;
    volatile int32_t  fd;
    volatile uint32_t _pad;
    volatile uint64_t offset;
    volatile int64_t  ret;
} comm_page_t;

#define NUMBER_OF_GEM_SLOTS 512
typedef struct {
    void* host_address[NUMBER_OF_GEM_SLOTS];
    void* guest_address[NUMBER_OF_GEM_SLOTS];
    bool slot_occupied[NUMBER_OF_GEM_SLOTS];
} gem_slots_t;

// events
const uint64_t LOG_MMAP_EVENT = 1;
const uint64_t SETUP_DATA = 0x2ULL;
const uint64_t GEM_ALLOCATION = 3;

// Sizes
const size_t ONE_MEGABYTE = 1024*1024;
const size_t DATA_SIZE = ONE_MEGABYTE*512; // 512MB
const size_t PAGE_SIZE    = 4096;

#define COMM_ADDR  0xf00000ULL
#define COMM_MAGIC 0x1234567812345678ULL

static void* DATA_REGION = (void*)0x100008000ULL;
// This is different than where it appears in the guest.
// Qemu maps the ram region from 0x80000000 into the allocation to 0x100000000 in the guest AS
static void* DATA_HOST_OFFSET = (void*)0x80008000ULL;

// static void* UNMAP_DATA_MSG = (void*)0x1234567f1234567fULL;
static pthread_t mmap_listen_thr;
static int mmap_listen_thr_started = 0;

// Data structure for keeping track of free slots
gem_slots_t gem_slots = {0};

static void* mmap_listener(void* arg) {
    comm_page_t* c = (comm_page_t*)(uintptr_t)COMM_ADDR;

    // Spin until comms region is set by game
    while (c->magic != COMM_MAGIC) {
        usleep(1000);
    }
    fprintf(stderr, "[QEMU] comm ready at 0x%llx\n",
            (unsigned long long)(uint64_t)(uintptr_t)c);

    /*
     * Event Processing loop
     * Giovanni - keep in mind if something fails in this, it needs to loudly fail, make sure to use asserts
     */
    for (;;) {
        if (c->req) {
            uint64_t evt = c->evt;
            uint64_t a   = c->addr;
            uint64_t len = c->length;
            int fd       = (int)c->fd;
            uint32_t fl  = c->flags;
            uint32_t pr  = c->prot;
            long long rc = (long long)c->ret;

            switch (evt) {
                case LOG_MMAP_EVENT:
                    fprintf(stderr,
                            "[QEMU] mmap evt=%llu addr=0x%llx len=0x%llx fd=%d flags=0x%x prot=0x%x ret=%lld\n",
                            (unsigned long long)evt,
                            (unsigned long long)a,
                            (unsigned long long)len,
                            fd, fl, pr, rc);
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
                    break;
                case GEM_ALLOCATION:
                    // Find an empty gem_slot
                    int chosenIndex = -1;
                    for(int i = 0; i < NUMBER_OF_GEM_SLOTS; i++)
                    {
                        if(!gem_slots.slot_occupied[i]){
                            gem_slots.slot_occupied[i] = true;
                            chosenIndex = i;
                            break;
                        }
                    }
                    assert(chosenIndex != -1); // did we find a free slot?

                    int dummyFd = memfd_create("dummy_file_for_alignment", MFD_CLOEXEC);
                    if (dummyFd < 0) {
                        perror("memfd_create failed in listener!");
                        assert(!(dummyFd < 0));
                    }
                    if (ftruncate(dummyFd, ONE_MEGABYTE) != 0) {
                        perror("ftruncate failed in listener!");
                    }

                    // ensure no MAP_ANONYMOUS
                    if(fl & MAP_ANONYMOUS){
                        fl = fl ^ MAP_ANONYMOUS;
                    }

                    // Unmap the slot first
                    assert(munmap(gem_slots.host_address[chosenIndex], ONE_MEGABYTE) == 0);
                    assert(munmap(gem_slots.guest_address[chosenIndex], ONE_MEGABYTE) == 0);
                    // Mapping on original offset
                    void * ret = mmap(gem_slots.host_address[chosenIndex], ONE_MEGABYTE, pr, fl | MAP_SHARED | MAP_FIXED, dummyFd, 0);
                    if(ret == MAP_FAILED){
                        perror("[QEMU] MMAP failed for GEM_ALLOCATION!!!!!");
                        assert(ret != MAP_FAILED);
                    }
                    assert(ret == gem_slots.host_address[chosenIndex]);

                    // Duplicate mapping for alignment
                    ret = mmap(gem_slots.guest_address[chosenIndex], ONE_MEGABYTE, pr, fl | MAP_SHARED | MAP_FIXED, dummyFd, 0);
                    if(ret == MAP_FAILED){
                        perror("[QEMU] MMAP failed for GEM_ALLOCATION!!!!!");
                        assert(ret != MAP_FAILED);
                    }
                    assert(ret == gem_slots.guest_address[chosenIndex]);
                    // Set address for guest
                    c->addr = (uint64_t)gem_slots.guest_address[chosenIndex];
                    char temp[256] = "";

                    char numbuf[32] = {0};
                    snprintf(numbuf, sizeof(numbuf), "%d", chosenIndex);
                    strcat(temp, numbuf);
                    strcat(temp, "hello guest");
                    strcpy((char *)gem_slots.guest_address[chosenIndex], temp);
                    // Ensure both addresses point to the same thing
                    assert(!strcmp((char *)gem_slots.guest_address[chosenIndex], (char *)gem_slots.host_address[chosenIndex]));
                    // printf("set string {%s}\n", (char *)gem_slots.guest_address[chosenIndex]);
                    // printf("test string {%s}\n", (char *)gem_slots.host_address[chosenIndex]);
                    break;
                default:
                    fprintf(stderr, "[QEMU] No such event:%llu", (unsigned long long)evt);
                    break;
            }

            c->resp = 0;
            c->req  = 0;
        } else { // if !req
            // Do nothing
        }
    }
    return NULL;
}

/*
 * ----------------------------------------------------------------------------------------------------------
 * ----------------------------------------------------------------------------------------------------------
 */


QemuFsType qemu_fd_getfs(int fd)
{
#ifdef CONFIG_LINUX
    struct statfs fs;
    int ret;

    if (fd < 0) {
        return QEMU_FS_TYPE_UNKNOWN;
    }

    do {
        ret = fstatfs(fd, &fs);
    } while (ret != 0 && errno == EINTR);

    switch (fs.f_type) {
    case TMPFS_MAGIC:
        return QEMU_FS_TYPE_TMPFS;
    case HUGETLBFS_MAGIC:
        return QEMU_FS_TYPE_HUGETLBFS;
    default:
        return QEMU_FS_TYPE_UNKNOWN;
    }
#else
    return QEMU_FS_TYPE_UNKNOWN;
#endif
}

size_t qemu_fd_getpagesize(int fd)
{
#ifdef CONFIG_LINUX
    struct statfs fs;
    int ret;

    if (fd != -1) {
        do {
            ret = fstatfs(fd, &fs);
        } while (ret != 0 && errno == EINTR);

        if (ret == 0 && fs.f_type == HUGETLBFS_MAGIC) {
            return fs.f_bsize;
        }
    }
#ifdef __sparc__
    /* SPARC Linux needs greater alignment than the pagesize */
    return QEMU_VMALLOC_ALIGN;
#endif
#endif

    return qemu_real_host_page_size();
}

#define OVERCOMMIT_MEMORY_PATH "/proc/sys/vm/overcommit_memory"
static bool map_noreserve_effective(int fd, uint32_t qemu_map_flags)
{
#if defined(__linux__)
    const bool readonly = qemu_map_flags & QEMU_MAP_READONLY;
    const bool shared = qemu_map_flags & QEMU_MAP_SHARED;
    gchar *content = NULL;
    const char *endptr;
    unsigned int tmp;

    /*
     * hugeltb accounting is different than ordinary swap reservation:
     * a) Hugetlb pages from the pool are reserved for both private and
     *    shared mappings. For shared mappings, all mappers have to specify
     *    MAP_NORESERVE.
     * b) MAP_NORESERVE is not affected by /proc/sys/vm/overcommit_memory.
     */
    if (qemu_fd_getpagesize(fd) != qemu_real_host_page_size()) {
        return true;
    }

    /*
     * Accountable mappings in the kernel that can be affected by MAP_NORESEVE
     * are private writable mappings (see mm/mmap.c:accountable_mapping() in
     * Linux). For all shared or readonly mappings, MAP_NORESERVE is always
     * implicitly active -- no reservation; this includes shmem. The only
     * exception is shared anonymous memory, it is accounted like private
     * anonymous memory.
     */
    if (readonly || (shared && fd >= 0)) {
        return true;
    }

    /*
     * MAP_NORESERVE is globally ignored for applicable !hugetlb mappings when
     * memory overcommit is set to "never". Sparse memory regions aren't really
     * possible in this system configuration.
     *
     * Bail out now instead of silently committing way more memory than
     * currently desired by the user.
     */
    if (g_file_get_contents(OVERCOMMIT_MEMORY_PATH, &content, NULL, NULL) &&
        !qemu_strtoui(content, &endptr, 0, &tmp) &&
        (!endptr || *endptr == '\n')) {
        if (tmp == 2) {
            error_report("Skipping reservation of swap space is not supported:"
                         " \"" OVERCOMMIT_MEMORY_PATH "\" is \"2\"");
            return false;
        }
        return true;
    }
    /* this interface has been around since Linux 2.6 */
    error_report("Skipping reservation of swap space is not supported:"
                 " Could not read: \"" OVERCOMMIT_MEMORY_PATH "\"");
    return false;
#endif
    /*
     * E.g., FreeBSD used to define MAP_NORESERVE, never implemented it,
     * and removed it a while ago.
     */
    error_report("Skipping reservation of swap space is not supported");
    return false;
}

/*
 * Reserve a new memory region of the requested size to be used for mapping
 * from the given fd (if any).
 */
static void *mmap_reserve(size_t size, int fd)
{
    int flags = MAP_PRIVATE;

#if defined(__powerpc64__) && defined(__linux__)
    /*
     * On ppc64 mappings in the same segment (aka slice) must share the same
     * page size. Since we will be re-allocating part of this segment
     * from the supplied fd, we should make sure to use the same page size, to
     * this end we mmap the supplied fd.  In this case, set MAP_NORESERVE to
     * avoid allocating backing store memory.
     * We do this unless we are using the system page size, in which case
     * anonymous memory is OK.
     */
    if (fd == -1 || qemu_fd_getpagesize(fd) == qemu_real_host_page_size()) {
        fd = -1;
        flags |= MAP_ANONYMOUS;
    } else {
        flags |= MAP_NORESERVE;
    }
#else
    fd = -1;
    flags |= MAP_ANONYMOUS;
#endif

    return mmap(0, size, PROT_NONE, flags, fd, 0);
}

/*
 * Activate memory in a reserved region from the given fd (if any), to make
 * it accessible.
 */
static void *mmap_activate(void *ptr, size_t size, int fd,
                           uint32_t qemu_map_flags, off_t map_offset)
{
    const bool noreserve = qemu_map_flags & QEMU_MAP_NORESERVE;
    const bool readonly = qemu_map_flags & QEMU_MAP_READONLY;
    const bool shared = qemu_map_flags & QEMU_MAP_SHARED;
    const bool sync = qemu_map_flags & QEMU_MAP_SYNC;
    const int prot = PROT_READ | (readonly ? 0 : PROT_WRITE);
    int map_sync_flags = 0;
    int flags = MAP_FIXED;
    void *activated_ptr;

    if (noreserve && !map_noreserve_effective(fd, qemu_map_flags)) {
        return MAP_FAILED;
    }

    flags |= fd == -1 ? MAP_ANONYMOUS : 0;
    flags |= shared ? MAP_SHARED : MAP_PRIVATE;
    flags |= noreserve ? MAP_NORESERVE : 0;
    if (shared && sync) {
        map_sync_flags = MAP_SYNC | MAP_SHARED_VALIDATE;
    }

    activated_ptr = mmap(ptr, size, prot, flags | map_sync_flags, fd,
                         map_offset);
    if (activated_ptr == MAP_FAILED && map_sync_flags) {
        if (errno == ENOTSUP) {
            char *proc_link = g_strdup_printf("/proc/self/fd/%d", fd);
            char *file_name = g_malloc0(PATH_MAX);
            int len = readlink(proc_link, file_name, PATH_MAX - 1);

            if (len < 0) {
                len = 0;
            }
            file_name[len] = '\0';
            fprintf(stderr, "Warning: requesting persistence across crashes "
                    "for backend file %s failed. Proceeding without "
                    "persistence, data might become corrupted in case of host "
                    "crash.\n", file_name);
            g_free(proc_link);
            g_free(file_name);
            warn_report("Using non DAX backing file with 'pmem=on' option"
                        " is deprecated");
        }
        /*
         * If mmap failed with MAP_SHARED_VALIDATE | MAP_SYNC, we will try
         * again without these flags to handle backwards compatibility.
         */
        activated_ptr = mmap(ptr, size, prot, flags, fd, map_offset);
    }

    // Heuristic, we allocate at least 4GB, and assume no other allocation will top this
    if(size >= 0x100000000){
        // printf("SIZE WE NEED = 0x%lx __ OFFSET = 0x%lx\n", size, map_offset);
        if(qemu_map_flags & QEMU_MAP_SHARED){
            // Shadow mapping of LOW RAM from file[0x100000 -> HIGH_OFFSET - LOW_OFFSET]
            if(size > LOW_OFFSET_INTO_MEMORY && map_offset == 0){
                size_t length = HIGH_OFFSET_INTO_MEMORY - LOW_OFFSET_INTO_MEMORY;
                off_t offset = map_offset + (off_t)LOW_OFFSET_INTO_MEMORY;
                void *want = (void *)VIRTUAL_ADDRESS_LOW;

                void *lowShadow = mmap(want, length, prot, (MAP_SHARED | MAP_FIXED), fd, offset);
                if (lowShadow == MAP_FAILED){
                    perror("WARNING 1:1 MAPPINGS NOT PRESENT -- mmap LOW FAILED!\n");
                }
            }

            // Shadow mapping of HIGH RAM from file[0x80000000 -> size - HIGH_OFFSET]
            if(size > HIGH_OFFSET_INTO_MEMORY && map_offset == 0){
                size_t length = size - HIGH_OFFSET_INTO_MEMORY;
                off_t offset = map_offset + (off_t)HIGH_OFFSET_INTO_MEMORY;
                void *want = (void *)VIRTUAL_ADDRESS_HIGH;

                void *highShadow = mmap(want, length, prot, (MAP_SHARED | MAP_FIXED), fd, offset);
                if(highShadow == MAP_FAILED){
                    perror("WARNING 1:1 MAPPINGS NOT PRESENT -- mmap HIGH FAILED!\n");
                }
            }
        }

        // After ram is mapped, spawn listener thread
        if (!mmap_listen_thr_started) {
            mmap_listen_thr_started = 1;
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            pthread_create(&mmap_listen_thr, &attr, mmap_listener, NULL);
            pthread_attr_destroy(&attr);
        }
        global_ram_address = activated_ptr;
    }else {
    // printf("SIZE WE DONT WANT -->>= %lx __ OFFSET = 0x%lx\n", size, map_offset);
    }

    return activated_ptr;
}

static inline size_t mmap_guard_pagesize(int fd)
{
#if defined(__powerpc64__) && defined(__linux__)
    /* Mappings in the same segment must share the same page size */
    return qemu_fd_getpagesize(fd);
#else
    return qemu_real_host_page_size();
#endif
}

void *qemu_ram_mmap(int fd,
                    size_t size,
                    size_t align,
                    uint32_t qemu_map_flags,
                    off_t map_offset)
{
    const size_t guard_pagesize = mmap_guard_pagesize(fd);
    size_t offset, total;
    void *ptr, *guardptr;

    /*
     * Note: this always allocates at least one extra page of virtual address
     * space, even if size is already aligned.
     */
    total = size + align;

    guardptr = mmap_reserve(total, fd);
    if (guardptr == MAP_FAILED) {
        return MAP_FAILED;
    }

    assert(is_power_of_2(align));
    /* Always align to host page size */
    assert(align >= guard_pagesize);

    offset = QEMU_ALIGN_UP((uintptr_t)guardptr, align) - (uintptr_t)guardptr;

    ptr = mmap_activate(guardptr + offset, size, fd, qemu_map_flags,
                        map_offset);
    if (ptr == MAP_FAILED) {
        munmap(guardptr, total);
        return MAP_FAILED;
    }

    if (offset > 0) {
        munmap(guardptr, offset);
    }

    /*
     * Leave a single PROT_NONE page allocated after the RAM block, to serve as
     * a guard page guarding against potential buffer overflows.
     */
    total -= offset;
    if (total > size + guard_pagesize) {
        munmap(ptr + size + guard_pagesize, total - size - guard_pagesize);
    }

    return ptr;
}

void qemu_ram_munmap(int fd, void *ptr, size_t size)
{
    if (ptr) {
        /* Unmap both the RAM block and the guard page */
        munmap(ptr, size + mmap_guard_pagesize(fd));
    }
}
