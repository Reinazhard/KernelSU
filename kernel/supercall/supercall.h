#ifndef __KSU_H_SUPERCALL
#define __KSU_H_SUPERCALL

#include <linux/types.h>
#include <linux/uaccess.h>

// IOCTL handler types
typedef int (*ksu_ioctl_handler_t)(void __user *arg);
typedef bool (*ksu_perm_check_t)(void);

// IOCTL command mapping
struct ksu_ioctl_cmd_map {
    unsigned int cmd;
    const char *name;
    ksu_ioctl_handler_t handler;
    ksu_perm_check_t perm_check; // Permission check function
};

// Install KSU fd to current process
int ksu_install_fd(void);
// Handed to a process that has just exec'd into ksud; called from fs/exec.c.
int ksu_install_su_fd(void);

void ksu_supercalls_init(void);
void ksu_supercalls_exit(void);
int ksu_supercall_reboot_handler(void __user **arg);
#endif // __KSU_H_SUPERCALL
