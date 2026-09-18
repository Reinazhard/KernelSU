#ifndef __KSU_H_KSUD
#define __KSU_H_KSUD

#include <asm/syscall.h>

#define KSUD_PATH "/data/adb/ksud"

void ksu_ksud_init();
void ksu_ksud_exit();

#define MAX_ARG_STRINGS 0x7FFFFFFF
struct user_arg_ptr {
#ifdef CONFIG_COMPAT
    bool is_compat;
#endif
    union {
        const char __user *const __user *native;
#ifdef CONFIG_COMPAT
        const compat_uptr_t __user *compat;
#endif
    } ptr;
};

int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr, struct user_arg_ptr *argv,
                             struct user_arg_ptr *envp, int *flags);

void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);

void ksu_install_rc_hook(struct file *file);
int ksu_file_permission(struct file *file, int mask);
void ksu_stop_input_hook(void);
#endif
