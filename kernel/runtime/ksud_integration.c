#include "feature/selinux_hide.h"
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/current.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/input-event-codes.h>
#include <linux/input.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/workqueue.h>
#include <linux/uio.h>
#include <linux/stat.h>

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"
#include "selinux/selinux.h"

DEFINE_STATIC_KEY_TRUE(ksu_is_init_rc_hook_enabled);
DEFINE_STATIC_KEY_TRUE(is_init_second_stage_not_executed);
DEFINE_STATIC_KEY_TRUE(is_first_zygote);

// clang-format off
static const char KERNEL_SU_RC[] =
    "\n"
    "on post-fs-data\n"
    "    start logd\n"
    // We should wait for the post-fs-data finish
    "    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " post-fs-data\n"
    "\n"
    "on nonencrypted\n"
    "    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " services\n"
    "\n"
    "on property:vold.decrypt=trigger_restart_framework\n"
    "    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " services\n"
    "\n"
    "on property:sys.boot_completed=1\n"
    "    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " boot-completed\n"
    "\n"
    "\n";
// clang-format on

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
    const char __user *native;

#ifdef CONFIG_COMPAT
    if (unlikely(argv.is_compat)) {
        compat_uptr_t compat;

        if (get_user(compat, argv.ptr.compat + nr))
            return ERR_PTR(-EFAULT);

        return compat_ptr(compat);
    }
#endif

    if (get_user(native, argv.ptr.native + nr))
        return ERR_PTR(-EFAULT);

    return native;
}

/*
 * count() counts the number of strings in array ARGV.
 */

/*
 * Make sure old GCC compiler can use __maybe_unused,
 * Test passed in 4.4.x ~ 4.9.x when use GCC.
 */

static int __maybe_unused count(struct user_arg_ptr argv, int max)
{
    int i = 0;

    if (argv.ptr.native != NULL) {
        for (;;) {
            const char __user *p = get_user_arg_ptr(argv, i);

            if (!p)
                break;

            if (IS_ERR(p))
                return -EFAULT;

            if (i >= max)
                return -E2BIG;
            ++i;

            if (fatal_signal_pending(current))
                return -ERESTARTNOHAND;
        }
    }
    return i;
}

static bool check_argv(struct user_arg_ptr argv, int index, const char *expected, char *buf, size_t buf_len)
{
    const char __user *p;
    int argc;

    argc = count(argv, MAX_ARG_STRINGS);
    if (argc <= index)
        return false;

    p = get_user_arg_ptr(argv, index);
    if (!p || IS_ERR(p))
        goto fail;

    if (strncpy_from_user(buf, p, buf_len) <= 0)
        goto fail;

    buf[buf_len - 1] = '\0';
    return !strcmp(buf, expected);

fail:
    pr_err("check_argv failed\n");
    return false;
}

extern int ksu_handle_execveat_init(struct filename *filename, struct user_arg_ptr *argv_user,
                                    struct user_arg_ptr *envp_user);

// IMPORTANT NOTE: the call from execve_handler_pre WON'T provided correct value for envp and flags in GKI version
int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr, struct user_arg_ptr *argv,
                             struct user_arg_ptr *envp, int *flags)
{
    struct filename *filename;
    static const char app_process[] = "/system/bin/app_process";

    /* This applies to versions Android 10+ */
    static const char system_bin_init[] = "/system/bin/init";

    if (!filename_ptr)
        return 0;

    filename = *filename_ptr;
    if (IS_ERR(filename)) {
        return 0;
    }

    if (static_branch_unlikely(&is_init_second_stage_not_executed)) {
        // https://cs.android.com/android/platform/superproject/+/android-16.0.0_r2:system/core/init/main.cpp;l=77
        if (unlikely(!memcmp(filename->name, system_bin_init, sizeof(system_bin_init) - 1) && argv)) {
            char buf[16];
            if (check_argv(*argv, 1, "second_stage", buf, sizeof(buf))) {
                pr_info("/system/bin/init second_stage executed\n");
                ksu_selinux_hide_handle_second_stage();
                apply_kernelsu_rules();
                cache_sid();
                setup_ksu_cred();
                static_branch_disable(&is_init_second_stage_not_executed);
            }
        }
    }

    if (static_branch_unlikely(&is_first_zygote)) {
        if (unlikely(!memcmp(filename->name, app_process, sizeof(app_process) - 1) && argv)) {
            char buf[16];
            if (check_argv(*argv, 1, "-Xzygote", buf, sizeof(buf))) {
                pr_info("exec zygote, /data prepared, second_stage: %d\n",
                        !static_key_enabled(&is_init_second_stage_not_executed));
                on_post_fs_data();
                static_branch_disable(&is_first_zygote);
            }
        }
    }

    return 0;
}

static ssize_t (*orig_read)(struct file *, char __user *, size_t, loff_t *);
static ssize_t (*orig_read_iter)(struct kiocb *, struct iov_iter *);
static struct file_operations fops_proxy;
static ssize_t ksu_rc_pos = 0;
const size_t ksu_rc_len = sizeof(KERNEL_SU_RC) - 1;

// Prefer /metadata/watchdog/ when present, else /metadata.
#define MODULE_RC_PATH_WATCHDOG "/metadata/watchdog/ksu/modules.rc"
#define MODULE_RC_PATH_DEFAULT "/metadata/ksu/modules.rc"
static char *module_rc_buf;
static size_t module_rc_len;
static ssize_t module_rc_pos;

static struct file *open_module_rc(const char **chosen_path)
{
    struct file *f = filp_open(MODULE_RC_PATH_WATCHDOG, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        *chosen_path = MODULE_RC_PATH_WATCHDOG;
        return f;
    }
    f = filp_open(MODULE_RC_PATH_DEFAULT, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        *chosen_path = MODULE_RC_PATH_DEFAULT;
        return f;
    }
    *chosen_path = MODULE_RC_PATH_DEFAULT;
    return f;
}

static void load_module_rc_once(void)
{
    static bool loaded = false;
    struct file *f;
    const char *path = NULL;
    loff_t pos = 0;
    ssize_t r;
    size_t fsize;
    const struct cred *old_cred;

    if (loaded)
        return;
    loaded = true;
    if (ksu_no_custom_rc) {
        pr_info("custom rc is disabled\n");
        return;
    }

    old_cred = override_creds(ksu_cred);

    f = open_module_rc(&path);
    if (IS_ERR(f)) {
        pr_info("module rc: open %s failed: %ld\n", path, PTR_ERR(f));
        goto out_revert_creds;
    }

    if (!S_ISREG(file_inode(f)->i_mode)) {
        pr_warn("module rc: %s is not a regular file\n", path);
        goto out_close_file;
    }

    fsize = i_size_read(file_inode(f));
    if (fsize == 0) {
        pr_warn("module rc: skip empty module rc\n");
        goto out_close_file;
    }

    module_rc_buf = kvmalloc(fsize, GFP_KERNEL);
    if (!module_rc_buf) {
        pr_err("module rc: alloc %zu failed\n", fsize);
        goto out_close_file;
    }

    r = kernel_read(f, module_rc_buf, fsize, &pos);

    if (r <= 0) {
        pr_err("module rc: read failed: %zd\n", r);
        kvfree(module_rc_buf);
        module_rc_buf = NULL;
        goto out_close_file;
    }

    module_rc_len = r;
    pr_info("module rc: loaded %zu bytes from %s\n", module_rc_len, path);

out_close_file:
    filp_close(f, NULL);

out_revert_creds:
    revert_creds(old_cred);
}

static void free_module_rc(void)
{
    kvfree(module_rc_buf);
    module_rc_buf = NULL;
    module_rc_len = 0;
}

// https://cs.android.com/android/platform/superproject/main/+/main:system/core/init/parser.cpp;l=144;drc=61197364367c9e404c7da6900658f1b16c42d0da
// https://cs.android.com/android/platform/superproject/main/+/main:system/libbase/file.cpp;l=241-243;drc=61197364367c9e404c7da6900658f1b16c42d0da
// The system will read init.rc file until EOF, whenever read() returns 0,
// so we begin append ksu rc when we meet EOF.

static ssize_t read_proxy(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    ssize_t ret = 0;
    size_t append_count;
    if (ksu_rc_pos && ksu_rc_pos < ksu_rc_len)
        goto append_ksu_rc;
    if (ksu_rc_pos >= ksu_rc_len && module_rc_pos < module_rc_len)
        goto append_module_rc;

    ret = orig_read(file, buf, count, pos);
    if (ret != 0) {
        return ret;
    }
    if (ksu_rc_pos >= ksu_rc_len && module_rc_pos >= module_rc_len) {
        return ret;
    }
    pr_info("read_proxy: orig read finished, start append rc\n");

append_ksu_rc:
    if (ksu_rc_pos < ksu_rc_len) {
        append_count = ksu_rc_len - ksu_rc_pos;
        if (append_count > count - ret)
            append_count = count - ret;
        // copy_to_user returns the number of bytes that could not be copied
        if (copy_to_user(buf + ret, KERNEL_SU_RC + ksu_rc_pos, append_count)) {
            pr_info("read_proxy: append error, totally appended %ld\n", ksu_rc_pos);
            return ret;
        }
        pr_info("read_proxy: append static %zu\n", append_count);
        ksu_rc_pos += append_count;
        ret += append_count;
        if (ksu_rc_pos == ksu_rc_len)
            pr_info("read_proxy: static append done\n");
    }

append_module_rc:
    if (module_rc_pos < module_rc_len && (size_t)ret < count) {
        append_count = module_rc_len - module_rc_pos;
        if (append_count > count - ret)
            append_count = count - ret;
        if (copy_to_user(buf + ret, module_rc_buf + module_rc_pos, append_count)) {
            pr_info("read_proxy: module append error, totally appended %zd\n", module_rc_pos);
            return ret;
        }
        pr_info("read_proxy: append module %zu\n", append_count);
        module_rc_pos += append_count;
        ret += append_count;
        if (module_rc_pos == (ssize_t)module_rc_len) {
            pr_info("read_proxy: module append done\n");
            free_module_rc();
        }
    }

    return ret;
}

static ssize_t read_iter_proxy(struct kiocb *iocb, struct iov_iter *to)
{
    ssize_t ret = 0;
    size_t append_count;
    if (ksu_rc_pos && ksu_rc_pos < ksu_rc_len)
        goto append_ksu_rc;
    if (ksu_rc_pos >= ksu_rc_len && module_rc_pos < module_rc_len)
        goto append_module_rc;

    ret = orig_read_iter(iocb, to);
    if (ret != 0) {
        return ret;
    }
    if (ksu_rc_pos >= ksu_rc_len && module_rc_pos >= module_rc_len) {
        return ret;
    }
    pr_info("read_iter_proxy: orig read finished, start append rc\n");

append_ksu_rc:
    if (ksu_rc_pos < ksu_rc_len) {
        // copy_to_iter returns the number of bytes successfully copied
        append_count = copy_to_iter(KERNEL_SU_RC + ksu_rc_pos, ksu_rc_len - ksu_rc_pos, to);
        if (!append_count) {
            pr_info("read_iter_proxy: append error, totally appended %ld\n", ksu_rc_pos);
            return ret;
        }
        pr_info("read_iter_proxy: append static %zu\n", append_count);
        ksu_rc_pos += append_count;
        ret += append_count;
        if (ksu_rc_pos == ksu_rc_len) {
            pr_info("read_iter_proxy: static append done\n");
        }
    }

append_module_rc:
    if (module_rc_pos < module_rc_len) {
        append_count = copy_to_iter(module_rc_buf + module_rc_pos, module_rc_len - module_rc_pos, to);
        if (!append_count) {
            pr_info("read_iter_proxy: module append error, appended %zd\n", module_rc_pos);
            return ret;
        }
        pr_info("read_iter_proxy: append module %zu\n", append_count);
        module_rc_pos += append_count;
        ret += append_count;
        if (module_rc_pos == (ssize_t)module_rc_len) {
            pr_info("read_iter_proxy: module append done\n");
            free_module_rc();
        }
    }
    return ret;
}

static bool is_init_rc(struct file *fp)
{
    if (strcmp(current->comm, "init")) {
        // we are only interest in `init` process
        return false;
    }

    if (!d_is_reg(fp->f_path.dentry)) {
        return false;
    }

    const char *short_name = fp->f_path.dentry->d_name.name;
    if (strcmp(short_name, "init.rc")) {
        // we are only interest `init.rc` file name file
        return false;
    }
    char path[256];
    char *dpath = d_path(&fp->f_path, path, sizeof(path));

    if (IS_ERR(dpath)) {
        return false;
    }

    if (strcmp(dpath, "/system/etc/init/hw/init.rc")) {
        return false;
    }

    return true;
}

void ksu_install_rc_hook(struct file *file)
{
    if (!is_init_rc(file)) {
        return;
    }

    // we only process the first read
    static bool rc_hooked = false;
    if (rc_hooked) {
        // we don't need these hooks, unregister it!

        return;
    }
    rc_hooked = true;

    if (static_key_enabled(&ksu_is_init_rc_hook_enabled)) {
        static_branch_disable(&ksu_is_init_rc_hook_enabled);
        pr_info("ksu_init_rc_hook is disabled\n");
    }

    // now we can sure that the init process is reading
    // `/system/etc/init/init.rc`

    load_module_rc_once();
    pr_info("read init.rc, comm: %s, rc_count: %zu, module_rc: %zu\n", current->comm, ksu_rc_len, module_rc_len);

    // Now we need to proxy the read and modify the result!
    // But, we can not modify the file_operations directly, because it's in read-only memory.
    // We just replace the whole file_operations with a proxy one.
    memcpy(&fops_proxy, file->f_op, sizeof(struct file_operations));
    orig_read = file->f_op->read;
    if (orig_read) {
        fops_proxy.read = read_proxy;
    }
    orig_read_iter = file->f_op->read_iter;
    if (orig_read_iter) {
        fops_proxy.read_iter = read_iter_proxy;
    }
    // replace the file_operations
    file->f_op = &fops_proxy;
}

/*
 * init.rc injection, reached from the file_permission hook instead of sys_read.
 * The static key is switched off as soon as the first read is hooked, so this is
 * free for the rest of the boot.
 */
int ksu_file_permission(struct file *file, int mask)
{
    if (static_branch_unlikely(&ksu_is_init_rc_hook_enabled))
        ksu_install_rc_hook(file);

    return 0;
}

// ksud: safemode detection as a real input handler, replacing the input_event hook
static bool safe_mode_flag = false;
#define VOLUME_PRESS_THRESHOLD_COUNT 3

static void vol_detector_event(struct input_handle *handle, unsigned int type, unsigned int code, int value)
{
    static int vol_up_cnt = 0;
    static int vol_down_cnt = 0;

    if (!value)
        return;

    if (type != EV_KEY)
        return;

    if (code == KEY_VOLUMEDOWN) {
        vol_down_cnt++;
        pr_info("KEY_VOLUMEDOWN press detected!\n");
    }

    if (code == KEY_VOLUMEUP) {
        vol_up_cnt++;
        pr_info("KEY_VOLUMEUP press detected!\n");
    }

    pr_info("volume_pressed_count: vol_up: %d vol_down: %d\n", vol_up_cnt, vol_down_cnt);

    /*
     * Unregistering an input handler from inside the handler is not safe, and
     * deferring it to a kthread causes issues too. Unregistration happens anyway
     * from ksu_is_safe_mode() and on_post_fs_data(), so do not bother here.
     */
    if (vol_up_cnt >= VOLUME_PRESS_THRESHOLD_COUNT || vol_down_cnt >= VOLUME_PRESS_THRESHOLD_COUNT) {
        pr_info("volume keys pressed max times, safe mode detected!\n");
        safe_mode_flag = true;
    }
}

static int vol_detector_connect(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id)
{
    struct input_handle *handle;
    int error;

    handle = kzalloc(sizeof(struct input_handle), GFP_KERNEL);
    if (!handle)
        return -ENOMEM;

    handle->dev = dev;
    handle->handler = handler;
    handle->name = "ksu_handle_input";

    error = input_register_handle(handle);
    if (error)
        goto err_free_handle;

    error = input_open_device(handle);
    if (error)
        goto err_unregister_handle;

    return 0;

err_unregister_handle:
    input_unregister_handle(handle);
err_free_handle:
    kfree(handle);
    return error;
}

static void vol_detector_disconnect(struct input_handle *handle)
{
    input_close_device(handle);
    input_unregister_handle(handle);
    kfree(handle);
}

static const struct input_device_id vol_detector_ids[] = {
    // volume up is matched too so a broken volume down key can still reach safemode,
    // and so ksu safemode can be tripped without tripping android's own safemode.
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT | INPUT_DEVICE_ID_MATCH_KEYBIT,
        .evbit = { BIT_MASK(EV_KEY) },
        .keybit = { [BIT_WORD(KEY_VOLUMEUP)] = BIT_MASK(KEY_VOLUMEUP) },
    },
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT | INPUT_DEVICE_ID_MATCH_KEYBIT,
        .evbit = { BIT_MASK(EV_KEY) },
        .keybit = { [BIT_WORD(KEY_VOLUMEDOWN)] = BIT_MASK(KEY_VOLUMEDOWN) },
    },
    {}
};

static struct input_handler vol_detector_handler = {
    .event = vol_detector_event,
    .connect = vol_detector_connect,
    .disconnect = vol_detector_disconnect,
    .name = "ksu",
    .id_table = vol_detector_ids,
};

static bool vol_detector_registered = false;

void ksu_stop_input_hook(void)
{
    if (!vol_detector_registered)
        return;

    vol_detector_registered = false;
    input_unregister_handler(&vol_detector_handler);
    pr_info("ksu_input_hook is disabled\n");
}

bool ksu_is_safe_mode()
{
    // don't need to check again, userspace may call multiple times
    static bool already_checked = false;

    if (already_checked)
        return true;

    // stop hook first!
    ksu_stop_input_hook();

    if (!safe_mode_flag)
        return false;

    already_checked = true;
    return true;
}

/*
 * Android 16 (Canary 2601+) reads init.rc with libbase ReadFdToString, which trusts
 * st_size from fstat. Without inflating it init never reads the injected rc.
 * Hooked at sys_newfstat return, so no other vfs_fstat caller is affected.
 */
void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr)
{
    void __user *st_size_ptr;
    struct file *file;
    bool is_rc = false;
    long size, new_size;

    if (unlikely(!fd || !statbuf_ptr || !*statbuf_ptr))
        return;

    if (likely(!static_branch_unlikely(&ksu_is_init_rc_hook_enabled)))
        return;

    file = fget(*fd);
    if (file) {
        if (is_init_rc(file)) {
            pr_info("stat init.rc");
            is_rc = true;
            load_module_rc_once();
        }
        fput(file);
    }

    if (!is_rc)
        return;

    st_size_ptr = (void __user *)*statbuf_ptr + offsetof(struct stat, st_size);
    if (copy_from_user_nofault(&size, st_size_ptr, sizeof(size))) {
        pr_err("newfstat: read st_size failed\n");
        return;
    }

    new_size = size + ksu_rc_len + module_rc_len;
    pr_info("adding rc len: %ld -> %ld (static=%zu module=%zu)\n", size, new_size, ksu_rc_len, module_rc_len);

    if (copy_to_user_nofault(st_size_ptr, &new_size, sizeof(new_size)))
        pr_err("newfstat: adding rc len failed\n");
}

// ksud: module support
void __init ksu_ksud_init()
{
    if (input_register_handler(&vol_detector_handler)) {
        pr_err("vol_detector: failed to register input handler\n");
        return;
    }

    vol_detector_registered = true;
}

void __exit ksu_ksud_exit()
{
    ksu_stop_input_hook();
    if (module_rc_buf) {
        free_module_rc();
    }
}
