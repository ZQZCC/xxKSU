// SPDX-License-Identifier: GPL-2.0
/*
 * Process-bound, one-shot root capability FD.
 *
 * The issuer receives this FD and transfers it to the bound process with
 * SCM_RIGHTS. All duplicated descriptors share the same consumed state.
 */

struct ksu_root_capfd {
	struct pid *target_tgid;
	struct mm_struct *target_mm;
	kuid_t target_uid;
	kuid_t target_euid;
	u64 target_start_boottime;
	struct root_profile profile;
	atomic_t consumed;
};

static bool ksu_capfd_target_uid_allowed(uid_t uid)
{
#ifdef CONFIG_KSU_SHELL_HAS_SU_ALWAYS
	if (uid == SHELL_UID)
		return true;
#endif
	return __ksu_is_allow_uid(uid);
}

static void ksu_root_capfd_free(struct ksu_root_capfd *cap)
{
	if (!cap)
		return;
	if (cap->target_mm)
		mmput(cap->target_mm);
	if (cap->target_tgid)
		put_pid(cap->target_tgid);
	kfree(cap);
}

static int ksu_root_capfd_release(struct inode *inode, struct file *file)
{
	struct ksu_root_capfd *cap = file->private_data;

	if (!cap)
		return 0;

	ksu_root_capfd_free(cap);
	return 0;
}

static long ksu_root_capfd_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	struct ksu_root_capfd *cap = file->private_data;
	(void)arg;

	if (cmd != KSU_CAPFD_IOCTL_ENTER_ROOT)
		return -ENOTTY;
	if (!cap)
		return -EBADF;
	if (task_tgid(current) != cap->target_tgid ||
	    current->mm != cap->target_mm ||
	    READ_ONCE(current->group_leader->start_boottime) !=
		    cap->target_start_boottime ||
	    !uid_eq(current_uid(), cap->target_uid) ||
	    !uid_eq(current_euid(), cap->target_euid))
		return -EPERM;
	if (atomic_cmpxchg(&cap->consumed, 0, 1) != 0)
		return -EALREADY;

	return escape_with_root_profile_snapshot(&cap->profile);
}

static const struct file_operations ksu_root_capfd_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ksu_root_capfd_ioctl,
	.compat_ioctl = ksu_root_capfd_ioctl,
	.release = ksu_root_capfd_release,
	.llseek = noop_llseek,
};

int ksu_create_root_capfd(void __user *arg)
{
	struct ksu_create_root_capfd_cmd cmd;
	struct ksu_root_capfd *cap = NULL;
	const struct cred *target_cred;
	struct root_profile *profile;
	struct task_struct *target;
	struct file *file;
	unsigned int pidfd_flags;
	uid_t target_uid;
	int fd;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.flags)
		return -EINVAL;

	target = pidfd_get_task(cmd.target_pidfd, &pidfd_flags);
	if (IS_ERR(target))
		return PTR_ERR(target);
	if (!pid_alive(target)) {
		fd = -ESRCH;
		goto out_task;
	}

	target_cred = get_task_cred(target);
	target_uid = __kuid_val(target_cred->uid);
	if (target_uid == 0 ||
	    uid_eq(target_cred->euid, GLOBAL_ROOT_UID) ||
	    !ksu_capfd_target_uid_allowed(target_uid)) {
		fd = -EPERM;
		goto out_cred;
	}

	cap = kzalloc(sizeof(*cap), GFP_KERNEL);
	if (!cap) {
		fd = -ENOMEM;
		goto out_cred;
	}

	cap->target_tgid = get_task_pid(target, PIDTYPE_TGID);
	cap->target_mm = get_task_mm(target);
	if (!cap->target_tgid || !cap->target_mm) {
		fd = -ESRCH;
		goto out_cap;
	}

	cap->target_uid = target_cred->uid;
	cap->target_euid = target_cred->euid;
	cap->target_start_boottime = READ_ONCE(target->start_boottime);
	profile = ksu_get_root_profile(target_uid);
	cap->profile = *profile;
	ksu_put_root_profile(profile);
	atomic_set(&cap->consumed, 0);
	put_cred(target_cred);
	put_task_struct(target);

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		goto out_cap_ready;

	file = anon_inode_getfile("[ksu_capfd]", &ksu_root_capfd_fops, cap,
				  O_RDWR | O_CLOEXEC);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		fd = PTR_ERR(file);
		goto out_cap_ready;
	}

	fd_install(fd, file);
	return fd;

out_cred:
	put_cred(target_cred);
out_task:
	put_task_struct(target);
	return fd;

out_cap:
	ksu_root_capfd_free(cap);
	goto out_cred;

out_cap_ready:
	ksu_root_capfd_free(cap);
	return fd;
}
