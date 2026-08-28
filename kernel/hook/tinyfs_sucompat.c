// SPDX-License-Identifier: GPL-2.0
/*
 * Fixed-kernel TinyFS sucompat prototype.
 *
 * The synthetic file only exposes a userspace launcher. Root is granted by
 * the normal KSU control fd after the launcher starts, never from a VFS read.
 */
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/namei.h>
#include <linux/pagemap.h>

#include "tinysu_arm64.h"

static struct inode *ksu_tinyfs_bin_inode;
static struct inode *ksu_tinyfs_su_inode;
static const struct inode_operations *ksu_tinyfs_orig_bin_iops;
static struct inode_operations ksu_tinyfs_bin_iops;
static bool ksu_tinyfs_ready;

bool ksu_tinyfs_sucompat_ready(void)
{
	return smp_load_acquire(&ksu_tinyfs_ready);
}

static __always_inline bool ksu_tinyfs_su_visible(void)
{
	if (!READ_ONCE(ksu_su_compat_enabled))
		return false;

	return ksu_sucompat_current_allowed();
}

static int ksu_tinyfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	bool visible;
	bool positive;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	visible = ksu_tinyfs_su_visible();
	positive = d_inode(dentry) == ksu_tinyfs_su_inode;
	return visible == positive;
}

static struct dentry_operations ksu_tinyfs_dops;

static void ksu_tinyfs_prepare_dentry(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	dentry->d_op = &ksu_tinyfs_dops;
	dentry->d_flags |= DCACHE_OP_REVALIDATE;
	spin_unlock(&dentry->d_lock);
}

static struct dentry *ksu_tinyfs_lookup(struct inode *dir,
					       struct dentry *dentry,
					       unsigned int flags)
{
	if (dentry->d_name.len != 2 ||
	    memcmp(dentry->d_name.name, "su", 2) != 0)
		return ksu_tinyfs_orig_bin_iops->lookup(dir, dentry, flags);

	ksu_tinyfs_prepare_dentry(dentry);
	if (!ksu_tinyfs_su_visible()) {
		d_add(dentry, NULL);
		return NULL;
	}

	d_add(dentry, igrab(ksu_tinyfs_su_inode));
	return NULL;
}

static int ksu_tinyfs_read_folio(struct file *file, struct folio *folio)
{
	void *page_addr = kmap_local_folio(folio, 0);
	loff_t offset = folio_pos(folio);
	size_t size = folio_size(folio);
	size_t count = 0;

	folio_zero_range(folio, 0, size);
	if (offset < sizeof(ksu_tinysu_arm64)) {
		count = min_t(size_t, sizeof(ksu_tinysu_arm64) - offset, size);
		memcpy(page_addr, ksu_tinysu_arm64 + offset, count);
	}

	kunmap_local(page_addr);
	flush_dcache_folio(folio);
	folio_mark_uptodate(folio);
	folio_unlock(folio);
	return 0;
}

static const struct address_space_operations ksu_tinyfs_aops = {
	.read_folio = ksu_tinyfs_read_folio,
};

static ssize_t ksu_tinyfs_read(struct file *file, char __user *buffer,
			       size_t length, loff_t *offset)
{
	return simple_read_from_buffer(buffer, length, offset,
				       ksu_tinysu_arm64,
				       sizeof(ksu_tinysu_arm64));
}

static const struct file_operations ksu_tinyfs_fops = {
	.read = ksu_tinyfs_read,
	.llseek = generic_file_llseek,
	.mmap = generic_file_readonly_mmap,
};

void ksu_tinyfs_sucompat_init(void)
{
	struct inode_security_struct *security;
	struct dentry *cached_su;
	struct path bin_path;
	struct path ksud_path;
	struct path su_path;
	struct qstr su_name = QSTR_INIT("su", 2);
	int err;

	if (ksu_tinyfs_sucompat_ready())
		return;

	if (kern_path(KSUD_PATH, LOOKUP_FOLLOW, &ksud_path)) {
		pr_err("tinyfs: %s is unavailable\n", KSUD_PATH);
		return;
	}
	if (!S_ISREG(d_inode(ksud_path.dentry)->i_mode)) {
		pr_err("tinyfs: %s is not a regular file\n", KSUD_PATH);
		path_put(&ksud_path);
		return;
	}
	path_put(&ksud_path);

	if (kern_path("/system/bin", LOOKUP_FOLLOW, &bin_path)) {
		pr_err("tinyfs: /system/bin is unavailable\n");
		return;
	}

	ksu_tinyfs_bin_inode = d_inode(bin_path.dentry);
	ksu_tinyfs_orig_bin_iops = READ_ONCE(ksu_tinyfs_bin_inode->i_op);
	if (!ksu_tinyfs_orig_bin_iops || !ksu_tinyfs_orig_bin_iops->lookup) {
		pr_err("tinyfs: /system/bin has no lookup operation\n");
		goto out_path;
	}
	if (ksu_tinyfs_bin_inode->i_sb->s_d_op &&
	    ksu_tinyfs_bin_inode->i_sb->s_d_op->d_revalidate) {
		pr_err("tinyfs: existing d_revalidate is unsupported\n");
		goto out_path;
	}

	err = kern_path("/system/bin/su", 0, &su_path);
	if (!err) {
		path_put(&su_path);
		pr_err("tinyfs: /system/bin/su already exists\n");
		goto out_path;
	}
	if (err != -ENOENT) {
		pr_err("tinyfs: failed to inspect /system/bin/su: %d\n", err);
		goto out_path;
	}

	if (ksu_tinyfs_bin_inode->i_sb->s_d_op)
		ksu_tinyfs_dops = *ksu_tinyfs_bin_inode->i_sb->s_d_op;
	ksu_tinyfs_dops.d_revalidate = ksu_tinyfs_d_revalidate;

	ksu_tinyfs_su_inode = new_inode(ksu_tinyfs_bin_inode->i_sb);
	if (!ksu_tinyfs_su_inode) {
		pr_err("tinyfs: failed to allocate su inode\n");
		goto out_path;
	}

	ksu_tinyfs_su_inode->i_ino = iunique(ksu_tinyfs_bin_inode->i_sb, 1000000);
	ksu_tinyfs_su_inode->i_mode = S_IFREG | 0755;
	ksu_tinyfs_su_inode->i_uid = GLOBAL_ROOT_UID;
	ksu_tinyfs_su_inode->i_gid = GLOBAL_ROOT_GID;
	ksu_tinyfs_su_inode->i_size = sizeof(ksu_tinysu_arm64);
	ksu_tinyfs_su_inode->i_fop = &ksu_tinyfs_fops;
	ksu_tinyfs_su_inode->i_mapping->a_ops = &ksu_tinyfs_aops;
	ksu_tinyfs_su_inode->i_flags |= S_PRIVATE | S_NOATIME;
	set_nlink(ksu_tinyfs_su_inode, 1);

	security = selinux_inode(ksu_tinyfs_su_inode);
	if (!security || !ksu_file_sid) {
		pr_err("tinyfs: ksu_file SID is unavailable\n");
		iput(ksu_tinyfs_su_inode);
		ksu_tinyfs_su_inode = NULL;
		goto out_path;
	}
	security->sid = ksu_file_sid;

	ksu_tinyfs_bin_iops = *ksu_tinyfs_orig_bin_iops;
	ksu_tinyfs_bin_iops.lookup = ksu_tinyfs_lookup;
	WRITE_ONCE(ksu_tinyfs_bin_inode->i_op, &ksu_tinyfs_bin_iops);
	smp_mb();

	cached_su = d_hash_and_lookup(bin_path.dentry, &su_name);
	if (IS_ERR(cached_su)) {
		pr_warn("tinyfs: failed to invalidate cached su dentry: %ld\n",
			PTR_ERR(cached_su));
	} else if (cached_su) {
		ksu_tinyfs_prepare_dentry(cached_su);
		d_invalidate(cached_su);
		dput(cached_su);
	}

	smp_store_release(&ksu_tinyfs_ready, true);
	ksu_sucompat_disable_branch();
	pr_info("tinyfs: synthetic /system/bin/su enabled\n");

out_path:
	path_put(&bin_path);
}
