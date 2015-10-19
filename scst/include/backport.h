#ifndef _SCST_BACKPORT_H_
#define _SCST_BACKPORT_H_

/*
 *  Copyright (C) 2015 SanDisk Corporation
 *
 *  Backports of functions introduced in recent kernel versions.
 *
 *  Please keep the functions in this file sorted according to the name of the
 *  header file in which these have been defined.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation, version 2
 *  of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include <linux/writeback.h> /* sync_page_range() */

/* <linux/fs.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0) && \
	!defined(CONFIG_COMPAT_KERNEL_3_12)
/*
 * See also patch "new helper: file_inode(file)" (commit ID
 * 496ad9aa8ef448058e36ca7a787c61f2e63f0f54). See also patch
 * "kill f_dentry macro" (commit ID 78d28e651f97).
 */
static inline struct inode *file_inode(const struct file *f)
{
	return f->f_dentry->d_inode;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
static inline int vfs_fsync_backport(struct file *file, int datasync)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	struct inode *inode = file_inode(file);

	return sync_page_range(inode, file->f_mapping, 0, i_size_read(inode));
#else
	return vfs_fsync(file, file->f_path.dentry, datasync);
#endif
}

#define vfs_fsync vfs_fsync_backport
#endif

#endif /* _SCST_BACKPORT_H_ */
