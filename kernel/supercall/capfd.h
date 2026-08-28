/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_CAPFD
#define __KSU_H_CAPFD

#ifdef CONFIG_KSU_CAPFD_ROOT
int ksu_create_root_capfd(void __user *arg);
#endif

#endif
