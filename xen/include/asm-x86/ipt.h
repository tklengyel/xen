/*
 * ipt.h: Intel Processor Trace virtualization for HVM domain.
 *
 * Copyright (c) 2018, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Luwei Kang <luwei.kang@intel.com>
 */

#ifndef __ASM_X86_HVM_IPT_H_
#define __ASM_X86_HVM_IPT_H_

#define IPT_MODE_OFF        0
#define IPT_MODE_GUEST      (1<<0)

extern unsigned int ipt_mode;

#endif /* __ASM_X86_HVM_IPT_H_ */
