/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include <sys/syscall.h>

#define NONE 0

__attribute__((noinline))
static long raw_syscall(long number, long a, long b, long c,
			long d, long e, long f)
{
	register long x8 __asm__("x8") = number;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;
	register long x4 __asm__("x4") = e;
	register long x5 __asm__("x5") = f;

	__asm__ volatile("svc #0"
			 : "=r"(x0)
			 : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3),
			   "r"(x4), "r"(x5)
			 : "memory");
	return x0;
}

void tinysu_main(long *stack);

__attribute__((naked))
void __start(void)
{
	__asm__ volatile("mov x0, sp\n"
			 "b tinysu_main\n");
}
