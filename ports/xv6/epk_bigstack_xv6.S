# epk_bigstack_xv6.S — run fn(arg) on a caller-provided stack.
# a0 = fn, a1 = arg, a2 = stack top (caller allocates the memory).
# After fn returns, exits the process with fn's value: xv6 has no
# C runtime, so returning from main() would execute garbage.
	.globl epk_bigstack_trampoline
epk_bigstack_trampoline:
	mv	s1, sp
	mv	sp, a2
	mv	t0, a0
	mv	a0, a1
	jalr	t0
	mv	sp, s1
	tail	epk_xv6_exit
	.globl epk_xv6_exit
epk_xv6_exit:				# a0 = exit code
	li	a7, 2			# SYS_exit
	ecall
1:	wfi
	j	1b
