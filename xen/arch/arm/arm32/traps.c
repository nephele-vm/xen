/*
 * xen/arch/arm/arm32/traps.c
 *
 * ARM AArch32 Specific Trap handlers
 *
 * Copyright (c) 2012 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/lib.h>
#include <xen/kernel.h>
#include <xen/sched.h>

#include <public/xen.h>

#include <asm/mmio.h>
#include <asm/processor.h>
#include <asm/traps.h>

void do_trap_reset(struct cpu_user_regs *regs)
{
    do_unexpected_trap("Reset", regs);
}

void do_trap_undefined_instruction(struct cpu_user_regs *regs)
{
    uint32_t pc = regs->pc;
    uint32_t instr;

    if ( !is_kernel_text(pc) &&
         (system_state >= SYS_STATE_active || !is_kernel_inittext(pc)) )
        goto die;

    /* PC should be always a multiple of 4, as Xen is using ARM instruction set */
    if ( regs->pc & 0x3 )
        goto die;

    instr = *((uint32_t *)pc);
    if ( instr != BUG_OPCODE )
        goto die;

    if ( do_bug_frame(regs, pc) )
        goto die;

    regs->pc += 4;
    return;

die:
    do_unexpected_trap("Undefined Instruction", regs);
}

void do_trap_hypervisor_call(struct cpu_user_regs *regs)
{
    do_unexpected_trap("Hypervisor Call", regs);
}

void do_trap_prefetch_abort(struct cpu_user_regs *regs)
{
    do_unexpected_trap("Prefetch Abort", regs);
}

void do_trap_data_abort(struct cpu_user_regs *regs)
{
    /*
     * We cannot distinguish between Asynchronous External Abort and
     * Synchronous Data Abort.
     *
     * As asynchronous abort (aka SError) generated by the hypervisor will
     * result in a crash of the system (see __do_trap_serror()), it is fine to
     * do it here.
     */
    if ( VABORT_GEN_BY_GUEST(regs) )
        do_trap_guest_serror(regs);
    else
        do_unexpected_trap("Data Abort", regs);
}

void post_increment_register(const struct instr_details *instr)
{
    /*
     * We have not implemented decoding of post indexing instructions for 32 bit.
     * Thus, this should be unreachable.
     */
    domain_crash(current->domain);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
