#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

void check_address(void *addr)
{
	/* check if pointer points user memory */
	/* if not, quit process */
	if (0x8048000 > addr || 0xc0000000 < addr) exit(-1);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	uint32_t *sp = f -> rsp; /* user stack pointer */
	check_address((void *)sp);
	int syscall_num = *sp; /* system call number */
	int *arg = malloc(100 * sizeof(int));

	switch (syscall_num)
	{
		case SYS_HALT :
			halt();
			break;
		case SYS_EXIT :
			get_argument(sp, arg, 1);
			check_address((void *)arg[0]);
			f -> R.rax = exec((int)arg[0]);
			break;
		case SYS_FORK :
			get_argument(sp, arg, 1);
			check_address((void *)arg[0]);
			f -> R.rax = exec((const char *)arg[0]);
			break;
		case SYS_EXEC :
			get_argument(sp, arg, 1);
			check_address((void *)arg[0]);
			f -> R.rax = exec((const char *)arg[0]);
			break;
		case SYS_WAIT : 
			get_argument(sp, arg, 1);
			check_address((void *)arg[0]);
			f -> R.rax = exec((tid_t)arg[0]);
			break;
		case SYS_CREATE :
			get_argument(sp, arg, 1);
			check_address((void *)arg[0]);
			f -> R.rax = exec((int)arg[0]);
		case SYS_REMOVE :
			get_argument(sp, arg, 1);
			check_address((void *)arg[0]);
			f -> R.rax = exec((int)arg[0]);
		case SYS_OPEN : 
			get_argument(sp, arg, 1);
			check_address((void *)arg[0]);
			f -> R.rax = open((const char *)arg[0]);
			break;
		case SYS_FILESIZE : 
			get_argument(sp, arg, 1);
			check_address((void *)arg[0]);
			f -> R.rax = filesize ((int)arg[0]);
			break;	
		case SYS_READ : 
			get_argument(sp, arg, 3);
			check_address((void *)arg[0]);
			f -> R.rax = read ((int)arg[0], (void *)arg[1], (unsigned )arg[2]);
			break;	
		case SYS_WRITE : 
			get_argument(sp, arg, 3);
			check_address((void *)arg[0]);
			f -> R.rax = write ((int)arg[0], (const void *)arg[1], (unsigned )arg[2]);
			break;	
		case SYS_SEEK :  
			get_argument(sp, arg, 2);
			check_address((void *)arg[0]);
			f -> R.rax = seek  ((int)arg[0], (unsigned )arg[1]);
			break;	
		case SYS_TELL :  
			get_argument(sp, arg, 1);
			check_address((void *)arg[0]);
			f -> R.rax = tell  ((int)arg[0]);
			break;	
		case SYS_CLOSE :
			get_argument(sp, arg, 1);
			check_address((void *)arg[0]);
			f -> R.rax = close   ((int)arg[0]);
			break;
		default :
			get_argument(sp, arg, 1);
			check_address((void *)arg[0]);
			f -> R.rax = exec((int)arg[0]);
			break;
	}
	printf ("system call!\n");
	thread_exit ();
}

void get_argument(void *esp, int *arg, int count)
{
	/* 유저 스택에 저장된 인자 값들을 커널로 저장 */
	/* 인자가 저장된 위치가 유저 영역인지 확인 */
	void *track = esp;
	for(int i=0; i<count; i++){
		check_address((int *)track);
		arg[i] = *(int *)track;
		track = track + sizeof(int);
	}
}
