#include "userprog/syscall.h"
#include "filesys/filesys.h"
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

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

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

void halt (void) {
	power_off();
}

void exit (int status) {
	struct thread *curr = thread_current();
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

int fork (const char *thread_name) {
	// struct thread *curr = thread_current();
	// tid_t pid = thread_create(thread_name, curr -> priority, );
	// if (true){
	// 	return TID_ERROR;
	// }
}
int exec (const char *file) {
	return;
}

int wait (int pid) {
	// find child process from my child list
	// if not exist -> err
	// child의 wait semaphore를 wait
	// child는 종료될때 wait sema를 해제
	// child의 exit status를 가져와서 return 진행
	// 그럼으로 exit 시에 child의 return status를 저장해줘야 함.
	// kernal에 의해 종료된 경우에는 -1 리턴
	// 이미 wait에 들어간 자식을 다시 wait 하는 경우에도 -1 리턴, sema쪽 waiter 길이가 1보다 크면 안될 듯.

	return;
}

bool create (const char *file, unsigned initial_size) {
	return filesys_create(file, initial_size);
}

bool remove (const char *file) {
	// special case = remove opened file
	return filesys_remove(file);
}

int open (const char *file) {
	bool success = filesys_open(file);
	if (!success) {
		return -1;
	}
	// return file descriptor
	// return file
}

int filesize (int fd) {
	return;
}

int read (int fd, void *buffer, unsigned length) {
	return;
}

int write (int fd, const void *buffer, unsigned length) {
	if (fd == 1) {
		putbuf(buffer, length);
		return length;
	}
	// file write
}
void seek (int fd, unsigned position) {
	return;
}
unsigned tell (int fd) {
	return;
}
void close (int fd) {
	return;
}


/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	int sys_num = f -> R.rax;
	// uintptr_t stack_ptr = f -> rsp;
	// if (!stack_ptr || is_kernel_vaddr(stack_ptr)) {
	// 	exit(-1);
	// }
	// %rdi, %rsi, %rdx, %r10, %r8, and %r9.

	// printf("num : %d\n", sys_num);
	switch (sys_num)
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit((int) f -> R.rdi);
			break;
		case SYS_FORK:
			fork((char *) f -> R.rdi);
			break;
		case SYS_EXEC:
			exec((char *) f -> R.rdi);
			break;
		case SYS_WAIT:
			wait((int) f -> R.rdi);
			break;
		case SYS_CREATE:
			create((char *) f -> R.rdi, (unsigned) f -> R.rsi);
			break;
		case SYS_REMOVE:
			remove((char *) f -> R.rdi);
			break;
		case SYS_OPEN:
			open((char *) f -> R.rdi);
			break;
		case SYS_FILESIZE:
			filesize((int) f -> R.rdi);
			break;
		case SYS_READ:
			read((int) f -> R.rdi, (void *) f -> R.rsi, (unsigned) f -> R.rdx);
			break;
		case SYS_WRITE:
			write((int) f -> R.rdi, (const void *) f -> R.rsi, (unsigned) f -> R.rdx);
			break;
		case SYS_SEEK:
			seek((int) f -> R.rdi, (unsigned) f -> R.rdx);
			break;
		case SYS_TELL:
			tell((int) f -> R.rdi);
			break;
		case SYS_CLOSE:
			close((int) f -> R.rdi);
			break;
	}
}
