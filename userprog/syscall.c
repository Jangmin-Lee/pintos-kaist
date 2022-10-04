#include "userprog/syscall.h"
#include "userprog/process.h"
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

void check_valid_ptr(void *_ptr) {
	// 없는경우, KERNEL 영역인 경우, User영역이지만 valid하지 않은 경우
	if (!_ptr || is_kernel_vaddr(_ptr) || !pml4_get_page(thread_current() -> pml4, _ptr)) {
		exit(-1);
	}
}

void halt (void) {
	power_off();
}

void exit (int status) {
	struct thread *curr = thread_current();
	curr -> exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

int fork (const char *thread_name) {
	check_valid_ptr(thread_name);
	struct thread *curr = thread_current();
	// tid_t pid = thread_create(thread_name, curr -> priority, );
	// if (true){
	// 	return TID_ERROR;
	// }
	process_fork(thread_name, &curr -> tf);
}
int exec (const char *file) {
	check_valid_ptr(file);
	return process_exec(file);
}

int wait (tid_t pid) {
	// find child process from my child list

	// if not exist -> err
	// child의 wait semaphore를 wait
	// child는 종료될때 wait sema를 해제
	// child의 exit status를 가져와서 return 진행
	// 그럼으로 exit 시에 child의 return status를 저장해줘야 함.
	// kernal에 의해 종료된 경우에는 -1 리턴
	// 이미 wait에 들어간 자식을 다시 wait 하는 경우에도 -1 리턴, sema쪽 waiter 길이가 1보다 크면 안될 듯.
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
	check_valid_ptr(file);
	return filesys_create(file, initial_size);
}

bool remove (const char *file) {
	check_valid_ptr(file);
	// special case = remove opened file
	return filesys_remove(file);
}

int open (const char *file) {
	check_valid_ptr(file);
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
	check_valid_ptr(buffer);
	return;
}

int write (int fd, const void *buffer, unsigned length) {
	check_valid_ptr(buffer);
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
	return 0;
}
void close (int fd) {
	return;
}


/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	int sys_num = f -> R.rax;
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
			f -> R.rax = fork((char *) f -> R.rdi);
			break;
		case SYS_EXEC:
			f -> R.rax = exec((char *) f -> R.rdi);
			break;
		case SYS_WAIT:
			f -> R.rax = wait((tid_t) f -> R.rdi);
			break;
		case SYS_CREATE:
			f -> R.rax = create((char *) f -> R.rdi, (unsigned) f -> R.rsi);
			break;
		case SYS_REMOVE:
			f -> R.rax = remove((char *) f -> R.rdi);
			break;
		case SYS_OPEN:
			f -> R.rax = open((char *) f -> R.rdi);
			break;
		case SYS_FILESIZE:
			f -> R.rax = filesize((int) f -> R.rdi);
			break;
		case SYS_READ:
			f -> R.rax = read((int) f -> R.rdi, (void *) f -> R.rsi, (unsigned) f -> R.rdx);
			break;
		case SYS_WRITE:
			f -> R.rax = write((int) f -> R.rdi, (const void *) f -> R.rsi, (unsigned) f -> R.rdx);
			break;
		case SYS_SEEK:
			seek((int) f -> R.rdi, (unsigned) f -> R.rdx);
			break;
		case SYS_TELL:
			f -> R.rax = tell((int) f -> R.rdi);
			break;
		case SYS_CLOSE:
			close((int) f -> R.rdi);
			break;
	}
}
