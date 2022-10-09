#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/palloc.h"
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
	lock_init(&file_lock);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

void check_valid_ptr(const uint64_t *_ptr) {
	// 없는경우, KERNEL 영역인 경우, User영역이지만 valid하지 않은 경우
	if (_ptr == NULL || is_kernel_vaddr(_ptr) || pml4_get_page(thread_current() -> pml4, _ptr) == NULL) {
		exit(-1);
	}
}

void halt (void) {
	power_off();
}

void exit (int status) {
	thread_current() -> exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

int fork (const char *thread_name, struct intr_frame *f) {
	check_valid_ptr(thread_name);
	return process_fork(thread_name, f);
}

int exec (const char *file) {
	check_valid_ptr(file);

	char *fn_copy = palloc_get_page(PAL_ZERO);
	if (fn_copy == NULL) {
		exit(-1);
	}
	strlcpy(fn_copy, file, strlen(file)+1);
	if (process_exec(fn_copy) == TID_ERROR) {
		exit(-1);
	}
	NOT_REACHED();
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
	filesys_create(file, initial_size);
}

bool remove (const char *file) {
	check_valid_ptr(file);
	return filesys_remove(file);
}

int open (const char *file) {
	check_valid_ptr(file);
	struct file *file_ptr = filesys_open(file);
	if (file_ptr == NULL) {
		return -1;
	}

	struct thread *curr = thread_current();
	for (int i = curr -> next_fd; i < 512; i++) {
		if (curr -> fd_table[i] == NULL) {
			curr -> next_fd = i;
			curr -> fd_table[i] = file_ptr;
			return i;
		}
	}
	file_close(file_ptr);
	return -1;
	// return file descriptor
	// 0 : stdin / 1 : stdout
	// 파일을 각 프로세스가 열 때 마다 각 fd가 생긴다.
	// 각 프로세스는 여러개의 fd를 가질 수 있다.
	// 2부터 시작하는 단조증가 값을 가지게 하라 (tid 관련 코드 참고 가능할듯)
	// fd -> file인 mapping 테이블이 필요할 것이다.
	// 단조증가이므로 그냥 list index 사용
	// 128개 by FAQ
	// Thread는 fd의 리스트를 가지게 될 것이다.
	// return file
	// page allocation으로 변경 & multi-oom이 212 까지 가져서 512으로 변경.
}

int filesize (int fd) {
	if (fd < 1 || fd > 512) {
		return -1;
	}
	struct file *_file = thread_current() -> fd_table[fd];
	if (_file == NULL) {
		return -1;
	}
	return file_length(_file);;
}

int read (int fd, void *buffer, unsigned length) {
	check_valid_ptr(buffer);
	if (fd == 0) {
		return input_getc ();
	}

	int ret_val = -1;
	if (fd < 1 || fd > 512) {
		ret_val = -1;
	} else {
		struct file *_file = thread_current() -> fd_table[fd];
		if (_file == NULL) {
			ret_val = -1;
		} else {
			lock_acquire(&file_lock);
			ret_val = file_read(_file, buffer, length);
			lock_release(&file_lock);
		}
	}
	return ret_val;
}

int write (int fd, const void *buffer, unsigned length) {
	check_valid_ptr(buffer);

	int ret_val = -1;
	// printf("thread struct size : %d\n", sizeof(struct thread));
	if (fd == 1) {
		lock_acquire(&file_lock);
		putbuf(buffer, length);
		lock_release(&file_lock);
		ret_val = length;
	}
	else if (fd < 2 || fd > 512) {
		ret_val = -1;
	} else {
		struct file *_file = thread_current() -> fd_table[fd];
		if (_file == NULL) {
			ret_val = -1;
		} else {
			// printf("(pid: %d) file_write, possible? : %s\n", thread_current() -> tid,  is_deny(_file) ? "denied" : "possible");
			// printf("pointer failed? : %p\n", _file);
			// printf("buff : %d, file_pos: %d \n", length, file_pos(_file));
			lock_acquire(&file_lock);
			ret_val = file_write(_file, buffer, length);
			lock_release(&file_lock);
			// printf("buff : %d, file_pos: %d \n", length, file_pos(_file));
		}
	}
	// printf("(pid: %d) fin? \n", thread_current() -> tid);

	return ret_val;
}

void seek (int fd, unsigned position) {
	if (fd < 2 || fd > 512) {
		return;
	}
	struct file *_file = thread_current() -> fd_table[fd];
	if (_file == NULL) {
		return;
	}
	// printf("seek called? at pos %d\n", position);
	lock_acquire(&file_lock);
	file_seek(_file, position);
	lock_release(&file_lock);
}

unsigned tell (int fd) {
	if (fd < 2 || fd > 512) {
		return;
	}
	struct file *_file = thread_current() -> fd_table[fd];
	if (_file == NULL) {
		return;
	}
	lock_acquire(&file_lock);
	unsigned pos = file_tell(_file);
	lock_release(&file_lock);
	return pos;
}

void close (int fd) {
	if (fd < 2 || fd > 512) {
		return;
	}
	struct thread *curr = thread_current();
	struct file *_file = curr -> fd_table[fd];
	if (_file == NULL) {
		return;
	}
	curr -> fd_table[fd] = NULL;
	file_close(_file);
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
			f -> R.rax = fork((char *) f -> R.rdi, f);
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
			seek((int) f -> R.rdi, (unsigned) f -> R.rsi);
			break;
		case SYS_TELL:
			f -> R.rax = tell((int) f -> R.rdi);
			break;
		case SYS_CLOSE:
			close((int) f -> R.rdi);
			break;
		default:
			exit(-1);
			break;
	}
}
