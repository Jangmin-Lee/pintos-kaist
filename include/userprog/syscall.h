#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
struct lock file_lock;
void close (int fd);

#endif /* userprog/syscall.h */
