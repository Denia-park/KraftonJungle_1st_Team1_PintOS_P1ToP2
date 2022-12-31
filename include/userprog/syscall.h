#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "../lib/stdbool.h"
#include "../lib/kernel/stdio.h"
#include "threads/interrupt.h"

typedef int pid_t;

void syscall_init (void);
void check_address(void *addr);
void halt (void);
void exit (int status);
bool create (const char *file_name, unsigned initial_size);
bool remove (const char *file_name);
int write (int fd, const void *buffer, unsigned size);
int open (const char *file_name);
void close (int fd);
void make_fd_to_null(int fd);
struct file *fd_to_struct_filep(int fd);
int filesize (int fd);
void seek (int fd, unsigned position);
int read (int fd, void *buffer, unsigned size);
unsigned tell (int fd);
int exec(char *file_name);
struct thread * get_child(int pid);
pid_t fork (const char *thread_name, struct intr_frame *f);

#endif /* userprog/syscall.h */
