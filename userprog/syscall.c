#include "userprog/syscall.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/palloc.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
int add_file_to_fd_table(struct file *file);

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

struct lock filesys_lock;

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	lock_init(&filesys_lock);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

//주소 값이 유저 영역 주소 값인지 확인하고, 유저 영역을 벗어난 영역일 경우 프로세스 종료 exit(-1)*/
void 
check_address(void *addr)
{
	struct thread *curr = thread_current();
	if ( is_kernel_vaddr(addr) || addr == NULL ||
		pml4_get_page(curr->pml4, addr) == NULL ){
			exit(-1) ;
	}
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	/* 유저 스택에 저장되어 있는 시스템 콜 넘버를 가져온다. */
	int sys_number = f->R.rax; // rax: 시스템 콜 넘버
    /* 
	인자 들어오는 순서:
	1번째 인자: %rdi
	2번째 인자: %rsi
	3번째 인자: %rdx
	4번째 인자: %r10
	5번째 인자: %r8
	6번째 인자: %r9 
	*/
	switch(sys_number) {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);	
			break;	
		case SYS_EXEC:
			if (exec((char *)f->R.rdi) == -1) {
				exit(-1);
			}
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create((char *) f->R.rdi, f->R.rsi);		
			break;
		case SYS_REMOVE:
			f->R.rax = remove((char *) f->R.rdi);
			break;		
		case SYS_OPEN:
			f->R.rax = open((char *) f->R.rdi);	
			break;	
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, (void *) f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, (void *) f->R.rsi, f->R.rdx);
			break;		
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;		
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);	
			break;	
		case SYS_CLOSE:
			close(f->R.rdi);
			break;	
		default:
			thread_exit ();
			break;
	}
}

void
halt (void) {
	power_off ();
}

void
exit (int status) {
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), curr->exit_status);
	thread_exit();
}

// 현재 프로세스를 cmd_line에서 지정된 인수를 전달하여 이름이 지정된 실행 파일로 변경
int 
exec(char *file_name) {
	check_address(file_name);

	int name_length = strlen(file_name) + 1; //Null 포함
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if (fn_copy == NULL) {
		exit(-1);
	}

	strlcpy(fn_copy, file_name, name_length);

	if (process_exec(fn_copy) == -1) {
		return -1;
	}

	NOT_REACHED();
	return 0;
}

pid_t
fork (const char *thread_name, struct intr_frame *f){
	return process_fork(thread_name, f);
}

bool
create (const char *file_name, unsigned initial_size) {
	check_address ((void *)file_name);
	return filesys_create((char *) file_name, initial_size);
}

bool
remove (const char *file_name) {
	check_address ((void *)file_name);
	return filesys_remove((char *) file_name);
}

 /* 파일을 현재 프로세스의 fdt에 추가 */
int add_file_to_fd_table(struct file *file) {
	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;
	int fd = t->fdidx; //fd값은 2부터 출발
	
	while (t->file_descriptor_table[fd] != NULL && fd < FDT_COUNT_LIMIT) {
		fd++;
	}

	if (fd >= FDT_COUNT_LIMIT) {
		return -1;
	}

	t->fdidx = fd;
	fdt[fd] = file;
	return fd;
}

int
open (const char *file_name) {
	check_address ((void *)file_name);
	struct file * file_obj = filesys_open(file_name);

	if(file_obj == NULL){
		return -1;
	}

	int fd = add_file_to_fd_table(file_obj); // 만들어진 파일을 스레드 내 fdt 테이블에 추가

	// 만약 파일을 열 수 없으면] -1을 받음
	if (fd == -1) {
		file_close(file_obj);
	}

	return fd;
}

/*  fd 값을 넣으면 해당 file을 반환하는 함수 */
struct file *fd_to_struct_filep(int fd) {
	if (fd < 0 || fd >= FDT_COUNT_LIMIT) {
		return NULL;
	}
	
	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;
	
	struct file *file = fdt[fd];
	return file;
}

/*  fd 값에 해당하는 테이블을 내용을 NULL로 변경*/
void make_fd_to_null(int fd) {
	if (fd < 0 || fd >= FDT_COUNT_LIMIT) {
		return;
	}
	
	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;
	
	fdt[fd] = NULL;
}

int
filesize (int fd) {
	struct file *fileobj = fd_to_struct_filep(fd);
	if (fileobj == NULL) {
		return -1;
	}
	return file_length(fileobj);
}

int
read (int fd, void *buffer, unsigned size) {
	// 유효한 주소인지부터 체크
	check_address((void *) buffer); // 버퍼 시작 주소 체크
	check_address((void *) buffer + size -1); // 버퍼 끝 주소도 유저 영역 내에 있는지 체크
	unsigned char *buf = buffer;
	unsigned int read_count;
	
	struct file *fileobj = fd_to_struct_filep(fd);

	if (fileobj == NULL) {
		return -1;
	}

	/* STDIN일 때: */
	if (fd == STDIN_FILENO) {
		char key;
		for (unsigned int read_count = 0; read_count < size; read_count++) {
			key  = input_getc();
			*buf++ = key;
			if (key == '\0') { // 엔터값
				break;
			}
		}
	}
	/* STDOUT일 때: -1 반환 */
	else if (fd == STDOUT_FILENO){
		return -1;
	}
	else {
		lock_acquire(&filesys_lock);
		read_count = file_read(fileobj, buffer, size); // 파일 읽어들일 동안만 lock 걸어준다.
		lock_release(&filesys_lock);
	}

	return read_count;
}

int
write (int fd, const void *buffer, unsigned size) {
	check_address((void *) buffer);
	check_address((void *) buffer + size); // 버퍼 끝 주소도 유저 영역 내에 있는지 체크
	struct file *fileobj = fd_to_struct_filep(fd);
	int read_count;
	if(fileobj == NULL){
		exit(-1);
	}
	if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		read_count = size;
	}	
	else if (fd == STDIN_FILENO) {
		return -1;
	}
	else {
		lock_acquire(&filesys_lock);
		read_count = file_write(fileobj, buffer, size);
		lock_release(&filesys_lock);
	}

	return read_count;
}

void
seek (int fd, unsigned position) {
	struct file *file = fd_to_struct_filep(fd);

	//std in , out 을 지칭하면 바로 return
	if (file == NULL || fd < 2) {
		return;
	}

	file_seek(file, position);
}

unsigned
tell (int fd) {
	struct file *file = fd_to_struct_filep(fd);

	//std in , out 을 지칭하면 바로 return
	if (file == NULL || fd < 2) {
		return;
	}

	check_address((void *) file);

	return file_tell(file);
}

void
close (int fd) {
	struct file *file = fd_to_struct_filep(fd);

	//std in , out 을 지칭하면 바로 return
	if (file == NULL || fd < 2) {
		return;
	}

	make_fd_to_null(fd);

	file_close(file);
}

