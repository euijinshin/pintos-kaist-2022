#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

// for exec()
#include "threads/palloc.h"
#include "filesys/file.h"

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

struct lock *filesys_lock;

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

// void check_address(void *addr)
// {
//  /* check if pointer points user memory */
//  /* if not, quit process */
//  if (0x8048000 > addr || 0xc0000000 < addr) exit(-1);
// }
// 주소값이 유저 영역(0x8048000~0xc0000000)에서 사용하는 주소값인지 확인하는 함수
void check_address(const uint64_t *addr)    
{
    struct thread *cur = thread_current();
    if (addr == NULL || !(is_user_vaddr(addr)) || pml4_get_page(cur->pml4, addr) == NULL) {
        exit(-1);
    }
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

void halt (void)
{
    /* power_off()를 사용하여 pintos 종료 */
    power_off();
}

void exit (int status)
{
    void exit(int status) {
	struct thread *cur = thread_current();
    cur->exit_status = status;		// 프로그램이 정상적으로 종료되었는지 확인(정상적 종료 시 0)

	printf("%s: exit(%d)\n", thread_name(), status); 	// 종료 시 Process Termination Message 출력
	thread_exit();		// 스레드 종료
}
}

int exec(char *file_name) {
    check_address(file_name);

    int file_size = strlen(file_name)+1;
    char *fn_copy = palloc_get_page(PAL_ZERO);
    if (fn_copy == NULL) {
        exit(-1);
    }
    strlcpy(fn_copy, file_name, file_size);

    if (process_exec(fn_copy) == -1) {
        return -1;
    }

    NOT_REACHED();
    return 0;
}

// 파일 생성하는 시스템 콜
// 성공일 경우 true, 실패일 경우 false 리턴
bool create(const char *file, unsigned initial_size) {      // file: 생성할 파일의 이름 및 경로 정보, initial_size: 생성할 파일의 크기
    check_address(file);
    return filesys_create(file, initial_size);
}

// 파일 삭제하는 시스템 콜
// 성공일 경우 true, 실패일 경우 false 리턴
bool remove(const char *file) {         // file: 제거할 파일의 이름 및 경로 정보
    check_address(file);
    return filesys_remove(file);
}

// fd값 리턴, 실패 시 -1 리턴
int open(const char *file) {
	check_address(file);
	struct file *open_file = filesys_open(file);

	if (open_file == NULL) {
		return -1;
	}

	int fd = add_file_to_fdt(open_file);

	// fd table 가득 찼다면
	if (fd == -1) {
		file_close(open_file);
	}
	return fd;
}

// 현재 프로세스의 fd테이블에 파일 추가
int add_file_to_fdt(struct file *file) {
    struct thread *cur = thread_current();
    struct file **fdt = cur->fd_table;

    // fd의 위치가 제한 범위를 넘지 않고, fdtable의 인덱스 위치와 일치한다면
    while (cur->fd_idx < FDCOUNT_LIMIT && fdt[cur->fd_idx]) {
        cur->fd_idx++;
    }

    // fdt이 가득 찼다면
    if (cur->fd_idx >= FDCOUNT_LIMIT)
        return -1;

    fdt[cur->fd_idx] = file;
    return cur->fd_idx;
}

// fd로 파일 찾는 함수
static struct file *find_file_by_fd(int fd) {
    struct thread *cur = thread_current();

    if (fd < 0 || fd >= FDCOUNT_LIMIT) {
        return NULL;
    }
    return cur->fd_table[fd];
}

// fd인자를 받아 파일 크기 리턴
int filesize(int fd) {
    struct file *open_file = find_file_by_fd(fd);
    if (open_file == NULL) {
        return -1;
    }
    return file_length(open_file);
}



int read(int fd, void *buffer, unsigned size) {
 check_address(buffer);

 int read_result;
 struct thread *cur = thread_current();
 struct file *file_fd = find_file_by_fd(fd);

 if (fd == 0) {
     // read_result = i;
     *(char *)buffer = input_getc();     // 키보드로 입력 받은 문자를 반환하는 함수
     read_result = size;
 }
 else {
     if (find_file_by_fd(fd) == NULL) {
         return -1;
     }
     else {
         lock_acquire(&filesys_lock);
         read_result = file_read(find_file_by_fd(fd), buffer, size);
         lock_release(&filesys_lock);
     }
 }
 return read_result;
}

// buffer로부터 사이즈 쓰기
int write(int fd, const void *buffer, unsigned size) {
 check_address(buffer);

 int write_result;
 lock_acquire(&filesys_lock);
 if (fd == 1) {
     putbuf(buffer, size);       // 문자열을 화면에 출력하는 함수
     write_result = size;
 }
 else {
     if (find_file_by_fd(fd) != NULL) {
         write_result = file_write(find_file_by_fd(fd), buffer, size);
     }
     else {
         write_result = -1;
     }
 }
 lock_release(&filesys_lock);
 return write_result;
}

// 파일 위치(offset)로 이동하는 함수
void seek(int fd, unsigned position) {
    struct file *seek_file = find_file_by_fd(fd);
    if (seek_file <= 2) {       // 초기값 2로 설정. 0: 표준 입력, 1: 표준 출력
        return;
    }
    seek_file->pos = position;
}
// void seek (int fd, unsigned position){
//  lock_acquire(filesys_lock);
//  struct thread *t = thread_current();
//  struct file *f;
    
//  if( f = process_get_file(fd) ){
//      //succeeded in accessing file
//      file_seek(f, (off_t)position);
//      lock_release(filesys_lock);
//      return;
//  }
//  //fail to access file
//  lock_release(filesys_lock);
//  return;
// }

// 파일의 위치(offset)을 알려주는 함수
unsigned tell(int fd) {
    struct file *tell_file = find_file_by_fd(fd);
    if (tell_file <= 2) {
        return;
    }
    return file_tell(tell_file);
}

int remove_file_from_fdt(int fd) {
    struct thread *cur = thread_current();
    struct file **fdt = cur->fd_table;

    fdt[fd] = NULL;
}

// 열린 파일을 닫는 시스템 콜. 파일을 닫고 fd제거
void close(int fd) {
    struct file *fileobj = find_file_by_fd(fd);
    if (fileobj == NULL) {
        return;
    }
    remove_file_from_fdt(fd);
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
            exit(f->R.rdi);
            break;
        // case SYS_FORK:
        //  f->R.rax = fork(f->R.rdi, f);
        //  break;
        case SYS_EXEC:
            if (exec(f->R.rdi) == -1) {
                exit(-1);
            }
            break;
        // case SYS_WAIT:
        //  f->R.rax = process_wait(f->R.rdi);
        //  break;
        case SYS_CREATE:
            f->R.rax = create(f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:
            f->R.rax = remove(f->R.rdi);
            break;
        case SYS_OPEN:
            f->R.rax = open(f->R.rdi);
            break;
        case SYS_FILESIZE:
            f->R.rax = filesize(f->R.rdi);
            break;
        case SYS_READ:
         f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
         break;
        case SYS_WRITE:
         f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
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
        default :
            exit(-1);
            break;
    }
}


