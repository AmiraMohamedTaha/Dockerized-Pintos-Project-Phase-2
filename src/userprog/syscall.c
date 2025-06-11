#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/init.h"

const int CLOSE_ALL = -1;

extern bool thread_alive;
struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);

static void load_args (struct intr_frame *f, int *arg, int n);
static void check_ptr(const void *virtual_addr);
static void verify_buffer(const void *buffer, unsigned size);
static void is_valid_str(const void* str);
static void is_alive_func(struct thread *t, void *aux);
static void reset_flag(void);

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int arg[3];
  
  check_ptr((const void*) f->esp);
  
  int *sp = f->esp;
  int syscall_code = *sp;
  
  switch (syscall_code) {
    case SYS_HALT:  //No arguments 
      break;
      
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
      load_args(f, arg, 1);
      break;
      
    case SYS_SEEK:
    case SYS_CREATE:
  
      load_args(f, arg, 2);
      break;
      
    case SYS_READ:
    case SYS_WRITE:
      load_args(f, arg, 3);
      break;
      
    default:
      break; // Invalid system call
  }
  
  switch (syscall_code) {
    case SYS_HALT:
      shutdown_power_off();
      break;
      
    case SYS_EXIT:
      exit(arg[0]);
      break;
      
    case SYS_EXEC:
      is_valid_str((const void *) arg[0]);
      f->eax = exec((const char *) arg[0]);
      break;
      
    case SYS_WAIT:
      f->eax = wait(arg[0]);
      break;
      
    case SYS_CREATE:
      is_valid_str((const void *) arg[0]);
      f->eax = create((const char *) arg[0], arg[1]);
      break;
      
    case SYS_REMOVE:
      is_valid_str((const void *) arg[0]);
      f->eax = remove((const char *) arg[0]);
      break;
      
    case SYS_OPEN:
      is_valid_str((const void *) arg[0]);
      f->eax = open((const char *) arg[0]);
      break;
      
    case SYS_FILESIZE:
      f->eax = filesize(arg[0]);
      break;
      
    case SYS_READ:
      verify_buffer((const void *) arg[1], arg[2]);
      f->eax = read(arg[0], (void *) arg[1], arg[2]);
      break;
      
    case SYS_WRITE:
      verify_buffer((const void *) arg[1], arg[2]);
      f->eax = write(arg[0], (const void *) arg[1], arg[2]);
      break;
      
    case SYS_SEEK:
      seek(arg[0], arg[1]);
      break;
      
    case SYS_TELL:
      f->eax = tell(arg[0]);
      break;
      
    case SYS_CLOSE:
      close(arg[0]);
      break;
      
    default:
      exit(-1);
  }
}



void exit (int status) {
  struct thread *cur = thread_current();
  
  if (cur->cp != NULL) {
    cur->cp->status = status;
  }
  
  if (!cur->exit_printed) {
    printf("%s: exit(%d)\n", cur->name, status);
    cur->exit_printed = true;
  }
  
  thread_exit();
}

int exec (const char *cmd_line) {
  if (cmd_line == NULL)
    return -1;
    
  int pid = process_execute(cmd_line);
  struct child_process* cp = get_child_process(pid, thread_current());
  
  if (cp != NULL) {
    if (cp->load == LOAD_FAIL) {
      remove_child_process(cp);
      return -1;
    }
  } else {
    return -1;
  }
  
  return pid;
}

int wait(pid_t pid){
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
  if (file == NULL || strlen(file) == 0)
    return false;
    
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return success;
}

int open(const char *file) {
  if (file == NULL)
    return -1;

  lock_acquire(&filesys_lock);
  struct file *f = filesys_open(file);
  if (f == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }

  struct thread *t = thread_current();
  int fd;
  
  /* Find first available file descriptor */
  for (fd = 2; fd < MAX_OPEN_FILES; fd++) {
    if (t->open_files[fd] == NULL) {
      t->open_files[fd] = f;
      lock_release(&filesys_lock);
      return fd;
    }
  }

  file_close(f);
  lock_release(&filesys_lock);
  return -1;
}

int filesize(int fd) {
  struct thread *t = thread_current();
  if (fd < 2 || fd >= MAX_OPEN_FILES || t->open_files[fd] == NULL)
    return -1;

  lock_acquire(&filesys_lock);
  int size = file_length(t->open_files[fd]);
  lock_release(&filesys_lock);
  return size;
}

int read(int fd, void *buffer, unsigned size) {
  if (buffer == NULL)
    exit(-1);
    
  verify_buffer(buffer, size);
  
  if (fd < 0 || fd >= MAX_OPEN_FILES)
    return -1;

  struct thread *t = thread_current();
  
  if (fd == STDIN_FILENO) {
    uint8_t *buff = (uint8_t *)buffer;
    for (unsigned i = 0; i < size; i++)
      buff[i] = input_getc();
    return size;
  }
  
  if (fd == STDOUT_FILENO || t->open_files[fd] == NULL)
    return -1;

  lock_acquire(&filesys_lock);
  int bytes = file_read(t->open_files[fd], buffer, size);
  lock_release(&filesys_lock);
  return bytes;
}

int write(int fd, const void *buffer, unsigned size) {
  if (buffer == NULL)
    exit(-1);
    
  verify_buffer(buffer, size);
  
  if (fd < 0 || fd >= MAX_OPEN_FILES)
    return -1;

  struct thread *t = thread_current();
  
  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    return size;
  }
  
  if (fd == STDIN_FILENO || t->open_files[fd] == NULL)
    return -1;

  lock_acquire(&filesys_lock);
  int bytes = file_write(t->open_files[fd], buffer, size);
  lock_release(&filesys_lock);
  return bytes;
}

void seek(int fd, unsigned position) {
  struct thread *t = thread_current();
  if (fd < 2 || fd >= MAX_OPEN_FILES || t->open_files[fd] == NULL)
    return;

  lock_acquire(&filesys_lock);
  file_seek(t->open_files[fd], position);
  lock_release(&filesys_lock);
}

unsigned tell(int fd) {
  struct thread *t = thread_current();
  if (fd < 2 || fd >= MAX_OPEN_FILES || t->open_files[fd] == NULL)
    return -1;

  lock_acquire(&filesys_lock);
  unsigned pos = file_tell(t->open_files[fd]);
  lock_release(&filesys_lock);
  return pos;
}

bool remove(const char *file) {
  if (file == NULL)
    return false;
    
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
  lock_release(&filesys_lock);
  return success;
}

void close(int fd) {
  struct thread *t = thread_current();
  if (fd < 2 || fd >= MAX_OPEN_FILES || t->open_files[fd] == NULL)
    return;

  lock_acquire(&filesys_lock);
  file_close(t->open_files[fd]);
  t->open_files[fd] = NULL;
  lock_release(&filesys_lock);
}



/*check the validity of given address*/
static void 
check_ptr (const void *virtual_addr)
{
  if (virtual_addr == NULL || !is_user_vaddr(virtual_addr) || 
      virtual_addr < (void *)0x08048000 ||  // User program load address
      pagedir_get_page(thread_current()->pagedir, virtual_addr) == NULL) {
    exit(-1);
  }
}

/* check the validity of given buffer with specific size */
static void 
verify_buffer(const void *buffer, unsigned size) 
{
  if (buffer == NULL)
    exit(-1);
    
  unsigned i;
  char *local_buffer = (char *) buffer;
  
  // Check first and last byte of buffer
  check_ptr((const void *) local_buffer);
  check_ptr((const void *) (local_buffer + size - 1));

  // Check buffer alignment and page boundaries
  for (i = 0; i < size; i++) {
    if ((uint32_t)(local_buffer + i) % PGSIZE == 0)
      check_ptr((const void *) (local_buffer + i));
  }
}

static void 
is_valid_str(const void *str) 
{
  if (str == NULL)
    exit(-1);
    
  check_ptr(str);
  const char *s = (const char *)str;
  while (*s != '\0') {
    if (!is_user_vaddr(s))
      exit(-1);
    check_ptr(s);
    s++;
  }
  check_ptr(s);  // Verify the null terminator
}

static void 
load_args (struct intr_frame *f, int *arg, int n)
{
  int i;
  int *ptr;
  
  for (i = 0; i < n; i++) {
    ptr = (int *) f->esp + i + 1;
    check_ptr((const void *) ptr);
    arg[i] = *ptr;
  }
}
/* function to check if thread is alive */
static void is_alive_func(struct thread *t, void *aux) {
  struct thread *parent = (struct thread *) aux;
  if (parent == t) {
    thread_alive = true;
  }
}

static void reset_flag(void) {
  thread_alive = false;
}


