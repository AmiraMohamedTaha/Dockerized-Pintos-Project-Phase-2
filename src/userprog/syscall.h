#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/process.h"  
#include "filesys/file.h"

extern struct lock filesys_lock;

void syscall_init (void);

void halt (void);
void exit (int status);
tid_t exec (const char *cmd_line);  
int wait (tid_t pid);               
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);

#endif /* userprog/syscall.h */
