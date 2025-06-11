#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <list.h>
#include "threads/thread.h"
#include "threads/synch.h"

typedef int pid_t;

/* Process load status */
#define NOT_LOADED 0
#define LOAD_SUCCESS 1
#define LOAD_FAIL 2

#define MAX_OPEN_FILES 128

struct child_process {
    pid_t pid;                     
    struct thread *parent;          
    struct list_elem elem;          
    bool waited;                    
    int status;                     
    int load;                       
    struct semaphore load_sema;     
    struct semaphore wait_sema;     
};

struct process_file {
    int fd;
    struct file *file;
    struct list_elem elem;
};


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
int process_add_file(struct file *f, struct thread *t);
struct file* process_get_file(int fd, struct thread *t);
void process_close_file(int fd, struct thread *t);
struct child_process *get_child_process(pid_t pid, struct thread *t);
void remove_child_process(struct child_process *cp);
void remove_all_child_processes(struct thread *t);

#endif /* userprog/process.h */
