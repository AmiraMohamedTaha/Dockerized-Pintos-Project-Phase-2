#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"


static void push_stack(int order, void **esp, char *token, char **argv, int argc);

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp, char** save_ptr);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
	char *fn_copy;
	tid_t tid;

	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);
	struct child_process *cp = malloc(sizeof(struct child_process));
	if (cp == NULL) {
		palloc_free_page (fn_copy);
		return TID_ERROR;
	}

	cp->parent = thread_current();
	cp->waited = false;
	cp->load = NOT_LOADED;
	sema_init(&cp->load_sema, 0);
	sema_init(&cp->wait_sema, 0);

	char *save_ptr;
	char *exec_name = malloc(strlen(file_name) + 1);
	if (exec_name == NULL) {
		palloc_free_page(fn_copy);
		free(cp);
		return TID_ERROR;
	}
	strlcpy(exec_name, file_name, strlen(file_name) + 1);
	strtok_r(exec_name, " ", &save_ptr);

	tid = thread_create(exec_name, PRI_DEFAULT, start_process, fn_copy);
	free(exec_name);
	
	if (tid == TID_ERROR) {
		palloc_free_page(fn_copy);
		free(cp);
		return TID_ERROR;
	}

	cp->pid = tid;
	list_push_back(&thread_current()->children, &cp->elem);
	sema_down(&cp->load_sema);
	if (cp->load == LOAD_FAIL) {
		remove_child_process(cp);
		return TID_ERROR;
	}

	return tid;
}

static void
start_process (void *file_name_)
{
	char *file_name = file_name_;
	struct intr_frame if_;
	bool success;
	struct thread *cur = thread_current();
	struct child_process *cp = NULL;

	if (cur->parent != NULL) {
		cp = get_child_process(cur->tid, cur->parent);
		if (cp != NULL) {
			cur->cp = cp;
			cp->load = NOT_LOADED;
		}
	}

	char *save_ptr;
	file_name = strtok_r(file_name, " ", &save_ptr);
	memset(&if_, 0, sizeof if_);
	if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
	if_.cs = SEL_UCSEG;
	if_.eflags = FLAG_IF | FLAG_MBS;
	success = load(file_name, &if_.eip, &if_.esp, &save_ptr);

	if (cp != NULL) {
		cp->load = success ? LOAD_SUCCESS : LOAD_FAIL;
		sema_up(&cp->load_sema);
	}

	/* If load failed, quit */
	palloc_free_page(file_name);
	if (!success) {
		
		if (cp != NULL) {
			cp->status = -1;
		}
		
		if (!cur->exit_printed) { // Print exit message for tests to check */
			printf("%s: exit(-1)\n", cur->name);
			cur->exit_printed = true;
		}
		
		thread_exit();
	}

	asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
	NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
	struct thread *cur = thread_current();
	struct child_process *cp = get_child_process(child_tid, cur);
	
	if (cp == NULL || cp->waited)
		return -1;
	
	cp->waited = true;
	
	sema_down(&cp->wait_sema); //Wait for child to exit
	int status = cp->status;
	remove_child_process(cp);
	
	return status;
}

void
process_exit (void)
{
	struct thread *cur = thread_current();

	if (cur->executable != NULL) {
		file_close(cur->executable);
	}
	
	/* Close all open files */
	for (int i = 0; i < MAX_OPEN_FILES; i++) {
		if (cur->open_files[i] != NULL) {
			file_close(cur->open_files[i]);
			cur->open_files[i] = NULL;
		}
	}
	
	/* Signal parent if waiting */
	if (cur->cp != NULL) {
		sema_up(&cur->cp->wait_sema);
	}
	remove_all_child_processes(cur);
	
	uint32_t *pd = cur->pagedir; //Free the page directory
	if (pd != NULL) {
		cur->pagedir = NULL;
		pagedir_activate(NULL);
		pagedir_destroy(pd);
	}
	
	if (!cur->exit_printed) {    // Print exit message only if not already printed
		printf("%s: exit(%d)\n", cur->name, cur->cp != NULL ? cur->cp->status : -1);
		cur->exit_printed = true;
	}
}


void
process_activate (void)
{
	struct thread *t = thread_current ();

	/* Activate thread's page tables. */
	pagedir_activate (t->pagedir);

	/* Set thread's kernel stack for use in processing
     interrupts. */
	tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
	unsigned char e_ident[16];
	Elf32_Half    e_type;
	Elf32_Half    e_machine;
	Elf32_Word    e_version;
	Elf32_Addr    e_entry;
	Elf32_Off     e_phoff;
	Elf32_Off     e_shoff;
	Elf32_Word    e_flags;
	Elf32_Half    e_ehsize;
	Elf32_Half    e_phentsize;
	Elf32_Half    e_phnum;
	Elf32_Half    e_shentsize;
	Elf32_Half    e_shnum;
	Elf32_Half    e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
	Elf32_Word p_type;
	Elf32_Off  p_offset;
	Elf32_Addr p_vaddr;
	Elf32_Addr p_paddr;
	Elf32_Word p_filesz;
	Elf32_Word p_memsz;
	Elf32_Word p_flags;
	Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* redefined setup_stack to take save_ptr as argument */
static bool setup_stack (void **esp, const char* file_name,	char** save_ptr);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp, char **save_ptr)
{
	struct thread *t = thread_current ();
	struct Elf32_Ehdr ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pagedir = pagedir_create ();
	if (t->pagedir == NULL)
		goto done;
	process_activate ();

	/* Open executable file. */
	lock_acquire(&filesys_lock);
	file = filesys_open (file_name);
	if (file == NULL)
	{
		printf ("load: %s: open failed\n", file_name);
		lock_release(&filesys_lock);
		goto done;
	}

	/* Deny writes to executable */
	file_deny_write(file);
	t->executable = file;
	lock_release(&filesys_lock);

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 3
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
			|| ehdr.e_phnum > 1024)
	{
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}


	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++)
	{
		struct Elf32_Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type)
		{
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment (&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint32_t file_page = phdr.p_offset & ~PGMASK;
				uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint32_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
					/* Normal segment.
                     Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
							- read_bytes);
				}
				else
				{
					/* Entirely zero.
                     Don't read anything from disk. */
					read_bytes = 0;
					zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment (file, file_page, (void *) mem_page,
						read_bytes, zero_bytes, writable))
					goto done;
			}
			else
				goto done;
			break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (esp, file_name, save_ptr))
		goto done;

	/* Start address. */
	*eip = (void (*) (void)) ehdr.e_entry;

	success = true;

	done:
	/* We arrive here whether the load is successful or not. */
	return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (Elf32_Off) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
     user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
     address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
		{
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable))
		{
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char* file_name, char** save_ptr) 
{
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage == NULL)
		return false;

	success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
	if (!success) {
		palloc_free_page (kpage);
		return false;
	}

	*esp = PHYS_BASE;

	/* Parse arguments */
	char **argv = malloc(2 * sizeof(char *));
	if (argv == NULL) {
		palloc_free_page (kpage);
		return false;
	}

	int argc = 0;
	int argv_size = 2;
	size_t total_len = 0;
	char *token = (char *) file_name;

	/* First pass: count arguments and total length */
	while (token != NULL) {
		size_t len = strlen(token) + 1;
		total_len += len;

		if (argc >= argv_size) {
			char **new_argv = realloc(argv, (argv_size * 2) * sizeof(char *));
			if (new_argv == NULL) {
				free(argv);
				palloc_free_page (kpage);
				return false;
			}
			argv = new_argv;
			argv_size *= 2;
		}

		argv[argc] = token;
		argc++;
		token = strtok_r (NULL, " ", save_ptr);
	}

	/* Push strings onto stack */
	for (int i = argc - 1; i >= 0; i--) {
		size_t len = strlen(argv[i]) + 1;
		*esp -= len;
		if (*esp < (void *)(PHYS_BASE - PGSIZE)) {
			free(argv);
			palloc_free_page (kpage);
			return false;
		}
		memcpy(*esp, argv[i], len);
		argv[i] = *esp;  /* Update argv to point to new string location */
	}

	/* Word-align to 4 bytes */
	*esp = (void *)((unsigned int)(*esp) & ~3);

	/* Push argv[argc] (null) */
	*esp -= sizeof(char *);
	if (*esp < (void *)(PHYS_BASE - PGSIZE)) {
		free(argv);
		palloc_free_page (kpage);
		return false;
	}
	*(char **)*esp = NULL;

	/* Push argv[0] through argv[argc-1] */
	for (int i = argc - 1; i >= 0; i--) {
		*esp -= sizeof(char *);
		if (*esp < (void *)(PHYS_BASE - PGSIZE)) {
			free(argv);
			palloc_free_page (kpage);
			return false;
		}
		*(char **)*esp = argv[i];
	}

	/* Push argv */
	char **argv_addr = *esp;
	*esp -= sizeof(char **);
	if (*esp < (void *)(PHYS_BASE - PGSIZE)) {
		free(argv);
		palloc_free_page (kpage);
		return false;
	}
	*(char ***)*esp = argv_addr;

	/* Push argc */
	*esp -= sizeof(int);
	if (*esp < (void *)(PHYS_BASE - PGSIZE)) {
		free(argv);
		palloc_free_page (kpage);
		return false;
	}
	*(int *)*esp = argc;

	/* Push fake return address */
	*esp -= sizeof(void *);
	if (*esp < (void *)(PHYS_BASE - PGSIZE)) {
		free(argv);
		palloc_free_page (kpage);
		return false;
	}
	*(void **)*esp = NULL;

	free(argv);
	return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
     address, then map our page there. */
	return (pagedir_get_page (t->pagedir, upage) == NULL
			&& pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* final argument push for the stack */
static void 
push_stack(int order, void **esp, char *token UNUSED, char **argv UNUSED, int argc UNUSED)
{
    ASSERT(esp != NULL);
    ASSERT(*esp != NULL);
    
    switch(order) {
        case 1:
            /* Push argv */
            if (*esp >= PHYS_BASE || *esp < (void *)(PHYS_BASE - PGSIZE)) {
                return;  /* Stack overflow protection */
            }
            token = *esp;
            *esp -= sizeof(void *);
            memcpy(*esp, &token, sizeof(void *));
            break;

        case 2:
            /* Push argc */
            if (*esp >= PHYS_BASE || *esp < (void *)(PHYS_BASE - PGSIZE)) {
                return;
            }
            *esp -= sizeof(int);
            memcpy(*esp, &argc, sizeof(int));
            break;

        case 3:
            /* Push return address (null) */
            if (*esp >= PHYS_BASE || *esp < (void *)(PHYS_BASE - PGSIZE)) {
                return;
            }
            *esp -= sizeof(void *);
            void *null_ptr = NULL;
            memcpy(*esp, &null_ptr, sizeof(void *));
            break;
    }
}

struct child_process *
get_child_process(pid_t pid, struct thread *t) 
{
	struct list_elem *e;
	
	for (e = list_begin(&t->children); e != list_end(&t->children); e = list_next(e)) {
		struct child_process *cp = list_entry(e, struct child_process, elem);
		if (cp->pid == pid)
			return cp;
	}
	return NULL;
}

void 
remove_child_process(struct child_process *cp) 
{
	if (cp != NULL) {
		list_remove(&cp->elem);
		free(cp);
	}
}

void 
remove_all_child_processes(struct thread *t) 
{
	struct list_elem *e;
	
	while (!list_empty(&t->children)) {
		e = list_pop_front(&t->children);
		struct child_process *cp = list_entry(e, struct child_process, elem);
		remove_child_process(cp);
	}
}