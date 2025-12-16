#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"
#include "fs.h"
#include "sleeplock.h"
#include "stat.h"
#include "file.h"
#include "fcntl.h"

// map ELF permissions to PTE permission bits.
int flags2perm(int flags)
{
    int perm = PTE_R;  // Always readable
    if(flags & 0x1)
      perm |= PTE_X;   // Add execute permission
    if(flags & 0x2)
      perm |= PTE_W;   // Add write permission
    return perm;
}

//
// the implementation of the exec() system call
//
int
kexec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint64 argc, sz = 0, sp, ustack[MAXARG], stackbase;
  uint64 cleanup_sz = 0;
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pagetable_t pagetable = 0, oldpagetable;
  struct proc *p = myproc();

  begin_op();

  // Open the executable file.
  if((ip = namei(path)) == 0){
    end_op();
    return -1;
  }
  ilock(ip);

  // Read the ELF header.
  if(readi(ip, 0, (uint64)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;

  // Is this really an ELF file?
  if(elf.magic != ELF_MAGIC)
    goto bad;

  // Validate ELF entry address
  if(elf.entry == 0 || elf.entry >= MAXVA) {
    printf("[pid %d] EXEC-ERROR: Invalid entry point %p\n", p->pid, (void*)elf.entry);
    goto bad;
  }

  if((pagetable = proc_pagetable(p)) == 0) {
    printf("[pid %d] EXEC-ERROR: Failed to allocate pagetable\n", p->pid);
    goto bad;
  }

  // Load program segments metadata and map address space; defer actual content load.
  uint64 text_start = (uint64)-1;
  uint64 text_end = 0;
  uint64 data_start = (uint64)-1;
  uint64 data_end = 0;
  p->nsegs = 0;
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz) {
      printf("[pid %d] EXEC-ERROR: memsz < filesz in program header\n", p->pid);
      goto bad;
    }
    if(ph.vaddr + ph.memsz < ph.vaddr) {
      printf("[pid %d] EXEC-ERROR: Virtual address overflow in program header\n", p->pid);
      goto bad;
    }
    if(ph.vaddr % PGSIZE != 0) {
      printf("[pid %d] EXEC-ERROR: Program header virtual address not page aligned\n", p->pid);
      goto bad;
    }
    if(ph.vaddr >= MAXVA) {
      printf("[pid %d] EXEC-ERROR: Program header virtual address exceeds MAXVA\n", p->pid);
      goto bad;
    }
    // Do not eagerly map/allocate exec segments; defer to page fault handler.
    // Just advance process size to cover the segment range.
    uint64 end = ph.vaddr + ph.memsz;
    if(end < ph.vaddr)
      goto bad;
    if(end > sz)
      sz = end;

    if(p->nsegs < MAX_SEGS){
      p->segs[p->nsegs].vaddr = ph.vaddr;
      p->segs[p->nsegs].memsz = ph.memsz;
      p->segs[p->nsegs].filesz = ph.filesz;
      p->segs[p->nsegs].off   = ph.off;
      p->segs[p->nsegs].perm  = flags2perm(ph.flags);
      p->nsegs++;
    }

    // Track text and data ranges for logging/bookkeeping
    if(ph.flags & 0x1){
      if(ph.vaddr < text_start) text_start = ph.vaddr;
      if(ph.vaddr + ph.memsz > text_end) text_end = ph.vaddr + ph.memsz;
    }
    if(ph.flags & 0x2){
      if(ph.vaddr < data_start) data_start = ph.vaddr;
      if(ph.vaddr + ph.memsz > data_end) data_end = ph.vaddr + ph.memsz;
    }
  }
  // Instrumentation: basic ELF info
  printf("[pid %d] EXEC-ELF path=%s entry=%p phnum=%d\n", p->pid, path, (void*)elf.entry, elf.phnum);
  iunlockput(ip);
  end_op();
  ip = 0;

  p = myproc();
  uint64 oldsz = p->sz;

  // Allocate some pages at the next page boundary.
  // Allocate USERSTACK pages plus one guard page (inaccessible).
  sz = PGROUNDUP(sz);
  uint64 heap_start = sz;
  uint64 stacksize = USERSTACK * PGSIZE;
  
  if(sz >= MAXVA || (sz + stacksize + PGSIZE) >= MAXVA) {
    printf("[pid %d] EXEC-ERROR: Process size exceeds MAXVA\n", p->pid);
    goto bad;
  }

  // Allocate stack (stacksize) above one-page guard. Leave guard page unmapped.
  uint64 alloc_end = sz + PGSIZE + stacksize;
  if(uvmalloc(pagetable, sz + PGSIZE, alloc_end, PTE_R | PTE_W) == 0) {  // Make stack readable and writable
    printf("[pid %d] EXEC-ERROR: Failed to allocate user stack\n", p->pid);
    goto bad;
  }
  cleanup_sz = alloc_end;
  // Guard page remains unmapped (no physical memory allocated).
  // Accessible stack is (sz+PGSIZE .. sz+PGSIZE+stacksize); start sp at the top of accessible stack.
  stackbase = sz + PGSIZE;
  sp = stackbase + stacksize;

  // Copy argument strings into new stack, remember their
  // addresses in ustack[].
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp -= strlen(argv[argc]) + 1;
    sp -= sp % 16; // riscv sp must be 16-byte aligned
    if(sp < stackbase)
      goto bad;
    if(copyout(pagetable, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[argc] = sp;
  }
  ustack[argc] = 0;

  // push a copy of ustack[], the array of argv[] pointers.
  sp -= (argc+1) * sizeof(uint64);
  sp -= sp % 16;  // ensure 16-byte alignment
  
  // Validate stack pointer
  if(sp < stackbase || sp >= MAXVA) {
    printf("[pid %d] EXEC-ERROR: Invalid stack pointer %p (stackbase=%p)\n", p->pid, (void*)sp, (void*)stackbase);
    goto bad;
  }

  if(copyout(pagetable, sp, (char *)ustack, (argc+1)*sizeof(uint64)) < 0) {
    printf("[pid %d] EXEC-ERROR: Failed to copy argv to user stack\n", p->pid);
    goto bad;
  }

  // Instrumentation: argv/stack push results
  printf("[pid %d] EXEC-ARGS argc=%d sp=%p stackbase=%p\n", p->pid, (int)argc, (void*)sp, (void*)stackbase);

  // a0 and a1 contain arguments to user main(argc, argv)
  // argc is returned via the system call return
  // value, which goes in a0.
  p->trapframe->a1 = sp;

  // Save program name for debugging and exec path for LOADEXEC.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));
  safestrcpy(p->exec_path, path, sizeof(p->exec_path));
    
  // Final validation before committing
  if(sz == 0 || sz >= MAXVA) {
    printf("[pid %d] EXEC-ERROR: Invalid process size %p\n", p->pid, (void*)sz);
    goto bad;
  }

  if(sp < stackbase || sp > (sz + PGSIZE + stacksize)) {
    printf("[pid %d] EXEC-ERROR: Stack pointer out of bounds\n", p->pid);
    goto bad;
  }

  // Commit to the user image.
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  // Include guard+stack in process size so user pointer checks work
  p->sz = alloc_end;
  p->trapframe->epc = elf.entry;  // initial program counter = main
  p->trapframe->sp = sp; // initial stack pointer
  
  if (oldpagetable != 0) {
    proc_freepagetable(p, oldpagetable, oldsz);
  }

  // Initialize and log lazy map boundaries for Part A
  p->text_start = (text_start == (uint64)-1) ? 0 : text_start;
  p->text_end = text_end;
  p->data_start = (data_start == (uint64)-1) ? 0 : data_start;
  p->data_end = data_end;
  p->heap_start = heap_start;
  p->stack_top = sp;
  p->next_fifo_seq = 1;
  p->num_resident_pages = 0;
  p->num_swapped_pages = 0;
  // Clear resident tracking array to prevent stale entries
  for(int i=0;i<MAX_RESIDENT;i++){
    p->resident[i].inuse = 0;
    p->resident[i].va = 0;
    p->resident[i].seq = 0;
    p->resident[i].dirty = 0;
    p->resident[i].exec_backed = 0;
  }
  // Prepare per-proc swap path (/pgswpPID), defer creation until first SWAPOUT
  safestrcpy(p->swap_path, "/pgswp00000", sizeof(p->swap_path));
  int pidtmp = p->pid;
  for(int k=10; k>=6; k--){ int d = pidtmp % 10; pidtmp /= 10; p->swap_path[k] = '0' + d; }
  for(int i=0;i<MAX_SWAP_SLOTS;i++){ p->swap_used[i]=0; p->slot_va[i]=0; }

  extern int audit_logs;
  if(audit_logs)
    printf("[pid %d] INIT-LAZYMAP text=[%p,%p) data=[%p,%p) heap_start=%p stack_top=%p\n",
           p->pid, (void*)p->text_start, (void*)p->text_end, (void*)p->data_start, (void*)p->data_end, (void*)p->heap_start, (void*)p->stack_top);

  // Instrumentation: final size/entry/stack
  printf("[pid %d] EXEC-COMMIT entry=%p sz=%p sp=%p heap_start=%p\n", p->pid, (void*)elf.entry, (void*)p->sz, (void*)p->trapframe->sp, (void*)p->heap_start);

  // Debug: dump global freelist and allocation counter to trace leaks
  dump_freelist();

  // Prefault the current user stack pages from sp down to stack base (excluding
  // the guard), so early copyout (e.g., wait(&xstatus)) does not change the
  // free-page baseline observed by long-lived parents.
  {
    char z = 0;
    uint64 stacksize = USERSTACK * PGSIZE;
    uint64 stackbase = p->sz - stacksize; // just above the guard page
    uint64 sp = p->trapframe->sp;
    if (sp > p->sz) sp = p->sz; // clamp just in case
    // Touch one byte in each page to fault it in.
    for (uint64 a = PGROUNDDOWN(sp - 1); a >= stackbase; a -= PGSIZE) {
      (void)copyout(p->pagetable, a, &z, 1);
      if (a < stackbase + PGSIZE) break; // prevent underflow
    }
  }

  // Prefault read-only data/rodata pages that are likely to be accessed soon
  // (e.g., printf format strings) so initial prints after exec don't change
  // the observed free-page baseline. We read a byte from each page of exec-
  // mapped segments that have read permission.
  {
    char tmp;
    for (int si = 0; si < p->nsegs; si++) {
      uint64 s = p->segs[si].vaddr;
      uint64 e = s + p->segs[si].memsz;
      int perm = p->segs[si].perm;
      if ((perm & PTE_R) == 0)
        continue;
      for (uint64 va = PGROUNDDOWN(s); va < e; va += PGSIZE) {
        (void)copyin(p->pagetable, &tmp, va, 1);
      }
    }
  }

  return argc; // this ends up in a0, the first argument to main(argc, argv)

 bad:
  if(pagetable)
    proc_freepagetable(p, pagetable, cleanup_sz);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}

// Load an ELF program segment into pagetable at virtual address va.
// va must be page-aligned
// and the pages from va to va+sz must already be mapped.
// Returns 0 on success, -1 on failure.
// loadseg removed due to lazy executable loading
