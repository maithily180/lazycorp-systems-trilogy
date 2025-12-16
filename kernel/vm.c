#include "param.h"
#include "types.h"
#include "memlayout.h"
#include "elf.h"
#include "riscv.h"
#include "defs.h"
#include "spinlock.h"
#include "proc.h"
#include "fs.h"
#include "sleeplock.h"
#include "stat.h"
#include "file.h"

/*
 * the kernel's page table.
 */
pagetable_t kernel_pagetable;

extern char etext[];  // kernel.ld sets this to end of kernel code.

extern char trampoline[]; // trampoline.S

// Make a direct-map page table for the kernel.
pagetable_t
kvmmake(void)
{
  pagetable_t kpgtbl;

  kpgtbl = (pagetable_t) kalloc();
  memset(kpgtbl, 0, PGSIZE);

  // uart registers
  kvmmap(kpgtbl, UART0, UART0, PGSIZE, PTE_R | PTE_W);

  // virtio mmio disk interface
  kvmmap(kpgtbl, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);

  // PLIC
  kvmmap(kpgtbl, PLIC, PLIC, 0x4000000, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  kvmmap(kpgtbl, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  kvmmap(kpgtbl, (uint64)etext, (uint64)etext, PHYSTOP-(uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  kvmmap(kpgtbl, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);

  // allocate and map a kernel stack for each process.
  proc_mapstacks(kpgtbl);
  
  return kpgtbl;
}

// add a mapping to the kernel page table.
// only used when booting.
// does not flush TLB or enable paging.
void
kvmmap(pagetable_t kpgtbl, uint64 va, uint64 pa, uint64 sz, int perm)
{
  if(mappages(kpgtbl, va, sz, pa, perm) != 0)
    panic("kvmmap");
}

// Initialize the kernel_pagetable, shared by all CPUs.
void
kvminit(void)
{
  kernel_pagetable = kvmmake();
}

// Switch the current CPU's h/w page table register to
// the kernel's page table, and enable paging.
void
kvminithart()
{
  // wait for any previous writes to the page table memory to finish.
  sfence_vma();

  w_satp(MAKE_SATP(kernel_pagetable));

  // flush stale entries from the TLB.
  sfence_vma();
}

// Return the address of the PTE in page table pagetable
// that corresponds to virtual address va.  If alloc!=0,
// create any required page-table pages.
//
// The risc-v Sv39 scheme has three levels of page-table
// pages. A page-table page contains 512 64-bit PTEs.
// A 64-bit virtual address is split into five fields:
//   39..63 -- must be zero.
//   30..38 -- 9 bits of level-2 index.
//   21..29 -- 9 bits of level-1 index.
//   12..20 -- 9 bits of level-0 index.
//    0..11 -- 12 bits of byte offset within the page.
pte_t *
walk(pagetable_t pagetable, uint64 va, int alloc)
{
  if(va >= MAXVA)
    panic("walk");

  for(int level = 2; level > 0; level--) {
    pte_t *pte = &pagetable[PX(level, va)];
    if(*pte & PTE_V) {
      pagetable = (pagetable_t)PTE2PA(*pte);
    } else {
      if(!alloc || (pagetable = (pde_t*)kalloc()) == 0)
        return 0;
      memset(pagetable, 0, PGSIZE);
      *pte = PA2PTE(pagetable) | PTE_V;
    }
  }
  return &pagetable[PX(0, va)];
}

// Look up a virtual address, return the physical address,
// or 0 if not mapped.
// Can only be used to look up user pages.
uint64
walkaddr(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  uint64 pa;

  if(va >= MAXVA)
    return 0;

  pte = walk(pagetable, va, 0);
  if(pte == 0)
    return 0;
  if((*pte & PTE_V) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  pa = PTE2PA(*pte);
  return pa;
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa.
// va and size MUST be page-aligned.
// Returns 0 on success, -1 if walk() couldn't
// allocate a needed page-table page.
int
mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
  uint64 a, last;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("mappages: va not aligned");

  if((size % PGSIZE) != 0)
    panic("mappages: size not aligned");

  if(size == 0)
    panic("mappages: size");
  
  a = va;
  last = va + size - PGSIZE;
  for(;;){
    if((pte = walk(pagetable, a, 1)) == 0)
      return -1;
    if(*pte & PTE_V)
      panic("mappages: remap");
    *pte = PA2PTE(pa) | perm | PTE_V;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// create an empty user page table.
// returns 0 if out of memory.
pagetable_t
uvmcreate()
{
  pagetable_t pagetable;
  pagetable = (pagetable_t) kalloc();
  if(pagetable == 0)
    return 0;
  memset(pagetable, 0, PGSIZE);
  return pagetable;
}

// Remove npages of mappings starting from va. va must be
// page-aligned. It's OK if the mappings don't exist.
// Optionally free the physical memory.
void
uvmunmap(pagetable_t pagetable, uint64 va, uint64 npages, int do_free)
{
  uint64 a;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("uvmunmap: not aligned");

  for(a = va; a < va + npages*PGSIZE; a += PGSIZE){
    // Find the level-0 PTE for this VA.
    pte = walk(pagetable, a, 0);
    if(pte == 0)
      continue; // nothing mapped for this VA
    if((*pte & PTE_V) == 0)
      continue; // PTE not valid
    // Only free leaf mappings (R/W/X set). If it's not a leaf, skip it;
    // page-table pages are freed by freewalk().
    if(((*pte) & (PTE_R|PTE_W|PTE_X)) == 0)
      continue;
    if(do_free){
      uint64 pa = PTE2PA(*pte);
      kfree((void*)pa);
    }
    *pte = 0;
  }
}

// Allocate PTEs and physical memory to grow a process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
uint64
uvmalloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz, int xperm)
{
  char *mem;
  uint64 a;

  if(newsz < oldsz)
    return oldsz;

  oldsz = PGROUNDUP(oldsz);
  for(a = oldsz; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pagetable, a, PGSIZE, (uint64)mem, PTE_R|PTE_U|xperm) != 0){
      kfree(mem);
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
  }
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
uint64
uvmdealloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  if(newsz >= oldsz)
    return oldsz;

  if(PGROUNDUP(newsz) < PGROUNDUP(oldsz)){
    int npages = (PGROUNDUP(oldsz) - PGROUNDUP(newsz)) / PGSIZE;
    uvmunmap(pagetable, PGROUNDUP(newsz), npages, 1);
  }
  // After unmapping, proactively free empty page-table subtrees so that
  // temporary growth/shrink cycles (e.g., countfree()) don't leave extra
  // intermediate page-table pages around and skew the amount of free memory.
  // This mirrors freewalk(), but preserves the root page table.
  extern int vm_shrink_and_check(pagetable_t);
  (void)vm_shrink_and_check(pagetable);
  return newsz;
}

// Recursively drop empty non-leaf page tables.
// Returns 1 if the subtree rooted at 'pt' is now empty (no valid entries).
static int vm_shrink_and_check_impl(pagetable_t pt){
  int any = 0; // whether any valid entry remains
  for(int i = 0; i < 512; i++){
    pte_t pte = pt[i];
    if((pte & PTE_V) == 0)
      continue;
    // Leaf mappings (R/W/X set) must not be freed here; they should
    // already have been unmapped above. If we still see a leaf, keep it.
    if(pte & (PTE_R|PTE_W|PTE_X)){
      any = 1;
      continue;
    }
    // Non-leaf: try to shrink the child.
    pagetable_t child = (pagetable_t)PTE2PA(pte);
    if(vm_shrink_and_check_impl(child)){
      // Child became empty: free and clear the entry.
      kfree((void*)child);
      pt[i] = 0;
    } else {
      any = 1;
    }
  }
  return any == 0;
}

int vm_shrink_and_check(pagetable_t pt){
  return vm_shrink_and_check_impl(pt);
}

// Recursively free page-table pages.
// All leaf mappings must already have been removed.
void
freewalk(pagetable_t pagetable)
{
  // there are 2^9 = 512 PTEs in a page table.
  for(int i = 0; i < 512; i++){
    pte_t pte = pagetable[i];
    if((pte & PTE_V) && (pte & (PTE_R|PTE_W|PTE_X)) == 0){
      // this PTE points to a lower-level page table.
      uint64 child = PTE2PA(pte);
      freewalk((pagetable_t)child);
      pagetable[i] = 0;
    }
  }
  kfree((void*)pagetable);
}


// Free user memory pages,
// then free page-table pages.
void
uvmfree(pagetable_t pagetable, uint64 sz)
{
  if(sz > 0)
    uvmunmap(pagetable, 0, PGROUNDUP(sz)/PGSIZE, 1);
  freewalk(pagetable);
}

// Given a parent process's page table, copy
// its memory into a child's page table.
// Copies both the page table and the
// physical memory.
// returns 0 on success, -1 on failure.
// frees any allocated pages on failure.
int
uvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa, i;
  uint flags;
  char *mem;

  // Copy pages in the range [0, sz) - this includes eagerly allocated pages like stack
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walk(old, i, 0)) == 0)
      continue;   // page table entry hasn't been allocated
    if((*pte & PTE_V) == 0)
      continue;   // physical page hasn't been allocated
    pa = PTE2PA(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto err;
    memmove(mem, (char*)pa, PGSIZE);
    if(mappages(new, i, PGSIZE, (uint64)mem, flags) != 0){
      kfree(mem);
      goto err;
    }
  }
  return 0;

 err:
  uvmunmap(new, 0, i / PGSIZE, 1);
  return -1;
}

// mark a PTE invalid for user access.
// used by exec for the user stack guard page.
void
uvmclear(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  
  pte = walk(pagetable, va, 0);
  if(pte == 0)
    panic("uvmclear");
  *pte &= ~PTE_U;
}

// Copy from kernel to user.
// Copy len bytes from src to virtual address dstva in a given page table.
// Return 0 on success, -1 on error.
int
copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
  uint64 n, va0, pa0;
  pte_t *pte;

  while(len > 0){
    va0 = PGROUNDDOWN(dstva);
    if(va0 >= MAXVA)
      return -1;
  
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0) {
      if((pa0 = vmfault(pagetable, va0, 0)) == 0) {
        return -1;
      }
    }

    pte = walk(pagetable, va0, 0);
    // forbid copyout over read-only user text pages.
    if((*pte & PTE_W) == 0)
      return -1;
      
    n = PGSIZE - (dstva - va0);
    if(n > len)
      n = len;
    memmove((void *)(pa0 + (dstva - va0)), src, n);

    len -= n;
    src += n;
    dstva = va0 + PGSIZE;
  }
  return 0;
}

// Copy from user to kernel.
// Copy len bytes to dst from virtual address srcva in a given page table.
// Return 0 on success, -1 on error.
int
copyin(pagetable_t pagetable, char *dst, uint64 srcva, uint64 len)
{
  uint64 n, va0, pa0;

  while(len > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0) {
      if((pa0 = vmfault(pagetable, va0, 1)) == 0) {
        return -1;
      }
    }
    n = PGSIZE - (srcva - va0);
    if(n > len)
      n = len;
    memmove(dst, (void *)(pa0 + (srcva - va0)), n);

    len -= n;
    dst += n;
    srcva = va0 + PGSIZE;
  }
  return 0;
}

// Copy a null-terminated string from user to kernel.
// Copy bytes to dst from virtual address srcva in a given page table,
// until a '\0', or max.
// Return 0 on success, -1 on error.
int
copyinstr(pagetable_t pagetable, char *dst, uint64 srcva, uint64 max)
{
  uint64 n, va0, pa0;
  int got_null = 0;

  while(got_null == 0 && max > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0) {
      if((pa0 = vmfault(pagetable, va0, 1)) == 0) {
        return -1;
      }
    }
    n = PGSIZE - (srcva - va0);
    if(n > max)
      n = max;

    char *p = (char *) (pa0 + (srcva - va0));
    while(n > 0){
      if(*p == '\0'){
        *dst = '\0';
        got_null = 1;
        break;
      } else {
        *dst = *p;
      }
      --n;
      --max;
      p++;
      dst++;
    }

    srcva = va0 + PGSIZE;
  }
  if(got_null){
    return 0;
  } else {
    return -1;
  }
}

// allocate and map user memory if process is referencing a page
// that was lazily allocated in sys_sbrk().
// returns 0 if va is invalid or already mapped, or if
// out of physical memory, and physical address if successful.
uint64
vmfault(pagetable_t pagetable, uint64 va, int read)
{
  uint64 mem;
  struct proc *p = myproc();

  // Disallow mapping beyond the maximum user virtual address.
  if (va >= MAXVA)
    return 0;

  if (va >= p->sz)
    return 0;
  va = PGROUNDDOWN(va);
  // Disallow mapping the guard page beneath the user stack.
  // exec() sets p->sz = heap_end + PGSIZE (guard) + USERSTACK*PGSIZE (stack).
  // The guard page range is [p->sz - USERSTACK*PGSIZE - PGSIZE, p->sz - USERSTACK*PGSIZE).
  {
    uint64 stacksize = USERSTACK * PGSIZE;
    uint64 guard_start = p->sz - stacksize - PGSIZE;
    uint64 guard_end   = p->sz - stacksize;
    if (va >= guard_start && va < guard_end)
      return 0;
  }
  if(ismapped(pagetable, va)) {
    return 0;
  }
  // Determine if this is exec-mapped region: load from executable
  int is_exec_region = ((p->text_start < p->text_end) && (va >= p->text_start && va < p->text_end)) ||
                       ((p->data_start < p->data_end) && (va >= p->data_start && va < p->data_end));
  mem = (uint64) kalloc();
  if(mem == 0)
  {
    // memory full: start eviction for this process using FIFO
    struct proc *p = myproc();
    printf("[pid %d] MEMFULL\n", p->pid);
    int victim = -1;
    int minseq = 0x7fffffff;
    for(int i=0;i<MAX_RESIDENT;i++){
      if(p->resident[i].inuse && p->resident[i].seq < minseq){
        minseq = p->resident[i].seq;
        victim = i;
      }
    }
    if(victim >= 0){
      uint64 vva = PGROUNDDOWN(p->resident[victim].va);
      printf("[pid %d] VICTIM va=%p seq=%d algo=FIFO\n", p->pid, (void*)vva, p->resident[victim].seq);
      // inspect PTE to decide clean/dirty
      pte_t *vpte = walk(p->pagetable, vva, 0);
      int is_dirty = (vpte && (*vpte & PTE_W));
      printf("[pid %d] EVICT  va=%p state=%s\n", p->pid, (void*)vva, is_dirty?"dirty":"clean");
      if(!is_dirty && p->resident[victim].exec_backed){
        // clean + exec-backed: discard
        printf("[pid %d] DISCARD va=%p\n", p->pid, (void*)vva);
        printf("[pid %d] DEBUG: kalloc_count before DISCARD uvmunmap = %d\n", p->pid, get_kalloc_count());
        uvmunmap(p->pagetable, vva, 1, 1);
        printf("[pid %d] DEBUG: kalloc_count after DISCARD uvmunmap = %d\n", p->pid, get_kalloc_count());
        p->resident[victim].inuse = 0;
        p->num_resident_pages--;
        // try allocation again
        mem = (uint64)kalloc();
        if(mem == 0) return 0;
      } else {
        // allocate a swap slot
        int slot = -1;
        for(int s=0;s<MAX_SWAP_SLOTS;s++) if(!p->swap_used[s]){ slot = s; break; }
        if(slot < 0){
          printf("[pid %d] SWAPFULL\n", p->pid);
          printf("[pid %d] KILL swap-exhausted\n", p->pid);
          setkilled(p);
          return 0;
        }
        // write page to swap file
        // lazily create swap file if it doesn't exist; then write page
        if(p->swap_path[0]){
          begin_op();
          char name[DIRSIZ]; char parent[MAXPATH];
          safestrcpy(parent, p->swap_path, sizeof(parent));
          struct inode *dp = nameiparent(parent, name);
          if(dp){
            ilock(dp);
            struct inode *exist = dirlookup(dp, name, 0);
            if(!exist){
              struct inode *sip = ialloc(dp->dev, T_FILE);
              if(sip){ ilock(sip); sip->nlink = 1; iupdate(sip); dirlink(dp, name, sip->inum); iunlockput(sip); }
            } else { iunlockput(exist); }
            iunlockput(dp);
          }
          end_op();
          struct inode *sip2 = namei(p->swap_path);
          if(sip2){ ilock(sip2); uint64 pa = walkaddr(p->pagetable, vva); if(pa){ writei(sip2, 0, pa, slot*PGSIZE, PGSIZE);} iunlockput(sip2);}          
        }
        p->swap_used[slot] = 1;
        p->slot_va[slot] = vva;
        printf("[pid %d] SWAPOUT va=%p slot=%d\n", p->pid, (void*)vva, slot);
        printf("[pid %d] DEBUG: kalloc_count before SWAPOUT uvmunmap = %d\n", p->pid, get_kalloc_count());
        uvmunmap(p->pagetable, vva, 1, 1);
        printf("[pid %d] DEBUG: kalloc_count after SWAPOUT uvmunmap = %d\n", p->pid, get_kalloc_count());
        p->resident[victim].inuse = 0;
        p->num_resident_pages--;
        p->num_swapped_pages++;
        // try allocation again
        mem = (uint64)kalloc();
        if(mem == 0) return 0;
      }
    } else {
      return 0;
    }
  }
  memset((void *) mem, 0, PGSIZE);
  int perm = PTE_U | PTE_R; // start read-only; upgrade on write fault to mark dirty
  // If this VA was swapped out, reload from swap
  int swapped_slot = -1;
  for(int s=0;s<MAX_SWAP_SLOTS;s++) if(p->swap_used[s] && p->slot_va[s] == va){ swapped_slot = s; break; }
  if(swapped_slot >= 0){
    // Map page and load from swap file
    int perm = PTE_U | PTE_R | PTE_W;
    if (mappages(p->pagetable, va, PGSIZE, mem, perm) != 0) {
      kfree((void *)mem);
      return 0;
    }
    if(p->swap_path[0]){
      struct inode *sip = namei(p->swap_path);
      if(sip){ ilock(sip); readi(sip, 0, mem, swapped_slot*PGSIZE, PGSIZE); iunlockput(sip); }
    }
    printf("[pid %d] SWAPIN va=%p slot=%d\n", p->pid, (void*)va, swapped_slot);
    p->swap_used[swapped_slot] = 0; p->slot_va[swapped_slot] = 0; p->num_swapped_pages--;
    int seq = p->next_fifo_seq++;
    printf("[pid %d] RESIDENT va=%p seq=%d\n", p->pid, (void*)va, seq);
    // record resident entry (best-effort)
    for(int i=0;i<MAX_RESIDENT;i++){
      if(!p->resident[i].inuse){
        p->resident[i].inuse=1;
        p->resident[i].va=va;
        p->resident[i].seq=seq;
        p->resident[i].dirty=0;
        p->resident[i].exec_backed=0;
        p->num_resident_pages++;
        break;
      }
    }
    return mem;
  }
  if(is_exec_region){
    // refine perms based on segment info (remove W if not permitted, add X if text)
    perm = PTE_U | PTE_R;
    for(int i=0;i<p->nsegs;i++){
      uint64 s = p->segs[i].vaddr;
      uint64 e = s + p->segs[i].memsz;
      if(va >= s && va < e){
        if(p->segs[i].perm & PTE_X) perm |= PTE_X;
        if(p->segs[i].perm & PTE_W) perm |= PTE_W;
        // Read from file offset if within filesz
        uint64 pageoff = va - s;
        uint n = PGSIZE;
        if(pageoff < p->segs[i].filesz){
          if(pageoff + n > p->segs[i].filesz) n = p->segs[i].filesz - pageoff;
          struct inode *ip = namei(p->exec_path);
          if(ip){
            ilock(ip);
            readi(ip, 0, mem, p->segs[i].off + pageoff, n);
            iunlockput(ip);
          }
        }
        break;
      }
    }
  } else {
    // For non-exec regions, use write permission by default
    perm = PTE_U | PTE_R | PTE_W;
  }
  // Map the page if not already mapped
  if (mappages(p->pagetable, va, PGSIZE, mem, perm) != 0) {
    kfree((void *)mem);
    return 0;
  }
  extern int audit_logs;
  if(audit_logs){
    if(is_exec_region){
      printf("[pid %d] LOADEXEC va=%p\n", p->pid, (void*)va);
    } else {
      printf("[pid %d] ALLOC va=%p\n", p->pid, (void*)va);
    }
  }
  int seq = p->next_fifo_seq++;
  if(audit_logs) printf("[pid %d] RESIDENT va=%p seq=%d\n", p->pid, (void*)va, seq);
  // record in resident set (best-effort: if array is full, page won't be tracked for eviction)
  for(int i=0;i<MAX_RESIDENT;i++){
    if(!p->resident[i].inuse){
      p->resident[i].inuse = 1;
      p->resident[i].va = va;
      p->resident[i].seq = seq;
      p->resident[i].exec_backed = is_exec_region;
      p->resident[i].dirty = 0;
      p->num_resident_pages++;
      break;
    }
  }
  // Note: page is allocated but may not be tracked if resident array is full
  // This is acceptable; the page will still be freed properly on process exit
  return mem;
}

int
ismapped(pagetable_t pagetable, uint64 va)
{
  pte_t *pte = walk(pagetable, va, 0);
  if (pte == 0) {
    return 0;
  }
  if (*pte & PTE_V){
    return 1;
  }
  return 0;
}
