#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"
#include "memstat.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int t;
  int n;

  argint(0, &n);
  argint(1, &t);
  addr = myproc()->sz;

  if(t == SBRK_EAGER || n < 0) {
    if(growproc(n) < 0) {
      return -1;
    }
  } else {
    // Lazily allocate memory for this process: increase its memory
    // size but don't allocate memory. If the processes uses the
    // memory, vmfault() will allocate it.
    if(addr + n < addr)
      return -1;
    myproc()->sz += n;
  }
  return addr;
}

uint64
sys_pause(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if(n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64
sys_memstat(void)
{
  uint64 uaddr;
  argaddr(0, &uaddr);
  struct proc *p = myproc();
  struct proc_mem_stat kinfo;
  kinfo.pid = p->pid;
  kinfo.next_fifo_seq = p->next_fifo_seq;
  int total = (PGROUNDUP(p->sz) / PGSIZE);
  if(total < 0) total = 0;
  kinfo.num_pages_total = total;
  kinfo.num_resident_pages = 0;
  kinfo.num_swapped_pages = p->num_swapped_pages;
  // Walk lowest-address pages up to MAX_PAGES_INFO
  int reported = 0;
  for(uint64 va = 0; va < p->sz && reported < MAX_PAGES_INFO; va += PGSIZE){
    struct page_stat ps;
    ps.va = (uint)va;
    ps.state = UNMAPPED;
    ps.is_dirty = 0;
    ps.seq = 0;
    ps.swap_slot = -1;
    pte_t *pte = walk(p->pagetable, va, 0);
    if(pte && (*pte & PTE_V)){
      ps.state = RESIDENT;
      if((*pte & PTE_W) != 0){
        ps.is_dirty = 1; // best-effort dirty inference
      }
      kinfo.num_resident_pages++;
    } else {
      // check swap slots
      for(int s=0;s<MAX_SWAP_SLOTS;s++){
        if(p->swap_used[s] && p->slot_va[s] == va){ ps.state = SWAPPED; ps.swap_slot = s; break; }
      }
    }
    kinfo.pages[reported++] = ps;
  }
  if(copyout(p->pagetable, uaddr, (char*)&kinfo, sizeof(kinfo)) < 0)
    return -1;
  return 0;
}

uint64
sys_kalloc_count(void)
{
  return get_kalloc_count();
}