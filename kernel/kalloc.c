// Physical memory allocator, for user processes,
// kernel stacks, page-table pages,
// and pipe buffers. Allocates whole 4096-byte pages.

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "riscv.h"
#include "defs.h"

void freerange(void *pa_start, void *pa_end);

extern char end[]; // first address after kernel.
                   // defined by kernel.ld.

struct run {
  struct run *next;
};

struct {
  struct spinlock lock;
  struct run *freelist;
} kmem;

// Debug counter to track allocations vs frees
int kalloc_count = 0;
int kalloc_initialized = 0;

void
kinit()
{
  initlock(&kmem.lock, "kmem");
  kalloc_initialized = 1;  // Mark as initialized before freerange
  freerange(end, (void*)PHYSTOP);
}

void
freerange(void *pa_start, void *pa_end)
{
  char *p;
  p = (char*)PGROUNDUP((uint64)pa_start);
  for(; p + PGSIZE <= (char*)pa_end; p += PGSIZE)
    kfree(p);
}

// Free the page of physical memory pointed at by pa,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(void *pa)
{
  struct run *r;

  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  // Fill with junk to catch dangling refs.
  memset(pa, 1, PGSIZE);

  r = (struct run*)pa;

  acquire(&kmem.lock);
  r->next = kmem.freelist;
  kmem.freelist = r;
  if (kalloc_initialized) {
    kalloc_count--;  // decrement on free only after initialization
  }
  release(&kmem.lock);
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void *
kalloc(void)
{
  struct run *r;

  acquire(&kmem.lock);
  r = kmem.freelist;
  if(r) {
    kmem.freelist = r->next;
    kalloc_count++;  // increment on successful alloc
  }
  release(&kmem.lock);

  if(r)
    memset((char*)r, 5, PGSIZE); // fill with junk
  return (void*)r;
}

// Debug function to get current allocation count
int
get_kalloc_count(void)
{
  int count;
  acquire(&kmem.lock);
  count = kalloc_count;
  release(&kmem.lock);
  return count;
}

// Print a small summary of the freelist for debugging. Prints total
// count and up to the first 8 physical page addresses on the freelist.
void
dump_freelist(void)
{
  struct run *r;
  int i = 0;

  acquire(&kmem.lock);
  printf("DEBUG: kalloc_count=%d freelist(->first8):", kalloc_count);
  for(r = kmem.freelist; r && i < 8; r = r->next){
    printf(" %p", (void*)r);
    i++;
  }
  printf("\n");
  release(&kmem.lock);
}