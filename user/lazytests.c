#include "kernel/types.h"
#include "kernel/fcntl.h"
#include "user/user.h"
#include "kernel/memstat.h"

static void print_result(int id, const char *name, int ok){
  printf("TEST %d: %s - %s\n", id, name, ok?"PASS":"FAIL");
}

static int test_heap_lazy(){
  int ok = 1;
  int pages = 8;
  char *base = sbrk(pages*4096);
  if((uint64)base == (uint64)SBRK_ERROR) return 0;
  for(int i=0;i<pages;i++){
    base[i*4096] = (char)(i+1);
  }
  for(int i=0;i<pages;i++){
    if(base[i*4096] != (char)(i+1)) ok = 0;
  }
  return ok;
}

static int test_stack_lazy(){
  int ok = 1;
  volatile char local = 0;
  volatile char *p = (volatile char *)((uint64)&local - 8);
  *p = 42;
  if(*p != 42) ok = 0;
  return ok;
}

static int test_memstat(){
  struct proc_mem_stat st;
  if(memstat(&st) != 0) return 0;
  if(st.pid <= 0) return 0;
  if(st.num_resident_pages < 1) return 0;
  return 1;
}

static int test_eviction_swap_basic(){
  // Try to allocate and write a bunch of pages, then read them back.
  // If eviction+swap happens, data should still be intact.
  int pages = 256; // moderate to avoid OOM
  char *base = sbrk(pages*4096);
  if((uint64)base == (uint64)SBRK_ERROR) return 0;
  for(int i=0;i<pages;i++) base[i*4096] = (char)(i);
  // touch more to increase pressure
  int more = 256;
  char *b2 = sbrk(more*4096);
  if((uint64)b2 == (uint64)SBRK_ERROR) return 0;
  for(int i=0;i<more;i++) b2[i*4096] = (char)(i^0x5a);
  // verify original
  for(int i=0;i<pages;i++){
    if(base[i*4096] != (char)(i)) return 0;
  }
  return 1;
}

int main(void){
  int id = 1;
  print_result(id++, "heap lazy", test_heap_lazy());
  print_result(id++, "stack lazy", test_stack_lazy());
  print_result(id++, "memstat", test_memstat());
  print_result(id++, "evict+swap basic", test_eviction_swap_basic());
  exit(0);
}



