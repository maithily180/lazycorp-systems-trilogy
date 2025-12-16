#include "kernel/types.h"
#include "kernel/fcntl.h"
#include "user/user.h"
#include "kernel/memstat.h"

int
main(void)
{
  struct proc_mem_stat st;
  // touch some heap pages to cause faults
  char *p = sbrk(3*4096);
  p[0] = 1; p[4096] = 2; p[8192] = 3;
  if(memstat(&st) == 0){
    printf("memstat pid=%d res=%d swp=%d next=%d total=%d\n", st.pid, st.num_resident_pages, st.num_swapped_pages, st.next_fifo_seq, st.num_pages_total);
    for(int i=0;i<st.num_pages_total && i<MAX_PAGES_INFO;i++){
      if(st.pages[i].state != UNMAPPED)
        printf("va=%p state=%d dirty=%d seq=%d slot=%d\n", (void*)(uint64)st.pages[i].va, st.pages[i].state, st.pages[i].is_dirty, st.pages[i].seq, st.pages[i].swap_slot);
    }
  }
  exit(0);
}

