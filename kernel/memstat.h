#pragma once
#include "types.h"

#define MAX_PAGES_INFO 128

#define UNMAPPED 0
#define RESIDENT 1
#define SWAPPED  2

struct page_stat {
  uint va;
  int state;
  int is_dirty;
  int seq;
  int swap_slot;
};

struct proc_mem_stat {
  int pid;
  int num_pages_total;
  int num_resident_pages;
  int num_swapped_pages;
  int next_fifo_seq;
  struct page_stat pages[MAX_PAGES_INFO];
};



