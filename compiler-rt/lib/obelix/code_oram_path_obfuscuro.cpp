/*
 * Adapted from
 * https://github.com/adilahmad17/Obfuscuro/blob/master/llvm/llvm-4.0.0.src/projects/compiler-rt/lib/obfuscuro/
 */

#include "sanitizer_common/sanitizer_common.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

using namespace __sanitizer;

#define NUM_TREE_CODE_LEAF     128
#define NUM_TREE_CODE_NODES    ((2*NUM_TREE_CODE_LEAF) - 1) // nodes in the tree

#define NUM_STASH_CODE_BLOCKS     16    //blocks in the stash

#define PAGE_SIZE     128

typedef unsigned long ADDRTY;
typedef unsigned long SIZETY;

/* struct for each oram block */
typedef struct {
  char memory[PAGE_SIZE];
} tree_block_t;

/* struct for tree nodes */
typedef struct {
  tree_block_t blocks[1];
} tree_node_t;

/* struct for position map */
typedef struct {
  int leaf;
  ADDRTY old_addr;
  ADDRTY new_addr;
  SIZETY size;
} pmap_block_t;

/* struct for stash map */
typedef struct {
  int leaf;
  bool real;
  bool filled;
  ADDRTY new_addr;
  ADDRTY old_addr;
} smap_block_t;

/* struct for tree map */
typedef struct {
  int filled = 0;
} tmap_block_t;

typedef struct {
  int leaf;
  ADDRTY old_addr;
  ADDRTY new_addr;
  char* buf;
} scratchbuf_t;


//#define DOUT
#define DOUT(...) Printf(__VA_ARGS__)

extern "C"
{
  /* from rerand_oram_init.cc */
  void populate_oram(ADDRTY addr, SIZETY size);

  /* from rerand_oram_ops.cc */
  ADDRTY otranslate(ADDRTY old_address);

  /* from rerand_oram_util.cc */
  int is_in_path(int leaf, int path_index);
}

/* required data structures for code-based ORAM */
tree_block_t ostash_code[NUM_STASH_CODE_BLOCKS] {};
tree_node_t otree_code[NUM_TREE_CODE_NODES] {};
pmap_block_t oposmap_code[NUM_TREE_CODE_LEAF] {};
smap_block_t osmap_code[NUM_STASH_CODE_BLOCKS] {};
tmap_block_t otmap_code[NUM_TREE_CODE_NODES] {};

/* scratch buffer */
scratchbuf_t scratch;

/* count of filled oram blocks */
int count_filled_code_blocks = 0;

uint64_t cmov(uint64_t val1, uint64_t test, uint64_t val2);
void cmov_memory(char* addr1, char* addr2, uint64_t size, uint32_t test);
int get_rand32(unsigned int* rand);

extern "C" u64 code_scratch_pad_address;

extern "C"
NOINLINE INTERFACE_ATTRIBUTE
ADDRTY __obfuscuro_oram_translate(ADDRTY  dst_addr) {

  DOUT("otranslate: %lx \n", dst_addr);
  ADDRTY new_addr = (ADDRTY) otranslate(dst_addr);
  DOUT("otranslate: ----------> %lx\n", new_addr);
  return new_addr;
}

extern "C" s32* function_info;
void init_path_oram_obfuscuro()
{
  uptr first = 0;

  s32 *functionInfoPtr = function_info;
  while (*functionInfoPtr != 0)
  {
    s32 *codeBlockTablePtr = reinterpret_cast<s32 *>(reinterpret_cast<uptr>(functionInfoPtr) + *functionInfoPtr);
    ++codeBlockTablePtr; // Skip block count
    while (*codeBlockTablePtr != 0)
    {
      uptr codeBlockPtr = reinterpret_cast<uptr>(codeBlockTablePtr) + *codeBlockTablePtr;
      if(first == 0)
        first = codeBlockPtr;

      populate_oram(codeBlockPtr, PAGE_SIZE);

      ++codeBlockTablePtr;
    }

    ++functionInfoPtr;
  }
}

void dump_oram()
{
  Printf("ORAM dump:\n");
  for(int i = 0; i < NUM_TREE_CODE_NODES; ++i) {
    u8 *block = (u8 *) otree_code[i].blocks[0].memory;
    tmap_block_t *tmblock = &(otmap_code[i]);

    Printf("%3d -> %d %lx   ", i, tmblock->filled, (uptr)block);
    for(int j = 0; j < 16; ++j) {
      Printf("%02x ", block[j]);
    }
    Printf("\n");
  }

  Printf("Pos map:\n");
  for(int i = 0; i < NUM_TREE_CODE_LEAF; ++i) {
    pmap_block_t *pmap = &(oposmap_code[i]);

    if(pmap->old_addr)
      Printf("%lx -> %d / %lx\n", pmap->old_addr, pmap->leaf, pmap->new_addr);
  }
}


/* find if in path or not */
// ISSUE. Make this oblivious
int is_in_path(int leaf, int path_index) {
  if (leaf == path_index) return 1;

  if (path_index > leaf) return 0;

  while (true) {
    if (path_index > leaf) break;
    else if (path_index == leaf) return 1;

    leaf -= 1;
    leaf /= 2;
  }

  return 0;
}

void update_position_map(ADDRTY addr, SIZETY size, int leaf, int pos) {
  pmap_block_t* temp;
  ADDRTY n_addr;
  int loop_end;

  n_addr = (ADDRTY) &(otree_code[pos].blocks[0].memory);
  loop_end = NUM_TREE_CODE_LEAF;

  int to_check;

  for (int i = 0; i < loop_end; i++) {

    /* check the type of update */
    if (i == 0) DOUT("UPDATE: code-based pmap\n");
    temp = &(oposmap_code[i]);
    to_check = count_filled_code_blocks;

    if (to_check == i) {
      temp->leaf = leaf;
      temp->old_addr = addr;
      temp->new_addr = n_addr;
      temp->size = size;
    } else {
      // using cmov
      temp->leaf = cmov(temp->leaf, 1, leaf);
      temp->old_addr = cmov(temp->old_addr, 1, addr);
      temp->new_addr = cmov(temp->new_addr, 1, n_addr);
      temp->size = cmov(temp->size, 1, size);
    }

    if(temp->old_addr && !temp->new_addr) {
      DOUT("update_position_map: %lx has no new_addr\n", temp->old_addr);
      internal__exit(0);
    }
  }

  return;
}

int populate_tree_using_memory(ADDRTY addr, SIZETY size, int leaf) {
  int flag = 0;
  int ret = -1;
  void* tmp = (void*) addr;
  void* tmp_block;
  tmap_block_t* tmblock;

  int loop_end = NUM_TREE_CODE_NODES - 1;

  CHECK(size <= PAGE_SIZE);

  for (int i = loop_end; i >= 0; i--) {

    // check the type to update accordingly
    tmblock = &(otmap_code[i]);

    if (tmblock->filled == 0 && is_in_path(leaf, i) && flag == 0) {
      DOUT("chosen: %d, copying: %ld\n", i, size);
      // tmp_block = (void*) &(otree[i].blocks[0].memory);

      tmp_block = (void*) &(otree_code[i].blocks[0].memory);

      // cmov_memory
      cmov_memory((char*) tmp_block,(char*) tmp, size, 0);

      tmblock->filled = 1;
      ret = i;
      flag = 1;

    } else {
      tmblock->filled = cmov(tmblock->filled, 1, 1);
      ret = (int) cmov(ret, 1, i);

      flag = (int) cmov(flag, 1, 1);

      tmp_block = (void*) &(otree_code[i].blocks[0].memory);

      cmov_memory((char*) tmp_block, (char*) tmp, size, 1);

    }
  }

  CHECK(flag == 1);

  return ret;
}

int check_exist_in_pmap(ADDRTY old_addr)
{
  pmap_block_t* tmp;

  int loop_end = NUM_TREE_CODE_LEAF;

  for (int i = 0; i < loop_end; i++) {

    if (i == 0) DOUT("FINDING: code-based pmap\n");
    tmp = &(oposmap_code[i]);

    if (tmp->leaf > 0) {
      if (tmp->old_addr == old_addr) {
        // XXX.
        return 1;
      } else if ((old_addr <= tmp->old_addr) && ((tmp->old_addr - PAGE_SIZE) < old_addr)){
        // XXX.
        return 1;
      }
    }
  }

  return 0;
}

/* add a memory region into the oram tree */
void populate_oram(ADDRTY addr, SIZETY size) {
  /* oram-tree population */

  unsigned int randleaf = 0;
  int pos;

  // DOUT("sanity check passed\n");
  CHECK(size <= PAGE_SIZE);


  //SGXOUT("old_addr -> %p, size -> %ld\n", addr, size);
  DOUT("old_addr -> %p, size -> %ld\n", addr, size);


  int loop_end = NUM_TREE_CODE_LEAF;

  while (randleaf < loop_end || randleaf >= ((2*loop_end) - 1)) {
    get_rand32(&randleaf);
    randleaf = (randleaf % loop_end);
    randleaf += (loop_end);
  }

  DOUT("Selected leaf: %d\n", randleaf);
  CHECK(randleaf >= loop_end && randleaf < ((2*loop_end) - 1));

  // populate into the right tree
  pos = populate_tree_using_memory(addr, size, randleaf);
  CHECK(randleaf != 0);

  // update the right position map
  update_position_map(addr, size, randleaf, pos);

  // Sanity check on both trees
  count_filled_code_blocks++;
  CHECK(count_filled_code_blocks <= loop_end);

  return;
}

#define NUM_UPDATES 4

typedef struct{
  ADDRTY old_addr;
  ADDRTY new_addr;
}update_queue_t;

update_queue_t update_queue[NUM_UPDATES];
//

// Variables declared for debugging purposes
static unsigned long int update_pmap_count = 0;
static int timing_or_pattern_experiment = 0;
static unsigned long oramly_translated = 0;
static unsigned int num_executed_code_blocks = 0;
static unsigned int num_fetched_data_blocks = 0;
static unsigned int num_oram_writes = 0;
static unsigned int num_oram_reads = 0;

void update_pmap_addr(ADDRTY old_addr, ADDRTY new_addr, bool pflag) {
  pmap_block_t* pblock;
  int flag = 0;
  bool check = false;
  ADDRTY toadd = 0;

  int loop_end = NUM_TREE_CODE_LEAF;

  DOUT("Update pos map: %lx -> %lx\n", old_addr, new_addr);

  for (int i = 0; i < loop_end; i++) {
    pblock = &oposmap_code[i];

    check = !((pblock->new_addr == new_addr) && pflag);
    if(old_addr && !check)
      DOUT("   check1\n");
    pblock->new_addr = cmov(pblock->new_addr, check, 0);
    flag = cmov(flag, check, 1);

    check = !((pblock->old_addr == old_addr) && pflag);
    if(old_addr && !check)
      DOUT("   check2\n");
    pblock->new_addr = cmov(pblock->new_addr, check, new_addr);
    flag = cmov(flag, check, 1);


    if(pblock->old_addr && !pblock->new_addr) {
      DOUT("%lx has no new_addr\n", pblock->old_addr);
      internal__exit(0);
    }
  }

  //CHECK(flag == 1 || !pflag);
}

void update_pmap_leaf(ADDRTY old_addr, unsigned int new_leaf) {
  pmap_block_t* pblock;
  int flag = 0;
  bool check = false;

  int loop_end = NUM_TREE_CODE_LEAF;

  for (int i = 0; i < loop_end; i++) {
    pblock = &oposmap_code[i];

    check = !(pblock->old_addr == old_addr);
    pblock->leaf = cmov(pblock->leaf, check, new_leaf);
    flag = cmov(flag, check, 1);
  }

  CHECK(flag == 1);
}

void write_back_from_scratch_to_stash() {
  tree_block_t* sblock;
  smap_block_t* smblock;
  int flag = 0;
  bool check = false;
  scratchbuf_t* scratchpad;

  int loop_end;
  scratchpad = &scratch;
  loop_end = NUM_STASH_CODE_BLOCKS;

  for (int i = 0; i < loop_end; i++) {

    sblock = &(ostash_code[i]);
    smblock = &(osmap_code[i]);

    check = !(scratchpad->old_addr == smblock->old_addr);
    flag = (flag, check, 1);
    smblock->leaf = cmov(smblock->leaf, check, scratchpad->leaf);
    cmov_memory(sblock->memory, scratchpad->buf, PAGE_SIZE, check);
  }

  CHECK(flag == 1);
}

void fill_tree_node_from_stash_cmov(int path_index) {
  tree_block_t* sblock;
  smap_block_t* smblock;
  char* tblock;
  bool check = false;
  bool check1 = false;
  tmap_block_t* tmblock;
  int cur_queue_fill = 0;

  int loop_end;
  tblock = (char*) &(otree_code[path_index].blocks[0].memory);
  tmblock = &(otmap_code[path_index]);
  loop_end = NUM_STASH_CODE_BLOCKS;

  // TODO This is a hotfix for Obelix
  if(tmblock->filled)
    return;

  int flag = 0;
  for (int i = 0; i < loop_end; i++) {

    sblock = &(ostash_code[i]);
    smblock = &(osmap_code[i]);

    check = !(smblock->leaf > 0 && smblock->filled == 1 && flag == 0);
    check1 = !(is_in_path(smblock->leaf, path_index));
    smblock->leaf = cmov(smblock->leaf, (check1 || check), 0);
    smblock->filled = cmov(smblock->filled, (check1 || check), 0);
    flag = cmov(flag, check1 || check, 1);
    tmblock->filled = cmov(tmblock->filled, check1 || check, 1);

    // Using the update queue.
    update_queue[cur_queue_fill].old_addr = cmov(update_queue[cur_queue_fill].old_addr, check1||check, smblock->old_addr);
    update_queue[cur_queue_fill].new_addr = cmov(update_queue[cur_queue_fill].new_addr, check1||check, (ADDRTY) tblock);

    if(update_queue[cur_queue_fill].old_addr && !update_queue[cur_queue_fill].new_addr) {
      DOUT("Update queue: Clearing %lx\n", update_queue[cur_queue_fill].old_addr);
    }

    cur_queue_fill = cmov(cur_queue_fill, check1||check, cur_queue_fill+1);
    if (cur_queue_fill > 4) {
      Printf("update queue full\n");
    }
    CHECK(cur_queue_fill <= 4);

    // Without the update queue. (TODO)
    //if (!(check1 || check))
    //update_pmap_addr(smblock->old_addr, (ADDRTY) tblock, !(check1 || check));

    cmov_memory(tblock, sblock->memory, PAGE_SIZE, check1 || check);
    smblock->old_addr = cmov(smblock->old_addr, check1 || check, 0);
    smblock->new_addr = cmov(smblock->new_addr, check1 || check, 0);
  }

  // Stream through the update queue and update the position-map.
  for (int i = 0; i < 4; i++) {
    update_pmap_addr(update_queue[i].old_addr, (ADDRTY) update_queue[i].new_addr, 1);
    update_queue[i].old_addr = 0;
    update_queue[i].new_addr = 0;
  }
}

void write_back_from_stash_to_tree(int old_leaf) {
  int start = old_leaf;
  while (true) {
    fill_tree_node_from_stash_cmov(start);
    if (start == 0) break;
    start -= 1;
    start /= 2;
  }
  return;
}

int check_real(ADDRTY addr, int* leaf, ADDRTY* old_addr) {
  pmap_block_t* pblock;
  int flag = 0;
  bool check = false;
  int loop_end;

  loop_end = NUM_TREE_CODE_LEAF;

  for (int i = 0; i < loop_end; i++) {
    pblock = &(oposmap_code[i]);
    check = !(pblock->leaf > 0 && pblock->new_addr == addr);
    flag = cmov(flag, check, 1);
    *leaf = cmov(*leaf, check, pblock->leaf);
    *old_addr = cmov(*old_addr, check, pblock->old_addr);
  }

  check = !(flag != 1);
  *old_addr = cmov(*old_addr, check, 0xFFFFFF);
  return flag;
}


void find_req_block_from_stash(ADDRTY old_addr, ADDRTY new_addr, int old_leaf) {
  tree_block_t* sblock;
  smap_block_t* smblock;
  char* sblock_mem;
  bool flag = false;
  int leaf;
  scratchbuf_t* scratchpad;
  bool check, check1 = false;
  int loop_end;

  scratchpad = &scratch;
  loop_end = NUM_STASH_CODE_BLOCKS;


  for (int i = 0; i < loop_end; i++) {
    sblock = &(ostash_code[i]);
    smblock = &(osmap_code[i]);

    check = !(smblock->filled == 1);
    check1 = !(smblock->old_addr == old_addr);
    sblock_mem = (char*) (sblock->memory);
    scratchpad->leaf = cmov(scratchpad->leaf, check1 || check, old_leaf);
    scratchpad->new_addr = cmov(scratchpad->new_addr, check1 || check, new_addr);
    scratchpad->old_addr = cmov(scratchpad->old_addr, check1 || check, old_addr);
    flag = cmov(flag, check1 || check, true);
    cmov_memory(scratchpad->buf, sblock_mem, PAGE_SIZE, check1 || check);
  }

  if(!flag) {
    // Debug
    dump_oram();

    // Dump stash
    Printf("old_addr = %lx\n", old_addr);
    for (int i = 0; i < loop_end; i++) {
      sblock = &(ostash_code[i]);
      smblock = &(osmap_code[i]);

      Printf("stash[%2d]: old = %lx, leaf = %d, filled = %d, real = %d\n", i, smblock->old_addr, smblock->leaf, smblock->filled, smblock->real);
    }
  }

  CHECK(flag == true);
}

void cmov_stash_copy(char* block, int old_leaf) {
  tree_block_t* sblock;
  smap_block_t* smblock;
  int fl = 0;
  bool check = false;
  int leaf = old_leaf;
  ADDRTY old_addr;
  int flag = check_real((ADDRTY) block, &leaf, &old_addr);
  int loop_end;

  loop_end = NUM_STASH_CODE_BLOCKS;

  DOUT("Copying leaf %d to stash, real = %d, old_addr = %lx\n", old_leaf, flag, old_addr);

  for (int i = 0; i < loop_end; i++) {
    sblock = &(ostash_code[i]);
    smblock = &(osmap_code[i]);

    check = !(smblock->filled == 0 && fl == 0);

    char* sblock_mem = (char*) (sblock->memory);
    cmov_memory(sblock_mem, block, PAGE_SIZE, check);
    smblock->real = cmov(smblock->real, check, flag);
    smblock->leaf = cmov(smblock->leaf, check, leaf);
    smblock->filled = cmov(smblock->filled, check, flag);
    smblock->new_addr = cmov(smblock->new_addr, check, (ADDRTY) block);
    smblock->old_addr = cmov(smblock->old_addr, check, old_addr);
    fl = cmov(fl, check, 1);
  }

  // XXX. Check here for stash being full.
  // CHECK(false);
}

void copy_path_onto_stash(int leaf) {
  int start = leaf;
  char* block;
  tmap_block_t* tmblock;
  while (true) {
    block = (char*) &(otree_code[start].blocks[0].memory);
    tmblock = &(otmap_code[start]);
    tmblock->filled = 0;
    cmov_stash_copy(block, leaf);
    if (start == 0) break;
    start -= 1;
    start /= 2;
  }
  return;
}

int locate_addr_from_pmap(ADDRTY old_addr, ADDRTY* closest_addr, ADDRTY* new_addr,
                          ADDRTY* offset) {
  pmap_block_t* tmp;
  int leaf = -1;
  int loop_end;
  bool check = false;
  bool check1 = false;
  bool check2 = false;
  bool check3 = false;

  loop_end = NUM_TREE_CODE_LEAF;

  for (int i = 0; i < loop_end; i++) {

    tmp = &(oposmap_code[i]);

    check = !(tmp->leaf > 0);
    check1 = !(old_addr == 0);
    check2 = !(tmp->old_addr == old_addr);
    check3 = !((old_addr >= tmp->old_addr) && ((tmp->old_addr + tmp->size) > old_addr));
    leaf = cmov(leaf, (check1 || check) && (check2 || check) && (check3 || check), tmp->leaf);
    *new_addr = cmov(*new_addr, (check1 || check) && (check2 || check) && (check3 || check), tmp->new_addr);
    *offset = cmov(*offset,(check1 || check) && (check2 || check), 0);
    *offset = cmov(*offset, (check3 || check), old_addr - tmp->old_addr);
    *closest_addr = cmov(*closest_addr, (check1 || check) && (check2 || check) && (check3 || check), tmp->old_addr);
  }

  return leaf;
}

ADDRTY otranslate(ADDRTY old_addr) {

  scratchbuf_t* scratchpad;

  scratchpad = &scratch;
  num_executed_code_blocks += 1;

  dump_oram();

  if (scratchpad->leaf > 0) {
    num_oram_writes++;
    int old_leaf = scratchpad->leaf;
    unsigned int randleaf = 1;
    int loop_end = NUM_TREE_CODE_LEAF;

    // Find a new leaf for this block
    int loop = 0;
    while (randleaf < loop_end || randleaf >= (2*loop_end -1)) {
      get_rand32(&randleaf);
      randleaf = (randleaf % loop_end);
      randleaf += (loop_end);
      loop++;
    }
    //CHECK(loop == 1);
    CHECK(randleaf >= loop_end && randleaf < (2*loop_end - 1));

    // Update the PMAP (Oblivious)
    scratchpad->leaf = randleaf;
    update_pmap_leaf(scratchpad->old_addr, randleaf);

    // Write back from scratchpad to the stash (Oblivious)
    write_back_from_scratch_to_stash();

    // Update the ORAM Tree (Secure by ORAM design)
    write_back_from_stash_to_tree(old_leaf);

    // Clear the scratchpad
    scratchpad->leaf = 0;
    scratchpad->new_addr = 0;
    scratchpad->old_addr = 0;
  }

  scratchpad->buf = (char*)code_scratch_pad_address;

  // step1: stroll through pmap to find leaf
  ADDRTY new_addr = 0;
  ADDRTY offset = 0;
  ADDRTY closest_addr = 0;

  //byunggill
  int leaf = locate_addr_from_pmap(old_addr, &closest_addr,
                                   &new_addr, &offset);

  bool flag = false;
  if (leaf == -1) {
    // XXX. should come here only once
    CHECK(flag == false);
    update_pmap_count +=1;

    Printf("code block does not exist: %lx\n", old_addr);

    flag = true;
    return old_addr;
  }

  // Debugging purposes
  num_oram_reads++;

  // Copy path from ORAM Tree to the stash (Secure by ORAM design)
  DOUT("Leaf: %d\n", leaf);
  copy_path_onto_stash(leaf);

  // Find the block from the stash (Oblivious)
  find_req_block_from_stash(closest_addr, new_addr, leaf);

  oramly_translated++;

  /* Sanity Checks for code-based (added by BG) */

  CHECK(scratch.leaf > 0);

  return (ADDRTY) (scratchpad->buf + offset);
}