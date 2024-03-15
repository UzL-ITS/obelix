/*
 * Code Path ORAM implementation in C.
 *
 * Notes:
 * - For efficiency, addresses are stored as 32-bit numbers. It is highly
 *   unlikely that there will ever be two code blocks which share the same 32
 *   least significant address bits.
 */

#include "code_oram_path_c.h"
#include "asm_inlines.h"
#include "constants.h"
#include "random.h"
#include "sanitizer_common/sanitizer_posix.h"
#include <immintrin.h>
#include <sys/mman.h>

using namespace __sanitizer;

// Utility macros for debugging. Enable/disable with 1/0.
#if 0
  #define DEBUG(...) Printf(__VA_ARGS__)
#else
  #define DEBUG(...) void()
  #undef CHECK
  #define CHECK(...) void()
#endif

extern "C" s32* function_info;
extern "C" u64 code_scratch_pad_address;

static constexpr int bucket_size = 1;

typedef __m256i v_code_block_t[code_block_size / 32];

typedef struct {
  [[gnu::aligned(32)]] u8 data[code_block_size];
} code_oram_entry;

typedef struct {
  code_oram_entry entries[bucket_size];
} code_oram_node;

typedef struct {
  u32 address;
  unsigned int leaf;
} code_oram_metadata_entry;

static constexpr u32 invalid_address = static_cast<u32>(-1);

// Code ORAM tree.
static code_oram_node *code_oram_tree = nullptr;
static code_oram_metadata_entry *code_oram_tree_metadata = nullptr;
static u32 code_oram_tree_height = 0;
static u32 leaf_count = 0;
static int entry_count = 0;

// Code ORAM position map.
static code_oram_metadata_entry *code_oram_position_map = nullptr;

// Code ORAM stash.
static code_oram_entry *code_oram_stash = nullptr;
static code_oram_metadata_entry *code_oram_stash_metadata = nullptr;
static int code_oram_stash_size = 0;

// Code ORAM cache.
typedef struct {
  s32 *functionInfoPtr;

  code_oram_node *oramTree;
  code_oram_metadata_entry *oramTreeMetadata;

  code_oram_entry *oramStash;
  code_oram_metadata_entry *oramStashMetadata;

  code_oram_metadata_entry *oramPositionMap;

  u32 leafCount;
  u32 oramTreeHeight;

  int oramStashSize;
  int oramEntryCount;
} code_oram_cache_entry;
static constexpr int code_oram_cache_size = 16;
static code_oram_cache_entry code_oram_cache[code_oram_cache_size] = { 0 };
static int *code_oram_cache_stash_size_ptr = nullptr;

// RNG state.
xorshift128p_state rng_state;

extern "C"
{
  void code_oram_path_c_fini();
  void code_oram_path_c_query(uptr address);
}

// Returns a uniform random leaf.
unsigned int get_random_leaf()
{
  auto getRandomInt = [] () -> u32 {
    return static_cast<u32>(xorshift128p_next(rng_state));
  };

  // Map unbiased into interval [leafCount-1; 2*leafCount)
  // Uses method from https://arxiv.org/pdf/1805.10941.pdf
  // L = 32
  u32 x = getRandomInt();
  u32 s = leaf_count;
  u64 m = static_cast<u64>(x) * s;
  u32 l = static_cast<u32>(m); // m mod 2^L
  if(l < s) {
    u32 t = -s % s;
    while(l < t) {
      x = getRandomInt();
      m = static_cast<u64>(x) * s;
      l = static_cast<u32>(m);
    }
  }

  return leaf_count - 1 + (m >> 32);
}

// Returns the parent node index for given node.
static unsigned int get_parent(unsigned int index)
{
  // left: 2 * index + 1
  // right: 2 * index + 2
  // -> -1 and then /2 yields index in both cases
  return (index - 1) / 2;
}

// Returns whether the path to the given leaf contains the given node.
static int is_in_path(unsigned int leaf, unsigned int node)
{
  unsigned int index = leaf;
  int result = 0;
  while(true)
  {
    result ^= (index == node); // true exactly once, if node is in path

    if(index == 0)
      break;
    index = get_parent(index);
  }

  return result;
}

// Returns a pointer to the given bucket metadata entry of the given node.
static code_oram_metadata_entry *get_bucket_entry_metadata(unsigned int node, int bucketOffset)
{
  return code_oram_tree_metadata + node * bucket_size + bucketOffset;
}

// Debug function.
static void dump_stash()
{
  Printf("Stash dump:\n");
  for(int s = 0; s < code_oram_stash_size; ++s)
  {
    code_oram_metadata_entry *stashEntryMetadata = code_oram_stash_metadata + s;

    Printf("  [%3d] ", s);

    if(stashEntryMetadata->leaf < 2 * leaf_count - 1)
      Printf("(leaf %2u) ", stashEntryMetadata->leaf);
    else
      Printf("(leaf ??) ");

    if(stashEntryMetadata->address == invalid_address)
      Printf("[      ]\n");
    else
      Printf("%x\n", stashEntryMetadata->address);
  }
}

// Debug function.
static void dump_position_map()
{
  Printf("Position map dump:\n");
  for(int p = 0; p < entry_count; ++p)
  {
    code_oram_metadata_entry *posMap = code_oram_position_map + p;

    Printf("  %x -> leaf %u\n", posMap->address, posMap->leaf);
  }
}

// Debug function.
static void dump_tree()
{
  Printf("Tree dump:\n");
  Printf("  ID  Parent  Address   Leaf  Data\n");
  for(unsigned int n = 0; n < 2 * leaf_count - 1; ++n)
  {
    code_oram_node *node = code_oram_tree + n;

    int parent = n == 0 ? -1 : get_parent(n);

    for(int b = 0; b < bucket_size; ++b)
    {
      code_oram_metadata_entry *bucketEntryMetadata = code_oram_tree_metadata + n * bucket_size + b;
      code_oram_entry *bucketEntry = node->entries + b;

      if (b == 0)
      {
        Printf("  %2u", n);

        if(parent >= 0)
          Printf("  %2d      ", parent);
        else
          Printf("          ");
      }
      else
      {
        Printf("              ");
      }

      if(bucketEntryMetadata->address == invalid_address)
        Printf("[      ]  ");
      else
        Printf("%08x  ", bucketEntryMetadata->address);

      Printf("%2d    ", bucketEntryMetadata->leaf);

      for (int i = 0; i < 48; ++i)
        Printf("%02x ", bucketEntry->data[i]);
      Printf("\n");
    }

    Printf("  ----------------------------\n");
  }
}

void init_path_oram_c()
{
  // Initialize RNG
  xorshift128p_init(rng_state);

  // Did we cache the code ORAM?
  int codeOramCacheIndex;
  for(codeOramCacheIndex = 0; codeOramCacheIndex < code_oram_cache_size; ++codeOramCacheIndex)
  {
    code_oram_cache_entry *cacheEntry = &code_oram_cache[codeOramCacheIndex];

    if(cacheEntry->functionInfoPtr == 0)
      break;

    if(cacheEntry->functionInfoPtr == function_info)
    {
      code_oram_tree = cacheEntry->oramTree;
      code_oram_tree_metadata = cacheEntry->oramTreeMetadata;
      leaf_count = cacheEntry->leafCount;
      code_oram_tree_height = cacheEntry->oramTreeHeight;
      code_oram_position_map = cacheEntry->oramPositionMap;
      code_oram_stash = cacheEntry->oramStash;
      code_oram_stash_metadata = cacheEntry->oramStashMetadata;
      code_oram_stash_size = cacheEntry->oramStashSize;
      entry_count = cacheEntry->oramEntryCount;
      code_oram_cache_stash_size_ptr = &code_oram_cache[codeOramCacheIndex].oramStashSize;
      return;
    }
  }

  // Compute size of code ORAM
  int codeOramSize = 0;
  s32 *functionInfoPtr = function_info;
  while (*functionInfoPtr != 0)
  {
    s32 *codeBlockTablePtr = reinterpret_cast<s32 *>(reinterpret_cast<uptr>(functionInfoPtr) + *functionInfoPtr);
    codeOramSize += *codeBlockTablePtr;
    ++functionInfoPtr;
  }
  entry_count = codeOramSize;

  // The tree size is ceil(log2(N))-1
  // Find next power of 2
  int treeSize = 2; // This is always off-by-one (height 0 -> size 1, 1 -> 3, 2 -> 7)
  int treeHeight = 0;
  while(treeSize - 1 < entry_count)
  {
    treeSize *= 2;
    ++treeHeight;
  }
  treeSize /= 2;
  --treeHeight;

  // For small bucket sizes, add safety margin
  if(bucket_size == 1)
  {
    treeSize *= 2 * 2;
    treeHeight += 2;
  }
  else if(bucket_size == 2)
  {
    treeSize *= 2;
    treeHeight += 1;
  }

  int leafCount = treeSize / 2;

  // Utility function for aligning a size to page size
  auto align_to_page = [] (int size) -> int {
    if(size & 0xfff)
      return (size & ~0xfff) + 0x1000;
    return size;
  };

  // Allocate ORAM tree
  // Round total size to next multiple of 4096
  int treeBytes = align_to_page(treeSize * sizeof(code_oram_node));
  code_oram_tree = reinterpret_cast<code_oram_node *>(internal_mmap(nullptr, treeBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));

  // Allocate ORAM tree metadata array
  // Maps directly to the tree nodes
  int treeMetadataBytes = align_to_page(treeSize * sizeof(code_oram_metadata_entry));
  code_oram_tree_metadata = reinterpret_cast<code_oram_metadata_entry *>(internal_mmap(nullptr, treeMetadataBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
  internal_memset(code_oram_tree_metadata, -1, treeMetadataBytes);

  // Ensure that the stash can hold all tree entries plus a dummy entry.
  // Not really efficient, but can never break.
  int stashBytes = align_to_page((entry_count + 1) * sizeof(code_oram_entry));
  code_oram_stash = reinterpret_cast<code_oram_entry *>(internal_mmap(nullptr, stashBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));

  int stashMetadataBytes = align_to_page((entry_count + 1) * sizeof(code_oram_metadata_entry));
  code_oram_stash_metadata = reinterpret_cast<code_oram_metadata_entry *>(internal_mmap(nullptr, stashMetadataBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
  internal_memset(code_oram_stash_metadata, -1, stashMetadataBytes);

  leaf_count = leafCount;
  code_oram_tree_height = treeHeight;
  code_oram_stash_size = code_oram_tree_height * bucket_size; // Minimum required size; the stash grows dynamically

  // Allocate position map
  // Round total size to next multiple of 4096
  int positionMapBytes = align_to_page(entry_count * sizeof(code_oram_metadata_entry));
  code_oram_position_map = reinterpret_cast<code_oram_metadata_entry *>(internal_mmap(nullptr, positionMapBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
  internal_memset(code_oram_position_map, -1, positionMapBytes);

  if(codeOramCacheIndex >= code_oram_cache_size)
    codeOramCacheIndex = 0; // TODO there is a memory leak if we don't free old code ORAMs

  code_oram_cache_entry *cacheEntry = &code_oram_cache[codeOramCacheIndex];
  cacheEntry->functionInfoPtr = function_info;
  cacheEntry->oramTree = code_oram_tree;
  cacheEntry->oramTreeMetadata = code_oram_tree_metadata;
  cacheEntry->leafCount = leaf_count;
  cacheEntry->oramTreeHeight = code_oram_tree_height;
  cacheEntry->oramPositionMap = code_oram_position_map;
  cacheEntry->oramStash = code_oram_stash;
  cacheEntry->oramStashMetadata = code_oram_stash_metadata;
  cacheEntry->oramStashSize = code_oram_stash_size;
  cacheEntry->oramEntryCount = entry_count;
  code_oram_cache_stash_size_ptr = &code_oram_cache[codeOramCacheIndex].oramStashSize;

  DEBUG("[OBELIX] Code ORAM size = %d; leaf count = %d; tree size = %d; height = %d\n", entry_count, leafCount, treeSize, treeHeight);

  // Comparison register
  __m256i vInvalidAddress = _mm256_set1_epi32(invalid_address);

  // Copy code blocks into ORAM
  functionInfoPtr = function_info;
  int positionMapIndex = 0;
  while (*functionInfoPtr != 0)
  {
    s32 *codeBlockTablePtr = reinterpret_cast<s32 *>(reinterpret_cast<uptr>(functionInfoPtr) + *functionInfoPtr);
    ++codeBlockTablePtr; // Skip block count
    while (*codeBlockTablePtr != 0)
    {
      u8 *codeBlock = reinterpret_cast<u8 *>(codeBlockTablePtr) + *codeBlockTablePtr;
      uptr codeBlockAddress = reinterpret_cast<uptr>(codeBlock);

      // Explicitly load code block data; the compiler will likely put it into registers
      v_code_block_t codeBlockData;
      for(int i = 0; i < code_block_size / 32; ++i)
        codeBlockData[i] = _mm256_load_si256(reinterpret_cast<const __m256i *>(codeBlock + 32 * i));

      unsigned int randomLeaf = get_random_leaf();
      DEBUG("[OBELIX] Inserting %lx\n", codeBlockAddress);
      DEBUG("[OBELIX]   Random leaf: %u\n", randomLeaf);

      // Traverse path from leaf to top, until there is an empty bucket
      unsigned int curIndex = randomLeaf;
      int found = 0;
      while(true)
      {
        DEBUG("[OBELIX]   Checking node: %d (found = %d)\n", curIndex, found);

        code_oram_node *node = code_oram_tree + curIndex;
        for(int b = 0; b < bucket_size; ++b)
        {
          code_oram_entry *bucketEntry = node->entries + b;
          code_oram_metadata_entry *bucketEntryMetadata = get_bucket_entry_metadata(curIndex, b);

          v_code_block_t &bucketEntryData = *reinterpret_cast<v_code_block_t *>(bucketEntry->data);

          // Conditionally copy code block contents
          // This also writes when found == 1, but we don't care (address is still invalid)
          __m256i vEntryAddress = _mm256_set1_epi32(bucketEntryMetadata->address);
#if defined(__AVX512F__) && defined(__AVX512VL__)
          __mmask8 mask = _mm256_cmpneq_epi32_mask(vEntryAddress, vInvalidAddress); // 1 if address != INVALID
          // The reversed mask allows us to blend directly with the data as memory operand,
          // saving one instruction

          for (int i = 0; i < code_block_size / 32; ++i)
            bucketEntryData[i] = _mm256_mask_blend_epi32(mask, codeBlockData[i], bucketEntryData[i]);

#else
          __m256i vMask = _mm256_cmpeq_epi32(vEntryAddress, vInvalidAddress); // 1 if address == INVALID

          for(int i = 0; i < code_block_size / 32; ++i)
            bucketEntryData[i] = _mm256_blendv_epi8(bucketEntryData[i], codeBlockData[i], vMask);
#endif
          // Conditionally update bucket
          cmov3_test<u32, unsigned int, int>(bucketEntryMetadata->address, static_cast<u32>(codeBlockAddress),
                                             bucketEntryMetadata->leaf, randomLeaf,
                                             found, 1,
                                             bucketEntryMetadata->address == invalid_address && !found);
        }

        // Did we reach and check the root node?
        if(curIndex == 0)
          break;

        curIndex = get_parent(curIndex);
      }

      // Spill to stash if necessary
      for(int s = 0; s < code_oram_stash_size; ++s)
      {
        code_oram_entry *stashEntry = code_oram_stash + s;
        code_oram_metadata_entry *stashEntryMetadata = code_oram_stash_metadata + curIndex;

        v_code_block_t &stashEntryData = *reinterpret_cast<v_code_block_t *>(stashEntry->data);

        // Conditionally copy code block contents
        // This also writes when found == 1, but we don't care (address is still invalid)
        __m256i vEntryAddress = _mm256_set1_epi32(stashEntryMetadata->address);
#if defined(__AVX512F__) && defined(__AVX512VL__)
        __mmask8 mask = _mm256_cmpneq_epi32_mask(vEntryAddress, vInvalidAddress); // 1 if address != INVALID
        // The reversed mask allows us to blend directly with the data as memory operand,
        // saving one instruction

        for (int i = 0; i < code_block_size / 32; ++i)
          stashEntryData[i] = _mm256_mask_blend_epi32(mask, codeBlockData[i], stashEntryData[i]);

#else
        __m256i vMask = _mm256_cmpeq_epi32(vEntryAddress, vInvalidAddress); // 1 if address == INVALID

        for(int i = 0; i < code_block_size / 32; ++i)
          stashEntryData[i] = _mm256_blendv_epi8(stashEntryData[i], codeBlockData[i], vMask);
#endif

        // Conditionally update slot
        cmov3_test<u32, unsigned int, int>(stashEntryMetadata->address, static_cast<u32>(codeBlockAddress),
                                            stashEntryMetadata->leaf, randomLeaf,
                                            found, 1,
                                            stashEntryMetadata->address == invalid_address && !found);
      }

      // If the stash is too small, expand it and store our new entry
      if(!found)
      {
        code_oram_entry *stashEnd = code_oram_stash + code_oram_stash_size;
        code_oram_metadata_entry *stashEndMetadata = code_oram_stash_metadata + code_oram_stash_size;

        v_code_block_t &stashEndData = *reinterpret_cast<v_code_block_t *>(stashEnd->data);

        stashEndMetadata->address = static_cast<u32>(codeBlockAddress);
        stashEndMetadata->leaf = randomLeaf;

        for(int i = 0; i < code_block_size / 32; ++i)
          stashEndData[i] = codeBlockData[i];

        ++code_oram_stash_size;
      }

      // Update position map
      code_oram_metadata_entry *posMap = &code_oram_position_map[positionMapIndex++];
      if(posMap->address != invalid_address){
        Printf("Position map entry is not empty. Address collision? %x != %x\n", posMap->address, invalid_address);
        internal__exit(1);
      }
      posMap->address = static_cast<u32>(codeBlockAddress);
      posMap->leaf = randomLeaf;

      ++codeBlockTablePtr;
    }

    ++functionInfoPtr;
  }

  // Mark end of positions array
  code_oram_position_map[positionMapIndex].address = invalid_address;

  CHECK(positionMapIndex == entry_count && "Position map should contain exactly entry_count entries");

  DEBUG("[OBELIX] ORAM initialized, stash size = %d\n", code_oram_stash_size);
  /*
  dump_tree();
  dump_stash();
  dump_position_map();
  */
}

void code_oram_path_c_fini()
{
  *code_oram_cache_stash_size_ptr = code_oram_stash_size;

  DEBUG("[OBELIX]   Final stash size: %d\n", code_oram_stash_size);
  DEBUG("[OBELIX]   Scanned data per access (estimation): 1*%d*%lu B posMap, ((%d*%d)*%d+1+%d*%d)*(%lu+%lu) B stash, 2*(%d*%d)*(%lu+%lu) B tree bucket entries\n",
        entry_count, sizeof(code_oram_metadata_entry), // posMap
        code_oram_tree_height, bucket_size, code_oram_stash_size, code_oram_tree_height, code_oram_stash_size, sizeof(code_oram_metadata_entry), sizeof(code_oram_entry), // stash
        code_oram_tree_height, bucket_size, sizeof(code_oram_metadata_entry), sizeof(code_oram_entry) // tree
  );
  DEBUG("[OBELIX]     total: %lu B\n",
        1 * entry_count * sizeof(code_oram_metadata_entry)
            + (2 * (code_oram_tree_height * bucket_size) * code_oram_stash_size + 1) * (sizeof(code_oram_metadata_entry) + sizeof(code_oram_entry))
            + 2 * (code_oram_tree_height * bucket_size) * (sizeof(code_oram_metadata_entry) + sizeof(code_oram_entry))
  );
  DEBUG("[OBELIX]     (linear: %d B)\n", entry_count * (8 + code_block_size));
}

void code_oram_path_c_query(uptr address)
{
  DEBUG("[OBELIX] Retrieving %lx (-> %x)\n", address, static_cast<u32>(address));

  // Get random new leaf for block
  unsigned int randomLeaf = get_random_leaf();
  DEBUG("[OBELIX]   Random leaf: %u\n", randomLeaf);

  // Scan position map for entry, get old leaf and set the new one
  unsigned int oldLeaf = 0;
  for(int i = 0; i < entry_count; ++i)
  {
    code_oram_metadata_entry *posMap = code_oram_position_map + i;

    cmov2rw_cmp<unsigned int, u32>(oldLeaf, posMap->leaf, randomLeaf,
                                    posMap->address, static_cast<u32>(address));
  }

  CHECK(oldLeaf != 0 && "Could not extract leaf from position map");

  DEBUG("[OBELIX]   Reading path %u\n", oldLeaf);

  // Comparison register
  __m256i vInvalidAddress = _mm256_set1_epi32(invalid_address);

  // Read entire path from leaf to root
  unsigned int curIndex = oldLeaf;
  while(true)
  {
    code_oram_node *node = code_oram_tree + curIndex;
    for(int b = 0; b < bucket_size; ++b)
    {
      code_oram_entry *bucketEntry = node->entries + b;
      code_oram_metadata_entry *bucketEntryMetadata = get_bucket_entry_metadata(curIndex, b);

      // Explicitly load data; the compiler will likely put it into registers
      v_code_block_t bucketEntryData;
      for (int i = 0; i < code_block_size / 32; ++i)
        bucketEntryData[i] = _mm256_load_si256(reinterpret_cast<const __m256i *>(bucketEntry->data + 32 * i));

      // Scan stash for available slot and copy entry to stash
      int stashFound = 0;
      for (int s = 0; s < code_oram_stash_size; ++s)
      {
        code_oram_entry *stashEntry = code_oram_stash + s;
        code_oram_metadata_entry *stashEntryMetadata = code_oram_stash_metadata + s;

        v_code_block_t &stashEntryData = *reinterpret_cast<v_code_block_t *>(stashEntry->data);

        // Conditionally copy code block contents
        // This also writes when stashFound == 1, but we don't care (address is still invalid)
        __m256i vEntryAddress = _mm256_set1_epi32(stashEntryMetadata->address);
#if defined(__AVX512F__) && defined(__AVX512VL__)
        __mmask8 mask = _mm256_cmpneq_epi32_mask(vEntryAddress, vInvalidAddress); // 1 if address != INVALID

        for (int i = 0; i < code_block_size / 32; ++i)
          stashEntryData[i] = _mm256_mask_blend_epi32(mask, bucketEntryData[i], stashEntryData[i]);
#else
        __m256i vMask = _mm256_cmpeq_epi32(vEntryAddress, vInvalidAddress); // 1 if address == INVALID

        for (int i = 0; i < code_block_size / 32; ++i)
          stashEntryData[i] = _mm256_blendv_epi8(stashEntryData[i], bucketEntryData[i], vMask);
#endif

        // Conditionally update slot
        cmov3_test<u32, unsigned int, int>(stashEntryMetadata->address, bucketEntryMetadata->address,
                                           stashEntryMetadata->leaf, bucketEntryMetadata->leaf,
                                           stashFound, 1,
                                           stashEntryMetadata->address == invalid_address && !stashFound);

        // If the bucket entry contains the searched block, use the new leaf ID
        cmov_cmp<unsigned int, u32>(stashEntryMetadata->leaf, randomLeaf,
                                    stashEntryMetadata->address, static_cast<u32>(address));
      }

      // If the stash is too small, expand it and store bucket entry there
      if (!stashFound) {
        code_oram_entry *stashEnd = code_oram_stash + code_oram_stash_size;
        code_oram_metadata_entry *stashEndMetadata = code_oram_stash_metadata + code_oram_stash_size;

        stashEndMetadata->address = bucketEntryMetadata->address;
        stashEndMetadata->leaf = bucketEntryMetadata->leaf;
        cmov_cmp<unsigned int, u32>(stashEndMetadata->leaf, randomLeaf,
                                    bucketEntryMetadata->address, static_cast<u32>(address));

        for (int i = 0; i < code_block_size; i += 32)
          _mm256_store_si256(reinterpret_cast<__m256i *>(&stashEnd->data[i]), bucketEntryData[i / 32]);

        ++code_oram_stash_size;
        DEBUG("Expanding stash during path read -> %d\n", code_oram_stash_size);
      }

      // Mark bucket entry as empty
      bucketEntryMetadata->address = invalid_address;
    }

    // Did we reach and process the root node?
    if(curIndex == 0)
      break;

    curIndex = get_parent(curIndex);
  }

  // Retrieve searched code block from stash
  v_code_block_t codeScratchPadTmp; // Use (likely) register storage to avoid lots of read/writes
  __m256i vAddress = _mm256_set1_epi32(static_cast<u32>(address));
  bool codeBlockFound = false;
  for(int s = 0; s < code_oram_stash_size; ++s)
  {
    code_oram_entry *stashEntry = code_oram_stash + s;
    code_oram_metadata_entry *stashEntryMetadata = code_oram_stash_metadata + s;

    v_code_block_t &stashEntryData = *reinterpret_cast<v_code_block_t *>(stashEntry->data);

    if(stashEntryMetadata->address == static_cast<u32>(address))
      codeBlockFound = true;

    // Conditionally copy code block contents
    __m256i vEntryAddress = _mm256_set1_epi32(stashEntryMetadata->address);
#if defined(__AVX512F__) && defined(__AVX512VL__)
    __mmask8 mask = _mm256_cmpeq_epi32_mask(vEntryAddress, vAddress); // 1 if stashEntry->address == address

    for(int i = 0; i < code_block_size / 32; ++i)
      codeScratchPadTmp[i] = _mm256_mask_blend_epi32(mask, codeScratchPadTmp[i], stashEntryData[i]);
#else
    __m256i vMask = _mm256_cmpeq_epi32(vEntryAddress, vAddress); // 1 if stashEntry->address == address

    for(int i = 0; i < code_block_size / 32; ++i)
      codeScratchPadTmp[i] = _mm256_blendv_epi8(codeScratchPadTmp[i], stashEntryData[i], vMask);
#endif
  }

  // Copy retrieved code into scratch pad
  u8 *codeScratchPad = reinterpret_cast<u8 *>(code_scratch_pad_address);
  for(int i = 0; i < code_block_size / 32; ++i)
    _mm256_store_si256(reinterpret_cast<__m256i *>(codeScratchPad + 32 * i), codeScratchPadTmp[i]);

  CHECK(codeBlockFound && "Code block could not be located in stash");

  // Write back into tree
  // Iterate through _new_ path and identify stash entries that can be copied into the nodes
  curIndex = randomLeaf;
  while(true)
  {
    code_oram_node *node = code_oram_tree + curIndex;
    for(int b = 0; b < bucket_size; ++b)
    {
      code_oram_entry *bucketEntry = node->entries + b;
      code_oram_metadata_entry *bucketEntryMetadata = get_bucket_entry_metadata(curIndex, b);

      // Use temporary for reduced memory reads/writes
      v_code_block_t bucketEntryDataTmp;
      for (int i = 0; i < code_block_size / 32; ++i)
        bucketEntryDataTmp[i] = _mm256_load_si256(reinterpret_cast<const __m256i *>(bucketEntry->data + 32 * i));

      int bucketEntryIsEmpty = bucketEntryMetadata->address == invalid_address;

      // TODO ciphertext countermeasure: Initialize register with dummy data, instead of old bucketEntryDataTmp[i]

      // Scan stash for fitting entry and copy, if matching
      for (int s = 0; s < code_oram_stash_size; ++s) {
        code_oram_entry *stashEntry = code_oram_stash + s;
        code_oram_metadata_entry *stashEntryMetadata = code_oram_stash_metadata + s;

        v_code_block_t &stashEntryData = *reinterpret_cast<v_code_block_t *>(stashEntry->data);

        // Only allow copying entries for which the current node is in the path
        int isInPath = is_in_path(stashEntryMetadata->leaf, curIndex);
        int holdsData = stashEntryMetadata->address != invalid_address;
        int doUpdate = bucketEntryIsEmpty && isInPath && holdsData;

        // Conditionally copy code block contents
#if defined(__AVX512F__) && defined(__AVX512VL__)
        __mmask8 mask = doUpdate * 0xff;

        for (int i = 0; i < code_block_size / 32; ++i)
          bucketEntryDataTmp[i] = _mm256_mask_blend_epi32(mask, bucketEntryDataTmp[i], stashEntryData[i]);
#else
        __m256i vMask = _mm256_set1_epi32(doUpdate * static_cast<s32>(-1));

        for (int i = 0; i < code_block_size / 32; ++i)
          bucketEntryDataTmp[i] = _mm256_blendv_epi8(bucketEntryDataTmp[i], stashEntryData[i], vMask);
#endif

        // Conditionally update bucket entry and stash
        cmov3_test<u32, unsigned int, int>(bucketEntryMetadata->address, stashEntryMetadata->address,
                                           bucketEntryMetadata->leaf, stashEntryMetadata->leaf,
                                           bucketEntryIsEmpty, 0,
                                           doUpdate);
        cmov_test<u32>(stashEntryMetadata->address, invalid_address,
                       doUpdate);
      }

      // Copy data into bucket entry
      for (int i = 0; i < code_block_size / 32; ++i)
        _mm256_store_si256(reinterpret_cast<__m256i *>(bucketEntry->data + 32 * i), bucketEntryDataTmp[i]);
    }

    // Did we reach and process the root node?
    if(curIndex == 0)
      break;

    curIndex = get_parent(curIndex);
  }
}
