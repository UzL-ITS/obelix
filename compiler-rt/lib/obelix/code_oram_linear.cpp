
#include "asm_inlines.h"
#include "code_oram_linear.h"
#include "constants.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_posix.h"
#include <sys/mman.h>
#include <immintrin.h>

using namespace __sanitizer;

extern "C" function_info_entry* function_info;
extern "C" u64 code_scratch_pad_address;

// The size of code block fragments.
// DO NOT simply change this, code below won't fully adapt!
static constexpr int code_fragment_size = 32;

// Smallest granularity of leakage. The following code assumes that (aligned)
// accesses within that granularity are indistinguishable.
static constexpr int cache_line_size = 64;

// Gather granularity.
// DO NOT change this, this constant is just for readability.
static constexpr int gather_size = 4; // DWORD
static constexpr int gather_count = 32 / gather_size;

// Padded code block.
struct code_block {
  u8 data[code_block_size];
};

struct original_to_copy_lookup_entry {
  uptr originalAddress;
  uptr copyAddress;
};

struct code_fragment {
  union {
    u8 fragment8[code_fragment_size];
    u32 fragment32[code_fragment_size / gather_size];
  };
};
static_assert(sizeof(code_fragment) == 32); // Assumed in assembly part
struct code_block_encoding {
  static constexpr int fragmentIndexesCount = code_block_size / code_fragment_size;
  static constexpr int fragmentIndexesIntCount = fragmentIndexesCount / 4 + (fragmentIndexesCount % 4 == 0 ? 0 : 1);

  u64 address;
  union {
    u16 fragmentIndexes[fragmentIndexesCount];
    u64 fragmentIndexesInt[fragmentIndexesIntCount];
  };
};

extern "C"
{
  // Both ORAMs: Lookup for mapping function pointers to the original function
  // back to its instrumented equivalent.
  original_to_copy_lookup_entry *original_to_copy_lookup;

  // Naive ORAM
  uptr *code_block_addresses;
  uptr *code_block_addresses_end;
  code_block *code_blocks;

  // Compressed ORAM
  code_fragment *code_fragments[code_block_size / code_fragment_size] = { };
  code_fragment *code_fragments_ends[code_block_size / code_fragment_size] = { };
  code_block_encoding *code_block_encodings = nullptr;
  code_block_encoding *code_block_encodings_end = nullptr;

  uptr code_oram_linear_naive_query_c(uptr address);
  uptr code_oram_linear_compressed_query_c(uptr address);
  uptr code_oram_linear_naive_query_text_c(uptr address);
}

// Cache
struct cache_entry_naive {
  function_info_entry *functionInfoPtr = nullptr;
  original_to_copy_lookup_entry *originalToCopyLookup = nullptr;
  uptr *codeBlockAddresses = nullptr;
  uptr *codeBlockAddressesEnd = nullptr;
  code_block *codeBlocks = nullptr;
};
struct cache_entry_compressed {
  function_info_entry *functionInfoPtr = nullptr;
  original_to_copy_lookup_entry *originalToCopyLookup = nullptr;
  code_fragment *codeFragments[code_block_size / code_fragment_size] = { };
  code_fragment *codeFragmentsEnds[code_block_size / code_fragment_size] = { };
  code_block_encoding *codeBlockEncodings = nullptr;
  code_block_encoding *codeBlockEncodingsEnd = nullptr;
};
static constexpr int cache_size = 16;
static cache_entry_naive cache_naive[cache_size] = { };
static cache_entry_compressed cache_compressed[cache_size] = { };

static original_to_copy_lookup_entry *build_original_to_copy_lookup(function_info_entry *functionInfo)
{
  constexpr int lookup_entry_count = 4096 / sizeof(original_to_copy_lookup_entry);
  original_to_copy_lookup_entry *lookup = reinterpret_cast<original_to_copy_lookup_entry *>(internal_mmap(0, lookup_entry_count * sizeof(original_to_copy_lookup_entry), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));

  function_info_entry *functionInfoPtr = function_info;
  int functionCount = 0;
  original_to_copy_lookup_entry *ptr = lookup;
  while (functionInfoPtr->codeTableOffset != 0)
  {
    ++functionCount;
    if(functionCount == lookup_entry_count)
    {
      Printf("No remaining space in original->copy lookup\n");
      internal__exit(-1);
    }

    ptr->originalAddress = reinterpret_cast<uptr>(functionInfoPtr) + functionInfoPtr->originalCodeOffset;

    // Get address of function's first code block
    s32 *codeBlockTablePtr = reinterpret_cast<s32 *>(reinterpret_cast<uptr>(functionInfoPtr) + functionInfoPtr->codeTableOffset);
    ++codeBlockTablePtr; // Skip block count
    ptr->copyAddress = reinterpret_cast<uptr>(codeBlockTablePtr) + *codeBlockTablePtr;

    ++ptr;
    ++functionInfoPtr;
  }

  // 0 marks the end
  ptr->originalAddress = 0;
  ptr->copyAddress = 0;

  return lookup;
}

void init_linear_oram_naive()
{
  // TODO May expose length of individual code blocks.

  // Did we cache the code ORAM?
  int cacheIndex;
  for(cacheIndex = 0; cacheIndex < cache_size; ++cacheIndex)
  {
    cache_entry_naive *cacheEntry = &cache_naive[cacheIndex];

    if(cacheEntry->functionInfoPtr == nullptr)
      break;

    if(cacheEntry->functionInfoPtr == function_info)
    {
      original_to_copy_lookup = cacheEntry->originalToCopyLookup;
      code_block_addresses = cacheEntry->codeBlockAddresses;
      code_block_addresses_end = cacheEntry->codeBlockAddressesEnd;
      code_blocks = cacheEntry->codeBlocks;
      return;
    }
  }

  // Initial allocation
  // We resize those arrays dynamically as needed
  u32 codeBlocksAllocSize = 4 * 4096;
  u32 codeBlocksCapacity = codeBlocksAllocSize / sizeof(code_block);
  u32 codeBlockAddressesAllocSize = 4096;
  u32 codeBlockAddressesCapacity = codeBlockAddressesAllocSize / sizeof(uptr);
  code_blocks = reinterpret_cast<code_block *>(internal_mmap(nullptr, codeBlocksAllocSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
  code_block_addresses = reinterpret_cast<uptr *>(internal_mmap(nullptr, codeBlockAddressesAllocSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
  code_block_addresses_end = code_block_addresses;

  // Iterate code blocks and fill arrays
  function_info_entry *functionInfoPtr = function_info;
  u32 codeBlockCount = 0;
  code_block *codeBlock = code_blocks;
  while(functionInfoPtr->codeTableOffset != 0)
  {
    s32 *codeBlockTablePtr = reinterpret_cast<s32 *>(reinterpret_cast<uptr>(functionInfoPtr) + functionInfoPtr->codeTableOffset);
    ++codeBlockTablePtr; // Skip block count
    while (*codeBlockTablePtr != 0)
    {
      u8 *codeBlockPtr = reinterpret_cast<u8 *>(codeBlockTablePtr) + *codeBlockTablePtr;

      *code_block_addresses_end = reinterpret_cast<uptr>(codeBlockPtr);

      // Copy code
      internal_memcpy(codeBlock->data, codeBlockPtr, code_block_size);

      ++codeBlockTablePtr;

      ++code_block_addresses_end;
      ++codeBlock;

      ++codeBlockCount;

      // Resize arrays, if necessary
      if(codeBlockCount == codeBlocksCapacity)
      {
        codeBlocksAllocSize *= 2;
        codeBlocksCapacity = codeBlocksAllocSize / sizeof(code_block);
        code_blocks = reinterpret_cast<code_block *>(internal_mremap(code_blocks, codeBlocksAllocSize / 2, codeBlocksAllocSize, MREMAP_MAYMOVE, nullptr));
        codeBlock = code_blocks + codeBlockCount;
      }
      if(codeBlockCount == codeBlockAddressesCapacity)
      {
        codeBlockAddressesAllocSize *= 2;
        codeBlockAddressesCapacity = codeBlockAddressesAllocSize / sizeof(uptr);
        code_block_addresses = reinterpret_cast<uptr *>(internal_mremap(code_block_addresses, codeBlockAddressesAllocSize / 2, codeBlockAddressesAllocSize, MREMAP_MAYMOVE, nullptr));
        code_block_addresses_end = code_block_addresses + codeBlockCount;
      }
    }

    ++functionInfoPtr;
  }
  
  original_to_copy_lookup = build_original_to_copy_lookup(function_info);

  // Update cache
  if(cacheIndex >= cache_size)
  {
    // TODO there is a memory leak if we don't free old code ORAMs
    cacheIndex = 0;
  }
  cache_entry_naive *newCacheEntry = &cache_naive[cacheIndex];
  newCacheEntry->functionInfoPtr = function_info;
  newCacheEntry->originalToCopyLookup = original_to_copy_lookup;
  newCacheEntry->codeBlockAddresses = code_block_addresses;
  newCacheEntry->codeBlockAddressesEnd = code_block_addresses_end;
  newCacheEntry->codeBlocks = code_blocks;

  /*
  Printf("[OBELIX] Processed %u code blocks\n", codeBlockCount);
  code_block *blockPtr = code_blocks;
  for(uptr *addrPtr = code_block_addresses; addrPtr != code_block_addresses_end; ++addrPtr) {
    Printf("%012lx  ", *addrPtr);
    for(int i = 0; i < code_block_size; ++i) {
      Printf("%02x ", blockPtr->data[i]);
    }
    Printf("\n");

    ++blockPtr;
  }
  //*/
}

void init_linear_oram_compressed()
{
  // TODO This not constant-time and may expose _some_ information about the code structure.
  //      Ideally this whole step is done at compile time. If we want to do this at runtime,
  //      we can mitigate most leakage by scanning always over the entire fragment array, and
  //      using a constant-time memcmp. In any case, the performance impact is negligible, as
  //      we cache the fragments and encodings after the first execution.

  // Did we cache the code ORAM?
  int cacheIndex;
  for(cacheIndex = 0; cacheIndex < cache_size; ++cacheIndex)
  {
    cache_entry_compressed *cacheEntry = &cache_compressed[cacheIndex];

    if(cacheEntry->functionInfoPtr == nullptr)
      break;

    if(cacheEntry->functionInfoPtr == function_info)
    {
      original_to_copy_lookup = cacheEntry->originalToCopyLookup;
      for(int i = 0; i < code_block_size / code_fragment_size; ++i) {
        code_fragments[i] = cacheEntry->codeFragments[i];
        code_fragments_ends[i] = cacheEntry->codeFragmentsEnds[i];
      }
      code_block_encodings = cacheEntry->codeBlockEncodings;
      code_block_encodings_end = cacheEntry->codeBlockEncodingsEnd;
      return;
    }
  }

  // Initial allocation
  // We resize those arrays dynamically as needed
  u32 codeFragsAllocSize = 4 * 4096;
  u32 codeFragsCapacity = codeFragsAllocSize / sizeof(code_fragment);
  u32 codeEncsAllocSize = 4096;
  u32 codeEncsCapacity = codeEncsAllocSize / sizeof(code_block_encoding);
  for(int i = 0; i < code_block_size / code_fragment_size; ++i) {
    code_fragments[i] = reinterpret_cast<code_fragment *>(internal_mmap(nullptr, codeFragsAllocSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
    code_fragments_ends[i] = code_fragments[i];
  }
  code_block_encodings = reinterpret_cast<code_block_encoding *>(internal_mmap(nullptr, codeEncsAllocSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
  code_block_encodings_end = code_block_encodings;

  // Iterate code blocks and fill arrays
  function_info_entry *functionInfoPtr = function_info;
  u32 codeFragmentsCounts[code_block_size / code_fragment_size] {};
  u32 totalCodeFragmentsCount = 0;
  u32 codeEncsCount = 0;
  while(functionInfoPtr->codeTableOffset != 0)
  {
    s32 *codeBlockTablePtr = reinterpret_cast<s32 *>(reinterpret_cast<uptr>(functionInfoPtr) + functionInfoPtr->codeTableOffset);
    ++codeBlockTablePtr; // Skip block count
    while (*codeBlockTablePtr != 0)
    {
      u8 *codeBlockPtr = reinterpret_cast<u8 *>(codeBlockTablePtr) + *codeBlockTablePtr;

      code_block_encodings_end->address = reinterpret_cast<uptr>(codeBlockPtr);

      for(int b = 0, i = 0; b < code_block_size; b += code_fragment_size, ++i)
      {
        code_fragment *fragBegin = code_fragments[i];
        code_fragment *fragEnd = code_fragments_ends[i];
        code_fragment *fragPtr = fragBegin;
        bool found = false;
        while(fragPtr != fragEnd)
        {
          if(internal_memcmp(codeBlockPtr + b, fragPtr->fragment8, code_fragment_size) == 0) {
            found = true;
            break;
          }

          ++fragPtr;
        }

        if(!found) {
          internal_memcpy(fragEnd->fragment8, codeBlockPtr + b, code_fragment_size);
          code_fragments_ends[i] = ++fragEnd;
          ++codeFragmentsCounts[i];
          ++totalCodeFragmentsCount;

          if(codeFragmentsCounts[i] == codeFragsCapacity)
          {
            // Resize all fragment arrays
            codeFragsAllocSize *= 2;
            codeFragsCapacity = codeFragsAllocSize / sizeof(code_fragment);
            for(int j = 0; j < code_block_size / code_fragment_size; ++j) {
              code_fragments[j] = reinterpret_cast<code_fragment *>(internal_mremap(code_fragments[j], codeFragsAllocSize / 2, codeFragsAllocSize, MREMAP_MAYMOVE, nullptr));
              code_fragments_ends[j] = code_fragments[j] + codeFragmentsCounts[j];
            }
          }
        }

        code_block_encodings_end->fragmentIndexes[i] = fragPtr - fragBegin;
      }

      ++codeBlockTablePtr;
      ++code_block_encodings_end;
      ++codeEncsCount;

      if(codeEncsCount == codeEncsCapacity)
      {
        // Resize array
        codeEncsAllocSize *= 2;
        codeEncsCapacity = codeEncsAllocSize / sizeof(code_block_encoding);
        code_block_encodings = reinterpret_cast<code_block_encoding *>(internal_mremap(code_block_encodings, codeEncsAllocSize / 2, codeEncsAllocSize, MREMAP_MAYMOVE, nullptr));
        code_block_encodings_end = code_block_encodings + codeEncsCount;
      }
    }

    ++functionInfoPtr;
  }

  // Transpose fragments in 4-byte chunks:
  //   a0 a1 a2 a3 a4 a5 a6 a7
  //   b0 b1 b2 b3 b4 b5 b6 b7  <- we want this line
  //   c0 c1 c2 c3 c4 c5 c6 c7
  // ->
  //   a0 b0 c0 d0 e0 f0 g0 h0
  //   a1 b1 c1 d1 e1 f1 g1 h1
  //   a2 b2 c2 d2 e2 f2 g2 h2
  //      ^
  //     we want this column
  //
  // ...this way, we can execute a parallel gather on lots of cache lines at
  // once, without needing masking.
  for(int i = 0; i < code_block_size / code_fragment_size; ++i)
  {
    // First, ensure that the amount of fragments is a multiple of the gather size
    u32 fragmentCount = codeFragmentsCounts[i];
    if(fragmentCount % gather_count > 0)
    {
      // Add dummy blocks (no need to initialize them)
      u32 dummyCount = gather_count - (fragmentCount % gather_count);
      fragmentCount += dummyCount;
      codeFragmentsCounts[i] = fragmentCount;
      code_fragments_ends[i] = code_fragments[i] + fragmentCount;

      // Ensure that array has sufficient size
      if(fragmentCount == codeFragsCapacity)
      {
        // Resize all fragment arrays
        codeFragsAllocSize *= 2;
        codeFragsCapacity = codeFragsAllocSize / sizeof(code_fragment);
        for(int j = 0; j < code_block_size / code_fragment_size; ++j) {
          code_fragments[j] = reinterpret_cast<code_fragment *>(internal_mremap(code_fragments[j], codeFragsAllocSize / 2, codeFragsAllocSize, MREMAP_MAYMOVE, nullptr));
          code_fragments_ends[j] = code_fragments[j] + codeFragmentsCounts[j];
        }
      }
    }

    // Transpose groups of fragments
    code_fragment *fragPtr = code_fragments[i];
    auto fragPart = [&] (int row, int col) -> u32 * {
      return &fragPtr[row].fragment32[col];
    };
    for(u32 g = 0; g < fragmentCount; g += gather_count, fragPtr += gather_count)
    {
      // Swap symmetric to diagonal
      static_assert(code_fragment_size / gather_size == gather_count);
      for(int x = 0; x < gather_count; ++x)
      {
        for(int y = 0; y < x; ++y)
        {
          u32 tmp = *fragPart(x, y);
          *fragPart(x, y) = *fragPart(y, x);
          *fragPart(y, x) = tmp;
        }
      }
    }
  }

  original_to_copy_lookup = build_original_to_copy_lookup(function_info);

  // Update cache
  if(cacheIndex >= cache_size)
  {
    // TODO there is a memory leak if we don't free old code ORAMs
    cacheIndex = 0;
  }
  cache_entry_compressed *newCacheEntry = &cache_compressed[cacheIndex];
  newCacheEntry->functionInfoPtr = function_info;
  newCacheEntry->originalToCopyLookup = original_to_copy_lookup;
  for(int i = 0; i < code_block_size / code_fragment_size; ++i) {
    newCacheEntry->codeFragments[i] = code_fragments[i];
    newCacheEntry->codeFragmentsEnds[i] = code_fragments_ends[i];
  }
  newCacheEntry->codeBlockEncodings = code_block_encodings;
  newCacheEntry->codeBlockEncodingsEnd = code_block_encodings_end;

  /*
  // Debug info
  Printf("Fragments:\n");
  for(int i = 0; i < code_block_size / code_fragment_size; ++i) {
    for(code_fragment *fragPtr = code_fragments[i]; fragPtr != code_fragments_ends[i]; ++fragPtr) {
      Printf("%d.%02x  ", i, static_cast<unsigned int>(fragPtr - code_fragments[i]));
      for(int j = 0; j < code_fragment_size; ++j) {
        Printf("%02x ", fragPtr->fragment8[j]);
      }
      Printf("\n");
    }
  }
  Printf("Block encodings:\n");
  for(code_block_encoding *encPtr = code_block_encodings; encPtr != code_block_encodings_end; ++encPtr) {
    Printf("%012llx  ", encPtr->address);
    for(int i = 0; i < code_block_size / code_fragment_size; ++i) {
      Printf("%02x ", encPtr->fragmentIndexes[i]);
    }
    Printf("\n");
  }
  Printf("Unique fragments: %u\n", totalCodeFragmentsCount);
  Printf("Number of blocks: %u\n", codeEncsCount);

  // Statistics
  int originalMemoryConsumption = codeEncsCount * (4 + code_block_size);
  int oramMemoryConsumption = codeEncsCount * sizeof(code_block_encoding) + totalCodeFragmentsCount * sizeof(code_fragment);
  Printf("Memory original vs. compressed: %d vs. %d -> %d %%\n", originalMemoryConsumption, oramMemoryConsumption, 100 * oramMemoryConsumption / originalMemoryConsumption);
  //internal__exit(0);
  //*/
}

uptr code_oram_linear_naive_query_c(uptr address)
{
  static_assert(code_block_size % 32 == 0);

  __m256i *codeScratchPad = reinterpret_cast<__m256i *>(code_scratch_pad_address);

  // Check whether we have a hit in the original->instrumented mapping and update
  // address
  original_to_copy_lookup_entry *lookupEntry = original_to_copy_lookup;
  uptr copyAddress = address;
  //Printf("Converting %lx", address);
  while(lookupEntry->originalAddress != 0)
  {
    cmov_cmp<uptr, uptr>(copyAddress, lookupEntry->copyAddress, lookupEntry->originalAddress, address);
    ++lookupEntry;
  }
  address = copyAddress;
  //Printf(" -> %lx\n", address);

  // Comparison register
  __m256i vAddress = _mm256_set1_epi64x(address);

  // Temporaries for holding the fetched blocks
  __m256i tmp[code_block_size / 32];

  // Iterate code blocks and match against address
  uptr *addrPtr = code_block_addresses;
  code_block *blockPtr = code_blocks;
  while(addrPtr != code_block_addresses_end)
  {
    __m256i vEntryAddress = _mm256_set1_epi64x(*addrPtr);
    __m256i vMask = _mm256_cmpeq_epi64(vEntryAddress, vAddress);

    for(int b = 0; b < code_block_size / 32; ++b)
      tmp[b] = _mm256_blendv_epi8(tmp[b], *reinterpret_cast<__m256i *>(&blockPtr->data[32 * b]), vMask);

    ++addrPtr;
    ++blockPtr;
  }

  for(int b = 0; b < code_block_size / 32; ++b)
    _mm256_store_si256(&codeScratchPad[b], tmp[b]);

  /*
  Printf("Fetched: %012lx  ", address);
  for(int i = 0; i < code_block_size; ++i) {
    Printf("%02x ", reinterpret_cast<u8 *>(code_scratch_pad_address)[i]);
  }
  Printf("\n");
  //*/

  /*
  // Sanity check: Is the address present in the ORAM?
  addrPtr = code_block_addresses;
  bool addrFound = false;
  while(addrPtr != code_block_addresses_end)
  {
    if(*addrPtr == address)
    {
      addrFound = true;
      break;
    }

    ++addrPtr;
  }
  if(!addrFound)
  {
    Printf("Could not find address %lx in code ORAM\n", address);
    internal__exit(-1);
  }
  //*/

  return address;
}

uptr code_oram_linear_naive_query_text_c(uptr address)
{
  __m256i *codeScratchPad = reinterpret_cast<__m256i *>(code_scratch_pad_address);

  // Comparison register
  __m256i vAddress = _mm256_set1_epi64x(address);

  // Code block data temporaries
  __m256i block0, block1, block2, block3;

  // Iterate code blocks and match against address
  function_info_entry *functionInfoPtr = function_info;
  while(functionInfoPtr->codeTableOffset != 0)
  {
    s32 *codeBlockTablePtr = reinterpret_cast<s32 *>(reinterpret_cast<uptr>(functionInfoPtr) + functionInfoPtr->codeTableOffset);
    ++codeBlockTablePtr; // Skip block count
    while (*codeBlockTablePtr != 0)
    {
      uptr codeBlockPtr = reinterpret_cast<uptr>(codeBlockTablePtr) + *codeBlockTablePtr;
      __m256i *codeBlock = reinterpret_cast<__m256i *>(codeBlockPtr);

      __m256i vEntryAddress = _mm256_set1_epi64x(codeBlockPtr);
      __m256i vMask = _mm256_cmpeq_epi64(vEntryAddress, vAddress);

      block0 = _mm256_blendv_epi8(block0, codeBlock[0], vMask);
      block1 = _mm256_blendv_epi8(block1, codeBlock[1], vMask);
      block2 = _mm256_blendv_epi8(block2, codeBlock[2], vMask);
      block3 = _mm256_blendv_epi8(block3, codeBlock[3], vMask);

      ++codeBlockTablePtr;
    }

    ++functionInfoPtr;
  }

  codeScratchPad[0] = block0;
  codeScratchPad[1] = block1;
  codeScratchPad[2] = block2;
  codeScratchPad[3] = block3;

  return address;
}

uptr code_oram_linear_compressed_query_c(uptr address)
{
  // Retrieve encoding
  code_block_encoding *encPtr = code_block_encodings;
  code_block_encoding enc;
  while(encPtr != code_block_encodings_end)
  {
    for(int e = 0; e < code_block_encoding::fragmentIndexesIntCount; ++e) {
      cmov_cmp<u64, uptr>(enc.fragmentIndexesInt[e], encPtr->fragmentIndexesInt[e],
                          encPtr->address, address);
    }

    ++encPtr;
  }

  // Find fragments for each index
  u8 *codeScratchPad = reinterpret_cast<u8 *>(code_scratch_pad_address);
  __m256i vOne = _mm256_set1_epi32(1);
  for(int i = 0; i < code_block_encoding::fragmentIndexesCount; ++i)
  {
    // Currently searched fragment index
    int encFragIndex = enc.fragmentIndexes[i];

    // Fragment group which contains this index
    int encFragGroupIndex = encFragIndex / gather_count;
    __m256i vEncFragGroupIndex = _mm256_set1_epi32(encFragGroupIndex);

    // Column within the fragment group that contains this index
    int encFragGroupColumn = encFragIndex % gather_count;

    // Build list of column indexes:
    // 0*gather_count+col  |  1*gather_count+col  |  2*gather_count+col...
    u32 colIndexes[gather_count];
    for(int r = 0; r < gather_count; ++r)
      colIndexes[r] = r * gather_count + encFragGroupColumn;
    __m256i vColumnIndexes = _mm256_load_si256(reinterpret_cast<const __m256i *>(colIndexes));

    // Find fragment index and copy fragment into vFragData
    code_fragment *fragPtr = code_fragments[i];
    code_fragment *fragEnd = code_fragments_ends[i];
    __m256i vCurFragGroupIndex = _mm256_set1_epi32(0);
    __m256i vFragData;
    while(fragPtr != fragEnd)
    {
      // Get column
      __m256i vTmp = _mm256_i32gather_epi32(reinterpret_cast<const int *>(fragPtr->fragment32), vColumnIndexes, 4);

      // Blend column onto result
      __m256i vMask = _mm256_cmpeq_epi32(vCurFragGroupIndex, vEncFragGroupIndex);
      vFragData = _mm256_blendv_epi8(vFragData, vTmp, vMask);

      // Next group
      vCurFragGroupIndex = _mm256_add_epi32(vCurFragGroupIndex, vOne);
      fragPtr += gather_count;
    }

    // Store fragment in code scratchpad
    _mm256_store_si256(reinterpret_cast<__m256i *>(codeScratchPad), vFragData);

    // Next fragment index
    codeScratchPad += code_fragment_size;
  }

  return address;
}