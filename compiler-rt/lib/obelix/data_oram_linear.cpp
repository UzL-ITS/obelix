
#include "asm_inlines.h"
#include "data_oram_linear.h"
#include "constants.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_posix.h"
#include <sys/mman.h>
#include <immintrin.h>

using namespace __sanitizer;

// Controls whether we use the randomized data ORAM.
static bool use_rand_oram = false;

extern "C" u64 data_scratch_pad_address;

struct data_oram_init_entry {
  uptr pointer;
  u64 length;
};

// Pointer to start of pointer array used for data ORAM initialization.
// The array is terminated by a 0. Each entry has 16 bytes.
static data_oram_init_entry *data_oram_init = nullptr;

// Number of entries in the data ORAM init pointer array.
static int data_oram_init_count = 0;

// Size (in bytes) of the pointer array used for data ORAM initialization.
static u64 data_oram_init_capacity = 0;

struct data_rand_oram_entry {
  u64 counterHigh;
  u64 dataHigh;
  u64 counterLow;
  u64 dataLow;
};
static_assert(sizeof(data_rand_oram_entry) == 32);

struct data_oram_entry {
  uptr startAddress;
  uptr endAddress;
  data_rand_oram_entry *randOramStart;
  data_rand_oram_entry *randOramEnd;
  bool isWritable;
};

// Pointer to start of data ORAM pointer array.
// The array is terminated by a 0.
static data_oram_entry *data_oram = nullptr;

// Number of entries in the data ORAM.
static int data_oram_count = 0;

// Capacity of the data ORAM pointer array (in bytes).
static u64 data_oram_capacity = 0;

// Pointer to start of data randomized ORAM.
static data_rand_oram_entry *data_rand_oram = nullptr;
static data_rand_oram_entry *data_rand_oram_end = nullptr;

// Capacity of the data randomized ORAM (in bytes).
static u64 data_rand_oram_capacity = 0;

// Counters used for the data randomized ORAM.
[[gnu::aligned(0x10)]] static u64 data_rand_oram_counters[2] = {0, 0};

// Tracks whether we need to write back.
static bool data_oram_pending_write_back = false;
static uptr data_oram_last_store_address = 0;

extern "C"
{
  void data_oram_linear_query(uptr address, uptr oldDataScratchPadAddress, bool isStore);
  void data_oram_linear_fini();
}

void preinit_linear_data_oram()
{
  // Initialize data ORAM with high capacity to avoid later resize
  // We subtract one element as the last element must be 0
  data_oram_capacity = 0x1000;
  data_oram = reinterpret_cast<data_oram_entry *>(internal_mmap(nullptr, data_oram_capacity, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));

  // Initialize data randomized ORAM with high capacity to avoid later resize
  data_rand_oram_capacity = 0x8000;
  data_rand_oram = reinterpret_cast<data_rand_oram_entry *>(internal_mmap(nullptr, data_rand_oram_capacity, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));

  // We allocate the init array once, with large enough size for all relevant circumstances.
  // Note that it only holds function arguments.
  // Also allocated in __obelix_add_init_data
  if(!data_oram_init)
  {
    data_oram_init_capacity = 0x1000;
    data_oram_init = reinterpret_cast<data_oram_init_entry *>(internal_mmap(nullptr, data_oram_init_capacity, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
  }
}

void dump_linear_data_oram()
{
  // Data ORAM
  Printf("[OBELIX]  Data ORAM (hex):\n");
  data_oram_entry *entryPtr = data_oram;
  while(entryPtr->startAddress != 0)
  {
    Printf("[OBELIX]   %lx ... %lx (r%c)\n", entryPtr->startAddress, entryPtr->endAddress, entryPtr->isWritable ? 'w' : '-');

    u8 *dataPtr = reinterpret_cast<u8 *>(entryPtr->startAddress);
    for(unsigned int i = 0; i < entryPtr->endAddress - entryPtr->startAddress; ++i)
    {
      Printf("               ");
      for(int j = 0; j < 32 && i < entryPtr->endAddress - entryPtr->startAddress; ++j, ++i) {
        Printf("%02x ", dataPtr[i]);
      }
      Printf("\n");
    }

    if(use_rand_oram)
    {
      Printf("[OBELIX]     RAND %lx ... %lx\n", reinterpret_cast<uptr>(entryPtr->randOramStart), reinterpret_cast<uptr>(entryPtr->randOramEnd));
      bool tick = false;
      for(data_rand_oram_entry *randPtr = entryPtr->randOramStart; randPtr < entryPtr->randOramEnd; ++randPtr)
      {
        if(!tick)
          Printf("               ");

        for(int j = 0; j < 8; ++j)
          Printf("%02x ", reinterpret_cast<u8 *>(&randPtr->dataHigh)[j]);
        for(int j = 0; j < 8; ++j)
          Printf("%02x ", reinterpret_cast<u8 *>(&randPtr->dataLow)[j]);

        if(tick)
        {
          Printf("\n");
          tick = false;
        }
        else
          tick = true;
      }

      if(tick)
        Printf("\n");
    }
    ++entryPtr;
  }
}

static void resize()
{
  u64 newCapacity = 2 * data_oram_capacity;
  data_oram = reinterpret_cast<data_oram_entry *>(internal_mremap(data_oram, data_oram_capacity, newCapacity, MREMAP_MAYMOVE, nullptr));
  data_oram_capacity = newCapacity;
}

static void resize_rand(u64 additionalCapacity)
{
  u64 newCapacity = 2 * data_rand_oram_capacity;
  while(newCapacity < data_rand_oram_capacity + additionalCapacity)
    newCapacity *= 2;

  // Remember old address of data array
  uptr oldDataRandOram = reinterpret_cast<uptr>(data_rand_oram);

  int length = data_rand_oram_end - data_rand_oram;

  data_rand_oram = reinterpret_cast<data_rand_oram_entry *>(internal_mremap(data_rand_oram, data_rand_oram_capacity, newCapacity, MREMAP_MAYMOVE, nullptr));
  s64 errorCode = reinterpret_cast<s64>(data_rand_oram);
  if(errorCode < 0)
  {
    Printf("ERROR: Could not resize randomized ORAM memory: %lld\n", errorCode);
    internal__exit(-1);
  }
  data_rand_oram_capacity = newCapacity;
  data_rand_oram_end = data_rand_oram + length;

  // Update all existing ORAM entry pointers
  u64 distance = reinterpret_cast<uptr>(data_rand_oram) - oldDataRandOram;
  data_oram_entry *entryPtr = data_oram;
  while(entryPtr->startAddress != 0)
  {
    entryPtr->randOramStart = reinterpret_cast<data_rand_oram_entry *>(reinterpret_cast<uptr>(entryPtr->randOramStart) + distance);
    entryPtr->randOramEnd = reinterpret_cast<data_rand_oram_entry *>(reinterpret_cast<uptr>(entryPtr->randOramEnd) + distance);
    ++entryPtr;
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __obelix_add_init_data(uptr pointer, u64 length)
{
  // Allocate init array early
  // Also allocated in preinit_linear_data_oram
  if(!data_oram_init)
  {
    data_oram_init_capacity = 0x1000;
    data_oram_init = reinterpret_cast<data_oram_init_entry *>(internal_mmap(nullptr, data_oram_init_capacity, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
  }

  // Align parameters to 16 bytes
  if(length & 0xf)
    length = (length + 16) & ~0xf;
  if(pointer & 0xf)
  {
    pointer &= ~0xf;
    length += 16;
  }

  // Insert entry
  data_oram_init[data_oram_init_count].pointer = pointer;
  data_oram_init[data_oram_init_count].length = length;

  // 0 marks the end of the pointer array
  ++data_oram_init_count;
  data_oram_init[data_oram_init_count].pointer = 0;
}

// Must only be called after init_linear_data_oram().
extern "C" SANITIZER_INTERFACE_ATTRIBUTE data_oram_entry *__obelix_add_data(uptr pointer, u64 length) {

  // Warn for unreasonably large insertions (probably caused by some broken arithmetic)
  if(length > 0x100000)
  {
    Printf("Rejecting insertion of very large data object: 0x%lx with 0x%llx bytes\n", pointer, length);
    internal__exit(-1);
  }

  // Check and double capacity
  if(data_oram_capacity - data_oram_count * sizeof(data_oram_entry) < 0x100)
    resize();

  // Align parameters to 16 bytes
  if(length & 0xf)
    length = (length + 16) & ~0xf;
  if(pointer & 0xf)
  {
    pointer &= ~0xf;
    length += 16;
  }

  // Add one more 16-byte block to prevent unnecessary lazy insertions
  length += 16;

  // Prevent overlaps
  uptr endPointer = pointer + length;
  data_oram_entry *curEntry = data_oram;
  while(curEntry->startAddress != 0)
  {
    if(curEntry->startAddress <= pointer && pointer < curEntry->endAddress)
      pointer = curEntry->endAddress;
    if(curEntry->startAddress < endPointer && endPointer <= curEntry->endAddress)
      endPointer = curEntry->startAddress;

    ++curEntry;
  }

  if(endPointer <= pointer)
    return nullptr;

  data_oram_entry *newEntry = &data_oram[data_oram_count];

  // Add to randomized ORAM, if necessary
  if(use_rand_oram)
  {
    // 8+8 payload bytes per entry
    int randEntryCount = (endPointer - pointer) / 16;

    // Ensure that randomized ORAM is large enough
    if(((data_rand_oram_end - data_rand_oram) + randEntryCount) * sizeof(data_rand_oram_entry) >= data_rand_oram_capacity)
      resize_rand(randEntryCount * sizeof(data_rand_oram_entry));

    data_rand_oram_entry *dataRandOramPtr = data_rand_oram_end;
    newEntry->randOramStart = dataRandOramPtr;

    u64 *curBlock = reinterpret_cast<u64 *>(pointer);
    u64 *curBlockEnd = reinterpret_cast<u64 *>(endPointer);

    while(curBlock != curBlockEnd) {
      dataRandOramPtr->counterHigh = 0;
      dataRandOramPtr->dataHigh = *curBlock++;
      dataRandOramPtr->counterLow = 0;
      dataRandOramPtr->dataLow = *curBlock++;
      ++dataRandOramPtr;
    }

    newEntry->randOramEnd = dataRandOramPtr;
    data_rand_oram_end = dataRandOramPtr;
  }

  // Insert entry
  // (we need to do this after randomized ORAM initialization, as a resize
  //  updates all existing entries and may get confused)
  newEntry->startAddress = pointer;
  newEntry->endAddress = pointer + length;
  newEntry->isWritable = false;

  // 0 marks the end of the pointer array
  ++data_oram_count;
  data_oram[data_oram_count].startAddress = 0;

  return newEntry;
}


void init_linear_data_oram(bool useRandOram)
{
  use_rand_oram = useRandOram;

  data_oram_count = 0;
  data_oram[0].startAddress = 0;

  data_rand_oram_end = data_rand_oram;

  // Initialize data ORAM from init array
  data_oram_init_entry *dataOramInitPtr = data_oram_init;
  while(dataOramInitPtr->pointer != 0) {
    __obelix_add_data(dataOramInitPtr->pointer, dataOramInitPtr->length);

    ++dataOramInitPtr;
  }

  // Clear init array
  data_oram_init_count = 0;
  data_oram_init[0].pointer = 0;

  data_oram_pending_write_back = false;
  data_oram_last_store_address = 0;
}

void data_oram_linear_query(uptr address, uptr oldDataScratchPadAddress, bool isStore)
{
  __m128i *dataScratchPad = reinterpret_cast<__m128i *>(data_scratch_pad_address);

  // Registers holding the final result
  __m128i vResult1;
  __m128i vResult2;

  // Is there a pending store?
  const bool writeBack = data_oram_pending_write_back;
  __m128i vWriteBackAddress1;
  __m128i vWriteBackAddress2;
  __m128i vWriteBackData1;
  __m128i vWriteBackData2;
  if(writeBack)
  {
    vWriteBackAddress1 = _mm_set1_epi64x(data_oram_last_store_address);
    vWriteBackAddress2 = _mm_set1_epi64x(data_oram_last_store_address + 16);

    __m128i *oldDataScratchPad = reinterpret_cast<__m128i *>(oldDataScratchPadAddress);
    vWriteBackData1 = _mm_load_si128(&oldDataScratchPad[0]);
    vWriteBackData2 = _mm_load_si128(&oldDataScratchPad[1]);

    data_oram_pending_write_back = false;
  }

  // Ignore accesses to dummy address
  int leftHalfFound = 0;
  int rightHalfFound = 0;
  cmov2_test<int, int>(leftHalfFound, 1,
                       rightHalfFound, 1,
                       address == 0);

  // Initialize comparison registers
  __m128i vAddress1 = _mm_set1_epi64x(address);
  __m128i vAddress2 = _mm_set1_epi64x(address + 16);

  // Utility registers
  __m128i vConst16 = _mm_set1_epi64x(16);

  const bool useRandOram = use_rand_oram;
  __m128i vRandCtr;
  if(useRandOram)
    vRandCtr = _mm_load_si128(reinterpret_cast<__m128i *>(data_rand_oram_counters));

  // Iterate through data ORAM and match entries
  data_oram_entry *entry = data_oram;
  while(entry->startAddress != 0)
  {
    // Check whether this is the searched entry
    int leftHalfMatches = check_between(address, entry->startAddress, entry->endAddress);
    int rightHalfMatches = check_between(address + 16, entry->startAddress, entry->endAddress);
    int entryMatches = leftHalfMatches || rightHalfMatches;
    leftHalfFound += leftHalfMatches;
    rightHalfFound += rightHalfMatches;

    // Dynamically detect whether memory region is writable
    if(isStore)
    {
      // if(!entry->isWritable) {
      //    entry->isWritable = entryMatches;
      // }
      __asm__ __volatile__("test %b0, %b0\n\t"
                           "cmove %k0, %k1"
          : "+&r" (entry->isWritable)
          : "rm"(entryMatches)
          : "cc"
          );
    }

    //Printf("  iterating %lx .. %lx %c %c\n", entry->startAddress, entry->endAddress, entryMatches ? 'M' : ' ', entry->isWritable ? 'W' : ' ');

    __m128i vCurPtr = _mm_set1_epi64x(entry->startAddress);
    if(!useRandOram)
    {
      for(__m128i *curPtr = reinterpret_cast<__m128i *>(entry->startAddress);
           curPtr < reinterpret_cast<__m128i *>(entry->endAddress);
           ++curPtr)
      {
        // Read location
        __m128i vCurVal = _mm_load_si128(curPtr);

        // Write back pending store data, if necessary
        if(writeBack && entry->isWritable)
        {
#if defined(__AVX512F__) && defined(__AVX512VL__)
          vCurVal = _mm_mask_blend_epi64(_mm_cmpeq_epi64_mask(vCurPtr, vWriteBackAddress1), vCurVal, vWriteBackData1);
          vCurVal = _mm_mask_blend_epi64(_mm_cmpeq_epi64_mask(vCurPtr, vWriteBackAddress2), vCurVal, vWriteBackData2);
#else
          vCurVal = _mm_blendv_epi8(vCurVal, vWriteBackData1, _mm_cmpeq_epi64(vCurPtr, vWriteBackAddress1));
          vCurVal = _mm_blendv_epi8(vCurVal, vWriteBackData2, _mm_cmpeq_epi64(vCurPtr, vWriteBackAddress2));
#endif
          _mm_store_si128(curPtr, vCurVal);
        }

        // Test against pointers and conditionally read data into result registers
#if defined(__AVX512F__) && defined(__AVX512VL__)
        vResult1 = _mm_mask_blend_epi64(_mm_cmpeq_epi64_mask(vCurPtr, vAddress1), vResult1, vCurVal);
        vResult2 = _mm_mask_blend_epi64(_mm_cmpeq_epi64_mask(vCurPtr, vAddress2), vResult2, vCurVal);
#else
        vResult1 = _mm_blendv_epi8(vResult1, vCurVal, _mm_cmpeq_epi64(vCurPtr, vAddress1));
        vResult2 = _mm_blendv_epi8(vResult2, vCurVal, _mm_cmpeq_epi64(vCurPtr, vAddress2));
#endif

        vCurPtr = _mm_add_epi64(vCurPtr, vConst16);
      }
    }
    else
    {
      for(data_rand_oram_entry *randEntry = entry->randOramStart;
           randEntry < entry->randOramEnd;
           ++randEntry)
      {
        // Read value, skip counters
        // ctrHigh | dataHigh | ctrLow | dataLow  -> 32 bytes total
        __m128i *vRandEntry = reinterpret_cast<__m128i *>(randEntry);
        __m128i vCurVal = _mm_load_si128(&vRandEntry[0]);
        vCurVal = _mm_unpackhi_epi64(vCurVal, vRandEntry[1]);

        /*Printf("Rand entry %lx / %lx: %llx %llx     ", entry->startAddress, (uptr)randEntry, randEntry->dataHigh, randEntry->dataLow);
        u8 tmp[16];
        _mm_store_si128(reinterpret_cast<__m128i *>(tmp), vCurVal);
        for(int i = 0; i < 16; ++i)
          Printf("%02x", tmp[i]);
        Printf("\n");*/

        // Write back pending store data, if necessary
        if(writeBack && entry->isWritable)
        {
#if defined(__AVX512F__) && defined(__AVX512VL__)
          vCurVal = _mm_mask_blend_epi64(_mm_cmpeq_epi64_mask(vCurPtr, vWriteBackAddress1), vCurVal, vWriteBackData1);
          vCurVal = _mm_mask_blend_epi64(_mm_cmpeq_epi64_mask(vCurPtr, vWriteBackAddress2), vCurVal, vWriteBackData2);
#else
          vCurVal = _mm_blendv_epi8(vCurVal, vWriteBackData1, _mm_cmpeq_epi64(vCurPtr, vWriteBackAddress1));
          vCurVal = _mm_blendv_epi8(vCurVal, vWriteBackData2, _mm_cmpeq_epi64(vCurPtr, vWriteBackAddress2));
#endif

          // Write with counter
          _mm_store_si128(&vRandEntry[0], _mm_unpacklo_epi64(vRandCtr, vCurVal));
          _mm_store_si128(&vRandEntry[1], _mm_unpackhi_epi64(vRandCtr, vCurVal));
        }

        // Test against pointers and conditionally read data into result registers
#if defined(__AVX512F__) && defined(__AVX512VL__)
        vResult1 = _mm_mask_blend_epi64(_mm_cmpeq_epi64_mask(vCurPtr, vAddress1), vResult1, vCurVal);
        vResult2 = _mm_mask_blend_epi64(_mm_cmpeq_epi64_mask(vCurPtr, vAddress2), vResult2, vCurVal);
#else
        vResult1 = _mm_blendv_epi8(vResult1, vCurVal, _mm_cmpeq_epi64(vCurPtr, vAddress1));
        vResult2 = _mm_blendv_epi8(vResult2, vCurVal, _mm_cmpeq_epi64(vCurPtr, vAddress2));
#endif

        vCurPtr = _mm_add_epi64(vCurPtr, vConst16);
      }
    }

    ++entry;
  }

  // Increment and write back counter, if necessary
  if(useRandOram)
  {
    vRandCtr = _mm_add_epi64(vRandCtr, vConst16);
    _mm_store_si128(reinterpret_cast<__m128i *>(data_rand_oram_counters), vRandCtr);
  }

  if(leftHalfFound && rightHalfFound)
  {
    // Write fetched data to scratchpad
    dataScratchPad[0] = vResult1;
    dataScratchPad[1] = vResult2;
  }
  else
  {
    // We did not find (a part of) the searched entry, so add it to the ORAM now
    // (lazy insertion)

    constexpr int lazyInsertionSize = 64;
    Printf("[OBELIX] Lazily inserting %lx .. %lx\n", address, address + lazyInsertionSize);

    // Check whether there are entries adjacent to the new one
    uptr newEntryStart = address;
    uptr newEntryEnd = address + lazyInsertionSize;
    entry = data_oram;
    bool overlap = false;
    while(entry->startAddress != 0)
    {
      // For normal mode, we try to extend existing entries. In randomized ORAM
      // mode, we want to avoid costly resizes, so we just ensure that the new
      // entries do not overlap with existing ones.

      // Fully enclosing existing entry
      if(newEntryStart < entry->startAddress && entry->endAddress < newEntryEnd)
      {
        // Just take the left part in randomized ORAM mode
        if(useRandOram)
          newEntryEnd = entry->startAddress;
        else
        {
          entry->startAddress = newEntryStart;
          entry->endAddress = newEntryEnd;
        }

        entry->isWritable |= isStore;
        overlap = true;

        if(!useRandOram)
          break;
      }
      // Overlapping/touching existing entry's left side
      else if(entry->startAddress <= newEntryEnd && newEntryEnd <= entry->endAddress)
      {
        if(useRandOram)
          newEntryEnd = entry->startAddress;
        else
          entry->startAddress = newEntryStart;

        entry->isWritable |= isStore;
        overlap = true;

        if(!useRandOram)
          break;
      }
      // Overlapping/touching existing entry's right side
      else if(entry->startAddress <= newEntryStart && newEntryStart <= entry->endAddress)
      {
        if(useRandOram)
          newEntryStart = entry->endAddress;
        else
          entry->endAddress = newEntryEnd;

        entry->isWritable |= isStore;
        overlap = true;

        if(!useRandOram)
          break;
      }

      ++entry;
    }

    if(!overlap || useRandOram)
    {
      // Printf("[OBELIX]  New non-overlapping boundaries: %lx .. %lx\n", newEntryStart, newEntryEnd);
      data_oram_entry *newEntry = __obelix_add_data(newEntryStart, newEntryEnd - newEntryStart);
      if(newEntry)
        newEntry->isWritable = isStore;
    }

    // Address is already aligned
    // Printf("[OBELIX]  Using original parts: left = %s, right = %s\n", leftHalfFound ? "no" : "yes", rightHalfFound ? "no" : "yes");
    dataScratchPad[0] = leftHalfFound ? vResult1 : *reinterpret_cast<__m128i *>(address);
    dataScratchPad[1] = rightHalfFound ? vResult2 : *reinterpret_cast<__m128i *>(address + 16);
  }

  /*
  if(address != 0)
  {
    Printf("Data: ");
    for (int i = 0; i < 32; ++i)
      Printf("%02x ", reinterpret_cast<u8 *>(data_scratch_pad_address)[i]);
    Printf("\n");

    if(!useRandOram)
    {
      Printf("Real: ");
      for (int i = 0; i < 32; ++i)
        Printf("%02x ", reinterpret_cast<u8 *>(address)[i]);
      Printf("\n");

      // Only check first part, as address2 may be out-of-bounds
      for (int i = 0; i < 16; ++i) {
        if (reinterpret_cast<u8 *>(data_scratch_pad_address)[i] != reinterpret_cast<u8 *>(address)[i]) {
          Printf("mismatch!");
          internal__exit(1);
        }
      }
    }
  }
  //*/

  // Remember if we need to write back a store later
  if(isStore) {
    data_oram_pending_write_back = true;
    data_oram_last_store_address = address;
  }
}

void data_oram_linear_fini()
{
  const bool writeBack = data_oram_pending_write_back;
  const bool useRandOram = use_rand_oram;
  if(writeBack || useRandOram)
  {
    // Is there a pending store?
    __m128i vWriteBackAddress1;
    __m128i vWriteBackAddress2;
    __m128i vWriteBackData1;
    __m128i vWriteBackData2;
    if(writeBack)
    {
      vWriteBackAddress1 = _mm_set1_epi64x(data_oram_last_store_address);
      vWriteBackAddress2 = _mm_set1_epi64x(data_oram_last_store_address + 16);

      __m128i *dataScratchPad = reinterpret_cast<__m128i *>(data_scratch_pad_address);
      vWriteBackData1 = _mm_load_si128(&dataScratchPad[0]);
      vWriteBackData2 = _mm_load_si128(&dataScratchPad[1]);
    }

    // Utility registers
    __m128i vConst16 = _mm_set1_epi64x(16);

    // Iterate through data ORAM and write back the pending store / copy back
    // data from rand ORAM
    data_oram_entry *entry = data_oram;
    while(entry->startAddress != 0)
    {
      //Printf("  write back %lx .. %lx %c\n", entry->startAddress, entry->endAddress, entry->isWritable ? 'W' : ' ');

      __m128i vCurPtr = _mm_set1_epi64x(entry->startAddress);
      if(!useRandOram)
      {
        for(__m128i *curPtr = reinterpret_cast<__m128i *>(entry->startAddress);
            curPtr < reinterpret_cast<__m128i *>(entry->endAddress);
            ++curPtr)
        {
          // Read location
          __m128i vCurVal = _mm_load_si128(curPtr);

          // Write back pending store data, if necessary
          if(writeBack && entry->isWritable)
          {
#if defined(__AVX512F__) && defined(__AVX512VL__)
            vCurVal = _mm_mask_blend_epi64(_mm_cmpeq_epi64_mask(vCurPtr, vWriteBackAddress1), vCurVal, vWriteBackData1);
            vCurVal = _mm_mask_blend_epi64(_mm_cmpeq_epi64_mask(vCurPtr, vWriteBackAddress2), vCurVal, vWriteBackData2);
#else
            vCurVal = _mm_blendv_epi8(vCurVal, vWriteBackData1, _mm_cmpeq_epi64(vCurPtr, vWriteBackAddress1));
            vCurVal = _mm_blendv_epi8(vCurVal, vWriteBackData2, _mm_cmpeq_epi64(vCurPtr, vWriteBackAddress2));
#endif
            _mm_store_si128(curPtr, vCurVal);
          }

          vCurPtr = _mm_add_epi64(vCurPtr, vConst16);
        }
      }
      else
      {
        // Only copy back data which could actually have changed
        if(entry->isWritable)
        {
          __m128i *curPtr = reinterpret_cast<__m128i *>(entry->startAddress);

          for(data_rand_oram_entry *randEntry = entry->randOramStart;
               randEntry < entry->randOramEnd;
               ++randEntry)
          {
            // Read value, skip counters
            // ctrHigh | dataHigh | ctrLow | dataLow  -> 32 bytes total
            __m128i *vRandEntry = reinterpret_cast<__m128i *>(randEntry);
            __m128i vCurVal = _mm_load_si128(&vRandEntry[0]);
            vCurVal = _mm_unpackhi_epi64(vCurVal, vRandEntry[1]);

            // Write back pending store data, if necessary
            if(writeBack)
            {
#if defined(__AVX512F__) && defined(__AVX512VL__)
              vCurVal = _mm_mask_blend_epi64(_mm_cmpeq_epi64_mask(vCurPtr, vWriteBackAddress1), vCurVal, vWriteBackData1);
              vCurVal = _mm_mask_blend_epi64(_mm_cmpeq_epi64_mask(vCurPtr, vWriteBackAddress2), vCurVal, vWriteBackData2);
#else
              vCurVal = _mm_blendv_epi8(vCurVal, vWriteBackData1, _mm_cmpeq_epi64(vCurPtr, vWriteBackAddress1));
              vCurVal = _mm_blendv_epi8(vCurVal, vWriteBackData2, _mm_cmpeq_epi64(vCurPtr, vWriteBackAddress2));
#endif
            }

            // Copy back data
            _mm_store_si128(curPtr, vCurVal);

            ++curPtr;
            vCurPtr = _mm_add_epi64(vCurPtr, vConst16);
          }
        }
      }

      ++entry;
    }
  }
}