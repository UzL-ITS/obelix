
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ObelixBuildFiles.h"
#include "llvm/Support/ObelixCommandLineFlags.h"
#include "llvm/Support/ObelixProperties.h"
#include "llvm/Transforms/Instrumentation/ObelixGeneratePattern.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <fstream>

using namespace llvm;

static ObelixIClasses parseIClass(char &C) {
  switch(C) {
  case '?': return ObelixIClasses::None;
  case 'r': return ObelixIClasses::Load;
  case 'w': return ObelixIClasses::Store;
  case 'p': return ObelixIClasses::PtrAdjust;
  case '1': return ObelixIClasses::Class1;
  case '2': return ObelixIClasses::Class2;
  case '3': return ObelixIClasses::Class3;
  case '4': return ObelixIClasses::Class4;
  default: llvm_unreachable("Unknown instruction class");
  }
}

void ObelixGeneratePatternPass::parseBasicBlocks(const std::string &FunctionName) {

  std::string BuildFileName = ObelixBuildFiles::getBuildFileName(FunctionName);
  std::ifstream FileStream(BuildFileName);

  if (FileStream.bad()) {
    errs() << "Can not open build file \"" << BuildFileName << "\"\n";
    report_fatal_error("Can not open build file");
  }

  int BasicBlockCount;
  FileStream >> BasicBlockCount;
  while (BasicBlockCount-- > 0) {

    BasicBlockIClassInfo *BBInfo = new BasicBlockIClassInfo();
    std::string ClassList;

    FileStream >> BBInfo->Weight >> ClassList;

    // Basic blocks of child functions all get a weight boost
    // TODO this is very inaccurate. We should extract more information in a
    //      higher-level analysis pass, i.e., how often is the function called,
    //      etc.
    BBInfo->Weight += 5;

    for(char &C : ClassList) {
      ObelixIClasses IClass = parseIClass(C);
      BBInfo->InstructionClasses.push_back(IClass);
      DetectedInstructionClasses.insert(IClass);
    }

    BasicBlocks.push_back(BBInfo);
  }
}

void ObelixPatternCandidate::crossover(
    const ObelixPatternCandidate &A,
    const ObelixPatternCandidate &B,
    std::mt19937_64 &RNG,
    ObelixPatternCandidate &Out1,
    ObelixPatternCandidate &Out2) {

  /*dbgs() << "crossover\n";
  dbgs() << "  ";
  A.dump();
  dbgs() << "\n";
  dbgs() << "  ";
  B.dump();
  dbgs() << "\n";*/

  int MaxLength = std::min(A.MaxPatternLength, B.MaxPatternLength);

  // We do a single point crossover, i.e., we pick a random index in each
  // candidate and then merge them:
  // A -> A1 | A2
  // B -> B1 | B2
  // ==> A1 | B2, B1 | A2

  // Ensure that the boundaries of the length distribution are between start and
  // end of A/B
  int LeftA = std::min(3, A.Length);
  int RightA = std::max(LeftA, A.Length - 3);
  int LeftB = std::min(3, B.Length);
  int RightB = std::max(LeftB, B.Length - 3);
  //dbgs() << "    " << LeftA << " " << RightA << " " << LeftB << " " << RightB << "\n";

  int LengthA1 = std::uniform_int_distribution<int>(LeftA, RightA)(RNG);
  int LengthA2 = A.Length - LengthA1;
  int LengthB1 = std::uniform_int_distribution<int>(LeftB, RightB)(RNG);
  int LengthB2 = B.Length - LengthB1;

  // Adjust chunk lengths
  // Keep 3 elements of each
  while (LengthA1 + LengthB2 > MaxLength - CandidateSuffixLength) {
    if (LengthA1 > 3)
      --LengthA1;
    if (LengthB2 > 3)
      --LengthB2;
  }
  while (LengthB1 + LengthA2 > MaxLength - CandidateSuffixLength) {
    if (LengthB1 > 3)
      --LengthB1;
    if (LengthA2 > 3)
      --LengthA2;
  }
  //dbgs() << "    " << LengthA1 << " + " << LengthB2 << ";  " << LengthB1 << " + " << LengthA2 << "\n";

  // Compute sizes of each chunk
  int SizeA1 = std::accumulate(&A.Sizes[0], &A.Sizes[LengthA1], 0, std::plus<int>());
  int SizeA2 = std::accumulate(&A.Sizes[A.Length - LengthA2], &A.Sizes[A.Length], 0, std::plus<int>());
  int SizeB1 = std::accumulate(&B.Sizes[0], &B.Sizes[LengthB1], 0, std::plus<int>());
  int SizeB2 = std::accumulate(&B.Sizes[B.Length - LengthB2], &B.Sizes[B.Length], 0, std::plus<int>());
  //dbgs() << "    " << SizeA1 << " + " << SizeB2 << ";  " << SizeB1 << " + " << SizeA2 << "\n";

  // Adjust sizes if they are too large
  // Keep at least one element of each (more may hang, if there are many loads/stores)
  while (SizeA1 + SizeB2 > CodeBlockInstrCount - CandidateSuffixSize) {
    if (LengthA1 > 1) {
      SizeA1 -= A.Sizes[LengthA1 - 1];
      --LengthA1;
    }
    if (LengthB2 > 1) {
      SizeB2 -= B.Sizes[B.Length - LengthB2];
      --LengthB2;
    }
  }
  while (SizeB1 + SizeA2 > CodeBlockInstrCount - CandidateSuffixSize) {
    if (LengthB1 > 1) {
      SizeB1 -= B.Sizes[LengthB1 - 1];
      --LengthB1;
    }
    if (LengthA2 > 1) {
      SizeA2 -= A.Sizes[A.Length - LengthA2];
      --LengthA2;
    }
  }

  // Clear output patterns
  // (most variables are directly overwritten later)
  for (int *IClassCountPtr = std::begin(Out1.IClassCounts); IClassCountPtr != std::end(Out1.IClassCounts); ++IClassCountPtr)
    *IClassCountPtr = 0;
  for (int *IClassCountPtr = std::begin(Out2.IClassCounts); IClassCountPtr != std::end(Out2.IClassCounts); ++IClassCountPtr)
    *IClassCountPtr = 0;
  for (auto &SuffixIClass : FixedCandSuffix) {
    int IClassIndex = static_cast<int>(SuffixIClass);

    ++Out1.IClassCounts[IClassIndex];
    ++Out2.IClassCounts[IClassIndex];
  }

  // Create new patterns
  ObelixIClasses *Out1ClassesPtr = &Out1.Classes[0];
  int *Out1SizesPtr = &Out1.Sizes[0];
  for (int i = 0; i < LengthA1; ++i) {
    ObelixIClasses IClass = A.Classes[i];

    *Out1ClassesPtr++ = IClass;
    *Out1SizesPtr++ = A.Sizes[i];
    ++Out1.IClassCounts[static_cast<int>(IClass)];
  }
  for (int i = 0; i < LengthB2; ++i) {
    ObelixIClasses IClass = B.Classes[B.Length - LengthB2 + i];

    *Out1ClassesPtr++ = IClass;
    *Out1SizesPtr++ = B.Sizes[B.Length - LengthB2 + i];
    ++Out1.IClassCounts[static_cast<int>(IClass)];
  }
  Out1.Length = LengthA1 + LengthB2;
  Out1.Size = CandidateSuffixSize + SizeA1 + SizeB2;

  ObelixIClasses *Out2ClassesPtr = &Out2.Classes[0];
  int *Out2SizesPtr = &Out2.Sizes[0];
  for (int i = 0; i < LengthB1; ++i) {
    ObelixIClasses IClass = B.Classes[i];

    *Out2ClassesPtr++ = IClass;
    *Out2SizesPtr++ = B.Sizes[i];
    ++Out2.IClassCounts[static_cast<int>(IClass)];
  }
  for (int i = 0; i < LengthA2; ++i) {
    ObelixIClasses IClass = A.Classes[A.Length - LengthA2 + i];

    *Out2ClassesPtr++ = IClass;
    *Out2SizesPtr++ = A.Sizes[A.Length - LengthA2 + i];
    ++Out2.IClassCounts[static_cast<int>(IClass)];
  }
  Out2.Length = LengthB1 + LengthA2;
  Out2.Size = CandidateSuffixSize + SizeB1 + SizeA2;

  /*dbgs() << "-->  ";
  Out1.dump();
  dbgs() << "\n";
  dbgs() << "-->  ";
  Out2.dump();
  dbgs() << "\n";*/

  assert(Out1.Length <= MaxLength - CandidateSuffixLength && "Pattern length is too high");
  assert(Out1.Size <= CodeBlockInstrCount && "Candidate exceeds maximum size");
  assert(Out2.Length <= MaxLength - CandidateSuffixLength && "Pattern length is too high");
  assert(Out2.Size <= CodeBlockInstrCount && "Candidate exceeds maximum size");
}

bool ObelixPatternCandidate::tryAdd(ObelixIClasses IClass) {

  // Do we still have space for the given class?
  if(Length >= MaxPatternLength - CandidateSuffixLength)
    return false;

  int IClassSize = getIClassSize(IClass);
  if(Size + IClassSize > CodeBlockInstrCount)
    return false;

  Classes[Length] = IClass;
  Sizes[Length] = IClassSize;
  ++Length;
  Size += IClassSize;
  ++IClassCounts[static_cast<int>(IClass)];

  assert(Length <= MaxPatternLength - CandidateSuffixLength && "Pattern length is too high");
  assert(Size <= CodeBlockInstrCount && "Candidate exceeds maximum size");

  return true;
}

bool ObelixPatternCandidate::tryInsert(int Index, ObelixIClasses IClass) {

  assert(0 <= Index && Index <= Length && "Index out of range");

  // Special case
  if(Index == Length)
    return tryAdd(IClass);

  // Do we still have space for the given class?
  if(Length >= MaxPatternLength - CandidateSuffixLength)
    return false;

  int IClassSize = getIClassSize(IClass);
  if(Size + IClassSize > CodeBlockInstrCount)
    return false;

  // Move all elements after the target one
  for(int i = Length - 1; i >= Index; --i) {
    Classes[i + 1] = Classes[i];
    Sizes[i + 1] = Sizes[i];
  }

  Classes[Index] = IClass;
  Sizes[Index] = IClassSize;
  ++Length;
  Size += IClassSize;
  ++IClassCounts[static_cast<int>(IClass)];

  assert(Length <= MaxPatternLength - CandidateSuffixLength && "Pattern length is too high");
  assert(Size <= CodeBlockInstrCount && "Candidate exceeds maximum size");

  return true;
}

bool ObelixPatternCandidate::tryReplace(int Index, ObelixIClasses IClass) {

  assert(0 <= Index && Index < Length && "Index out of range");

  ObelixIClasses OldIClass = Classes[Index];
  if(IClass == OldIClass)
    return false;

  int OldSize = Sizes[Index];
  int IClassSize = getIClassSize(IClass);
  if(Size - OldSize + IClassSize > CodeBlockInstrCount)
    return false;

  Classes[Index] = IClass;
  Sizes[Index] = IClassSize;
  Size = Size - OldSize + IClassSize;
  --IClassCounts[static_cast<int>(OldIClass)];
  ++IClassCounts[static_cast<int>(IClass)];

  return true;
}

bool ObelixPatternCandidate::tryRemove(int Index) {

  assert(0 <= Index && Index < Length && "Index out of range");

  ObelixIClasses IClass = Classes[Index];
  int IClassSize = getIClassSize(IClass);

  // Move all elements after the target one
  for(int i = Index; i < Length - 1; ++i)
  {
    Classes[i] = Classes[i + 1];
    Sizes[i] = Sizes[i + 1];
  }

  --Length;
  Size -= IClassSize;
  --IClassCounts[static_cast<int>(IClass)];

  return true;
}

bool ObelixPatternCandidate::mutate(std::mt19937_64 &RNG,
                                                     std::uniform_int_distribution<int> &IClassDistribution,
                                                     SmallSet<ObelixIClasses, 8> &InstructionClasses) {

  // Parameters
  constexpr int MutateInsertChance = 10;
  constexpr int MutateDeleteChance = 10;

  std::uniform_int_distribution<int> PercentageDistribution(0, 99);

  std::uniform_int_distribution<int> IndexDistribution(0, Length - 1);
  int Index = IndexDistribution(RNG);

  // Insert?
  if(PercentageDistribution(RNG) < MutateInsertChance)
  {
    ObelixIClasses RandomIClass;
    do {
      RandomIClass = (ObelixIClasses)IClassDistribution(RNG);
    } while (!InstructionClasses.contains(RandomIClass));

    if(tryInsert(Index, RandomIClass))
      return true;
  }

  // If we did not choose insertion OR insertion failed, delete one entry.
  // A slight bias toward deletion is OK here
  if(PercentageDistribution(RNG) < MutateDeleteChance)
  {
    return tryRemove(Index);
  }

  // We neither inserted nor deleted, try modification
  {
    ObelixIClasses RandomIClass;
    do {
      RandomIClass = (ObelixIClasses)IClassDistribution(RNG);
    } while (!InstructionClasses.contains(RandomIClass));

    // There is a certain chance that the candidate remains untouched. We just
    // ignore this, as there still may result an interesting candidate during
    // recombination. When we are in duplicate elimination mode, we just retry
    // until we get a new candidate.
    return tryReplace(Index, RandomIClass);
  }
}

void ObelixPatternCandidate::makeValid(SmallSet<ObelixIClasses, 8> &InstructionClasses) {

  assert(Size <= CodeBlockInstrCount && "Candidate exceeds maximum size");

  // Ensure that all classes are present
  for(auto &IClass : InstructionClasses) {
    int IClassCount = IClassCounts[static_cast<int>(IClass)];
    if (IClassCount > 0)
      continue;

    // Try to simply add the class at the end. If this is not possible, remove
    // random entries which appear more than one time.
    int Index = Length - 1;
    while (!tryAdd(IClass)) {

      assert(Index >= 0 && "Cannot remove any more elements");

      ObelixIClasses EntryIClass = Classes[Index];
      int EntryIClassCount = IClassCounts[static_cast<int>(EntryIClass)];
      if (EntryIClassCount > 1)
        tryRemove(Index);

      --Index;
    }
  }

  // Ensure that suffix is actually present in class list
  std::copy(std::begin(FixedCandSuffix), std::end(FixedCandSuffix), &Classes[Length]);

  assert(Length <= MaxPatternLength - CandidateSuffixLength && "Pattern length is too high");
  assert(Size <= CodeBlockInstrCount && "Candidate exceeds maximum size");
}

static void dumpIClassList(const ObelixIClasses *Start, const ObelixIClasses *End, raw_ostream &Ostream) {
  for(const ObelixIClasses *It = Start; It != End; ++It) {
    switch(*It) {
    case ObelixIClasses::None: Ostream << "?"; break;
    case ObelixIClasses::Load: Ostream << "r"; break;
    case ObelixIClasses::Store: Ostream << "w"; break;
    case ObelixIClasses::PtrAdjust: Ostream << "p"; break;
    case ObelixIClasses::Class1: Ostream << "1"; break;
    case ObelixIClasses::Class2: Ostream << "2"; break;
    case ObelixIClasses::Class3: Ostream << "3"; break;
    case ObelixIClasses::Class4: Ostream << "4"; break;
    default: dbgs() << "_" << static_cast<int>(*It) << "_"; break;
    }
  }
}

static void dumpIClassList(const ObelixIClasses *Start, const ObelixIClasses *End) {
  dumpIClassList(Start, End, dbgs());
}

static void dumpIClassList(const SmallVector<ObelixIClasses, ObelixPatternCandidate::CodeBlockInstrCount> &List) {
  dumpIClassList(List.begin(), List.end(), dbgs());
}

void ObelixPatternCandidate::dump() const {
  dumpIClassList(&Classes[0], &Classes[Length]);
  dbgs() << "-";
  dumpIClassList(&Classes[Length], &Classes[Length + CandidateSuffixLength]);
}

int ObelixGeneratePatternPass::evaluatePatternCandidate(ObelixPatternCandidate &Candidate) const {

  // Here, we emulate the translation of the basic blocks according to the
  // pattern candidate. We then use the information about necessary dummys to
  // calculate an estimated cost of the given candidate. Lower cost is better.

  int totalCodeBlockCount = 0; // Code fetching is similarly expensive as a load
  int numDummyLoads = 0;
  int numDummyStores = 0;
  for (const auto &BBInfo : BasicBlocks) {

    ++totalCodeBlockCount;
    const ObelixIClasses *CandIT = Candidate.begin();
    const ObelixIClasses *CandEnd = Candidate.end();
    const ObelixIClasses *InstIT = BBInfo->InstructionClasses.begin();
    const ObelixIClasses *InstEnd = BBInfo->InstructionClasses.end();
    while(true)
    {
      // If both candidate and instruction are fully handled, we are done
      if(CandIT == CandEnd
          && InstIT == InstEnd)
        break;

      // If we encountered the end of the candidate, start a new iteration
      if(CandIT == CandEnd)
      {
        totalCodeBlockCount += BBInfo->Weight;
        CandIT = Candidate.begin();
      }

      // If we encountered the end of the instruction list, fill block with
      // dummy entries
      if(InstIT == InstEnd)
      {
        for(; CandIT != CandEnd; ++CandIT)
        {
          ObelixIClasses CandIClass = *CandIT;
          if(CandIClass == ObelixIClasses::Load)
            numDummyLoads += BBInfo->Weight;
          else if(CandIClass == ObelixIClasses::Store)
            numDummyStores += BBInfo->Weight;
        }
        break;
      }

      ObelixIClasses InstIClass = *InstIT;

      // Find next match in candidate
      while(true)
      {
        ObelixIClasses CandIClass = *CandIT;
        if(CandIClass == InstIClass)
          break;

        // Not a hit, we need to insert a dummy
        if(CandIClass == ObelixIClasses::Load)
          numDummyLoads += BBInfo->Weight;
        else if(CandIClass == ObelixIClasses::Store)
          numDummyStores += BBInfo->Weight;

        ++CandIT;

        // If we encountered the end of the candidate, start a new iteration
        if(CandIT == CandEnd)
        {
          totalCodeBlockCount += BBInfo->Weight;
          CandIT = Candidate.begin();
        }
      }

      ++InstIT;
      if(CandIT != CandEnd)
        ++CandIT;
    }
  }

  // At the moment we count the number of ORAM queries, and assume that data
  // ORAM accesses are similarly as expensive as code ORAM accesses.
  // Stores take two queries (fetch and write back).
  return 1 * totalCodeBlockCount + 1 * numDummyLoads + 2 * numDummyStores;
}


ObelixGeneratePatternPass::ObelixGeneratePatternPass() {}

PreservedAnalyses ObelixGeneratePatternPass::run(Function &F,
                                              FunctionAnalysisManager &AM) {

  if (ObelixBuildStage != 2)
    return PreservedAnalyses::all();

  // We compute the pattern only once per top-level parent of each call tree
  if (!F.hasFnAttribute(Attribute::AttrKind::Obelix)
      || F.getFnAttribute(Attribute::AttrKind::Obelix)
          .getObelixProperties()
          .getState() != ObelixProperties::State::Copy) {
    return PreservedAnalyses::all();
  }

  dbgs() << "[OBELIX] Running pattern generator for '" << F.getName() << "'\n";

  // Read this function's generated file from stage 1
  BasicBlocks.clear();
  DetectedInstructionClasses.clear();
  std::vector<std::string> CalleeNames;
  {
    // Read
    std::string BuildFileName = ObelixBuildFiles::getBuildFileName(F.getName().str());
    std::ifstream FileStream(BuildFileName);

    if (FileStream.bad()) {
      errs() << "Can not open build file \"" << F.getName() << "\"\n";
      report_fatal_error("Can not open build file");
    }

    int BasicBlockCount;
    FileStream >> BasicBlockCount;
    while (BasicBlockCount-- > 0) {

      BasicBlockIClassInfo *BBInfo = new BasicBlockIClassInfo();
      std::string ClassList;

      FileStream >> BBInfo->Weight >> ClassList;

      for (char &C : ClassList) {
        ObelixIClasses IClass = parseIClass(C);
        BBInfo->InstructionClasses.push_back(IClass);
        DetectedInstructionClasses.insert(IClass);
      }

      BasicBlocks.push_back(BBInfo);
    }

    int CalleeCount;
    FileStream >> CalleeCount;
    while (CalleeCount-- > 0) {
      std::string CalleeName;
      FileStream >> CalleeName;
      CalleeNames.push_back(CalleeName);
    }
  }

  // Parse basic block patterns of dependencies
  for(auto &CalleeName : CalleeNames) {
    parseBasicBlocks(CalleeName);
  }

  // Compute maximum length of a code block pattern.
  /// We subtract instruction classes which are mandatory and generate multiple
  /// instructions, to reduce chances that we randomly generate patterns that
  /// are too long.
  /// - At least 1 Load with 3 instruction slots (-2)
  ///
  /// The mandatory suffix is treated elsewhere.
  MaxPatternLength = ObelixPatternCandidate::CodeBlockInstrCount;
  MaxPatternLength -= 2;

  // Generate dummy patterns for less secure instrumentation levels
  if(ObelixFeatureLevel < ObelixFeatureLevels::FixedPattern) {

    // Return simple pattern with fixed number of instructions
    F.CodeBlockPattern = new ObelixPatternCandidate(MaxPatternLength);
    F.CodeBlockPattern->tryAdd(ObelixIClasses::Load);
    F.CodeBlockPattern->tryAdd(ObelixIClasses::Store);
    while (F.CodeBlockPattern->tryAdd(ObelixIClasses::None)) {
      // Nothing
    }
    F.CodeBlockPattern->makeValid(DetectedInstructionClasses); // empty set

    dbgs() << "[OBELIX]  Wildcard candidate: ";
    F.CodeBlockPattern->dump();
    dbgs() << "\n";

    return PreservedAnalyses::all();
  }

  // We actually try to find an optimal pattern

  // (Debug) Dump accumulated BBs
  dbgs() << "[OBELIX]  Accumulated basic blocks:\n";
  for (const auto *BBInfo : BasicBlocks)
  {
    dbgs() << "[OBELIX]    ";
    dumpIClassList(BBInfo->InstructionClasses);
    dbgs() << "   Weight: " << BBInfo->Weight << "\n";
  }

  // Parameters
  constexpr int NumTopCandidates = 15;
  constexpr int NumCandidates = 2 * NumTopCandidates + 2 * NumTopCandidates * NumTopCandidates;
  constexpr int MaxNumGenerations = 10000;
  constexpr int MaxTimeMilliseconds = 10000;
  constexpr int MinCandidateLength = 4;
  int MaxCandidateLength = MaxPatternLength;

  // Determine first non-used instruction class
  ObelixIClasses MinIClass = ObelixIClasses::Load;
  ObelixIClasses MaxIClass = ObelixIClasses::Class1;
  for(auto &IClass : DetectedInstructionClasses) {
    if(IClass > MaxIClass)
      MaxIClass = IClass;
  }

  // Initialize RNG with fixed seed
  std::mt19937_64 RNG(42);
  std::uniform_int_distribution<int> IClassDistribution((int)MinIClass, (int)MaxIClass);
  std::uniform_int_distribution<int> CandidateLengthDistribution(
      MinCandidateLength - ObelixPatternCandidate::CandidateSuffixLength,
      MaxCandidateLength - ObelixPatternCandidate::CandidateSuffixLength
  );
  std::uniform_int_distribution<int> DuplicateUpdateChunkIndexDistribution(
      0,
      MaxCandidateLength - ObelixPatternCandidate::CandidateSuffixLength - 3
  );
  std::uniform_int_distribution<int> DuplicateUpdateChunkLengthDistribution(
      3,
      MaxCandidateLength - ObelixPatternCandidate::CandidateSuffixLength
  );

  // Candidate array
  std::vector<ObelixPatternCandidate> Candidates(NumCandidates, ObelixPatternCandidate(MaxPatternLength));
  std::pair<int, int> CandidateCostsAndIndexes[NumCandidates];
  std::vector<ObelixPatternCandidate> TopCandidates(NumTopCandidates, ObelixPatternCandidate(MaxPatternLength));

  // Create random initial candidates
  // Some may be invalid, but this will be fixed after the first generation
  for(int c = 0; c < NumCandidates; ++c) {
    auto Cand = ObelixPatternCandidate(RNG,
                                       MaxPatternLength,
                                       IClassDistribution,
                                       CandidateLengthDistribution,
                                       DetectedInstructionClasses);
    Cand.makeValid(DetectedInstructionClasses);
    Candidates[c] = std::move(Cand);
  }

  auto StartTime = std::chrono::system_clock::now();
  auto EndTime = StartTime + std::chrono::milliseconds(MaxTimeMilliseconds);
  int BestCost;
  int g = 0;
  while(true) {

    // Compute candidate costs
    BestCost = 1000000;
    for(int c = 0; c < NumCandidates; ++c)
    {
      int cost = evaluatePatternCandidate(Candidates[c]);
      if(cost < BestCost)
        BestCost = cost;

      // Debug output
      /*if(g == 0 || g == MaxNumGenerations - 1) {
        dbgs() << "     ";
        dumpIClassList(Candidates[c]);
        dbgs() << "  ----> " << cost << "\n";
      }*/

      CandidateCostsAndIndexes[c] = std::make_pair(cost, c);
    }

    // Sort candidates by cost (first element)
    std::sort(std::begin(CandidateCostsAndIndexes), std::end(CandidateCostsAndIndexes), std::less<>{});

    // Info
    if(g % (std::min(MaxNumGenerations / 10, 1000)) == 0) {
      dbgs() << "[OBELIX]  Best cost after " << g << " generations: " << BestCost << "\n";
    }

    // Abort search after we have hit the maximum amount of generations; or
    // after a certain time has elapsed, to prevent hangs in large instances.
    // We abort at this exact position to ensure that we have up-to-date cost
    // values for the candidates. This way, we don't have to save the best
    // candidate before mutation each time (we do not know when the loop might
    // terminate)
    if(g == MaxNumGenerations) {
      dbgs() << "[OBELIX]  Terminating genetic search after processing full "
             << MaxNumGenerations << " generations\n";
      break;
    }
    if(g % 100 == 0 && std::chrono::system_clock::now() > EndTime) {
      dbgs() << "[OBELIX]  Terminating genetic search due to hitting "
             << MaxTimeMilliseconds << "ms time limit\n";
      break;
    }

    // Copy top N candidates
    for (int t = 0; t < NumTopCandidates; ++t)
      TopCandidates[t] = Candidates[CandidateCostsAndIndexes[t].second];

    // Build new candidate list:
    // 1. First copy the top N from the last generation
    int newCandIndex = 0;
    for (int t = 0; t < NumTopCandidates; ++t)
      Candidates[newCandIndex++] = TopCandidates[t];

    // 2. Mutate the top N from the last generation
    for (int t = 0; t < NumTopCandidates; ++t)
    {
      ObelixPatternCandidate NewCand = TopCandidates[t]; // Copy
      NewCand.mutate(RNG, IClassDistribution, DetectedInstructionClasses);
      Candidates[newCandIndex++] = std::move(NewCand);
    }

    // 3. Recombine top N with mutated N (single point crossover)
    for(int t = 0; t < NumTopCandidates; ++t) {
      for(int m = 0; m < NumTopCandidates; ++m) {

        auto &TCand = Candidates[t];
        auto &MCand = Candidates[NumTopCandidates + m];

        ObelixPatternCandidate::crossover(TCand, MCand, RNG,
                                    Candidates[newCandIndex],
                                    Candidates[newCandIndex + 1]);
        newCandIndex += 2;
      }
    }

    assert(newCandIndex == NumCandidates && "New candidates don't fill array");

    // Ensure that all candidates are valid
    for(int c = 0; c < NumCandidates; ++c) {
      auto &CurrentCand = Candidates[c];
      CurrentCand.makeValid(DetectedInstructionClasses);
    }

    // Detect and remove duplicates
    DenseSet<int> CandidateHashes;
    for(auto &CurrentCand : Candidates)
    {
      int Hash = CurrentCand.getHash();

      // Duplicate?
      if(CandidateHashes.contains(Hash))
      {
        // We fix duplicates by adding more mutations
        while(!CurrentCand.mutate(RNG, IClassDistribution, DetectedInstructionClasses)){
          // Retry
        }

        // Ensure that candidate is still valid
        CurrentCand.makeValid(DetectedInstructionClasses);

        // We got a modified candidate. If we still have a duplicate, we don't
        // care anymore and wait for the next round.
        Hash = CurrentCand.getHash();
      }

      CandidateHashes.insert(Hash);
    }

    ++g;
  }

  // In best candidates, find the shortest one
  int ShortestBestIndex = CandidateCostsAndIndexes[0].second;
  int ShortestBestSize = ObelixPatternCandidate::CodeBlockInstrCount;
  for(int i = 0; i < NumCandidates; ++i)
  {
    if(CandidateCostsAndIndexes[i].first > BestCost)
      break;
    if(Candidates[CandidateCostsAndIndexes[i].second].getSize() < ShortestBestSize)
    {
      ShortestBestIndex = i;
      ShortestBestSize = Candidates[CandidateCostsAndIndexes[i].second].getSize();
    }
  }

  // Info output
  auto &BestCand = Candidates[CandidateCostsAndIndexes[ShortestBestIndex].second];
  dbgs() << "[OBELIX]  Best cost after " << g << " generations: " << BestCost << "   Candidate: ";
  BestCand.dump();
  dbgs() << "\n";

  // Copy best candidate
  F.CodeBlockPattern = new ObelixPatternCandidate(BestCand);

  // Free allocated memory
  for(auto *BBInfo : BasicBlocks) {
    delete BBInfo;
  }

  return PreservedAnalyses::all();
}