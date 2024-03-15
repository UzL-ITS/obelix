#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_OBELIXGENERATEPATTERN_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_OBELIXGENERATEPATTERN_H

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/IR/PassManager.h"
#include <random>

namespace llvm {

// Local declaration of relevant constants.
// MUST be kept consistent with those in X86BaseInfo.h!
enum class ObelixIClasses {
  None,
  Load,
  Store,
  PtrAdjust,
  Class1,
  Class2,
  Class3,
  Class4,

  // Must be last element
  Count
};

/// Represents a code block pattern candidate.
class ObelixPatternCandidate {
public:

  /// Size of a code block in bytes.
  /// Must not be set to a value below 96.
  /// Changing this here is not sufficient, other passes and the controller have
  /// their own constants and assumptions.
  static constexpr int CodeBlockSize = 160;

  /// The maximum size of a code block in instructions.
  /// A code block has N bytes of space, which results in N/8 8-byte
  /// instruction slots. The last instruction slot is reserved for
  /// jumping to the controller.
  static constexpr int CodeBlockInstrCount = CodeBlockSize / 8 - 1;

  static constexpr int CandidateSuffixLength = 3;
  static constexpr int CandidateSuffixSize = 3;

  /// Fixed classes at end of each candidate.
  /// Needed for JCC translation.
  // TODO Verify that this indeed matches the given classes
  static constexpr ObelixIClasses FixedCandSuffix[CandidateSuffixLength] = {
      ObelixIClasses::Class1,
      ObelixIClasses::PtrAdjust,
      ObelixIClasses::Class1
  };

private:
  /// The class list of the pattern.
  ObelixIClasses Classes[CodeBlockInstrCount];

  /// Sizes of the pattern classes. Directly corresponds to Classes.
  int Sizes[CodeBlockInstrCount];

  /// Counts the number of occurrences for each instruction class.
  /// Speeds up checking whether the candidate is valid.
  int IClassCounts[static_cast<int>(ObelixIClasses::Count)] = {0};

  /// The amount of classes in this candidate.
  int Length = 0;

  /// The number of instructions in the code block.
  /// Updated when changing the stored classes.
  int Size = CandidateSuffixSize;

  /// Maximum length of a pattern (optimization).
  int MaxPatternLength = CodeBlockInstrCount;

  /// Size of loads (number of slots).
  static constexpr int LoadSize = 3;

  /// Size of stores (number of slots).
  static constexpr int StoreSize = 3;

public:
  inline ObelixPatternCandidate(int MaxLength)
    : MaxPatternLength(MaxLength) {

    for (auto &SuffixIClass : FixedCandSuffix) {
      ++IClassCounts[static_cast<int>(SuffixIClass)];
    }
  }

  /// Creates a new random candidate from the given distributions.
  inline ObelixPatternCandidate(std::mt19937_64 &RNG,
                                int MaxLength,
  std::uniform_int_distribution<int> &IClassDistribution,
      std::uniform_int_distribution<int> &LengthDistribution,
  SmallSet<ObelixIClasses, 8> &InstructionClasses)
  : ObelixPatternCandidate(MaxLength) {

    int CandLength = LengthDistribution(RNG);
    for(int i = 0; i < CandLength; ++i) {
      ObelixIClasses RandomIClass;
      do {
        RandomIClass = (ObelixIClasses)IClassDistribution(RNG);
      } while (!InstructionClasses.contains(RandomIClass));

      // Does the class still fit?
      if(!tryAdd(RandomIClass))
        break;
    }
  }

  /// Gets the candidate's size in instructions.
  inline int getSize() const {
    return Size;
  }

  /// Gets the candidate's pattern length.
  /// Only safe after calling makeValid().
  inline int getLength() const {
    return Length + CandidateSuffixLength;
  }

  /// Gets the entry at the given index.
  inline ObelixIClasses at(int Index) const {
    assert(0 <= Index && Index < Length + CandidateSuffixLength
               && "Index out of range");

    return Classes[Index];
  }

  /// Creates a new candidate from a crossover of the given two candidates.
  static void crossover(const ObelixPatternCandidate &A,
                        const ObelixPatternCandidate &B,
                        std::mt19937_64 &RNG,
                        ObelixPatternCandidate &Out1,
                        ObelixPatternCandidate &Out2);

  /// Returns a pointer to the first instruction class entry.
  inline const ObelixIClasses *begin() const {
    return &Classes[0];
  }

  /// Returns a pointer to after the last instruction class entry.
  /// Only safe after calling makeValid().
  inline const ObelixIClasses *end() const {
    return &Classes[Length + CandidateSuffixLength];
  }

  /// Tries to add the given instruction class to the candidate, and returns
  /// whether the operation was successful (i.e., whether there is enough
  /// enough).
  bool tryAdd(ObelixIClasses IClass);

  /// Tries to insert the given instruction class at the given index, and
  /// returns whether the operation was successful (i.e., whether there is
  //  enough space).
  bool tryInsert(int Index, ObelixIClasses IClass);

  /// Tries to replace the given instruction class at the given index, and
  /// returns whether the operation was successful (i.e., whether there was
  //  enough space).
  bool tryReplace(int Index, ObelixIClasses IClass);

  /// Tries to remove the instruction class at the given index.
  bool tryRemove(int Index);

  /// Randomly mutates the candidate. Returns whether any changes were made.
  bool mutate(std::mt19937_64 &RNG,
              std::uniform_int_distribution<int> &IClassDistribution,
              SmallSet<ObelixIClasses, 8> &InstructionClasses);

  /// Ensures that the candidate is valid.
  /// Takes a list of instruction classes that must exist in the candidate.
  void makeValid(SmallSet<ObelixIClasses, 8> &InstructionClasses);

  /// Returns a hash over the current pattern.
  inline int getHash() {
    int Hash = 17;
    for(const ObelixIClasses *IClassIt = begin(); IClassIt != end(); ++IClassIt) {
      Hash = 19 * Hash + static_cast<int>(*IClassIt);
    }
    return Hash;
  }

  /// Returns the amount of instruction slots a certain instruction class takes.
  inline int getIClassSize(ObelixIClasses IClass) {
    switch (IClass) {
    case ObelixIClasses::None: return 1; // Used as classX wildcard
    case ObelixIClasses::Load: return LoadSize;
    case ObelixIClasses::Store: return StoreSize;
    case ObelixIClasses::PtrAdjust: return 1;
    case ObelixIClasses::Class1: return 1;
    case ObelixIClasses::Class2: return 1;
    case ObelixIClasses::Class3: return 1;
    case ObelixIClasses::Class4: return 1;
    default: llvm_unreachable("Unknown instruction class");
    }
  }

  /// Writes the instruction class list to dbgs().
  void dump() const;
};

/// Pass for finding an optimal code block pattern.
class ObelixGeneratePatternPass : public PassInfoMixin<ObelixGeneratePatternPass> {
public:
  ObelixGeneratePatternPass();

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }

private:

  /// The maximum length of a code block pattern (optimization).
  int MaxPatternLength = ObelixPatternCandidate::CodeBlockInstrCount;

  /// Contains the instruction classes present in the associated basic
  /// block, and some metadata.
  class BasicBlockIClassInfo {
  public:
    int Weight = 1;
    SmallVector<ObelixIClasses, ObelixPatternCandidate::CodeBlockInstrCount> InstructionClasses;
  };

  std::vector<BasicBlockIClassInfo *> BasicBlocks;
  SmallSet<ObelixIClasses, 8> DetectedInstructionClasses;

  /// Reads the saved basic block pattern information for the given function.
  void parseBasicBlocks(const std::string &FunctionName);

  int evaluatePatternCandidate(ObelixPatternCandidate &Candidate) const;
};

} // namespace llvm

#endif // LLVM_TRANSFORMS_INSTRUMENTATION_OBELIXGENERATEPATTERN_H
