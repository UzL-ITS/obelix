#pragma clang diagnostic push
#pragma ide diagnostic ignored "readability-identifier-naming"

#include "X86ObelixCodeAnalysis.h"
#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCContext.h"
#include "llvm/Pass.h"
#include "llvm/Support/ObelixCommandLineFlags.h"
#include "llvm/Support/ObelixProperties.h"
#include "llvm/Transforms/Instrumentation/ObelixGeneratePattern.h"


using namespace llvm;

#define OBELIXCODESPLIT_DESC                                                   \
  "Obelix: Splits basic blocks into equal-sized chunks"
#define OBELIXCODESPLIT_NAME "x86-obelix-code-split"

#define DUMP_TRANSLATED_INSTRUCTIONS 0

namespace {

class X86ObelixCodeSplitPass : public MachineFunctionPass {

  /// Indicates to the ORAM controller that the next block is the fallthrough
  /// of the current one.
  /// MUST be 0, as this way we can use a four-byte `movzx r15, r14b` instead of
  /// a longer immediate move, which in turn allows to compress the block end
  /// into a single 8-byte instruction slot.
  static constexpr int BLOCK_ADDRESS_FALLTHROUGH = 0;

  /// Indicates to the ORAM controller that there is no next block, and
  /// that the ORAM mode should be left.
  static constexpr int BLOCK_ADDRESS_EXIT = 1;

  /// Indicates to the ORAM controller that the block wants to access
  /// a dummy memory location.
  static constexpr int MEMORY_ADDRESS_DUMMY = 0;

  /// The addend to the data access return address to indicate that the address
  /// is RIP-relative and needs adjustment.
  static constexpr int ADJUSTMENT_NEEDED_ADDEND = 0x100000;

public:
  static char ID;

  X86ObelixCodeSplitPass() : MachineFunctionPass(ID) {}

protected:
  bool runOnMachineFunction(MachineFunction &machineFunction) override;
  void getAnalysisUsage(AnalysisUsage &AU) const override;

private:
  MachineFunction *MF = nullptr;
  const X86Subtarget *STI = nullptr;
  const TargetInstrInfo *TII = nullptr;
  const TargetRegisterInfo *TRI = nullptr;
  MachineLoopInfo *MLI = nullptr;
  X86ObelixCodeAnalysis *OCA = nullptr;

  ObelixPatternCandidate *CodeBlockPattern = nullptr;

  /// Applies ORAM transformation to the given machine basic block.
  void handleMachineBasicBlock(MachineBasicBlock *MBB) const;

  /// Splits an MBB at the given position.
  void splitMachineBasicBlock(MachineBasicBlock *MBB, MachineBasicBlock::iterator splitIt) const;

  /// Inserts a jump to the ORAM code fetch controller.
  /// Returns the address of the first inserted instruction.
  MachineInstr* insertJumpToNextBlock(MachineBasicBlock *MBB, MachineBasicBlock::iterator insertIt) const;

  /// Inserts a jump to the ORAM data fetch controller.
  void insertJumpToMemoryFetch(MachineBasicBlock *MBB, MachineBasicBlock::iterator InsertIt, bool IsStore, bool IsRipRelativePtr) const;

  /// Inserts a jump to the ORAM data fetch controller before the given instruction.
  /// If the instruction is null, it inserts the jump at the end of the basic block instead.
  inline void insertJumpToMemoryFetch(MachineBasicBlock *MBB, MachineInstr *MI, bool IsStore, bool IsRipRelativePtr) const {
    if(MI == nullptr)
      insertJumpToMemoryFetch(MBB, MBB->end(), IsStore, IsRipRelativePtr);
    else
      insertJumpToMemoryFetch(MBB, MI->getIterator(), IsStore, IsRipRelativePtr);
  }

  /// Inserts a dummy memory access before the given instruction. If the instruction
  /// is null, the access is inserted at the end of the basic block instead.
  void insertDummyMemoryAccess(MachineBasicBlock *MBB, MachineInstr *MI, bool IsStore) const;

  /// Returns an estimation of the encoded size of the given instruction. Errs on
  /// the side of a higher than accurate estimation. Used only for the Obfuscuro
  /// feature level.
  int estimateInstrByteSize(const MachineInstr *MI) const;
};

/// Utility class for storing a memory operand.
class X86MemoryOperand {
public:
  X86MemoryOperand(const MachineOperand *Base, const MachineOperand *Scale,
                   const MachineOperand *Index, const MachineOperand *Disp,
                   const MachineOperand *Segment)
      : Base(Base->getReg()), Scale(Scale->getImm()), Index(Index->getReg()),
        Disp(Disp), Segment(Segment->getReg()) {
  }

  /// Parses the first memory operand of the given machine instruction.
  /// OperandNo receives the index of the memory operand in the operand list.
  X86MemoryOperand(const MachineInstr *MI, int &OperandNo) {
    // Get number of first memory operand
    const MCInstrDesc &Desc = MI->getDesc();
    OperandNo = X86II::getMemoryOperandNo(Desc.TSFlags);

    assert(OperandNo >= 0 && "Could not locate first memory operand");

    OperandNo += X86II::getOperandBias(Desc);

    Base = MI->getOperand(OperandNo + X86::AddrBaseReg).getReg();
    Scale = MI->getOperand(OperandNo + X86::AddrScaleAmt).getImm();
    Index = MI->getOperand(OperandNo + X86::AddrIndexReg).getReg();
    Disp = &MI->getOperand(OperandNo + X86::AddrDisp);
    Segment = MI->getOperand(OperandNo + X86::AddrSegmentReg).getReg();
  }

  Register Base;
  int64_t Scale;
  Register Index;
  const MachineOperand *Disp;
  Register Segment;
};

} // end anonymous namespace

char X86ObelixCodeSplitPass::ID = 0;

void X86ObelixCodeSplitPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<MachineLoopInfo>();
  AU.addRequired<X86ObelixCodeAnalysis>();

  MachineFunctionPass::getAnalysisUsage(AU);
}

void X86ObelixCodeSplitPass::splitMachineBasicBlock(llvm::MachineBasicBlock *MBB,
                                                    MachineBasicBlock::iterator splitIt) const {

  // Create new MBB after current one
  MachineFunction::iterator CurMBBI = MBB->getIterator();
  MachineBasicBlock *NewMBB = MF->CreateMachineBasicBlock(nullptr);
  MBB->getParent()->insert(++CurMBBI, NewMBB);

  // Split MBB
  NewMBB->splice(NewMBB->begin(), MBB, splitIt, MBB->end());

  // Insert new MBB into CFG, add fallthrough
  NewMBB->transferSuccessors(MBB);
  MBB->addSuccessor(NewMBB);

  // Inherit loop info from old MBB
  if (MLI)
    if (MachineLoop *ML = MLI->getLoopFor(MBB))
      ML->addBasicBlockToLoop(NewMBB, MLI->getBase());
}

/// Returns an estimation of the encoded size of the given instruction. Errs on
/// the side of a higher than accurate estimation.
/// Used only for the Obfuscuro feature level.
int X86ObelixCodeSplitPass::estimateInstrByteSize(const MachineInstr *MI) const {
  if(MI == nullptr)
    return 0;

  if(MI->getOpcode() == X86::MOV64rm && MI->getObelixFlag(MachineInstr::ObelixFlag::PtrAdjust))
    return 3;

  auto Is8BitImm = [&](int64_t Imm) -> bool {
    return -128 <= Imm && Imm <= 127;
  };

  switch(MI->getOpcode()) {
  case X86::LEA64r:
  case X86::LEA64_32r: {
    int MemoryOperandNo;
    X86MemoryOperand MemoryOperand(MI, MemoryOperandNo);
    if(MemoryOperand.Disp->isImm()) {
      return Is8BitImm(MemoryOperand.Disp->getImm()) ? 5 : 8;
    }
    return 7; // rip+X
  }
  case X86::JCC_1:
  case X86::JMP_1:
  case X86::JMP64r:
    return 8;
  case X86::MOV32rr:
  case X86::MOV64rr:
    return 3;
  case X86::MOV64ri:
  case X86::MOV64ri32:
    return 7;
  case X86::MOV32ri:
    return 6;
  case X86::INC32r:
  case X86::INC64r:
  case X86::DEC32r:
  case X86::DEC64r:
    return 3;
  case X86::CMOV16rr:
    return 5;
  case X86::CMOV32rr:
  case X86::CMOV64rr:
    return 4;
  case X86::DIV32r:
  case X86::DIV64r:
    return 3;
  case X86::BT32rr:
  case X86::BT64rr:
    return 4;
  case X86::IMUL32rr:
  case X86::IMUL64rr:
    return 4;
  case X86::MUL8r:
  case X86::MUL32r:
  case X86::MUL64r:
    return 3;
  case X86::SETCCr:
    return 4;
  case X86::SHLD64rri8:
  case X86::SHRD64rri8:
  case X86::SHLD32rri8:
  case X86::SHRD32rri8:
    return 5;
  default:
    const MCInstrDesc &MIDesc = TII->get(MI->getOpcode());

    if(MIDesc.getNumOperands() == 2) {
      const auto &MCOp1 = MIDesc.operands()[0];
      const auto &MCOp2 = MIDesc.operands()[1];

      // reg OP reg
      if(MCOp1.OperandType == MCOI::OPERAND_REGISTER
          && MCOp2.OperandType == MCOI::OPERAND_REGISTER)
      {
        return 3;
      }

      // reg OP imm
      if(MCOp1.OperandType == MCOI::OPERAND_REGISTER
          && MCOp2.OperandType == MCOI::OPERAND_IMMEDIATE)
      {
        // Locate immediate
        for(auto &Op : MI->operands()) {
          if(Op.isImm())
            return Is8BitImm(Op.getImm()) ? 5 : 8;
        }
      }
    }

    if(MIDesc.getNumOperands() == 3) {
      const auto &MCOp1 = MIDesc.operands()[0];
      const auto &MCOp2 = MIDesc.operands()[1];
      const auto &MCOp3 = MIDesc.operands()[2];

      // reg <- reg OP reg
      if(MCOp1.OperandType == MCOI::OPERAND_REGISTER
          && MCOp2.OperandType == MCOI::OPERAND_REGISTER
          && MCOp3.OperandType == MCOI::OPERAND_REGISTER)
      {
        return 3;
      }

      // reg <- reg OP imm
      if(MCOp1.OperandType == MCOI::OPERAND_REGISTER
          && MCOp2.OperandType == MCOI::OPERAND_REGISTER
          && MCOp3.OperandType == MCOI::OPERAND_IMMEDIATE)
      {
        // Locate immediate
        for(auto &Op : MI->operands()) {
          if(Op.isImm())
            return Is8BitImm(Op.getImm()) ? 5 : 8;
        }
      }
    }

    // Ok, no idea
    MI->dump();
    dbgs() << "Can not estimate instruction size. NumOperands = " << MI->getNumOperands() << "\n";
    for(auto &Op : MI->operands()) {
      Op.dump();
    }
    dbgs() << "MCInstrDesc operands (" << MIDesc.operands().size() << "):\n";
    for(auto &MCOp : MIDesc.operands()) {
      dbgs() << " - " << (int)MCOp.OperandType << "\n";
    }
    llvm_unreachable("Unsupported opcode");
  }
}

// Same as BuildMI, but checks the instruction pointer for null and uses
// BB->end() in that case.
static MachineInstrBuilder BuildMISafe(MachineBasicBlock &BB, MachineInstr *I,
                                       const MIMetadata &MIMD,
                                       const MCInstrDesc &MCID,
                                       Register DestReg) {
  if(I == nullptr)
    return BuildMI(BB, BB.end(), MIMD, MCID, DestReg);
  return BuildMI(BB, I, MIMD, MCID, DestReg);
}

// Same as BuildMI, but checks the instruction pointer for null and uses
// BB->end() in that case.
static MachineInstrBuilder BuildMISafe(MachineBasicBlock &BB, MachineInstr *I,
                                       const MIMetadata &MIMD,
                                       const MCInstrDesc &MCID) {
  if(I == nullptr)
    return BuildMI(BB, BB.end(), MIMD, MCID);
  return BuildMI(BB, I, MIMD, MCID);
}

MachineInstr* X86ObelixCodeSplitPass::insertJumpToNextBlock(llvm::MachineBasicBlock *MBB, MachineBasicBlock::iterator insertIt) const {

  // Jump to controller
  // 4 bytes
  MachineInstr *Jmp = BuildMI(*MBB, insertIt, DebugLoc(), TII->get(X86::JMP64m))
      .addUse(X86::R14)
      .addImm(1)
      .addUse(0)
      .addImm(0x8)
      .addUse(0);
  Jmp->setObelixFlags(MachineInstr::ObelixFlag::DoNotProcess
                         | MachineInstr::ObelixFlag::ControllerJump);

  return Jmp;
}

void X86ObelixCodeSplitPass::insertJumpToMemoryFetch(MachineBasicBlock *MBB, MachineBasicBlock::iterator InsertIt, bool IsStore, bool IsRipRelativePtr) const {

  // We disable NOP padding for the lea/jmp pair, as they are always the same:
  // - lea: 7 bytes
  // - jmp: 4 bytes
  // - load/store: 3 bytes
  //      `mov reg, [r15]` and `mov [r15], reg` are both 3 bytes. The same holds
  //      for standard arithmetic with loads like add/sub/and/...
  //      Basic arithmetic with stores may be longer, but is forbidden due to
  //      the also included load.
  // - NOP: 2 bytes
  // This way, we reduce the total size of load/store to 3 instruction slots
  // (the `lea r15, [addr]` at the beginning is included).

  // Load return address (after subsequent jump)
  // We encode necessary adjustment of RIP-relative pointers into the return address,
  // such that it points outside the code scratchpad (which is not possible).
  MachineInstr *LeaI = BuildMI(*MBB, InsertIt, DebugLoc(), TII->get(X86::LEA64r), X86::R13)
      .addUse(X86::RIP)
      .addImm(0)
      .addUse(0)
      .addImm((IsRipRelativePtr ? ADJUSTMENT_NEEDED_ADDEND : 0) + 0x4) // The subsequent JMP takes exactly 4 bytes
      .addUse(0);
  LeaI->setObelixFlags(MachineInstr::ObelixFlag::DoNotProcess
                      | MachineInstr::ObelixFlag::DoNotPad);

  // Jump to controller
  // This JMP takes EXACTLY 4 bytes (assumed in the LEA above)
  MachineInstr *JumpI = BuildMI(*MBB, InsertIt, DebugLoc(), TII->get(X86::JMP64m))
      .addUse(X86::R14)
      .addImm(1)
      .addUse(0)
      .addImm(IsStore ? 0x18 : 0x10)
      .addUse(0);
  JumpI->setObelixFlags(MachineInstr::ObelixFlag::DoNotProcess
                           | MachineInstr::ObelixFlag::DoNotPad);
}

void X86ObelixCodeSplitPass::insertDummyMemoryAccess(llvm::MachineBasicBlock *MBB, llvm::MachineInstr *MI, bool IsStore) const {

  if(IsStore)
  {
    // mov [dummy], r14  (we avoid writing zeroes)
    dbgs() << "[OBELIX]   Creating dummy store\n";

    BuildMISafe(*MBB, MI, DebugLoc(), TII->get(X86::MOV32ri), X86::R15D)
        .addImm(MEMORY_ADDRESS_DUMMY);

    insertJumpToMemoryFetch(MBB, MI, true, false);

    MachineInstr *Store = BuildMISafe(*MBB, MI, DebugLoc(), TII->get(X86::MOV64mr))
        .addUse(X86::R15)
        .addImm(1)
        .addUse(0)
        .addImm(0)
        .addUse(0)
        .addUse(X86::R13);

    Store->addMemOperand(*MF, MF->getMachineMemOperand(MachinePointerInfo(), MachineMemOperand::Flags::MOStore, 0, Align(1)));
  }
  else
  {
    // mov r15, [dummy]
    dbgs() << "[OBELIX]   Creating dummy load\n";

    BuildMISafe(*MBB, MI, DebugLoc(), TII->get(X86::MOV32ri), X86::R15D)
        .addImm(MEMORY_ADDRESS_DUMMY);

    insertJumpToMemoryFetch(MBB, MI, false, false);

    MachineInstr *Load = BuildMISafe(*MBB, MI, DebugLoc(), TII->get(X86::MOV64rm), X86::R15)
        .addUse(X86::R15)
        .addImm(1)
        .addUse(0)
        .addImm(0)
        .addUse(0);

    Load->addMemOperand(*MF, MF->getMachineMemOperand(MachinePointerInfo(), MachineMemOperand::Flags::MOLoad, 0, Align(1)));
  }
}

void X86ObelixCodeSplitPass::handleMachineBasicBlock(MachineBasicBlock *MBB) const {

  dbgs() << "[OBELIX]  Instrumenting MBB '" << MBB->getFullName() << "'\n";

  MachineInstr *CurMI = &MBB->front();

  assert(CodeBlockPattern->getLength() > 0 && "Code block pattern must not be empty");

  int PatternIndex = 0;
  ObelixIClasses CurIClass = ObelixIClasses::None;

  // Treat class "None" as classX wildcard for inserting arbitrary non-memory
  // instructions. Used for support of less secure instrumentation levels.
  bool TreatIClassNoneAsWildcard = ObelixFeatureLevel < ObelixFeatureLevels::FixedPattern;

  // We don't really use the pattern in Obfuscuro mode, but update the index
  // for load/store anyway. The pattern is the same as for Obelix Base, i.e.,
  // load/store followed by arbitrary instructions.
  bool ObfuscuroMode = ObelixFeatureLevel < ObelixFeatureLevels::Base;

  // Obfuscuro mode states:
  // 0: Next is load
  // 1: Next is store
  // 2: Arbitrary non-memory instructions until block end
  int ObfuscuroModeState = 0;

  // Track the current estimated byte size of the code block. Only used for the
  // feature levels 10 and 20 and for evaluation purposes. The native Obelix
  // implementation always prefers fixed patterns and instruction slots, which
  // safely fit all relevant instructions, so we don't have to preempt lowering
  // to machine code.
  int EstimatedBlockByteSize = 0;
  static constexpr int EstimatedFallthroughSize = 8;
  static constexpr int EstimatedBranchSize = 27; // JMP/JCC with pointer adjust
  static constexpr int EstimatedLoadSize = 8 + 7 + 4 + 3;
  static constexpr int EstimatedStoreSize = 8 + 7 + 4 + 3;
  static constexpr int EstimatedPtrAdjustSize = 3 + 5;

  // Lambda that inserts dummy instructions until the given instruction class
  // is found in the pattern. If inserting dummy instructions was not
  // sufficient, but a block split was necessary, the lambda returns `false`.
  // Then, the outer function must immediately return as well.
  // The optional index parameter allows to specify a pattern index which should
  // be reached through padding. Negative indexes count from the end of the
  // pattern.
  auto insertPaddingUntil = [&] (ObelixIClasses iClass, std::optional<int> index = std::nullopt) -> bool {
    int TargetPatternIndex = CodeBlockPattern->getLength() + index.value_or(0);
    if(TargetPatternIndex >= CodeBlockPattern->getLength())
      TargetPatternIndex -= CodeBlockPattern->getLength();

    if(ObfuscuroMode) {
      if(iClass == ObelixIClasses::Load) {
        if(ObfuscuroModeState == 0)
          return true;
        if(ObfuscuroModeState == 1) {
          EstimatedBlockByteSize += EstimatedStoreSize;
          insertDummyMemoryAccess(MBB, CurMI, true);
        }

        // State 2, split
      }
      else if(iClass == ObelixIClasses::Store) {
        if(ObfuscuroModeState == 0) {
          EstimatedBlockByteSize += EstimatedLoadSize;
          insertDummyMemoryAccess(MBB, CurMI, false);

          ObfuscuroModeState = 1;
          return true;
        }
        if(ObfuscuroModeState == 1)
          return true;

        // State 2, split
      }
      else {
        if(ObfuscuroModeState == 0) {
          EstimatedBlockByteSize += EstimatedLoadSize;
          insertDummyMemoryAccess(MBB, CurMI, false);

          EstimatedBlockByteSize += EstimatedStoreSize;
          insertDummyMemoryAccess(MBB, CurMI, true);

          ObfuscuroModeState = 2;
          return true;
        }
        if(ObfuscuroModeState == 1) {
          EstimatedBlockByteSize += EstimatedStoreSize;
          insertDummyMemoryAccess(MBB, CurMI, true);

          ObfuscuroModeState = 2;
          return true;
        }

        // Does the current instruction fit?
        if(CurMI == nullptr
          || EstimatedBlockByteSize + estimateInstrByteSize(CurMI) + EstimatedBranchSize <= ObelixPatternCandidate::CodeBlockSize) {
          // Yes
          return true;
        }

        // No, split
      }

      // Split: Insert fallthrough to next MBB
      assert(CurMI != nullptr && "CurMI is null");
      static_assert(BLOCK_ADDRESS_FALLTHROUGH == 0); // mov r15d, 0 == movzx r15, r14b
      MachineInstr *Mov = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::MOVZX64rr8), X86::R15)
          .addReg(X86::R14B);
      Mov->setObelixFlags(MachineInstr::ObelixFlag::DoNotProcess
                              | MachineInstr::ObelixFlag::DoNotPad
                              | MachineInstr::ObelixFlag::ControllerJump);
      insertJumpToNextBlock(MBB, CurMI);
      EstimatedBlockByteSize += EstimatedFallthroughSize;

      splitMachineBasicBlock(MBB, CurMI);
      return false;
    }

    while(CurIClass != iClass  // Fill until class is found
          || CurMI == nullptr  // Fill until end of block
          || (index.has_value() && PatternIndex != TargetPatternIndex) // Fill until class and index
          || (TreatIClassNoneAsWildcard && iClass == ObelixIClasses::None)) // We only ever search for None if we
                                                                               // want to skip the remainder of a pattern
                                                                               // before a controller jump. So special
                                                                               // case it here such that "None" wildcard
                                                                               // entries in the pattern get ignored
    {

      // Wildcard for classX instructions
      if(TreatIClassNoneAsWildcard && CurIClass == ObelixIClasses::None
          && iClass != ObelixIClasses::None
          && iClass != ObelixIClasses::Load && iClass != ObelixIClasses::Store
          && !(index.has_value() && PatternIndex != TargetPatternIndex)) // Respect search for specific index
        return true;

      // Insert dummy instructions depending on the instruction class
      if(CurIClass == ObelixIClasses::Load)
      {
        insertDummyMemoryAccess(MBB, CurMI, false);
        EstimatedBlockByteSize += EstimatedLoadSize;
      }
      else if(CurIClass == ObelixIClasses::Store)
      {
        insertDummyMemoryAccess(MBB, CurMI, true);
        EstimatedBlockByteSize += EstimatedStoreSize;
      }
      else if(CurIClass == ObelixIClasses::PtrAdjust)
      {
        // Dummy adjust
        MachineInstr *ReadAdjustValue = BuildMISafe(*MBB, CurMI, DebugLoc(), TII->get(X86::MOV64rm), X86::R13)
            .addUse(X86::R14)
            .addImm(1)
            .addUse(0)
            .addImm(0)
            .addUse(0);
        ReadAdjustValue->setObelixFlags(llvm::MachineInstr::DoNotPad | llvm::MachineInstr::PtrAdjust); // 3 bytes
        MachineInstr *PtrAdjustLea = BuildMISafe(*MBB, CurMI, DebugLoc(), TII->get(X86::LEA64r), X86::R13)
            .addUse(X86::R13)
            .addImm(1)
            .addUse(0)
            .addImm(0)
            .addUse(0);
        PtrAdjustLea->setObelixFlags(llvm::MachineInstr::PtrAdjust); // 4 bytes -> pad to 8

        EstimatedBlockByteSize += 7;
      }
      else if(CurIClass == ObelixIClasses::Class1)
      {
        // lea r13, [r13+0]
        BuildMISafe(*MBB, CurMI, DebugLoc(), TII->get(X86::LEA64r), X86::R13)
            .addUse(X86::R13)
            .addImm(1)
            .addUse(0)
            .addImm(0)
            .addUse(0);

        EstimatedBlockByteSize += 1;
      }
      else if(CurIClass == ObelixIClasses::Class2)
      {
        // We must be careful to not overwrite status flags or live registers,
        // so we use the following sequence:
        //   mov r13, rax
        //   lahf
        //   mov r15b, 0xff
        //   div r14b
        //   sahf
        //   mov rax, r13

        // TODO
        //   (those are only for testing that r13/r15 are safe to overwrite)
        MachineInstr *SaveRax = BuildMISafe(*MBB, CurMI, DebugLoc(), TII->get(X86::MOV64rr), X86::R13)
          .addUse(X86::RAX);
        SaveRax->setObelixFlags(llvm::MachineInstr::DoNotPad);
        BuildMISafe(*MBB, CurMI, DebugLoc(), TII->get(X86::MOV8ri), X86::R15B)
          .addImm(-1);

        EstimatedBlockByteSize += 6;
      }
      else if(TreatIClassNoneAsWildcard && CurIClass == ObelixIClasses::None)
      {
        // lea r13, [r13+0]
        BuildMISafe(*MBB, CurMI, DebugLoc(), TII->get(X86::LEA64r), X86::R13)
            .addUse(X86::R13)
            .addImm(1)
            .addUse(0)
            .addImm(0)
            .addUse(0);

        EstimatedBlockByteSize += 1;
      }
      else
        llvm_unreachable("Unhandled instruction class");

      // Next pattern entry
      ++PatternIndex;

      if(PatternIndex >= CodeBlockPattern->getLength()) {
        // We encountered the end of the pattern

        // Did we only want to pad the remaining block before a branch?
        if(iClass == ObelixIClasses::None) {
          return true;
        }

        // ...no. We need to split the MBB before current instruction and
        // handle the new MBB in the next run

        // Insert fallthrough to next MBB
        assert(CurMI != nullptr && "CurMI is null");
        static_assert(BLOCK_ADDRESS_FALLTHROUGH == 0); // mov r15d, 0 == movzx r15, r14b
        MachineInstr *Mov = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::MOVZX64rr8), X86::R15)
            .addReg(X86::R14B);
        Mov->setObelixFlags(MachineInstr::ObelixFlag::DoNotProcess
                                | MachineInstr::ObelixFlag::DoNotPad
                                | MachineInstr::ObelixFlag::ControllerJump);
        insertJumpToNextBlock(MBB, CurMI);
        EstimatedBlockByteSize += EstimatedFallthroughSize;

        splitMachineBasicBlock(MBB, CurMI->getIterator());
        return false;
      }

      CurIClass = CodeBlockPattern->at(PatternIndex);
    }

    return true;
  };

  // We enforce the code block pattern as determined by the analysis.
  // General approach: Process MBB instructions one by one. If the current
  // instruction fits the current instruction class, great; if not, insert dummy
  // instructions until we have a fit.
  while(true)
  {
    // Did we find the end of the basic block? In this case, emit padding until
    // pattern is complete and add fallthrough to the next block
    if(CurMI == nullptr) {

      if(!ObfuscuroMode && PatternIndex < CodeBlockPattern->getLength()) {
        CurIClass = CodeBlockPattern->at(PatternIndex);
        insertPaddingUntil(ObelixIClasses::None);
      }

      static_assert(BLOCK_ADDRESS_FALLTHROUGH == 0); // mov r15d, 0 == movzx r15, r14b
      MachineInstr *Mov = BuildMI(*MBB, MBB->end(), DebugLoc(), TII->get(X86::MOVZX64rr8), X86::R15)
          .addReg(X86::R14B);
      Mov->setObelixFlags(MachineInstr::ObelixFlag::DoNotProcess
                              | MachineInstr::ObelixFlag::DoNotPad
                              | MachineInstr::ObelixFlag::ControllerJump);
      insertJumpToNextBlock(MBB, MBB->end());

      EstimatedBlockByteSize += EstimatedFallthroughSize;

      break;
    }

    if(!ObfuscuroMode && PatternIndex >= CodeBlockPattern->getLength()) {
      // We have reached the end of the pattern -> split block

      // Insert fallthrough to next MBB
      static_assert(BLOCK_ADDRESS_FALLTHROUGH == 0); // mov r15d, 0 == movzx r15, r14b
      MachineInstr *Mov = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::MOVZX64rr8), X86::R15)
          .addReg(X86::R14B);
      Mov->setObelixFlags(MachineInstr::ObelixFlag::DoNotProcess
                              | MachineInstr::ObelixFlag::DoNotPad
                              | MachineInstr::ObelixFlag::ControllerJump);
      insertJumpToNextBlock(MBB, CurMI);
      EstimatedBlockByteSize += EstimatedFallthroughSize;

      // Split before current instruction and handle the new MBB in the next run
      splitMachineBasicBlock(MBB, CurMI);
      break;
    }

    CurIClass = CodeBlockPattern->at(PatternIndex);

    // Stop processing when encountering a controller jump that was previously
    // inserted when instrumenting another instruction.
    // This happens e.g. when a `ret` is rewritten to a load and `jmp`.
    if (CurMI->getObelixFlag(MachineInstr::ObelixFlag::ControllerJump))
    {
      // Any time we insert `jmp`, we also split the MBB. So we can safely
      // assume that the MBB ends here. We may only need to insert some
      // remaining padding
      insertPaddingUntil(ObelixIClasses::None);
      break;
    }

    // Ignore certain instruction types
    if(CurMI->isCFIInstruction() || CurMI->isKill()
        || CurMI->getObelixFlag(MachineInstr::ObelixFlag::DoNotProcess)) {
      CurMI = CurMI->getNextNode();
      continue;
    }

    // Relative-to-absolute pointer adjustment
    if(CurMI->getObelixFlag(MachineInstr::ObelixFlag::PtrAdjust)) {

      // Pad code block if necessary
      if(!insertPaddingUntil(ObelixIClasses::PtrAdjust))
        break;

      // Skip instructions (they were inserted by an earlier iteration)
      do {
        CurMI = CurMI->getNextNode();
      }
      while(CurMI != nullptr && CurMI->getObelixFlag(MachineInstr::ObelixFlag::PtrAdjust));

      EstimatedBlockByteSize += EstimatedPtrAdjustSize;

      ++PatternIndex;
      continue;
    }

    // Handle different load instruction types
    // We always fallthrough to the generic load translation, so we only need
    // to pad the code block there.
    if (CurMI->getOpcode() == X86::RET || CurMI->getOpcode() == X86::RET64) {
      dbgs() << "[OBELIX]   Breaking up `ret` instruction\n";

      // Split `ret` into `pop; jmp` pair

      // Retrieve return address
      // No adjustment needed, this is already an absolute address
      // TODO we use the r10 register to temporarily save the return address, so it doesn't
      //   get overwritten by subsequent dummy instructions. We can probably safely assume that
      //   r10 isn't used due to the calling convention, but this is still prone to break
      //   randomly. _At least_ we should assert that r10 is in fact a volatile register per
      //   the calling convention.
      MachineInstr *Pop = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::POP64r), X86::R10);

      // Jump to controller
      MachineInstr *Mov = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::MOV64rr), X86::R15)
          .addUse(X86::R10);
      Mov->setObelixFlags(MachineInstr::ObelixFlag::DoNotProcess
                              | MachineInstr::ObelixFlag::DoNotPad
                              | MachineInstr::ObelixFlag::ControllerJump);
      insertJumpToNextBlock(MBB, CurMI);

      CurMI->removeFromParent();
      MF->deleteMachineInstr(CurMI);

      // Continue processing, as the `pop` instruction accesses memory
      CurMI = Pop;
    }
    if (isPop(CurMI)) // Fallthrough from `ret`
    {
      dbgs() << "[OBELIX]   Breaking up `pop` instruction\n";

      // Split `pop` into load and `add`

      // Create load instruction
      MachineInstr *Load;
      switch (CurMI->getOpcode()) {
      case X86::POP64r:
        Load = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::MOV64rm), CurMI->getOperand(0).getReg())
            .addUse(X86::RSP) // Base
            .addImm(1) // Scale
            .addUse(0) // Index
            .addImm(0) // Displacement
            .addUse(0); // Segment
        break;

      default:llvm_unreachable("Unsupported `pop` operand type");
      }

      // Update stack pointer
      BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::ADD64ri8), X86::RSP)
          .addUse(X86::RSP)
          .addImm(8);

      CurMI->removeFromParent();
      MF->deleteMachineInstr(CurMI);

      // Continue processing the load
      Load->addMemOperand(*MF, MF->getMachineMemOperand(MachinePointerInfo(), MachineMemOperand::Flags::MOLoad, 0, Align(1)));
      CurMI = Load;
    }
    if (isLoad(CurMI)) // Fallthrough from `pop`
    {
      // Pad code block if necessary
      if(!insertPaddingUntil(ObelixIClasses::Load))
        break;

      assert(!CurMI->isCall() && !CurMI->isReturn() && !CurMI->isBranch() && "Unexpected control flow instruction in load handler");

      dbgs() << "[OBELIX]   Translating load instruction `" << TII->getName(CurMI->getOpcode()) << "`\n";
#if DUMP_TRANSLATED_INSTRUCTIONS
      CurMI->dump();
#endif

      // Extract address expression
      int MemoryOperandNo;
      X86MemoryOperand MemoryOperand(CurMI, MemoryOperandNo);
      bool MemoryOperandIsRipRelative = MemoryOperand.Base == X86::RIP;
      auto LeaBuilder = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::LEA64r), X86::R15)
          .addUse(MemoryOperand.Base)
          .addImm(MemoryOperand.Scale)
          .addUse(MemoryOperand.Index);

      if (MemoryOperand.Disp->isImm())
        LeaBuilder.addImm(MemoryOperand.Disp->getImm());
      else if (MemoryOperand.Disp->isMCSymbol())
        LeaBuilder.addSym(MemoryOperand.Disp->getMCSymbol());
      else if (MemoryOperand.Disp->isGlobal())
      {
        LeaBuilder.addGlobalAddress(MemoryOperand.Disp->getGlobal(),
                                    MemoryOperand.Disp->getOffset());
      }
      else
        llvm_unreachable("Unhandled load displacement");

      LeaBuilder.addUse(MemoryOperand.Segment);

      // Fetch memory
      insertJumpToMemoryFetch(MBB, CurMI->getIterator(), false, MemoryOperandIsRipRelative);

      // Do actual load
      // Replace memory operand by new one
      CurMI->getOperand(MemoryOperandNo + X86::AddrBaseReg)
          .ChangeToRegister(X86::R15, false);
      CurMI->getOperand(MemoryOperandNo + X86::AddrScaleAmt)
          .ChangeToImmediate(1);
      CurMI->getOperand(MemoryOperandNo + X86::AddrIndexReg)
          .ChangeToRegister(0, false);
      CurMI->getOperand(MemoryOperandNo + X86::AddrDisp)
          .ChangeToImmediate(0);
      CurMI->getOperand(MemoryOperandNo + X86::AddrSegmentReg)
          .ChangeToRegister(0, false);

#if DUMP_TRANSLATED_INSTRUCTIONS
      dbgs() << " -->\n";
      CurMI->dump();
#endif

      ObfuscuroModeState = 1;
      EstimatedBlockByteSize += EstimatedLoadSize;

      CurMI = CurMI->getNextNode();
      ++PatternIndex; // Load was translated
      continue;
    }

    // Handle different store instruction types
    // We always fallthrough to the generic store translation, so we only need
    // to pad the code block there.
    if (isPush(CurMI)) {
      dbgs() << "[OBELIX]   Breaking up `push` instruction\n";

      // Split `push` into store and `sub` (in that order).
      // This way, we can subsequently translate the store. The order matches the
      // one assumed in the analysis, so late reordering may be harmful here,
      // and may actually make things more complicated as we cannot directly
      // proceed to handling the resulting store.

      // Create store instruction
      MachineInstr *Store;
      switch (CurMI->getOpcode()) {
      case X86::PUSH64r:
        Store = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::MOV64mr))
            .addUse(X86::RSP) // Base
            .addImm(1) // Scale
            .addUse(0) // Index
            .addImm(-8) // Displacement
            .addUse(0) // Segment
            .addUse(CurMI->getOperand(0).getReg());
        break;

      default:llvm_unreachable("Unsupported `push` operand type");
      }

      // Update stack pointer
      BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::SUB64ri8), X86::RSP)
          .addUse(X86::RSP)
          .addImm(8);

      CurMI->removeFromParent();
      MF->deleteMachineInstr(CurMI);

      // Continue processing the store
      Store->addMemOperand(*MF, MF->getMachineMemOperand(MachinePointerInfo(), MachineMemOperand::Flags::MOStore, 0, Align(1)));
      CurMI = Store;
    }
    if (isStore(CurMI)) // Fallthrough from `push`
    {
      // Pad code block if necessary
      if(!insertPaddingUntil(ObelixIClasses::Store))
        break;

      dbgs() << "[OBELIX]   Translating store instruction `" << TII->getName(CurMI->getOpcode()) << "`\n";

#if DUMP_TRANSLATED_INSTRUCTIONS
      CurMI->dump();
#endif

      // Check opcodes - we only allow pure stores, no combined load/store
      assert((CurMI->getOpcode() == X86::MOV64mr || CurMI->getOpcode() == X86::MOV64mi32
              || CurMI->getOpcode() == X86::MOV32mr || CurMI->getOpcode() == X86::MOV32mi
              || CurMI->getOpcode() == X86::MOV16mr || CurMI->getOpcode() == X86::MOV16mi
              || CurMI->getOpcode() == X86::MOV8mr || CurMI->getOpcode() == X86::MOV8mi)
        && "Store instruction is not a move"
      );

      // Extract address expression
      int MemoryOperandNo;
      X86MemoryOperand MemoryOperand(CurMI, MemoryOperandNo);
      bool MemoryOperandIsRipRelative = MemoryOperand.Base == X86::RIP;
      auto LeaBuilder = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::LEA64r), X86::R15)
          .addUse(MemoryOperand.Base)
          .addImm(MemoryOperand.Scale)
          .addUse(MemoryOperand.Index);

      if (MemoryOperand.Disp->isImm())
        LeaBuilder.addImm(MemoryOperand.Disp->getImm());
      else if (MemoryOperand.Disp->isMCSymbol())
        LeaBuilder.addSym(MemoryOperand.Disp->getMCSymbol(), MemoryOperand.Disp->getTargetFlags());
      else if (MemoryOperand.Disp->isGlobal())
        LeaBuilder.addGlobalAddress(MemoryOperand.Disp->getGlobal(), MemoryOperand.Disp->getOffset(), MemoryOperand.Disp->getTargetFlags());
      else {
        CurMI->dump();
        llvm_unreachable("Unhandled store displacement");
      }

      LeaBuilder.addUse(MemoryOperand.Segment);

      // Fetch memory
      insertJumpToMemoryFetch(MBB, CurMI->getIterator(), true, MemoryOperandIsRipRelative);

      // Do actual store
      // Replace memory operand by new one
      CurMI->getOperand(MemoryOperandNo + X86::AddrBaseReg)
          .ChangeToRegister(X86::R15, false);
      CurMI->getOperand(MemoryOperandNo + X86::AddrScaleAmt)
          .ChangeToImmediate(1);
      CurMI->getOperand(MemoryOperandNo + X86::AddrIndexReg)
          .ChangeToRegister(0, false);
      CurMI->getOperand(MemoryOperandNo + X86::AddrDisp)
          .ChangeToImmediate(0);
      CurMI->getOperand(MemoryOperandNo + X86::AddrSegmentReg)
          .ChangeToRegister(0, false);

#if DUMP_TRANSLATED_INSTRUCTIONS
      dbgs() << " -->\n";
      CurMI->dump();
#endif

      ObfuscuroModeState = 2;
      EstimatedBlockByteSize += EstimatedStoreSize;

      CurMI = CurMI->getNextNode();
      ++PatternIndex; // Store was translated
      continue;
    }

    // If the instruction has a RIP-relative memory operand, we need to rewrite
    // it so it is relative to the code scratchpad.
    // The load/store handlers only do this for actual load/stores, but not for
    // `lea`.
    if (CurMI->getOpcode() == X86::LEA64r)
    {
      // Extract and check address expression
      int MemoryOperandNo;
      X86MemoryOperand MemoryOperand(CurMI, MemoryOperandNo);
      if (MemoryOperand.Base == X86::RIP)
      {
        dbgs() << "[OBELIX]   Adjusting RIP-relative memory operand of `" << TII->getName(CurMI->getOpcode()) << "`\n";
#if DUMP_TRANSLATED_INSTRUCTIONS
        CurMI->dump();
#endif

        // Insert padding until we find a position where there is a class1 followed by a pointer adjust
        // We do not want the pointer adjust to end up on a different block, as the offset won't fit
        // anymore
        // TODO reflect this in pattern cost evaluation
        bool FoundClass1 = false;
        bool HasValidPosition = false;
        for(int Pos = PatternIndex; Pos < CodeBlockPattern->getLength(); ++Pos) {
          ObelixIClasses PosIClass = CodeBlockPattern->at(Pos);
          if(!FoundClass1 && (PosIClass == ObelixIClasses::None || PosIClass == ObelixIClasses::Class1))
            FoundClass1 = true;
          else if(FoundClass1 && (PosIClass == ObelixIClasses::None || PosIClass == ObelixIClasses::PtrAdjust)) {
            HasValidPosition = true;
            break;
          }
        }
        if(!HasValidPosition) {
          // Fill block
          if (!insertPaddingUntil(ObelixIClasses::None))
            break;
          continue;
        }

        // Extract destination register
        unsigned int DestReg = 0;
        for(const auto &Op : CurMI->operands()) {
          if(Op.isReg()) {
            DestReg = Op.getReg();
            break;
          }
        }

        // Emit adjust after this instruction
        // Will be picked up and moved to the correct pattern location in a later
        // iteration.
        MachineInstr *NextMI = CurMI->getNextNode();
        MachineInstr *ReadAdjustValue = BuildMISafe(*MBB, NextMI, DebugLoc(), TII->get(X86::MOV64rm), X86::R13)
            .addUse(X86::R14)
            .addImm(1)
            .addUse(0)
            .addImm(0)
            .addUse(0);
        ReadAdjustValue->setObelixFlags(llvm::MachineInstr::DoNotPad | llvm::MachineInstr::PtrAdjust);
        MachineInstr *Lea = BuildMISafe(*MBB, NextMI, DebugLoc(), TII->get(X86::LEA64r), DestReg)
            .addUse(DestReg)
            .addImm(1)
            .addUse(X86::R13)
            .addImm(0)
            .addUse(0);
        Lea->setObelixFlags(llvm::MachineInstr::DoNotPad | llvm::MachineInstr::PtrAdjust);

#if DUMP_TRANSLATED_INSTRUCTIONS
        dbgs() << " -->\n";
        CurMI->dump();
        ReadAdjustValue->dump();
        Lea->dump();
#endif
      }
    }

    // Handle branch instructions
    if (CurMI->isBranch() || CurMI->getOpcode() == X86::TAILJMPd64)
    {
      // Convert control flow into ORAM controller calls

      dbgs() << "[OBELIX]   Rewriting branch instruction `" << TII->getName(CurMI->getOpcode()) << "`\n";

      switch (CurMI->getOpcode()) {
      case X86::JMP_1:
      case X86::TAILJMPd64: {

        // Skip ahead to end of pattern
        // Remaining:
        // - class1
        // - adjust
        // - class1
        if(!insertPaddingUntil(ObelixIClasses::Class1, -3))
          break;

        switch (CurMI->getOperand(0).getType()) {
        case llvm::MachineOperand::MO_MachineBasicBlock:
        case llvm::MachineOperand::MO_BlockAddress:
        case llvm::MachineOperand::MO_MCSymbol:
        case llvm::MachineOperand::MO_ExternalSymbol: {

          // Get target address (relative to code-scratchpad: scrbase + off)
          BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::LEA64r), X86::R15)
              .addUse(X86::RIP)
              .addImm(0)
              .addUse(0)
              .add(CurMI->getOperand(0))
              .addUse(0);

          // Convert to absolute address
          // [r14+0] = block - scrbase
          // -> (scrbase + off) + block - scrbase = block + off
          MachineInstr *ReadAdjustValue = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::MOV64rm), X86::R13)
              .addUse(X86::R14)
              .addImm(1)
              .addUse(0)
              .addImm(0)
              .addUse(0);
          ReadAdjustValue->setObelixFlags(llvm::MachineInstr::DoNotPad | llvm::MachineInstr::PtrAdjust);
          MachineInstr *PtrAdjustLea = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::LEA64r), X86::R15)
              .addUse(X86::R15)
              .addImm(1)
              .addUse(X86::R13)
              .addImm(0)
              .addUse(0);
          PtrAdjustLea->setObelixFlags(llvm::MachineInstr::DoNotPad | llvm::MachineInstr::PtrAdjust);

          break;
        }
        case llvm::MachineOperand::MO_GlobalAddress: {

          // Jump to a function (likely from an earlier translated `call`).

          // For now, we rely on the -fno-semantic-interposition compiler flag
          // to keep the compiler from referencing the PLT for every call/jump
          // to non-static functions.
          // If we want to get rid of the flag, we would need to somehow manually
          // mark those functions as callable without interposition, probably by
          // messing with the members of the callee Function* object.

          //const GlobalValue *GV = CurMI->getOperand(0).getGlobal();
          //const Function *Callee = dyn_cast<Function>(GV);
          //assert(Callee != nullptr && "Unexpected type of global");

          MachineOperand &Op = CurMI->getOperand(0);
          //Op.setTargetFlags(X86II::MO_NO_FLAG);

          // The function and its first block are 256-byte aligned, and the entrypoint is shorter than
          // 256 bytes. Thus, the first block is at Callee+256.
          Op.setOffset(256);

          // Get target address (relative to code-scratchpad: scrbase + off)
          BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::LEA64r), X86::R15)
              .addUse(X86::RIP)
              .addImm(0)
              .addUse(0)
              .add(Op)
              .addUse(0);

          // Convert to absolute address
          // [r14+0] = block - scrbase
          // -> (scrbase + off) + block - scrbase = block + off
          MachineInstr *ReadAdjustValue = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::MOV64rm), X86::R13)
              .addUse(X86::R14)
              .addImm(1)
              .addUse(0)
              .addImm(0)
              .addUse(0);
          ReadAdjustValue->setObelixFlags(llvm::MachineInstr::DoNotPad | llvm::MachineInstr::PtrAdjust);
          MachineInstr *PtrAdjustLea = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::LEA64r), X86::R15)
              .addUse(X86::R15)
              .addImm(1)
              .addUse(X86::R13)
              .addImm(0)
              .addUse(0);
          PtrAdjustLea->setObelixFlags(llvm::MachineInstr::DoNotPad | llvm::MachineInstr::PtrAdjust);

          break;
        };
        default:
          dbgs() << "Unsupported `jmp` operand type\n";
          CurMI->dump();
          llvm_unreachable("Unsupported `jmp` operand type");
        }

        // class1 Dummy
        BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::MOV64rr), X86::R13)
          .addUse(X86::R15);

        // Jump to controller
        MachineInstr *Mov = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::MOV64rr), X86::R13)
            .addUse(X86::R15); // no-op, not needed
        Mov->setObelixFlags(MachineInstr::ObelixFlag::DoNotProcess
                                | MachineInstr::ObelixFlag::DoNotPad
                                | MachineInstr::ObelixFlag::ControllerJump);
        insertJumpToNextBlock(MBB, CurMI);

        CurMI->removeFromParent();
        MF->deleteMachineInstr(CurMI);

        EstimatedBlockByteSize += EstimatedBranchSize;

        break;
      }
      case X86::JMP64r: {

        // Skip ahead to end of pattern
        insertPaddingUntil(ObelixIClasses::None);

        // Jump to controller
        MachineInstr *Mov = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::MOV64rr), X86::R15)
            .addUse(CurMI->getOperand(0).getReg());
        Mov->setObelixFlags(MachineInstr::ObelixFlag::DoNotProcess
                                | MachineInstr::ObelixFlag::DoNotPad
                                | MachineInstr::ObelixFlag::ControllerJump);
        insertJumpToNextBlock(MBB, CurMI);

        CurMI->removeFromParent();
        MF->deleteMachineInstr(CurMI);

        EstimatedBlockByteSize += EstimatedBranchSize;

        break;
      }
      case X86::JCC_1: {
        // We jump depending on the condition, or fallthrough to the next MBB

        // To implement the decision, we need four instructions:
        //   mov r15d, FALLTHROUGH_ADDRESS
        //   lea r13, [rip+JUMP_TARGET]
        //   cmovcc r15, r13
        //   jmp controller
        // The latter two are included in the generic code block format.
        // However, the first two must conform to the block pattern. We cannot
        // put them anywhere, as intermittent dummy instructions may overwrite
        // the r13/r15 registers. So we put fixed instruction classes at the end
        // of the pattern, allowing us to directly emit the above JCC logic.

        // Skip ahead to end of pattern
        // Remaining:
        // - class1
        // - adjust
        // - class1
        if(!insertPaddingUntil(ObelixIClasses::Class1, -3))
          break;

        // Load target address
        switch (CurMI->getOperand(0).getType()) {
        case llvm::MachineOperand::MO_MachineBasicBlock:
        case llvm::MachineOperand::MO_BlockAddress:
        case llvm::MachineOperand::MO_MCSymbol:
        case llvm::MachineOperand::MO_ExternalSymbol: {

          // Get target address (relative to code-scratchpad: scrbase + off)
          BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::LEA64r), X86::R13)
              .addUse(X86::RIP)
              .addImm(0)
              .addUse(0)
              .add(CurMI->getOperand(0))
              .addUse(0);

          // Convert to absolute address
          // [r14+0] = block - scrbase
          // -> (scrbase + off) + block - scrbase = block + off
          MachineInstr *ReadAdjustValue = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::MOV64rm), X86::R15)
              .addUse(X86::R14)
              .addImm(1)
              .addUse(0)
              .addImm(0)
              .addUse(0);
          ReadAdjustValue->setObelixFlags(llvm::MachineInstr::DoNotPad | llvm::MachineInstr::PtrAdjust);
          MachineInstr *PtrAdjustLea = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::LEA64r), X86::R13)
              .addUse(X86::R13)
              .addImm(1)
              .addUse(X86::R15)
              .addImm(0)
              .addUse(0);
          PtrAdjustLea->setObelixFlags(llvm::MachineInstr::DoNotPad | llvm::MachineInstr::PtrAdjust);

          break;
        }
        default:
          dbgs() << "Unsupported `jcc` operand type\n";
          CurMI->dump();
          llvm_unreachable("Unsupported `jcc` operand type");
        }

        // Write fallthrough address to r15
        static_assert(BLOCK_ADDRESS_FALLTHROUGH == 0); // mov r15d, 0 == movzx r15, r14b
        BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::MOVZX64rr8), X86::R15)
            .addReg(X86::R14B);

        // Extract condition
        X86::CondCode CC = X86::CondCode::COND_INVALID;
        for (int o = CurMI->getNumOperands() - 1; o >= 0; --o) {
          auto &OP = CurMI->getOperand(o);
          if (OP.getType() == llvm::MachineOperand::MO_Immediate) {
            CC = static_cast<X86::CondCode>(OP.getImm());
            break;
          }
        }

        // Choose address
        // Encoded length: 4 bytes
        MachineInstr *Cmov = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::CMOV64rr), X86::R15)
            .addUse(X86::R15)
            .addUse(X86::R13)
            .addImm(CC);
        Cmov->setObelixFlags(MachineInstr::ObelixFlag::DoNotProcess
                                 | MachineInstr::ObelixFlag::DoNotPad
                                 | MachineInstr::ObelixFlag::ControllerJump);

        // Jump to controller
        MachineInstr *ControllerJmp = insertJumpToNextBlock(MBB, CurMI);

        CurMI->removeFromParent();
        MF->deleteMachineInstr(CurMI);

        // Is there another instruction after this one?
        // Sometimes fallthroughs are encoded as explicit jumps
        MachineInstr *FallthroughMI = ControllerJmp->getNextNode();
        if(FallthroughMI != nullptr) {
          if(FallthroughMI->getOpcode() == X86::JMP_1) {
            // Split MBB so the jump is correctly translated
            // TODO we may solve this directly via the `mov r15`, which is a
            //   full 8-byte instruction slot.
            splitMachineBasicBlock(MBB, FallthroughMI);
          }
          else {
            FallthroughMI->dump();
            llvm_unreachable("Unsupported instruction after JCC");
          }
        }

        EstimatedBlockByteSize += EstimatedBranchSize;
        break;
      }
      default: {
        dbgs() << "Unhandled branch opcode\n";
        CurMI->dump();
        llvm_unreachable("Unhandled branch opcode");
      }
      }

      // Branches always end code blocks
      break;
    }

    // Handle `call`. We first need to determine the return address, which needs
    // arithmetic and thus does not belong at the beginning of a block.
    // (check that we don't have a composite call/return pseudo-instruction,
    //  like a tail jump)
    if (CurMI->isCall() && !CurMI->isReturn()) {
      dbgs() << "[OBELIX]   Breaking up `call` instruction\n";

      // Split `call` into `lea r10, [fallthrough]; push r10; jmp [target]`

      // If there are instructions behind this call, split them into a new MBB
      if(CurMI->getNextNode() != nullptr) {
        splitMachineBasicBlock(MBB, CurMI->getNextNode());
      }

      assert(MBB->getNextNode() != nullptr && "No fallthrough after call");

      // TODO We just overwrite the r10 register here, as it is volatile per the x86-64 ABI
      //      and not used as a function parameter.
      //      We should assert that the register is in fact dead

      // Retrieve and push return address
      // The resulting value needs pointer adjustment to an absolute address, which will get
      // taken care of in the next iteration
      MachineInstr *LeaRetAddr = BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::LEA64r), X86::R10)
          .addUse(X86::RIP)
          .addImm(0)
          .addUse(0)
          .addMBB(MBB->getNextNode()) // `call` will end this block
          .addUse(0);

      BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::PUSH64r))
          .addUse(X86::R10);

      // Only the jump remains. Don't fully convert it here, as we need another
      // RIP adjustment, which in turn requires padding.
      switch (CurMI->getOperand(0).getType()) {

      case llvm::MachineOperand::MO_Register: {
        // call reg

        MachineOperand &Op = CurMI->getOperand(0);

        BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::JMP64r))
            .add(Op);

        break;
      }

      case llvm::MachineOperand::MO_GlobalAddress: {

        MachineOperand &Op = CurMI->getOperand(0);

        BuildMI(*MBB, CurMI, DebugLoc(), TII->get(X86::JMP_1))
            .add(Op);

        break;
      }

      default:
        dbgs() << "Unsupported `call` operand type (" << (int)CurMI->getOperand(0).getType() << ")\n";
        CurMI->dump();
        llvm_unreachable("Unsupported `call` operand type");
      }

      CurMI->removeFromParent();
      MF->deleteMachineInstr(CurMI);

      // Continue processing from the first newly inserted instruction
      CurMI = LeaRetAddr;
      continue;
    }

    // Other instructions are left as-is, with appropriate padding
    dbgs() << "[OBELIX]   Processing classX instruction `" << TII->getName(CurMI->getOpcode()) << "`\n";
    ObelixIClasses CurInstrIClass =
        static_cast<ObelixIClasses>(OCA->getInstructionClass(CurMI->getOpcode()) >> X86II::ObelixInstructionClassShift);
    if(CurInstrIClass == ObelixIClasses::None) {
      dbgs() << "Unknown instruction class for " << TII->getName(CurMI->getOpcode()) << "\n";
      llvm_unreachable("Unknown instruction class");
    }

    if(!insertPaddingUntil(CurInstrIClass))
      break;

    EstimatedBlockByteSize += estimateInstrByteSize(CurMI);

    CurMI = CurMI->getNextNode();
    if(!ObfuscuroMode)
      ++PatternIndex;
  }

  // Add some padding after the code block end to ensure that it takes the expected storage space
  // (and, more important, all blocks have the same distance to ensure that the fallthrough
  // offsets are identical)
  int PadCount = 0;
  if (ObelixFeatureLevel < ObelixFeatureLevels::UniformBlocks && EstimatedBlockByteSize < ObelixPatternCandidate::CodeBlockSize)
    PadCount = ObelixPatternCandidate::CodeBlockSize - EstimatedBlockByteSize;
  else if (ObelixFeatureLevel >= ObelixFeatureLevels::UniformBlocks && (CodeBlockPattern->getSize() + 1) * 8 < ObelixPatternCandidate::CodeBlockSize)
    PadCount = (ObelixPatternCandidate::CodeBlockSize - (CodeBlockPattern->getSize() + 1) * 8) / 8;

  for (int i = 0; i < PadCount; ++i)
    BuildMI(*MBB, MBB->end(), DebugLoc(), TII->get(X86::INT3));
}

bool X86ObelixCodeSplitPass::runOnMachineFunction(
    MachineFunction &machineFunction) {

  OCA = &getAnalysis<X86ObelixCodeAnalysis>();

  if(ObelixBuildStage != 2)
    return false;

  // Retrieve some needed objects and store them as private class members to
  // avoid excessive function parameters
  MF = &machineFunction;
  STI = &MF->getSubtarget<X86Subtarget>();
  TII = STI->getInstrInfo();
  TRI = STI->getRegisterInfo();

  // Is the function marked as needing ORAM instrumentation?
  if(!MF->getFunction().hasFnAttribute(Attribute::Obelix))
    return false;

  const Attribute &FOAttr = MF->getFunction().getFnAttribute(Attribute::Obelix);
  if(FOAttr.getObelixProperties().getState() != ObelixProperties::Copy
      && FOAttr.getObelixProperties().getState() != ObelixProperties::AutoCopy)
    return false;

  MLI = &getAnalysis<MachineLoopInfo>();

  dbgs() << "[OBELIX] Running code splitter on '" << MF->getName() << "'\n";

  // Find generated code block pattern
  Function *ParentF = &MF->getFunction();
  if(ParentF->ObelixParent != nullptr)
    ParentF = ParentF->ObelixParent;
  CodeBlockPattern = ParentF->CodeBlockPattern;

  // Check whether this function accesses any globals
  // TODO we may move this into the call graph traversal pass and propagate the
  //   accesses from callees
  SmallPtrSet<const GlobalValue *, 4> AccessedGlobals;
  for(auto &MBB : *MF) {
    for(auto &MI : MBB) {
      for(auto &Op : MI.operands()) {
        if(Op.isGlobal()) {
          const GlobalValue *GV = Op.getGlobal();
          if(!GV->isDeclaration()) {
            AccessedGlobals.insert(GV);
          }
        }
      }
    }
  }

  // Insert entry block
  MachineBasicBlock *CurMBB = &MF->front();
  MachineBasicBlock *NewEntryMBB = MF->CreateMachineBasicBlock(nullptr);
  MF->insert(MF->begin(), NewEntryMBB);
  NewEntryMBB->addSuccessor(CurMBB);

  // Top level functions get an ORAM entry block. All others get a short dummy
  // header to indicate that they must not be called directly.
  if(MF->getFunction().ObelixParent == nullptr) {

    // TODO check whether r10 is indeed dead at begin of function (should
    //      hold due to the x86-64 ABI, but better be sure)
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::MOV64rm), X86::R10)
        .addUse(X86::RIP)
        .addImm(0)
        .addUse(0)
        .addExternalSymbol("__obelix_save", X86II::MO_GOTPCREL)
        .addUse(0);

    // Save ORAM controller registers
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::MOV64mr))
        .addUse(X86::R10)
        .addImm(1)
        .addUse(0)
        .addImm(0x00)
        .addUse(0)
        .addUse(X86::R13);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::MOV64mr))
        .addUse(X86::R10)
        .addImm(1)
        .addUse(0)
        .addImm(0x08)
        .addUse(0)
        .addUse(X86::R14);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::MOV64mr))
        .addUse(X86::R10)
        .addImm(1)
        .addUse(0)
        .addImm(0x10)
        .addUse(0)
        .addUse(X86::R15);

    // Save original return address
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::MOV64rm), X86::R13)
        .addUse(X86::RSP)
        .addImm(1)
        .addUse(0)
        .addImm(0)
        .addUse(0);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::MOV64mr))
        .addUse(X86::R10)
        .addImm(1)
        .addUse(0)
        .addImm(0x18)
        .addUse(0)
        .addUse(X86::R13);

    // Overwrite return address with marker for leaving protected code
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::MOV64mi32))
        .addUse(X86::RSP)
        .addImm(1)
        .addUse(0)
        .addImm(0)
        .addUse(0)
        .addImm(BLOCK_ADDRESS_EXIT);

    // Load address of function info block
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::LEA64r), X86::R15)
        .addUse(X86::RIP)
        .addImm(0)
        .addUse(0)
        .addSym(MF->getContext().getOrCreateSymbol(MF->getFunction().getObelixOramFunctionInfoSymbolName()))
        .addUse(0);

    // Temporarily save other registers while we do the initialization
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::PUSH64r), X86::R12);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::PUSH64r), X86::R11);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::PUSH64r), X86::R10);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::PUSH64r), X86::R9);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::PUSH64r), X86::R8);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::PUSH64r), X86::RBP);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::PUSH64r), X86::RDI);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::PUSH64r), X86::RSI);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::PUSH64r), X86::RDX);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::PUSH64r), X86::RCX);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::PUSH64r), X86::RBX);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::PUSH64r), X86::RAX);

    // Align stack
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::SUB64ri8), X86::RSP)
        .addUse(X86::RSP)
        .addImm(8);

    // Call initializer
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::MOV64rr), X86::RDI)
        .addUse(X86::R15); // s32 *functionInfo
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::MOV32ri), X86::ESI)
        .addImm(ObelixFeatureLevel < ObelixFeatureLevels::CiphertextProtection ? 0 : 1); // bool useRandOram
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::CALL64pcrel32))
        .addExternalSymbol("__obelix_init");

    // Register stack frame in data ORAM
    // As the stack grows to smaller address, we have to invert the parameters:
    //     rsp-0x08: X
    //     rsp-0x10: Y
    //     rsp-0x18: Z
    //   We currently have `rsp-0x00`. Thus we have to subtract 0x18 for the base address
    //   and pass 0x18 as size.
    uint64_t StackSize = MF->getFunction().ObelixStackSize;
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::LEA64r), X86::RDI)
        .addUse(X86::RSP)
        .addImm(1)
        .addUse(0)
        .addImm(12 * 8 + 8 - StackSize) // Value of RSP before the return address was pushed
        .addUse(0);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::MOV64ri), X86::RSI)
        .addImm(StackSize);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::CALL64pcrel32))
        .addExternalSymbol("__obelix_add_data");

    // Register globals for which we have the size
    for(const GlobalValue *GV : AccessedGlobals)
    {
      Type *ValTy = GV->getValueType();
      if(ValTy->isSized())
      {
        dbgs() << "[OBELIX]  Registering global variable in data ORAM\n";

        uint64_t GVSize = MF->getDataLayout().getTypeAllocSize(ValTy);
        BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::LEA64r), X86::RDI)
            .addUse(X86::RIP)
            .addImm(1)
            .addUse(0)
            .addGlobalAddress(GV)
            .addUse(0);
        BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::MOV64ri), X86::RSI)
            .addImm(GVSize);
        BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::CALL64pcrel32))
            .addExternalSymbol("__obelix_add_data");
      }
    }

    // Debug output
    //BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::CALL64pcrel32))
    //    .addExternalSymbol("__obelix_dump");

    // Remove stack alignment
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::ADD64ri8), X86::RSP)
        .addUse(X86::RSP)
        .addImm(8);

    // Restore other registers
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::POP64r), X86::RAX);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::POP64r), X86::RBX);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::POP64r), X86::RCX);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::POP64r), X86::RDX);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::POP64r), X86::RSI);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::POP64r), X86::RDI);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::POP64r), X86::RBP);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::POP64r), X86::R8);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::POP64r), X86::R9);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::POP64r), X86::R10);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::POP64r), X86::R11);
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::POP64r), X86::R12);

    // Jump into controller main function
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::JMP_1))
        .addExternalSymbol("__obelix_controller_enter");
  }
  else {

    // Output an error message and crash
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::CALL64pcrel32))
        .addExternalSymbol("__obelix_invalid_entrypoint");
    BuildMI(*NewEntryMBB, NewEntryMBB->end(), DebugLoc(), TII->get(X86::HLT));
  }

  // Ensure that the entry point is correctly aligned
  MF->setAlignment(Align(256));

  // Reformat basic blocks
  bool first = true;
  while (CurMBB != nullptr) {

    if(first) {
      CurMBB->setAlignment(Align(256));
      first = false;
    }

    // This BB will be processed by the code ORAM
    CurMBB->IsObelixOramBlock = true;
    MF->ObelixCodeBlocks.push_back(CurMBB);

    // Ensure that every code block MBB has a label
    CurMBB->getSymbol();
    CurMBB->setLabelMustBeEmitted();

    // Transform block
#if DUMP_TRANSLATED_INSTRUCTIONS
    dbgs() << "## MBB before translation ##\n";
    CurMBB->dump();
    dbgs() << "############################\n";
#endif

    handleMachineBasicBlock(CurMBB);

#if DUMP_TRANSLATED_INSTRUCTIONS
    dbgs() << "%% MBB after translation %%\n";
    CurMBB->dump();
    dbgs() << "%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";
#endif

    // Continue with new block, possibly containing the remainder of the current
    // one
    CurMBB = CurMBB->getNextNode();
  }

  return true;
}

INITIALIZE_PASS(X86ObelixCodeSplitPass, OBELIXCODESPLIT_NAME,
                OBELIXCODESPLIT_DESC, false, false)

FunctionPass *llvm::createX86ObelixCodeSplitPass() {
  return new X86ObelixCodeSplitPass();
}
#pragma clang diagnostic pop