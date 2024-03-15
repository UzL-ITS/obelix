#ifndef LLVM_X86OBELIXCODEANALYSIS_H
#define LLVM_X86OBELIXCODEANALYSIS_H

#include "X86Subtarget.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/Transforms/Instrumentation/ObelixGeneratePattern.h"

namespace llvm {

class X86ObelixCodeAnalysis : public MachineFunctionPass {

public:
  static char ID;

  X86ObelixCodeAnalysis();
  uint64_t getInstructionClass(unsigned short Opcode);

protected:
  bool runOnMachineFunction(MachineFunction &MF) override;
  void getAnalysisUsage(AnalysisUsage &AU) const override;

private:
  MachineFunction *MF = nullptr;
  const MachineLoopInfo *MLI = nullptr;
  const X86Subtarget *STI = nullptr;
  const TargetInstrInfo *TII = nullptr;

  /// Contains the instruction classes present in the associated basic
  /// block, and some metadata.
  class BasicBlockIClassInfo {
  public:
    int Weight = 1;
    SmallVector<uint64_t, ObelixPatternCandidate::CodeBlockInstrCount> InstructionClasses;
  };
};

// Utility functions

static inline bool isPush(const MachineInstr *MI) {
  switch (MI->getOpcode()) {
  case X86::PUSH32i8:
  case X86::PUSH32r:
  case X86::PUSH32rmm:
  case X86::PUSH32rmr:
  case X86::PUSHi32:
  case X86::PUSH64i8:
  case X86::PUSH64r:
  case X86::PUSH64rmm:
  case X86::PUSH64rmr:
  case X86::PUSH64i32:
    return true;
  default:
    return false;
  }
}

static inline bool isPop(const MachineInstr *MI) {
  switch (MI->getOpcode()) {
  case X86::POP32r:
  case X86::POP32rmm:
  case X86::POP32rmr:
  case X86::POP64r:
  case X86::POP64rmm:
  case X86::POP64rmr:
    return true;
  default:
    return false;
  }
}

static inline bool isLoad(const MachineInstr *MI) {
  return MI->getNumMemOperands() > 0 && (*MI->memoperands_begin())->isLoad();
}

static inline bool isStore(const MachineInstr *MI) {
  return MI->getNumMemOperands() > 0 && (*MI->memoperands_begin())->isStore();
}

}

#endif // LLVM_X86OBELIXCODEANALYSIS_H
