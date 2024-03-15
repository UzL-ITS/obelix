#pragma clang diagnostic push
#pragma ide diagnostic ignored "readability-identifier-naming"

#include "X86ObelixCodeAnalysis.h"
#include "X86.h"
#include "X86InstrInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCContext.h"
#include "llvm/Pass.h"
#include "llvm/Support/ObelixBuildFiles.h"
#include "llvm/Support/ObelixCommandLineFlags.h"
#include "llvm/Support/ObelixProperties.h"
#include <fstream>
#include <random>

using namespace llvm;


#define OBELIXCODEANALYSIS_DESC                                                \
  "Obelix: Converts basic blocks into abstract instruction classes"
#define OBELIXCODEANALYSIS_NAME "x86-obelix-code-analysis"

char X86ObelixCodeAnalysis::ID = 0;

X86ObelixCodeAnalysis::X86ObelixCodeAnalysis() : MachineFunctionPass(ID) {
  initializeX86ObelixCodeAnalysisPass(*PassRegistry::getPassRegistry());
}

void X86ObelixCodeAnalysis::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.setPreservesAll();
  AU.addRequired<MachineLoopInfo>();
  MachineFunctionPass::getAnalysisUsage(AU);
}

static void dumpIClassList(const uint64_t *Start, const uint64_t *End, raw_ostream &Ostream) {
  for(const uint64_t *It = Start; It != End; ++It) {
    switch(*It) {
    case X86II::ObelixIClassNone: Ostream << "?"; break;
    case X86II::ObelixIClassLoad: Ostream << "r"; break;
    case X86II::ObelixIClassStore: Ostream << "w"; break;
    case X86II::ObelixIClassPtrAdjust: Ostream << "p"; break;
    case X86II::ObelixIClass1: Ostream << "1"; break;
    case X86II::ObelixIClass2: Ostream << "2"; break;
    case X86II::ObelixIClass3: Ostream << "3"; break;
    case X86II::ObelixIClass4: Ostream << "4"; break;
    default: dbgs() << "_" << static_cast<int>(*It) << "_"; break;
    }
  }
}

static void dumpIClassList(const SmallVector<uint64_t, ObelixPatternCandidate::CodeBlockInstrCount> &List) {
  dumpIClassList(List.begin(), List.end(), dbgs());
}

static void dumpIClassList(const SmallVector<uint64_t, ObelixPatternCandidate::CodeBlockInstrCount> &List, raw_ostream &Ostream) {
  dumpIClassList(List.begin(), List.end(), Ostream);
}

uint64_t X86ObelixCodeAnalysis::getInstructionClass(unsigned short Opcode) {
  return STI->getInstrInfo()->get(Opcode).TSFlags
      & X86II::ObelixInstructionClassMask;
}

bool X86ObelixCodeAnalysis::runOnMachineFunction(
    MachineFunction &MFunc) {

  // Retrieve some needed objects and store them as private class members to
  // avoid excessive function parameters
  MF = &MFunc;
  STI = &MF->getSubtarget<X86Subtarget>();
  TII = STI->getInstrInfo();

  // No further analysis in other build stages, we just serve some helper
  // functions
  if(ObelixBuildStage != 1)
    return false;

  // Is the function marked as needing ORAM instrumentation?
  if(!MF->getFunction().hasFnAttribute(Attribute::Obelix))
    return false;

  const Attribute &FOAttr = MF->getFunction().getFnAttribute(Attribute::Obelix);
  if(FOAttr.getObelixProperties().getState() != ObelixProperties::Copy
      && FOAttr.getObelixProperties().getState() != ObelixProperties::AutoCopy)
    return false;

  dbgs() << "[OBELIX] Running basic block analysis on '" << MF->getName() << "'\n";

  assert(ObelixBuildFiles::buildDirectoryExists() && "The build directory does not exist");

  // Get analyses
  MLI = &getAnalysis<MachineLoopInfo>();

  // Translate instruction opcodes into the respective classes
  DenseMap<MachineBasicBlock *, BasicBlockIClassInfo *> BasicBlockMap;
  for (auto &MBB : *MF) {

    BasicBlockIClassInfo *BBInfo = new BasicBlockIClassInfo();
    for (auto &MI : MBB) {

      const MCInstrDesc &MIDesc = MI.getDesc();
      uint64_t MIObIClass = getInstructionClass(MIDesc.Opcode);

      // Handle some instructions manually
      if (isPush(&MI)) {
        // Becomes `store; sub rsp, 8`
        BBInfo->InstructionClasses.push_back(X86II::ObelixIClassStore);

        uint64_t SubIClass = getInstructionClass(X86::SUB64ri8);
        assert(SubIClass != X86II::ObelixIClassNone && "Unknown instruction class");
        BBInfo->InstructionClasses.push_back(SubIClass);
      }
      else if (isPop(&MI) || MIDesc.Opcode == X86::RET64) {
        // `ret` becomes `pop; jmp` -> `load; add rsp, 8; jmp`
        // `pop` becomes `load; add rsp, 8`
        // As `ret` is always at the end of a basic block, we can treat it the
        // same as `pop`.

        BBInfo->InstructionClasses.push_back(X86II::ObelixIClassLoad);

        uint64_t AddIClass = getInstructionClass(X86::ADD64ri8);
        assert(AddIClass != X86II::ObelixIClassNone && "Unknown instruction class");
        BBInfo->InstructionClasses.push_back(AddIClass);
      }
      else if (MI.isBranch()) {
        // A mov+JMP is implicitly at the end of each block. Only add classes
        // for branches which need more than those two instructions
        if(MIDesc.Opcode == X86::JMP_1) {

          // lea
          uint64_t LeaIClass = getInstructionClass(X86::LEA64r);
          assert(LeaIClass != X86II::ObelixIClassNone && "Unknown instruction class");
          BBInfo->InstructionClasses.push_back(LeaIClass);

          // <adjust>
          BBInfo->InstructionClasses.push_back(X86II::ObelixIClassPtrAdjust);

          // dummy
          uint64_t MovIClass = getInstructionClass(X86::MOV64rr);
          assert(MovIClass != X86II::ObelixIClassNone && "Unknown instruction class");
          BBInfo->InstructionClasses.push_back(MovIClass);
        }
        if(MIDesc.Opcode == X86::JCC_1) {

          // lea
          uint64_t LeaIClass = getInstructionClass(X86::LEA64r);
          assert(LeaIClass != X86II::ObelixIClassNone && "Unknown instruction class");
          BBInfo->InstructionClasses.push_back(LeaIClass);

          // <adjust>
          BBInfo->InstructionClasses.push_back(X86II::ObelixIClassPtrAdjust);

          // mov
          uint64_t MovIClass = getInstructionClass(X86::MOV32ri);
          assert(MovIClass != X86II::ObelixIClassNone && "Unknown instruction class");
          BBInfo->InstructionClasses.push_back(MovIClass);
        }
      }
      else if (MI.isCall()) {
        // `call` becomes `lea [fallthrough]; <adjust>; push; jmp [target]`
        //        -> `lea [fallthrough]; <adjust>; store; sub rsp, 8;
        //            lea [target]; <adjust>; mov dummy; jmp`

        // lea
        uint64_t LeaIClass = getInstructionClass(X86::LEA64r);
        assert(LeaIClass != X86II::ObelixIClassNone && "Unknown instruction class");
        BBInfo->InstructionClasses.push_back(LeaIClass);

        // <adjust>
        BBInfo->InstructionClasses.push_back(X86II::ObelixIClassPtrAdjust);

        // store
        BBInfo->InstructionClasses.push_back(X86II::ObelixIClassStore);

        // sub
        uint64_t SubIClass = getInstructionClass(X86::SUB64ri8);
        assert(SubIClass != X86II::ObelixIClassNone && "Unknown instruction class");
        BBInfo->InstructionClasses.push_back(SubIClass);

        // lea
        BBInfo->InstructionClasses.push_back(LeaIClass);

        // <adjust>
        BBInfo->InstructionClasses.push_back(X86II::ObelixIClassPtrAdjust);

        // dummy
        uint64_t MovIClass = getInstructionClass(X86::MOV64rr);
        assert(MovIClass != X86II::ObelixIClassNone && "Unknown instruction class");
        BBInfo->InstructionClasses.push_back(MovIClass);
      }
      else if (MI.isCFIInstruction() || MI.isKill()) {
        // Ignore
      }
      else if (isLoad(&MI)) {
        BBInfo->InstructionClasses.push_back(X86II::ObelixIClassLoad);
      }
      else if (isStore(&MI)) {
        BBInfo->InstructionClasses.push_back(X86II::ObelixIClassStore);
      }
      else if (MIObIClass == X86II::ObelixIClassNone) {
        dbgs() << "[OBELIX]  Unhandled opcode `"
               << TII->getName(MI.getOpcode()) << "`\n";
        llvm_unreachable("Unhandled opcode in block pattern analyzer");
      }
      else {
        BBInfo->InstructionClasses.push_back(MIObIClass);
      }
    }

    BasicBlockMap[&MBB] = BBInfo;
  }

  // Add loop info to basic blocks
  std::vector<MachineLoop *> PendingLoops(MLI->begin(), MLI->end());
  while(!PendingLoops.empty())
  {
    MachineLoop *ML = PendingLoops.back();
    PendingLoops.pop_back();

    // Add sub loops
    for(auto *SubML : *ML)
      PendingLoops.push_back(SubML);

    for (auto *MBB : ML->blocks()) {
      // TODO is there any way to better estimate the "hotness" of a certain BB?
      // TODO take into account child functions, those should probably get a weight boost as well?
      BasicBlockMap[MBB]->Weight += 10;
    }
  }

  // (Debug) Dump classified BBs
  dbgs() << "[OBELIX]  Classified basic blocks:\n";
  for (const auto &BB : BasicBlockMap)
  {
    dbgs() << "[OBELIX]    ";
    dumpIClassList(BB.second->InstructionClasses);
    dbgs() << "   Weight: " << BB.second->Weight << "\n";
  }

  // Compute stack frame size
  MachineFrameInfo &MFI = MF->getFrameInfo();
  uint64_t StackFixedObjectsSize = 0;
  uint64_t StackOtherObjectsSize = 0;
  for(unsigned i = 0; i < MFI.getNumFixedObjects(); ++i) {
    uint64_t StackObjectSize = MFI.getObjectSize(-(i + 1));
    if(StackObjectSize != ~0ULL)
      StackFixedObjectsSize += StackObjectSize;
  }
  for(unsigned i = 0; i < MFI.getNumObjects() - MFI.getNumFixedObjects(); ++i) {
    uint64_t StackObjectSize = MFI.getObjectSize(i);
    if(StackObjectSize != ~0ULL)
      StackOtherObjectsSize += StackObjectSize;
  }
  uint64_t StackSize = StackFixedObjectsSize + StackOtherObjectsSize;
  StackSize += 32; // Add a few more bytes to account for alignment etc.
  StackSize &= ~0xf; // Align to 16 bytes
  dbgs() << "[OBELIX]  Computed stack frame size:"
         << " 0x" << Twine::utohexstr(StackFixedObjectsSize)
         << " 0x" << Twine::utohexstr(StackOtherObjectsSize)
         << " -> 0x" << Twine::utohexstr(StackSize) << " (including alignment)"
         << "\n";

  // Write info to temporary file for stage 2
  std::string OutputFileName = ObelixBuildFiles::getBuildFileName(MF->getName().str());
  std::error_code FileErr;
  llvm::raw_fd_ostream OutputFileStream(OutputFileName, FileErr, sys::fs::OpenFlags::OF_Text);
  if(FileErr) {
    errs () << "Can not open build file \"" << OutputFileName << "\": " << FileErr.message() << " (" << FileErr.value() << ")\n";
    report_fatal_error("Can not open build file");
  }

  // Write classified BBs
  OutputFileStream << BasicBlockMap.size() << "\n";
  for(const auto &BB : BasicBlockMap) {
    auto *BBInfo = BB.second;
    OutputFileStream << BBInfo->Weight << " ";
    dumpIClassList(BBInfo->InstructionClasses, OutputFileStream);
    OutputFileStream << "\n";
  }

  // Write functions called by the current one
  const Function &F = MF->getFunction();
  OutputFileStream << F.ObelixCalledFunctions.size() << "\n";
  for(const auto *Callee : F.ObelixCalledFunctions) {
    OutputFileStream << Callee->getName() << "\n";
  }

  // Append stack frame size info
  std::string StackFrameInfoFileName = ObelixBuildFiles::getBuildFileName("__StackFrameInfo__");
  llvm::raw_fd_ostream StackFrameInfoFileStream(StackFrameInfoFileName,
                                                FileErr,
                                                sys::fs::OpenFlags::OF_Append);
  if(FileErr) {
    errs () << "Can not open stack frame info file \"" << StackFrameInfoFileName << "\": " << FileErr.message() << " (" << FileErr.value() << ")\n";
    report_fatal_error("Can not open stack frame info file");
  }

  StackFrameInfoFileStream << MF->getName() << " " << StackSize << "\n";

  // This is a pure analysis pass, so it never changes the function
  return false;
}

INITIALIZE_PASS(X86ObelixCodeAnalysis, OBELIXCODEANALYSIS_NAME,
                OBELIXCODEANALYSIS_DESC, false, true)

FunctionPass *llvm::createX86ObelixCodeAnalysis() {
  return new X86ObelixCodeAnalysis();
}
#pragma clang diagnostic pop