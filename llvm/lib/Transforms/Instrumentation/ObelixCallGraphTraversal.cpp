
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ObelixBuildFiles.h"
#include "llvm/Support/ObelixCommandLineFlags.h"
#include "llvm/Support/ObelixProperties.h"
#include "llvm/Transforms/Instrumentation/ObelixCallGraphTraversal.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <fstream>

using namespace llvm;

ObelixCallGraphTraversalPass::ObelixCallGraphTraversalPass() {

}

Function *ObelixCallGraphTraversalPass::cloneFunction(Function *F, const std::string &NameSuffix, bool IsAutoCopy) {

  // Update attribute of original function
  if(!IsAutoCopy)
    F->addFnAttr(Attribute::getWithObelixProperties(F->getContext(), ObelixProperties(ObelixProperties::State::Original)));

  // Create function clone for subsequent instrumentation
  Function *FCopy = Function::Create(F->getFunctionType(), F->getLinkage(), F->getName() + NameSuffix, M);
  FCopy->ObelixOriginal = F;
  ValueToValueMapTy VMap;
  Function::arg_iterator FCopyArgIt = FCopy->arg_begin();
  for (Function::const_arg_iterator FArgIt = F->arg_begin(); FArgIt != F->arg_end(); ++FArgIt) {
    VMap[FArgIt] = FCopyArgIt++;
  }
  SmallVector<ReturnInst*, 8> FCopyReturns;
  CloneFunctionInto(FCopy, F, VMap, CloneFunctionChangeType::GlobalChanges, FCopyReturns);

  if(IsAutoCopy)
    FCopy->addFnAttr(Attribute::getWithObelixProperties(F->getContext(), ObelixProperties(ObelixProperties::State::AutoCopy)));
  else
    FCopy->addFnAttr(Attribute::getWithObelixProperties(F->getContext(), ObelixProperties(ObelixProperties::State::Copy)));

  return FCopy;
}

/// Recursively computes the maximum total stack size of the given call graph node.
static uint64_t computeStackFrameSize(uint64_t CurrentSize,
                                      const CallGraphNode *CGNode,
                                      const DenseMap<const Function *, uint64_t> &StackFrameSizes,
                                      const SmallPtrSet<const Function *, 16> &IgnoredFunctions,
                                      SmallPtrSet<const CallGraphNode *, 16> &VisitedNodes) {

  uint64_t MaxSize = CurrentSize + StackFrameSizes.at(CGNode->getFunction());
  for(auto &Child : *CGNode) {

    if(Child.second->getFunction() == nullptr
      || IgnoredFunctions.contains(Child.second->getFunction()))
      continue;

    // Ignore cycles. If we have cycles, we treat the stack frame size as unknown
    // and rely on the lazy data ORAM insertion at runtime
    if(VisitedNodes.contains(Child.second))
      continue;

    VisitedNodes.insert(Child.second);
    uint64_t ChildSize = computeStackFrameSize(CurrentSize, Child.second, StackFrameSizes, IgnoredFunctions, VisitedNodes);
    VisitedNodes.erase(Child.second);

    if(ChildSize > MaxSize)
      MaxSize = ChildSize;
  }

  return MaxSize;
}

PreservedAnalyses ObelixCallGraphTraversalPass::run(Module &Mod,
                                                    ModuleAnalysisManager &AM) {

  M = &Mod;

  // If we are in stage 1, we emit lots of information to build files, which are
  // picked up again in stage 2.
  if(!ObelixBuildFiles::createBuildDirectory())
    report_fatal_error("Could not create build directory");

  // Clear some information at the beginning of stage 1
  if(ObelixBuildStage == 1) {
    sys::fs::remove(ObelixBuildFiles::getBuildFileName("__StackFrameInfo__"));
  }

  auto &CG = AM.getResult<CallGraphAnalysis>(*M);

  // Iterate through all functions manually marked as needing instrumentation.
  // For each function, we traverse its call graph, create specific clones of all
  // callees, and rewrite calls accordingly.

  // Find all initially marked functions
  std::vector<CallGraphNode *> MarkedFunctions;
  for (auto &F : *M) {
    if (F.hasFnAttribute(Attribute::AttrKind::Obelix)) {
      const Attribute &FOAttr = F.getFnAttribute(Attribute::AttrKind::Obelix);
      const ObelixProperties &OP = FOAttr.getObelixProperties();

      if (OP.getState() == ObelixProperties::Marked) {
        MarkedFunctions.push_back(CG[&F]);
      }
    }
  }

  // Visit all marked functions
  int CloneSuffixCounter = 0;
  std::map<std::string, Function *> FunctionNameMap; // For stack frame size estimation
  std::vector<CallGraphNode *> PendingStackFrameInfo; // For stack frame size estimation
  SmallPtrSet<const Function *, 16> IgnoredFunctionsSet;
  for(auto *MarkedCGNode : MarkedFunctions) {

    dbgs() << "[OBELIX] Cloning \"" << MarkedCGNode->getFunction()->getName().str() << "\"\n";

    Function *NewMarked = cloneFunction(MarkedCGNode->getFunction(), "__obelix", false);
    FunctionNameMap[NewMarked->getName().str()] = NewMarked;
    CG.addToCallGraph(NewMarked);
    CallGraphNode *NewMarkedCGNode = CG[NewMarked];
    PendingStackFrameInfo.push_back(NewMarkedCGNode);

    // The functions in the queue have already been cloned, and wait for their
    // callees to be processed.
    std::vector<CallGraphNode *> Queue;
    Queue.push_back(NewMarkedCGNode);

    if(NewMarkedCGNode->size() > 0)
      ++CloneSuffixCounter;

    while(!Queue.empty()) {

      // Current child function
      CallGraphNode *CGNode = Queue.back();
      Queue.pop_back();
      Function *CurF = CGNode->getFunction();

      dbgs() << "[OBELIX]   Processing callees of  \"" << CurF->getName() << "\"\n";

      // Iterate callees of child function
      SmallVector<CallGraphNode::CallRecord, 8> CGNodeCallees(CGNode->begin(), CGNode->end());
      for(auto &CalleeCGInfo : CGNodeCallees) {

        auto *CalleeCGNode = CalleeCGInfo.second;
        auto *Callee = CalleeCGNode->getFunction();

        if(Callee == nullptr) {

          // Try to extract associated call instructions
          auto CalleeCallInfo = CalleeCGInfo.first;
          if(CalleeCallInfo.has_value() && CalleeCallInfo.value().pointsToAliveValue()) {
            Value *CalleeCallValue = CalleeCallInfo.value();
            if(CallBase *CalleeCallInst = dyn_cast<CallBase>(CalleeCallValue)) {
              if(CalleeCallInst->isInlineAsm()) {
                // Skip inline assembly
                continue;
              }
            }
          }

          dbgs() << "[OBELIX]     WARNING: Encountered nullptr callee. Probably an indirect call\n";
          continue;
        }

        Function *ToClone = Callee;
        if(Callee->isIntrinsic()) {

          switch(Callee->getIntrinsicID()) {
            // Ignore certain intrinsics that won't be translated to function calls
          case Intrinsic::lifetime_start:
          case Intrinsic::lifetime_end:
          case Intrinsic::fshl:
          case Intrinsic::bswap:
          case Intrinsic::abs:
          case Intrinsic::umin:
          case Intrinsic::umax:
          case Intrinsic::ctlz:
          case Intrinsic::cttz:
          case Intrinsic::umul_with_overflow:
            IgnoredFunctionsSet.insert(Callee);
            continue;

            // Replace others by our custom implementations
          case Intrinsic::memset:
            ToClone = M->getFunction("_obelix_memset_intrinsic");
            break;
          case Intrinsic::memcpy:
            ToClone = M->getFunction("_obelix_memcpy_intrinsic");
            break;

          default:
            dbgs() << "[OBELIX]     Encountered intrinsic callee \"" << Callee->getName() << "\", which cannot be instrumented\n";
            llvm_unreachable("Unexpected intrinsic");
          }
        }

        // Replace external functions by our custom ones, as we cannot instrument
        // them otherwise
        if(Callee->isDeclaration() && !Callee->isIntrinsic()) {

          // Do we have a custom definition for that function?
          std::string CustomExternalName = "_obelix_" + Callee->getName().str();
          Function *CustomExternal = M->getFunction(CustomExternalName);
          if(CustomExternal == nullptr) {
            dbgs() << "[OBELIX]     Encountered declaration-only callee \"" << Callee->getName() << "\", probably an external function?\n";
            llvm_unreachable("Undefined child function");
          }

          ToClone = CustomExternal;
        }

        // Did we already process that callee elsewhere?
        std::string ClonedNameSuffix = "__obelix_" + std::to_string(CloneSuffixCounter);
        Function *Cloned = M->getFunction(ToClone->getName().str() + ClonedNameSuffix);
        bool AlreadyProcessed = Cloned != nullptr;

        // Clone
        if(!AlreadyProcessed) {
          dbgs() << "[OBELIX]     Cloning child \"" << ToClone->getName() << "\"\n";
          Cloned = cloneFunction(ToClone, ClonedNameSuffix, true);
          Cloned->ObelixParent = NewMarked;
          FunctionNameMap[Cloned->getName().str()] = Cloned;
          CG.addToCallGraph(Cloned);
        }
        CallGraphNode *ClonedCGNode = CG[Cloned];

        // Rewrite all calls to current callee
        for (BasicBlock *BB = &CurF->front(); BB != nullptr; BB = BB->getNextNode()) {
          for (Instruction *I = &BB->front(); I != nullptr; I = I->getNextNode()) {

            CallInst *CI = dyn_cast<CallInst>(I);
            if (CI == nullptr || CI->getCalledFunction() != Callee)
              continue;

            // Replace call target
            if(CI->getIntrinsicID() != Intrinsic::not_intrinsic) {
              switch(CI->getIntrinsicID()) {
              case Intrinsic::memset:
              case Intrinsic::memcpy:
                CI->setCalledFunction(Cloned);
                break;

              default:
                dbgs() << "[OBELIX]     Cannot translate call to \"" << Callee->getName() << "\"\n";
                llvm_unreachable("Unhandled intrinsic");
              }
            }
            else {
              CI->setCalledFunction(Cloned);
            }
            NewMarked->ObelixCalledFunctions.insert(Cloned);

            CGNode->replaceCallEdge(*CI, *CI, ClonedCGNode);
          }
        }

        // Enqueue this callee
        if(!AlreadyProcessed)
          Queue.push_back(ClonedCGNode);
      }
    }
  }

  // In stage 2, we compute the total call tree stack frame size as seen from
  // the parent function
  if(ObelixBuildStage == 2) {

    std::string StackFrameInfoFileName = ObelixBuildFiles::getBuildFileName("__StackFrameInfo__");
    std::ifstream StackFrameInfoFileStream(StackFrameInfoFileName);

    if (StackFrameInfoFileStream.bad()) {
      errs() << "Can not open stack frame info file \"" << StackFrameInfoFileName << "\"\n";
      report_fatal_error("Can not open stack frame info file");
    }

    DenseMap<const Function *, uint64_t> StackFrameSizes;
    while(!StackFrameInfoFileStream.eof()) {

      std::string FuncName;
      uint64_t FuncStackSize;

      StackFrameInfoFileStream >> FuncName;
      if(StackFrameInfoFileStream.eof() || FuncName.empty())
        break;

      StackFrameInfoFileStream >> FuncStackSize;

      const auto &FuncMapIt = FunctionNameMap.find(FuncName);
      if(FuncMapIt == FunctionNameMap.end())
      {
        dbgs() << "Could not find stack frame info entry for '" << FuncName << "'\n";
        report_fatal_error("Could not find stack frame info entry");
      }

      StackFrameSizes[FuncMapIt->second] = FuncStackSize;
    }

    // Assign stack frame size to each top-level parent
    SmallPtrSet<const CallGraphNode *, 16> VisitedNodes;
    for(auto *CGNode : PendingStackFrameInfo) {
      if(CGNode->getFunction() == nullptr
        || IgnoredFunctionsSet.contains(CGNode->getFunction()))
        continue;

      CGNode->getFunction()->ObelixStackSize =
          computeStackFrameSize(0, CGNode, StackFrameSizes, IgnoredFunctionsSet, VisitedNodes);
    }

    assert(VisitedNodes.empty() && "Visited nodes set should be empty");
  }

  return PreservedAnalyses::all();
}