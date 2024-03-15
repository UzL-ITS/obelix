
#include "llvm/ADT/ScopeExit.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ObelixCommandLineFlags.h"
#include "llvm/Support/ObelixProperties.h"
#include "llvm/Transforms/Instrumentation/ObelixRewriteCalls.h"
#include "llvm/Transforms/Utils/Cloning.h"

using namespace llvm;


ObelixRewriteCallsPass::ObelixRewriteCallsPass() {}

void ObelixRewriteCallsPass::initializeRtFuncs(Function &F) {

  // Install runtime functions in module
  auto &Ctx = M->getContext();

  ObelixRtAddInitData = M->getOrInsertFunction("__obelix_add_init_data",
                                               Type::getVoidTy(Ctx),
                                               Type::getInt64Ty(Ctx),
                                               Type::getInt64Ty(Ctx));
}

PreservedAnalyses ObelixRewriteCallsPass::run(Function &F,
                                              FunctionAnalysisManager &AM) {

  M = F.getParent();
  LLVMContext &Ctx = M->getContext();

  initializeRtFuncs(F);

  // Rewrite all functions that call instrumented functions.
  // Everything else is taken care of in the call graph traversal pass.
  if (F.hasFnAttribute(Attribute::AttrKind::Obelix)) {
    return PreservedAnalyses::all();
  }

  // Handle all relevant instructions
  for (BasicBlock *BB = &F.front(); BB != nullptr; BB = BB->getNextNode()) {
    for (Instruction *I = &BB->front(); I != nullptr; I = I->getNextNode()) {

      CallInst *CI = dyn_cast<CallInst>(I);
      if (CI == nullptr)
        continue;

      Function *Callee = CI->getCalledFunction();
      if (Callee == nullptr)
        continue;

      // Is the called function annotated for protection?
      // If not, no change needed
      if (!Callee->hasFnAttribute(Attribute::AttrKind::Obelix))
        continue;

      const Attribute &CalleeOAttr = Callee->getFnAttribute(Attribute::AttrKind::Obelix);
      ObelixProperties::State CalleeState = CalleeOAttr.getObelixProperties().getState();

      assert(CalleeState != ObelixProperties::AutoCopy && "Callee has impossible state attribute value");

      // If we already call a transformed function (i.e., the name was rewritten),
      // we don't need to touch this call. Probably it was edited in an earlier application
      // of this pass
      if (CalleeState == ObelixProperties::Copy)
        continue;

      dbgs() << "[OBELIX] Editing call " << F.getName() << " -> " << Callee->getName() << "\n";

      // If this is a call within the same compile unit, rewrite the name of the called function.
      // For everything else, we rely on the user using the right name at the moment.
      // TODO make this more convenient and robust
      if (CalleeState != ObelixProperties::State::Extern) {
        std::string TransformedCalleeName = Callee->getName().str() + "__obelix";

        Function *TransformedCallee = M->getFunction(TransformedCalleeName);
        if (TransformedCallee == nullptr)
          llvm_unreachable("Cannot find transformed equivalent");

        CI->setCalledFunction(TransformedCallee);
      }

      // Register potential pointer arguments in data ORAM
      // TODO take this information from a (not yet existing) analysis pass

      IRBuilder<> Builder(I);
      Type *UInt64Type = Type::getInt64Ty(M->getContext());

      // Extract arguments
      auto *CIF = CI->getCalledFunction();
      assert(CIF->arg_size() == CI->arg_size());
      for (unsigned int i = 0; i < CI->arg_size(); ++i) {
        auto *Arg = CI->getArgOperand(i);

        // We only handle pointer arguments
        if (!Arg->getType()->isPointerTy())
          continue;

        // Unwrap constant expressions
        bool UnwrappedConstantExpr = false;
        auto CleanupUnwrappedConstantExpr =
            llvm::make_scope_exit([&]() {
              if(UnwrappedConstantExpr) {
                // TODO This is broken and throws an error
                Arg->deleteValue();
              }
            });
        if (ConstantExpr *ArgCE = dyn_cast<ConstantExpr>(Arg)) {
          /*if(ArgCE->getOpcode() == Instruction::GetElementPtr) {
            Arg = ArgCE->getAsInstruction();
            UnwrappedConstantExpr = true;
          }
          else {*/
            dbgs() << "[OBELIX]  Detected constant expression argument, but could not unwrap\n";
          //}
        }

        // Handle different types
        if (AllocaInst *ArgAllocInst = dyn_cast<AllocaInst>(Arg)) {

          // Stack allocation

          // Determine allocation size
          // Adapted from AllocaInst::getAllocationSize
          Value *ArgAllocSize = nullptr;
          uint64_t ArgAllocTypeSize = M->getDataLayout().getTypeAllocSize(ArgAllocInst->getAllocatedType()).getKnownMinValue();
          if (ArgAllocInst->isArrayAllocation()) {
            if (ConstantInt *ArgAllocFixedArraySize = dyn_cast<ConstantInt>(ArgAllocInst->getArraySize())) {
              ArgAllocSize = ConstantInt::get(
                  UInt64Type,
                  ArgAllocTypeSize * ArgAllocFixedArraySize->getZExtValue(),
                  false);
            }
          } else {
            ArgAllocSize = ConstantInt::get(UInt64Type, ArgAllocTypeSize, false);
          }

          if (!ArgAllocSize) {
            dbgs() << "[OBELIX]  Could not determine size of stack allocation argument '" << Arg->getName() << "'. Instruction:\n";
            ArgAllocInst->dump();
            continue;
          }

          // Insert into ORAM
          Value *ArgPointerInt = Builder.CreatePtrToInt(Arg, UInt64Type);
          Builder.CreateCall(ObelixRtAddInitData, {ArgPointerInt, ArgAllocSize});

        } else if(GetElementPtrInst *GEPInst = dyn_cast<GetElementPtrInst>(Arg)) {

          // getelementptr <type>, <ptr>, <array index>, <element index 1>, <element index 2>, ...

          // Result of this instruction is a pointer to a single element or an
          // array We cannot actually distinguish those, so we take the origin
          // of the element into account. If it is the first element of an
          // array, insert the whole array into the data ORAM; if it is a single
          // value, only insert the pointed at element itself.

          // Extract type
          // We can only eagerly insert types for which we know the size
          Type *SrcElemTy = GEPInst->getSourceElementType();
          Type *ResElemTy = GEPInst->getResultElementType();
          if (!SrcElemTy->isSized() || isa<ScalableVectorType>(SrcElemTy))
            continue;

          // Find out whether we are dealing with an array by extracting the
          // second last indexed element's type
          Type *PrevType = SrcElemTy;
          auto *GEPInstIdx = GEPInst->idx_begin();
          for(unsigned int o = 2; o < GEPInst->getNumOperands() - 1; ++i) {
            PrevType = GetElementPtrInst::getTypeAtIndex(SrcElemTy, *GEPInstIdx);
            if(!PrevType)
              break;

            ++GEPInstIdx;
          }

          // If we have an array, take its type
          // Trick:
          //   %ArgSizePtr = getelementptr %PrevType, null, i32 1
          //   %ArgSize = ptrtoint %PrevType to u64
          Value *ArgSizePtr;
          if(PrevType != nullptr && PrevType->isArrayTy()){
            ArgSizePtr = Builder.CreateGEP(
                PrevType,
                ConstantPointerNull::get(PointerType::get(M->getContext(), 0)),
                Builder.getInt32(1));
          }
          else {
            ArgSizePtr = Builder.CreateGEP(
                ResElemTy,
                ConstantPointerNull::get(PointerType::get(M->getContext(), 0)),
                Builder.getInt32(1));
          }
          Value *ArgSize = Builder.CreatePtrToInt(ArgSizePtr, UInt64Type);

          // Insert into ORAM
          Value *ArgPointerInt = Builder.CreatePtrToInt(Arg, UInt64Type);
          Builder.CreateCall(ObelixRtAddInitData, {ArgPointerInt, ArgSize});

        } else if(LoadInst *LI = dyn_cast<LoadInst>(Arg)) {

          dbgs() << "[OBELIX]  Unhandled 'load' argument #" << i << "\n";
          Arg->dump();

          if(LI->getType()->isOpaquePointerTy()) {
            // load ptr, ptr <ptr>
            // Ignore such loads, as we don't have any type information for them
            continue;
          }

        } else if(GlobalVariable *GV = dyn_cast<GlobalVariable>(Arg)) {

          Type *AllocType = GV->getValueType();
          uint64_t Size =  M->getDataLayout().getTypeAllocSize(AllocType);

          // Insert into ORAM
          Value *ArgAllocSize = ConstantInt::get(UInt64Type, Size, false);
          Value *ArgPointerInt = Builder.CreatePtrToInt(Arg, UInt64Type);
          Builder.CreateCall(ObelixRtAddInitData, {ArgPointerInt, ArgAllocSize});

        } else if(isa<Argument>(Arg)) {

          // Opaque pointer argument passed through from the caller, we don't
          // have any type information

          dbgs() << "[OBELIX]  Unhandled opaque pointer function argument #" << i << "\n";
          Arg->dump();

        } else if(isa<ConstantPointerNull>(Arg)) {

          // Ignore null pointers

        } else {
          dbgs() << "[OBELIX]  Unhandled argument #" << i << "\n";
          Arg->dump();
        }
      }
    }
  }

  return PreservedAnalyses::none(); // TODO
}

raw_ostream &llvm::operator<<(raw_ostream &OS, const ObelixProperties &OP) {
  OS << "State: " << ObelixProperties::getStateString(OP.getState());
  return OS;
}
