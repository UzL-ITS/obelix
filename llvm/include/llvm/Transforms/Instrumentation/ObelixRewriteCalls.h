#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_OBELIXREWRITECALLS_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_OBELIXREWRITECALLS_H

#include "llvm/IR/PassManager.h"

namespace llvm {

/// Pass for rewriting calls to Obelix-protected functions.
class ObelixRewriteCallsPass : public PassInfoMixin<ObelixRewriteCallsPass> {

public:
  ObelixRewriteCallsPass();

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }

private:
  // Current module.
  Module *M;

  // Functions residing in compiler-rt, called by the instrumentation
  FunctionCallee ObelixRtAddInitData;

  void initializeRtFuncs(Function &F);
};

} // namespace llvm

#endif // LLVM_TRANSFORMS_INSTRUMENTATION_OBELIXREWRITECALLS_H
