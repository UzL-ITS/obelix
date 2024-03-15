#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_OBELIXCALLGRAPHTRAVERSAL_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_OBELIXCALLGRAPHTRAVERSAL_H

#include "llvm/IR/PassManager.h"

namespace llvm {

class Module;

/// Pass that traverses the call graph and marks all functions that need Obelix
/// instrumentation.
class ObelixCallGraphTraversalPass :
    public PassInfoMixin<ObelixCallGraphTraversalPass> {

  Module *M;

public:
  ObelixCallGraphTraversalPass();

  Function *cloneFunction(Function *F, const std::string &NameSuffix, bool IsAutoCopy);

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);

  static bool isRequired() { return true; }
};

} // namespace llvm


#endif