#ifndef LLVM_SUPPORT_OBELIXCOMMANDLINEFLAGS_H
#define LLVM_SUPPORT_OBELIXCOMMANDLINEFLAGS_H

#include "llvm/Support/CommandLine.h"

enum class ObelixFeatureLevels {
  ObfuscuroFixedLoadStore,
  Base,
  FixedPattern,
  UniformBlocks,
  CiphertextProtection
};

extern llvm::cl::opt<ObelixFeatureLevels> ObelixFeatureLevel;

extern llvm::cl::opt<int> ObelixBuildStage;

#endif