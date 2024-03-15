
#include "llvm/Support/ObelixBuildFiles.h"

using namespace llvm;

static std::string BuildDirectoryName = "/tmp/obelix";

bool llvm::ObelixBuildFiles::createBuildDirectory() {

  // Create new directory
  std::error_code Err = sys::fs::create_directory(BuildDirectoryName);
  if(Err) {
    errs() << "Can not create build directory: " << Err.message() << " (" << Err.value() << ")\n";
    return false;
  }

  return true;
}

bool llvm::ObelixBuildFiles::buildDirectoryExists() {

  std::error_code Err;
  return sys::fs::is_directory(BuildDirectoryName);
}

std::string llvm::ObelixBuildFiles::getBuildFileName(const std::string &FunctionName) {

  return BuildDirectoryName + "/" + FunctionName;
}