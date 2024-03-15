


#include "llvm/Support/FileSystem.h"


namespace llvm::ObelixBuildFiles {

/// Ensures that the build directory exists.
bool createBuildDirectory();

/// Checks whether the build directory exists.
bool buildDirectoryExists();

/// Returns a build file path for the given function name.
std::string getBuildFileName(const std::string &FunctionName);

} // namespace llvm::ObelixBuildFiles
