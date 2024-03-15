
#include "llvm/Support/ObelixCommandLineFlags.h"

using namespace llvm;

cl::opt<ObelixFeatureLevels> ObelixFeatureLevel(
    "fobelix-level",
    cl::desc("Choose Obelix feature level (higher is more secure):"),
    cl::value_desc("level"),
    cl::values(
        clEnumValN(ObelixFeatureLevels::ObfuscuroFixedLoadStore, "10", "Obfuscuro baseline with one load+store at block begin"),
        clEnumValN(ObelixFeatureLevels::Base, "20", "Fixed number of instructions per block"),
        clEnumValN(ObelixFeatureLevels::FixedPattern, "30", "Fixed instruction latency pattern per block"),
        clEnumValN(ObelixFeatureLevels::UniformBlocks, "40", "Instructions all aligned at 0x8"),
        clEnumValN(ObelixFeatureLevels::CiphertextProtection, "50", "Ciphertext side-channel protection")
    ),
    cl::init(ObelixFeatureLevels::UniformBlocks)
    );

cl::opt<int> ObelixBuildStage(
    "fobelix-stage",
    cl::desc("Specify the Obelix build stage"),
    cl::value_desc("stage"),
    cl::init(1)
    );