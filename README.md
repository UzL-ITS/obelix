# Obelix: Mitigating Side-Channels Through Dynamic Obfuscation
This repository contains the proof-of-concept implementation of the Obelix software hardening framework, to appear at IEEE S&P 2024.

Obelix works as follows: When linking a library, the LLVM compiler extension scans for `clang::obelix` attributes. All such annotated functions are copied and then traversed to propagate the attribute to their callees, which are copied as well, recursively ([ObelixCallGraphTraversal](llvm/lib/Transforms/Instrumentation/ObelixCallGraphTraversal.cpp) pass). A machine pass builds instruction profiles for the annotated functions ([X86ObelixCodeAnalysis](llvm/lib/Target/X86/X86ObelixCodeAnalysis.cpp) pass). The compiler then needs a second invocation, which loads the latency profiles from the first invocation and builds code block patterns for each call tree ([ObelixGeneratePattern](llvm/lib/Transforms/Instrumentation/ObelixGeneratePattern.cpp) pass). Finally, the machine code is split into uniform code blocks ([X86ObelixCodeSplitPass](llvm/lib/Target/X86/X86ObelixCodeSplitPass.cpp) pass) and linked against the [Obelix runtime](compiler-rt/lib/obelix/)). Calls to Obelix-protected functions are automatically adjusted by the [ObelixRewriteCalls](llvm/lib/Transforms/Instrumentation/ObelixRewriteCalls.cpp) pass.

For usage examples, check out the [examples/small/](examples/small/) directory, which contains two minimal examples. In the following, we outline the steps needed for compiling Obelix and applying it to the minimal examples.

## Building the compiler
The [instructions for building LLVM](https://llvm.org/docs/GettingStarted.html#getting-the-source-code-and-building-llvm) apply. In the following, we give the commands which we used on our test machine (Ubuntu 22.04, CMake 3.22.1 with Ccache, Ninja 1.10.1, GCC 11.4.0).

Setup build system:
```bash
mkdir obelix-build
cmake llvm/ \
    -B obelix-build \
    -G Ninja \
    -DLLVM_ENABLE_PROJECTS="clang;lld;compiler-rt" \
    -DLLVM_TARGETS_TO_BUILD=X86 \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_ASSERTIONS=true \
    -DLLVM_CCACHE_BUILD=true \
    -DLLVM_USE_LINKER=lld \
    -DBUILD_SHARED_LIBS=true \
    -DCOMPILER_RT_BUILD_LIBFUZZER=false
```

Build:
```
cmake --build obelix-build -j
```


## Compiling the small examples
After the compiler was successfully built, the examples can be compiled simply through
```
cd examples/small/
make all
```

This will build all Obelix variants. You can test them by calling (for example)
```
LD_LIBRARY_PATH=./bin bin/matmul-40
```
Expected output (annotated with explanations):
```
Time:         2 ms ->     0.026 us / round      <-- Original runtime
Result:                                         <-- Original result
10 10 10 10 
20 20 20 20 
30 30 30 30 
40 40 40 40 

-------------------------
Time:      1512 ms ->    15.130 us / round      <-- Protected runtime
  ---> Overhead: 592.9                          <-- Multiplicative overhead
100000 2552 1512979 592.9                       <-- Encoded measurement results
Result:                                         <-- Protected result
10 10 10 10 
20 20 20 20 
30 30 30 30 
40 40 40 40 
```

## Paper
For an extended description of the framework, please refer to our paper:

Jan Wichelmann, Anja Rabich, Anna Pätschke and Thomas Eisenbarth. 2024. **Obelix: Mitigating Side-Channels Through Dynamic Obfuscation.** In 2024 IEEE Symposium on Security and Privacy (S&P '24). \[[Link](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a189/1WPcYic94rK)\] \[[DOI](https://doi.ieeecomputersociety.org/10.1109/SP54263.2024.00182)\]

## License
The project is based on LLVM and subject to the same [license](LICENSE.TXT).
