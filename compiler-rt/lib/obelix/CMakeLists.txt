add_compiler_rt_component(obelix)

set(OBELIX_SOURCES
        obelix.cpp
        controller.S
        #data_oram.S
        code_oram_linear_naive.S
        code_oram_linear.cpp
        #code_oram_path_obfuscuro.cpp
        #code_oram_path_obfuscuro_asm.cpp
        code_oram_path_c.cpp
        data_oram_linear.cpp
        )

include_directories(..)

set(OBELIX_CFLAGS ${SANITIZER_COMMON_CFLAGS} -masm=intel -march=znver3 -mprefer-vector-width=256)

foreach (arch ${OBELIX_SUPPORTED_ARCH})
    add_compiler_rt_runtime(clang_rt.obelix
            STATIC
            ARCHS ${arch}
            SOURCES ${OBELIX_SOURCES}
            $<TARGET_OBJECTS:RTSanitizerCommon.${arch}>
            $<TARGET_OBJECTS:RTSanitizerCommonLibc.${arch}>
            CFLAGS ${OBELIX_CFLAGS}
            PARENT_TARGET obelix)
endforeach ()
