cmake_minimum_required(VERSION 3.20)
project(Mortis
    VERSION 0.1.0
    DESCRIPTION "Modern C++ cross-platform reverse engineering framework"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)

option(MORTIS_BUILD_TESTS    "Build unit tests (GTest)" ON)
option(MORTIS_BUILD_EXAMPLES "Build example programs"   ON)
option(MORTIS_ENABLE_SANITIZERS "Enable ASAN and UBSAN" OFF)

FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone
    GIT_TAG v6
    EXCLUDE_FROM_ALL
)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_SYSTEMZ_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_M68K_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_MIPS_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_PPC_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_SPARC_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_XCORE_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_TMS320C64X_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_M680X_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_EVM_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_MOS65XX_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_WASM_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BPF_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_RISCV_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_SH_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_TRICORE_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ALPHA_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_HPPA_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_LOONGARCH_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_XTENSA_SUPPORT OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(capstone)

# Silence third-party warnings from capstone.
if(TARGET capstone)
    if(MSVC)
        # Remove capstone's own /W1 before setting /W0
        get_target_property(_cs_opts capstone COMPILE_OPTIONS)
        if(_cs_opts)
            list(FILTER _cs_opts EXCLUDE REGEX "/[Ww][0-4]")
            set_target_properties(capstone PROPERTIES COMPILE_OPTIONS "${_cs_opts}")
        endif()
        target_compile_options(capstone PRIVATE /W0)
    else()
        target_compile_options(capstone PRIVATE -w)
    endif()
endif()

FetchContent_Declare(
    libhat
    GIT_REPOSITORY https://github.com/BasedInc/libhat.git
    GIT_TAG v0.9.0
)
FetchContent_MakeAvailable(libhat)

if(MORTIS_BUILD_TESTS)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.15.2
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(gtest_disable_pthreads ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND MSVC)
        foreach(_gt_target gtest gtest_main gmock gmock_main)
            if(TARGET ${_gt_target})
                target_compile_options(${_gt_target} PRIVATE -Wno-character-conversion)
            endif()
        endforeach()
    endif()
endif()

set(MORTIS_SOURCES
    src/Core/Process.cpp
    src/Core/MemoryScanner.cpp
    src/Hook/HookBackendCapstone.cpp
    src/Hook/Disassembler.cpp
    src/Hook/TrampolineAllocator.cpp
    src/Hook/CodePatcher.cpp
)

if(CMAKE_CXX_COMPILER_ARCHITECTURE_ID)
    set(_mortis_target_arch "${CMAKE_CXX_COMPILER_ARCHITECTURE_ID}")
else()
    set(_mortis_target_arch "${CMAKE_SYSTEM_PROCESSOR}")
endif()
message(STATUS "Mortis target architecture: ${_mortis_target_arch}")

if(_mortis_target_arch MATCHES "x64|X64|AMD64|x86_64")
    set(MORTIS_ARCH "X64")
    list(APPEND MORTIS_SOURCES
        src/Arch/X64/DisassemblerX64.cpp
        src/Arch/X64/InstructionRelocatorX64.cpp
        src/Arch/X64/TrampolineWriterX64.cpp
    )
elseif(_mortis_target_arch MATCHES "ARM64|aarch64")
    set(MORTIS_ARCH "ARM64")
    list(APPEND MORTIS_SOURCES
        src/Arch/ARM64/DisassemblerARM64.cpp
        src/Arch/ARM64/InstructionRelocatorARM64.cpp
        src/Arch/ARM64/TrampolineWriterARM64.cpp
    )
else()
    message(FATAL_ERROR "Unsupported target architecture: ${_mortis_target_arch}")
endif()

if(WIN32)
    set(MORTIS_OS "WINDOWS")
    list(APPEND MORTIS_SOURCES
        src/Platform/Win32/ProcessWin32.cpp
        src/Platform/Win32/InjectWin32.cpp
        src/Platform/Win32/ImportHookWin32.cpp
        src/Platform/Win32/ThreadFreezerWin32.cpp
    )
else()
    set(MORTIS_OS "LINUX")
    list(APPEND MORTIS_SOURCES
        src/Platform/Linux/ProcessLinux.cpp
        src/Platform/Linux/ImportHookLinux.cpp
        src/Platform/Linux/ThreadFreezerLinux.cpp
    )
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" OR (CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND MSVC))
    set(MORTIS_COMPILER "MSVC")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(MORTIS_COMPILER "CLANG")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(MORTIS_COMPILER "GCC")
else()
    set(MORTIS_COMPILER "UNKNOWN")
endif()

add_library(Mortis STATIC ${MORTIS_SOURCES})

target_compile_definitions(Mortis PUBLIC
    MORTIS_ARCH_${MORTIS_ARCH}=1
    MORTIS_OS_${MORTIS_OS}=1
    MORTIS_COMPILER_${MORTIS_COMPILER}=1
)

target_include_directories(Mortis PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(Mortis PUBLIC cxx_std_23)
target_link_libraries(Mortis PRIVATE capstone)

if(WIN32)
    target_link_libraries(Mortis PRIVATE Psapi)
else()
    target_link_libraries(Mortis PRIVATE dl)
endif()

target_link_libraries(Mortis PRIVATE libhat::libhat)

if(MORTIS_ENABLE_SANITIZERS)
    set(SANITIZER_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
    target_compile_options(Mortis PUBLIC ${SANITIZER_FLAGS})
    target_link_options(Mortis PUBLIC ${SANITIZER_FLAGS})
endif()

if(MSVC)
    target_compile_options(Mortis PRIVATE /W4)
else()
    target_compile_options(Mortis PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(MORTIS_BUILD_TESTS)
    enable_testing()

    set(TEST_SOURCES
        tests/TestHelpers.cpp
        tests/TestCore.cpp
        tests/TestProcess.cpp
        tests/TestMemory.cpp
        tests/TestInlineHook.cpp
        tests/TestMemoryScanner.cpp
        tests/TestHookRobustness.cpp
    )
    if(WIN32)
        list(APPEND TEST_SOURCES
            tests/TestImportHook.cpp
            tests/TestInject.cpp
        )
    endif()

    add_executable(MortisTests ${TEST_SOURCES})
    target_link_libraries(MortisTests PRIVATE Mortis GTest::gtest_main)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND MSVC)
        target_compile_options(MortisTests PRIVATE -Wno-character-conversion)
    endif()
    if(WIN32)
        add_executable(MortisInjectionTarget tests/InjectionTarget.cpp)
        target_compile_features(MortisInjectionTarget PRIVATE cxx_std_23)

        add_library(MortisInjectionDll SHARED
            tests/InjectionDll.cpp
            tests/InjectionDll.def
        )
        target_link_libraries(MortisInjectionDll PRIVATE Mortis)
        target_compile_features(MortisInjectionDll PRIVATE cxx_std_23)

        add_dependencies(MortisTests MortisInjectionTarget MortisInjectionDll)
    endif()
    include(GoogleTest)
    gtest_discover_tests(MortisTests)
endif()

include(GNUInstallDirs)

install(TARGETS Mortis
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/Mortis
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
