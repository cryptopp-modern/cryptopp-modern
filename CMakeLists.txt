# ===-----------------------------------------------------------------------===#
# Distributed under the 3-Clause BSD License. See accompanying file LICENSE or
# copy at https://opensource.org/licenses/BSD-3-Clause).
# SPDX-License-Identifier: BSD-3-Clause
# ===-----------------------------------------------------------------------===#

# ------------------------------------------------------------------------------
# CMake basic options
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/cmake/cmake_minimum_required.cmake)
cmake_minimum_required(VERSION ${CRYPTOPP_MINIMUM_CMAKE_VERSION})

# List of directories specifying a search path for CMake modules to be loaded by
# the include() or find_package() commands before checking the default modules
# that come with CMake.
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# ------------------------------------------------------------------------------
# Project description and (meta) information
# ------------------------------------------------------------------------------

# Get git revision
include(GetGitRevisionDescription)
get_git_head_revision(GIT_REFSPEC GIT_SHA1)
string(SUBSTRING "${GIT_SHA1}" 0 12 GIT_REV)
if(NOT GIT_SHA1)
    set(GIT_REV "0")
endif()

set(META_PROJECT_NAME "cryptopp-modern")
set(META_PROJECT_DESCRIPTION "Modern C++ cryptography library - fork of Crypto++")
set(META_GITHUB_REPO "https://github.com/cryptopp-modern/cryptopp-modern")
set(META_VERSION_MAJOR "2025")
set(META_VERSION_MINOR "12")
set(META_VERSION_PATCH "0")
set(META_VERSION_REVISION "${GIT_REV}")
set(META_VERSION
    "${META_VERSION_MAJOR}.${META_VERSION_MINOR}.${META_VERSION_PATCH}"
)
set(META_NAME_VERSION
    "${META_PROJECT_NAME} v${META_VERSION} (${META_VERSION_REVISION})"
)

# ------------------------------------------------------------------------------
# Project Declaration
# ------------------------------------------------------------------------------

project(
    "${META_PROJECT_NAME}"
    VERSION "${META_VERSION}"
    DESCRIPTION "${META_PROJECT_DESCRIPTION}"
    HOMEPAGE_URL "${META_GITHUB_REPO}"
    LANGUAGES CXX C ASM
)

message(STATUS "=> Project : ${PROJECT_NAME} v${cryptopp-modern_VERSION}")

# ============================================================================
# Settable options
# ============================================================================

option(
    CRYPTOPP_USE_INTERMEDIATE_OBJECTS_TARGET
    "Use a common intermediate objects target for the static and shared library targets"
    ON
)

if(CRYPTOPP_INCLUDE_PREFIX)
    set(CRYPTOPP_INCLUDE_PREFIX
        ${CRYPTOPP_INCLUDE_PREFIX}
        CACHE STRING
        "Set the dir where the headers get installed. Defaults to cryptopp."
    )
else()
    set(CRYPTOPP_INCLUDE_PREFIX
        "cryptopp"
        CACHE STRING
        "Set the dir where the headers get installed. Defaults to cryptopp."
    )
endif()

option(CRYPTOPP_USE_OPENMP
    "Enable OpenMP to parallelize some of the algorithms. Note that this isn't always faster, see https://www.cryptopp.com/wiki/OpenMP"
    OFF
)

# IA-32 options
option(CRYPTOPP_DISABLE_ASM "Disable ASM" OFF)
option(CRYPTOPP_DISABLE_SSSE3 "Disable SSSE3" OFF)
option(CRYPTOPP_DISABLE_SSE4 "Disable SSE4" OFF)
option(CRYPTOPP_DISABLE_AESNI "Disable AES-NI" OFF)
option(CRYPTOPP_DISABLE_CLMUL "Disable CLMUL" OFF)
option(CRYPTOPP_DISABLE_SHA "Disable SHA" OFF)
option(CRYPTOPP_DISABLE_AVX "Disable AVX" OFF)
option(CRYPTOPP_DISABLE_AVX2 "Disable AVX2" OFF)

# ARM A-32 options
option(CRYPTOPP_DISABLE_ARM_NEON "Disable NEON" OFF)

# Aarch64 options
option(CRYPTOPP_DISABLE_ARM_AES "Disable ARM AES" OFF)
option(CRYPTOPP_DISABLE_ARM_PMULL "Disable ARM PMULL" OFF)
option(CRYPTOPP_DISABLE_ARM_SHA "Disable ARM SHA" OFF)

# PowerPC options
option(CRYPTOPP_DISABLE_ALTIVEC "Disable Altivec" OFF)
option(CRYPTOPP_DISABLE_POWER7 "Disable POWER7" OFF)
option(CRYPTOPP_DISABLE_POWER8 "Disable POWER8" OFF)
option(CRYPTOPP_DISABLE_POWER9 "Disable POWER9" OFF)

option(CRYPTOPP_BUILD_TESTING "Build library tests" ON)

# Override the CRYPTOPP_INSTALL option to ON/OFF to respectively force
# install/no-install behavior for cryptopp module.
option(CRYPTOPP_INSTALL "Generate the install target for this project." ON)

# Crypto++ DOES NOT properly support DLL builds. The old DLL was the FIPS one,
# which is being abandoned. Therefore, we only allow static builds.
option(CRYPTOPP_BUILD_SHARED "Build shared library" OFF)
if(${CRYPTOPP_BUILD_SHARED})
    message(
        FATAL_ERROR
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        "Crypto++ DOES NOT properly support DLL builds. The old DLL was the FIPS "
        "one which is being abandoned.\nTherefore, we only allow static builds "
        "until that situation changes.\n"
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
    )
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/.git")
    set(CRYPTOPP_DEFAULT_BUILD_TYPE "Debug")
else()
    set(CRYPTOPP_DEFAULT_BUILD_TYPE "Release")
endif()

# Set the possible values of build type for cmake-gui
if(CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_CONFIGURATION_TYPES
        "Debug;Release"
        CACHE STRING
        "Semicolon separated list of supported configuration types"
        FORCE
    )
    set_property(
        CACHE CMAKE_CONFIGURATION_TYPES
        PROPERTY STRINGS "Debug" "Release"
    )
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(
        STATUS
        "Setting build type to '${CRYPTOPP_DEFAULT_BUILD_TYPE}' as none was specified."
    )
    set(CMAKE_BUILD_TYPE
        "${CRYPTOPP_DEFAULT_BUILD_TYPE}"
        CACHE STRING
        "Choose the type of build."
        FORCE
    )
endif()

# ------------------------------------------------------------------------------
# Testing
# ------------------------------------------------------------------------------

if(CRYPTOPP_BUILD_TESTING)
    enable_testing()
endif()

# ------------------------------------------------------------------------------
# Build the library
# ------------------------------------------------------------------------------

# Print useful information
message(STATUS "[cryptopp-modern] CMake version ${CMAKE_VERSION}")
message(STATUS "[cryptopp-modern] System ${CMAKE_SYSTEM_NAME}")
message(STATUS "[cryptopp-modern] Processor ${CMAKE_SYSTEM_PROCESSOR}")

# Source directory for crypto++ sources (this repo has them in-tree)
set(cryptopp_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Make RelWithDebInfo the default if not in multi-configuration environments
if(
    NOT CMAKE_CONFIGURATION_TYPES
    AND NOT CMAKE_NO_BUILD_TYPE
    AND NOT CMAKE_BUILD_TYPE
    AND NOT CMAKE_CXX_FLAGS
    AND CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR
)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

include(CheckCXXCompilerFlag)

# Test programs directory
set(TEST_PROG_DIR ${cryptopp_SOURCE_DIR}/TestPrograms)
set(TEST_CXX_FILE ${TEST_PROG_DIR}/test_cxx.cpp)

# https://github.com/noloader/cryptopp-cmake/issues/56
if(CMAKE_GENERATOR STREQUAL Xcode)
    set(CRYPTOPP_USE_INTERMEDIATE_OBJECTS_TARGET OFF)
endif()

# ============================================================================
# Compiler options
# ============================================================================

# Enable PIC for all target machines except 32-bit i386
if(NOT CRYPTOPP_I386)
    set(CMAKE_POSITION_INDEPENDENT_CODE 1)
endif()

set(CRYPTOPP_COMPILE_DEFINITIONS)
set(CRYPTOPP_COMPILE_OPTIONS)

if(CMAKE_CXX_COMPILER_ID MATCHES "Intel")
    list(
        APPEND
        CRYPTOPP_COMPILE_OPTIONS
        -wd68
        -wd186
        -wd279
        -wd327
        -wd161
        -wd3180
    )
endif()

# Reflect any requests to disable features into the CXX compile definitions
foreach(
    feature
    ASM
    SSSE3
    SSE4
    CLMUL
    AESNI
    RDRAND
    RDSEED
    AVX
    AVX2
    SHA
    ARM_NEON
    ARM_ASIMD
    ARM_AES
    ARM_PMULL
    ARM_SHA
    ALTIVEC
    POWER7
    POWER8
    POWER9
)
    if(${CRYPTOPP_DISABLE_${feature}})
        message(
            STATUS
            "[cryptopp-modern] -!!- CRYPTOPP_DISABLE_${feature}=${CRYPTOPP_DISABLE_${feature}}"
        )
        list(
            APPEND
            CRYPTOPP_COMPILE_DEFINITIONS
            "CRYPTOPP_DISABLE_${feature}=1"
        )
    endif()
endforeach()

# ##############################################################################

# Try to find a Posix compatible grep and sed
if(EXISTS /usr/xpg4/bin/grep)
    set(GREP_CMD /usr/xpg4/bin/grep)
elseif(EXISTS /usr/gnu/bin/grep)
    set(GREP_CMD /usr/gnu/bin/grep)
elseif(EXISTS /usr/linux/bin/grep)
    set(GREP_CMD /usr/linux/bin/grep)
else()
    set(GREP_CMD grep)
endif()

if(EXISTS /usr/xpg4/bin/sed)
    set(SED_CMD /usr/xpg4/bin/sed)
elseif(EXISTS /usr/gnu/bin/sed)
    set(SED_CMD /usr/gnu/bin/sed)
elseif(EXISTS /usr/linux/bin/sed)
    set(SED_CMD /usr/linux/bin/sed)
else()
    set(SED_CMD sed)
endif()

# ##############################################################################

function(check_compile_option opt var)
    if(DEFINED "${var}")
        return()
    endif()
    check_cxx_compiler_flag(${opt} ${var})
endfunction(check_compile_option)

function(check_compile_link_option opt var prog)
    if(DEFINED "${var}")
        return()
    endif()

    message(STATUS "[cryptopp-modern] Performing Test ${var}")
    set(definitions ${CRYPTOPP_COMPILE_DEFINITIONS})
    if(MSVC)
        list(APPEND definitions ${CRYPTOPP_MSVC_COMPILE_DEFINITIONS})
    endif()
    list(TRANSFORM definitions PREPEND "-D")
    list(APPEND definitions ${opt})
    try_compile(
        COMMAND_SUCCESS
        ${CMAKE_BINARY_DIR}
        ${prog}
        COMPILE_DEFINITIONS ${definitions}
    )
    if(COMMAND_SUCCESS)
        set(${var} 1 CACHE INTERNAL "Test ${var}")
        message(STATUS "[cryptopp-modern] Performing Test ${var} - Success")
    else()
        set(${var} 0 CACHE INTERNAL "Test ${var}")
        message(STATUS "[cryptopp-modern] Performing Test ${var} - Failed")
    endif()
endfunction(check_compile_link_option)

# ##############################################################################

function(check_target_architecture output pattern)
    include(TargetArch)
    target_architecture(target_arch)
    string(TOLOWER ${target_arch} target_arch)
    if("${target_arch}" MATCHES ${pattern})
        message(
            STATUS
            "[cryptopp-modern] Target architecture detected as: ${target_arch} -> ${output}"
        )
        set(${output} TRUE PARENT_SCOPE)
    else()
        set(${output} FALSE PARENT_SCOPE)
    endif()
endfunction()

if(APPLE)
    message(
        STATUS
        "[cryptopp-modern]     CMAKE_OSX_ARCHITECTURES : ${CMAKE_OSX_ARCHITECTURES}"
    )
endif()
message(
    STATUS
    "[cryptopp-modern] CMAKE_HOST_SYSTEM_PROCESSOR : ${CMAKE_HOST_SYSTEM_PROCESSOR}"
)
message(
    STATUS
    "[cryptopp-modern]      CMAKE_SYSTEM_PROCESSOR : ${CMAKE_SYSTEM_PROCESSOR}"
)

check_target_architecture(CRYPTOPP_AMD64 "(x86_64|amd64)")
check_target_architecture(CRYPTOPP_CYGWIN "cygwin")
check_target_architecture(CRYPTOPP_I386 "^i.86$")
check_target_architecture(CRYPTOPP_MINGW32 "^mingw32")
check_target_architecture(CRYPTOPP_MINGW64 "(w64-mingw32|mingw64)")
check_target_architecture(CRYPTOPP_ARMV8 "(armv8|arm64|aarch32|aarch64)")
check_target_architecture(CRYPTOPP_ARM32 "(^arm$|arm32|armhf|arm7l|eabihf)")
check_target_architecture(CRYPTOPP_PPC32 "^(powerpc|ppc)")
check_target_architecture(CRYPTOPP_PPC64 "^ppc64")

# Cleanup 32/64 bit
if(CRYPTOPP_AMD64)
    set(CRYPTOPP_I386 0)
endif()

if(CRYPTOPP_ARMV8)
    set(CRYPTOPP_ARM32 0)
endif()

if(CRYPTOPP_PPC64)
    set(CRYPTOPP_PPC32 0)
endif()

# ##############################################################################

# Test SunCC for a string like 'CC: Sun C++ 5.13 SunOS_i386'
if(NOT CRYPTOPP_SOLARIS AND NOT MSVC)
    execute_process(
        COMMAND sh -c "${CMAKE_CXX_COMPILER} -V 2>&1"
        COMMAND ${GREP_CMD} -i -c "SunOS"
        OUTPUT_VARIABLE CRYPTOPP_SOLARIS
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

# Test GCC for a string like 'i386-pc-solaris2.11'
if(NOT CRYPTOPP_SOLARIS AND NOT MSVC)
    execute_process(
        COMMAND sh -c "${CMAKE_CXX_COMPILER} -dumpmachine 2>&1"
        COMMAND ${GREP_CMD} -i -c "Solaris"
        OUTPUT_VARIABLE CRYPTOPP_SOLARIS
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

# Fixup PowerPC
if(CRYPTOPP_PPC32 AND CRYPTOPP_PPC64)
    unset(CRYPTOPP_PPC32)
endif()

# Fixup for xlC compiler
if(CMAKE_CXX_COMPILER MATCHES "xlC")
    message(STATUS "[cryptopp-modern] -- Fixing platform due to IBM xlC")
    set(CRYPTOPP_PPC64 1)
endif()

# DumpMachine SunCC style
if(CMAKE_CXX_COMPILER_ID STREQUAL "SunPro")
    execute_process(
        COMMAND sh -c "${CMAKE_CXX_COMPILER} -V 2>&1"
        COMMAND ${GREP_CMD} -i -c "Sparc"
        OUTPUT_VARIABLE CRYPTOPP_SPARC
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
        COMMAND sh -c "${CMAKE_CXX_COMPILER} -V 2>&1"
        COMMAND ${GREP_CMD} -i -c -E "i386|i86"
        OUTPUT_VARIABLE CRYPTOPP_I386
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
        COMMAND isainfo -k
        COMMAND ${GREP_CMD} -i -c "i386"
        OUTPUT_VARIABLE KERNEL_I386
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
        COMMAND isainfo -k
        COMMAND ${GREP_CMD} -i -c "amd64"
        OUTPUT_VARIABLE KERNEL_AMD64
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
        COMMAND isainfo -k
        COMMAND ${GREP_CMD} -i -c "Sparc"
        OUTPUT_VARIABLE KERNEL_SPARC
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
        COMMAND isainfo -k
        COMMAND ${GREP_CMD} -i -c -E "UltraSarc|Sparc64|SparcV9"
        OUTPUT_VARIABLE KERNEL_SPARC64
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

# ##############################################################################

if(MSVC)
    set(CRYPTOPP_MSVC_COMPILE_OPTIONS)
    set(CRYPTOPP_MSVC_COMPILE_DEFINITIONS)

    if(CMAKE_SYSTEM_VERSION MATCHES "10\\.0.*")
        list(APPEND CRYPTOPP_MSVC_COMPILE_DEFINITIONS "_WIN32_WINNT=0x0A00")
    endif()

    include(CheckIncludeFileCXX)
    check_include_file_cxx("winapifamily.h" HAVE_WINAPIFAMILY_H)
    if(HAVE_WINAPIFAMILY_H)
        list(APPEND CRYPTOPP_MSVC_COMPILE_OPTIONS "/FIwinapifamily.h")
    endif()

    list(APPEND CRYPTOPP_MSVC_COMPILE_OPTIONS "/GR")
    if (NOT (CMAKE_CXX_COMPILER_ID MATCHES "IntelLLVM"))
        list(APPEND CRYPTOPP_MSVC_COMPILE_OPTIONS "/MP")
    endif ()
    list(APPEND CRYPTOPP_MSVC_COMPILE_OPTIONS "/EHsc")
endif()

# IBM XLC compiler options
if(CMAKE_CXX_COMPILER MATCHES "xlC")
    check_compile_link_option("-qrtti" CRYPTOPP_PPC_RTTI "${TEST_CXX_FILE}")
    if(CRYPTOPP_PPC_RTTI)
        list(APPEND CRYPTOPP_COMPILE_OPTIONS "-qrtti")
    endif()

    check_compile_link_option("-qmaxmem=-1" CRYPTOPP_PPC_MAXMEM "${TEST_CXX_FILE}")
    if(CRYPTOPP_PPC_MAXMEM)
        list(APPEND CRYPTOPP_COMPILE_OPTIONS "-qmaxmem=-1")
    endif()

    check_compile_link_option("-qthreaded" CRYPTOPP_PPC_THREADED "${TEST_CXX_FILE}")
    if(CRYPTOPP_PPC_THREADED)
        list(APPEND CRYPTOPP_COMPILE_OPTIONS "-qthreaded")
    endif()
endif()

# Solaris specific
if(CRYPTOPP_SOLARIS)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "SunPro")
        list(APPEND CRYPTOPP_COMPILE_OPTIONS "-template=no%extdef")
    endif()

    if(
        CMAKE_CXX_COMPILER_ID STREQUAL "SunPro"
        AND (CRYPTOPP_SPARC OR CRYPTOPP_SPARC64)
    )
        list(APPEND CRYPTOPP_COMPILE_OPTIONS "-xregs=no%appl")
    endif()

    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        list(APPEND CRYPTOPP_COMPILE_OPTIONS "-Wa,--divide")
    endif()
endif()

# ------------------------------------------------------------------------------
# GCC 12+ workaround
if(
    CMAKE_SYSTEM_NAME STREQUAL "Linux"
    AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU"
    AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "12"
)
    list(APPEND CRYPTOPP_COMPILE_OPTIONS "-fno-devirtualize")
endif()
# ------------------------------------------------------------------------------

# ============================================================================
# Sources & headers
# ============================================================================

include(sources)

# ==============================================================================
# Compiler and architecture specific options
# ==============================================================================

# ##############################################################################
# X86/X32/X64 Options
# ##############################################################################

if(
    (
        CRYPTOPP_I386
        OR CRYPTOPP_AMD64
        OR CRYPTOPP_MINGW32
        OR CRYPTOPP_MINGW64
        OR CRYPTOPP_CYGWIN
    )
    AND NOT MSVC
)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "SunPro")
        set(sse2_flag "-xarch=sse2")
        set(sse3_flag "-xarch=sse3")
        set(ssse3_flag "-xarch=ssse3")
        set(sse41_flag "-xarch=sse4_1")
        set(sse42_flag "-xarch=sse4_2")
        set(clmul_flag "-xarch=aes")
        set(aesni_flag "-xarch=aes")
        set(avx_flag "-xarch=avx")
        set(avx2_flag "-xarch=avx2")
        set(shani_flag "-xarch=sha")
    else()
        set(sse2_flag "-msse2")
        set(sse3_flag "-msse3")
        set(ssse3_flag "-mssse3")
        set(sse41_flag "-msse4.1")
        set(sse42_flag "-msse4.2")
        set(clmul_flag "-mpclmul")
        set(aesni_flag "-maes")
        set(avx_flag "-mavx")
        set(avx2_flag "-mavx2")
        set(shani_flag "-msha")
    endif()

    # For Darwin and GCC, check for -Wa,-q
    if(APPLE)
        check_compile_link_option("-Wa,-q" CRYPTOPP_X86_WAQ
                                  "${TEST_PROG_DIR}/test_x86_sse2.cpp"
        )
        if(CRYPTOPP_X86_WAQ)
            list(APPEND CRYPTOPP_COMPILE_OPTIONS "-Wa,-q")
        endif()
    endif()

    check_compile_link_option(${sse2_flag} CRYPTOPP_HAVE_SSE2
                              "${TEST_PROG_DIR}/test_x86_sse2.cpp"
    )
    if(CRYPTOPP_HAVE_SSE2)
        list(APPEND CRYPTOPP_CHACHA_FLAGS "${sse2_flag}")
        list(APPEND CRYPTOPP_SUN_LDFLAGS "${sse2_flag}")

        check_compile_link_option(${sse3_flag} CRYPTOPP_HAVE_SSE3
                                  "${TEST_PROG_DIR}/test_x86_sse3.cpp"
        )
        if(NOT CRYPTOPP_HAVE_SSE3)
            set(sse3_flag "")
        endif()

        check_compile_link_option(${ssse3_flag} CRYPTOPP_HAVE_SSSE3
                                  "${TEST_PROG_DIR}/test_x86_ssse3.cpp"
        )
        if(CRYPTOPP_HAVE_SSSE3)
            list(APPEND CRYPTOPP_ARIA_FLAGS "${ssse3_flag}")
            list(APPEND CRYPTOPP_CHAM_FLAGS "${ssse3_flag}")
            list(APPEND CRYPTOPP_GCM_FLAGS "${ssse3_flag}")
            list(APPEND CRYPTOPP_KECCAK_FLAGS "${ssse3_flag}")
            list(APPEND CRYPTOPP_LEA_FLAGS "${ssse3_flag}")
            list(APPEND CRYPTOPP_LSH256_FLAGS "${ssse3_flag}")
            list(APPEND CRYPTOPP_LSH512_FLAGS "${ssse3_flag}")
            list(APPEND CRYPTOPP_SIMON128_FLAGS "${ssse3_flag}")
            list(APPEND CRYPTOPP_SM4_FLAGS "${ssse3_flag}")
            list(APPEND CRYPTOPP_SPECK128_FLAGS "${ssse3_flag}")
            list(APPEND CRYPTOPP_SUN_LDFLAGS "${ssse3_flag}")
        else()
            set(ssse3_flag "")
        endif()

        check_compile_link_option(${sse41_flag} CRYPTOPP_HAVE_SSE41
                                  "${TEST_PROG_DIR}/test_x86_sse41.cpp"
        )
        if(CRYPTOPP_HAVE_SSE41)
            list(APPEND CRYPTOPP_AES_FLAGS "${sse41_flag}")
            list(APPEND CRYPTOPP_BLAKE2B_FLAGS "${sse41_flag}")
            list(APPEND CRYPTOPP_BLAKE2S_FLAGS "${sse41_flag}")
            list(APPEND CRYPTOPP_BLAKE3_FLAGS "${sse41_flag}")
            list(APPEND CRYPTOPP_SUN_LDFLAGS "${sse41_flag}")
        else()
            set(sse41_flag "")
        endif()

        check_compile_link_option(${sse42_flag} CRYPTOPP_HAVE_SSE42
                                  "${TEST_PROG_DIR}/test_x86_sse42.cpp"
        )
        if(CRYPTOPP_HAVE_SSE42)
            list(APPEND CRYPTOPP_CRC_FLAGS "${sse42_flag}")
            list(APPEND CRYPTOPP_SHA_FLAGS "${sse42_flag}")
            list(APPEND CRYPTOPP_SUN_LDFLAGS "${sse42_flag}")
        else()
            set(sse42_flag "")
        endif()

        check_compile_link_option(${clmul_flag} CRYPTOPP_HAVE_CLMUL
                                  "${TEST_PROG_DIR}/test_x86_clmul.cpp"
        )
        if(CRYPTOPP_HAVE_CLMUL)
            list(APPEND CRYPTOPP_GCM_FLAGS "${clmul_flag}")
            list(APPEND CRYPTOPP_GF2N_FLAGS "${clmul_flag}")
            list(APPEND CRYPTOPP_SUN_LDFLAGS "${clmul_flag}")
        else()
            set(clmul_flag "")
        endif()

        check_compile_link_option(${aesni_flag} CRYPTOPP_HAVE_AESNI
                                  "${TEST_PROG_DIR}/test_x86_aes.cpp"
        )
        if(CRYPTOPP_HAVE_CLMUL)
            list(APPEND CRYPTOPP_AES_FLAGS "${aesni_flag}")
            list(APPEND CRYPTOPP_SM4_FLAGS "${aesni_flag}")
            list(APPEND CRYPTOPP_SUN_LDFLAGS "${aesni_flag}")
        else()
            set(aesni_flag "")
        endif()

        check_compile_link_option(${avx_flag} CRYPTOPP_HAVE_AVX
                                  "${TEST_PROG_DIR}/test_x86_avx.cpp"
        )
        if(CRYPTOPP_HAVE_CLMUL)
            list(APPEND CRYPTOPP_SUN_LDFLAGS "${avx_flag}")
        else()
            set(avx_flag "")
        endif()

        check_compile_link_option(${avx2_flag} CRYPTOPP_HAVE_AVX2
                                  "${TEST_PROG_DIR}/test_x86_avx2.cpp"
        )
        if(CRYPTOPP_HAVE_CLMUL)
            # BLAKE3 AVX2 needs both SSE4.1 (for fallback) and AVX2
            list(APPEND CRYPTOPP_BLAKE3_AVX2_FLAGS "${sse41_flag}" "${avx2_flag}")
            list(APPEND CRYPTOPP_CHACHA_AVX2_FLAGS "${avx2_flag}")
            list(APPEND CRYPTOPP_LSH256_AVX2_FLAGS "${avx2_flag}")
            list(APPEND CRYPTOPP_LSH512_AVX2_FLAGS "${avx2_flag}")
            list(APPEND CRYPTOPP_SUN_LDFLAGS "${avx2_flag}")
        else()
            set(avx2_flag "")
        endif()

        check_compile_link_option(${shani_flag} CRYPTOPP_HAVE_SHANI
                                  "${TEST_PROG_DIR}/test_x86_sha.cpp"
        )
        if(CRYPTOPP_HAVE_SHANI)
            list(APPEND CRYPTOPP_SHA_FLAGS "${shani_flag}")
            list(APPEND CRYPTOPP_SUN_LDFLAGS "${shani_flag}")
        else()
            set(shani_flag "")
        endif()

        if(NOT sse3_flag)
            list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_SSE3=1")
        elseif(NOT ssse3_flag)
            list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_SSSE3=1")
        elseif(NOT sse41_flag)
            list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_SSE41=1")
        elseif(NOT sse42_flag)
            list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_SSE42=1")
        endif()

        if(sse42_flag)
            if(NOT clmul_flag)
                list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_CLMUL=1")
            endif()
            if(NOT aesni_flag)
                list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_AESNI=1")
            endif()

            if(NOT avx_flag)
                list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_AVX=1")
            elseif(NOT avx2_flag)
                list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_AVX2=1")
            endif()
            if(NOT shani_flag)
                list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_SHANI=1")
            endif()
        endif()

        if(NOT gcm_flag)
            set(gcm_flag ${sse2_flag})
        endif()
    else()
        set(sse2_flag "")
        list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_ASM=1")
    endif()

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Intel")
        list(
            APPEND
            CRYPTOPP_COMPILE_OPTIONS
            -wd68
            -wd186
            -wd279
            -wd327
            -wd161
            -wd3180
        )
        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "11.1")
            list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_ASM=1")
        endif()
    endif()

    list(
        FIND
        CRYPTOPP_COMPILE_DEFINITIONS
        "CRYPTOPP_DISABLE_ASM=1"
        has_disable_asm
    )
    if(has_disable_asm EQUAL -1)
        if(CMAKE_SYSTEM MATCHES "SunOS" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU")
            list(APPEND CRYPTOPP_COMPILE_OPTIONS -Wa,--divide)
        endif()
    endif()
endif()

# ##############################################################################
# ARM A-32 and NEON
# ##############################################################################

if(CRYPTOPP_ARM32 AND NOT CRYPTOPP_DISABLE_ARM_NEON)
    check_compile_link_option(
      "-DCRYPTOPP_ARM_NEON_HEADER=1 -march=armv7-a -mfpu=neon"
      CRYPTOPP_ARM_NEON_HEADER "${TEST_PROG_DIR}/test_arm_neon_header.cpp"
    )
    if(CRYPTOPP_ARM_NEON_HEADER)
        list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_ARM_NEON_HEADER=1")
    endif()

    list(APPEND arm_neon_flags -march=armv7-a -mfpu=neon)
    check_compile_link_option("-march=armv7-a -mfpu=neon" CRYPTOPP_HAVE_ARM_NEON
                              "${TEST_PROG_DIR}/test_arm_neon.cpp"
    )
    if(CRYPTOPP_HAVE_ARM_NEON)
        list(APPEND CRYPTOPP_NEON_FLAGS -march=armv7-a -mfpu=neon)
        list(APPEND CRYPTOPP_ARIA_FLAGS -march=armv7-a -mfpu=neon)
        list(APPEND CRYPTOPP_GCM_FLAGS -march=armv7-a -mfpu=neon)
        list(APPEND CRYPTOPP_BLAKE2B_FLAGS -march=armv7-a -mfpu=neon)
        list(APPEND CRYPTOPP_BLAKE2S_FLAGS -march=armv7-a -mfpu=neon)
        list(APPEND CRYPTOPP_BLAKE3_FLAGS -march=armv7-a -mfpu=neon)
        list(APPEND CRYPTOPP_CHACHA_FLAGS -march=armv7-a -mfpu=neon)
        list(APPEND CRYPTOPP_CHAM_FLAGS -march=armv7-a -mfpu=neon)
        list(APPEND CRYPTOPP_LEA_FLAGS -march=armv7-a -mfpu=neon)
        list(APPEND CRYPTOPP_SIMON128_FLAGS -march=armv7-a -mfpu=neon)
        list(APPEND CRYPTOPP_SPECK128_FLAGS -march=armv7-a -mfpu=neon)
        list(APPEND CRYPTOPP_SM4_FLAGS -march=armv7-a -mfpu=neon)
    else()
        list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_ARM_NEON=1")
    endif()
endif()

# Cryptogams source files for ARM
if(
    CRYPTOPP_ARM32
    AND (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR ANDROID)
    AND NOT CRYPTOPP_DISABLE_ARM_NEON
    AND NOT CRYPTOPP_DISABLE_ASM
)
    list(APPEND cryptopp_SOURCES_ASM ${cryptopp_SOURCES_ASM_ARM})
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        list(APPEND CRYPTOGAMS_ARM_FLAG -march=armv7-a)
        list(APPEND CRYPTOGAMS_ARM_THUMB_FLAG -march=armv7-a -mthumb)
    else()
        list(APPEND CRYPTOGAMS_ARM_FLAG -march=armv7-a)
        list(APPEND CRYPTOGAMS_ARM_THUMB_FLAG -march=armv7-a)
    endif()
endif()

# ##############################################################################
# Aarch32 and Aarch64
# ##############################################################################

if(CRYPTOPP_ARMV8)
    if (MSVC)
        list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_ARM_NEON_HEADER=1")
        list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_ARM_ACLE_HEADER=0")
    else()
        check_compile_link_option(
          "-DCRYPTOPP_ARM_NEON_HEADER=1" CRYPTOPP_ARM_NEON_HEADER
          "${TEST_PROG_DIR}/test_arm_neon_header.cpp"
        )
        if(CRYPTOPP_ARM_NEON_HEADER)
            list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_ARM_NEON_HEADER=1")
        endif()

        check_compile_link_option(
          "-DCRYPTOPP_ARM_ACLE_HEADER=1 -march=armv8-a" CRYPTOPP_ARM_ACLE_HEADER
          "${TEST_PROG_DIR}/test_arm_acle_header.cpp"
        )
        if(CRYPTOPP_ARM_ACLE_HEADER)
            list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_ARM_ACLE_HEADER=1")
        endif()

        check_compile_link_option("-march=armv8-a" CRYPTOPP_ARM_SIMD
                                  "${TEST_PROG_DIR}/test_arm_asimd.cpp"
        )
        if(CRYPTOPP_ARM_SIMD)
            list(APPEND CRYPTOPP_ASIMD_FLAGS -march=armv8-a)
            list(APPEND CRYPTOPP_ARIA_FLAGS -march=armv8-a)
            list(APPEND CRYPTOPP_BLAKE2B_FLAGS -march=armv8-a)
            list(APPEND CRYPTOPP_BLAKE2S_FLAGS -march=armv8-a)
            list(APPEND CRYPTOPP_CHACHA_FLAGS -march=armv8-a)
            list(APPEND CRYPTOPP_CHAM_FLAGS -march=armv8-a)
            list(APPEND CRYPTOPP_LEA_FLAGS -march=armv8-a)
            list(APPEND CRYPTOPP_NEON_FLAGS -march=armv8-a)
            list(APPEND CRYPTOPP_SIMON128_FLAGS -march=armv8-a)
            list(APPEND CRYPTOPP_SPECK128_FLAGS -march=armv8-a)
            list(APPEND CRYPTOPP_SM4_FLAGS -march=armv8-a)

            check_compile_link_option("-march=armv8-a+crc" CRYPTOPP_HAVE_ARM_CRC32
                                      "${TEST_PROG_DIR}/test_arm_crc.cpp"
            )
            if(CRYPTOPP_HAVE_ARM_CRC32)
                list(APPEND CRYPTOPP_CRC_FLAGS -march=armv8-a+crc)
            else()
                list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_ARM_CRC32=1")
            endif()

            check_compile_link_option("-march=armv8-a+crypto" CRYPTOPP_HAVE_ARM_AES
                                      "${TEST_PROG_DIR}/test_arm_aes.cpp"
            )
            if(CRYPTOPP_HAVE_ARM_AES)
                list(APPEND CRYPTOPP_AES_FLAGS -march=armv8-a+crypto)
            else()
                list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_ARM_AES=1")
            endif()

            check_compile_link_option("-march=armv8-a+crypto" CRYPTOPP_HAVE_ARM_PMULL
                                      "${TEST_PROG_DIR}/test_arm_pmull.cpp"
            )
            if(CRYPTOPP_HAVE_ARM_PMULL)
                list(APPEND CRYPTOPP_GCM_FLAGS -march=armv8-a+crypto)
                list(APPEND CRYPTOPP_GF2N_FLAGS -march=armv8-a+crypto)
            else()
                list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_ARM_PMULL=1")
            endif()

            check_compile_link_option("-march=armv8-a+crypto" CRYPTOPP_HAVE_ARM_SHA1
                                      "${TEST_PROG_DIR}/test_arm_sha1.cpp"
            )
            if(CRYPTOPP_HAVE_ARM_SHA1)
                list(APPEND CRYPTOPP_SHA_FLAGS -march=armv8-a+crypto)
            else()
                list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_ARM_SHA1=1")
            endif()

            check_compile_link_option("-march=armv8-a+crypto" CRYPTOPP_HAVE_ARM_SHA2
                                      "${TEST_PROG_DIR}/test_arm_sha256.cpp"
            )
            if(CRYPTOPP_HAVE_ARM_SHA2)
                list(APPEND CRYPTOPP_SHA_FLAGS -march=armv8-a+crypto)
            else()
                list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_ARM_SHA2=1")
            endif()

            check_compile_link_option("-march=armv8.4-a+sm3" CRYPTOPP_HAVE_ARM_SM3
                                      "${TEST_PROG_DIR}/test_arm_sm3.cpp"
            )
            if(CRYPTOPP_HAVE_ARM_SM3)
                list(APPEND CRYPTOPP_SM3_FLAGS -march=armv8.4-a+sm3)
                list(APPEND CRYPTOPP_SM4_FLAGS -march=armv8.4-a+sm3)
            endif()

            check_compile_link_option("-march=armv8.4-a+sha3" CRYPTOPP_HAVE_ARM_SHA3
                                      "${TEST_PROG_DIR}/test_arm_sha3.cpp"
            )
            if(CRYPTOPP_HAVE_ARM_SHA3)
                list(APPEND CRYPTOPP_SHA3_FLAGS -march=armv8.4-a+sha3)
            endif()

            check_compile_link_option("-march=armv8.4-a+sha512" CRYPTOPP_HAVE_ARM_SHA512
                                      "${TEST_PROG_DIR}/test_arm_sha512.cpp"
            )
            if(CRYPTOPP_HAVE_ARM_SHA512)
                list(APPEND CRYPTOPP_SHA3_FLAGS -march=armv8.4-a+sha512)
            endif()
        else()
            list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_ASM=1")
        endif()
    endif()
endif()

# ##############################################################################
# PowerPC
# ##############################################################################

if(CRYPTOPP_PPC32 OR CRYPTOPP_PPC64)
    if(CMAKE_CXX_COMPILER MATCHES "xlC")
        list(APPEND CRYPTOPP_POWER8_FLAGS -qarch=pwr8 -qaltivec)
        list(APPEND CRYPTOPP_POWER7_VSX_FLAGS -qarch=pwr7 -qvsx -qaltivec)
        list(APPEND CRYPTOPP_POWER7_PWR_FLAGS -qarch=pwr7 -qaltivec)
        list(APPEND CRYPTOPP_ALTIVEC_FLAGS -qarch=auto -qaltivec)
    else()
        list(APPEND CRYPTOPP_POWER8_FLAGS -mcpu=power8)
        list(APPEND CRYPTOPP_POWER7_VSX_FLAGS -mcpu=power7 -mvsx)
        list(APPEND CRYPTOPP_POWER7_PWR_FLAGS -mcpu=power7)
        list(APPEND CRYPTOPP_ALTIVEC_FLAGS -maltivec)
    endif()

    set(POWER9_FLAG)

    string(REPLACE ";" " " CRYPTOPP_POWER8_FLAGS_STR "${CRYPTOPP_POWER8_FLAGS}")
    check_compile_link_option(${CRYPTOPP_POWER8_FLAGS_STR} CRYPTOPP_HAVE_POWER8
                              "${TEST_PROG_DIR}/test_ppc_power8.cpp"
    )
    if(CRYPTOPP_HAVE_POWER8)
        list(APPEND CRYPTOPP_AES_FLAGS ${CRYPTOPP_POWER8_FLAGS})
        list(APPEND CRYPTOPP_BLAKE2B_FLAGS ${CRYPTOPP_POWER8_FLAGS})
        list(APPEND CRYPTOPP_CRC_FLAGS ${CRYPTOPP_POWER8_FLAGS})
        list(APPEND CRYPTOPP_GCM_FLAGS ${CRYPTOPP_POWER8_FLAGS})
        list(APPEND CRYPTOPP_GF2N_FLAGS ${CRYPTOPP_POWER8_FLAGS})
        list(APPEND CRYPTOPP_LEA_FLAGS ${CRYPTOPP_POWER8_FLAGS})
        list(APPEND CRYPTOPP_SHA_FLAGS ${CRYPTOPP_POWER8_FLAGS})
    else()
        set(CRYPTOPP_POWER8_FLAGS)
    endif()

    string(REPLACE ";" " " CRYPTOPP_POWER7_VSX_FLAGS_STR "${CRYPTOPP_POWER7_VSX_FLAGS}")
    check_compile_link_option(${CRYPTOPP_POWER7_VSX_FLAGS_STR} CRYPTOPP_HAVE_POWER7_VSX
                              "${TEST_PROG_DIR}/test_ppc_power7.cpp"
    )
    if(CRYPTOPP_HAVE_POWER7_VSX)
        list(APPEND CRYPTOPP_POWER7_FLAGS ${CRYPTOPP_POWER7_VSX_FLAGS})
    else()
        string(REPLACE ";" " " CRYPTOPP_POWER7_PWR_FLAGS_STR "${CRYPTOPP_POWER7_PWR_FLAGS}")
        check_compile_link_option(${CRYPTOPP_POWER7_PWR_FLAGS_STR} CRYPTOPP_HAVE_POWER7_PWR
                                  "${TEST_PROG_DIR}/test_ppc_power7.cpp"
        )
        if(CRYPTOPP_HAVE_POWER7_PWR)
            list(APPEND CRYPTOPP_POWER7_FLAGS ${CRYPTOPP_POWER7_PWR_FLAGS})
        else()
            set(CRYPTOPP_POWER7_FLAGS)
        endif()
    endif()

    string(REPLACE ";" " " CRYPTOPP_ALTIVEC_FLAGS_STR "${CRYPTOPP_ALTIVEC_FLAGS}")
    check_compile_link_option(${CRYPTOPP_ALTIVEC_FLAGS_STR} CRYPTOPP_HAVE_ALTIVEC
                              "${TEST_PROG_DIR}/test_ppc_altivec.cpp"
    )
    if(CRYPTOPP_HAVE_ALTIVEC)
        list(APPEND CRYPTOPP_BLAKE2S_FLAGS ${CRYPTOPP_ALTIVEC_FLAGS})
        list(APPEND CRYPTOPP_CHACHA_FLAGS ${CRYPTOPP_ALTIVEC_FLAGS})
        list(APPEND CRYPTOPP_SPECK128_FLAGS ${CRYPTOPP_ALTIVEC_FLAGS})
        list(APPEND CRYPTOPP_SIMON128_FLAGS ${CRYPTOPP_ALTIVEC_FLAGS})
    else()
        set(CRYPTOPP_ALTIVEC_FLAGS)
    endif()

    if(CRYPTOPP_ALTIVEC_FLAGS AND NOT CRYPTOPP_GCM_FLAGS)
        list(APPEND CRYPTOPP_CGM_FLAGS ${CRYPTOPP_ALTIVEC_FLAGS})
    endif()

    if(NOT CRYPTOPP_ALTIVEC_FLAGS)
        list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_ALTIVEC=1")
    elseif(NOT CRYPTOPP_POWER7_FLAGS)
        list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_POWER7=1")
    elseif(NOT CRYPTOPP_POWER8_FLAGS)
        list(APPEND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_POWER8=1")
    endif()

    if(CMAKE_CXX_COMPILER MATCHES "xlC")
        list(APPEND CRYPTOPP_COMPILE_OPTIONS -qmaxmem=-1)
        list(APPEND CRYPTOPP_COMPILE_OPTIONS -qrtti)

        check_compile_link_option("-qsuppress=1500-036" CRYPTOPP_HAVE_QSUPPRESS
                                  "${TEST_PROG_DIR}/test_cxx.cpp"
        )
        if(CRYPTOPP_HAVE_QSUPPRESS)
            list(APPEND CRYPTOPP_COMPILE_OPTIONS -qsuppress=1500-036)
        endif()
    endif()
endif()

# Remove unneeded arch specific files to speed build time.
if(NOT CRYPTOPP_PPC32 AND NOT CRYPTOPP_PPC64)
    list(FILTER cryptopp_SOURCES EXCLUDE REGEX "_ppc.cpp")
endif()
if(NOT CRYPTOPP_ARM32 AND NOT CRYPTOPP_ARMV8)
    list(FILTER cryptopp_SOURCES EXCLUDE REGEX "arm_|neon_|_armv4.S")
endif()
if(
    NOT CRYPTOPP_I386
    AND NOT CRYPTOPP_AMD64
    AND NOT CRYPTOPP_MINGW32
    AND NOT CRYPTOPP_MINGW64
    AND NOT CRYPTOPP_CYGWIN
)
    list(FILTER cryptopp_SOURCES EXCLUDE REGEX "sse_|_sse.cpp|_avx.cpp")
endif()

# If ASM is disabled we can remove the SIMD files, too.
list(FIND CRYPTOPP_COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_ASM=1" has_disable_asm)
if(NOT has_disable_asm EQUAL -1)
    list(
        FILTER cryptopp_SOURCES
        EXCLUDE
        REGEX
            "arm_|ppc_|neon_|sse_|_sse.cpp|_avx.cpp|_ppc.cpp|_simd.cpp|_armv4.S"
    )
    # But keep sse_simd.cpp or we get undefined symbols at link
    list(PREPEND cryptopp_SOURCES "${cryptopp_SOURCE_DIR}/src/core/sse_simd.cpp")
endif()

# Apply compiler options to SIMD source files
set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/symmetric/aria.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_ARIA_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/hash/blake2s_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_BLAKE2S_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/hash/blake2b_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_BLAKE2B_FLAGS}"
)

# BLAKE3 SIMD: Use /arch:AVX2 on MSVC for fair comparison with GCC -mavx2
if(MSVC)
    set_source_files_properties(
        ${cryptopp_SOURCE_DIR}/src/hash/blake3_simd.cpp
        PROPERTIES COMPILE_OPTIONS "/arch:AVX2"
    )
else()
    set_source_files_properties(
        ${cryptopp_SOURCE_DIR}/src/hash/blake3_simd.cpp
        PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_BLAKE3_AVX2_FLAGS}"
    )
endif()

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/symmetric/chacha_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_CHACHA_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/symmetric/chacha_avx.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_CHACHA_AVX2_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/symmetric/cham_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_CHAM_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/hash/crc_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_CRC_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/random/darn.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_DARN_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/pubkey/donna_sse.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_DONNA_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/modes/gcm_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_GCM_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/core/gf2n_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_GF2N_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/hash/keccak_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_KECCAK_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/symmetric/lea_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_LEA_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/hash/lsh256_sse.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_LSH256_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/hash/lsh256_avx.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_LSH256_AVX2_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/hash/lsh512_sse.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_LSH512_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/hash/lsh512_avx.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_LSH512_AVX2_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/core/neon_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_NEON_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/core/ppc_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_PPC_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/symmetric/rijndael_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_AES_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/hash/sha_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_SHA_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/symmetric/shacal2_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_SHA_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/symmetric/simon128_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_SIMON128_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/symmetric/speck128_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_SPECK128_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/hash/sm3.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_SM3_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/symmetric/sm4_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_SM4_FLAGS}"
)

set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/symmetric/aes_armv4.S
    PROPERTIES COMPILE_OPTIONS "${CRYPTOGAMS_ARM_THUMB_FLAG}"
)

foreach(file sha1_armv4.S sha256_armv4.S sha512_armv4.S)
    set_source_files_properties(
        ${cryptopp_SOURCE_DIR}/src/hash/${file}
        PROPERTIES COMPILE_OPTIONS "${CRYPTOGAMS_ARM_FLAG}"
    )
endforeach()

# IBM XLC -O3 optimization bug
if(CMAKE_CXX_COMPILER MATCHES "xlC")
    foreach(file sm3.cpp donna_32.cpp donna_64.cpp)
        get_source_file_property(
            xlc_compile_options
            ${cryptopp_SOURCE_DIR}/src/pubkey/${file}
            COMPILE_OPTIONS
        )
        list(REMOVE_ITEM xlc_compile_options "-O3")
        list(APPEND xlc_compile_options "-O2")
        set_source_files_properties(
            ${cryptopp_SOURCE_DIR}/src/pubkey/${file}
            PROPERTIES COMPILE_OPTIONS "${xlc_compile_options}"
        )
    endforeach()
endif()

# SSE2 on i686
set_source_files_properties(
    ${cryptopp_SOURCE_DIR}/src/core/sse_simd.cpp
    PROPERTIES COMPILE_OPTIONS "${CRYPTOPP_SSE2_FLAGS}"
)

# ------------------------------------------------------------------------------
# Compiler: MSVC
# ------------------------------------------------------------------------------
if(MSVC AND NOT CRYPTOPP_DISABLE_ASM)
    if(${CMAKE_GENERATOR_PLATFORM} MATCHES "ARM" OR CRYPTOPP_ARM32 OR CRYPTOPP_ARMV8)
        message(
            STATUS
            "[cryptopp-modern] Disabling ASM because ARM is specified as target platform."
        )
    else()
        enable_language(ASM_MASM)
        if(NOT CRYPTOPP_DISABLE_RDRAND)
            list(APPEND cryptopp_SOURCES_ASM ${cryptopp_SOURCE_DIR}/src/random/rdrand.asm)
            if(${CMAKE_GENERATOR} MATCHES "Visual Studio.*")
                set_source_files_properties(
                    ${cryptopp_SOURCE_DIR}/src/random/rdrand.asm
                    PROPERTIES COMPILE_OPTIONS "/Fo\$(IntDir)rdrand.asm.obj"
                )
            endif()
        endif()
        if(NOT CRYPTOPP_DISABLE_RDSEED)
            list(APPEND cryptopp_SOURCES_ASM ${cryptopp_SOURCE_DIR}/src/random/rdseed.asm)
        endif()
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            list(
                APPEND
                cryptopp_SOURCES_ASM
                ${cryptopp_SOURCE_DIR}/src/core/x64dll.asm
                ${cryptopp_SOURCE_DIR}/src/core/x64masm.asm
            )
            if(EXISTS "${cryptopp_SOURCE_DIR}/src/core/cpuid64.asm")
                list(
                    APPEND
                    cryptopp_SOURCES_ASM
                    ${cryptopp_SOURCE_DIR}/src/core/cpuid64.asm
                )
            endif()
            set_source_files_properties(
                ${cryptopp_SOURCES_ASM}
                PROPERTIES COMPILE_DEFINITIONS "_M_X64"
            )
        else()
            set_source_files_properties(
                ${cryptopp_SOURCES_ASM}
                PROPERTIES COMPILE_DEFINITIONS "_M_X86" COMPILE_FLAGS "/safeseh"
            )
        endif()
        set_source_files_properties(
            ${cryptopp_SOURCES_ASM}
            PROPERTIES LANGUAGE ASM_MASM
        )
    endif()
endif()

# ============================================================================
# Compile targets
# ============================================================================

function(cryptopp_set_compile_properties)
    set(options ${CRYPTOPP_COMPILE_OPTIONS})
    if(MSVC)
        list(APPEND options ${CRYPTOPP_MSVC_COMPILE_OPTIONS})
    endif()
    if(options)
        list(REMOVE_DUPLICATES options)
        if(CMAKE_CXX_FLAGS)
            string(REPLACE " " ";" global_flags ${CMAKE_CXX_FLAGS})
            list(REMOVE_ITEM options ${global_flags})
        endif()
    endif()
    foreach(cxx_file ${cryptopp_SOURCES} ${cryptopp_SOURCES_TEST})
        set_property(
            SOURCE ${cxx_file}
            APPEND
            PROPERTY COMPILE_OPTIONS ${options}
        )
        set_property(
            SOURCE ${cxx_file}
            APPEND
            PROPERTY COMPILE_DEFINITIONS ${CRYPTOPP_COMPILE_DEFINITIONS} ${CRYPTOPP_MSVC_COMPILE_DEFINITIONS}
        )
    endforeach()
endfunction()

cryptopp_set_compile_properties()

if(DEFINED CRYPTOPP_BUILD_SHARED)
    set(BUILD_SHARED_LIBS ${CRYPTOPP_BUILD_SHARED})
endif()

if(
    NOT DEFINED CMAKE_CXX_VISIBILITY_PRESET
    AND NOT DEFINED CMAKE_VISIBILITY_INLINES_HIDDEN
)
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)
endif()

set(cryptopp_LIBRARY_SOURCES ${cryptopp_SOURCES_ASM})
list(APPEND cryptopp_LIBRARY_SOURCES ${cryptopp_SOURCES})

add_library(cryptopp ${cryptopp_LIBRARY_SOURCES})
add_library(cryptopp::cryptopp ALIAS cryptopp)
set_target_properties(
    cryptopp
    PROPERTIES
        VERSION ${cryptopp-modern_VERSION}
        SOVERSION ${cryptopp-modern_VERSION_MAJOR}
)
set_target_properties(cryptopp PROPERTIES LINKER_LANGUAGE CXX)
if(${CRYPTOPP_BUILD_SHARED})
    target_compile_definitions(cryptopp PRIVATE "CRYPTOPP_EXPORTS")
endif()
target_compile_definitions(
    cryptopp
    INTERFACE
        $<INSTALL_INTERFACE:CRYPTOPP_INCLUDE_PREFIX=${CRYPTOPP_INCLUDE_PREFIX}>
        ${CRYPTOPP_COMPILE_DEFINITIONS}
)

target_include_directories(
    cryptopp
    PUBLIC
        $<BUILD_INTERFACE:${cryptopp_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if(CMAKE_CXX_COMPILER_ID STREQUAL "SunPro")
    target_link_options(cryptopp PRIVATE ${CRYPTOPP_SUN_LDFLAGS})
endif()

# ============================================================================
# Static linking (recommended for portability)
# ============================================================================

# For MinGW/GCC, link statically to avoid runtime DLL dependencies
if(MINGW OR (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND WIN32))
    # Static link libgcc, libstdc++, and pthreads
    target_link_options(cryptopp PRIVATE
        -static
        -static-libgcc
        -static-libstdc++
    )
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
endif()

# ============================================================================
# Third-party libraries
# ============================================================================

if(WIN32)
    target_link_libraries(cryptopp kernel32)
endif()

find_package(Threads)
if(MINGW)
    # Use static pthreads on MinGW
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    target_link_libraries(cryptopp ${CMAKE_THREAD_LIBS_INIT} -static -lpthread)
else()
    target_link_libraries(cryptopp ${CMAKE_THREAD_LIBS_INIT})
endif()

# ============================================================================
# Setup OpenMP
# ============================================================================
if(CRYPTOPP_USE_OPENMP)
    list(APPEND CMAKE_PREFIX_PATH /usr/local/opt/libomp)
    list(APPEND CMAKE_PREFIX_PATH /opt/homebrew/opt/libomp/)
    list(APPEND CMAKE_PREFIX_PATH /opt/local/lib/libomp/)
    list(APPEND CMAKE_INCLUDE_PATH /opt/local/include/libomp/)
    find_package(OpenMP REQUIRED)
endif()

target_link_libraries(
    cryptopp
    $<$<BOOL:${CRYPTOPP_USE_OPENMP}>:OpenMP::OpenMP_CXX>
)

# ============================================================================
# Tests
# ============================================================================

if(CRYPTOPP_BUILD_TESTING)
    add_executable(cryptest ${cryptopp_SOURCES_TEST})
    target_link_libraries(cryptest PRIVATE cryptopp::cryptopp)

    # Match GNUmakefile behavior: always use .exe suffix (even on Linux/macOS)
    set_target_properties(cryptest PROPERTIES SUFFIX ".exe")

    # Copy TestData and TestVectors to build directory so tests can run from there
    add_custom_command(
        TARGET cryptest POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${cryptopp_SOURCE_DIR}/TestData
            $<TARGET_FILE_DIR:cryptest>/TestData
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${cryptopp_SOURCE_DIR}/TestVectors
            $<TARGET_FILE_DIR:cryptest>/TestVectors
        COMMENT "Copying TestData and TestVectors to build directory"
    )

    set_property(SOURCE
        ${cryptopp_SOURCE_DIR}/src/test/bench3.cpp
        ${cryptopp_SOURCE_DIR}/src/test/datatest.cpp
        ${cryptopp_SOURCE_DIR}/src/test/test.cpp
        ${cryptopp_SOURCE_DIR}/src/test/validat0.cpp
        ${cryptopp_SOURCE_DIR}/src/test/validat4.cpp
        ${cryptopp_SOURCE_DIR}/src/test/validat7.cpp
        ${cryptopp_SOURCE_DIR}/src/test/validat8.cpp
        ${cryptopp_SOURCE_DIR}/src/test/validat9.cpp
        APPEND PROPERTY
            COMPILE_DEFINITIONS
                CRYPTOPP_DATA_DIR="${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR}/cryptopp/"
    )

    add_test(
        NAME cryptopp-modern-build_cryptest
        COMMAND
            "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR} --target cryptest
            --config ${CMAKE_BUILD_TYPE}
    )
    set_tests_properties(
        cryptopp-modern-build_cryptest
        PROPERTIES
            FIXTURES_SETUP cryptest-build
            LABELS "cryptopp-modern;cryptopp-cryptest"
    )

    add_test(
        NAME cryptopp-modern-cryptest
        COMMAND $<TARGET_FILE:cryptest> v
        WORKING_DIRECTORY ${cryptopp_SOURCE_DIR}
    )
    set_tests_properties(
        cryptopp-modern-cryptest
        PROPERTIES
            FIXTURES_REQUIRED cryptest-build
            LABELS "cryptopp-modern;cryptopp-cryptest"
    )

    add_test(
        NAME cryptopp-modern-cryptest-extensive
        COMMAND $<TARGET_FILE:cryptest> tv all
        WORKING_DIRECTORY ${cryptopp_SOURCE_DIR}
    )
    set_tests_properties(
        cryptopp-modern-cryptest-extensive
        PROPERTIES
            FIXTURES_CLEANUP cryptest-build
            LABELS "cryptopp-modern;cryptopp-cryptest"
    )
endif()

# ==============================================================================
# Deployment instructions
# ==============================================================================

include(GNUInstallDirs)

if(CRYPTOPP_INSTALL)
    set(TARGETS_EXPORT_NAME "cryptopp-modern_Targets")
    set(runtime "cryptopp-modern_runtime")
    set(dev "cryptopp-modern_dev")

    include(ConfigFiles)
    create_module_config_files()

    install(
        TARGETS cryptopp
        EXPORT ${TARGETS_EXPORT_NAME}
        RUNTIME
        COMPONENT ${runtime}
        LIBRARY
        COMPONENT ${runtime}
        ARCHIVE
        COMPONENT ${dev}
    )

    # Header files
    install(
        FILES ${cryptopp_HEADERS}
        COMPONENT ${dev}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${CRYPTOPP_INCLUDE_PREFIX}"
    )

    if(CRYPTOPP_BUILD_SHARED)
        set(type shared)
    else()
        set(type static)
    endif()

    install(
        EXPORT ${TARGETS_EXPORT_NAME}
        DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/cmake/cryptopp-modern"
        NAMESPACE cryptopp::
        FILE cryptopp-modern-${type}-targets.cmake
        COMPONENT ${dev}
    )

    # Package configuration files
    install(
        FILES
            ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cryptopp-modernConfig.cmake
            ${CMAKE_CURRENT_BINARY_DIR}/cryptopp-modernConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/cmake/cryptopp-modern
        COMPONENT ${dev}
    )
    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/cryptopp-modern.pc
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig
        COMPONENT ${dev}
    )

    # Tests
    if(CRYPTOPP_BUILD_TESTING)
        install(TARGETS cryptest DESTINATION ${CMAKE_INSTALL_BINDIR})
        install(
            DIRECTORY ${cryptopp_SOURCE_DIR}/TestData
            DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/cryptopp
        )
        install(
            DIRECTORY ${cryptopp_SOURCE_DIR}/TestVectors
            DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/cryptopp
        )
    endif()
endif()

# Print a configuration summary
if(CRYPTOPP_I386)
    message(STATUS "[cryptopp-modern] Platform: i386/i686")
elseif(CRYPTOPP_AMD64)
    message(STATUS "[cryptopp-modern] Platform: x86_64")
elseif(CRYPTOPP_ARM32)
    message(STATUS "[cryptopp-modern] Platform: ARM-32")
elseif(CRYPTOPP_ARMV8)
    message(STATUS "[cryptopp-modern] Platform: ARMv8")
elseif(CRYPTOPP_SPARC)
    message(STATUS "[cryptopp-modern] Platform: Sparc")
elseif(CRYPTOPP_SPARC64)
    message(STATUS "[cryptopp-modern] Platform: Sparc64")
elseif(CRYPTOPP_PPC32)
    message(STATUS "[cryptopp-modern] Platform: PowerPC")
elseif(CRYPTOPP_PPC64)
    message(STATUS "[cryptopp-modern] Platform: PowerPC-64")
elseif(CRYPTOPP_MINGW32)
    message(STATUS "[cryptopp-modern] Platform: MinGW-32")
elseif(CRYPTOPP_MINGW64)
    message(STATUS "[cryptopp-modern] Platform: MinGW-64")
endif()
if(CRYPTOPP_HAVE_ARM_NEON)
    message(STATUS "[cryptopp-modern] NEON: TRUE")
endif()
message(
    STATUS
    "[cryptopp-modern] Compiler definitions: ${CMAKE_CPP_FLAGS} ${CRYPTOPP_COMPILE_DEFINITIONS}"
)
message(
    STATUS
    "[cryptopp-modern] Compiler options: ${CMAKE_CXX_FLAGS} ${CRYPTOPP_COMPILE_OPTIONS} ${CRYPTOPP_MSVC_COMPILE_OPTIONS}"
)
message(STATUS "[cryptopp-modern] Build type: ${CMAKE_BUILD_TYPE}")
