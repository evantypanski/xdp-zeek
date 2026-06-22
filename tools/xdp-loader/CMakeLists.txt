cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
project(zeek-xdp-loader C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
    cli11
    GIT_REPOSITORY https://github.com/cliutils/cli11
    GIT_TAG v2.6.2
)

FetchContent_MakeAvailable(cli11)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBXDP REQUIRED IMPORTED_TARGET libxdp)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

set(SHARED_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/common")

# Include object and skeleton
set(BPF_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/bpf")
set(BPF_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/bpf/shunter.c")
set(BPF_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/bpf/shunter.o")
set(BPF_SKELETON "${CMAKE_CURRENT_BINARY_DIR}/bpf/shunter.skel.h")

file(MAKE_DIRECTORY ${BPF_OUTPUT_DIR})

find_program(CLANG_EXECUTABLE clang)
find_program(BPF_GCC_EXECUTABLE NAMES bpf-gcc bpf-unknown-none-gcc)
find_program(BPFTOOL_EXECUTABLE bpftool REQUIRED)

if ( NOT CLANG_EXECUTABLE AND NOT BPF_GCC_EXECUTABLE )
   message(FATAL_ERROR "clang or bpf-gcc are required to be in your PATH to build this plugin")
endif ()

# Build the bpf object with either clang or bpf-gcc. LLVM appears
# to be the preferred method to the documentation, but bpf-gcc should
# work also.
if ( CLANG_EXECUTABLE )
    message(STATUS "Compiling bpf shunter with clang")
    add_custom_command(
        OUTPUT ${BPF_OBJECT}
        COMMAND ${CLANG_EXECUTABLE}
            -g -O2
            -target bpf
            -I${SHARED_INCLUDE_DIR}
            -D__BPF_BUILD__
            -c ${BPF_SOURCE}
            -o ${BPF_OBJECT}
        DEPENDS ${BPF_SOURCE}
        COMMENT "Compiling BPF code ${BPF_SOURCE}"
    )
elseif ( BPF_GCC_EXECUTABLE )
    message(STATUS "Compiling bpf shunter with bpf-gcc")
    add_custom_command(
        OUTPUT ${BPF_OBJECT}
        COMMAND ${BPF_GCC_EXECUTABLE}
            -std=gnu11
            -gbtf -O2
            -I${SHARED_INCLUDE_DIR}
            -D__BPF_BUILD__
            -I/usr/include
            -c ${BPF_SOURCE}
            -o ${BPF_OBJECT}
        DEPENDS ${BPF_SOURCE}
        COMMENT "Compiling BPF code ${BPF_SOURCE}"
    )
endif ()

add_custom_command(
    OUTPUT ${BPF_SKELETON}
    COMMAND bash -c "${BPFTOOL_EXECUTABLE} gen skeleton ${BPF_OBJECT} > ${BPF_SKELETON}"
    DEPENDS ${BPF_OBJECT}
    COMMENT "Generating BPF skeleton ${BPF_SKELETON}"
    VERBATIM
)

add_custom_target(loader_bpf ALL
    DEPENDS ${BPF_SKELETON}
)

add_executable(zeek-xdp-loader loader/main.cc loader/connect.cc loader/options.cc loader/shunt.cc)
add_dependencies(zeek-xdp-loader loader_bpf)
target_include_directories(zeek-xdp-loader PRIVATE
    ${BPF_OUTPUT_DIR}
    ${SHARED_INCLUDE_DIR}
)

target_link_libraries(zeek-xdp-loader PRIVATE
    CLI11::CLI11
    PkgConfig::LIBXDP
    PkgConfig::LIBBPF
)

set_target_properties(zeek-xdp-loader PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Allow building outside of plugin
# That's also why the dependencies are still above :)
if (DEFINED ZEEK_CMAKE_INSTALL_PREFIX)
    set(XDP_LOADER_INSTALL_DIR "${ZEEK_CMAKE_INSTALL_PREFIX}/bin")
else ()
    set(XDP_LOADER_INSTALL_DIR "bin")
endif ()

install(TARGETS zeek-xdp-loader DESTINATION "${XDP_LOADER_INSTALL_DIR}")
