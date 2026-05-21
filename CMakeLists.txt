cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ZeekPluginShunter)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBXDP REQUIRED IMPORTED_TARGET libxdp)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

include(ZeekPlugin)

zeek_plugin_begin(Zeek XDP_Shunter ${ZEEK_PLUGIN_BEGIN_OPTS})
zeek_plugin_cc(src/Plugin.cc src/ShuntUtil.cc src/bpf/UserXDP.cc)
zeek_plugin_bif(src/shunter.bif src/ip_pair_shunter.bif src/conn_id_shunter.bif)
zeek_plugin_dist_files(README CHANGES COPYING VERSION zeekctl/xdp.py)
zeek_plugin_scripts(scripts/__load__.zeek scripts/__preload__.zeek scripts/types.zeek
                    scripts/xdp/__load__.zeek scripts/xdp/bulk.zeek scripts/xdp/conn-id-logging.zeek
                    scripts/xdp/connect.zeek scripts/xdp/main.zeek scripts/xdp/shunt-conn-id.zeek
                    scripts/xdp/shunt-ip-pair.zeek scripts/xdp/ssl.zeek
                )
zeek_plugin_end()

# Include filter.o. HACKY :)
set(BPF_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/bpf")
set(BPF_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/filter.c")
set(BPF_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/bpf/filter.o")
set(BPF_SKELETON "${CMAKE_CURRENT_BINARY_DIR}/bpf/filter.skel.h")

set(canon_name "Zeek_XDP_Shunter")
set(dist_tarball_dir ${CMAKE_CURRENT_BINARY_DIR}/dist/${canon_name})

add_custom_command(
    OUTPUT ${dist_tarball_dir}/bpf/filter.o
    COMMAND ${CMAKE_COMMAND} -E make_directory ${dist_tarball_dir}/bpf
    COMMAND ${CMAKE_COMMAND} -E copy ${BPF_OBJECT} ${dist_tarball_dir}/bpf/filter.o
    DEPENDS ${BPF_OBJECT}
)

add_custom_target(bpf_dist DEPENDS ${dist_tarball_dir}/bpf/filter.o)

add_dependencies(${canon_name}_tarball bpf_dist)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()

target_link_libraries(Zeek_XDP_Shunter PRIVATE
    PkgConfig::LIBXDP
    PkgConfig::LIBBPF
)

find_program(CLANG_EXECUTABLE clang)
find_program(BPF_GCC_EXECUTABLE NAMES bpf-gcc bpf-unknown-none-gcc)

if ( NOT CLANG_EXECUTABLE AND NOT BPF_GCC_EXECUTABLE )
   message(FATAL_ERROR "clang or bpf-gcc are required to be in your PATH to build this plugin")
endif ()

file(MAKE_DIRECTORY ${BPF_OUTPUT_DIR})

# Build the bpf object with either clang or bpf-gcc. LLVM appears
# to be the preferred method to the documentation, but bpf-gcc should
# work also.

if ( CLANG_EXECUTABLE )
    message(STATUS "Compiling bpf filter with clang")
    add_custom_command(
        OUTPUT ${BPF_OBJECT}
        COMMAND ${CLANG_EXECUTABLE}
            -g -O2
            -target bpf
            -D__BPF_BUILD__
            -c ${BPF_SOURCE}
            -o ${BPF_OBJECT}
        DEPENDS ${BPF_SOURCE}
        COMMENT "Compiling BPF code ${BPF_SOURCE}"
    )
elseif ( BPF_GCC_EXECUTABLE )
    message(STATUS "Compiling bpf filter with bpf-gcc")
    add_custom_command(
        OUTPUT ${BPF_OBJECT}
        COMMAND ${BPF_GCC_EXECUTABLE}
            -std=gnu11
            -gbtf -O2
            -D__BPF_BUILD__
            -I/usr/include
            -c ${BPF_SOURCE}
            -o ${BPF_OBJECT}
        DEPENDS ${BPF_SOURCE}
        COMMENT "Compiling BPF code ${BPF_SOURCE}"
    )
endif ()

target_include_directories(Zeek_XDP_Shunter PRIVATE
    ${BPF_OUTPUT_DIR}
)
