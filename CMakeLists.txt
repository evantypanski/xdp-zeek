cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ZeekPluginShunter)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBXDP REQUIRED IMPORTED_TARGET libxdp)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

include(ZeekPlugin)

zeek_plugin_begin(XDP Shunter ${ZEEK_PLUGIN_BEGIN_OPTS})
zeek_plugin_cc(src/Plugin.cc src/XDPProgram.cc src/shunt-util.cc src/bpf/UserXDP.cc src/ShuntThread.cc)
zeek_plugin_bif(src/shunter.bif src/ip_pair_shunter.bif src/conn_id_shunter.bif)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_scripts(scripts/__load__.zeek scripts/__preload__.zeek scripts/types.zeek)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()

target_link_libraries(XDP_Shunter PRIVATE
    PkgConfig::LIBXDP
    PkgConfig::LIBBPF
)

set(BPF_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/bpf")
set(BPF_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/filter.c")
set(BPF_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/bpf/filter.o")
set(BPF_SKELETON "${CMAKE_CURRENT_BINARY_DIR}/bpf/filter.skel.h")

find_program(CLANG_EXECUTABLE clang REQUIRED)
find_program(BPFTOOL_EXECUTABLE bpftool REQUIRED)

file(MAKE_DIRECTORY ${BPF_OUTPUT_DIR})

add_custom_command(
    OUTPUT ${BPF_OBJECT}
    COMMAND ${CLANG_EXECUTABLE}
        -g -O2
        -target bpf
        -c ${BPF_SOURCE}
        -o ${BPF_OBJECT}
    DEPENDS ${BPF_SOURCE}
    COMMENT "Compiling BPF code ${BPF_SOURCE}"
)

add_custom_command(
    OUTPUT ${BPF_SKELETON}
    COMMAND bash -c "${BPFTOOL_EXECUTABLE} gen skeleton ${BPF_OBJECT} > ${BPF_SKELETON}"
    DEPENDS ${BPF_OBJECT}
    COMMENT "Generating BPF skeleton ${BPF_SKELETON}"
    VERBATIM
)

add_custom_target(bpf_build ALL
    DEPENDS ${BPF_SKELETON}
)

target_include_directories(XDP_Shunter PRIVATE
    ${BPF_OUTPUT_DIR}
)

add_dependencies(XDP_Shunter bpf_build)
