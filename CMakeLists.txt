cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ZeekPluginShunter)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBXDP REQUIRED IMPORTED_TARGET libxdp)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

include(ZeekPlugin)

zeek_plugin_begin(XDP Shunter ${ZEEK_PLUGIN_BEGIN_OPTS})
zeek_plugin_cc(src/Plugin.cc src/XDPProgram.cc src/common_user_bpf_xdp.c)
zeek_plugin_bif(src/shunter.bif)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_scripts(scripts/__load__.zeek scripts/__preload__.zeek scripts/types.zeek
                    scripts/XDP/Shunter/__load__.zeek)
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
