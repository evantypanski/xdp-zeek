cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ZeekPluginShunter)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBXDP REQUIRED IMPORTED_TARGET libxdp)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

include(ZeekPlugin)

zeek_plugin_begin(Zeek XDP_Shunter ${ZEEK_PLUGIN_BEGIN_OPTS})
zeek_plugin_cc(src/Plugin.cc src/xdp-shunt/ShuntUtil.cc src/xdp-shunt/bpf/UserXDP.cc)
zeek_plugin_bif(src/xdp-shunt/shunter.bif src/xdp-shunt/ip_pair_shunter.bif src/xdp-shunt/conn_id_shunter.bif)
zeek_plugin_dist_files(README CHANGES COPYING VERSION zeekctl/xdp.py)
zeek_plugin_scripts(scripts/__preload__.zeek scripts/xdp-shunt/types.zeek
                    scripts/xdp-shunt/__load__.zeek scripts/xdp-shunt/bulk.zeek
                    scripts/xdp-shunt/connect.zeek scripts/xdp-shunt/main.zeek scripts/xdp-shunt/shunt-conn-id.zeek
                    scripts/xdp-shunt/shunt-ip-pair.zeek scripts/xdp-shunt/ssl.zeek scripts/xdp-shunt/netcontrol.zeek 
                )
zeek_plugin_end()

target_include_directories(Zeek_XDP_Shunter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/xdp-shunt)

set(canon_name "Zeek_XDP_Shunter")
set(dist_tarball_dir ${CMAKE_CURRENT_BINARY_DIR}/dist/${canon_name})

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

add_subdirectory(tools/xdp-loader)
