#pragma once

#include <getopt.h>
#include <optional>
#include <xdp/libxdp.h>
#include <map>
#include <string>

namespace options {

enum class Command { None, Load, Unload, ShuntStatus };

static const std::map<std::string, enum xdp_attach_mode> mode_map{{"auto", XDP_MODE_UNSPEC},
                                                                  {"native", XDP_MODE_NATIVE},
                                                                  {"drv", XDP_MODE_NATIVE},
                                                                  {"skb", XDP_MODE_SKB},
                                                                  {"hw", XDP_MODE_HW},
                                                                  {"offload", XDP_MODE_HW}};

struct config {
    Command cmd = Command::None;

    enum xdp_attach_mode attach_mode = XDP_MODE_UNSPEC;
    int ifindex = -1;
    std::optional<std::string> ifname = {};
    std::string pin_path = "/sys/fs/bpf/zeek";

    // Load
    bool force = false;
    bool load_shunter = false;
    bool include_vlan = false;
    uint32_t conn_id_map_max_size = 65535;
    uint32_t ip_pair_map_max_size = 65535;

    // Unload
    bool unpin_maps = false;
};

bool parse_cmdline(int argc, char** argv, config* cfg);
} // namespace options
