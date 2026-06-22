#include "shunt.h"

#include <linux/if_link.h>
#include <shunter.h>
#include <unistd.h>
#include <iostream>
#include <system_error>
#include <vector>

namespace zeek::xdp::shunt {

struct bpf_map* get_canonical_id_map(struct shunter* skel) { return skel->maps.shunt_map; }
struct bpf_map* get_ip_pair_map(struct shunter* skel) { return skel->maps.ip_pair_map; }

std::optional<std::string> load_shunter(const options::config& cfg) {
    struct bpf_object_open_opts open_opts = {
        .sz = sizeof(struct bpf_object_open_opts),
        .pin_root_path = cfg.pin_path.c_str(),
    };
    auto skel = shunter::open(&open_opts);

    // This must be 1 or greater.
    bpf_map__set_max_entries(get_canonical_id_map(skel), cfg.conn_id_map_max_size);
    bpf_map__set_max_entries(get_ip_pair_map(skel), cfg.ip_pair_map_max_size);

    skel->rodata->include_vlan = cfg.include_vlan;


    auto sec_name = bpf_program__section_name(skel->progs.xdp_shunt);
    if ( ! sec_name ) {
        shunter::destroy(skel);
        return "Could not determine ELF section name for shunter";
    }

    auto* prog = xdp_program__from_bpf_obj(skel->obj, sec_name);
    if ( ! prog ) {
        shunter::destroy(skel);
        return "Failed to parse BPF object via libxdp";
    }

    int err = xdp_program__attach(prog, cfg.ifindex, cfg.attach_mode, 0);
    if ( err ) {
        std::string err_msg = "Libxdp attach failed: ";
        // libxdp uses negative on fail
        err_msg += (err < 0) ? std::generic_category().message(-err) : std::to_string(err);
        shunter::destroy(skel);
        return err_msg;
    }

    return {};
}

size_t count_map(int map_fd, size_t key_size) {
    // TODO
    if ( map_fd < 0 || key_size == 0 )
        return 0;

    std::vector<uint8_t> key_buf(key_size);

    void* prev_key = nullptr;
    void* next_key = key_buf.data();
    size_t flow_count = 0;

    while ( bpf_map_get_next_key(map_fd, prev_key, next_key) == 0 ) {
        flow_count++;
        prev_key = next_key;
    }

    return flow_count;
}

void status(const options::config& cfg) {
    auto is_shunter_attached = false;
    uint32_t prog_id = 0;

    if ( cfg.ifindex >= 0 && cfg.ifname ) {
        auto* mp = xdp_multiprog__get_from_ifindex(cfg.ifindex);
        if ( mp && libxdp_get_error(mp) == 0 ) {
            struct xdp_program* prog = nullptr;
            // Loop through all programs to find the shunter
            while ( (prog = xdp_multiprog__next_prog(prog, mp)) ) {
                if ( std::string_view(xdp_program__name(prog)) == "xdp_shunt" ) {
                    is_shunter_attached = true;
                    prog_id = xdp_program__id(prog);
                    break;
                }
            }
        }

        if ( is_shunter_attached )
            std::cout << "Shunter is attached on interface " << *cfg.ifname << "\n\n";
        else
            std::cout << "Shunter is NOT attached on interface " << *cfg.ifname << "\n\n";
    }

    {
        auto flow_map_path = cfg.pin_path + "/shunt_map";
        auto flow_map_fd = bpf_obj_get(flow_map_path.c_str());

        if ( flow_map_fd < 0 )
            std::cout << "Flow map not found at " << flow_map_path << "\n";
        else {
            size_t count = count_map(flow_map_fd, sizeof(canonical_tuple));

            auto flow = count == 1 ? " flow" : " flows";
            std::cout << count << flow << " actively shunted\n";

            close(flow_map_fd);
        }
    }

    {
        auto ip_pair_map_path = cfg.pin_path + "/ip_pair_map";
        auto ip_pair_map_fd = bpf_obj_get(ip_pair_map_path.c_str());

        if ( ip_pair_map_fd < 0 )
            std::cout << "IP pair map not found at " << ip_pair_map_path << "\n";
        else {
            size_t count = count_map(ip_pair_map_fd, sizeof(canonical_tuple));

            auto pairs = count == 1 ? " IP pair" : " IP pairs";
            std::cout << count << pairs << " actively shunted\n";

            close(ip_pair_map_fd);
        }
    }
}
} // namespace zeek::xdp::shunt
