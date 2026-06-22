#include "connect.h"

#include <unistd.h>
#include <linux/if_link.h>
#include <filesystem>

#include "shunt.h"

namespace zeek::xdp {

std::optional<std::string> load(const options::config& cfg) {
    if ( cfg.force )
        unload_all(cfg);

    if ( cfg.load_shunter ) {
        if ( auto err = zeek::xdp::shunt::load_shunter(cfg) )
            return err;
    }

    return {};
}

void unload_all(const options::config& cfg) {
    bpf_xdp_detach(cfg.ifindex, XDP_FLAGS_DRV_MODE, nullptr);
    bpf_xdp_detach(cfg.ifindex, XDP_FLAGS_SKB_MODE, nullptr);

    if ( cfg.force && std::filesystem::exists(cfg.pin_path) )
        std::filesystem::remove_all(cfg.pin_path);
}
} // namespace zeek::xdp
