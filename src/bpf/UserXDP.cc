#include "UserXDP.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <filesystem>
#include <optional>
#include <string>

#include "filter.skel.h"
#include "filter_common.h"

bool operator<(const canonical_tuple& lhs, const canonical_tuple& rhs) {
    auto ip1_cmp = compare_ips(&lhs.ip1, &rhs.ip1);
    if ( ip1_cmp != 0 )
        return ip1_cmp < 0;

    auto ip2_cmp = compare_ips(&lhs.ip2, &rhs.ip2);
    if ( ip2_cmp != 0 )
        return ip2_cmp < 0;

    if ( lhs.port1 != rhs.port1 )
        return lhs.port1 < rhs.port1;

    if ( lhs.port2 != rhs.port2 )
        return lhs.port2 < rhs.port2;

    return lhs.protocol < rhs.protocol;
}

bool operator<(const ip_pair_key& lhs, const ip_pair_key& rhs) {
    int ip1_cmp = compare_ips(&lhs.ip1, &rhs.ip1);
    if ( ip1_cmp != 0 )
        return ip1_cmp < 0;

    int ip2_cmp = compare_ips(&lhs.ip2, &rhs.ip2);
    return ip2_cmp < 0;
}

namespace zeek::plugin::detail::Zeek_XDP_Shunter {

std::optional<std::string> reuse_maps(struct filter** skel, std::string pin_path) {
    // Exit if the map dir doesn't exist
    if ( ! std::filesystem::exists(pin_path) )
        return "Pin path " + std::string(pin_path) + " does not exist";

    // Check each map...
    auto filter_map = pin_path + std::string("/filter_map");
    auto filter_map_fd = bpf_obj_get(filter_map.c_str());
    if ( filter_map_fd < 0 )
        return "Pinned canonical ID map not found at " + filter_map;

    auto ip_pair_map = pin_path + std::string("/ip_pair_map");
    auto ip_pair_map_fd = bpf_obj_get(filter_map.c_str());
    if ( ip_pair_map_fd < 0 )
        return "Pinned IP pair map not found at " + ip_pair_map;

    struct bpf_object_open_opts open_opts = {
        .sz = sizeof(struct bpf_object_open_opts),
    };
    *skel = filter::open(&open_opts);

    if ( ! *skel )
        return "Failed to open BPF skeleton";

    bpf_map__reuse_fd(get_canonical_id_map(*skel), filter_map_fd);
    bpf_map__reuse_fd(get_ip_pair_map(*skel), ip_pair_map_fd);

    // No need to load the program.
    return {};
}

void release_maps(struct filter** skel) {
    filter::destroy(*skel);
    *skel = nullptr;
}

struct bpf_map* get_canonical_id_map(struct filter* skel) { return skel->maps.filter_map; }
struct bpf_map* get_ip_pair_map(struct filter* skel) { return skel->maps.ip_pair_map; }

template<SupportedBpfKey Key>
std::optional<std::string> update_map(struct bpf_map* map, Key* key) {
    auto val = shunt_val{0};
    auto err = bpf_map_update_elem(bpf_map__fd(map), key, &val, BPF_ANY);
    if ( err ) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        return std::string(err_buf);
    }

    return {};
}

template std::optional<std::string> update_map<canonical_tuple>(struct bpf_map* map, canonical_tuple* key);
template std::optional<std::string> update_map<ip_pair_key>(struct bpf_map* map, ip_pair_key* key);

template<SupportedBpfKey Key>
std::optional<std::string> remove_from_map(struct bpf_map* map, const Key* key) {
    auto err = bpf_map_delete_elem(bpf_map__fd(map), key);
    if ( err ) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        return std::string(err_buf);
    }

    return {};
}

template std::optional<std::string> remove_from_map<canonical_tuple>(struct bpf_map* map, const canonical_tuple* key);
template std::optional<std::string> remove_from_map<ip_pair_key>(struct bpf_map* map, const ip_pair_key* key);

template<SupportedBpfKey Key>
std::map<Key, struct shunt_val> get_map(struct bpf_map* map) {
    std::map<Key, struct shunt_val> found_map;
    Key next_key;
    Key* prev_key = nullptr;
    while ( bpf_map_get_next_key(bpf_map__fd(map), prev_key, &next_key) == 0 ) {
        shunt_val value;
        if ( bpf_map_lookup_elem(bpf_map__fd(map), &next_key, &value) != 0 )
            // TODO: what would I do?
            return {};

        found_map[next_key] = value;
        prev_key = &next_key;
    }

    return found_map;
}

template std::map<canonical_tuple, struct shunt_val> get_map<canonical_tuple>(struct bpf_map* map);
template std::map<ip_pair_key, struct shunt_val> get_map<ip_pair_key>(struct bpf_map* map);

template<SupportedBpfKey Key>
std::optional<shunt_val> get_val(struct bpf_map* map, Key* key) {
    shunt_val value;

    if ( bpf_map_lookup_elem(bpf_map__fd(map), key, &value) != 0 )
        return std::nullopt;

    return value;
}

template std::optional<shunt_val> get_val<canonical_tuple>(struct bpf_map* map, canonical_tuple* key);
template std::optional<shunt_val> get_val<ip_pair_key>(struct bpf_map* map, ip_pair_key* key);
} // namespace zeek::plugin::detail::Zeek_XDP_Shunter
