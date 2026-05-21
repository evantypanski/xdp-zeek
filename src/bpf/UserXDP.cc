#include "UserXDP.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <filesystem>
#include <optional>
#include <string>

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

std::pair<int, int> reuse_maps(std::string pin_path) {
    // Exit if the map dir doesn't exist
    if ( ! std::filesystem::exists(pin_path) )
        return {-1, -1};//"Pin path " + std::string(pin_path) + " does not exist";

    // Check each map...
    auto filter_map = pin_path + std::string("/filter_map");
    auto filter_map_fd = bpf_obj_get(filter_map.c_str());
    if ( filter_map_fd < 0 )
        return {-1, -1};//"Pinned canonical ID map not found at " + filter_map;

    auto ip_pair_map = pin_path + std::string("/ip_pair_map");
    auto ip_pair_map_fd = bpf_obj_get(ip_pair_map.c_str());
    if ( ip_pair_map_fd < 0 )
        return {-1, -1};//"Pinned IP pair map not found at " + ip_pair_map;

    // No need to load the program.
    return {filter_map_fd, ip_pair_map_fd};
}

template<SupportedBpfKey Key>
std::optional<std::string> update_map(int fd, Key* key) {
    auto val = shunt_val{0};
    auto err = bpf_map_update_elem(fd, key, &val, BPF_ANY);
    if ( err ) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        return std::string(err_buf);
    }

    return {};
}

template std::optional<std::string> update_map<canonical_tuple>(int fd, canonical_tuple* key);
template std::optional<std::string> update_map<ip_pair_key>(int fd, ip_pair_key* key);

template<SupportedBpfKey Key>
std::optional<std::string> remove_from_map(int fd, const Key* key) {
    auto err = bpf_map_delete_elem(fd, key);
    if ( err ) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        return std::string(err_buf);
    }

    return {};
}

template std::optional<std::string> remove_from_map<canonical_tuple>(int fd, const canonical_tuple* key);
template std::optional<std::string> remove_from_map<ip_pair_key>(int fd, const ip_pair_key* key);

template<SupportedBpfKey Key>
std::map<Key, struct shunt_val> get_map(int fd) {
    std::map<Key, struct shunt_val> found_map;
    Key next_key;
    Key* prev_key = nullptr;
    while ( bpf_map_get_next_key(fd, prev_key, &next_key) == 0 ) {
        shunt_val value;
        if ( bpf_map_lookup_elem(fd, &next_key, &value) != 0 )
            // TODO: what would I do?
            return {};

        found_map[next_key] = value;
        prev_key = &next_key;
    }

    return found_map;
}

template std::map<canonical_tuple, struct shunt_val> get_map<canonical_tuple>(int fd);
template std::map<ip_pair_key, struct shunt_val> get_map<ip_pair_key>(int fd);

template<SupportedBpfKey Key>
std::optional<shunt_val> get_val(int fd, Key* key) {
    shunt_val value;

    if ( bpf_map_lookup_elem(fd, key, &value) != 0 )
        return std::nullopt;

    return value;
}

template std::optional<shunt_val> get_val<canonical_tuple>(int fd, canonical_tuple* key);
template std::optional<shunt_val> get_val<ip_pair_key>(int fd, ip_pair_key* key);
} // namespace zeek::plugin::detail::Zeek_XDP_Shunter
