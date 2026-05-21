// See the file "COPYING" in the main distribution directory for copyright.

/* Common BPF/XDP functions used by userspace side programs */
#pragma once

#include <net/if.h>
#include <concepts>
#include <map>
#include <optional>
#include <string>

#include "filter_common.h"

struct filter;
struct bpf_map;

namespace zeek::plugin::detail::Zeek_XDP_Shunter {

#ifndef __LIBXDP_LIBXDP_H
enum xdp_action { // NOLINT(performance-enum-size)
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

struct ring_buffer;
#endif

// Helper
template<typename T, typename... U>
concept IsAnyOf = (std::same_as<T, U> || ...);

// Possible key values
template<typename T>
concept SupportedBpfKey = IsAnyOf<T, canonical_tuple, ip_pair_key>;

/**
 * Reuses the maps from an already-existing XDP shunter.
 *
 * This is the preferred way of connecting Zeek to the XDP program so that
 * the brittle Zeek process is not in charge of the health of the XDP
 * program.
 */
std::pair<int, int> reuse_maps(std::string pin_path);

/** Adds a key to the map. */
template<SupportedBpfKey Key>
std::optional<std::string> update_map(int fd, Key* key);

/** Removes a key to the map. */
template<SupportedBpfKey Key>
std::optional<std::string> remove_from_map(int fd, const Key* key);

/** Retrieves the keys and elements of a given map. */
template<SupportedBpfKey Key>
std::map<Key, struct shunt_val> get_map(int fd);

/** Retrieves the value of a given key in a map, if any. */
template<SupportedBpfKey Key>
std::optional<shunt_val> get_val(int fd, Key* key);

} // namespace zeek::plugin::detail::Zeek_XDP_Shunter
