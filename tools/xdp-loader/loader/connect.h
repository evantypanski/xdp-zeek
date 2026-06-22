#pragma once

#include <net/if.h>
#include <xdp/libxdp.h>
#include <optional>
#include <string>

#include "options.h"

namespace zeek::xdp {
/**
 * Loads and attaches to the XDP program.
 */
std::optional<std::string> load(const options::config& cfg);

/**
 * Unloads all XDP programs, and optionally the pinned maps at pin_path.
 */
void unload_all(const options::config& cfg);
} // namespace zeek::xdp
