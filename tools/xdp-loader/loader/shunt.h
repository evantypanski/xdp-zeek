#pragma once

#include <net/if.h>
#include <xdp/libxdp.h>
#include <optional>
#include <string>

#include "options.h"
#include "shunter.skel.h"

namespace zeek::xdp::shunt {

struct bpf_map* get_canonical_id_map(struct shunter* skel);
struct bpf_map* get_ip_pair_map(struct shunter* skel);

std::optional<std::string> load_shunter(const options::config& cfg);
void status(const options::config& cfg);

}
