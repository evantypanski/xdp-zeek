#include "options.h"

#include <net/if.h>
#include <CLI/CLI.hpp>
#include <iostream>
#include <system_error>

#include "CLI/CLI.hpp"

namespace options {

void add_load_cmd(CLI::App* app, options::config* cfg) {
    auto* load_cmd = app->add_subcommand("load", "load XDP programs on an interface");

    load_cmd->add_option("-d,--dev", cfg->ifname, "network interface device")->required();
    load_cmd->add_option("-m,--mode", cfg->attach_mode, "XDP attachment mode")
        ->transform(CLI::CheckedTransformer(mode_map, CLI::ignore_case))
        ->capture_default_str();

    load_cmd->add_flag("--shunter", cfg->load_shunter, "load XDP shunter");
    load_cmd
        ->add_option("--shunt-flow-map-max-entries", cfg->conn_id_map_max_size,
                     "max number of entries in shunt flow map")
        ->check(CLI::PositiveNumber);
    load_cmd
        ->add_option("--shunt-ip-pair-map-max-entries", cfg->ip_pair_map_max_size,
                     "max number of entries in shunt IP pair map")
        ->check(CLI::PositiveNumber);
    load_cmd->add_flag("--include-vlan", cfg->include_vlan, "include VLANs in shunt keys");

    load_cmd->add_flag("-F,--force", cfg->force, "force overwrite all XDP programs on interface");
}

void add_unload_cmd(CLI::App* app, options::config* cfg) {
    auto* unload_cmd = app->add_subcommand("unload", "unload XDP programs on an interface");
    unload_cmd->add_option("-d,--dev", cfg->ifname, "network interface device")->required();
    unload_cmd->add_flag("-F,--force", cfg->force, "force complete unloading (including maps)");
}

void add_shunt_status_cmd(CLI::App* app, options::config* cfg) {
    auto* status_cmd = app->add_subcommand("shunt-status", "print the current shunter status");
    status_cmd->add_option("-d,--dev", cfg->ifname, "network interface device to check if shunter is loaded");
}

bool parse_cmdline(int argc, char** argv, options::config* cfg) {
    CLI::App app{"Zeek XDP loader"};

    app.add_option("--pin-path", cfg->pin_path, "BPF pin directory");

    add_load_cmd(&app, cfg);
    add_unload_cmd(&app, cfg);
    add_shunt_status_cmd(&app, cfg);

    try {
        app.parse(argc, argv);
    } catch ( const CLI::ParseError& e ) {
        return app.exit(e) == 0;
    }

    // get interface index
    if ( auto dev = cfg->ifname ) {
        cfg->ifindex = if_nametoindex(dev->c_str());

        if ( cfg->ifindex == 0 ) {
            auto error_msg = std::system_error(errno, std::generic_category()).what();
            std::cerr << "ERR: --dev name unknown: " << error_msg << "\n";

            return false;
        }
    }

    // Set command state
    if ( app.got_subcommand("load") )
        cfg->cmd = options::Command::Load;
    else if ( app.got_subcommand("unload") )
        cfg->cmd = options::Command::Unload;
    else if ( app.got_subcommand("shunt-status") )
        cfg->cmd = options::Command::ShuntStatus;

    return true;
}

} // namespace options
