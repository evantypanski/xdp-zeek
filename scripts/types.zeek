module XDP;

export {
    type AttachMode: enum {
        UNSPEC = 0,
        NATIVE = 1,
        SKB = 2,
        HW = 3,
    };

    type ShuntOptions: record {
        attach_mode: AttachMode &default=UNSPEC;
        conn_id_map_max_size: count &default=65536; # Must be >1
        ip_pair_map_max_size: count &default=65536; # Must be >1
    };

    type ShuntedStats: record {
        packets_from_1: count; # From IP1, or orig in conn_id
        bytes_from_1: count; # From IP1, or orig in conn_id
        packets_from_2: count; # From IP2, or resp in conn_id
        bytes_from_2: count; # From IP2, or resp in conn_id
        fin: count; # The number of TCP fin packets shunted
        rst: count; # The number of TCP rst packets shunted
        timestamp: time &optional; # The last shunted timestamp seen, if any

        present: bool; # If this means anything :) probably a better way
    };

    type shunt_table: table[conn_id] of ShuntedStats;

    type ip_pair: record {
        ip1: addr;
        ip2: addr;
    };

    type ip_pair_shunt_table: table[ip_pair] of ShuntedStats;
}
