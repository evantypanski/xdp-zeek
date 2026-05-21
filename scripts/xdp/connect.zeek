##! Loads or reuses an XDP program. By default, loading
##! this means that an XDP program is already started, and two BPF
##! maps are found corresponding to the two ways to shunt traffic.
##!
##! You may also start the XDP program within this Zeek instance
##! by redefining :zeek:see:`XDP::start_new_xdp`.
module XDP;

@load ./main

export {
	## The directory that the BPF maps are pinned to.
	const pin_path: string = "/sys/fs/bpf/zeek" &redef;

	## If we should force not using VLANs, regardless of conn_id_ctx. This
	## is used to override the VLAN handling from loading the vlan conn key
	## factory if necessary. Note that VLANs must be included when loading the
	## XDP program as well.
	const force_no_vlans: bool = F &redef;

	## If we should load the XDP pins. By default, only load if it's in a
	## cluster worker or not in a cluster. This is helpful for any
	## nodes that don't read traffic, so they don't try to connect to
	## a possibly nonexistent map.
	const should_load: bool = Cluster::local_node_type() == Cluster::WORKER
	    || Cluster::local_node_type() == Cluster::NONE &redef;
}

function should_load_with_vlan(): bool
	{
	local fields = record_fields(conn_id_ctx);
	return "vlan" in fields && "inner_vlan" in fields;
	}

event zeek_init()
	{
	if ( ! should_load )
		return;

	vlans_included = ( ! force_no_vlans ) && should_load_with_vlan();

	reuse_maps(pin_path);
	}

event zeek_done()
	{
	release_maps();
	}
