module NetControl;

export {
	## Instantiates the plugin.
	global create_xdp_shunt: function(): PluginState;

	## Shunts a connection (bidirectional)
	global shunt_connection: function(cid: conn_id, t: interval, location: string
	    &default=""): string;
}

function shunt_name(p: PluginState): string
	{
	return "NetControl XDP shunting plugin";
	}

function xdp_shunt_add_rule_fun(p: PluginState, r: Rule): bool
	{
	# This only applies to dropping bidirectional connections
	if ( r$ty != DROP || r$target != MONITOR || ! r$entity?$conn )
		return F;

	local result = XDP::Shunt::ConnID::__shunt(XDP::xdp_fds$filter_map_fd,
	    XDP::conn_id_to_canonical(r$entity$conn));

	if ( result )
		{
		event NetControl::rule_added(r, p);
		}

	return result;
	}

function xdp_shunt_remove_rule_fun(p: PluginState, r: Rule, reason: string
    &default=""): bool
	{
	# This only applies to dropping bidirectional connections
	if ( r$ty != DROP || r$target != MONITOR || ! r$entity?$conn )
		return F;

	local stats = XDP::Shunt::ConnID::__unshunt(XDP::xdp_fds$filter_map_fd,
	    XDP::conn_id_to_canonical(r$entity$conn));

	if ( stats$present )
		{
		# Build info record
		local info: XDP::Shunt::ConnID::Info = XDP::Shunt::ConnID::Info(
		    $id=r$entity$conn,
		    $bytes_shunted=stats$bytes_from_1 + stats$bytes_from_2, $packets_shunted=stats$packets_from_1 + stats$packets_from_2, );

		if ( stats?$timestamp )
			info$last_packet = stats$timestamp;

		# TODO: Should this be a different log?
		Log::write(XDP::Shunt::ConnID::LOG, info);

		event NetControl::rule_removed(r, p);
		}

	return stats$present;
	}

global xdp_shunt_plugin = Plugin($name=shunt_name, $can_expire=F,
    $add_rule=xdp_shunt_add_rule_fun, $remove_rule=xdp_shunt_remove_rule_fun);

function create_xdp_shunt(): PluginState
	{
	return PluginState($plugin=xdp_shunt_plugin);
	}

function shunt_connection(cid: conn_id, t: interval, location: string
    &default=""): string
	{
	local e = Entity($ty=CONNECTION, $conn=cid);
	local r = Rule($ty=DROP, $target=MONITOR, $entity=e, $expire=t,
	    $location=location);

	# Error should already be logged
	return add_rule(r);
	}
