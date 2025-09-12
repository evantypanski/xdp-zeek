global xdp_prog: opaque of XDP::Program;

event zeek_init() {
    xdp_prog = XDP::start_shunt();
}

event http_request(c: connection, method: string, original_URI: string,
    unescaped_URI: string, version: string)
    {
    print fmt("HTTP request: %s %s (%s->%s)", method, original_URI, c$id$orig_h,
        c$id$resp_h);
    XDP::drop(xdp_prog, c$id);
    }

event zeek_done() {
    XDP::end_shunt(xdp_prog);
}
