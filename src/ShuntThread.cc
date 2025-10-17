#include "ShuntThread.h"

#include <zeek/Event.h> // TODO remove
#include <iostream>     // TODO remove

#include "event.bif.h"

zeek::EventMgr zeek::event_mgr;

namespace xdp::shunter::detail {
// Callback function remains the same
int ShuntThread::handle_event(void* ctx, void* data, size_t data_sz) {
    const canonical_fin* fin = static_cast<const canonical_fin*>(data);
    // std::cout << "Event: PID=" << e->pid << ", CMD=" << e->command << std::endl;
    auto zeek_key = zeek::make_intrusive<zeek::RecordVal>(zeek::id::conn_id);
    if ( IN6_IS_ADDR_V4MAPPED(&fin->key.ip1) )
        zeek_key->Assign(0, zeek::make_intrusive<zeek::AddrVal>(
                                *reinterpret_cast<const uint32_t*>(&fin->key.ip1.s6_addr[12])));
    else
        zeek_key->Assign(0,
                         zeek::make_intrusive<zeek::AddrVal>(reinterpret_cast<const uint32_t*>(&fin->key.ip1.s6_addr)));

    zeek_key->Assign(1, zeek::val_mgr->Port(fin->key.port1));

    if ( IN6_IS_ADDR_V4MAPPED(&fin->key.ip2) )
        zeek_key->Assign(2, zeek::make_intrusive<zeek::AddrVal>(
                                *reinterpret_cast<const uint32_t*>(&fin->key.ip2.s6_addr[12])));
    else
        zeek_key->Assign(2,
                         zeek::make_intrusive<zeek::AddrVal>(reinterpret_cast<const uint32_t*>(&fin->key.ip2.s6_addr)));

    zeek_key->Assign(3, zeek::val_mgr->Port(fin->key.port2));
    zeek_key->Assign(4, zeek::val_mgr->Count(fin->key.protocol));

    zeek::event_mgr.Enqueue(sawfin, zeek_key);

    return 0;
}
} // namespace xdp::shunter::detail
