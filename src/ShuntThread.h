#include <zeek/IntrusivePtr.h>
#include <zeek/OpaqueVal.h>

#include "bpf/UserXDP.h"

namespace xdp::shunter::detail {

class ShuntThread {
public:
    ShuntThread() = default;
    ShuntThread(struct filter* skel) : rb(make_shunt_fin_buffer(skel, handle_event)), running(true) { poller = std::thread(&ShuntThread::poll_loop, this); }
    ~ShuntThread() {}

    static int handle_event(void *ctx, void *data, size_t data_sz);

private:
    void poll_loop() {
        while ( running ) {
            poll_shunt_fin(rb, 100);
        }
    }
    std::thread poller;
    ring_buffer* rb = nullptr;
    std::atomic<bool> running = false;
};
} // namespace xdp::shunter::detail
