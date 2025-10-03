#include <zeek/IntrusivePtr.h>
#include <zeek/OpaqueVal.h>

#include "bpf/UserXDP.h"

namespace xdp::shunter::detail {

extern zeek::OpaqueTypePtr program_opaque;

class XDPProgramVal : public zeek::OpaqueVal {
public:
    XDPProgramVal() : zeek::OpaqueVal(program_opaque) {}
    XDPProgramVal(struct filter* prog) : OpaqueVal(detail::program_opaque), prog(prog) {}
    ~XDPProgramVal() override = default;

    static zeek::expected<xdp::shunter::detail::XDPProgramVal*, std::string> CastFromAny(Val* prog) {
        if ( prog->GetType() != detail::program_opaque )
            return zeek::unexpected<std::string>("Invalid XDP program");

        auto xdp_prog = dynamic_cast<xdp::shunter::detail::XDPProgramVal*>(prog);
        if ( ! xdp_prog )
            return zeek::unexpected<std::string>("Invalid XDP program");

        return xdp_prog;
    }

    struct filter* prog;

protected:
    zeek::IntrusivePtr<Val> DoClone(CloneState* state) override { return {zeek::NewRef{}, this}; }

    DECLARE_OPAQUE_VALUE_DATA(XDPProgramVal)
};
using XDPProgramPtr = zeek::IntrusivePtr<struct xdp_program>;

} // namespace xdp::shunter::detail
