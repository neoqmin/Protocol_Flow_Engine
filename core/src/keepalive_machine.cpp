#include "pf/keepalive_machine.h"

namespace pf {

MachineDocument keepalive_machine_document() {
    MachineBuilder b("keepalive");
    b.doc().description = "OpenVPN data-channel keepalive (ping / ping-restart) as a state machine; equivalent to KeepaliveTimer";
    b.event("packet:sent").event("packet:received").output("ping")
        .timer_param("restart", "restartMs", true)
        .timer_param("ping", "pingMs", true)
        .initial("init").state("alive").final_failed("dead")
        .transition("init", "auto", "alive").act({"arm:restart", "arm:ping"})
        .transition("alive", "packet:sent", "alive").act({"arm:ping"})
        .transition("alive", "packet:received", "alive").act({"arm:restart"})
        .transition("alive", "timer:restart", "dead")
        .transition("alive", "timer:ping", "alive").act({"emit:ping", "arm:ping"})
        .unbounded("keepalive pings for the whole session; the restart timer or the session ends it");
    return b.doc();
}

}  // namespace pf
