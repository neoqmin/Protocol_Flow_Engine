#pragma once
#include "pf/machine.h"

namespace pf {

// KeepaliveTimer (keepalive.h) expressed as a State Machine: the first equivalence proof of F-1 (plan S4, D-041).
// tests/flow/test_machine_keepalive.cpp drives both with the same random event/time sequences and requires identical
// behaviour; tests/regression/golden/machine_keepalive.machine.json is this document's canonical file.
//
//   params   pingMs, restartMs   (0 = disabled, like OpenVPN `ping 0` / `ping-restart 0`)
//   events   packet:sent      we transmitted something        -> re-arm ping
//            packet:received  an authenticated packet arrived  -> re-arm restart
//   output   ping             send a keepalive ping now
//   final    dead (failed)    nothing received for restartMs
//
// Timer order matters: restart is declared first so that, when both fall due at the same instant, the peer is declared
// dead instead of pinged (KeepaliveTimer checks ping-restart first). Timers are delivered at their deadlines (the event
// loop sleeps until next_deadline_ms); if a caller polls late, past BOTH deadlines, the machine still fires them in
// deadline order (one last ping, then dead) where KeepaliveTimer reports only the timeout.
MachineDocument keepalive_machine_document();

}  // namespace pf
