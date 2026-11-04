// message (Hermes mailbox) + push transports. The client reads its inbox/secured
// mailboxes on session start; those reads are ARRAYS of messages, not objects. The
// old catch-all answered "{}", which the messaging transport can't iterate. Return
// empty arrays for mailbox reads and status for the push-endpoint registrations.
// Shapes per the MCVS Hermes contract (report 02 §M).
//   GET  messages/{transport}/me[?delete=delete]      -> []   (array of messages)
//   POST messages/{transport}/{credential}            -> status (send)
//   POST messages/{transport}/multicast               -> status
//   POST transports/{transport}/endpoints/{endpoint}  -> status (push register)
//   POST transports/{transport}/endpoints/delete      -> status

#include "services.hpp"

#include "../core/http.hpp"

namespace mc5 {

void register_message(Router& router, ServerContext& /*ctx*/) {
    // Mailbox reads: empty arrays (the client iterates them).
    router.add("GET", "messages/{transport}/me", [](const Request&) { return Response::json("[]"); });
    // Push-transport endpoint registration / removal: status only.
    router.add("POST", "transports/{transport}/endpoints/delete", [](const Request&) { return Response::json("{}"); });
    router.add("POST", "transports/{transport}/endpoints/{*endpoint}", [](const Request&) { return Response::json("{}"); });
    // Sends (not used by the boot, but answer cleanly).
    router.add("POST", "messages/{transport}/multicast", [](const Request&) { return Response::json("{}"); });
    router.add("POST", "messages/{transport}/{credential}", [](const Request&) { return Response::json("{}"); });
}

} // namespace mc5
