// alert (Kairos): the long-lived push-alert stream the client opens as
// GET alerts/me?push_method=streaming&content_type=event-stream. It is a
// Server-Sent-Events stream that must stay OPEN: the client treats it as its live
// online connection. Returning an immediate 2-byte 200 (the old catch-all) read as
// a dropped connection and contributed to the post-login "connection error" popup.
//
// We hold the stream open with periodic keep-alives (handled by the server when
// Response::stream is set) and deliver no alerts yet. IMPORTANT: never push an alert
// of type "connection" here — the client treats that as "multiple connection
// detected" and kicks the session (MCVS AlertHub note). Real alert delivery (gifts,
// messages, social) is M1.

#include "services.hpp"

#include "../core/http.hpp"

namespace mc5 {

void register_alert(Router& router, ServerContext& /*ctx*/) {
    // Held-open SSE stream. The initial ": connected" comment line tells the client
    // the stream is live; the server then emits ": keep-alive" periodically.
    router.add("GET", "alerts/me", [](const Request&) { return Response::sse(": connected\n\n"); });
}

} // namespace mc5
