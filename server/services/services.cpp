#include "services.hpp"

namespace mc5 {

void register_services(Router& router, ServerContext& ctx) {
    // Service names pandora/locate hands out as a path prefix. A request that
    // arrives prefixed (e.g. "/auth/authorize") is retried with the prefix
    // stripped so it reaches the root-registered route ("authorize").
    router.set_service_prefixes({
        "auth", "storage", "message", "feeds", "leaderboard", "social", "asset",
        "matchmaker", "lobby", "lottery", "voice", "config", "alert", "schedule",
        "transaction", "groupchat", "game_stats", "crm", "assets",
    });

    // Order: specific service routes first, catch-all fallback last.
    register_core(router, ctx);
    register_eve(router, ctx);
    register_pandora(router, ctx);
    register_auth(router, ctx);
    register_misc(router, ctx); // installs the fallback
}

} // namespace mc5
