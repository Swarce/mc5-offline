// gameplay.hpp — game-thread services for the server (cheat bytes, zone table walk,
// local bot match). See gameplay.cpp. C++17.
#pragma once

#include <string>

#include "../../server/services/services.hpp"

namespace mc5 {
namespace gameplay {

void set_context(ServerContext* ctx);
// Quick Play -> locally hosted match with bots (settings bots.quickPlay / searchSeconds*).
void configure_quick_play(bool enabled, int search_min_s, int search_max_s);
// Installs the per-frame pump hook and the bot tick hook (after libMC5 is loaded).
int install();
// Queued for the next game frame:
void queue_cheats(bool god, bool ammo, bool medkits);
void queue_zone_walk();                 // runs ~2 s later, read twice and compared
std::string queue_bot_match(int bots);  // "" queued, else why not

} // namespace gameplay
} // namespace mc5
