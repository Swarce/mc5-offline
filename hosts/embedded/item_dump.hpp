// item_dump.hpp — read the unlock-code item lists from the player's OWN in-memory game
// data (the armory built from armory.bin, and the killsig table). Nothing is shipped.
//
// Layouts are from libMC5 6.0.12a arm64 (docs/research/04-progression.md §10): the
// armory singleton A = *(base+0x1bbed40) (getter 0x4e5f98), libc++ std::vector
// {begin,end,cap} and std::string (0x18 bytes, standard layout). The game stores each
// item's FNV-1a-32 hash next to its name, so every list is self-checked element by
// element; a list that fails any check is dropped (logged), never guessed.
//
// Portable: all memory goes through a caller-supplied fault-safe reader, so the host
// unit test runs it over a synthetic memory image. C++17.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace mc5 {
namespace itemdump {

// Reads n bytes at addr into out; false if any byte is unreadable.
using ReadFn = std::function<bool(std::uint64_t addr, void* out, std::size_t n)>;

struct Result {
    // "classes" (soldier classes from skills.bin), "weapons", "attachments" ("<weapon>#<att>"), "camos", "gear" (masks, trinkets,
    // body pieces, body camos), "killsigs". Only items that are not free by default.
    std::map<std::string, std::vector<std::string>> groups;
    std::vector<std::string> notes; // per-list outcome, for the log
};

// armory = the armory object address; killsig_mgr = *(base+0x1bbed00) and skills_mgr =
// *(base+0x1bbed08) (0 to skip either).
Result dump(const ReadFn& rd, std::uint64_t armory, std::uint64_t killsig_mgr, std::uint64_t skills_mgr = 0);

// Exposed for tests.
std::uint32_t fnv1a(const std::string& s);

} // namespace itemdump
} // namespace mc5
