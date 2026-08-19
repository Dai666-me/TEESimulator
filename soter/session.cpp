#include "soter.hpp"
#include "logging.hpp"
#include <map>
#include <mutex>
#include <cstdint>
#include <vector>
#include <string>
#include <inttypes.h>

struct SoterSession {
    uint64_t id;
    int uid;
    std::string name;
    std::vector<uint8_t> data; // arbitrary payload saved at initSign
};

static std::mutex g_sessions_mu;
static std::map<uint64_t, SoterSession> g_sessions;
static uint64_t g_next_session = 1;

uint64_t create_session(int uid, const std::string& name, const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lk(g_sessions_mu);
    uint64_t id = g_next_session++;
    SoterSession s;
    s.id = id;
    s.uid = uid;
    s.name = name;
    s.data = data;
    g_sessions[id] = s;
    LOGI("[SOTER] session created id=0x%016" PRIx64 " uid=%d name=%s", id, uid, name.c_str());
    return id;
}

bool get_session(uint64_t id, SoterSession &out) {
    std::lock_guard<std::mutex> lk(g_sessions_mu);
    auto it = g_sessions.find(id);
    if (it == g_sessions.end()) return false;
    out = it->second;
    return true;
}

bool remove_session(uint64_t id) {
    std::lock_guard<std::mutex> lk(g_sessions_mu);
    auto n = g_sessions.erase(id);
    if (n) LOGI("[SOTER] session removed id=0x%016" PRIx64, id);
    return n > 0;
}
