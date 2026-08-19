#include "soter.hpp"
#include "logging.hpp"
#include "lsplt.hpp"

#include <string>

qsee_send_fn_t real_qsee_send = nullptr;

static bool is_soter_target(const std::string& path) {
    return path ==
               "/vendor/lib64/libQSEEComAPI.so" ||
           path ==
               "/vendor/lib64/hw/vendor.qti.hardware.soter-impl.so";
}

extern "C"
[[gnu::visibility("default")]]
bool entry(void* /*handle*/) {

    LOGI("[SOTER] service started");

    auto maps = lsplt::MapInfo::Scan();

    bool registered = false;

    for (const auto& map : maps) {
        if (map.path.empty() || map.inode == 0) {
            continue;
        }

        if (!is_soter_target(map.path)) {
            continue;
        }

        LOGI("[SOTER] registering QSEECom_send_cmd hook: %s",
             map.path.c_str());

        lsplt::RegisterHook(
            map.dev,
            map.inode,
            "QSEECom_send_cmd",
            reinterpret_cast<void*>(
                soter_qsee_send_cmd_hook),
            reinterpret_cast<void**>(
                &real_qsee_send));

        registered = true;
    }

    if (!registered) {
        LOGE("[SOTER][ERR] QSEEComAPI target not found");
        return false;
    }

    lsplt::CommitHook();

    if (real_qsee_send == nullptr) {
        LOGE("[SOTER][ERR] original QSEECom_send_cmd unresolved");
        return false;
    }

    LOGI("[SOTER] QSEECom_send_cmd hook installed");

    return true;
}
