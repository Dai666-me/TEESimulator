#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace soter {

constexpr uint32_t CMD_GENERATE_ATTK = 0x101;
constexpr uint32_t CMD_VERIFY_ATTK   = 0x102;
constexpr uint32_t CMD_EXPORT_ATTK   = 0x103;
constexpr uint32_t CMD_GET_DEVICE_ID = 0x104;

constexpr uint32_t CMD_GENERATE_ASK  = 0x105;
constexpr uint32_t CMD_EXPORT_ASK    = 0x106;
constexpr uint32_t CMD_HAS_ASK       = 0x107;
constexpr uint32_t CMD_REMOVE_ALL_UID = 0x108;

constexpr uint32_t CMD_GENERATE_AUTH = 0x109;
constexpr uint32_t CMD_EXPORT_AUTH   = 0x10A;
constexpr uint32_t CMD_REMOVE_AUTH   = 0x10B;
constexpr uint32_t CMD_HAS_AUTH      = 0x10C;

constexpr uint32_t CMD_INIT_SIGN     = 0x10D;
constexpr uint32_t CMD_FINISH_SIGN   = 0x10E;

constexpr bool is_soter_command(uint32_t cmd) {
    switch (cmd) {
        case CMD_GENERATE_ATTK:
        case CMD_VERIFY_ATTK:
        case CMD_EXPORT_ATTK:
        case CMD_GET_DEVICE_ID:
        case CMD_GENERATE_ASK:
        case CMD_EXPORT_ASK:
        case CMD_HAS_ASK:
        case CMD_REMOVE_ALL_UID:
        case CMD_GENERATE_AUTH:
        case CMD_EXPORT_AUTH:
        case CMD_REMOVE_AUTH:
        case CMD_HAS_AUTH:
        case CMD_INIT_SIGN:
        case CMD_FINISH_SIGN:
            return true;
        default:
            return false;
    }
}

/*
 * IMPORTANT:
 *
 * This is deliberately NOT a generic
 *
 *   status | payload_length | payload
 *
 * structure.
 *
 * The Qualcomm TA response ABI is command-specific and must be
 * constructed according to the reverse-engineered response layout.
 */
struct TaResponse {
    bool handled = false;

    /*
     * Raw response bytes that will be copied to the buffer supplied
     * by QSEECom_send_cmd().
     *
     * The contents are command-specific.
     */
    std::vector<uint8_t> bytes;

    /*
     * Return value of QSEECom_send_cmd().
     *
     * Normally 0 for a successfully handled Soter command.
     */
    int transport_status = 0;
};

} // namespace soter

using qsee_send_fn_t =
    int (*)(void* handle,
            void* cmd,
            uint32_t cmd_len,
            void* resp,
            uint32_t* resp_len);

extern "C" bool entry(void* handle);

extern "C" int soter_qsee_send_cmd_hook(
    void* handle,
    void* cmd,
    uint32_t cmd_len,
    void* resp,
    uint32_t* resp_len);
