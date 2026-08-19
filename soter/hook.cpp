#include "soter.hpp"
#include "logging.hpp"

#include <cstring>
#include <exception>
#include <mutex>

extern qsee_send_fn_t real_qsee_send;

extern soter::TaResponse soter_handle_command(
    uint32_t command,
    const uint8_t* request,
    size_t request_size);

static std::mutex g_soter_mutex;

extern "C" int soter_qsee_send_cmd_hook(
    void* handle,
    void* cmd,
    uint32_t cmd_len,
    void* resp,
    uint32_t* resp_len) {

    /*
     * Never interfere with malformed calls.
     */
    if (cmd == nullptr || cmd_len < sizeof(uint32_t)) {
        if (real_qsee_send != nullptr) {
            return real_qsee_send(
                handle, cmd, cmd_len, resp, resp_len);
        }

        return -1;
    }

    uint32_t command = 0;
    std::memcpy(&command, cmd, sizeof(command));

    /*
     * Do NOT use:
     *
     *   command >= 0x101 && command <= 0x10E
     *
     * because that could accidentally consume another QSEE command.
     */
    if (!soter::is_soter_command(command)) {
        if (real_qsee_send != nullptr) {
            return real_qsee_send(
                handle, cmd, cmd_len, resp, resp_len);
        }

        return -1;
    }

    LOGI("[SOTER] QSEE command 0x%03x", command);

    soter::TaResponse response;

    try {
        std::lock_guard<std::mutex> lock(g_soter_mutex);

        response = soter_handle_command(
            command,
            reinterpret_cast<const uint8_t*>(cmd),
            static_cast<size_t>(cmd_len));

    } catch (const std::exception& e) {
        LOGE("[SOTER][ERR] exception handling 0x%03x: %s",
             command,
             e.what());

        /*
         * Do NOT fabricate a Qualcomm TA error response here.
         *
         * Until the exact error response ABI is confirmed,
         * fail the intercepted operation at the transport layer.
         */
        return -1;
    }

    if (!response.handled) {
        /*
         * Backend explicitly declined the command.
         * Pass it to the real QSEE implementation.
         */
        if (real_qsee_send != nullptr) {
            return real_qsee_send(
                handle, cmd, cmd_len, resp, resp_len);
        }

        return -1;
    }

    if (response.transport_status != 0) {
        return response.transport_status;
    }

    if (resp == nullptr || resp_len == nullptr) {
        LOGE("[SOTER][ERR] missing response buffer");
        return -1;
    }

    const uint32_t capacity = *resp_len;
    const size_t response_size = response.bytes.size();

    if (response_size > capacity) {
        LOGE(
            "[SOTER][ERR] response buffer too small: "
            "need=%zu capacity=%u command=0x%03x",
            response_size,
            capacity,
            command);

        /*
         * Never truncate a structured TA response.
         */
        return -1;
    }

    if (response_size != 0) {
        std::memcpy(
            resp,
            response.bytes.data(),
            response_size);
    }

    *resp_len = static_cast<uint32_t>(response_size);

    return 0;
}
