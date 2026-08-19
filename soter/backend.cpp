#include "soter.hpp"
#include "logging.hpp"

#include <cstdint>
#include <cstddef>
#include <cstring>

#include <mutex>
#include <vector>

/*
 * Soter backend
 *
 * IMPORTANT:
 *
 * This file intentionally does NOT invent a Qualcomm Soter TA
 * request/response format.
 *
 * The exact command structures must be recovered from the real
 * vendor.qti.hardware.soter-impl.so before software responses are
 * generated.
 *
 * Therefore this stage only:
 *
 *   1. identifies Soter commands;
 *   2. records the raw request;
 *   3. provides a clean backend boundary;
 *   4. does NOT fabricate a response;
 *   5. returns handled=false until the corresponding command ABI
 *      has been confirmed.
 *
 * This prevents an incorrect response layout from being treated
 * as a real Soter TA implementation.
 */

namespace {

std::mutex g_backend_mutex;

static const char* command_name(uint32_t command) {
    switch (command) {
        case soter::CMD_GENERATE_ATTK:
            return "generateAttkKeyPair";

        case soter::CMD_VERIFY_ATTK:
            return "verifyAttkKeyPair";

        case soter::CMD_EXPORT_ATTK:
            return "exportAttkPublicKey";

        case soter::CMD_GET_DEVICE_ID:
            return "getDeviceId";

        case soter::CMD_GENERATE_ASK:
            return "generateAskKeyPair";

        case soter::CMD_EXPORT_ASK:
            return "exportAskPublicKey";

        case soter::CMD_HAS_ASK:
            return "hasAskAlready";

        case soter::CMD_REMOVE_ALL_UID:
            return "removeAllUidKey";

        case soter::CMD_GENERATE_AUTH:
            return "generateAuthKeyPair";

        case soter::CMD_EXPORT_AUTH:
            return "exportAuthKeyPublicKey";

        case soter::CMD_REMOVE_AUTH:
            return "removeAuthKey";

        case soter::CMD_HAS_AUTH:
            return "hasAuthKey";

        case soter::CMD_INIT_SIGN:
            return "initSign";

        case soter::CMD_FINISH_SIGN:
            return "finishSign";

        default:
            return "unknown";
    }
}


/*
 * Dump a bounded amount of the request.
 *
 * This is deliberately limited so that logging cannot accidentally
 * dump an arbitrarily large QSEE command buffer.
 *
 * Do NOT interpret these bytes here.
 */
static void log_request(
        uint32_t command,
        const uint8_t* request,
        size_t request_size) {

    if (request == nullptr || request_size == 0) {
        SLOGI(
            "[SOTER] %s cmd=0x%08x request_size=%zu",
            command_name(command),
            command,
            request_size);

        return;
    }

    constexpr size_t MAX_DUMP = 256;
    const size_t dump_size =
        request_size < MAX_DUMP ? request_size : MAX_DUMP;

    SLOGI(
        "[SOTER] %s cmd=0x%08x request_size=%zu dump=%zu",
        command_name(command),
        command,
        request_size,
        dump_size);

    /*
     * Do not assume a structure yet.
     *
     * The actual bytes can later be decoded after the request ABI
     * has been recovered from the real HAL.
     */
    for (size_t offset = 0; offset < dump_size; offset += 16) {
        char line[16 * 3 + 1];
        size_t pos = 0;

        const size_t remaining = dump_size - offset;
        const size_t count =
            remaining < 16 ? remaining : 16;

        for (size_t i = 0; i < count; ++i) {
            const int written = snprintf(
                line + pos,
                sizeof(line) - pos,
                "%02x ",
                request[offset + i]);

            if (written <= 0) {
                break;
            }

            pos += static_cast<size_t>(written);

            if (pos >= sizeof(line)) {
                break;
            }
        }

        line[pos < sizeof(line) ? pos : sizeof(line) - 1] = '\0';

        SLOGI(
            "[SOTER]   +0x%04zx: %s",
            offset,
            line);
    }

    if (dump_size < request_size) {
        SLOGI(
            "[SOTER]   ... %zu bytes omitted",
            request_size - dump_size);
    }
}


/*
 * Backend dispatcher.
 *
 * This is the ONLY place where command-specific software TA logic
 * should eventually be implemented.
 *
 * Do not add guessed command layouts here.
 */
static soter::TaResponse dispatch_command(
        uint32_t command,
        const uint8_t* request,
        size_t request_size) {

    soter::TaResponse result{};

    result.handled = false;
    result.transport_status = 0;

    switch (command) {

        case soter::CMD_GENERATE_ATTK:
            /*
             * TODO:
             *
             * Recover the real request/response ABI from:
             *
             *   Soter::generateAttkKeyPair()
             *       ->
             *   SoterUtils::send_cmd()
             *       ->
             *   QSEECom_send_cmd()
             *
             * Do NOT generate a response until the real TA response
             * structure is known.
             */
            break;

        case soter::CMD_VERIFY_ATTK:
            /*
             * TODO: recover real VERIFY_ATTK ABI.
             */
            break;

        case soter::CMD_EXPORT_ATTK:
            /*
             * TODO: recover real EXPORT_ATTK ABI.
             *
             * In particular, do NOT return PEM directly.
             */
            break;

        case soter::CMD_GET_DEVICE_ID:
            /*
             * TODO: recover real GET_DEVICE_ID ABI.
             */
            break;

        case soter::CMD_GENERATE_ASK:
            /*
             * TODO: recover real GENERATE_ASK ABI.
             */
            break;

        case soter::CMD_EXPORT_ASK:
            /*
             * TODO: recover real EXPORT_ASK ABI.
             */
            break;

        case soter::CMD_HAS_ASK:
            /*
             * TODO: recover real HAS_ASK ABI.
             */
            break;

        case soter::CMD_REMOVE_ALL_UID:
            /*
             * TODO: recover real REMOVE_ALL_UID ABI.
             */
            break;

        case soter::CMD_GENERATE_AUTH:
            /*
             * TODO: recover real GENERATE_AUTH ABI.
             */
            break;

        case soter::CMD_EXPORT_AUTH:
            /*
             * TODO: recover real EXPORT_AUTH ABI.
             */
            break;

        case soter::CMD_REMOVE_AUTH:
            /*
             * TODO: recover real REMOVE_AUTH ABI.
             */
            break;

        case soter::CMD_HAS_AUTH:
            /*
             * TODO: recover real HAS_AUTH ABI.
             */
            break;

        case soter::CMD_INIT_SIGN:
            /*
             * TODO: recover real INIT_SIGN ABI.
             *
             * The eventual implementation will create a software
             * signing session, but the request fields and response
             * structure must first be known.
             */
            break;

        case soter::CMD_FINISH_SIGN:
            /*
             * TODO: recover real FINISH_SIGN ABI.
             */
            break;

        default:
            break;
    }

    /*
     * request/request_size are intentionally unused for now.
     * They are retained in the interface because the eventual
     * implementation must decode the complete raw TA request.
     */
    (void)request;
    (void)request_size;

    return result;
}

} // namespace


/*
 * Called by hook.cpp after QSEECom_send_cmd() has identified a
 * Soter command.
 */
soter::TaResponse soter_handle_command(
        uint32_t command,
        const uint8_t* request,
        size_t request_size) {

    std::lock_guard<std::mutex> lock(g_backend_mutex);

    SLOGI(
        "[SOTER] dispatch %s cmd=0x%08x",
        command_name(command),
        command);

    log_request(
        command,
        request,
        request_size);

    /*
     * IMPORTANT:
     *
     * Do not fabricate a response.
     *
     * Returning handled=false causes hook.cpp to fall through to
     * the original QSEECom_send_cmd().
     *
     * This means this backend cannot break unrelated QSEE traffic
     * while we are still reverse-engineering the protocol.
     */
    return dispatch_command(
        command,
        request,
        request_size);
}
