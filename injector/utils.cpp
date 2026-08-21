#include "utils.hpp"

#include <algorithm>  // === ADDED: for std::min ===
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sched.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "logging.hpp"

// Anonymous namespace for file-local constants and helper functions.
namespace {
constexpr size_t kMaxPathLengthInternal = PATH_MAX;
// constexpr size_t kMsgBufferSize = 64;  // === REMOVED: unused ===
constexpr size_t kStatusBufferSize = 128;
constexpr int kInvalidFd = -1;
constexpr uintptr_t kStackAlignmentMask = 0xf;

// Architecture-specific number of register arguments
#if defined(__x86_64__)
constexpr size_t kX86_64RegisterArgs = 6;
#elif defined(__aarch64__)
constexpr size_t kAArch64RegisterArgs = 8;
#elif defined(__arm__)
constexpr size_t kArmRegisterArgs = 4;
#endif

constexpr char kReadPerm = 'r';
constexpr char kWritePerm = 'w';
constexpr char kExecPerm = 'x';
constexpr char kNoPerm = '-';

constexpr std::string_view kRandomChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#if defined(__x86_64__)
void setup_x86_64_args(struct user_regs_struct &regs, const std::vector<uintptr_t> &args) {
    if (args.size() >= 1) regs.rdi = args[0];
    if (args.size() >= 2) regs.rsi = args[1];
    if (args.size() >= 3) regs.rdx = args[2];
    if (args.size() >= 4) regs.rcx = args[3];
    if (args.size() >= 5) regs.r8 = args[4];
    if (args.size() >= 6) regs.r9 = args[5];
}
#elif defined(__aarch64__)
void setup_aarch64_args(struct user_regs_struct &regs, const std::vector<uintptr_t> &args) {
    for (size_t i = 0; i < std::min(args.size(), static_cast<size_t>(kAArch64RegisterArgs)); i++) {
        regs.regs[i] = args[i];
    }
}
#elif defined(__arm__)
void setup_arm_args(struct user_regs_struct &regs, const std::vector<uintptr_t> &args) {
    for (size_t i = 0; i < std::min(args.size(), static_cast<size_t>(kArmRegisterArgs)); i++) {
        regs.uregs[i] = args[i];
    }
}
#endif
} // namespace

bool switch_mnt_ns(int pid, int *fd) {
    if (pid == 0) {
        if (!fd || *fd == kInvalidFd) {
            LOGE("Invalid file descriptor for namespace switch (restore operation).");
            return false;
        }
        UniqueFd nsfd(*fd);
        *fd = kInvalidFd;
        if (setns(nsfd, CLONE_NEWNS) == -1) {
            PLOGE("Failed to switch back to original namespace (FD: %d).", nsfd.operator const int &());
            return false;
        }
        LOGD("Successfully switched back to original namespace (FD: %d).", nsfd.operator const int &());
        return true;
    } else {
        UniqueFd old_nsfd;
        if (fd) {
            int raw_fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
            if (raw_fd == kInvalidFd) {
                PLOGE("Failed to open current mount namespace for backup.");
                return false;
            }
            old_nsfd.reset(raw_fd);
        }

        std::string target_path = "/proc/" + std::to_string(pid) + "/ns/mnt";
        UniqueFd target_nsfd = open(target_path.c_str(), O_RDONLY | O_CLOEXEC);
        if (target_nsfd == kInvalidFd) {
            PLOGE("Failed to open target PID %d's mount namespace: %s", pid, target_path.c_str());
            return false;
        }

        if (setns(target_nsfd, CLONE_NEWNS) == -1) {
            PLOGE("Failed to switch to target PID %d's mount namespace: %s", pid, target_path.c_str());
            return false;
        }

        if (fd) {
            *fd = old_nsfd.release();
            LOGV("Backup namespace FD %d stored for later restore.", *fd);
        }

        LOGD("Successfully switched to mount namespace for PID %d.", pid);
        return true;
    }
}

ssize_t write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len, bool use_proc_mem) {
    if (!buf || len == 0) {
        LOGE("Invalid parameters for write_proc: buffer is null or length is zero.");
        return -1;
    }

    LOGV("Writing %zu bytes to PID %d at address %" PRIxPTR " (use_proc_mem=%s).", len, pid, remote_addr,
         use_proc_mem ? "true" : "false");

    ssize_t bytes_written;

    if (use_proc_mem) {
        char proc_path[kMaxPathLengthInternal];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/mem", pid);

        UniqueFd proc_fd = open(proc_path, O_WRONLY | O_CLOEXEC);
        if (proc_fd == kInvalidFd) {
            PLOGE("Failed to open %s for writing.", proc_path);
            return -1;
        }

        bytes_written = pwrite(proc_fd, buf, len, static_cast<off_t>(remote_addr));
        if (bytes_written == -1) {
            PLOGE("pwrite failed for remote address %" PRIxPTR ".", remote_addr);
        }
    } else {
        struct iovec local_iov = {.iov_base = const_cast<void *>(buf), .iov_len = len};
        struct iovec remote_iov = {.iov_base = reinterpret_cast<void *>(remote_addr), .iov_len = len};

        bytes_written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
        if (bytes_written == -1) {
            PLOGE("process_vm_writev failed for remote address %" PRIxPTR ".", remote_addr);
        }
    }

    if (bytes_written != -1 && static_cast<size_t>(bytes_written) != len) {
        LOGW("Partial write: %zd bytes written, %zu expected for PID %d at %" PRIxPTR ".", bytes_written, len, pid,
             remote_addr);
    }

    return bytes_written;
}

ssize_t read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len) {
    if (!buf || len == 0) {
        LOGE("Invalid parameters for read_proc: buffer is null or length is zero.");
        return -1;
    }

    LOGV("Reading %zu bytes from PID %d at address %" PRIxPTR ".", len, pid, remote_addr);

    struct iovec local_iov = {.iov_base = buf, .iov_len = len};
    struct iovec remote_iov = {.iov_base = reinterpret_cast<void *>(remote_addr), .iov_len = len};

    ssize_t bytes_read = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (bytes_read == -1) {
        PLOGE("process_vm_readv failed for remote address %" PRIxPTR ".", remote_addr);
    } else if (static_cast<size_t>(bytes_read) != len) {
        LOGW("Partial read: %zd bytes read, %zu expected for PID %d at %" PRIxPTR ".", bytes_read, len, pid,
             remote_addr);
    }

    return bytes_read;
}

bool get_regs(int pid, struct user_regs_struct &regs) {
    LOGV("Retrieving registers for PID %d.", pid);

#if defined(__x86_64__) || defined(__i386__)
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        PLOGE("Failed to get registers for PID %d.", pid);
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    struct iovec reg_iov = {.iov_base = &regs, .iov_len = sizeof(struct user_regs_struct)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &reg_iov) == -1) {
        PLOGE("Failed to get register set for PID %d.", pid);
#if defined(__arm__)
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            PLOGE("Fallback to PTRACE_GETREGS failed.");
            return false;
        }
#else
        return false;
#endif
    }
#else
#    error "Unsupported architecture for register access in get_regs."
#endif

    LOGV("Successfully retrieved registers for PID %d.", pid);
    return true;
}

bool set_regs(int pid, struct user_regs_struct &regs) {
    LOGV("Setting registers for PID %d.", pid);

#if defined(__x86_64__) || defined(__i386__)
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        PLOGE("Failed to set registers for PID %d.", pid);
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    struct iovec reg_iov = {.iov_base = &regs, .iov_len = sizeof(struct user_regs_struct)};
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &reg_iov) == -1) {
        PLOGE("Failed to set register set for PID %d.", pid);
#if defined(__arm__)
        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
            PLOGE("Fallback to PTRACE_SETREGS failed.");
            return false;
        }
#else
        return false;
#endif
    }
#else
#    error "Unsupported architecture for register access in set_regs."
#endif

    LOGV("Successfully set registers for PID %d.", pid);
    return true;
}

std::string get_addr_mem_region(const std::vector<lsplt::MapInfo> &map_info, uintptr_t addr) {
    for (const auto &map : map_info) {
        if (map.start <= addr && map.end > addr) {
            std::string perms_str;
            perms_str.reserve(4);
            perms_str += (map.perms & PROT_READ) ? kReadPerm : kNoPerm;
            perms_str += (map.perms & PROT_WRITE) ? kWritePerm : kNoPerm;
            perms_str += (map.perms & PROT_EXEC) ? kExecPerm : kNoPerm;
            return map.path + ' ' + perms_str;
        }
    }
    return "<unknown>";
}

void *find_module_base(const std::vector<lsplt::MapInfo> &map_info, std::string_view module_suffix) {
    uintptr_t lowest_start = UINTPTR_MAX;
    uintptr_t offset_zero_start = 0;
    bool found_offset_zero = false;
    bool found_any = false;

    for (const auto &map : map_info) {
        if (map.path.ends_with(module_suffix)) {
            if (map.offset == 0) {
                offset_zero_start = map.start;
                found_offset_zero = true;
                break;
            }
            if (map.start < lowest_start) {
                lowest_start = map.start;
                found_any = true;
            }
        }
    }

    if (found_offset_zero) {
        LOGV("Found module base for '%.*s' at %p (offset==0).", static_cast<int>(module_suffix.length()),
             module_suffix.data(), reinterpret_cast<void *>(offset_zero_start));
        return reinterpret_cast<void *>(offset_zero_start);
    }

    if (found_any) {
        LOGV("Found module base for '%.*s' at %p (lowest start, no offset==0).", static_cast<int>(module_suffix.length()),
             module_suffix.data(), reinterpret_cast<void *>(lowest_start));
        return reinterpret_cast<void *>(lowest_start);
    }

    LOGV("Module base not found for suffix '%.*s'.", static_cast<int>(module_suffix.length()), module_suffix.data());
    return nullptr;
}

void *find_func_addr(const std::vector<lsplt::MapInfo> &local_map_info,
                     const std::vector<lsplt::MapInfo> &remote_map_info, std::string_view module_name,
                     std::string_view function_name) {
    LOGV("Resolving function '%.*s' in module '%.*s'.", static_cast<int>(function_name.length()), function_name.data(),
         static_cast<int>(module_name.length()), module_name.data());

    void *lib_handle = dlopen(module_name.data(), RTLD_NOW);
    if (!lib_handle) {
        LOGE("Failed to open local library '%.*s': %s.", static_cast<int>(module_name.length()), module_name.data(),
             dlerror());
        return nullptr;
    }

    auto lib_closer = [lib_handle]() { dlclose(lib_handle); };

    auto *symbol_addr = reinterpret_cast<uint8_t *>(dlsym(lib_handle, function_name.data()));
    if (!symbol_addr) {
        LOGE("Failed to find local symbol '%.*s' in library '%.*s': %s.", static_cast<int>(function_name.length()),
             function_name.data(), static_cast<int>(module_name.length()), module_name.data(), dlerror());
        lib_closer();
        return nullptr;
    }
    LOGV("Found local symbol '%.*s' at address %p.", static_cast<int>(function_name.length()), function_name.data(),
         symbol_addr);

    auto *local_base = reinterpret_cast<uint8_t *>(find_module_base(local_map_info, module_name));
    if (!local_base) {
        LOGE("Failed to find local base address for module '%.*s'.", static_cast<int>(module_name.length()),
             module_name.data());
        lib_closer();
        return nullptr;
    }

    uintptr_t local_end = 0;
    for (const auto &map : local_map_info) {
        if (map.path.ends_with(module_name) && map.end > local_end) {
            local_end = map.end;
        }
    }

    if (symbol_addr < local_base || symbol_addr >= reinterpret_cast<uint8_t *>(local_end)) {
        LOGE("Symbol '%.*s' at %p is outside local module range [%p, %p).", static_cast<int>(function_name.length()),
             function_name.data(), symbol_addr, local_base, reinterpret_cast<void *>(local_end));
        lib_closer();
        return nullptr;
    }

    auto *remote_base = reinterpret_cast<uint8_t *>(find_module_base(remote_map_info, module_name));
    if (!remote_base) {
        LOGE("Failed to find remote base address for module '%.*s'.", static_cast<int>(module_name.length()),
             module_name.data());
        lib_closer();
        return nullptr;
    }

    ptrdiff_t symbol_offset = symbol_addr - local_base;
    auto *remote_symbol_addr = remote_base + symbol_offset;

    LOGV("Address translation: local_base=%p, remote_base=%p, offset=%td -> remote_addr=%p", local_base, remote_base,
         symbol_offset, remote_symbol_addr);

    lib_closer();
    return remote_symbol_addr;
}

static void align_stack_generic(struct user_regs_struct &regs, uintptr_t preserve_bytes, uintptr_t alignment) {
    regs.REG_SP = (regs.REG_SP - preserve_bytes) & ~alignment;
    LOGV("Stack aligned to %" PRIxPTR " (preserved %zu bytes, alignment mask 0x%" PRIxPTR ").",
         static_cast<uintptr_t>(regs.REG_SP), preserve_bytes, alignment);
}

uintptr_t push_memory(int pid, struct user_regs_struct &regs, const void *data, size_t length) {
    if (!data || length == 0) {
        LOGE("Invalid parameters for push_memory: data=%p, length=%zu.", data, length);
        return 0;
    }

    uintptr_t old_sp = regs.REG_SP;
    regs.REG_SP -= length;
    auto stack_addr = static_cast<uintptr_t>(regs.REG_SP);

    if (write_proc(pid, stack_addr, data, length) != static_cast<ssize_t>(length)) {
        LOGE("Failed to push %zu bytes to remote stack at %" PRIxPTR ". Restoring SP.", length, stack_addr);
        regs.REG_SP = old_sp;
        return 0;
    }

    LOGV("Pushed %zu bytes to remote stack at %" PRIxPTR ".", length, stack_addr);
    return stack_addr;
}

uintptr_t push_string(int pid, struct user_regs_struct &regs, const char *str) {
    if (!str) {
        LOGE("Null string pointer passed to push_string.");
        return 0;
    }

    size_t str_length = strlen(str) + 1;
    uintptr_t old_sp = regs.REG_SP;
    regs.REG_SP -= str_length;
    auto stack_addr = static_cast<uintptr_t>(regs.REG_SP);

    if (write_proc(pid, stack_addr, str, str_length) != static_cast<ssize_t>(str_length)) {
        LOGE("Failed to push string '%s' (%zu bytes) to remote stack at %" PRIxPTR ". Restoring SP.", str, str_length,
             stack_addr);
        regs.REG_SP = old_sp;
        return 0;
    }

    LOGV("Pushed string '%s' (%zu bytes) to remote stack at %" PRIxPTR ".", str, str_length, stack_addr);
    return stack_addr;
}

bool remote_pre_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr, uintptr_t return_addr,
                     std::vector<uintptr_t> &args) {
    struct user_regs_struct original_regs = regs;
    bool registers_modified = false;

    align_stack_generic(regs, 0, kStackAlignmentMask);

    LOGV("Setting up remote function call to %p (func_addr=%" PRIxPTR ") with %zu arguments. Return to %p.",
         reinterpret_cast<void *>(func_addr), func_addr, args.size(), reinterpret_cast<void *>(return_addr));
    for (size_t i = 0; i < args.size(); i++) {
        LOGV("  arg[%zu] = %p (%" PRIuPTR ")", i, reinterpret_cast<void *>(args[i]), args[i]);
    }

#if defined(__x86_64__)
    setup_x86_64_args(regs, args);

    size_t num_stack_args = (args.size() > kX86_64RegisterArgs) ? (args.size() - kX86_64RegisterArgs) : 0;
    size_t stack_args_bytes = num_stack_args * sizeof(uintptr_t);
    size_t total_bytes = stack_args_bytes + sizeof(uintptr_t);

    uintptr_t base_sp = regs.REG_SP;
    uintptr_t new_sp = ((base_sp - total_bytes - 8) & ~0xfULL) + 8;
    if (new_sp + total_bytes > base_sp) {
        new_sp -= 16;
    }
    regs.REG_SP = new_sp;

    if (write_proc(pid, regs.REG_SP, &return_addr, sizeof(return_addr)) != sizeof(return_addr)) {
        LOGE("Failed to write return address for x86_64 remote call. Rolling back.");
        regs = original_regs;
        return false;
    }

    if (num_stack_args > 0) {
        uintptr_t args_pos = regs.REG_SP + sizeof(uintptr_t);
        if (write_proc(pid, args_pos, args.data() + kX86_64RegisterArgs, stack_args_bytes) !=
            static_cast<ssize_t>(stack_args_bytes)) {
            LOGE("Failed to push stack arguments for x86_64 remote call. Rolling back.");
            regs = original_regs;
            return false;
        }
    }

    regs.REG_IP = func_addr;
    registers_modified = true;

#elif defined(__i386__)
    if (args.size() > 0) {
        size_t stack_args_size = args.size() * sizeof(uintptr_t);
        regs.REG_SP = (regs.REG_SP - stack_args_size) & ~0x3ULL;

        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data(), stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("Failed to push arguments for i386 remote call. Rolling back.");
            regs = original_regs;
            return false;
        }
    }

    regs.REG_SP -= sizeof(uintptr_t);
    if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), &return_addr, sizeof(return_addr)) !=
        sizeof(return_addr)) {
        LOGE("Failed to write return address for i386 remote call. Rolling back.");
        regs = original_regs;
        return false;
    }

    regs.REG_IP = func_addr;
    registers_modified = true;

#elif defined(__aarch64__)
    setup_aarch64_args(regs, args);

    if (args.size() > kAArch64RegisterArgs) {
        size_t stack_args_size = (args.size() - kAArch64RegisterArgs) * sizeof(uintptr_t);
        align_stack_generic(regs, stack_args_size, kStackAlignmentMask);

        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data() + kAArch64RegisterArgs, stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("Failed to push stack arguments for AArch64 remote call. Rolling back.");
            regs = original_regs;
            return false;
        }
    }

    regs.regs[30] = return_addr; // LR
    regs.REG_IP = func_addr;     // PC
    registers_modified = true;

#elif defined(__arm__)
    setup_arm_args(regs, args);

    if (args.size() > kArmRegisterArgs) {
        size_t stack_args_size = (args.size() - kArmRegisterArgs) * sizeof(uintptr_t);
        regs.REG_SP = (regs.REG_SP - stack_args_size) & ~0x7ULL;

        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data() + kArmRegisterArgs, stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("Failed to push stack arguments for ARM remote call. Rolling back.");
            regs = original_regs;
            return false;
        }
    }

    regs.uregs[14] = return_addr;
    regs.REG_IP = func_addr;

    constexpr auto CPSR_T_MASK = 1lu << 5;
    if ((regs.REG_IP & 1) != 0) {
        regs.REG_IP = regs.REG_IP & ~1;
        regs.uregs[16] = regs.uregs[16] | CPSR_T_MASK;
    } else {
        regs.uregs[16] = regs.uregs[16] & ~CPSR_T_MASK;
    }
    registers_modified = true;

#else
#    error "Unsupported architecture for remote function calls in remote_pre_call."
#endif

    if (!set_regs(pid, regs)) {
        LOGE("Failed to set registers for remote function call in PID %d. Rolling back.", pid);
        if (registers_modified) {
            set_regs(pid, original_regs);
        }
        regs = original_regs;
        return false;
    }

    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
        PLOGE("Failed to continue remote process %d execution. Rolling back target registers.", pid);
        set_regs(pid, original_regs);
        regs = original_regs;
        return false;
    }

    LOGV("Remote function call initiated successfully for PID %d to %p.", pid, reinterpret_cast<void *>(func_addr));
    return true;
}

uintptr_t remote_post_call(int pid, struct user_regs_struct &regs, uintptr_t expected_return_addr) {
    LOGV("Waiting for remote function call completion in PID %d.", pid);

    int status;
    if (!wait_for_trace(pid, &status, __WALL)) {
        LOGE("Failed to wait for remote function completion in PID %d.", pid);
        return 0;
    }

    if (!get_regs(pid, regs)) {
        LOGE("Failed to get registers after remote call completion in PID %d.", pid);
        return 0;
    }

    int stop_signal = WSTOPSIG(status);
    LOGV("Remote function in PID %d stopped with signal: %s(%d) at address %p.", pid, sigabbrev_np(stop_signal),
         stop_signal, reinterpret_cast<void *>(regs.REG_IP));

    if (static_cast<uintptr_t>(regs.REG_IP) != expected_return_addr) {
        LOGE("Remote function in PID %d returned to unexpected address %p (expected %p).", pid,
             reinterpret_cast<void *>(regs.REG_IP), reinterpret_cast<void *>(expected_return_addr));

        if (stop_signal == SIGSEGV || stop_signal == SIGBUS || stop_signal == SIGILL) {
            siginfo_t crash_info;
            if (ptrace(PTRACE_GETSIGINFO, pid, 0, &crash_info) == 0) {
                LOGE("Crash details for PID %d: si_code=%d si_addr=%p.", pid, crash_info.si_code, crash_info.si_addr);
            } else {
                PLOGE("Failed to get crash signal info for PID %d.", pid);
            }
        }
        return 0;
    }

    if (stop_signal != SIGSEGV) {
        LOGW("Remote call returned to expected address but with signal %s(%d) instead of SIGSEGV. "
             "This may indicate abnormal termination.",
             sigabbrev_np(stop_signal), stop_signal);
    }

    uintptr_t return_value = regs.REG_RET;
    LOGV("Remote function in PID %d completed with return value: %p (%" PRIxPTR ").", pid,
         reinterpret_cast<void *>(return_value), return_value);
    return return_value;
}

uintptr_t remote_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr, uintptr_t return_addr,
                      std::vector<uintptr_t> &args) {
    if (!remote_pre_call(pid, regs, func_addr, return_addr, args)) {
        LOGE("Failed to prepare remote function call in PID %d.", pid);
        return 0;
    }
    return remote_post_call(pid, regs, return_addr);
}

int fork_dont_care() {
    int first_pid = fork();
    if (first_pid < 0) {
        PLOGE("Failed first fork for daemon process.");
        return first_pid;
    }

    if (first_pid == 0) {
        int second_pid = fork();
        if (second_pid < 0) {
            PLOGE("Failed second fork for daemon process.");
            exit(EXIT_FAILURE);
        } else if (second_pid > 0) {
            exit(EXIT_SUCCESS);
        }
        return 0;
    } else {
        int status;
        waitpid(first_pid, &status, __WALL);
        return first_pid;
    }
}

bool wait_for_trace(int pid, int *status, int flags) {
    if (!status) {
        LOGE("Null status pointer passed to wait_for_trace.");
        return false;
    }

    while (true) {
        pid_t result = waitpid(pid, status, flags);
        if (result == -1) {
            if (errno == EINTR) {
                LOGV("waitpid for PID %d interrupted, retrying.", pid);
                continue;
            } else {
                PLOGE("waitpid failed for PID %d.", pid);
                return false;
            }
        }

        if (!WIFSTOPPED(*status)) {
            LOGE("Process %d not stopped for trace: %s.", pid, parse_status(*status).c_str());
            return false;
        }

        LOGV("Process %d stopped for trace with status: %s.", pid, parse_status(*status).c_str());
        return true;
    }
}

std::string parse_status(int status) {
    char status_buf[kStatusBufferSize];

    if (WIFEXITED(status)) {
        snprintf(status_buf, sizeof(status_buf), "0x%x exited with code %d", status, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        snprintf(status_buf, sizeof(status_buf), "0x%x terminated by signal %s(%d)", status,
                 sigabbrev_np(WTERMSIG(status)), WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
        int stop_signal = WSTOPSIG(status);
        snprintf(status_buf, sizeof(status_buf), "0x%x stopped by signal=%s(%d), event=%s", status,
                 sigabbrev_np(stop_signal), stop_signal, parse_ptrace_event(status));
    } else {
        snprintf(status_buf, sizeof(status_buf), "0x%x unknown status", status);
    }

    return std::string(status_buf);
}

std::string get_program(int pid) {
    std::string exe_path = "/proc/" + std::to_string(pid) + "/exe";
    char resolved_path[kMaxPathLengthInternal + 1];

    ssize_t link_size = readlink(exe_path.c_str(), resolved_path, kMaxPathLengthInternal);
    if (link_size == -1) {
        PLOGE("Failed to read executable path for PID %d: %s", pid, exe_path.c_str());
        return "";
    }

    resolved_path[link_size] = '\0';
    return std::string(resolved_path);
}

void *find_module_return_addr(const std::vector<lsplt::MapInfo> &map_info, std::string_view module_suffix) {
    uintptr_t lowest_addr = UINTPTR_MAX;
    bool found = false;

    for (const auto &map : map_info) {
        if (!(map.perms & PROT_EXEC) && (map.perms & PROT_READ) && map.path.ends_with(module_suffix)) {
            if (map.start < lowest_addr) {
                lowest_addr = map.start;
                found = true;
            }
        }
    }

    if (found) {
        LOGV("Found return address region for '%.*s' at %p.", static_cast<int>(module_suffix.length()),
             module_suffix.data(), reinterpret_cast<void *>(lowest_addr));
        return reinterpret_cast<void *>(lowest_addr);
    }

    LOGV("No suitable return address region found for module suffix '%.*s'.", static_cast<int>(module_suffix.length()),
         module_suffix.data());
    return nullptr;
}

std::string generateMagic(size_t length) {
    if (length == 0) {
        LOGW("Zero length requested for magic string, returning empty string.");
        return "";
    }

    std::mt19937 random_generator{std::random_device{}()};
    std::uniform_int_distribution<size_t> char_distribution(0, kRandomChars.length() - 1);

    std::string magic_string;
    magic_string.reserve(length);

    for (size_t i = 0; i < length; i++) {
        magic_string += kRandomChars[char_distribution(random_generator)];
    }

    LOGV("Generated magic string of length %zu.", length);
    return magic_string;
}

int setfilecon(const char *file_path, const char *security_context) {
    if (!file_path || !security_context) {
        LOGE("Invalid parameters for setfilecon: file_path=%p, security_context=%p.", file_path, security_context);
        return -1;
    }

    size_t context_len = strlen(security_context) + 1;
    int result = syscall(__NR_setxattr, file_path, XATTR_NAME_SELINUX, security_context, context_len, 0);

    if (result == 0) {
        LOGV("Successfully set SELinux context '%s' for file '%s'.", security_context, file_path);
    } else {
        PLOGE("Failed to set SELinux context '%s' for file '%s'.", security_context, file_path);
    }

    return result;
}

bool set_sockcreate_con(const char *security_context) {
    if (!security_context) {
        LOGE("Null security context passed to set_sockcreate_con.");
        return false;
    }

    size_t context_size = strlen(security_context) + 1;

    UniqueFd sockcreate_fd = open("/proc/thread-self/attr/sockcreate", O_WRONLY | O_CLOEXEC);
    if (sockcreate_fd != kInvalidFd &&
        write(sockcreate_fd, security_context, context_size) == static_cast<ssize_t>(context_size)) {
        LOGV("Successfully set socket creation context via /proc/thread-self/attr/sockcreate: '%s'.", security_context);
        return true;
    }

    LOGV("Failed to set socket creation context via /proc/thread-self/attr/sockcreate,"
         " attempting process-specific fallback.");

    char process_path[kMaxPathLengthInternal];
    snprintf(process_path, sizeof(process_path), "/proc/%d/attr/sockcreate", gettid());

    sockcreate_fd = open(process_path, O_WRONLY | O_CLOEXEC);
    if (sockcreate_fd == kInvalidFd ||
        write(sockcreate_fd, security_context, context_size) != static_cast<ssize_t>(context_size)) {
        PLOGE("Failed to set socket creation context via fallback path '%s'.", process_path);
        return false;
    }

    LOGV("Successfully set socket creation context via fallback path '%s': '%s'.", process_path, security_context);
    return true;
}
