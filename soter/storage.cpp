#include "soter.hpp"
#include "logging.hpp"

#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#include <fstream>
#include <vector>
#include <string>

// Storage helpers for soter persistent data under /data/tee/soter

bool ensure_dir_recursive(const std::string& path) {
    if (path.empty()) return false;
    // If already exists and is directory, done
    struct stat st;
    if (stat(path.c_str(), &st) == 0) return S_ISDIR(st.st_mode);

    // Create parent recursively
    size_t pos = 1; // skip leading '/'
    while (pos != std::string::npos) {
        pos = path.find('/', pos+1);
        std::string prefix = (pos == std::string::npos) ? path : path.substr(0, pos);
        if (prefix.empty()) continue;
        struct stat pst;
        if (stat(prefix.c_str(), &pst) != 0) {
            if (mkdir(prefix.c_str(), 0700) != 0 && errno != EEXIST) {
                SLOGE("ensure_dir_recursive: mkdir(%s) failed: %s", prefix.c_str(), strerror(errno));
                return false;
            }
        } else if (!S_ISDIR(pst.st_mode)) {
            SLOGE("ensure_dir_recursive: %s exists and is not a directory", prefix.c_str());
            return false;
        }
    }
    return true;
}

std::vector<uint8_t> read_file_bytes(const std::string& path) {
    std::vector<uint8_t> out;
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return out;
    ifs.seekg(0, std::ios::end);
    std::streamsize sz = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    if (sz <= 0) return out;
    out.resize(static_cast<size_t>(sz));
    ifs.read(reinterpret_cast<char*>(out.data()), sz);
    return out;
}

bool write_file_atomic(const std::string& path, const std::vector<uint8_t>& data) {
    std::string tmp = path + ".tmp";
    std::ofstream ofs(tmp, std::ios::binary);
    if (!ofs) {
        SLOGE("write_file_atomic: open %s failed", tmp.c_str());
        return false;
    }
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    ofs.close();
    if (rename(tmp.c_str(), path.c_str()) != 0) {
        SLOGE("write_file_atomic: rename %s -> %s failed: %s", tmp.c_str(), path.c_str(), strerror(errno));
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

bool remove_file(const std::string& path) {
    if (unlink(path.c_str()) != 0) {
        if (errno == ENOENT) return true;
        SLOGE("remove_file: unlink %s failed: %s", path.c_str(), strerror(errno));
        return false;
    }
    return true;
}

std::vector<std::string> list_dir(const std::string& path) {
    std::vector<std::string> out;
    DIR* d = opendir(path.c_str());
    if (!d) return out;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        out.emplace_back(e->d_name);
    }
    closedir(d);
    return out;
}
