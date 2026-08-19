#pragma once

#include "../injector/include/logging.hpp"

// Simple wrappers to unify SOTER log prefix with project's logging macros.
#define SOTER_PREFIX "[SOTER] "

#define SLOGI(fmt, ...) LOGI(SOTER_PREFIX fmt, ##__VA_ARGS__)
#define SLOGW(fmt, ...) LOGW(SOTER_PREFIX fmt, ##__VA_ARGS__)
#define SLOGE(fmt, ...) LOGE(SOTER_PREFIX fmt, ##__VA_ARGS__)
