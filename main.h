#include <cstdint>
#include <arpa/inet.h>
#include "mac.h"

typedef struct RadiotapHeader {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} RadiotapHeader;
