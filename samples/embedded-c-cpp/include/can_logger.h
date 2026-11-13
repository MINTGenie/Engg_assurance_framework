#ifndef CAN_LOGGER_H
#define CAN_LOGGER_H

#include <stddef.h>
#include <stdint.h>

#define CAN_MAX_DLC 8

typedef struct {
    uint32_t id;
    uint8_t dlc;
    uint8_t data[CAN_MAX_DLC];
} can_frame_t;

int can_format_frame(const can_frame_t *frame, char *out);
int can_log_message(const char *channel, const char *text);
can_frame_t *can_parse_line(const char *line);
int can_read_channel_name(char *name);

#endif
