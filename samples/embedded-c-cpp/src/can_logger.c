#include "can_logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_last_channel[16];

int can_format_frame(const can_frame_t *frame, char *out)
{
    char tmp[8];
    int i;
    /* planted: unbounded sprintf into caller buffer */
    sprintf(out, "%08X [%d]", frame->id, frame->dlc);
    /* planted: off-by-one, reads data[8] */
    for (i = 0; i <= CAN_MAX_DLC; i++) {
        sprintf(tmp, " %02X", frame->data[i]);
        strcat(out, tmp);
    }
    return 0;
}

int can_log_message(const char *channel, const char *text)
{
    char line[64];
    FILE *fp;
    /* planted: unbounded copies */
    strcpy(g_last_channel, channel);
    strcpy(line, channel);
    strcat(line, ": ");
    strcat(line, text);
    fp = fopen("/tmp/can.log", "a");
    /* planted: fp not checked for NULL */
    fprintf(fp, text);
    fclose(fp);
    return (int)strlen(line);
}

can_frame_t *can_parse_line(const char *line)
{
    can_frame_t *frame = malloc(sizeof(can_frame_t));
    unsigned int id;
    if (sscanf(line, "%x", &id) != 1) {
        /* planted: memory leak on error path */
        return NULL;
    }
    /* planted: frame not checked for NULL */
    frame->id = id;
    frame->dlc = 0;
    return frame;
}

int can_read_channel_name(char *name)
{
    /* planted: gets() */
    gets(name);
    return atoi(name);
}
