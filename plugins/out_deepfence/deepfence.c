#include "deepfence.h"
#include "out_deepfence.h"

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "format", NULL,
     0, FLB_FALSE, 0,
     "Specifies the data format to be printed. Supported formats are msgpack json, json_lines and json_stream."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_deepfence, json_date_key),
    "Specifies the name of the date field in output."
    },

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_deepfence_plugin = {
    .name         = "deepfence",
    .description  = "Sends to deepfence server",
    .cb_init      = FLBPluginInit,
    .cb_flush     = FLBPluginFlush,
    .cb_exit      = FLBPluginExit,
    .flags        = 0,
    .workers      = 1,
    .event_type   = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS | FLB_OUTPUT_TRACES,
    .config_map   = config_map
};
