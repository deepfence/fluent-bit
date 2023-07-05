#include "deepfence.h"
#include "out_deepfence.h"

static int cb_deepfence_init(
	struct flb_output_instance *ins,
	struct flb_config *config,
	void *data)
{
    struct flb_deepfence *ctx = flb_calloc(1, sizeof(struct flb_deepfence));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    int ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

	FLBPluginInit(
		(char*)flb_output_get_property("dftopic", ins),
		(char*)flb_output_get_property("dfhost", ins),
		(char*)flb_output_get_property("dfport", ins),
		(char*)flb_output_get_property("dfpath", ins),
		(char*)flb_output_get_property("dfschema", ins),
		(char*)flb_output_get_property("dfkey", ins),
		(char*)flb_output_get_property("dfcertpath", ins),
		(char*)flb_output_get_property("dfcertkey", ins)
	);

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_deepfence_flush(
	struct flb_event_chunk *event_chunk,
	struct flb_output_flush *out_flush,
	struct flb_input_instance *i_ins,
	void *out_context,
	struct flb_config *config)
{
    struct flb_deepfence *ctx = (struct flb_deepfence *) out_context;

	int ret = FLBPluginFlushCtx(
		(char*)flb_output_get_property("dftopic", ctx->ins),
		event_chunk->data,
		event_chunk->size);

    FLB_OUTPUT_RETURN(ret);
}

static int cb_deepfence_exit(void *data, struct flb_config *config)
{
    struct flb_deepfence *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "dftopic", NULL,
     0, FLB_FALSE, 0,
     "Unique topic config"
    },
    {
     FLB_CONFIG_MAP_STR, "dfhost", NULL,
     0, FLB_FALSE, 0,
     "Management Console Host"
    },
    {
     FLB_CONFIG_MAP_STR, "dfport", NULL,
     0, FLB_FALSE, 0,
     "Management Console Port"
    },
    {
     FLB_CONFIG_MAP_STR, "dfpath", NULL,
     0, FLB_FALSE, 0,
     "Path to listen"
    },
    {
     FLB_CONFIG_MAP_STR, "dfschema", NULL,
     0, FLB_FALSE, 0,
     "Schema used for accessing console URL"
    },
    {
     FLB_CONFIG_MAP_STR, "dfkey", NULL,
     0, FLB_FALSE, 0,
     "API key from console"
    },
    {
     FLB_CONFIG_MAP_STR, "dfcertpath", NULL,
     0, FLB_FALSE, 0,
     "Cert path from console"
    },
    {
     FLB_CONFIG_MAP_STR, "dfcertkey", NULL,
     0, FLB_FALSE, 0,
     "Cert key from console"
    },
    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_deepfence_plugin = {
    .name         = "deepfence",
    .description  = "Plugin sending data to deepfence server",
    .cb_init      = cb_deepfence_init,
    .cb_flush     = cb_deepfence_flush,
    .cb_exit      = cb_deepfence_exit,
    .flags        = 0,
    .workers      = 1,
    .event_type   = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS | FLB_OUTPUT_TRACES,
    .config_map   = config_map
};
