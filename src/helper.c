#include "helper.h"
#include <glib.h>

guint potential_connections_hash(gconstpointer key)
{
    PacketInfo* p       = (PacketInfo*) key;
    guint       hash    = g_str_hash(p->src_ip) ^ g_str_hash(p->dst_ip) ^ p->src_port ^ p->dst_port;
    return hash;
}

gboolean potential_connections_equal(gconstpointer a, gconstpointer b)
{
    PacketInfo* p1 = (PacketInfo*) a;
    PacketInfo* p2 = (PacketInfo*) b;
    return strcmp(p1->src_ip, p2->src_ip) == 0 &&
           strcmp(p1->dst_ip, p2->dst_ip) == 0 &&
           p1->src_port == p2->src_port &&
           p1->dst_port == p2->dst_port;
}

guint failed_connections_hash(gconstpointer key)
{
    PacketInfo* p       = (PacketInfo*) key;
    guint       hash    = g_str_hash(p->src_ip) ^ g_str_hash(p->dst_ip) ^ p->dst_port;
    return hash;
}

gboolean failed_connections_equal(gconstpointer a, gconstpointer b)
{
    PacketInfo* p1 = (PacketInfo*) a;
    PacketInfo* p2 = (PacketInfo*) b;
    return strcmp(p1->src_ip, p2->src_ip) == 0 &&
           strcmp(p1->dst_ip, p2->dst_ip) == 0 &&
           p1->dst_port == p2->dst_port;
}

void init_context(Context* ctx)
{
    ctx->potential_connections	= g_hash_table_new_full(potential_connections_hash,
                                                        potential_connections_equal,
                                                        g_free,
                                                        g_free);
    ctx->failed_connections     = g_hash_table_new_full(failed_connections_hash,
                                                        failed_connections_equal,
                                                        g_free,
                                                        g_free);
    ctx->records                = g_async_queue_new();
    ctx->file                   = 0;
}

void clean_context(Context* ctx)
{
    g_hash_table_destroy(ctx->potential_connections);
    gpointer element;
    while((element = g_async_queue_try_pop(ctx->records))) { g_free(element); }
    g_async_queue_unref(ctx->records);
    if(ctx->file) { fclose(ctx->file); }
}