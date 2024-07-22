#include "helper.h"
#include <glib.h>

void report_failed_connection(Context* ctx, PacketInfo* packet)
{
    GAsyncQueue*    records             = ctx->records;
    GHashTable*     failed_connections  = ctx->failed_connections;
    int*            count               = (int*) g_hash_table_lookup(failed_connections, packet);
    char*           record              = NULL;
    if(count)
    {
        ++(*count);
        record = g_strdup_printf(FAILED_CONNECTION_RECORD_RETRY,
                                 packet->src_ip,
                                 packet->src_port,
                                 packet->dst_ip,
                                 packet->dst_port,
                                 *count);
    }
    else
    {
        int* new_count = malloc(sizeof(int));
        *new_count = 1;
        packet->last_syn_time = time(NULL);
        g_hash_table_insert(failed_connections, g_memdup2(packet, sizeof(PacketInfo)), new_count);
        record = g_strdup_printf(FAILED_CONNECTION_RECORD,
                                 packet->src_ip,
                                 packet->src_port,
                                 packet->dst_ip,
                                 packet->dst_port);
    }

    g_async_queue_push(records, record);
}

void process_syn(Context* ctx, PacketInfo* packet)
{
    g_mutex_lock(&ctx->potential_connections_mutex);

    GHashTable* potential_connections   = ctx->potential_connections;
    int*        count                   = (int*)g_hash_table_lookup(potential_connections, packet);
    if(count)
    {
        ++(*count);
        packet->last_syn_time = time(NULL);
        g_debug("Retry SYN obtained. Increment counter for connection (%p) (src: %s:%u - dst: %s:%u)",
                packet,
                packet->src_ip,
                packet->src_port,
                packet->dst_ip,
                packet->dst_port);
    }
    else
    {
        int* new_count = malloc(sizeof(int));
        *new_count = 1;
        packet->last_syn_time = time(NULL);
        g_hash_table_insert(potential_connections, g_memdup2(packet, sizeof(PacketInfo)), new_count);
        g_debug("SYN obtained. Add connection (%d) to the table of potential connections (src: %s:%u - dst: %s:%u)",
                potential_connections_hash(packet),
                packet->src_ip,
                packet->src_port,
                packet->dst_ip,
                packet->dst_port);
    }

    g_mutex_unlock(&ctx->potential_connections_mutex);
}

void process_syn_ack(Context* ctx, PacketInfo* packet)
{
    g_mutex_lock(&ctx->potential_connections_mutex);

    GHashTable*     potential_connections   = ctx->potential_connections;
    GAsyncQueue*    records                 = ctx->records;

    g_hash_table_remove(potential_connections, packet);
    g_debug("SYN-ACK obtained. Connection (%p) will be considered as successful (src: %s:%u - dst: %s:%u)",
            packet,
            packet->src_ip,
            packet->src_port,
            packet->dst_ip,
            packet->dst_port);

    char* record = g_strdup_printf(SUCCESSFUL_CONNECTION_RECORD,
                                   packet->src_ip,
                                   packet->src_port,
                                   packet->dst_ip,
                                   packet->dst_port);

    g_async_queue_push(records, record);

    g_mutex_unlock(&ctx->potential_connections_mutex);
}

void process_rst(Context* ctx, PacketInfo* packet)
{
    g_debug("RST obtained. Connection (%p) will be considered as failed (src: %s:%u - dst: %s:%u)",
            packet,
            packet->src_ip,
            packet->src_port,
            packet->dst_ip,
            packet->dst_port);

    g_mutex_lock(&ctx->potential_connections_mutex);
    GHashTable* potential_connections = ctx->potential_connections;
    g_hash_table_remove(potential_connections, packet);
    g_mutex_unlock(&ctx->potential_connections_mutex);

    report_failed_connection(ctx, packet);
}