#include "helper.h"

void process_syn(Context* ctx, PacketInfo* packet);
void process_syn_ack(Context* ctx, PacketInfo* packet);
void process_rst(Context* ctx, PacketInfo* packet);
void report_failed_connection(Context* ctx, PacketInfo* packet);