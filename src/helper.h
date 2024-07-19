#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <glib.h>
#include <stdbool.h>
#include <stdio.h>

#define TIMEOUT_THRESHOLD_SECONDS			(10)
#define SUCCESSFUL_CONNECTION_RECORD		"SUCCESS %s:%u -> %s:%u"
#define FAILED_CONNECTION_RECORD			"FAILED %s:%u -> %s:%u"
#define FAILED_CONNECTION_RECORD_RETRY		"FAILED %s:%u -> %s:%u. Attempt: %d"

typedef struct {
    char        src_ip[INET_ADDRSTRLEN];
    char        dst_ip[INET_ADDRSTRLEN];
    uint16_t    src_port;
    uint16_t    dst_port;
	time_t		last_syn_time;
} PacketInfo;

typedef struct
{
	GHashTable*     potential_connections;
	GMutex		    potential_connections_mutex;
	GHashTable*	    failed_connections;
	GAsyncQueue*    records;
	FILE* 			file;
} Context;

void		init_context(Context* ctx);
void		clean_context(Context* ctx);
guint		potential_connections_hash(gconstpointer key);
gboolean	potential_connections_equal(gconstpointer a, gconstpointer b);
guint		failed_connections_hash(gconstpointer key);
gboolean	failed_connections_equal(gconstpointer a, gconstpointer b);