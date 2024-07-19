#include <pcap.h>
#include <unistd.h>
#include "process_packet.h"

void packet_handler(u_char*						args,
					const struct pcap_pkthdr*	pkt_hdr,
					const u_char*				pkt)
{
	const struct ip*		ip_hdr	= (struct ip*) (pkt + 14);
	const struct tcphdr*	tcp_hdr	= (struct tcphdr*) (pkt + 14 + (ip_hdr->ip_hl * 4));
	char					src_ip[INET_ADDRSTRLEN],
							dst_ip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
	
	uint16_t	src_port	= ntohs(tcp_hdr->th_sport);
	uint16_t	dst_port	= ntohs(tcp_hdr->th_dport);
	bool		is_syn		= tcp_hdr->th_flags & TH_SYN;
	bool		is_ack		= tcp_hdr->th_flags & TH_ACK;
	bool		is_rst		= tcp_hdr->th_flags & TH_RST;

	Context* ctx = (Context*) args;
	PacketInfo pkt_info;
    strcpy(pkt_info.src_ip, src_ip);
    strcpy(pkt_info.dst_ip, dst_ip);
    pkt_info.src_port = src_port;
    pkt_info.dst_port = dst_port;

	if(is_syn && is_ack)		{ process_syn_ack(ctx, &pkt_info); }
	else if(is_syn && is_rst)	{ process_rst(ctx, &pkt_info); }
	else if(is_syn)				{ process_syn(ctx, &pkt_info); }
}

void* records_reader(void* data)
{
	Context*		ctx = (Context*) data;
    GAsyncQueue*	queue = ctx->records;
    while(true)
	{
		if(g_async_queue_length(queue))
		{
			char* message = (char*) g_async_queue_pop(queue);
			if(!message) { continue; }
			g_print("%s\n", message);
			if(ctx->file)
			{
				fprintf(ctx->file, "%s\n", message);
				fflush(ctx->file);
			}
			g_free(message);
		}
		else
		{
			 g_usleep(G_USEC_PER_SEC);
		}
    }
}

void* silent_drop_validator(void* data)
{
	Context* ctx = (Context*) data;
    while (true)
	{
        g_mutex_lock(&ctx->potential_connections_mutex);

        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, ctx->potential_connections);
        while(g_hash_table_iter_next(&iter, &key, &value))
		{
            PacketInfo* packet = (PacketInfo*) key;
            time_t current_time = time(NULL);
            if(current_time - packet->last_syn_time >= TIMEOUT_THRESHOLD_SECONDS)
			{
                g_debug("No SYN-ACK response. Connection (src: %s:%u - dst: %s:%u) will be considered as failed.",
                        packet->src_ip, packet->src_port, packet->dst_ip, packet->dst_port);
				report_failed_connection(ctx, packet);
                g_hash_table_iter_remove(&iter);
            }
        }

        g_mutex_unlock(&ctx->potential_connections_mutex);

        g_usleep(G_USEC_PER_SEC * 5);
    }
}

typedef struct
{
	bool	debug_mode;
	bool	quiet_mode;
	char*	filename;
	char*	interface;
} CliArgs;

void print_help(const char *prog_name)
{
    g_print("Usage: %s [-d] [-f filename]\n", prog_name);
	g_print("Options:\n");
    g_print("  -d           Enable debug mode.\n");
    g_print("  -f filename  Specify a file for logging.\n");
	g_print("  -i interface Specify an interface for tracking.\n");
    g_print("  --help       Display this help message and exit.\n");
}

void print_error_and_exit(const char *message) {
   
}

int parse_args(int argc, char** argv, CliArgs* cli_args)
{
	int opt;
	cli_args->debug_mode	= false;
	cli_args->filename		= NULL;
	cli_args->interface		= NULL;

    while((opt = getopt(argc, argv, "f:di:")) != -1)
	{
        switch(opt)
		{
            case 'f':
                cli_args->filename = optarg;
                break;
			case 'd':
                cli_args->debug_mode = true;
                break;
			case 'i':
                cli_args->interface = optarg;
                break;
			default:
				print_help(argv[0]);
				break;
        }
    }

	if(!cli_args->interface)
	{
		g_printerr("Interface is mandatory parameter.\n");
		return -1;
	}

	if(optind < argc && strcmp(argv[optind], "--help") == 0)
	{
        print_help(argv[0]);
    }

	return 0;
}

int main(int argc, char** argv)
{
	CliArgs cli_args;
	if(parse_args(argc, argv, &cli_args)) { return -1; }

	if(cli_args.debug_mode)	{ g_setenv("G_MESSAGES_DEBUG", "all", true); }
	else					{ g_unsetenv("G_MESSAGES_DEBUG"); }

	Context ctx;
	init_context(&ctx);
	if(cli_args.filename)
	{
		ctx.file = fopen(cli_args.filename, "a");
		if(!ctx.file)
		{
			g_printerr("Error opening file for writing\n");
			return -1;
		}
	}

	char				err_buff[PCAP_ERRBUF_SIZE];
	struct bpf_program	filter;
	char				filter_exp[] = "tcp";
	bpf_u_int32			subnet_mask, 
						ip;

	if(pcap_lookupnet(cli_args.interface, &ip, &subnet_mask, err_buff) == -1)
	{
		ip			= 0;
		subnet_mask = 0;
	}

	pcap_t* handle = pcap_open_live(cli_args.interface,
									BUFSIZ,
							   		0,
							   		10000,
							   		err_buff);
	if(!handle)
	{
		g_printerr("Could not open device %s: %s\n", cli_args.interface, err_buff);
		return -1;
	}

	if(pcap_compile(handle, &filter, filter_exp, 0, ip) == -1)
	{
		g_printerr("Failed to compiler a filter - %s\n", pcap_geterr(handle));
		return -1;
	}

	if(pcap_setfilter(handle, &filter) == -1)
	{
		g_printerr("Failed to set a filter - %s\n", pcap_geterr(handle));
		return -1;
	}

	pthread_t	reader_thread,
				validator_thread;

	pthread_create(&reader_thread, NULL, records_reader, &ctx);
	pthread_create(&validator_thread, NULL, silent_drop_validator, &ctx);

	pcap_loop(handle, 0, packet_handler, (u_char*)&ctx);
	pcap_close(handle);

	pthread_join(reader_thread, NULL);
	pthread_join(validator_thread, NULL);

	clean_context(&ctx);

	return 0;
}
