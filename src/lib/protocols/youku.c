/*youku.c*/

#include "ndpi_api.h"

#ifdef NDPI_SERVICE_YOUKU

static void ndpi_int_youku_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
				       struct ndpi_flow_struct *flow/* , */
				       /* ndpi_protocol_type_t protocol_type */)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_SERVICE_YOUKU, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_youku_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    NDPI_LOG(NDPI_SERVICE_YOUKU,ndpi_struct, NDPI_LOG_DEBUG,"youku detection...\n");
    /* skip marked packets by checking if the detection protocol statck */
    /*if (packet->detected_protocol_stack[0] == NDPI_SERVICE_YOUKU) 
        return ;
*/
    if (
#ifdef NDPI_PROTOCOL_HTTP
            packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
#endif    
            ((packet->payload_packet_len > 3 && memcmp(packet->payload, "GET ", 4) == 0) ||
             (packet->payload_packet_len > 4 && memcmp(packet->payload, "POST", 5) == 0) ||
             (packet->payload_packet_len > NDPI_STATICSTRING_LEN("HTTP/1.1 20") && 
              ((memcmp(packet->payload,"HTTP/1.1 20",NDPI_STATICSTRING_LEN("HTTP/1.1 20")) == 0) ||
              (memcmp(packet->payload,"HTTP/1.0 20",NDPI_STATICSTRING_LEN("HTTP/1.0 20")) == 0))
             ))) {
        ndpi_parse_packet_line_info(ndpi_struct, flow);
        if (packet->server_line.ptr != NULL &&
            packet->server_line.len > NDPI_STATICSTRING_LEN("YOUKU") && 
            ((memcmp(packet->server_line.ptr,"YOUKU.NB",NDPI_STATICSTRING_LEN("YOUKU.NB")) == 0) ||
             (memcmp(packet->server_line.ptr,"YouKu",NDPI_STATICSTRING_LEN("YouKu")) == 0) ||
             (memcmp(packet->server_line.ptr,"IKUACC",NDPI_STATICSTRING_LEN("IKUACC")) == 0)
            )) {
            printf("detected youku by server_line\n");
            ndpi_int_youku_add_connection(ndpi_struct, flow);
            return;
        }else if (packet->referer_line.ptr != NULL &&
            packet->referer_line.len > NDPI_STATICSTRING_LEN("http://static.youku.com/") && 
            memcmp(packet->referer_line.ptr,"http://static.youku.com/", NDPI_STATICSTRING_LEN("http://static.youku.com/")) == 0) {
            //printf("detected youku with referer_line......hahhahhah\n");
            ndpi_int_youku_add_connection(ndpi_struct, flow);
            return;
        }
    }
#if 0
    if (packet->packet_direction == flow->setup_packet_direction)
        return;

    if ((packet->payload_packet_len <= NDPI_STATICSTRING_LEN("HTTP/1.1 20"))
        || (packet->payload == NULL)
        || (memcmp(packet->payload, "HTTP/1.1 ",NDPI_STATICSTRING_LEN("HTTP/1.1 ")) != 0))
    {
        return;
    }
    if ((packet->payload[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] == '2' ||
            packet->payload[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] == '3' ||
            packet->payload[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] == '4' ||
            packet->payload[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] == '5')) {
//#ifdef NDPI_CONTENT_QUICKTIME
        ndpi_parse_packet_line_info(ndpi_struct, flow);
        if(packet->server_line.ptr != NULL) {
            printf("server_line=%s\n",packet->server_line.ptr);
        }

        if (packet->detected_protocol_stack[0] == NDPI_CONTENT_QUICKTIME &&
            packet->server_line.ptr != NULL && 
            packet->server_line.len > NDPI_STATICSTRING_LEN("YOUKU") &&
            ((memcmp(packet->server_line.ptr, "YOUKU.NB",NDPI_STATICSTRING_LEN("YOUKU.NB")) == 0) ||
             (memcmp(packet->server_line.ptr, "youku",NDPI_STATICSTRING_LEN("youku")) == 0))) {
            //NDPI_LOG(NDPI_SERVICE_YOUKU,ndpi_struct,NDPI_LOG_DEBUG,"youku detected.\n");
            printf("...............youku detected ...............");
            ndpi_int_youku_add_connection(ndpi_struct, flow);
            return;
        }
//#endif
    }
#endif
   return;
}
void ndpi_search_youku(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  if (packet->tcp != NULL && flow->detected_protocol_stack[0] != NDPI_SERVICE_YOUKU)
      ndpi_search_youku_tcp(ndpi_struct, flow);
}


void init_youku_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("YOUKU", ndpi_struct, detection_bitmask, *id,
				      NDPI_SERVICE_YOUKU,
				      ndpi_search_youku,
                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}


#endif
