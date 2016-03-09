/*iqiyi.c*/

#include "ndpi_api.h"

#ifdef NDPI_SERVICE_IQIYI

static void ndpi_int_iqiyi_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
				       struct ndpi_flow_struct *flow/* , */
				       /* ndpi_protocol_type_t protocol_type */)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_SERVICE_IQIYI, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_iqiyi_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_SERVICE_IQIYI,ndpi_struct, NDPI_LOG_DEBUG,"iqiyi detection...\n");
    /* skip marked packets by checking if the detection protocol statck */
    /*if (packet->detected_protocol_stack[0] == NDPI_SERVICE_YOUKU) 
        return ;
*/
    if (
#ifdef NDPI_PROTOCOL_HTTP
            packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
#endif    
            ((packet->payload_packet_len > 3 && memcmp(packet->payload, "GET ", 4) == 0) ||
             (packet->payload_packet_len > 4 && memcmp(packet->payload, "POST", 5) == 0))) {
        ndpi_parse_packet_line_info(ndpi_struct, flow);
		if (packet->referer_line.ptr != NULL &&
            packet->referer_line.len > NDPI_STATICSTRING_LEN("http://www.iqiyi.com/") && 
            memcmp(packet->referer_line.ptr,"http://www.iqiyi.com/", NDPI_STATICSTRING_LEN("http://www.iqiyi.com/")) == 0) {
    //        printf("detected iqiyi with referer_line......hahhahhah\n");
            ndpi_int_iqiyi_add_connection(ndpi_struct, flow);
            return;
        }
    }
  return;
}
void ndpi_search_iqiyi(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  if (packet->tcp != NULL && flow->detected_protocol_stack[0] != NDPI_SERVICE_IQIYI)
      ndpi_search_iqiyi_tcp(ndpi_struct, flow);
}


void init_iqiyi_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("IQIYI", ndpi_struct, detection_bitmask, *id,
				      NDPI_SERVICE_IQIYI,
				      ndpi_search_iqiyi,
                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}


#endif
