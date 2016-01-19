/*weixin.c (Wechat)*/

#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_WEIXIN

static void ndpi_int_weixin_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
				       struct ndpi_flow_struct *flow/* , */
				       /* ndpi_protocol_type_t protocol_type */)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WEIXIN, NDPI_PROTOCOL_UNKNOWN);
}


void ndpi_search_weixin_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    NDPI_LOG(NDPI_PROTOCOL_WEIXIN,ndpi_struct, NDPI_LOG_DEBUG,"weixin detection...\n");
    
    /* skip marked packets by checking if the detection protocol statck */
    if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_WEIXIN) {
        /*ndpi_check_weinxin(ndpi_struct, flow);*/
        /*------------TODO-----------*/
    }
    
}
void ndpi_search_weixin(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	
  if (packet->tcp != NULL && flow->detected_protocol_stack[0] != NDPI_PROTOCOL_QQ)
    ndpi_search_weixin_tcp(ndpi_struct, flow);
}


void init_weixin_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("WEIXIN", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_WEIXIN,
				      ndpi_search_weixin,
                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}


#endif
