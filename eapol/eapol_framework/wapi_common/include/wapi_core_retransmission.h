/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wapi_core_retransmission.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 8 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.2
*/



#if !defined(_WAPI_CORE_RETRANSMISSION_H_)
#define _WAPI_CORE_RETRANSMISSION_H_

#include "eap_tools.h"
#include "eap_am_export.h"
#include "abs_eap_am_crypto.h"
#include "wai_variable_data.h"

class eap_am_network_id_c;
class wai_message_c;


/**
 * This class stores the information of re-transmission of WAI-packet.
 * @todo { Add more comments. }
 */
class wapi_core_retransmission_c
{
private:
	
	abs_eap_am_tools_c * const m_am_tools;

	eap_am_network_id_c *m_send_network_id;

	const wai_message_c * m_wai_message_data;

	const wai_message_c * m_wai_received_message_data;

	bool m_is_valid;

	u32_t m_retransmission_time;
	u32_t m_retransmission_counter;
	u16_t m_packet_sequence_number;
	wai_protocol_subtype_e m_wapi_subtype;

public:

	EAP_FUNC_IMPORT virtual ~wapi_core_retransmission_c();

	EAP_FUNC_IMPORT wapi_core_retransmission_c(
		abs_eap_am_tools_c * const tools,
		const eap_am_network_id_c * const send_network_id,
		const wai_message_c * const received_wai_message_data_or_null,
		const wai_message_c * const wai_message_data,
		const u32_t retransmission_time,
		const u32_t retransmission_counter,
		const u16_t packet_sequence_number,
		const wai_protocol_subtype_e wapi_subtype);

	EAP_FUNC_IMPORT bool get_is_valid() const;

	EAP_FUNC_IMPORT u32_t get_next_retransmission_counter();

	EAP_FUNC_IMPORT u32_t get_retransmission_counter() const;

	EAP_FUNC_IMPORT u32_t get_next_retransmission_time();

	EAP_FUNC_IMPORT eap_am_network_id_c *get_send_network_id() const;

	EAP_FUNC_IMPORT const wai_message_c * get_wai_message_data() const;

	EAP_FUNC_IMPORT const wai_message_c * get_wai_received_message_data() const;

	EAP_FUNC_IMPORT u16_t get_packet_sequence_number() const;

	EAP_FUNC_IMPORT wai_protocol_subtype_e get_wapi_subtype() const;
};


#endif //#if !defined(_WAPI_CORE_RETRANSMISSION_H_)

//--------------------------------------------------

// End.
