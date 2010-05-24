/*
* Copyright (c) 2001-2006 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of the License "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: %
*/

#if !defined(_GSMSIM_RETRANSMISSION_H_)
#define _GSMSIM_RETRANSMISSION_H_

//#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_export.h"
#include "abs_eap_am_crypto.h"
#include "eap_variable_data.h"

/**
 * This class stores the information of re-transmission of EAP-packet.
 * @{ Add more comments. }
 */
class EAP_EXPORT eap_core_retransmission_c
{
private:
	
	abs_eap_am_tools_c * const m_am_tools;

	eap_am_network_id_c *m_send_network_id;
	eap_buf_chain_wr_c *m_sent_packet;
	const u32_t m_header_offset;
	const u32_t m_data_length;

	bool m_is_valid;

	u32_t m_retransmission_time;
	u32_t m_retransmission_counter;

	eap_code_value_e m_eap_code;
	u8_t m_eap_identifier;
	eap_type_value_e m_eap_type;

public:

	EAP_FUNC_IMPORT virtual ~eap_core_retransmission_c();

	EAP_FUNC_IMPORT eap_core_retransmission_c(
		abs_eap_am_tools_c * const tools,
		const eap_am_network_id_c * const send_network_id,
		eap_buf_chain_wr_c * const sent_packet,
		const u32_t header_offset,
		const u32_t data_length,
		const u32_t retransmission_time,
		const u32_t retransmission_counter,
		const eap_code_value_e eap_code,
		const u8_t eap_identifier,
		const eap_type_value_e eap_type);

	EAP_FUNC_IMPORT bool get_is_valid() const;

	EAP_FUNC_IMPORT u32_t get_next_retransmission_counter();

	EAP_FUNC_IMPORT u32_t get_retransmission_counter() const;

	EAP_FUNC_IMPORT u32_t get_next_retransmission_time();

	EAP_FUNC_IMPORT eap_am_network_id_c *get_send_network_id();

	EAP_FUNC_IMPORT eap_buf_chain_wr_c * get_sent_packet() const;

	EAP_FUNC_IMPORT u32_t get_header_offset() const;

	EAP_FUNC_IMPORT u32_t get_data_length() const;

	EAP_FUNC_IMPORT u32_t get_buffer_size() const;

	EAP_FUNC_IMPORT eap_code_value_e get_eap_code() const;

	EAP_FUNC_IMPORT u8_t get_eap_identifier() const;

	EAP_FUNC_IMPORT eap_type_value_e get_eap_type() const;
};


#endif //#if !defined(_GSMSIM_RETRANSMISSION_H_)

//--------------------------------------------------



// End.
