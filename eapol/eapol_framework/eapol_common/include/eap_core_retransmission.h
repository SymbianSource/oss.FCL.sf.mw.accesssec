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
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_CORE_RETRANSMISSION_H)
	#define EAP_CLASS_VISIBILITY_EAP_CORE_RETRANSMISSION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H 
	#define EAP_FUNC_EXPORT_EAP_CORE_RETRANSMISSION_H 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_RETRANSMISSION_H 
#elif defined(EAP_EXPORT_EAP_CORE_RETRANSMISSION_H)
	#define EAP_CLASS_VISIBILITY_EAP_CORE_RETRANSMISSION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_CORE_RETRANSMISSION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_RETRANSMISSION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_CORE_RETRANSMISSION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_CORE_RETRANSMISSION_H 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_RETRANSMISSION_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_crypto.h"
#include "eap_variable_data.h"

/**
 * This class stores the information of re-transmission of EAP-packet.
 * @{ Add more comments. }
 */
class EAP_CLASS_VISIBILITY_EAP_CORE_RETRANSMISSION_H eap_core_retransmission_c
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

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H virtual ~eap_core_retransmission_c();

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H eap_core_retransmission_c(
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

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H bool get_is_valid() const;

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H u32_t get_next_retransmission_counter();

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H u32_t get_retransmission_counter() const;

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H u32_t get_next_retransmission_time();

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H eap_am_network_id_c *get_send_network_id();

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H eap_buf_chain_wr_c * get_sent_packet() const;

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H u32_t get_header_offset() const;

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H u32_t get_data_length() const;

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H u32_t get_buffer_size() const;

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H eap_code_value_e get_eap_code() const;

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H u8_t get_eap_identifier() const;

	EAP_FUNC_VISIBILITY_EAP_CORE_RETRANSMISSION_H eap_type_value_e get_eap_type() const;
};


#endif //#if !defined(_GSMSIM_RETRANSMISSION_H_)

//--------------------------------------------------



// End.
