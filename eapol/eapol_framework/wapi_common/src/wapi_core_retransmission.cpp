/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wapi_core_retransmission.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 10 % << Don't touch! Updated by Synergy at check-out.
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
* Template version: 4.1.1
*/

// This is enumeration of WAPI source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 47 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_export.h"
#include "abs_eap_base_timer.h"
#include "wapi_core_retransmission.h"
#include "eap_am_network_id.h"
#include "wai_message.h"

//--------------------------------------------------

EAP_FUNC_EXPORT wapi_core_retransmission_c::~wapi_core_retransmission_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	delete m_send_network_id;
	m_send_network_id = 0;

	delete m_wai_message_data;
	m_wai_message_data = 0;

	delete m_wai_received_message_data;
	m_wai_received_message_data = 0;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT wapi_core_retransmission_c::wapi_core_retransmission_c(
	abs_eap_am_tools_c * const tools,
	const eap_am_network_id_c * const send_network_id,
	const wai_message_c * const received_wai_message_data_or_null,
	const wai_message_c * const wai_message_data,
	const u32_t retransmission_time,
	const u32_t retransmission_counter,
	const u16_t packet_sequence_number,
	const wai_protocol_subtype_e wapi_subtype)
	: m_am_tools(tools)
	, m_send_network_id(send_network_id->copy())
	, m_wai_message_data(wai_message_data->copy())
	, m_wai_received_message_data(0)
	, m_is_valid(false)
	, m_retransmission_time(retransmission_time)
	, m_retransmission_counter(retransmission_counter)
	, m_packet_sequence_number(packet_sequence_number)
	, m_wapi_subtype(wapi_subtype)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	//EAP_ASSERT(m_send_network_id->get_source() != 0);
	//EAP_ASSERT(m_send_network_id->get_destination() != 0);

	if (received_wai_message_data_or_null != 0)
	{
		m_wai_received_message_data = received_wai_message_data_or_null->copy();
	}

	if (m_send_network_id != 0
		&& m_wai_message_data != 0
		&& m_wai_message_data->get_is_valid() == true)
	{
		m_is_valid = true;
	}
	else
	{
		delete m_send_network_id;
		m_send_network_id = 0;

		delete m_wai_message_data;
		m_wai_message_data = 0;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool wapi_core_retransmission_c::get_is_valid() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t wapi_core_retransmission_c::get_next_retransmission_counter()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return --m_retransmission_counter;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t wapi_core_retransmission_c::get_retransmission_counter() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_retransmission_counter;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t wapi_core_retransmission_c::get_next_retransmission_time()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	u32_t time = m_retransmission_time;

	u32_t jitter_data = 0ul;
	i32_t jitter = 0;
	eap_status_e status = m_am_tools->get_crypto()->get_rand_bytes(
		reinterpret_cast<u8_t *>(&jitter_data),
		sizeof(jitter_data));
	if (status != eap_status_ok)
	{
		jitter = 0;
	}
	else
	{
		// Jitter should be -m_retransmission_time/2 ... m_retransmission_time/2.
		jitter_data = (jitter_data % (m_retransmission_time));
		jitter = jitter_data - m_retransmission_time/2;
	}
	m_retransmission_time += (m_retransmission_time + jitter);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return time;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_network_id_c *wapi_core_retransmission_c::get_send_network_id() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_send_network_id;
}

//--------------------------------------------------

EAP_FUNC_EXPORT const wai_message_c * wapi_core_retransmission_c::get_wai_message_data() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_wai_message_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u16_t wapi_core_retransmission_c::get_packet_sequence_number() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_packet_sequence_number;
}

//--------------------------------------------------

EAP_FUNC_EXPORT const wai_message_c * wapi_core_retransmission_c::get_wai_received_message_data() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_wai_received_message_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT wai_protocol_subtype_e wapi_core_retransmission_c::get_wapi_subtype() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_wapi_subtype;
}

//--------------------------------------------------

// End.
