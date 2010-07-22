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

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 47 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_export.h"
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "abs_eap_base_timer.h"
#include "eap_core_retransmission.h"
#include "eap_buffer.h"
#include "eap_am_network_id.h"

//--------------------------------------------------

EAP_FUNC_EXPORT eap_core_retransmission_c::~eap_core_retransmission_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	if (m_send_network_id != 0)
	{
		delete m_send_network_id;
		m_send_network_id = 0;
	}
	if (m_sent_packet != 0)
	{
		delete m_sent_packet;
		m_sent_packet = 0;
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_core_retransmission_c::eap_core_retransmission_c(
	abs_eap_am_tools_c * const tools,
	const eap_am_network_id_c * const send_network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t retransmission_time,
	const u32_t retransmission_counter,
	const eap_code_value_e eap_code,
	const u8_t eap_identifier,
	const eap_type_value_e eap_type)
	: m_am_tools(tools)
	, m_send_network_id(send_network_id->copy())
	, m_sent_packet(sent_packet->copy())
	, m_header_offset(header_offset)
	, m_data_length(data_length)
	, m_is_valid(false)
	, m_retransmission_time(retransmission_time)
	, m_retransmission_counter(retransmission_counter)
	, m_eap_code(eap_code)
	, m_eap_identifier(eap_identifier)
	, m_eap_type(eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_send_network_id != 0
		&& m_sent_packet != 0
		&& m_send_network_id->get_is_valid_data() == true)
	{
		m_is_valid = true;
	}
	else
	{
		if (m_send_network_id != 0)
		{
			delete m_send_network_id;
			m_send_network_id = 0;
		}
		if (m_send_network_id != 0)
		{
			delete m_sent_packet;
			m_sent_packet = 0;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_core_retransmission_c::get_is_valid() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_core_retransmission_c::get_next_retransmission_counter()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return --m_retransmission_counter;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_core_retransmission_c::get_retransmission_counter() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_retransmission_counter;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_core_retransmission_c::get_next_retransmission_time()
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

EAP_FUNC_EXPORT eap_am_network_id_c *eap_core_retransmission_c::get_send_network_id()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_send_network_id;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_buf_chain_wr_c * eap_core_retransmission_c::get_sent_packet() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_sent_packet;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_core_retransmission_c::get_header_offset() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_header_offset;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_core_retransmission_c::get_data_length() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_data_length;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_core_retransmission_c::get_buffer_size() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_sent_packet->get_buffer_length();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_code_value_e eap_core_retransmission_c::get_eap_code() const
{
	return m_eap_code;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t eap_core_retransmission_c::get_eap_identifier() const
{
	return m_eap_identifier;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_type_value_e eap_core_retransmission_c::get_eap_type() const
{
	return m_eap_type;
}

//--------------------------------------------------



// End.
