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
* Description:  This class defines one SIMPLE_CONFIG-message.
*
*/

/*
* %version: 18.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 596 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_array.h"
#include "simple_config_message.h"
#include "simple_config_types.h"

/** @file */


//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_message_c::~simple_config_message_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_message_c::simple_config_message_c(
	abs_eap_am_tools_c * const tools,
	const bool is_client)
	: m_am_tools(tools)
	, m_simple_config_message_data(tools)
	, m_received_eap_identifier(0ul)
	, m_is_client(is_client)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_message_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_received_eap_identifier = 0ul;

	eap_status_e status = m_simple_config_message_data.reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_message_c::set_simple_config_message_data(
	eap_variable_data_c * const simple_config_message_data,
	u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_simple_config_message_data.set_copy_of_buffer(simple_config_message_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_received_eap_identifier = received_eap_identifier;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * simple_config_message_c::get_simple_config_message_data()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_simple_config_message_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_message_c::add_padding(const u32_t block_size)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok;

	u32_t data_length = m_simple_config_message_data.get_data_length();
	u32_t remaining_bytes = data_length % block_size;

	{
		const u32_t padding_length = block_size - remaining_bytes;

		status = m_simple_config_message_data.set_buffer_length(data_length + padding_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_simple_config_message_data.set_data_length(data_length + padding_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		const u8_t padding_byte = static_cast<u8_t>(padding_length);

		m_am_tools->memset(m_simple_config_message_data.get_data_offset(data_length, padding_length), padding_byte, padding_length);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_message_c::add_padding(): %d bytes\n"),
			(m_is_client == true ? "client": "server"),
			padding_length));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool simple_config_message_c::get_is_valid()
{
	return m_simple_config_message_data.get_is_valid();
}

//--------------------------------------------------

// End.
