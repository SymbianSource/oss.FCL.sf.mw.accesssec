/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/ec_cs_tlv_message.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 6 % << Don't touch! Updated by Synergy at check-out.
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
	#define EAP_FILE_NUMBER_ENUM 704 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#if defined(USE_WAPI_CORE)

#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_array.h"
#include "ec_cs_tlv_message.h"

/** @file */


//--------------------------------------------------

EAP_FUNC_EXPORT ec_cs_tlv_message_c::~ec_cs_tlv_message_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT ec_cs_tlv_message_c::ec_cs_tlv_message_c(
	abs_eap_am_tools_c * const tools,
	const bool is_client)
	: m_am_tools(tools)
	, m_message_data(tools)
	, m_is_client(is_client)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_message_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_message_data.reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_message_c::set_ec_cs_message_data(
	eap_variable_data_c * const ec_cs_message_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_message_data.set_copy_of_buffer(ec_cs_message_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * ec_cs_tlv_message_c::get_ec_cs_message_data()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_message_data;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_cs_tlv_message_c::add_padding(const u32_t block_size)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok;

	u32_t data_length = m_message_data.get_data_length();
	u32_t remaining_bytes = data_length % block_size;

	{
		const u32_t padding_length = block_size - remaining_bytes;

		status = m_message_data.set_buffer_length(data_length + padding_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_message_data.set_data_length(data_length + padding_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		const u8_t padding_byte = static_cast<u8_t>(padding_length);

		m_am_tools->memset(m_message_data.get_data_offset(data_length, padding_length), padding_byte, padding_length);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EC-CS: %s: message_function: ec_cs_tlv_message_c::add_padding(): %d bytes\n"),
			(m_is_client == true ? "client": "server"),
			padding_length));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool ec_cs_tlv_message_c::get_is_valid()
{
	return m_message_data.get_is_valid();
}

//--------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
