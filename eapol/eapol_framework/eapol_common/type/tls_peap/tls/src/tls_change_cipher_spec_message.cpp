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
	#define EAP_FILE_NUMBER_ENUM 127 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_tools.h"
#include "eap_array.h"
#include "eap_array_algorithms.h"
#include "tls_change_cipher_spec_message.h"
#include "tls_record_header.h"
#include "tls_peap_types.h"


/** @file */

//--------------------------------------------------

EAP_FUNC_EXPORT tls_change_cipher_spec_message_c::~tls_change_cipher_spec_message_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_change_cipher_spec_message_c::tls_change_cipher_spec_message_c(
	abs_eap_am_tools_c * const tools,
	abs_tls_change_cipher_spec_c * const change_cipher_spec,
	const bool is_client)
: m_am_tools(tools)
, m_change_cipher_spec(change_cipher_spec)
, m_tls_change_cipher_spec_message_buffer(tools)
, m_type(tls_change_cipher_spec_type_none)
, m_is_client(is_client)
, m_is_valid(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_change_cipher_spec_message_c::set_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_change_cipher_spec_message_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_change_cipher_spec_message_c::set_change_cipher_spec_type(
	const tls_change_cipher_spec_type_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_type = type;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_change_cipher_spec_type_e tls_change_cipher_spec_message_c::get_change_cipher_spec_type() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_change_cipher_spec_message_c::create_message_data()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: data_function: tls_change_cipher_spec_message_c::create_message_data(): tls_change_cipher_spec_type_change_cipher_spec\n"),
		 (m_is_client == true ? "client": "server")));

	eap_status_e status = eap_status_not_supported;

	m_tls_change_cipher_spec_message_buffer.reset();
	status = m_tls_change_cipher_spec_message_buffer.set_buffer_length(TLS_PEAP_DEFAULT_RECORD_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t change_cipher_spec_data_length_start = m_tls_change_cipher_spec_message_buffer.get_data_length();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u8_t type = static_cast<u8_t>(m_type);

	status = m_tls_change_cipher_spec_message_buffer.add_data(
		&type,
		sizeof(type));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-change_cipher_spec type"),
														   &type,
														   sizeof(type)));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (status == eap_status_ok)
	{
		u32_t change_cipher_spec_data_length
			= m_tls_change_cipher_spec_message_buffer.get_data_length()
			- change_cipher_spec_data_length_start;

		EAP_UNREFERENCED_PARAMETER(change_cipher_spec_data_length); // in release

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("change_cipher_spec length %d bytes.\n"),
			 change_cipher_spec_data_length));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_change_cipher_spec_message_c::add_message_data(
	eap_variable_data_c * const tls_message_buffer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: data_function: tls_change_cipher_spec_message_c::add_message_data(): tls_change_cipher_spec_type_change_cipher_spec\n"),
		 (m_is_client == true ? "client": "server")));

	eap_status_e status = eap_status_not_supported;

	if (m_tls_change_cipher_spec_message_buffer.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	status = tls_message_buffer->add_data(
		m_tls_change_cipher_spec_message_buffer.get_data(m_tls_change_cipher_spec_message_buffer.get_data_length()),
		m_tls_change_cipher_spec_message_buffer.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------



// End.
