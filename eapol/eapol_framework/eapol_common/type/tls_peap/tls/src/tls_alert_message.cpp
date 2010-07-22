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
	#define EAP_FILE_NUMBER_ENUM 122 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_tools.h"
#include "eap_array.h"
#include "eap_array_algorithms.h"
#include "tls_alert_message.h"
#include "tls_record_header.h"
#include "tls_peap_types.h"


/** @file */

//--------------------------------------------------

EAP_FUNC_EXPORT tls_alert_message_c::~tls_alert_message_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_alert_message_c::tls_alert_message_c(
	abs_eap_am_tools_c * const tools,
	const bool is_client)
: m_am_tools(tools)
, m_tls_alert_message_buffer(tools)
, m_alert_level(tls_alert_level_none)
, m_alert_description(tls_alert_description_none)
, m_is_client(is_client)
, m_is_valid(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_alert_message_c::set_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_alert_message_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_alert_message_c::set_alert_level(const tls_alert_level_e alert_level)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_alert_level = alert_level;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_alert_level_e tls_alert_message_c::get_alert_level() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_alert_level;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_alert_message_c::set_alert_description(const tls_alert_description_e alert_description)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_alert_description = alert_description;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_alert_description_e tls_alert_message_c::get_alert_description() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_alert_description;
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_alert_message_c::create_message_data()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: %s: data_function: tls_alert_description_e::create_message_data()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status = eap_status_not_supported;

	m_tls_alert_message_buffer.reset();
	status = m_tls_alert_message_buffer.set_buffer_length(TLS_PEAP_DEFAULT_RECORD_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t alert_data_length_start = m_tls_alert_message_buffer.get_data_length();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		u8_t alert_level = static_cast<u8_t>(m_alert_level);

		status = m_tls_alert_message_buffer.add_data(
			&alert_level,
			sizeof(alert_level));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-alert alert_level"),
															   &alert_level,
															   sizeof(alert_level)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		u8_t alert_description = static_cast<u8_t>(m_alert_description);

		status = m_tls_alert_message_buffer.add_data(
			&alert_description,
			sizeof(alert_description));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS-alert alert_description"),
															   &alert_description,
															   sizeof(alert_description)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (status == eap_status_ok)
	{
		u32_t alert_data_length = m_tls_alert_message_buffer.get_data_length() - alert_data_length_start;
		EAP_UNREFERENCED_PARAMETER(alert_data_length); // in release
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("alert length %d bytes.\n"),
			 alert_data_length));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_alert_message_c::add_message_data(
	eap_variable_data_c * const tls_message_buffer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: %s: data_function: tls_alert_message_c::add_message_data()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status = eap_status_not_supported;

	if (m_tls_alert_message_buffer.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	status = tls_message_buffer->add_data(
		m_tls_alert_message_buffer.get_data(m_tls_alert_message_buffer.get_data_length()),
		m_tls_alert_message_buffer.get_data_length());
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
