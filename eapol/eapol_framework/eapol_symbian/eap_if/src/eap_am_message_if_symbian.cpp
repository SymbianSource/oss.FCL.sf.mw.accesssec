/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* %version: 19 %
*/

// INCLUDES
#include <e32std.h>

#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "eap_am_message_if_symbian.h"
#include "eap_variable_data.h"
#include "eap_automatic_variable.h"
#include "EapServerStrings.h"

//-----------------------------------------------------------------------------------------

/**
 * C++ default constructor.
 */
EAP_FUNC_EXPORT eap_am_message_if_symbian_c::eap_am_message_if_symbian_c(
	abs_eap_am_tools_c * const tools,
	const TEapRequests if_request)
: m_am_tools(tools)
, m_partner(0)
, m_if_request(if_request)
, m_is_valid(false)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("eap_am_message_if_symbian_c::eap_am_message_if_symbian_c(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_am_message_if_symbian_c::eap_am_message_if_symbian_c()");

	if (m_am_tools == 0
		|| m_am_tools->get_is_valid() == false)
	{
		return;
	}

	m_is_valid = true;
}

//-----------------------------------------------------------------------------------------

/**
 * Destructor.
 */
EAP_FUNC_EXPORT eap_am_message_if_symbian_c::~eap_am_message_if_symbian_c()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("eap_am_message_if_symbian_c::~eap_am_message_if_symbian_c(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_am_message_if_symbian_c::~eap_am_message_if_symbian_c()");

	m_partner = 0;
}

//-----------------------------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_am_message_if_symbian_c::set_partner(abs_eap_am_message_if_c * const client)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("eap_am_message_if_symbian_c::set_partner(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_am_message_if_symbian_c::set_partner()");

	m_partner = client;

	if (m_partner == 0)
	{
		m_is_valid = false;
	}

}

//-----------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_message_if_symbian_c::configure(
	const eap_variable_data_c * const client_configuration)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("eap_am_message_if_symbian_c::configure(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_am_message_if_symbian_c::configure()");

	TBuf<KMaxServerExe> ServerName;
	TBuf<KMaxServerExe> ServerExe;

	GetServerNameAndExe(&ServerName, &ServerExe);

	const void * aConfigurationData = 0;
	TInt aConfigurationDataLength = 0ul;

	if (client_configuration != 0)
	{
		aConfigurationData = client_configuration->get_data();
		aConfigurationDataLength = client_configuration->get_data_length();
	}

	TRAPD(err, iSession.ConnectL(m_am_tools, this, ServerName, ServerExe, aConfigurationData, aConfigurationDataLength, m_if_request));

	if(err)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_message_if_symbian_c::configure(): - iSession.ConnectL err=%d\n"), err ));    
	}

	return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
}

//-----------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_message_if_symbian_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("eap_am_message_if_symbian_c::shutdown(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_am_message_if_symbian_c::shutdown()");

    iSession.Close();

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//-----------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_message_if_symbian_c::process_data(const void * const data, const u32_t length)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("eap_am_message_if_symbian_c::process_data(): this = 0x%08x, m_if_request=%d=%s.\n"),
		this,
		m_if_request,
		EapServerStrings::GetEapRequestsString(m_if_request)));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_am_message_if_symbian_c::process_data()");

	TEapRequests aRequest(EEapNone);

	if (m_if_request == EEapPluginNew)
	{
		aRequest = EEapPluginProcessData;
	}
	else if (m_if_request == EEapSettingsNew)
	{
		aRequest = EEapSettingsProcessData;
	}
	else if (m_if_request == EEapPacStoreNew)
	{
		aRequest = EEapPacStoreProcessData;
	}
	else if (m_if_request == EWapiCoreIfNew)
    {
        aRequest = EWapiCoreProcessData;
    }
    else if (m_if_request == EWapiSettingsNew)
    {
        aRequest = EWapiSettingsProcessData;
    }

	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("eap_am_message_if_symbian_c::process_data(): calls iSession.process_data(), this = 0x%08x, aRequest=%d=%s.\n"),
		this,
		aRequest,
		EapServerStrings::GetEapRequestsString(aRequest)));

	return EAP_STATUS_RETURN(
		m_am_tools,
		m_am_tools->convert_am_error_to_eapol_error(
			iSession.process_data(aRequest, data, length)));
}

//-----------------------------------------------------------------------------------------

EAP_FUNC_EXPORT bool eap_am_message_if_symbian_c::get_is_valid()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("eap_am_message_if_symbian_c::get_is_valid(): this = 0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_am_message_if_symbian_c::get_is_valid()");

	return m_is_valid;
}

//-----------------------------------------------------------------------------------------

/// Function sends the data message to lower layer.
/// Data is formatted to Attribute-Value Pairs.
/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
EAP_FUNC_EXPORT eap_status_e eap_am_message_if_symbian_c::send_data(const TDesC8& message)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("eap_am_message_if_symbian_c::send_data(): this = 0x%08x, data=0x%08x, length=%d.\n"),
		this,
		message.Ptr(),
		message.Length()));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, EAP_TRACE_FLAGS_MESSAGE_DATA, "returns: eap_am_message_if_symbian_c::send_data()");

	return EAP_STATUS_RETURN(
		m_am_tools, 
		m_partner->send_data(message.Ptr(), message.Length()));
}

//-----------------------------------------------------------------------------------------

// End of file.

