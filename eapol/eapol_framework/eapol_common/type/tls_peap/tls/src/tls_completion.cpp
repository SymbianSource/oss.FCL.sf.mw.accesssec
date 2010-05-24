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
	#define EAP_FILE_NUMBER_ENUM 128 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_tools.h"
#include "eap_array.h"
#include "tls_completion.h"
#include "tls_peap_types.h"

/** @file */


//--------------------------------------------------

EAP_FUNC_EXPORT tls_completion_c::~tls_completion_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_completion_c::tls_completion_c(
	abs_eap_am_tools_c * const tools,
	tls_completion_action_e completion_action)
: m_am_tools(tools)
, m_completion_action(completion_action)
, m_is_valid(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_completion_c::set_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_completion_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_completion_c::set_completion_action(tls_completion_action_e completion_action)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_completion_action = completion_action;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_completion_action_e tls_completion_c::get_completion_action() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_completion_action;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string tls_completion_c::get_completion_action_string() const
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_none)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_create_handshake_type_hello_request)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_create_handshake_type_client_hello)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_create_handshake_type_server_hello)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_create_handshake_type_certificate)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_create_handshake_type_server_key_exchange)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_create_handshake_type_certificate_request)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_create_handshake_type_server_hello_done)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_create_handshake_type_certificate_verify)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_create_handshake_type_client_key_exchange)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_create_handshake_type_finished)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_finish_handshake)
#if defined(USE_EAP_TLS_SESSION_TICKET)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_create_handshake_type_new_session_ticket)
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_create_change_cipher_spec_type_change_cipher_spec)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_query_dh_parameters)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_verify_certificate_chain)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_process_tls_records)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_check_sent_tls_message)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_complete_create_handshake_type_server_key_exchange)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_complete_create_handshake_type_certificate_verify)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_complete_create_handshake_type_client_key_exchange)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_query_cipher_suites_and_previous_session)
	else EAP_IF_RETURN_STRING(m_completion_action, tls_completion_action_check_tunnel_authentication_runs)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown completion_action");
	}
}

//--------------------------------------------------



// End.
