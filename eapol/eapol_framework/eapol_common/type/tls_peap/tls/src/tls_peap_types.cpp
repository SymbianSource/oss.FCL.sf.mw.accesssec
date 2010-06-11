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
	#define EAP_FILE_NUMBER_ENUM 134 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "tls_peap_types.h"

/** @file tls_peap_types.cpp 
 */

//--------------------------------------------------

EAP_FUNC_EXPORT eap_tls_trace_string_c::~eap_tls_trace_string_c()
{
}

EAP_FUNC_EXPORT eap_tls_trace_string_c::eap_tls_trace_string_c()
{
}


#if defined(USE_FAST_EAP_TYPE)

EAP_FUNC_EXPORT eap_const_string eap_tls_trace_string_c::get_eap_fast_state_string(const eap_fast_state_e state)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(state, eap_fast_state_none)
	else EAP_IF_RETURN_STRING(state, eap_fast_state_wait_TLVs)
	else EAP_IF_RETURN_STRING(state, eap_fast_state_wait_crypto_binding_TLV)
	else EAP_IF_RETURN_STRING(state, eap_fast_state_wait_result_TLV)
	else EAP_IF_RETURN_STRING(state, eap_fast_state_wait_PAC_TLV)
	else EAP_IF_RETURN_STRING(state, eap_fast_state_wait_PAC_acknowledge_TLV)
	else EAP_IF_RETURN_STRING(state, eap_fast_state_wait_PAC_TLV_or_plain_eap_success)
	else EAP_IF_RETURN_STRING(state, eap_fast_state_success)
#else
	EAP_UNREFERENCED_PARAMETER(state);	
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown EAP-FAST state");
	}
}

#endif //#if defined(USE_FAST_EAP_TYPE)


EAP_FUNC_EXPORT eap_const_string eap_tls_trace_string_c::get_cipher_suite_string(const tls_cipher_suites_e suite)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(suite, tls_cipher_suites_TLS_NULL_WITH_NULL_NULL)
	else EAP_IF_RETURN_STRING(suite, tls_cipher_suites_TLS_RSA_WITH_RC4_128_MD5)
	else EAP_IF_RETURN_STRING(suite, tls_cipher_suites_TLS_RSA_WITH_RC4_128_SHA)
	else EAP_IF_RETURN_STRING(suite, tls_cipher_suites_TLS_RSA_WITH_3DES_EDE_CBC_SHA)
	else EAP_IF_RETURN_STRING(suite, tls_cipher_suites_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA)
	else EAP_IF_RETURN_STRING(suite, tls_cipher_suites_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA)
	else EAP_IF_RETURN_STRING(suite, tls_cipher_suites_TLS_RSA_WITH_AES_128_CBC_SHA)
	else EAP_IF_RETURN_STRING(suite, tls_cipher_suites_TLS_DHE_DSS_WITH_AES_128_CBC_SHA)
	else EAP_IF_RETURN_STRING(suite, tls_cipher_suites_TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
#if defined(USE_FAST_EAP_TYPE)
	else EAP_IF_RETURN_STRING(suite, tls_cipher_suites_TLS_DH_anon_WITH_AES_128_CBC_SHA)
#endif //#if defined(USE_FAST_EAP_TYPE)
	else
#else
	EAP_UNREFERENCED_PARAMETER(suite);	
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown cipher suite");
	}
}

EAP_FUNC_EXPORT eap_const_string eap_tls_trace_string_c::get_certificate_type_string(const tls_certificate_type_e certificate_type)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(certificate_type, tls_certificate_type_rsa_sign)
	else EAP_IF_RETURN_STRING(certificate_type, tls_certificate_type_dss_sign)
	else EAP_IF_RETURN_STRING(certificate_type, tls_certificate_type_none)
	else
#else
	EAP_UNREFERENCED_PARAMETER(certificate_type);		
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown certificate type");
	}
}

EAP_FUNC_EXPORT eap_const_string eap_tls_trace_string_c::get_compression_method_string(const tls_compression_method_e compression_method)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(compression_method, tls_compression_method_null)
	else EAP_IF_RETURN_STRING(compression_method, tls_compression_method_none)
	else
#else
	EAP_UNREFERENCED_PARAMETER(compression_method);		
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown compression method");
	}
}

EAP_FUNC_EXPORT eap_const_string eap_tls_trace_string_c::get_state_string(const tls_peap_state_e state)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(state, tls_peap_state_none)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_tls_start)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_handshake_type_client_hello)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_handshake_type_server_hello)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_handshake_type_certificate)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_handshake_type_server_key_exchange)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_handshake_type_certificate_request_or_server_hello_done)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_handshake_type_server_hello_done)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_handshake_type_client_key_exchange)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_handshake_type_certificate_verify)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_handshake_type_finished)
#if defined(USE_EAP_TLS_SESSION_TICKET)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_handshake_type_new_session_ticket)
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_change_cipher_spec)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_peap_tunnel_ready)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_full_authentication)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_original_session_resumption)
#if defined(USE_EAP_TLS_SESSION_TICKET)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_stateless_session_resumption)
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_tppd_peapv1_waits_eap_success_or_tunneled_packet)
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_client_send_ttls_plain_ms_chap_v2_empty_ack)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_server_waits_ttls_plain_ms_chap_v2_empty_ack)
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_tunneled_authentication_start)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_wait_application_data)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_process_pending_tls_completions)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_pending_tls_messages_processed)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_tls_success)
	else EAP_IF_RETURN_STRING(state, tls_peap_state_failure)
	else
#else
	EAP_UNREFERENCED_PARAMETER(state);			
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown TLS-state");
	}
}

EAP_FUNC_EXPORT eap_const_string eap_tls_trace_string_c::get_peap_version_string(const peap_version_e peap_version)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(peap_version, peap_version_none)
	else EAP_IF_RETURN_STRING(peap_version, peap_version_0_xp)
	else EAP_IF_RETURN_STRING(peap_version, peap_version_1)
	else EAP_IF_RETURN_STRING(peap_version, peap_version_2)
	else
#else
	EAP_UNREFERENCED_PARAMETER(peap_version);			
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown TLS-tunnel (PEAP) type");
	}
}

EAP_FUNC_EXPORT eap_const_string eap_tls_trace_string_c::get_alert_level_string(const tls_alert_level_e alert_level)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(alert_level, tls_alert_level_warning)
	else EAP_IF_RETURN_STRING(alert_level, tls_alert_level_fatal)
	else EAP_IF_RETURN_STRING(alert_level, tls_alert_level_none)
	else
#else
	EAP_UNREFERENCED_PARAMETER(alert_level);			
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown TLS-alert level");
	}
}

EAP_FUNC_EXPORT eap_const_string eap_tls_trace_string_c::get_alert_description_string(const tls_alert_description_e alert_description)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(alert_description, tls_alert_description_close_notify)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_unexpected_message)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_bad_record_mac)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_decryption_failed)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_record_overflow)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_decompression_failure)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_handshake_failure)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_bad_certificate)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_unsupported_certificate)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_certificate_revoked)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_certificate_expired)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_certificate_unknown)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_illegal_parameter)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_unknown_ca)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_access_denied)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_decode_error)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_decrypt_error)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_export_restriction)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_protocol_version)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_insufficient_security)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_internal_error)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_user_canceled)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_no_renegotiation)
	else EAP_IF_RETURN_STRING(alert_description, tls_alert_description_none)
	else
#else
	EAP_UNREFERENCED_PARAMETER(alert_description);			
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown TLS-alert description");
	}
}


EAP_FUNC_EXPORT eap_const_string eap_tls_trace_string_c::get_tls_session_type_string(const tls_session_type_e tls_session_type)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(tls_session_type, tls_session_type_none)
	else EAP_IF_RETURN_STRING(tls_session_type, tls_session_type_full_authentication)
	else EAP_IF_RETURN_STRING(tls_session_type, tls_session_type_original_session_resumption)
	else EAP_IF_RETURN_STRING(tls_session_type, tls_session_type_stateless_session_resumption)
#if defined(USE_FAST_EAP_TYPE)
	else EAP_IF_RETURN_STRING(tls_session_type, tls_session_type_eap_fast_pac_session_resumption)
	else EAP_IF_RETURN_STRING(tls_session_type, tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP)
#endif //#if defined(USE_FAST_EAP_TYPE)
	else
#else
	EAP_UNREFERENCED_PARAMETER(tls_session_type);			
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown TLS-session type");
	}
}


EAP_FUNC_EXPORT eap_const_string eap_tls_trace_string_c::get_ttls_state_string(const eap_ttls_tunneled_message_state_e ttls_state)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(ttls_state, eap_ttls_tunneled_message_state_none)
	else EAP_IF_RETURN_STRING(ttls_state, eap_ttls_tunneled_message_state_process_identity_response)
	else EAP_IF_RETURN_STRING(ttls_state, eap_ttls_tunneled_message_state_process_identity_response)
	else EAP_IF_RETURN_STRING(ttls_state, eap_ttls_tunneled_message_state_process_response)
	else EAP_IF_RETURN_STRING(ttls_state, eap_ttls_tunneled_message_state_process_change_password_response)
	else EAP_IF_RETURN_STRING(ttls_state, eap_ttls_tunneled_message_state_process_identity_request)
	else EAP_IF_RETURN_STRING(ttls_state, eap_ttls_tunneled_message_state_process_identity_request_pending)
	else EAP_IF_RETURN_STRING(ttls_state, eap_ttls_tunneled_message_state_process_challenge_request)
	else EAP_IF_RETURN_STRING(ttls_state, eap_ttls_tunneled_message_state_process_success_request)
	else EAP_IF_RETURN_STRING(ttls_state, eap_ttls_tunneled_message_state_complete_success_request)
	else EAP_IF_RETURN_STRING(ttls_state, eap_ttls_tunneled_message_state_process_error_request)
	else EAP_IF_RETURN_STRING(ttls_state, eap_ttls_tunneled_message_state_complete_error_request)
	else
#else
	EAP_UNREFERENCED_PARAMETER(ttls_state);			
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown TTLS-state");
	}
}


EAP_FUNC_EXPORT eap_const_string eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(const tls_identity_privacy_handshake_state_e privacy_state)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(privacy_state, tls_identity_privacy_handshake_state_none)
	else EAP_IF_RETURN_STRING(privacy_state, tls_identity_privacy_handshake_state_negotiates)
	else EAP_IF_RETURN_STRING(privacy_state, tls_identity_privacy_handshake_state_runs)
	else
#else
	EAP_UNREFERENCED_PARAMETER(privacy_state);			
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown privacy-state");
	}
}

//--------------------------------------------------

// End.
