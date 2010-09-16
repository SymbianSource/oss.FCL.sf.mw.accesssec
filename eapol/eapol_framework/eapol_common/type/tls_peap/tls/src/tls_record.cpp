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
* %version: 200 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 135 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_am_export.h"
#include "eap_am_tools.h"
#include "eap_tools.h"
#include "eap_crypto_api.h"
#include "abs_tls_base_record.h"
#include "tls_base_record.h"
#include "tls_record.h"
#include "tls_am_services.h"
#include "tls_handshake_header.h"
#include "tls_peap_types.h"
#include "tls_message.h"
#include "eap_automatic_variable.h"
#include "eap_state_notification.h"
#include "eap_type_tls_peap_types.h"
#include "eap_header_string.h"

#if defined(USE_FAST_EAP_TYPE)
	#include "eap_fast_tlv_payloads.h"
#endif //#if defined(USE_FAST_EAP_TYPE)

#if defined(USE_EAP_TLS_SESSION_TICKET)
#include "tls_extension.h"
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

//--------------------------------------------------

#define EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(tools, status) \
	EAP_STATUS_RETURN(tools, eap_status_return_and_create_tls_protocol_alert((status)))


EAP_FUNC_EXPORT eap_status_e tls_record_c::eap_status_return_and_create_tls_protocol_alert(
	const eap_status_e status)
{
	if (status != eap_status_ok
		&& status != eap_status_success
		&& status != eap_status_pending_request
		&& status != eap_status_drop_packet_quietly)
	{
		(void) create_tls_protocol_alert(tls_alert_description_none, tls_alert_level_none, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_record_c::~tls_record_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("this = 0x%08x, %s: function: starts: tls_record_c::~tls_record_c(): m_am_tls_services")
					 EAPL(" = 0x%08x (validity %d).\n"),
					 this,
					 (m_is_client == true ? "client": "server"),
					 m_am_tls_services,
					 m_am_tls_services->get_is_valid()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::~tls_record_c()");

	EAP_ASSERT(m_shutdown_was_called == true);

	completion_action_clenup();

	if (m_free_am_tls_services == true)
	{
		delete m_am_tls_services;
	}
	m_am_tls_services = 0;

	if (m_free_application == true)
	{
		delete m_application;
	}
	m_application = 0;

	reset_block_ciphers(true);
	reset_block_ciphers(false);

	reset_stream_ciphers(true);
	reset_stream_ciphers(false);

	reset_hmac_algorithms(true);
	reset_hmac_algorithms(false);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

EAP_FUNC_EXPORT tls_record_c::tls_record_c(
	abs_eap_am_tools_c * const tools, ///< tools is pointer to the tools class. @see abs_eap_am_tools_c.
	tls_am_services_c * const am_tls_services, ///< This is pointer to adaptation module of TLS.
	const bool free_am_tls_services,
	tls_base_application_c * const application, ///< application is pointer to application object.
	const bool free_application,
	const bool is_client_when_true, ///< Indicates whether this is client (true) or server (false).
	const eap_type_value_e eap_type,
	const eap_am_network_id_c * const receive_network_id)
	: tls_base_record_c(tools /*, partner */)
	, m_am_tools(tools)
	, m_am_tls_services(am_tls_services)
	, m_free_am_tls_services(free_am_tls_services)
	, m_application(application)
	, m_free_application(free_application)
	, m_completion_queue(tools)
	, m_received_tls_message(tools, this, this, this, is_client_when_true)
	, m_new_tls_message(tools, this, this, this, is_client_when_true)
	, m_message_hash_md5(tools)
	, m_message_hash_sha1(tools)
	, m_message_hash_md5_certificate_verify(tools)
	, m_message_hash_sha1_certificate_verify(tools)
	, m_client_message_hash_md5_finished(tools)
	, m_client_message_hash_sha1_finished(tools)
	, m_server_message_hash_md5_finished(tools)
	, m_server_message_hash_sha1_finished(tools)
	, m_client_handshake_random_value(tools)
	, m_server_handshake_random_value(tools)
	, m_session_id(tools)
	, m_master_secret(tools)
	, m_eap_master_session_key(tools, eap_type)
	, m_new_send_mac_key(tools)
	, m_new_receive_mac_key(tools)
	, m_new_send_encryption_key(tools)
	, m_new_receive_encryption_key(tools)
	, m_new_send_iv(tools)
	, m_new_receive_iv(tools)
	, m_send_mac_key(tools)
	, m_receive_mac_key(tools)
	, m_send_encryption_key(tools)
	, m_receive_encryption_key(tools)
	, m_send_iv(tools)
	, m_receive_iv(tools)
	, m_session_key_seed(tools)
	, m_mschapv2_challenges(tools)
	, m_own_private_dhe_key(tools)
	, m_own_public_dhe_key(tools)
	, m_peer_public_dhe_key(tools)
	, m_shared_dh_key(tools)
	, m_dhe_prime(tools)
	, m_dhe_group_generator(tools)
	, m_signed_message_hash(tools)
	, m_premaster_secret(tools)
	, m_own_encrypted_premaster_secret(tools)
#if defined(USE_FAST_EAP_TYPE)
	, m_eap_fast_pac_key(tools)
#endif //#if defined(USE_FAST_EAP_TYPE)
	, m_proposed_cipher_suites(tools)
	, m_proposed_compression_methods(tools)
#if defined(USE_EAP_TLS_SESSION_TICKET)
	, m_supported_tls_extensions(tools)
	, m_received_tls_extensions(tools)
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
	, m_NAI_realm(tools)
	, m_send_network_id(tools)
	, m_own_certificate_chain(tools)
	, m_own_certificate_types(tools)
	, m_own_certificate_authorities(tools)
	, m_peer_certificate_chain(tools)
	, m_peer_certificate_chain_result(eap_status_illegal_certificate)
	, m_verify_signature(eap_status_authentication_failure)
	, m_peer_certificate_types(tools)
	, m_peer_certificate_authorities(tools)
	, m_resumed_cipher_suite(tls_cipher_suites_none)
	, m_selected_cipher_suite(tls_cipher_suites_none)
	, m_selected_compression_method(tls_compression_method_none)
	, m_receive_cipher_suite(tls_cipher_suites_TLS_NULL_WITH_NULL_NULL)
	, m_receive_compression_method(tls_compression_method_null)
	, m_send_cipher_suite(tls_cipher_suites_TLS_NULL_WITH_NULL_NULL)
	, m_send_compression_method(tls_compression_method_null)
	, m_send_block_cipher(0)
	, m_receive_block_cipher(0)
	, m_send_stream_cipher(0)
	, m_receive_stream_cipher(0)
	, m_send_hmac_algorithm(0)
	, m_receive_hmac_algorithm(0)
	, m_send_record_sequence_number(0ul)
	, m_receive_record_sequence_number(0ul)
	, m_tls_peap_state(tls_peap_state_wait_tls_start)
	, m_tls_session_type(tls_session_type_none)
	, m_eap_type(eap_type)
	, m_peap_version(peap_version_none)
	, m_tunneled_eap_type_authentication_state(eap_state_none)
	, m_is_valid(false)
	, m_is_client(is_client_when_true)
	, m_allow_message_send(true)
	, m_already_in_completion_action_check(false)
	, m_already_in_process_tls_records(false)
	, m_pending_query_certificate_authorities_and_types(false)
	, m_pending_query_certificate_chain(false)
	, m_pending_query_cipher_suites_and_previous_session(false)
	, m_pending_query_dh_parameters(false)
	, m_pending_query_realm(false)
	, m_pending_select_cipher_suite_and_check_session_id(false)
	, m_pending_verify_certificate_chain(false)
	, m_pending_rsa_decrypt_with_private_key(false)
	, m_pending_rsa_encrypt_with_public_key(false)
	, m_pending_sign_with_private_key(false)
	, m_pending_verify_with_public_key(false)
	, m_pending_query_tunnel_PAC(false)
	, m_tls_peap_test_version(false)
	, m_key_material_generated(false)
	, m_tls_peap_server_authenticates_client_policy_flag(true)
	, m_tls_peap_server_authenticates_client_config_server(true)
	, m_tls_peap_server_authenticates_client_action(true)
	, m_tls_peap_server_requested_client_certificate(false)
	, m_could_send_fatal_alert_message(true)
	, m_could_send_warning_alert_message(true)
	, m_force_tls_message_send(false)
	, m_shutdown_was_called(false)
	, m_use_separate_tls_record(true)  // Some vendors seems to use only separate TLS-records. Windows RAS and FreeRadius works too with this.
	, m_use_extra_padding_length(false) // It seems that EAP-TLS of Microsoft Windows does not work with extra padding.
	, m_client_allows_empty_certificate_authorities_list(false)
	, m_server_sends_empty_certificate_authorities_list(false)
	, m_use_tppd_tls_peap(true)
	, m_use_tppd_peapv1_acknowledge_hack(false)
	, m_server_offers_new_session_id(true)
	, m_will_receive_new_session_ticket(false)
	, m_send_piggypacked_eap_identity_request(true)
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	, m_tls_use_identity_privacy(false)
	, m_tls_identity_privacy_handshake_state(tls_identity_privacy_handshake_state_none)
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
#if defined(USE_FAST_EAP_TYPE)
	, m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP(false)
	, m_remove_tunnel_pac(false)
#endif //#if defined(USE_FAST_EAP_TYPE)
	{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: function: starts: tls_record_c::tls_record_c(): "),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::tls_record_c()");

#if defined(USE_FAST_EAP_TYPE)
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: tls_record_c::tls_record_c(): EAP-FAST enabled.")));
#else
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: tls_record_c::tls_record_c(): EAP-FAST disabled.")));
#endif //#if defined(USE_FAST_EAP_TYPE)

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		// No need to delete anything here because it is done in destructor.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	if (m_am_tls_services == 0
		|| m_am_tls_services->get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_TLS_PEAP_ERROR,
						(EAPL("ERROR: %s: function: tls_record_c::tls_record_c() failed,")
						 EAPL(" m_am_tls_services = 0x%08x (validity %d) is invalid.\n"),
						 (m_is_client == true ? "client": "server"),
						 m_am_tls_services, (m_am_tls_services != 0) ? m_am_tls_services->get_is_valid() : false));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}
	m_am_tls_services->set_tls_am_partner(this);

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(
		m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());

	eap_status_e status = m_send_network_id.set_copy_of_network_id(&send_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	if (get_is_tunneled_tls() == true
		&& m_application == 0)
	{
		// Application is required in tunneled mode.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	if (m_application != 0)
	{
		m_application->set_application_partner(this);
	}

	if (m_is_client == false)
	{
		set_state(tls_peap_state_wait_handshake_type_client_hello);
	}

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_c::reset_block_ciphers(const bool send_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (send_when_true == true)
	{
		delete m_send_block_cipher;
		m_send_block_cipher = 0;
	}
	else
	{
		delete m_receive_block_cipher;
		m_receive_block_cipher = 0;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_c::reset_stream_ciphers(const bool send_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (send_when_true == true)
	{
		delete m_send_stream_cipher;
		m_send_stream_cipher = 0;
	}
	else
	{
		delete m_receive_stream_cipher;
		m_receive_stream_cipher = 0;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_c::reset_hmac_algorithms(const bool send_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (send_when_true == true)
	{
		delete m_send_hmac_algorithm;
		m_send_hmac_algorithm = 0;
	}
	else
	{
		delete m_receive_hmac_algorithm;
		m_receive_hmac_algorithm = 0;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_c::set_state(const tls_peap_state_e state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: state_function: starts: tls_record_c::set_state() from %s to %s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
		 eap_tls_trace_string_c::get_state_string(state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::set_state()");

	if (m_tls_peap_state != tls_peap_state_failure)
	{
		m_tls_peap_state = state;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_peap_state_e tls_record_c::get_state() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_tls_peap_state;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_c::verify_state(const tls_peap_state_e state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	bool are_equal = false;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: state_function: starts: tls_record_c::verify_state(): (current state %s) %s (new state %s)\n"),
		 (m_is_client == true ? "client": "server"),
		 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
		 ((m_tls_peap_state == state) ? "==" : "!="),
		 eap_tls_trace_string_c::get_state_string(state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::verify_state()");

	if (m_tls_peap_state == state)
	{
		are_equal = true;
	}
	else
	{
		are_equal = false;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return are_equal;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_c::set_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_c::get_is_tunneled_tls()
{
	return (
		m_eap_type == eap_type_peap
		|| m_eap_type == eap_type_ttls
#if defined(USE_FAST_EAP_TYPE)
		|| m_eap_type == eap_type_fast
#endif //#if defined(USE_FAST_EAP_TYPE)
		);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_c::set_peap_version(
	const peap_version_e peap_version,
	const bool use_tppd_tls_peap,
	const bool use_tppd_peapv1_acknowledge_hack)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_peap_version = peap_version;

	m_use_tppd_tls_peap = use_tppd_tls_peap;

	m_use_tppd_peapv1_acknowledge_hack = use_tppd_peapv1_acknowledge_hack;

	m_am_tls_services->set_peap_version(
		peap_version,
		use_tppd_tls_peap,
		use_tppd_peapv1_acknowledge_hack);

	if (m_application != 0)
	{
		m_application->set_peap_version(
			peap_version,
			use_tppd_tls_peap,
			use_tppd_peapv1_acknowledge_hack);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: function: starts: tls_record_c::configure():\n"),
		 this,
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::configure()");

	eap_status_e status = m_am_tls_services->configure();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c test_version(m_am_tools);

		status = get_type_partner()->read_configure(
			cf_str_EAP_TLS_test_version.get_field(),
			&test_version);
		if (status == eap_status_ok
			&& test_version.get_is_valid_data() == true
			&& test_version.get_data_length() == sizeof(u32_t)
			&& test_version.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(test_version.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_tls_peap_test_version = false;
				}
				else
				{
					m_tls_peap_test_version = true;
				}
			}
		}

		status = eap_status_ok;
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c use_separate_tls_record(m_am_tools);

		status = get_type_partner()->read_configure(
			cf_str_TLS_use_separate_tls_record.get_field(),
			&use_separate_tls_record);
		if (status == eap_status_ok
			&& use_separate_tls_record.get_is_valid_data() == true
			&& use_separate_tls_record.get_data_length() == sizeof(u32_t)
			&& use_separate_tls_record.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				use_separate_tls_record.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_use_separate_tls_record = false;
				}
				else
				{
					m_use_separate_tls_record = true;
				}
			}
		}

		status = eap_status_ok;
	}

	//----------------------------------------------------------

	if (m_is_client == false)
	{
		eap_variable_data_c server_offers_new_session_id(m_am_tools);

		status = get_type_partner()->read_configure(
			cf_str_TLS_server_offers_new_session_id.get_field(),
			&server_offers_new_session_id);
		if (status == eap_status_ok
			&& server_offers_new_session_id.get_is_valid_data() == true
			&& server_offers_new_session_id.get_data_length() == sizeof(u32_t)
			&& server_offers_new_session_id.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				server_offers_new_session_id.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_server_offers_new_session_id = false;
				}
				else
				{
					m_server_offers_new_session_id = true;
				}
			}
		}

		status = eap_status_ok;
	}

	//----------------------------------------------------------

	if (get_is_tunneled_tls() == true)
	{
		// Default function in PEAP and TTLS is only client authenticates server.
		m_tls_peap_server_authenticates_client_config_server = false;
	}

	if (m_is_client == false)
	{
		eap_variable_data_c server_authenticates_client(m_am_tools);

		status = get_type_partner()->read_configure(
			cf_str_TLS_server_authenticates_client.get_field(),
			&server_authenticates_client);
		if (status == eap_status_ok
			&& server_authenticates_client.get_is_valid_data() == true
			&& server_authenticates_client.get_data_length() == sizeof(u32_t)
			&& server_authenticates_client.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				server_authenticates_client.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_tls_peap_server_authenticates_client_config_server = false;
				}
				else
				{
					m_tls_peap_server_authenticates_client_config_server = true;
				}
			}
		}

		if (m_tls_peap_server_authenticates_client_config_server == false)
		{
			m_tls_peap_server_authenticates_client_action = false;
		}

		status = eap_status_ok;
	}

	//----------------------------------------------------------

	if (get_is_tunneled_tls() == true)
	{
		// Default function in PEAP and TTLS is only client authenticates server.
		m_tls_peap_server_authenticates_client_policy_flag = false;
	}

	if (m_is_client == true)
	{
		eap_variable_data_c server_authenticates_client(m_am_tools);

		status = get_type_partner()->read_configure(
			cf_str_TLS_server_authenticates_client_policy_in_client.get_field(),
			&server_authenticates_client);
		if (status == eap_status_ok
			&& server_authenticates_client.get_is_valid_data() == true
			&& server_authenticates_client.get_data_length() == sizeof(u32_t)
			&& server_authenticates_client.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				server_authenticates_client.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_tls_peap_server_authenticates_client_policy_flag = false;
				}
				else
				{
					m_tls_peap_server_authenticates_client_policy_flag = true;
				}
			}
		}

		status = eap_status_ok;
	}
	else
	{
		eap_variable_data_c server_authenticates_client(m_am_tools);

		status = get_type_partner()->read_configure(
			cf_str_TLS_server_authenticates_client_policy_in_server.get_field(),
			&server_authenticates_client);
		if (status == eap_status_ok
			&& server_authenticates_client.get_is_valid_data() == true
			&& server_authenticates_client.get_data_length() == sizeof(u32_t)
			&& server_authenticates_client.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				server_authenticates_client.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_tls_peap_server_authenticates_client_policy_flag = false;
				}
				else
				{
					m_tls_peap_server_authenticates_client_policy_flag = true;
				}
			}
		}

		status = eap_status_ok;
	}

	//----------------------------------------------------------

	if (m_is_client == true)
	{
		eap_variable_data_c client_allows_empty_certificate_authorities_list(m_am_tools);

		status = get_type_partner()->read_configure(
			cf_str_TLS_client_allows_empty_certificate_authorities_list.get_field(),
			&client_allows_empty_certificate_authorities_list);
		if (status == eap_status_ok
			&& client_allows_empty_certificate_authorities_list.get_is_valid_data() == true
			&& client_allows_empty_certificate_authorities_list.get_data_length() == sizeof(u32_t)
			&& client_allows_empty_certificate_authorities_list.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				client_allows_empty_certificate_authorities_list.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_client_allows_empty_certificate_authorities_list = false;
				}
				else
				{
					m_client_allows_empty_certificate_authorities_list = true;
				}
			}
		}

		status = eap_status_ok;
	}
	else
	{
		eap_variable_data_c server_sends_empty_certificate_authorities_list(m_am_tools);

		status = get_type_partner()->read_configure(
			cf_str_TLS_server_sends_empty_certificate_authorities_list.get_field(),
			&server_sends_empty_certificate_authorities_list);
		if (status == eap_status_ok
			&& server_sends_empty_certificate_authorities_list.get_is_valid_data() == true
			&& server_sends_empty_certificate_authorities_list.get_data_length() == sizeof(u32_t)
			&& server_sends_empty_certificate_authorities_list.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				server_sends_empty_certificate_authorities_list.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_server_sends_empty_certificate_authorities_list = false;
				}
				else
				{
					m_server_sends_empty_certificate_authorities_list = true;
				}
			}
		}

		status = eap_status_ok;
	}

	//----------------------------------------------------------

	if (m_is_client == false)
	{
		eap_variable_data_c send_piggypacked_eap_identity_request(m_am_tools);

		status = get_type_partner()->read_configure(
			cf_str_EAP_FAST_send_piggypacked_eap_identity_request.get_field(),
			&send_piggypacked_eap_identity_request);
		if (status == eap_status_ok
			&& send_piggypacked_eap_identity_request.get_is_valid_data() == true
			&& send_piggypacked_eap_identity_request.get_data_length() == sizeof(u32_t)
			&& send_piggypacked_eap_identity_request.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				send_piggypacked_eap_identity_request.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_send_piggypacked_eap_identity_request = false;
				}
				else
				{
					m_send_piggypacked_eap_identity_request = true;
				}
			}
		}

		status = eap_status_ok;
	}

	//----------------------------------------------------------

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

	{
		eap_variable_data_c tls_use_privacy(m_am_tools);

		status = get_type_partner()->read_configure(
			cf_str_EAP_TLS_PEAP_use_identity_privacy.get_field(),
			&tls_use_privacy);
		if (status == eap_status_ok
			&& tls_use_privacy.get_is_valid_data() == true
			&& tls_use_privacy.get_data_length() == sizeof(u32_t)
			&& tls_use_privacy.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				tls_use_privacy.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_tls_use_identity_privacy = false;
				}
				else
				{
					m_tls_use_identity_privacy = true;
				}
			}
		}

		status = eap_status_ok;
	}

	if (m_is_client == false)
	{
		eap_variable_data_c tls_server_use_privacy(m_am_tools);

		status = get_type_partner()->read_configure(
			cf_str_EAP_TLS_PEAP_use_identity_privacy_server.get_field(),
			&tls_server_use_privacy);
		if (status == eap_status_ok
			&& tls_server_use_privacy.get_is_valid_data() == true
			&& tls_server_use_privacy.get_data_length() == sizeof(u32_t)
			&& tls_server_use_privacy.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				tls_server_use_privacy.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_tls_use_identity_privacy = false;
				}
				else
				{
					m_tls_use_identity_privacy = true;
				}
			}
		}

		status = eap_status_ok;
	}

#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

	//----------------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)
	if (m_eap_type == eap_type_fast)
	{
		// Client and server configuration.
		{
			eap_variable_data_c provisioning(m_am_tools);

			status = get_type_partner()->read_configure(
				cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP.get_field(),
				&provisioning);
			if (status == eap_status_ok
				&& provisioning.get_is_valid_data() == true
				&& provisioning.get_data_length() == sizeof(u32_t)
				&& provisioning.get_data(sizeof(u32_t)) != 0)
			{
				// This is optional value.
				u32_t *flag = reinterpret_cast<u32_t *>(
					provisioning.get_data(sizeof(u32_t)));
				if (flag != 0)
				{
					if (*flag == 0)
					{
						m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP = false;
					}
					else
					{
						m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP = true;
					}
				}
			}

			status = eap_status_ok;
		}

		{
			eap_variable_data_c allow_server_authenticated_provisioning_mode(m_am_tools);

			status = read_configure(
				cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode.get_field(),
				&allow_server_authenticated_provisioning_mode);
			if (status == eap_status_ok
				&& allow_server_authenticated_provisioning_mode.get_is_valid_data() == true
				&& allow_server_authenticated_provisioning_mode.get_data_length() == sizeof(u32_t)
				&& allow_server_authenticated_provisioning_mode.get_data(sizeof(u32_t)) != 0)
			{
				// This is optional value.
				u32_t *flag = reinterpret_cast<u32_t *>(
					allow_server_authenticated_provisioning_mode.get_data(sizeof(u32_t)));
				if (flag != 0)
				{
					if (*flag == 0)
					{
						m_fast_allow_server_authenticated_provisioning_mode = false;
					}
					else
					{
						m_fast_allow_server_authenticated_provisioning_mode = true;
					}
				}
			}

			status = eap_status_ok;
		}

	}
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

	//----------------------------------------------------------

	status = message_hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	//----------------------------------------------------------

	if (m_application != 0)
	{
		status = m_application->configure();
	}
	else
	{
		status = eap_status_ok;
	}

	//----------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: function: starts: tls_record_c::shutdown():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::shutdown()");

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	if (m_tls_peap_state != tls_peap_state_tls_success)
	{
		set_state(tls_peap_state_failure);
	}

	eap_status_e status = eap_status_ok;

	if (m_application != 0)
	{
		status = m_application->shutdown();
	}


	if (m_pending_query_certificate_authorities_and_types == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: function: tls_record_c::shutdown(): calls cancel_query_certificate_authorities_and_types()\n")));

		m_am_tls_services->cancel_query_certificate_authorities_and_types();
		m_pending_query_certificate_authorities_and_types = false;
	}

	if (m_pending_query_certificate_chain == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: function: tls_record_c::shutdown(): calls cancel_query_certificate_chain()\n")));

		m_am_tls_services->cancel_query_certificate_chain();
		m_pending_query_certificate_chain = false;
	}

	if (m_pending_query_cipher_suites_and_previous_session == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: function: tls_record_c::shutdown(): calls cancel_query_cipher_suites_and_previous_session()\n")));

		m_am_tls_services->cancel_query_cipher_suites_and_previous_session();
		m_pending_query_cipher_suites_and_previous_session = false;
	}

	if (m_pending_query_dh_parameters == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: function: tls_record_c::shutdown(): calls cancel_query_dh_parameters()\n")));

		m_am_tls_services->cancel_query_dh_parameters();
		m_pending_query_dh_parameters = false;
	}

	if (m_pending_query_realm == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: function: tls_record_c::shutdown(): calls cancel_query_realm()\n")));

		m_am_tls_services->cancel_query_realm();
		m_pending_query_realm = false;
	}

	if (m_pending_select_cipher_suite_and_check_session_id == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: function: tls_record_c::shutdown(): calls cancel_select_cipher_suite_and_check_session_id()\n")));

		m_am_tls_services->cancel_select_cipher_suite_and_check_session_id();
		m_pending_select_cipher_suite_and_check_session_id = false;
	}

	if (m_pending_verify_certificate_chain == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: function: tls_record_c::shutdown(): calls cancel_verify_certificate_chain()\n")));

		m_am_tls_services->cancel_verify_certificate_chain();
		m_pending_verify_certificate_chain = false;
	}

	if (m_pending_rsa_decrypt_with_private_key == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: function: tls_record_c::shutdown(): calls cancel_rsa_decrypt_with_private_key()\n")));

		m_am_tls_services->cancel_rsa_decrypt_with_private_key();
		m_pending_rsa_decrypt_with_private_key = false;
	}

	if (m_pending_rsa_encrypt_with_public_key == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: function: tls_record_c::shutdown(): calls cancel_rsa_encrypt_with_public_key()\n")));

		m_am_tls_services->cancel_rsa_encrypt_with_public_key();
		m_pending_rsa_encrypt_with_public_key = false;
	}

	if (m_pending_sign_with_private_key == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: function: tls_record_c::shutdown(): calls cancel_sign_with_private_key()\n")));

		m_am_tls_services->cancel_sign_with_private_key();
		m_pending_sign_with_private_key = false;
	}

	if (m_pending_verify_with_public_key == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: function: tls_record_c::shutdown(): calls cancel_verify_with_public_key()\n")));

		m_am_tls_services->cancel_verify_with_public_key();
		m_pending_verify_with_public_key = false;
	}

	if (m_pending_query_tunnel_PAC == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: function: tls_record_c::shutdown(): calls cancel_query_tunnel_PAC()\n")));

		if (m_application != 0)
		{
			m_application->cancel_query_tunnel_PAC();
		}
		m_pending_query_tunnel_PAC = false;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::set_nai_realm(
	const eap_variable_data_c * const NAI_realm)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_NAI_realm.set_copy_of_buffer(NAI_realm);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_c::send_error_notification(const eap_status_e error)
{
	// Notifies the lower level of an authentication error.

	eap_general_state_variable_e general_state_variable(eap_general_state_authentication_error);

	if (error == eap_status_user_cancel_authentication)
	{
		general_state_variable = eap_general_state_authentication_cancelled;
	}

	eap_state_notification_c notification(
		m_am_tools,
		&m_send_network_id,
		true,
		eap_state_notification_eap,
		eap_protocol_layer_general,
		m_eap_type,
		eap_state_none,
		general_state_variable,
		0,
		false);

	notification.set_authentication_error(error);

	get_type_partner()->state_notification(&notification);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::completion_action_add(
	tls_completion_action_e action)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: %s: send_function: completion_action_add()\n"),
					 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::completion_action_add()");

	tls_completion_c *completion_action = new tls_completion_c(
		m_am_tools,
		action);

	if (completion_action == 0
		|| completion_action->get_is_valid() == false)
	{
		delete completion_action;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// add_object() will delete completion_action if operation fails.
	eap_status_e status = m_completion_queue.add_object(completion_action, true);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: %s: send_function: completion_action_add(): action %s\n"),
					 (m_is_client == true ? "client": "server"),
					 completion_action->get_completion_action_string()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::completion_action_clenup()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: %s: send_function: starts: tls_record_c::completion_action_clenup()\n"),
					 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::completion_action_clenup()");

	eap_status_e final_status = eap_status_ok;
	u32_t counter = 0ul;

	while(m_completion_queue.get_object_count() > 0ul)
	{
		tls_completion_c * const completion_action = m_completion_queue.get_object(0ul);
		EAP_UNREFERENCED_PARAMETER(completion_action); // Not referenced without trace.

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: TLS: %s: send_function: completion_action_clenup(): ")
			 EAPL("action[%u] %s not completed.\n"),
			 (m_is_client == true ? "client": "server"),
			 counter,
			 completion_action->get_completion_action_string()));

		final_status = m_completion_queue.remove_object(0ul);
		if (final_status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, final_status);
		}

		++counter;

	} // while()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, final_status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::completion_action_check()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools, TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: send_function: starts: tls_record_c::completion_action_check()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::completion_action_check()");

	if (m_already_in_completion_action_check == true)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		// This is recursive call of completion_action_check().
		// This MUST return eap_status_ok. Other return values will skip
		// further prosessing of completion action list.
		EAP_TRACE_DEBUG(
			m_am_tools, TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: send_function: completion_action_check(): skip recursion\n"),
			(m_is_client == true ? "client": "server")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_already_in_completion_action_check = true;

	eap_automatic_simple_value_c<bool> restore_already_in_completion_action_check(
		m_am_tools,
		&m_already_in_completion_action_check,
		false);

	eap_status_e status = eap_status_ok;
	bool continue_with_next_action = true;
	u32_t counter = 0ul;

	while(continue_with_next_action == true
		&& m_completion_queue.get_object_count() > 0ul)
	{
		status = eap_status_ok;

		tls_completion_c * const completion_action = m_completion_queue.get_object(0ul);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: send_function: completion_action_check(): action[%d] %s\n"),
			 (m_is_client == true ? "client": "server"),
			 counter,
			 completion_action->get_completion_action_string()));

		switch(completion_action->get_completion_action())
		{
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		case tls_completion_action_create_handshake_type_hello_request:
		{
			// We must send Handshake/HelloRequest message.
			eap_status_e status = create_handshake_type_hello_request();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
			}
			break;
		}
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		case tls_completion_action_query_cipher_suites_and_previous_session:
		{
			m_allow_message_send = false;

			status = m_am_tls_services->query_cipher_suites_and_previous_session();

			m_allow_message_send = true;

			if (status == eap_status_pending_request)
			{
				// This is pending query, that will be completed by
				// complete_query_cipher_suites_and_previous_session() call.
				m_pending_query_cipher_suites_and_previous_session = true;

				// Cannot complete yet.
				continue_with_next_action = false;
			}

			break;
		}
		case tls_completion_action_create_handshake_type_client_hello:
		{
			if (m_pending_query_cipher_suites_and_previous_session == false
				&& m_proposed_cipher_suites.get_object_count() > 0ul
				&& m_proposed_compression_methods.get_object_count() > 0ul)
			{
				// We must send Handshake/ClientHello message.
				eap_status_e status = create_handshake_type_client_hello();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}
			else
			{
				// Cannot complete yet.
				continue_with_next_action = false;
			}
			break;
		}
		case tls_completion_action_create_handshake_type_server_hello:
		{
			if (m_pending_select_cipher_suite_and_check_session_id == false
				&& m_selected_cipher_suite != tls_cipher_suites_none
				&& m_selected_compression_method != tls_compression_method_none)
			{
				// We must send Handshake/ServerHello message.
				eap_status_e status = create_handshake_type_server_hello(
					static_cast<u8_t>(m_selected_cipher_suite),
					static_cast<u8_t>(m_selected_compression_method));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}
			else
			{
				// Cannot complete yet.
				continue_with_next_action = false;
			}
			break;
		}
		case tls_completion_action_create_handshake_type_certificate:
		{
			if (m_pending_query_certificate_chain == false
				&& m_pending_verify_certificate_chain == false)
			{
				// We must send Handshake/Certificate message.
				// NOTE m_own_certificate_chain could be empty.
				status = create_handshake_type_certificate(&m_own_certificate_chain);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}
			else
			{
				// Cannot complete yet.
				continue_with_next_action = false;
			}
			break;
		}
		case tls_completion_action_create_handshake_type_server_key_exchange:
		{
			if (m_pending_query_dh_parameters == false)
			{
				if ((cipher_suite_is_TLS_DHE_DSS() == true
					|| cipher_suite_is_TLS_DHE_RSA() == true
#if defined(USE_FAST_EAP_TYPE)
					|| (m_eap_type == eap_type_fast
						&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
						&& cipher_suite_is_TLS_DH_anon() == true)
#endif //#if defined(USE_FAST_EAP_TYPE)
					)
					&& m_dhe_prime.get_is_valid_data() == true
					&& m_dhe_group_generator.get_is_valid_data() == true)
				{
					status = generate_dhe_keys();
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
					}

					// We must send Handshake/ServerKeyExchange.
					status = create_handshake_type_server_key_exchange();
					if (status == eap_status_pending_request)
					{
						// This is pending query, that will be completed by 
						// complete_create_handshake_type_server_key_exchange() call.
					}
					else if (status == eap_status_completed_request)
					{
						// This is already completed by
						// complete_create_handshake_type_server_key_exchange() call.
						status = eap_status_ok;
					}
					else if (status == eap_status_ok)
					{
						// This is also an error case, because this call
						// is always completed on success.
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
							m_am_tools,
							eap_status_process_general_error);
					}
					else // All other status values means error, because this
						// call is always completed on success.
					{
						// This is an error case.
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
					}
				}
				else
				{
					// Cannot complete yet.
					continue_with_next_action = false;
				}
			}
			else
			{
				// Cannot complete yet.
				continue_with_next_action = false;
			}
			break;
		}
		case tls_completion_action_create_handshake_type_certificate_request:
		{
			if (m_pending_query_certificate_authorities_and_types == false
				&& m_own_certificate_types.get_object_count() != 0ul
				&& (m_own_certificate_authorities.get_object_count() != 0ul
					|| m_server_sends_empty_certificate_authorities_list == false))
			{
				// We must send Handshake/CertificateRequest message.
				status = create_handshake_type_certificate_request(
					&m_own_certificate_types,
					&m_own_certificate_authorities);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}
			else
			{
				// Cannot complete yet.
				continue_with_next_action = false;
			}
			break;
		}
		case tls_completion_action_create_handshake_type_server_hello_done:
		{
			status = create_handshake_type_server_hello_done();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
			}

			break;
		}
		case tls_completion_action_create_handshake_type_certificate_verify:
		{
			if (m_pending_query_certificate_chain == false
				&& m_pending_verify_certificate_chain == false
				&& m_own_certificate_chain.get_object_count() > 0ul)
			{
				// We must send Handshake/CertificateVerify.
				status = create_handshake_type_certificate_verify();
				if (status == eap_status_pending_request)
				{
					// This is pending query, that will be completed by
					// complete_create_handshake_type_certificate_verify() call.
				}
				else if (status == eap_status_completed_request)
				{
					// This is already completed by
					// complete_create_handshake_type_certificate_verify() call.
					status = eap_status_ok;
				}
				else if (status == eap_status_ok)
				{
					// This is also an error case, because this
					// call is always completed on success. 
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
						m_am_tools,
						eap_status_process_general_error);
				}
				else // All other status values means error, because this
					// call is always completed on success.
				{
					// This is an error case.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}
			else if (m_pending_query_certificate_chain == false
				&& m_pending_verify_certificate_chain == false
				&& m_own_certificate_chain.get_object_count() == 0ul)
			{
				// No user certificate.
			}
			else
			{
				// Cannot complete yet.
				continue_with_next_action = false;
			}
			break;
		}
		case tls_completion_action_create_handshake_type_client_key_exchange:
		{
			if (m_pending_query_certificate_chain == false
				&& m_pending_verify_certificate_chain == false)
			{
				if (cipher_suite_is_TLS_DHE_DSS() == true
					|| cipher_suite_is_TLS_DHE_RSA() == true
#if defined(USE_FAST_EAP_TYPE)
					|| (m_eap_type == eap_type_fast
						&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
						&& cipher_suite_is_TLS_DH_anon() == true)
#endif //#if defined(USE_FAST_EAP_TYPE)
					)
				{
					// DHE parameters should have been received in ServerKeyExchange message.

					if (m_dhe_prime.get_is_valid_data() == true
						&& m_dhe_group_generator.get_is_valid_data() == true)
					{
						status = generate_dhe_keys();
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
								m_am_tools,
								status);
						}
					}
					else
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
							m_am_tools,
							eap_status_authentication_failure);
					}
				}
				else if (cipher_suite_is_TLS_RSA() == true)
				{
					// Do nothing special.
				}
				else
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
						m_am_tools,
						eap_status_not_supported);
				}
			
				// We must generate premaster secret.
				status = generate_premaster_secret();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
				
				// We must generate master secret.
				status = generate_master_secret();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
				
				// We must generate the key material.
				status = generate_key_material();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}

				// We must send Handshake/ClientKeyExchange.
				status = create_handshake_type_client_key_exchange();
				if (status == eap_status_pending_request)
				{
					// This is pending query, that will be completed by
					// complete_create_handshake_type_client_key_exchange() call.
					// Cannot complete yet.
					continue_with_next_action = false;
				}
				else if (status == eap_status_completed_request)
				{
					// This is already completed by
					// complete_create_handshake_type_client_key_exchange() call.
					status = eap_status_ok;
				}
				else if (status == eap_status_ok)
				{
					// NOTE: This is not always an error case. 
					if (cipher_suite_is_TLS_DHE_DSS() == true
						|| cipher_suite_is_TLS_DHE_RSA() == true
#if defined(USE_FAST_EAP_TYPE)
						|| (m_eap_type == eap_type_fast
							&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
							&& cipher_suite_is_TLS_DH_anon() == true)
#endif //#if defined(USE_FAST_EAP_TYPE)
						)
					{
						// Cipher suites cipher_suite_is_TLS_DHE_DSS()
						// and cipher_suite_is_TLS_DHE_RSA() are syncronous.
						// Do nothing special.
					}
					else if (cipher_suite_is_TLS_RSA() == true)
					{
						// Cipher suites cipher_suite_is_TLS_RSA() are asyncronous
						// and they must NOT return eap_status_ok.
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
							m_am_tools,
							eap_status_process_general_error);
					}
					else
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
							m_am_tools,
							eap_status_not_supported);
					}
				}
				else // All other status values means error, because this
					// call is always completed on success.
				{
					// This is an error case.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}
			else
			{
				// Cannot complete yet.
				continue_with_next_action = false;
			}
			break;
		}
		case tls_completion_action_create_handshake_type_finished:
		{
			// We must send Handshake/Finished.
			status = create_handshake_type_finished();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
			}
			break;
		}
		case tls_completion_action_finish_handshake:
		{
			// We must finish the handshake.
			status = finish_handshake();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
			}
			break;
		}
		case tls_completion_action_create_change_cipher_spec_type_change_cipher_spec:
		{
			// We must send ChangeCipherSpec/ChangeCipherSpec.
			status = create_change_cipher_spec_type_change_cipher_spec();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
			}
			break;
		}
#if defined(USE_EAP_TLS_SESSION_TICKET)
		case tls_completion_action_create_handshake_type_new_session_ticket:
		{
			// We must send Hanshake/NewSessionTicket.
			status = create_handshake_type_new_session_ticket();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
			}
			break;
		}
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
		case tls_completion_action_query_dh_parameters:
		{
			if (m_selected_cipher_suite != tls_cipher_suites_none)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: %s: pki_function: query_dh_parameters()\n"),
					 (m_is_client == true ? "client": "server")));
				// Note, server does not query DH parametrs from certificate chain,
				// instead server should consult it's configuration settings.
				status = m_am_tls_services->query_dh_parameters(0, m_selected_cipher_suite);
				if (status == eap_status_pending_request)
				{
					// This is pending query, that will be completed
					// by complete_query_dh_parameters() call.
					m_pending_query_dh_parameters = true;
				}
				else if (status == eap_status_completed_request)
				{
					// This is already completed by complete_query_dh_parameters() call.
					status = eap_status_ok;
				}
				else if (status == eap_status_ok)
				{
					// This is also an error case, because this call
					// is always completed on success. 
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
						m_am_tools,
						eap_status_process_general_error);
				}
				else // All other status values means error, because this
					// call is always completed on success.
				{
					// This is an error case.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}
			else
			{
				// Cannot complete yet.
				continue_with_next_action = false;
			}
			break;
		}
		case tls_completion_action_process_tls_records:
		{
			if (are_pending_queries_completed() == eap_status_ok)
			{
				status = process_tls_records();
				if (status == eap_status_ok)
				{
					// All pending messages processed.
					// Do nothing special.
				}
				else if (status == eap_status_end_recursion)
				{
					// Break recursion.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, eap_status_ok);
				}
				else if (status == eap_status_pending_request)
				{
					// Cannot complete yet.
					continue_with_next_action = false;
				}
				else 
				{
					// This is an error case.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}

				if ((get_is_tunneled_tls() == false
						&& m_tls_peap_state == tls_peap_state_tls_success)
					|| (get_is_tunneled_tls() == true
						&& m_tls_peap_state == tls_peap_state_peap_tunnel_ready))
				{
					// TLS authentication OK.
					// Note PEAP may continue.
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("TLS: %s: process_tls_records() returned, ")
						 EAPL("TLS authentication successfull.\n"),
						 (m_is_client == true ? "client": "server")));
				}
			}
			else
			{
				// Cannot complete yet.
				continue_with_next_action = false;
			}
			break;
		}
		case tls_completion_action_complete_create_handshake_type_server_key_exchange:
		{
			if (m_signed_message_hash.get_is_valid_data() == true
#if defined(USE_FAST_EAP_TYPE)
				|| (m_eap_type == eap_type_fast
					&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
					&& cipher_suite_is_TLS_DH_anon() == true)
#endif //#if defined(USE_FAST_EAP_TYPE)
				)
			{
				status = complete_create_handshake_type_server_key_exchange();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}
			else
			{
				// Cannot complete yet.
				continue_with_next_action = false;
			}
			break;
		}
		case tls_completion_action_complete_create_handshake_type_certificate_verify:
		{
			if (m_signed_message_hash.get_is_valid_data() == true
				&& m_own_certificate_chain.get_object_count() > 0ul)
			{
				status = complete_create_handshake_type_certificate_verify();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}
			else if (m_own_certificate_chain.get_object_count() == 0ul)
			{
				// No user certificate.
			}
			else
			{
				// Cannot complete yet.
				continue_with_next_action = false;
			}
			break;
		}
		case tls_completion_action_complete_create_handshake_type_client_key_exchange:
		{
			if ((cipher_suite_is_TLS_RSA() == true
				 && m_own_encrypted_premaster_secret.get_is_valid_data() == true)
				|| ((cipher_suite_is_TLS_DHE_DSS() == true
						|| cipher_suite_is_TLS_DHE_RSA() == true
#if defined(USE_FAST_EAP_TYPE)
						|| (m_eap_type == eap_type_fast
							&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
							&& cipher_suite_is_TLS_DH_anon() == true)
#endif //#if defined(USE_FAST_EAP_TYPE)
						)
					&& m_own_encrypted_premaster_secret.get_is_valid_data() == false))
			{
				status = complete_create_handshake_type_client_key_exchange();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}
			else
			{
				// Cannot complete yet.
				continue_with_next_action = false;
			}
			break;
		}
		case tls_completion_action_verify_certificate_chain:
		{
			if (m_peer_certificate_chain.get_object_count() != 0ul
				&& m_selected_cipher_suite != tls_cipher_suites_none
				&& m_pending_query_certificate_chain == false
				&& m_pending_verify_certificate_chain == false)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: %s: pki_function: verify_certificate_chain()\n"),
					 (m_is_client == true ? "client": "server")));

				status = m_am_tls_services->verify_certificate_chain(
					&m_peer_certificate_chain,
					m_selected_cipher_suite);
				if (status == eap_status_pending_request)
				{
					// This is pending query, that will be completed
					// by complete_verify_certificate_chain() call.
					m_pending_verify_certificate_chain = true;
				}
				else if (status == eap_status_completed_request)
				{
					// This is already completed by complete_verify_certificate_chain() call.
					status = eap_status_ok;
				}
				else if (status == eap_status_ok)
				{
					// This is also an error case, because this call is
					// always completed on success. 
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
						m_am_tools,
						eap_status_process_general_error);
				}
				else // All other status values means error, because this
					// call is always completed on success.
				{
					// This is an error case.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}
			else
			{
				// Cannot complete yet.
				continue_with_next_action = false;
			}
			break;
		}
		case tls_completion_action_check_sent_tls_message:
		{
			// Note this call will return eap_status_pending_request if any asyncronous call is pending.
			status = check_sent_tls_message();
			break;
		}
		case tls_completion_action_check_tunnel_authentication_runs:
		{
			// Check we get some tunneled authentication message and tunneled authentication runs or it did finished.
			if (m_tunneled_eap_type_authentication_state == eap_state_none)
			{
				// Here we swap the addresses.
				eap_am_network_id_c receive_network_id(m_am_tools,
					m_send_network_id.get_destination_id(),
					m_send_network_id.get_source_id(),
					m_send_network_id.get_type());

				status = start_peap_tunneled_authentication(
					&receive_network_id,
					m_received_eap_identifier,
					m_tls_session_type);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}
			break;
		}
		default:
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR TLS: %s: send_function: completion_action_check(): ")
				 EAPL("unhandled action[%u] %s.\n"),
				 (m_is_client == true ? "client": "server"),
				 counter,
				 completion_action->get_completion_action_string()));
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
				m_am_tools,
				eap_status_not_supported);
		}
		} // switch()

		if (continue_with_next_action == true
			|| status == eap_status_pending_request)
		{
			const tls_completion_c * const removed_completion_action = m_completion_queue.get_object(0ul);
			EAP_UNREFERENCED_PARAMETER(removed_completion_action); // Not referenced without trace.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: encrypt_function: starts: tls_record_c::completion_action_check(): removes action[%d] %s\n"),
				(m_is_client == true ? "client": "server"),
				0ul,
				removed_completion_action->get_completion_action_string()));

			eap_status_e remove_status = m_completion_queue.remove_object(0ul);
			if (remove_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
			}
		}

		++counter;

	} // while()

	if (continue_with_next_action == false)
	{
		status = eap_status_pending_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u8_t tls_record_c::get_extra_padding_length(
	const u8_t padding_length,
	const u32_t block_size)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: encrypt_function: starts: tls_record_c::get_extra_padding_length()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::get_extra_padding_length()");

	crypto_random_c rand(m_am_tools);

	u8_t count = 0ul;

	if (m_use_extra_padding_length == true)
	{
		eap_status_e status = rand.get_rand_bytes(&count, sizeof(count));
		if (status != eap_status_ok)
		{
			count = 3ul;
		}
	}

	u32_t final_padding_length = ((count * block_size) % 0xff) + padding_length;

	count = static_cast<u8_t>((final_padding_length-padding_length) / block_size);

	while (count > 0ul
		&& (count * block_size)+padding_length > 0xff)
	{
		--count;
	}

	const u8_t final_length = static_cast<u8_t>((count * block_size)+padding_length);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: encrypt_function: get_extra_padding_length(): length = %d = 0x%02x\n"),
		 (m_is_client == true ? "client": "server"),
		 final_length,
		 final_length));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return final_length;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::apply_send_block_cipher_suite(
	eap_variable_data_c * const tls_record_message_buffer,
	abs_crypto_cbc_block_algorithm_c * const encrypt,
	abs_crypto_hmac_algorithm_c * const mac)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: send_function: starts: tls_record_c::apply_send_block_cipher_suite(): %s\n"),
		(m_is_client == true ? "client": "server"),
		eap_tls_trace_string_c::get_cipher_suite_string(m_send_cipher_suite)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::apply_send_block_cipher_suite()");

	eap_status_e status = eap_status_process_general_error;

	tls_record_header_c tmp_tls_record_header_on_tls_message_buffer(
		m_am_tools,
		tls_record_message_buffer->get_data(tls_record_header_c::get_header_length()),
		tls_record_message_buffer->get_data_length());

	if (tmp_tls_record_header_on_tls_message_buffer.get_is_valid() == false
		|| tls_record_message_buffer->get_data_length()
		< tmp_tls_record_header_on_tls_message_buffer.get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_send_mac_key"),
		 m_send_mac_key.get_data(m_send_mac_key.get_data_length()),
		 m_send_mac_key.get_data_length()));

	status = mac->hmac_set_key(&m_send_mac_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	if (mac->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	u64_t send_record_sequence_number_network_order = eap_htonll(m_send_record_sequence_number);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send_record_sequence_number_network_order"),
		 &send_record_sequence_number_network_order,
		 sizeof(send_record_sequence_number_network_order)));

	status = mac->hmac_update(
		&send_record_sequence_number_network_order,
		sizeof(send_record_sequence_number_network_order));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("verified record"),
		 tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
		 tls_record_message_buffer->get_data_length()));

	status = mac->hmac_update(
		tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
		tls_record_message_buffer->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c mac_data(m_am_tools);

	status = mac_data.set_buffer_length(mac->get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	mac_data.set_data_length(mac->get_digest_length());
		
	u32_t mac_length = mac->get_digest_length();

	status = mac->hmac_final(
		mac_data.get_data(mac_data.get_data_length()),
		&mac_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (mac_length != mac->get_digest_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send MAC"),
		 mac_data.get_data(mac_data.get_data_length()),
		 mac_data.get_data_length()));

	status = tls_record_message_buffer->add_data(&mac_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// We must get the address of the record header again. A new buffer may be allocated.
	tmp_tls_record_header_on_tls_message_buffer.set_header_buffer(
		tls_record_message_buffer->get_data(tls_record_header_c::get_header_length()),
		tls_record_message_buffer->get_data_length());

	if (tmp_tls_record_header_on_tls_message_buffer.get_is_valid() == false
		|| tls_record_message_buffer->get_data_length()
		< tmp_tls_record_header_on_tls_message_buffer.get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	tmp_tls_record_header_on_tls_message_buffer.set_data_length(
		static_cast<u16_t>(
			tmp_tls_record_header_on_tls_message_buffer.get_data_length()
			+ mac->get_digest_length()));


	u32_t padded_data_length = encrypt->aligned_data_length(
		tmp_tls_record_header_on_tls_message_buffer.get_data_length());
	u8_t padding_length = static_cast<u8_t>(
		padded_data_length-tmp_tls_record_header_on_tls_message_buffer.get_data_length());

	padding_length = get_extra_padding_length(padding_length, encrypt->get_block_size());

	eap_variable_data_c padding(m_am_tools);
	status = padding.set_buffer_length(padding_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	padding.set_data_length(padding_length);
	
	status = encrypt->add_padding_bytes(
		padding.get_data(padding.get_data_length()),
		padding.get_data_length(),
		static_cast<u8_t>(padding_length-1ul));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = tls_record_message_buffer->add_data(&padding);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	// We must get the address of the record header again. A new buffer may be allocated.
	tmp_tls_record_header_on_tls_message_buffer.set_header_buffer(
		tls_record_message_buffer->get_data(tls_record_header_c::get_header_length()),
		tls_record_message_buffer->get_data_length());
	
	if (tmp_tls_record_header_on_tls_message_buffer.get_is_valid() == false
		|| tls_record_message_buffer->get_data_length()
		< tmp_tls_record_header_on_tls_message_buffer.get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	tmp_tls_record_header_on_tls_message_buffer.set_data_length(
		static_cast<u16_t>(
			tmp_tls_record_header_on_tls_message_buffer.get_data_length()
			+ padding_length));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("plain text record"),
		 tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
		 tls_record_message_buffer->get_data_length()));

	status = encrypt->encrypt_data(
		tmp_tls_record_header_on_tls_message_buffer.get_data(
			tmp_tls_record_header_on_tls_message_buffer.get_data_length()),
		tmp_tls_record_header_on_tls_message_buffer.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("encrypted record"),
		 tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
		 tls_record_message_buffer->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::apply_receive_block_cipher_suite(
	eap_variable_data_c * const tls_record_message_buffer,
	abs_crypto_cbc_block_algorithm_c * const encrypt,
	abs_crypto_hmac_algorithm_c * const mac)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: receive_function: starts: tls_record_c::apply_receive_block_cipher_suite(): %s\n"),
		(m_is_client == true ? "client": "server"),
		eap_tls_trace_string_c::get_cipher_suite_string(m_receive_cipher_suite)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::apply_receive_block_cipher_suite()");

	eap_status_e status = eap_status_process_general_error;

	tls_record_header_c tmp_tls_record_header_on_tls_message_buffer(
		m_am_tools,
		tls_record_message_buffer->get_data(tls_record_header_c::get_header_length()),
		tls_record_message_buffer->get_data_length());

	if (tmp_tls_record_header_on_tls_message_buffer.get_is_valid() == false
		|| tls_record_message_buffer->get_data_length()
		< tmp_tls_record_header_on_tls_message_buffer.get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("encrypted record"),
		 tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
		 tls_record_message_buffer->get_data_length()));

	status = encrypt->decrypt_data(
		tmp_tls_record_header_on_tls_message_buffer.get_data(
			tmp_tls_record_header_on_tls_message_buffer.get_data_length()),
		tmp_tls_record_header_on_tls_message_buffer.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("plain text record"),
		 tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
		 tls_record_message_buffer->get_data_length()));

	// We must get the address of the record header again. A new buffer may be allocated.
	tmp_tls_record_header_on_tls_message_buffer.set_header_buffer(
		tls_record_message_buffer->get_data(tls_record_header_c::get_header_length()),
		tls_record_message_buffer->get_data_length());

	if (tmp_tls_record_header_on_tls_message_buffer.get_is_valid() == false
		|| tls_record_message_buffer->get_data_length()
		< tmp_tls_record_header_on_tls_message_buffer.get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	u32_t padding_length_offset
		= tmp_tls_record_header_on_tls_message_buffer.get_data_length() - 1ul;
	const u8_t * const p_padding_length
		= tmp_tls_record_header_on_tls_message_buffer.get_data_offset(padding_length_offset,
			TLS_PADDINF_LENGTH_FIELD_SIZE);

	if (p_padding_length == 0
		|| (*p_padding_length)+1ul > tmp_tls_record_header_on_tls_message_buffer.get_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
	}

	u32_t padding_length = (*p_padding_length) + 1ul;

	const u8_t * const p_padding
		= tmp_tls_record_header_on_tls_message_buffer.get_data_offset(
			tmp_tls_record_header_on_tls_message_buffer.get_data_length() - padding_length,
			padding_length);
	if (p_padding == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
	}

	eap_status_e padding_status = encrypt->check_padding_bytes(
		p_padding,
		*p_padding_length,
		*p_padding_length);
	if (padding_status != eap_status_ok)
	{
		// NOTE, padding_status is checked in the end of this function.
		// HMAC is checked always.
		// We set the padding length to zero, so the end of the message is used as a MAC.
		// This will fail anyway.
		// This will make some timing attacks more difficult.
		padding_length = 0ul;
	}



	tmp_tls_record_header_on_tls_message_buffer.set_data_length(
		static_cast<u16_t>(
			tmp_tls_record_header_on_tls_message_buffer.get_data_length() - padding_length));

	tls_record_message_buffer->set_data_length(
		tls_record_message_buffer->get_data_length()
		- padding_length);
	
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	
	// HMAC-XXX authentication.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_receive_mac_key"),
		 m_receive_mac_key.get_data(m_receive_mac_key.get_data_length()),
		 m_receive_mac_key.get_data_length()));
	
	status = mac->hmac_set_key(&m_receive_mac_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	if (mac->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}
	
	if (tls_record_message_buffer->get_data_length()
		< (tmp_tls_record_header_on_tls_message_buffer.get_data_length()
		   + tmp_tls_record_header_on_tls_message_buffer.get_header_length()))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}
	
	if (tmp_tls_record_header_on_tls_message_buffer.get_data_length() < mac->get_digest_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	u32_t start_offset_of_mac
		= tmp_tls_record_header_on_tls_message_buffer.get_data_length()
		- mac->get_digest_length();
	
	const u8_t * const received_mac
		= tmp_tls_record_header_on_tls_message_buffer.get_data_offset(
			start_offset_of_mac,
			mac->get_digest_length());
	if (received_mac == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("received MAC"),
		 received_mac,
		 mac->get_digest_length()));

	tmp_tls_record_header_on_tls_message_buffer.set_data_length(
		static_cast<u16_t>(tmp_tls_record_header_on_tls_message_buffer.get_data_length()
						   - mac->get_digest_length()));
	
	u64_t receive_record_sequence_number_network_order
		= eap_htonll(m_receive_record_sequence_number);
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("receive_record_sequence_number_network_order"),
		 &receive_record_sequence_number_network_order,
		 sizeof(receive_record_sequence_number_network_order)));

	status = mac->hmac_update(
		&receive_record_sequence_number_network_order,
		sizeof(receive_record_sequence_number_network_order));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("verified record"),
		 tmp_tls_record_header_on_tls_message_buffer.get_header_buffer(
			 tmp_tls_record_header_on_tls_message_buffer.get_header_length()
			 + tmp_tls_record_header_on_tls_message_buffer.get_data_length()),
		 tmp_tls_record_header_on_tls_message_buffer.get_header_length()
		 + tmp_tls_record_header_on_tls_message_buffer.get_data_length()));

	status = mac->hmac_update(
		tmp_tls_record_header_on_tls_message_buffer.get_header_buffer(
			tmp_tls_record_header_on_tls_message_buffer.get_header_length()
			+ tmp_tls_record_header_on_tls_message_buffer.get_data_length()),
		tmp_tls_record_header_on_tls_message_buffer.get_header_length()
		+ tmp_tls_record_header_on_tls_message_buffer.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c mac_data(m_am_tools);
	
	status = mac_data.set_buffer_length(mac->get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	mac_data.set_data_length(mac->get_digest_length());
	
	u32_t mac_length = mac->get_digest_length();
	
	status = mac->hmac_final(
		mac_data.get_data(mac_data.get_data_length()),
		&mac_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (mac_length != mac->get_digest_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("verify MAC"),
		 mac_data.get_data(mac_data.get_data_length()),
		 mac_data.get_data_length()));
	
	if (padding_status != eap_status_ok)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: ERROR: %s: receive_function: apply_receive_cipher_suite(): ")
			 EAPL("padding failed\n"),
			 (m_is_client == true ? "client": "server")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, padding_status);
	}
	else if (m_am_tools->memcmp(
				 mac_data.get_data(mac_data.get_data_length()),
				 received_mac,
				 mac_data.get_data_length()) != 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: ERROR: %s: receive_function: apply_receive_cipher_suite(): MAC failed\n"),
			 (m_is_client == true ? "client": "server")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}
	else
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: receive_function: apply_receive_cipher_suite(): MAC OK\n"),
			 (m_is_client == true ? "client": "server")));
	}

	tls_record_message_buffer->set_data_length(
		tls_record_message_buffer->get_data_length()
		- mac->get_digest_length());
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::apply_send_stream_cipher_suite(
	eap_variable_data_c * const tls_record_message_buffer,
	abs_crypto_stream_algorithm_c * const encrypt,
	abs_crypto_hmac_algorithm_c * const mac)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: send_function: starts: tls_record_c::apply_send_stream_cipher_suite(): %s\n"),
		(m_is_client == true ? "client": "server"),
		eap_tls_trace_string_c::get_cipher_suite_string(m_send_cipher_suite)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::apply_send_stream_cipher_suite()");

	eap_status_e status = eap_status_process_general_error;

	tls_record_header_c tmp_tls_record_header_on_tls_message_buffer(
		m_am_tools,
		tls_record_message_buffer->get_data(tls_record_header_c::get_header_length()),
		tls_record_message_buffer->get_data_length());

	if (tmp_tls_record_header_on_tls_message_buffer.get_is_valid() == false
		|| tls_record_message_buffer->get_data_length()
		< tmp_tls_record_header_on_tls_message_buffer.get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_send_mac_key"),
		 m_send_mac_key.get_data(m_send_mac_key.get_data_length()),
		 m_send_mac_key.get_data_length()));

	status = mac->hmac_set_key(&m_send_mac_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	if (mac->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	u64_t send_record_sequence_number_network_order = eap_htonll(m_send_record_sequence_number);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send_record_sequence_number_network_order"),
		 &send_record_sequence_number_network_order,
		 sizeof(send_record_sequence_number_network_order)));

	status = mac->hmac_update(
		&send_record_sequence_number_network_order,
		sizeof(send_record_sequence_number_network_order));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("verified record"),
		 tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
		 tls_record_message_buffer->get_data_length()));

	status = mac->hmac_update(
		tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
		tls_record_message_buffer->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c mac_data(m_am_tools);

	status = mac_data.set_buffer_length(mac->get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	mac_data.set_data_length(mac->get_digest_length());
		
	u32_t mac_length = mac->get_digest_length();

	status = mac->hmac_final(
		mac_data.get_data(mac_data.get_data_length()),
		&mac_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (mac_length != mac->get_digest_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send MAC"),
		 mac_data.get_data(mac_data.get_data_length()),
		 mac_data.get_data_length()));

	status = tls_record_message_buffer->add_data(&mac_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// We must get the address of the record header again. A new buffer may be allocated.
	tmp_tls_record_header_on_tls_message_buffer.set_header_buffer(
		tls_record_message_buffer->get_data(tls_record_header_c::get_header_length()),
		tls_record_message_buffer->get_data_length());

	if (tmp_tls_record_header_on_tls_message_buffer.get_is_valid() == false
		|| tls_record_message_buffer->get_data_length()
		< tmp_tls_record_header_on_tls_message_buffer.get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	tmp_tls_record_header_on_tls_message_buffer.set_data_length(
		static_cast<u16_t>(
			tmp_tls_record_header_on_tls_message_buffer.get_data_length()
			+ mac->get_digest_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("plain text record"),
		 tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
		 tls_record_message_buffer->get_data_length()));

	status = encrypt->encrypt_data(
		tmp_tls_record_header_on_tls_message_buffer.get_data(
			tmp_tls_record_header_on_tls_message_buffer.get_data_length()),
		tmp_tls_record_header_on_tls_message_buffer.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("encrypted record"),
		 tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
		 tls_record_message_buffer->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::apply_receive_stream_cipher_suite(
	eap_variable_data_c * const tls_record_message_buffer,
	abs_crypto_stream_algorithm_c * const encrypt,
	abs_crypto_hmac_algorithm_c * const mac)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: receive_function: starts: tls_record_c::apply_receive_block_cipher_suite(): %s\n"),
		(m_is_client == true ? "client": "server"),
		eap_tls_trace_string_c::get_cipher_suite_string(m_receive_cipher_suite)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::apply_receive_stream_cipher_suite()");

	eap_status_e status = eap_status_process_general_error;

	tls_record_header_c tmp_tls_record_header_on_tls_message_buffer(
		m_am_tools,
		tls_record_message_buffer->get_data(tls_record_header_c::get_header_length()),
		tls_record_message_buffer->get_data_length());

	if (tmp_tls_record_header_on_tls_message_buffer.get_is_valid() == false
		|| tls_record_message_buffer->get_data_length()
		< tmp_tls_record_header_on_tls_message_buffer.get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("encrypted record"),
		 tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
		 tls_record_message_buffer->get_data_length()));

	status = encrypt->decrypt_data(
		tmp_tls_record_header_on_tls_message_buffer.get_data(
			tmp_tls_record_header_on_tls_message_buffer.get_data_length()),
		tmp_tls_record_header_on_tls_message_buffer.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("plain text record"),
		 tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
		 tls_record_message_buffer->get_data_length()));

	tls_record_message_buffer->set_data_length(
		tls_record_message_buffer->get_data_length());
	
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	
	// HMAC-SHA1 authentication.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_receive_mac_key"),
		 m_receive_mac_key.get_data(m_receive_mac_key.get_data_length()),
		 m_receive_mac_key.get_data_length()));
	
	status = mac->hmac_set_key(&m_receive_mac_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	if (mac->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}
	
	if (tls_record_message_buffer->get_data_length()
		< (tmp_tls_record_header_on_tls_message_buffer.get_data_length()
		   + tmp_tls_record_header_on_tls_message_buffer.get_header_length()))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}
	
	if (tmp_tls_record_header_on_tls_message_buffer.get_data_length() < mac->get_digest_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	u32_t start_offset_of_mac
		= tmp_tls_record_header_on_tls_message_buffer.get_data_length()
		- mac->get_digest_length();
	
	const u8_t * const received_mac
		= tmp_tls_record_header_on_tls_message_buffer.get_data_offset(
			start_offset_of_mac,
			mac->get_digest_length());
	if (received_mac == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("received MAC"),
		 received_mac,
		 mac->get_digest_length()));

	tmp_tls_record_header_on_tls_message_buffer.set_data_length(
		static_cast<u16_t>(tmp_tls_record_header_on_tls_message_buffer.get_data_length()
						   - mac->get_digest_length()));
	
	u64_t receive_record_sequence_number_network_order
		= eap_htonll(m_receive_record_sequence_number);
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("receive_record_sequence_number_network_order"),
		 &receive_record_sequence_number_network_order,
		 sizeof(receive_record_sequence_number_network_order)));

	status = mac->hmac_update(
		&receive_record_sequence_number_network_order,
		sizeof(receive_record_sequence_number_network_order));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("verified record"),
		 tmp_tls_record_header_on_tls_message_buffer.get_header_buffer(
			 tmp_tls_record_header_on_tls_message_buffer.get_header_length()
			 + tmp_tls_record_header_on_tls_message_buffer.get_data_length()),
		 tmp_tls_record_header_on_tls_message_buffer.get_header_length()
		 + tmp_tls_record_header_on_tls_message_buffer.get_data_length()));

	status = mac->hmac_update(
		tmp_tls_record_header_on_tls_message_buffer.get_header_buffer(
			tmp_tls_record_header_on_tls_message_buffer.get_header_length()
			+ tmp_tls_record_header_on_tls_message_buffer.get_data_length()),
		tmp_tls_record_header_on_tls_message_buffer.get_header_length()
		+ tmp_tls_record_header_on_tls_message_buffer.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c mac_data(m_am_tools);
	
	status = mac_data.set_buffer_length(mac->get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	mac_data.set_data_length(mac->get_digest_length());
	
	u32_t mac_length = mac->get_digest_length();
	
	status = mac->hmac_final(
		mac_data.get_data(mac_data.get_data_length()),
		&mac_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (mac_length != mac->get_digest_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("verify MAC"),
		 mac_data.get_data(mac_data.get_data_length()),
		 mac_data.get_data_length()));
	
	if (m_am_tools->memcmp(
			mac_data.get_data(mac_data.get_data_length()),
			received_mac, mac_data.get_data_length()) != 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: receive_function: apply_receive_cipher_suite(): MAC failed\n"),
			 (m_is_client == true ? "client": "server")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}
	else
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: receive_function: apply_receive_cipher_suite(): MAC OK\n"),
			 (m_is_client == true ? "client": "server")));
	}

	tls_record_message_buffer->set_data_length(
		tls_record_message_buffer->get_data_length()
		- mac->get_digest_length());
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::apply_send_cipher_suite(
	eap_variable_data_c * const tls_record_message_buffer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: send_function: starts: tls_record_c::apply_send_cipher_suite(): %d=%s\n"),
		(m_is_client == true ? "client": "server"),
		m_send_cipher_suite,
		eap_tls_trace_string_c::get_cipher_suite_string(m_send_cipher_suite)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::apply_send_cipher_suite()");

	eap_status_e status = eap_status_process_general_error;

	tls_record_header_c tmp_tls_record_header_on_tls_message_buffer(
		m_am_tools,
		tls_record_message_buffer->get_data(tls_record_header_c::get_header_length()),
		tls_record_message_buffer->get_data_length());

	if (tmp_tls_record_header_on_tls_message_buffer.get_is_valid() == false
		|| tls_record_message_buffer->get_data_length()
		< tmp_tls_record_header_on_tls_message_buffer.get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	if (m_send_cipher_suite != tls_cipher_suites_TLS_NULL_WITH_NULL_NULL)
	{
		EAP_TRACE_DATA_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("plaintext TLS-record"),
			 tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
			 tls_record_message_buffer->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * @{ Add compression of data. Well this will be optional very long time. }
	 */
	if (m_send_compression_method == tls_compression_method_null)
	{
		// No compression.
		status = eap_status_ok;
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_send_cipher_suite == tls_cipher_suites_TLS_NULL_WITH_NULL_NULL)
	{
		// No authentication.
		// No encryption.

		u64_t send_record_sequence_number_network_order = eap_htonll(m_send_record_sequence_number);
		EAP_UNREFERENCED_PARAMETER(send_record_sequence_number_network_order); // in release

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("send_record_sequence_number_network_order"),
			 &send_record_sequence_number_network_order,
			 sizeof(send_record_sequence_number_network_order)));

		status = eap_status_ok;
	}
	else if (cipher_suite_is_3DES_EDE_CBC_SHA(m_send_cipher_suite) == true
		|| cipher_suite_is_AES_128_CBC_SHA(m_send_cipher_suite) == true)
	{
		EAP_ASSERT_TOOLS(m_am_tools, m_send_block_cipher != 0);
		EAP_ASSERT_TOOLS(m_am_tools, m_send_hmac_algorithm != 0);

		status = apply_send_block_cipher_suite(
			tls_record_message_buffer,
			m_send_block_cipher,
			m_send_hmac_algorithm);
	}
	else if (cipher_suite_is_RC4_128_MD5(m_send_cipher_suite) == true
		|| cipher_suite_is_RC4_128_SHA(m_send_cipher_suite) == true)
	{
		EAP_ASSERT_TOOLS(m_am_tools, m_send_stream_cipher != 0);
		EAP_ASSERT_TOOLS(m_am_tools, m_send_hmac_algorithm != 0);

		status = apply_send_stream_cipher_suite(
			tls_record_message_buffer,
			m_send_stream_cipher,
			m_send_hmac_algorithm);
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_send_cipher_suite != tls_cipher_suites_TLS_NULL_WITH_NULL_NULL)
	{
		m_send_record_sequence_number = m_send_record_sequence_number + 1ul;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::apply_receive_cipher_suite(
	eap_variable_data_c * const tls_record_message_buffer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: receive_function: starts: tls_record_c::apply_receive_cipher_suite(): %d=%s\n"),
		(m_is_client == true ? "client": "server"),
		m_receive_cipher_suite,
		eap_tls_trace_string_c::get_cipher_suite_string(m_receive_cipher_suite)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::apply_receive_cipher_suite()");

	eap_status_e status = eap_status_process_general_error;

	tls_record_header_c tmp_tls_record_header_on_tls_message_buffer(
		m_am_tools,
		tls_record_message_buffer->get_data(tls_record_header_c::get_header_length()),
		tls_record_message_buffer->get_data_length());

	if (tmp_tls_record_header_on_tls_message_buffer.get_is_valid() == false
		|| tls_record_message_buffer->get_data_length()
		< tmp_tls_record_header_on_tls_message_buffer.get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_receive_cipher_suite == tls_cipher_suites_TLS_NULL_WITH_NULL_NULL)
	{
		// No decryption.
		// No authentication.

		u64_t receive_record_sequence_number_network_order
			= eap_htonll(m_receive_record_sequence_number);
		EAP_UNREFERENCED_PARAMETER(receive_record_sequence_number_network_order); // in release

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("receive_record_sequence_number_network_order"),
			 &receive_record_sequence_number_network_order,
			 sizeof(receive_record_sequence_number_network_order)));

		status = eap_status_ok;
	}
	else if (cipher_suite_is_3DES_EDE_CBC_SHA(m_receive_cipher_suite) == true
		|| cipher_suite_is_AES_128_CBC_SHA(m_receive_cipher_suite) == true)
	{
		status = apply_receive_block_cipher_suite(
			tls_record_message_buffer,
			m_receive_block_cipher,
			m_receive_hmac_algorithm);
	}
	else if (cipher_suite_is_RC4_128_MD5(m_receive_cipher_suite) == true
		|| cipher_suite_is_RC4_128_SHA(m_receive_cipher_suite) == true)
	{
		status = apply_receive_stream_cipher_suite(
			tls_record_message_buffer,
			m_receive_stream_cipher,
			m_receive_hmac_algorithm);
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}

	if (m_receive_cipher_suite != tls_cipher_suites_TLS_NULL_WITH_NULL_NULL)
	{
		EAP_TRACE_DATA_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("decrypted TLS-record"),
			 tls_record_message_buffer->get_data(tls_record_message_buffer->get_data_length()),
			 tls_record_message_buffer->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * @{ Add de-compression of data. Well this will be optional very long time. }
	 */
	if (m_send_compression_method == tls_compression_method_null)
	{
		// No de-compression.
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_receive_cipher_suite != tls_cipher_suites_TLS_NULL_WITH_NULL_NULL)
	{
		m_receive_record_sequence_number = m_receive_record_sequence_number + 1ul;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e tls_record_c::packet_send(
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t /*data_length*/,
	const u32_t /*buffer_length*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: receive_function: starts: tls_record_c::packet_send(): %d=%s\n"),
		(m_is_client == true ? "client": "server"),
		m_receive_cipher_suite,
		eap_tls_trace_string_c::get_cipher_suite_string(m_receive_cipher_suite)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::packet_send()");

	eap_status_e status = create_tls_application_data(
		sent_packet,
		header_offset);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT u32_t tls_record_c::get_header_offset(
	u32_t * const MTU_length,
	u32_t * const trailer_length)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: receive_function: starts: tls_record_c::get_header_offset()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::get_header_offset()");

	if (m_eap_type == eap_type_peap
		&& m_peap_version == peap_version_0_xp)
	{
		// PEAPv0 cannot use long tunneled EAP-packets,
		// bacause of the inner EAP-packets does not
		// have own EAP-header. Long inner EAP-packets will be 
		// fragmented in outer PEAPv0 application data and that will cause
		// wrong EAP-identifier values after reassembly.
		u32_t offset = get_type_partner()->get_header_offset(
			MTU_length,
			trailer_length);

		// Here we try set MTU such the inner EAP-packets does not need fragmentation.
		*MTU_length -= (offset
						+ 4ul*(tls_record_header_c::get_header_length()
							   + tls_handshake_header_c::get_header_length()));
		*trailer_length = 0ul;

		return 0ul;
	}
	else
	{
		*MTU_length = EAP_TLS_PEAP_MAX_MESSAGE_LENGTH;
		*trailer_length = 0ul;

		return 0ul;
	}
}

//--------------------------------------------------

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e tls_record_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return get_type_partner()->read_configure(
			field,
			data);
}

//--------------------------------------------------

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e tls_record_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return get_type_partner()->write_configure(
			field,
			data);
}

//--------------------------------------------------

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT void tls_record_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x, %s: starts: tls_record_c::state_notification(): EAP-type 0xfe%06x%08x=%s: m_tls_session_type=%d=%s, tls_state=%d=%s, notification state=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_eap_type.get_vendor_id(),
		 m_eap_type.get_vendor_type(),
		 eap_header_string_c::get_eap_type_string(m_eap_type),
		 m_tls_session_type,
		 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
		 m_tls_peap_state,
		 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
		 eap_state_notification_c::get_state_string(state->get_protocol_layer(), state->get_current_state())));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::state_notification()");

	if (state->get_protocol_layer() == eap_protocol_layer_general)
	{
		if (state->get_current_state() == eap_general_state_authentication_cancelled)
		{
			// Tunneled EAP-type terminated unsuccessfully.
			m_tunneled_eap_type_authentication_state
				= static_cast<eap_state_variable_e>(state->get_current_state());
			set_state(tls_peap_state_failure);
		}
	}
	else if (state->get_protocol_layer() == eap_protocol_layer_eap)
	{
		if (state->get_current_state() == eap_state_authentication_terminated_unsuccessfully
#if defined(USE_EAP_PEAPV1_EXTENSIONS)
			|| state->get_current_state() == eap_state_authentication_terminated_unsuccessfully_peapv1_extension
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)
			)
		{
			// Tunneled EAP-type terminated unsuccessfully.
			m_tunneled_eap_type_authentication_state
				= static_cast<eap_state_variable_e>(state->get_current_state());
			set_state(tls_peap_state_failure);

			// Because we process aplication data, we do not send alert messages anymore.
			m_could_send_fatal_alert_message = false;
			m_could_send_warning_alert_message = false;
		}
		else if (state->get_current_state()
				 == eap_state_authentication_finished_successfully
			|| state->get_current_state()
				 == eap_state_tppd_peapv1_authentication_finished_successfully_with_tunneled_eap_success
#if defined(USE_EAP_PEAPV1_EXTENSIONS)
			|| state->get_current_state()
				 == eap_state_authentication_finished_successfully_peapv1_extension
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)
			 )
		{
			// Tunneled EAP-type finished successfully.

			if ((m_eap_type == eap_type_peap
					&& m_peap_version >= peap_version_0_xp
					&& m_peap_version <= peap_version_2)
				|| m_eap_type == eap_type_ttls
#if defined(USE_FAST_EAP_TYPE)
				|| m_eap_type == eap_type_fast
#endif //#if defined(USE_FAST_EAP_TYPE)
				)
			{
				eap_status_e status = get_type_partner()->set_tls_master_secret(
					&m_eap_master_session_key);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return;
				}

				if (m_eap_type == eap_type_ttls
					|| m_eap_type == eap_type_peap
#if defined(USE_FAST_EAP_TYPE)
					|| m_eap_type == eap_type_fast
#endif //#if defined(USE_FAST_EAP_TYPE)
					)
				{

					tls_identity_privacy_handshake_state_e tmp_identity_privacy_handshake_state = 
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
						m_tls_identity_privacy_handshake_state;
#else
						tls_identity_privacy_handshake_state_none;
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
					EAP_UNREFERENCED_PARAMETER(tmp_identity_privacy_handshake_state);

					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("%s: state_notification(): TLS/PEAP authentication ")
						 EAPL("SUCCESS: %s, %s, tunnel %d, tunneling type %s, tunneling version %s, cipher_suite %s, %s\n"),
						 (m_is_client == true ? "client": "server"),
						 (m_tls_peap_server_authenticates_client_action == true
						  ? "mutual": "anonymous client"),
						 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
						 get_is_tunneled_tls(),
						 eap_header_string_c::get_eap_type_string(m_eap_type),
						 eap_tls_trace_string_c::get_peap_version_string(m_peap_version),
						 eap_tls_trace_string_c::get_cipher_suite_string(m_selected_cipher_suite),
						 eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(tmp_identity_privacy_handshake_state)));

					eap_status_e save_status = m_am_tls_services->save_tls_session(
						&m_session_id,
						&m_master_secret,
						m_selected_cipher_suite
#if defined(USE_EAP_TLS_SESSION_TICKET)
						, tls_extension_c::get_tls_extension(
							tls_extension_type_session_ticket,
							&m_received_tls_extensions,
							m_am_tools)
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
						);
					if (save_status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						(void) EAP_STATUS_RETURN(m_am_tools, save_status);
					}
				}

			}

			m_tunneled_eap_type_authentication_state
				= static_cast<eap_state_variable_e>(state->get_current_state());
			set_state(tls_peap_state_tls_success);
		}
#if defined(USE_FAST_EAP_TYPE)
		else if (m_eap_type == eap_type_fast
			&& state->get_current_state() == eap_state_inner_eap_method_skipped)
		{
			m_tunneled_eap_type_authentication_state
				= static_cast<eap_state_variable_e>(state->get_current_state());
		}
		else if (m_is_client == false
			&& m_eap_type == eap_type_fast
			&& state->get_current_state() == eap_state_authentication_wait_eap_fast_empty_acknowledge)
		{
			set_state(tls_peap_state_wait_tunneled_authentication_start);
		}
#endif //#if defined(USE_FAST_EAP_TYPE)
	}
	else if (state->get_protocol_layer() == eap_protocol_layer_internal_type)
	{

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		if (state->get_current_state() == tls_peap_state_server_waits_ttls_plain_ms_chap_v2_empty_ack)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: tls_record_c::state_notification(): ")
				 EAPL("waits TTLS/plain MsChapv2 empty Ack: EAP-type 0xfe%06x%08x=%s\n"),
				 (m_is_client == true ? "client": "server"),
				 m_eap_type.get_vendor_id(),
				 m_eap_type.get_vendor_type(),
				 eap_header_string_c::get_eap_type_string(m_eap_type)));
		}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	}

	get_type_partner()->state_notification(
			state);
}

//--------------------------------------------------

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e tls_record_c::set_timer(
	abs_eap_base_timer_c * const initializer, 
	const u32_t id, 
	void * const data,
	const u32_t p_time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (get_type_partner() == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return get_type_partner()->set_timer(
		initializer, 
		id, 
		data,
		p_time_ms);
}

//--------------------------------------------------

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e tls_record_c::cancel_timer(
	abs_eap_base_timer_c * const initializer, 
	const u32_t id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (get_type_partner() == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return get_type_partner()->cancel_timer(
		initializer,
		id);
}

//--------------------------------------------------

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e tls_record_c::load_module(
	const eap_type_value_e type,
	const eap_type_value_e tunneling_type,
	abs_eap_base_type_c * const partner,
	eap_base_type_c ** const eap_type,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_type_partner()->load_module(
		type,
		tunneling_type,
		partner,
		eap_type,
		is_client_when_true,
		receive_network_id);
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e tls_record_c::unload_module(const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_type_partner()->unload_module(type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e tls_record_c::restart_authentication(
	const eap_am_network_id_c * const receive_network_id,
	const bool is_client_when_true,
	const bool force_clean_restart,
	const bool from_timer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_type_partner()->restart_authentication(
		receive_network_id,
		is_client_when_true,
		force_clean_restart,
		from_timer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e tls_record_c::packet_data_crypto_keys(
	const eap_am_network_id_c * const /* send_network_id */,
	const eap_master_session_key_c * const master_session_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: receive_function: starts: tls_record_c::packet_data_crypto_keys()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::packet_data_crypto_keys()");

	if ((m_eap_type == eap_type_peap
			&& (m_peap_version == peap_version_0_xp
				|| m_peap_version == peap_version_1))
		|| m_eap_type == eap_type_ttls)
	{
		// We do not forward keys to lower layer.
	}
#if defined(USE_FAST_EAP_TYPE)
	else if (m_eap_type == eap_type_fast)
	{
		eap_status_e status = m_eap_master_session_key.set_copy_of_buffer(
			master_session_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// NOTE: state_notification() will deliver master_session_key to lower layers.
	}
#endif //#if defined(USE_FAST_EAP_TYPE)
	else if (m_eap_type == eap_type_peap
				&& m_peap_version == peap_version_2)
	{
		eap_status_e status = m_eap_master_session_key.set_copy_of_buffer(
			master_session_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = get_type_partner()->set_tls_master_secret(&m_eap_master_session_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e tls_record_c::check_is_valid_eap_type(
	const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_type_partner()->check_is_valid_eap_type(eap_type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

// This is commented in abs_tls_base_application_c.
EAP_FUNC_EXPORT eap_status_e tls_record_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_type_partner()->get_eap_type_list(eap_type_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::start_tls_peap_authentication(
	const eap_variable_data_c * const received_authority_identity_payload
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::start_tls_peap_authentication()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::start_tls_peap_authentication()");

	eap_status_e status = completion_action_add(tls_completion_action_query_cipher_suites_and_previous_session);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_state(tls_peap_state_wait_handshake_type_server_hello);

	status = completion_action_add(tls_completion_action_create_handshake_type_client_hello);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if defined(USE_FAST_EAP_TYPE)
	if (m_eap_type == eap_type_fast)
	{
		if (m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true)
		{
			set_tls_session_type(tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP);
		}
		else if (received_authority_identity_payload != 0
			&& received_authority_identity_payload->get_is_valid_data() == true)
		{
			eap_fast_variable_data_c in_A_ID_TLV(m_am_tools);

			status = in_A_ID_TLV.set_copy_of_buffer(
				received_authority_identity_payload->get_data(),
				received_authority_identity_payload->get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_application->query_tunnel_PAC(
				&in_A_ID_TLV);
			if (status == eap_status_pending_request)
			{
				// This is pending query, that will be completed by
				// complete_query_tunnel_PAC() call.
				m_pending_query_tunnel_PAC = true;

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else if (status == eap_status_completed_request)
			{
				// This is already completed by complete_query_PACs() call.

				status = check_sent_tls_message();

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else if (status == eap_status_ok)
			{
				// This is also an error case, because this call is always completed on success. 
				status = eap_status_process_general_error;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else // All other status values means error, because this call is always completed on success.
			{
				// This is an error case.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
			}
		}
	}
#else
	EAP_UNREFERENCED_PARAMETER(received_authority_identity_payload);
#endif //#if defined(USE_FAST_EAP_TYPE)


	status = check_sent_tls_message();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::start_peap_tunneled_authentication(
	const eap_am_network_id_c * const receive_network_id,
	const u8_t received_eap_identifier,
	const tls_session_type_e tls_session_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::start_peap_tunneled_authentication()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::start_peap_tunneled_authentication()");

	if (m_is_client == true
		&& verify_state(tls_peap_state_peap_tunnel_ready) == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: TLS: %s: function: verify_state(): current state %s != %s\n"),
			 (m_is_client == true ? "client": "server"),
			 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
			 eap_tls_trace_string_c::get_state_string(tls_peap_state_peap_tunnel_ready)));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}
	else if (m_is_client == false
		&& verify_state(tls_peap_state_wait_tunneled_authentication_start) == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: TLS: %s: function: verify_state(): current state %s != %s\n"),
			 (m_is_client == true ? "client": "server"),
			 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
			 eap_tls_trace_string_c::get_state_string(tls_peap_state_wait_tunneled_authentication_start)));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}
	

	set_state(tls_peap_state_wait_application_data);

	eap_status_e status = eap_status_process_general_error;

	{
		// This must be inside a block. Automatic variable must be restored after
		// the start_peap_tunneled_authentication() function call.
		eap_automatic_simple_value_c<bool> restore_allow_message_send(
			m_am_tools,
			&m_allow_message_send,
			m_allow_message_send);

		// Packet send is delayed until after the
		// m_application->start_peap_tunneled_authentication() function returns.
		m_allow_message_send = false;

		status = m_application->start_peap_tunneled_authentication(
			receive_network_id,
			m_is_client,
			received_eap_identifier,
			tls_session_type,
			m_tls_peap_server_authenticates_client_action);
	}


	{
		// Note this call will return eap_status_pending_request
		// if any asyncronous call is pending.
		eap_status_e send_status = check_sent_tls_message();
		if (send_status != eap_status_ok)
		{
			status = send_status;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::allocate_handshake_message_copy(
	tls_handshake_message_c ** const tls_handshake_message,
	eap_automatic_variable_c<tls_handshake_message_c> * const automatic_tls_handshake_message,
	tls_handshake_header_c * const tls_handshake_header)
{
	*tls_handshake_message
		= new tls_handshake_message_c(m_am_tools, this, m_is_client);
	
	automatic_tls_handshake_message->set_variable(*tls_handshake_message);

	if (*tls_handshake_message == 0
		|| (*tls_handshake_message)->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = (*tls_handshake_message)->set_handshake_header_copy(
		tls_handshake_header);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TLS_SESSION_TICKET)

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_tls_extension_list(
	const u32_t handshake_data_length,
	u32_t * const data_offset,
	const tls_handshake_header_c * const tls_handshake_header,
	tls_handshake_message_c * const tls_handshake_message
)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: receive_function: starts: tls_record_c::parse_tls_extension_list()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_tls_extension_list()");

	eap_status_e status(eap_status_ok);

	// This is optional field.
	if ((*data_offset)+TLS_EXTENSIONS_LENGTH_FIELD_SIZE <= handshake_data_length)
	{
		// Extension list is formatted as:
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                                 | extension list length         |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | extension 1 type              | extension 1 data length       |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | extension 1 data ...
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | extension 2 type              | extension 2 data length       |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | extension 2 data ...
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		u8_t *p_extension_list = tls_handshake_header->get_data_offset(
			(*data_offset),
			TLS_EXTENSIONS_LENGTH_FIELD_SIZE);
		if (p_extension_list == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		(*data_offset) += TLS_EXTENSIONS_LENGTH_FIELD_SIZE;

		u32_t extension_list_length(
			eap_read_u16_t_network_order(
				p_extension_list,
				TLS_EXTENSIONS_LENGTH_FIELD_SIZE));

		if ((*data_offset)+extension_list_length > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		const u32_t offset_end((*data_offset)+extension_list_length);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS-handshake extension payload"),
			p_extension_list,
			TLS_EXTENSIONS_LENGTH_FIELD_SIZE+extension_list_length));

		if (extension_list_length > 0ul)
		{
			eap_array_c<tls_extension_c> extensions_array(m_am_tools);

			while((*data_offset) < offset_end)
			{
				// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

				if ((*data_offset)+TLS_EXTENSION_TYPE_FIELD_SIZE > handshake_data_length)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
				}

				u8_t *p_extension_type = tls_handshake_header->get_data_offset(
					(*data_offset),
					TLS_EXTENSION_TYPE_FIELD_SIZE);
				if (p_extension_type == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
				}

				(*data_offset) += TLS_EXTENSION_TYPE_FIELD_SIZE;

				u16_t extension_type_host(
					eap_read_u16_t_network_order(
						p_extension_type,
						TLS_EXTENSIONS_LENGTH_FIELD_SIZE));

				tls_extension_type_e extension_type(static_cast<tls_extension_type_e>(extension_type_host));

				// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

				if ((*data_offset)+TLS_EXTENSION_DATA_LENGTH_FIELD_SIZE > handshake_data_length)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
				}

				u8_t *p_extension_data_length = tls_handshake_header->get_data_offset(
					(*data_offset),
					TLS_EXTENSION_DATA_LENGTH_FIELD_SIZE);
				if (p_extension_data_length == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
				}

				(*data_offset) += TLS_EXTENSION_DATA_LENGTH_FIELD_SIZE;

				u16_t extension_data_length_host(
					eap_read_u16_t_network_order(
						p_extension_data_length,
						TLS_EXTENSION_DATA_LENGTH_FIELD_SIZE));

				// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

				tls_extension_c * const tls_extension = new tls_extension_c(m_am_tools);

				eap_automatic_variable_c<tls_extension_c>
					automatic_tls_extension(m_am_tools, tls_extension);

				if (tls_extension == 0
					|| tls_extension->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				tls_extension->set_type(extension_type);

				// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

				if (extension_data_length_host > 0ul)
				{
					if ((*data_offset)+extension_data_length_host > handshake_data_length)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
					}

					const u8_t * const p_extension_data = tls_handshake_header->get_data_offset(
						(*data_offset),
						extension_data_length_host);
					if (p_extension_data == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
					}

					status = tls_extension->set_copy_of_buffer(p_extension_data, extension_data_length_host);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					(*data_offset) += extension_data_length_host;
				}

				// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

				automatic_tls_extension.do_not_free_variable();

				// add_object() will delete extension if operation fails.
				status = extensions_array.add_object(tls_extension, true);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

			} // while()

			status = tls_handshake_message->set_tls_extensions(&extensions_array);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_handshake_type_hello_request(
	tls_record_message_c * const received_tls_record_message,
	tls_handshake_header_c * const tls_handshake_header,
	const u32_t handshake_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_handshake_type_hello_request()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_handshake_type_hello_request()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message_copy(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_header);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (handshake_data_length != 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
	}

	if (status == eap_status_ok)
	{
		// Note the add_handshake_message() frees message in any case.
		automatic_tls_handshake_message.do_not_free_variable();

		status = received_tls_record_message->add_handshake_message(tls_handshake_message, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_handshake_type_client_hello(
	tls_record_message_c * const received_tls_record_message,
	tls_handshake_header_c * const tls_handshake_header,
	const u32_t handshake_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_handshake_type_client_hello()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_handshake_type_client_hello()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message_copy(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_header);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t data_offset = 0ul;
	u8_t * const handshake_data = tls_handshake_header->get_data_offset(
		data_offset,
		tls_handshake_header->get_data_length());
	if (handshake_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_VERSION_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_version = handshake_data;
		u16_t version = eap_read_u16_t_network_order(p_version, TLS_VERSION_FIELD_SIZE);
		
		if (version != tls_version_3_1)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
		
		data_offset += TLS_VERSION_FIELD_SIZE;
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_HANDSHAKE_RANDOM_VALUE_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_random_value = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_HANDSHAKE_RANDOM_VALUE_SIZE);
		if (p_random_value == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		eap_variable_data_c client_random_value(m_am_tools);
		status = client_random_value.set_buffer(
			p_random_value,
			TLS_HANDSHAKE_RANDOM_VALUE_SIZE,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = tls_handshake_message->set_random_value(&client_random_value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data_offset += TLS_HANDSHAKE_RANDOM_VALUE_SIZE;

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: parse_handshake_type_client_hello(): m_client_random_value"),
			 client_random_value.get_data(client_random_value.get_data_length()),
			 client_random_value.get_data_length()));
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_SESSION_ID_LENGTH_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_session_id_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_SESSION_ID_LENGTH_FIELD_SIZE);
		if (p_session_id_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		data_offset += TLS_SESSION_ID_LENGTH_FIELD_SIZE;

		if (data_offset+*p_session_id_length > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		if (*p_session_id_length > 0ul)
		{
			u8_t *p_session_id = tls_handshake_header->get_data_offset(
				data_offset,
				*p_session_id_length);
			if (p_session_id == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
			}

			eap_variable_data_c session_id(m_am_tools);
			status = session_id.set_buffer(p_session_id, *p_session_id_length, false, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = tls_handshake_message->set_session_id(&session_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		data_offset += *p_session_id_length;
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_CIPHER_SUITE_LENGTH_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_cipher_suite_length_network_order = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_CIPHER_SUITE_LENGTH_FIELD_SIZE);
		if (p_cipher_suite_length_network_order == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		u16_t cipher_suite_length = eap_read_u16_t_network_order(
			p_cipher_suite_length_network_order,
			TLS_CIPHER_SUITE_LENGTH_FIELD_SIZE);
		data_offset += TLS_CIPHER_SUITE_LENGTH_FIELD_SIZE;

		if (data_offset+cipher_suite_length > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		if ((cipher_suite_length % 2) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		if (cipher_suite_length > 0ul)
		{
			u8_t *p_cipher_suite = tls_handshake_header->get_data_offset(
				data_offset,
				cipher_suite_length);
			if (p_cipher_suite == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
			}

			eap_array_c<u16_t> cipher_suites_array(m_am_tools);

			for (u32_t ind = 0ul; ind < cipher_suite_length; ind += 2ul)
			{
				u16_t * const cipher_suite = new u16_t;
				if (cipher_suite == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				u16_t cipher_suite_host_order = eap_read_u16_t_network_order(
					p_cipher_suite,
					TLS_CIPHER_SUITE_FIELD_SIZE);
				*cipher_suite = cipher_suite_host_order;

				// add_object() will delete cipher_suite if operation fails.
				status = cipher_suites_array.add_object(cipher_suite, true);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				p_cipher_suite += TLS_CIPHER_SUITE_FIELD_SIZE;
			} // for()

			status = tls_handshake_message->set_cipher_suites(&cipher_suites_array);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		data_offset += cipher_suite_length;
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_COMPRESSION_LENGTH_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_compression_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_COMPRESSION_LENGTH_FIELD_SIZE);
		if (p_compression_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		data_offset += TLS_COMPRESSION_LENGTH_FIELD_SIZE;

		if (data_offset+*p_compression_length > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		if (*p_compression_length > 0ul)
		{
			u8_t *p_compression = tls_handshake_header->get_data_offset(
				data_offset,
				*p_compression_length);
			if (p_compression == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
			}

			eap_array_c<u8_t> compression_array(m_am_tools);

			for (u32_t ind = 0ul; ind < *p_compression_length; ind++)
			{
				u8_t * const compression_value = new u8_t;
				if (compression_value == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}
				*compression_value = *p_compression;

				// add_object() will delete compression_value if operation fails.
				status = compression_array.add_object(compression_value, true);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				p_compression += TLS_COMPRESSION_FIELD_SIZE;
			} // for()

			status = tls_handshake_message->set_compression_methods(&compression_array);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		data_offset += *p_compression_length;
	}

	//----------------------------------------------------------

#if defined(USE_EAP_TLS_SESSION_TICKET)

	status = parse_tls_extension_list(
		handshake_data_length,
		&data_offset,
		tls_handshake_header,
		tls_handshake_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

	//----------------------------------------------------------

	if (status == eap_status_ok)
	{
		// Note the add_handshake_message() frees message in any case.
		automatic_tls_handshake_message.do_not_free_variable();

		status = received_tls_record_message->add_handshake_message(tls_handshake_message, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message_hash_init();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_handshake_type_certificate(
	tls_record_message_c * const received_tls_record_message,
	tls_handshake_header_c * const tls_handshake_header,
	const u32_t handshake_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_handshake_type_certificate()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_handshake_type_certificate()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message_copy(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_header);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t data_offset = 0ul;

	//----------------------------------------------------------

	{
		if (data_offset+(TLS_CERTIFICATE_LENGTH_FIELD_SIZE) > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		u8_t *p_certificate_chain_length = tls_handshake_header->get_data_offset(
			data_offset,
			(TLS_CERTIFICATE_LENGTH_FIELD_SIZE));
		if (p_certificate_chain_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		u32_t certificate_chain_length = 
			eap_read_u24_t_network_order(
				p_certificate_chain_length,
				TLS_CERTIFICATE_LENGTH_FIELD_SIZE);

		data_offset += (TLS_CERTIFICATE_LENGTH_FIELD_SIZE);

		if (certificate_chain_length > 0ul)
		{
			eap_array_c<eap_variable_data_c> certificate_chain(m_am_tools);
			u32_t max_data_offset = data_offset + certificate_chain_length;

			for (;data_offset < max_data_offset;)
			{
				u8_t *p_certificate_length = tls_handshake_header->get_data_offset(
					data_offset,
					(TLS_CERTIFICATE_LENGTH_FIELD_SIZE));
				if (p_certificate_length == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
				}
				
				u32_t certificate_length = 
					eap_read_u24_t_network_order(
						p_certificate_length,
						TLS_CERTIFICATE_LENGTH_FIELD_SIZE);

				data_offset += (TLS_CERTIFICATE_LENGTH_FIELD_SIZE);


				eap_variable_data_c * const certificate = new eap_variable_data_c(m_am_tools);

				eap_automatic_variable_c<eap_variable_data_c>
					automatic_certificate(m_am_tools, certificate);

				if (certificate == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}


				u8_t *p_certificate = tls_handshake_header->get_data_offset(
					data_offset,
					certificate_length);
				if (p_certificate == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
				}

				status = certificate->set_copy_of_buffer(p_certificate, certificate_length);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				automatic_certificate.do_not_free_variable();

				// add_object() will delete certificate if operation fails.
				status = certificate_chain.add_object(certificate, true);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				data_offset += certificate_length;
			} // for()

			status = tls_handshake_message->set_certificate_chain(&certificate_chain);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		data_offset += certificate_chain_length;
	}

	//----------------------------------------------------------

	if (status == eap_status_ok)
	{
		// Note the add_handshake_message() frees message in any case.
		automatic_tls_handshake_message.do_not_free_variable();

		status = received_tls_record_message->add_handshake_message(tls_handshake_message, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_handshake_type_certificate_request(
	tls_record_message_c * const received_tls_record_message,
	tls_handshake_header_c * const tls_handshake_header,
	const u32_t handshake_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_handshake_type_certificate_request()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_handshake_type_certificate_request()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message_copy(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_header);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t data_offset = 0ul;

	//----------------------------------------------------------

	{
		if (data_offset+TLS_CERTIFICATE_TYPE_LENGTH_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_certificate_type_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_CERTIFICATE_TYPE_LENGTH_FIELD_SIZE);
		if (p_certificate_type_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		data_offset += TLS_CERTIFICATE_TYPE_LENGTH_FIELD_SIZE;

		if (data_offset+*p_certificate_type_length > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		if (*p_certificate_type_length > 0ul)
		{
			u8_t *p_certificate_type = tls_handshake_header->get_data_offset(
				data_offset,
				*p_certificate_type_length);
			if (p_certificate_type == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
			}

			eap_array_c<u8_t> certificate_type_array(m_am_tools);

			for (u32_t ind = 0ul; ind < *p_certificate_type_length; ind++)
			{
				u8_t * const certificate_type_value = new u8_t;
				if (certificate_type_value == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}
				*certificate_type_value = *p_certificate_type;

				// add_object() will delete certificate_type_value if operation fails.
				status = certificate_type_array.add_object(certificate_type_value, true);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				p_certificate_type += TLS_CERTIFICATE_TYPE_FIELD_SIZE;
			} // for()

			status = tls_handshake_message->set_certificate_types(&certificate_type_array);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		data_offset += *p_certificate_type_length;
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_CERTIFICATE_AUTHORITIES_LENGTH_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		u8_t *p_certificate_authorities_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_CERTIFICATE_AUTHORITIES_LENGTH_FIELD_SIZE);
		if (p_certificate_authorities_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		u32_t certificate_authorities_length = 
			eap_read_u16_t_network_order(
				p_certificate_authorities_length,
				TLS_CERTIFICATE_AUTHORITIES_LENGTH_FIELD_SIZE);

		data_offset += TLS_CERTIFICATE_AUTHORITIES_LENGTH_FIELD_SIZE;

		if (certificate_authorities_length > 0ul)
		{
			eap_array_c<eap_variable_data_c> certificate_authorities(m_am_tools);
			u32_t max_data_offset = data_offset + certificate_authorities_length;

			for (;data_offset < max_data_offset;)
			{
				u8_t *p_certificate_authority_length = tls_handshake_header->get_data_offset(
					data_offset,
					TLS_CERTIFICATE_AUTHORITIES_LENGTH_FIELD_SIZE);
				if (p_certificate_authority_length == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
				}
				
				u32_t certificate_authority_length = 
					eap_read_u16_t_network_order(
						p_certificate_authority_length,
						TLS_CERTIFICATE_AUTHORITIES_LENGTH_FIELD_SIZE);

				data_offset += TLS_CERTIFICATE_AUTHORITIES_LENGTH_FIELD_SIZE;

				{
					eap_variable_data_c * const certificate_authority
						= new eap_variable_data_c(m_am_tools);

					eap_automatic_variable_c<eap_variable_data_c>
						automatic_certificate_authority(m_am_tools, certificate_authority);

					if (certificate_authority == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}


					u8_t *p_certificate_authority = tls_handshake_header->get_data_offset(
						data_offset,
						certificate_authority_length);
					if (p_certificate_authority == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
					}

					status = certificate_authority->set_copy_of_buffer(
						p_certificate_authority,
						certificate_authority_length);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					automatic_certificate_authority.do_not_free_variable();

					// add_object() will delete certificate_authority if operation fails.
					status = certificate_authorities.add_object(certificate_authority, true);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}

				data_offset += certificate_authority_length;
			} // for()

			status = tls_handshake_message->set_certificate_authorities(&certificate_authorities);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		data_offset += certificate_authorities_length;
	}

	//----------------------------------------------------------

	if (status == eap_status_ok)
	{
		// Note the add_handshake_message() frees message in any case.
		automatic_tls_handshake_message.do_not_free_variable();

		status = received_tls_record_message->add_handshake_message(tls_handshake_message, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_handshake_type_server_hello_done(
	tls_record_message_c * const received_tls_record_message,
	tls_handshake_header_c * const tls_handshake_header,
	const u32_t /* handshake_data_length */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_handshake_type_server_hello_done()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_handshake_type_server_hello_done()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message_copy(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_header);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (tls_handshake_header->get_data_length() > 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
	}

	//----------------------------------------------------------

	if (status == eap_status_ok)
	{
		// Note the add_handshake_message() frees message in any case.
		automatic_tls_handshake_message.do_not_free_variable();

		status = received_tls_record_message->add_handshake_message(tls_handshake_message, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_handshake_type_server_hello(
	tls_record_message_c * const received_tls_record_message,
	tls_handshake_header_c * const tls_handshake_header,
	const u32_t handshake_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_handshake_type_server_hello()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_handshake_type_server_hello()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message_copy(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_header);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t data_offset = 0ul;

	u8_t * handshake_data = tls_handshake_header->get_data_offset(
		data_offset,
		tls_handshake_header->get_data_length());
	if (handshake_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_VERSION_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_version = handshake_data;
		u16_t version = eap_read_u16_t_network_order(p_version, TLS_VERSION_FIELD_SIZE);
		
		if (version != tls_version_3_1)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
		
		data_offset += TLS_VERSION_FIELD_SIZE;
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_HANDSHAKE_RANDOM_VALUE_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_random_value = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_HANDSHAKE_RANDOM_VALUE_SIZE);
		if (p_random_value == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		eap_variable_data_c server_random_value(m_am_tools);
		status = server_random_value.set_buffer(
			p_random_value,
			TLS_HANDSHAKE_RANDOM_VALUE_SIZE,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = tls_handshake_message->set_random_value(&server_random_value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data_offset += TLS_HANDSHAKE_RANDOM_VALUE_SIZE;

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: parse_handshake_type_server_hello(): m_server_random_value"),
			 server_random_value.get_data(server_random_value.get_data_length()),
			 server_random_value.get_data_length()));
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_SESSION_ID_LENGTH_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_session_id_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_SESSION_ID_LENGTH_FIELD_SIZE);
		if (p_session_id_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		data_offset += TLS_SESSION_ID_LENGTH_FIELD_SIZE;

		if (data_offset+*p_session_id_length > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		if (*p_session_id_length > 0ul)
		{
			u8_t *p_session_id = tls_handshake_header->get_data_offset(
				data_offset,
				*p_session_id_length);
			if (p_session_id == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
			}

			eap_variable_data_c session_id(m_am_tools);
			status = session_id.set_buffer(p_session_id, *p_session_id_length, false, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = tls_handshake_message->set_session_id(&session_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: parse_handshake_type_server_hello(): session_id"),
				 session_id.get_data(session_id.get_data_length()),
				 session_id.get_data_length()));
		}
		
		data_offset += *p_session_id_length;
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_CIPHER_SUITE_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_cipher_suite_network_order = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_CIPHER_SUITE_FIELD_SIZE);
		if (p_cipher_suite_network_order == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		u16_t cipher_suite
			= eap_read_u16_t_network_order(
				p_cipher_suite_network_order,
				TLS_CIPHER_SUITE_FIELD_SIZE);

		status = tls_handshake_message->set_selected_cipher_suite(
			static_cast<tls_cipher_suites_e>(cipher_suite));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: parse_handshake_type_server_hello(): cipher_suite"),
			 &cipher_suite,
			 sizeof(cipher_suite)));

		data_offset += TLS_CIPHER_SUITE_FIELD_SIZE;
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_COMPRESSION_METHOD_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_compression = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_COMPRESSION_METHOD_FIELD_SIZE);
		if (p_compression == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		status = tls_handshake_message->set_selected_compression_method(
			static_cast<tls_compression_method_e>(*p_compression));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: parse_handshake_type_server_hello(): p_compression"),
			 p_compression,
			 sizeof(*p_compression)));

		data_offset += TLS_COMPRESSION_METHOD_FIELD_SIZE;
	}

	//----------------------------------------------------------

#if defined(USE_EAP_TLS_SESSION_TICKET)

	status = parse_tls_extension_list(
		handshake_data_length,
		&data_offset,
		tls_handshake_header,
		tls_handshake_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

	//----------------------------------------------------------

	if (status == eap_status_ok)
	{
		// Note the add_handshake_message() frees message in any case.
		automatic_tls_handshake_message.do_not_free_variable();

		status = received_tls_record_message->add_handshake_message(tls_handshake_message, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_handshake_type_server_key_exchange(
	tls_record_message_c * const received_tls_record_message,
	tls_handshake_header_c * const tls_handshake_header,
	const u32_t handshake_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_handshake_type_server_key_exchange()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_handshake_type_server_key_exchange()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message_copy(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_header);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t handshake_length = tls_handshake_header->get_data_length();
	u32_t data_offset = 0ul;

	//----------------------------------------------------------

	{
		if (data_offset+TLS_DHE_PRIME_LENGTH_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_dhe_prime_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_DHE_PRIME_LENGTH_FIELD_SIZE);
		if (p_dhe_prime_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		data_offset += TLS_DHE_PRIME_LENGTH_FIELD_SIZE;

		u16_t dhe_prime_length
			= eap_read_u16_t_network_order(p_dhe_prime_length, TLS_DHE_PRIME_LENGTH_FIELD_SIZE);

		u8_t *p_dhe_prime_value = tls_handshake_header->get_data_offset(
			data_offset,
			dhe_prime_length);
		if (p_dhe_prime_value == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		eap_variable_data_c dhe_prime(m_am_tools);
		status = dhe_prime.set_buffer(p_dhe_prime_value, dhe_prime_length, false, false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = tls_handshake_message->set_dhe_prime(&dhe_prime);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data_offset += dhe_prime_length;
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_DHE_GROUP_GENERATOR_LENGTH_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_dhe_group_generator_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_DHE_GROUP_GENERATOR_LENGTH_FIELD_SIZE);
		if (p_dhe_group_generator_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		data_offset += TLS_DHE_GROUP_GENERATOR_LENGTH_FIELD_SIZE;

		u16_t dhe_group_generator_length = 
			eap_read_u16_t_network_order(
				p_dhe_group_generator_length,
				TLS_DHE_GROUP_GENERATOR_LENGTH_FIELD_SIZE);

		u8_t *p_dhe_group_generator_value = tls_handshake_header->get_data_offset(
			data_offset,
			dhe_group_generator_length);
		if (p_dhe_group_generator_value == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		eap_variable_data_c dhe_group_generator(m_am_tools);
		status = dhe_group_generator.set_buffer(
			p_dhe_group_generator_value,
			dhe_group_generator_length,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = tls_handshake_message->set_dhe_group_generator(&dhe_group_generator);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data_offset += dhe_group_generator_length;
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_PUBLIC_DHE_KEY_LENGTH_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_public_dhe_key_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_PUBLIC_DHE_KEY_LENGTH_FIELD_SIZE);
		if (p_public_dhe_key_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		data_offset += TLS_PUBLIC_DHE_KEY_LENGTH_FIELD_SIZE;

		u16_t public_dhe_key_length = 
			eap_read_u16_t_network_order(
				p_public_dhe_key_length,
				TLS_PUBLIC_DHE_KEY_LENGTH_FIELD_SIZE);

		u8_t *p_public_dhe_key_value = tls_handshake_header->get_data_offset(
			data_offset,
			public_dhe_key_length);
		if (p_public_dhe_key_value == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		eap_variable_data_c public_dhe_key(m_am_tools);
		status = public_dhe_key.set_buffer(
			p_public_dhe_key_value,
			public_dhe_key_length,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = tls_handshake_message->set_public_dhe_key(&public_dhe_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data_offset += public_dhe_key_length;
	}

	//----------------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)
	if (m_eap_type == eap_type_fast
		&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
		&& data_offset == handshake_data_length)
	{
		// Here are no signed hash.
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_handshake_type_server_key_exchange(): EAP-FAST server unauthenticated provisioning mode, no signed hash\n"),
			(m_is_client == true ? "client": "server")));
	}
	else
#endif //#if defined(USE_FAST_EAP_TYPE)
	{
		if (data_offset >= handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		u16_t expected_dss_sha1_signature_length
			= static_cast<u16_t>(handshake_length - data_offset);
		
		u8_t *p_dss_sha1_signature_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_DSS_SHA1_SIGNATURE_LENGTH_FIELD_SIZE);
		if (p_dss_sha1_signature_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		u16_t dss_sha1_signature_length = 
			eap_read_u16_t_network_order(
				p_dss_sha1_signature_length,
				TLS_DSS_SHA1_SIGNATURE_LENGTH_FIELD_SIZE);

		if (expected_dss_sha1_signature_length == dss_sha1_signature_length+2ul)
		{
			// WARNING: Here we have additional length field. OpenSSL does this.
			/*
				// TLS 1.0 RFC 2246 says the length of sha_hash is explicitly 20 bytes
				// (Chapter 7.4.3. Server key exchange message).
				// The length of the vector is not included in the encoded stream
				// (Chapter 4.3. Vectors).
				select (SignatureAlgorithm)
				{   case anonymous: struct { };
				   case rsa:
					   digitally-signed struct {
						   opaque md5_hash[16];
						   opaque sha_hash[20];
					   };
				   case dsa:
					   digitally-signed struct {
						   opaque sha_hash[20];
					   };
				} Signature;
			*/
			data_offset += TLS_DSS_SHA1_SIGNATURE_LENGTH_FIELD_SIZE;
		}
		else
		{
			dss_sha1_signature_length = expected_dss_sha1_signature_length;
		}

		u8_t *p_dss_sha1_signature = tls_handshake_header->get_data_offset(
			data_offset,
			dss_sha1_signature_length);
		if (p_dss_sha1_signature == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		eap_variable_data_c dss_sha1_signature(m_am_tools);
		status = dss_sha1_signature.set_buffer(
			p_dss_sha1_signature,
			dss_sha1_signature_length,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = tls_handshake_message->set_signed_message_hash(&dss_sha1_signature);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data_offset += dss_sha1_signature_length;
	}

	//----------------------------------------------------------

	if (status == eap_status_ok)
	{
		// Note the add_handshake_message() frees message in any case.
		automatic_tls_handshake_message.do_not_free_variable();

		status = received_tls_record_message->add_handshake_message(tls_handshake_message, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_handshake_type_client_key_exchange(
	tls_record_message_c * const received_tls_record_message,
	tls_handshake_header_c * const tls_handshake_header,
	const u32_t handshake_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_handshake_type_client_key_exchange()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_handshake_type_client_key_exchange()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message_copy(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_header);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t data_offset = 0ul;

	//----------------------------------------------------------

	if (cipher_suite_is_TLS_RSA() == true)
	{
		u32_t encrypted_premaster_secret_length = tls_handshake_header->get_data_length();

		if (data_offset+encrypted_premaster_secret_length > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_encrypted_premaster_secret_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_ENCRYPTED_PREMASTER_SECRET_LENGTH_FIELD_SIZE);
		if (p_encrypted_premaster_secret_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		data_offset += TLS_ENCRYPTED_PREMASTER_SECRET_LENGTH_FIELD_SIZE;

		u16_t data_encrypted_premaster_secret_length
			= eap_read_u16_t_network_order(
				p_encrypted_premaster_secret_length,
				TLS_ENCRYPTED_PREMASTER_SECRET_LENGTH_FIELD_SIZE);

		if ((data_encrypted_premaster_secret_length + 2ul) != encrypted_premaster_secret_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t *p_encrypted_premaster_secret_value = tls_handshake_header->get_data_offset(
			data_offset,
			encrypted_premaster_secret_length-2ul);
		if (p_encrypted_premaster_secret_value == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		eap_variable_data_c encrypted_premaster_secret(m_am_tools);
		status = encrypted_premaster_secret.set_buffer(
			p_encrypted_premaster_secret_value,
			encrypted_premaster_secret_length-2ul,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: parse_handshake_type_client_key_exchange(): encrypted premaster_secret"),
			 encrypted_premaster_secret.get_data(),
			 encrypted_premaster_secret.get_data_length()));

		status = tls_handshake_message->set_encrypted_premaster_secret(&encrypted_premaster_secret);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data_offset += encrypted_premaster_secret_length;
	}
	else if (cipher_suite_is_TLS_DHE_DSS() == true
		|| cipher_suite_is_TLS_DHE_RSA() == true
#if defined(USE_FAST_EAP_TYPE)
		|| (m_eap_type == eap_type_fast
			&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
			&& cipher_suite_is_TLS_DH_anon() == true)
#endif //#if defined(USE_FAST_EAP_TYPE)
		)
	{
		if (data_offset+TLS_PUBLIC_DHE_KEY_LENGTH_LENGTH_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_public_dhe_key_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_PUBLIC_DHE_KEY_LENGTH_LENGTH_FIELD_SIZE);
		if (p_public_dhe_key_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		data_offset += TLS_PUBLIC_DHE_KEY_LENGTH_LENGTH_FIELD_SIZE;

		u16_t public_dhe_key_length
			= eap_read_u16_t_network_order(
				p_public_dhe_key_length,
				TLS_PUBLIC_DHE_KEY_LENGTH_LENGTH_FIELD_SIZE);

		u8_t *p_public_dhe_key_value = tls_handshake_header->get_data_offset(
			data_offset,
			public_dhe_key_length);
		if (p_public_dhe_key_value == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		eap_variable_data_c public_dhe_key(m_am_tools);
		status = public_dhe_key.set_buffer(
			p_public_dhe_key_value,
			public_dhe_key_length,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = tls_handshake_message->set_public_dhe_key(&public_dhe_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data_offset += public_dhe_key_length;
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}

	//----------------------------------------------------------

	if (status == eap_status_ok)
	{
		// Note the add_handshake_message() frees message in any case.
		automatic_tls_handshake_message.do_not_free_variable();

		status = received_tls_record_message->add_handshake_message(tls_handshake_message, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_handshake_type_certificate_verify(
	tls_record_message_c * const received_tls_record_message,
	tls_handshake_header_c * const tls_handshake_header,
	const u32_t handshake_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_handshake_type_certificate_verify()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_handshake_type_certificate_verify()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message_copy(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_header);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t data_offset = 0ul;

	//----------------------------------------------------------


	// Save the message hash.
	message_hash_save_certificate_verify();

	if (cipher_suite_is_TLS_RSA() == true
		|| cipher_suite_is_TLS_DHE_RSA() == true)
	{
		eap_variable_data_c signed_hash(m_am_tools);

		if (data_offset >= handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		u32_t handshake_length = tls_handshake_header->get_data_length();
		u32_t rsa_md5_sha1_signature_length = handshake_length - data_offset;
		
		u8_t *p_signature_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_SIGNATURE_LENGTH_FIELD_SIZE);
		if (p_signature_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		data_offset += TLS_SIGNATURE_LENGTH_FIELD_SIZE;

		u16_t data_signature_length
			= eap_read_u16_t_network_order(p_signature_length, TLS_SIGNATURE_LENGTH_FIELD_SIZE);

		if ((data_signature_length + 2ul) != rsa_md5_sha1_signature_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t *p_rsa_md5_sha1_signature = tls_handshake_header->get_data_offset(
			data_offset,
			rsa_md5_sha1_signature_length-2ul);
		if (p_rsa_md5_sha1_signature == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		status = signed_hash.set_copy_of_buffer(
			p_rsa_md5_sha1_signature,
			rsa_md5_sha1_signature_length-2ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = tls_handshake_message->set_signed_message_hash(
			&signed_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data_offset += rsa_md5_sha1_signature_length;
	}
	else if (cipher_suite_is_TLS_DHE_DSS() == true)
	{
		eap_variable_data_c signed_hash(m_am_tools);

		if (data_offset >= handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		u32_t handshake_length = tls_handshake_header->get_data_length();
		u32_t dss_sha1_signature_length = handshake_length - data_offset;
		
		u8_t *p_signature_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_SIGNATURE_LENGTH_FIELD_SIZE);
		if (p_signature_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		data_offset += TLS_SIGNATURE_LENGTH_FIELD_SIZE;

		u16_t data_signature_length
			= eap_read_u16_t_network_order(p_signature_length, TLS_SIGNATURE_LENGTH_FIELD_SIZE);

		if ((data_signature_length + 2ul) != dss_sha1_signature_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t *p_dss_sha1_signature = tls_handshake_header->get_data_offset(
			data_offset,
			dss_sha1_signature_length-2ul);
		if (p_dss_sha1_signature == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		status = signed_hash.set_copy_of_buffer(
			p_dss_sha1_signature,
			dss_sha1_signature_length-2ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = tls_handshake_message->set_signed_message_hash(
			&signed_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data_offset += dss_sha1_signature_length;
	}

	//----------------------------------------------------------

	if (status == eap_status_ok)
	{
		// Note the add_handshake_message() frees message in any case.
		automatic_tls_handshake_message.do_not_free_variable();

		status = received_tls_record_message->add_handshake_message(tls_handshake_message, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_handshake_type_finished(
	tls_record_message_c * const received_tls_record_message,
	tls_handshake_header_c * const tls_handshake_header,
	const u32_t /* handshake_data_length */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_handshake_type_finished()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_handshake_type_finished()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message_copy(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_header);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t data_offset = 0ul;

	//----------------------------------------------------------

	bool client_originated = true;
	if (m_is_client == true)
	{
		client_originated = false;
	}
	// Save the message hash.
	message_hash_save_finished(client_originated);

	{
		eap_variable_data_c finished_data(m_am_tools);

		u8_t *p_finished_data = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_FINISHED_DATA_SIZE);
		if (p_finished_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		status = finished_data.set_copy_of_buffer(p_finished_data, TLS_FINISHED_DATA_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = tls_handshake_message->set_finished_data(
			&finished_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data_offset += TLS_FINISHED_DATA_SIZE;
	}

	//----------------------------------------------------------

	if (status == eap_status_ok)
	{
		// Note the add_handshake_message() frees message in any case.
		automatic_tls_handshake_message.do_not_free_variable();

		status = received_tls_record_message->add_handshake_message(tls_handshake_message, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TLS_SESSION_TICKET)

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_handshake_type_new_session_ticket(
	tls_record_message_c * const received_tls_record_message,
	tls_handshake_header_c * const tls_handshake_header,
	const u32_t handshake_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_handshake_type_new_session_ticket()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_handshake_type_new_session_ticket()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message_copy(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_header);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t data_offset = 0ul;

	u8_t * handshake_data = tls_handshake_header->get_data_offset(
		data_offset,
		tls_handshake_header->get_data_length());
	if (handshake_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	//----------------------------------------------------------

	u32_t session_ticket_lifetime_hint(0ul);

	{
		if (data_offset+TLS_SESSION_TICKET_LIFETIME_HINT_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_session_ticket_lifetime_hint = handshake_data;

		session_ticket_lifetime_hint = eap_read_u32_t_network_order(
			p_session_ticket_lifetime_hint,
			TLS_SESSION_TICKET_LIFETIME_HINT_FIELD_SIZE);
		
		data_offset += TLS_SESSION_TICKET_LIFETIME_HINT_FIELD_SIZE;
	}

	//----------------------------------------------------------

	{
		if (data_offset+TLS_EXTENSION_DATA_LENGTH_FIELD_SIZE > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}
		
		u8_t *p_opaque_session_ticket_length = tls_handshake_header->get_data_offset(
			data_offset,
			TLS_EXTENSION_DATA_LENGTH_FIELD_SIZE);
		if (p_opaque_session_ticket_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		u16_t opaque_session_ticket_length = eap_read_u16_t_network_order(
			p_opaque_session_ticket_length,
			TLS_EXTENSION_DATA_LENGTH_FIELD_SIZE);
		
		data_offset += TLS_EXTENSION_DATA_LENGTH_FIELD_SIZE;

		if (data_offset+opaque_session_ticket_length > handshake_data_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		tls_extension_c opaque_session_ticket(m_am_tools);

		if (opaque_session_ticket.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u8_t *p_opaque_session_ticket = tls_handshake_header->get_data_offset(
			data_offset,
			opaque_session_ticket_length);
		if (p_opaque_session_ticket_length == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		status = opaque_session_ticket.set_buffer(
			p_opaque_session_ticket,
			opaque_session_ticket_length,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		opaque_session_ticket.set_type(tls_extension_type_session_ticket);

		opaque_session_ticket.set_lifetime_hint(session_ticket_lifetime_hint);

		eap_array_c<tls_extension_c> tls_extensions(m_am_tools);

		status = tls_extensions.add_object(&opaque_session_ticket, false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Save the new session ticket to be included in next NewSessionTicket message.
		status = tls_handshake_message->set_tls_extensions(
			&tls_extensions);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: parse_handshake_type_new_session_ticket(): opaque_session_ticket"),
			 opaque_session_ticket.get_data(opaque_session_ticket.get_data_length()),
			 opaque_session_ticket.get_data_length()));

		data_offset += opaque_session_ticket_length;
	}

	//----------------------------------------------------------

	if (status == eap_status_ok)
	{
		// Note the add_handshake_message() frees message in any case.
		automatic_tls_handshake_message.do_not_free_variable();

		status = received_tls_record_message->add_handshake_message(tls_handshake_message, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_tls_protocol_change_cipher_spec(
	tls_record_message_c * const tls_record_message,
	eap_variable_data_c * const tls_protocol_messages_buffer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_tls_protocol_change_cipher_spec()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_tls_protocol_change_cipher_spec()");

	tls_record_message->set_parsed_record();

	if (verify_state(tls_peap_state_wait_change_cipher_spec) == false
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		&& (m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_none
			&& verify_state(tls_peap_state_wait_handshake_type_certificate_verify) == false)
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: TLS: %s: function: verify_state(): current state %s != %s\n"),
			 (m_is_client == true ? "client": "server"),
			 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
			 eap_tls_trace_string_c::get_state_string(tls_peap_state_wait_change_cipher_spec)));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	eap_status_e status = eap_status_not_supported;

	const u32_t tls_protocols_length = tls_protocol_messages_buffer->get_data_length();

	tls_change_cipher_spec_message_c * const tls_change_cipher_spec_message
		= new tls_change_cipher_spec_message_c(m_am_tools, this, m_is_client);

	eap_automatic_variable_c<tls_change_cipher_spec_message_c>
		automatic_tls_change_cipher_spec_message(m_am_tools, tls_change_cipher_spec_message);

	if (tls_change_cipher_spec_message == 0
		|| tls_change_cipher_spec_message->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t data_offset = 0ul;

	//----------------------------------------------------------

	{
		if (data_offset+TLS_CHANGE_CIPHER_SPEC_FIELD_SIZE > tls_protocols_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		u8_t *p_change_cipher_spec_type = tls_protocol_messages_buffer->get_data_offset(
			data_offset,
			TLS_CHANGE_CIPHER_SPEC_FIELD_SIZE);
		if (p_change_cipher_spec_type == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		status = tls_change_cipher_spec_message->set_change_cipher_spec_type(
			static_cast<tls_change_cipher_spec_type_e>(*p_change_cipher_spec_type));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data_offset += TLS_CHANGE_CIPHER_SPEC_FIELD_SIZE;
	}

	//----------------------------------------------------------

	if (tls_protocols_length != data_offset)
	{
		// Parsed record length does not match with received record length.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	if (status == eap_status_ok)
	{
		// Note add_change_cipher_spec_message() frees message on any case.
		automatic_tls_change_cipher_spec_message.do_not_free_variable();

		status = tls_record_message->add_change_cipher_spec_message(
			tls_change_cipher_spec_message,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_tls_protocol_alert(
	tls_record_message_c * const tls_record_message,
	eap_variable_data_c * const tls_protocol_messages_buffer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_tls_protocol_alert()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_tls_protocol_alert()");

	tls_record_message->set_parsed_record();

	eap_status_e status = eap_status_not_supported;

	// Because we received alert message, we do not send alert messages anymore.
	m_could_send_fatal_alert_message = false;
	m_could_send_warning_alert_message = false;

	const u32_t tls_protocol_messages_length = tls_protocol_messages_buffer->get_data_length();
	u32_t data_start_offset = 0ul;

	while (data_start_offset < tls_protocol_messages_length)
	{
		tls_alert_message_c * const tls_alert_message
			= new tls_alert_message_c(m_am_tools, m_is_client);

		eap_automatic_variable_c<tls_alert_message_c>
			automatic_tls_alert_message(m_am_tools, tls_alert_message);

		if (tls_alert_message == 0
			|| tls_alert_message->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		
		u32_t data_offset = 0ul;

		//----------------------------------------------------------

		{
			if (data_start_offset+data_offset+TLS_ALERT_LEVEL_FIELD_SIZE
				> tls_protocol_messages_length)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
			}

			u8_t *p_alert_level = tls_protocol_messages_buffer->get_data_offset(
				data_start_offset+data_offset,
				TLS_ALERT_LEVEL_FIELD_SIZE);
			if (p_alert_level == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
			}

			status = tls_alert_message->set_alert_level(
				static_cast<tls_alert_level_e>(*p_alert_level));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			data_offset += TLS_ALERT_LEVEL_FIELD_SIZE;
		}

		//----------------------------------------------------------

		{
			if (data_start_offset+data_offset+TLS_ALERT_DESCRIPTION_FIELD_SIZE
				> tls_protocol_messages_length)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
			}

			u8_t *p_alert_description = tls_protocol_messages_buffer->get_data_offset(
				data_start_offset+data_offset,
				TLS_ALERT_DESCRIPTION_FIELD_SIZE);
			if (p_alert_description == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
			}

			status = tls_alert_message->set_alert_description(
				static_cast<tls_alert_description_e>(*p_alert_description));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			data_offset += TLS_ALERT_DESCRIPTION_FIELD_SIZE;
		}

		if (status == eap_status_ok)
		{
			// Note add_alert_message() frees message on any case.
			automatic_tls_alert_message.do_not_free_variable();

			status = tls_record_message->add_alert_message(tls_alert_message, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		data_start_offset += data_offset;
	} // while()

	//----------------------------------------------------------

	if (tls_protocol_messages_length != data_start_offset)
	{
		// Parsed record length does not match with received record length.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_tls_protocol_handshake(
	tls_record_message_c * const tls_record_message,
	eap_variable_data_c * const tls_protocol_messages_buffer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_tls_protocol_handshake()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_tls_protocol_handshake()");

	tls_record_message->set_parsed_record();

	const u32_t tls_protocol_messages_length = tls_protocol_messages_buffer->get_data_length();

	u32_t data_start_offset = 0ul;

	tls_handshake_header_c tls_handshake_header(
		m_am_tools,
		tls_protocol_messages_buffer->get_data_offset(
			data_start_offset,
			tls_protocol_messages_buffer->get_data_length()-data_start_offset),
		tls_protocol_messages_buffer->get_data_length()-data_start_offset);
	if (tls_handshake_header.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	if (tls_handshake_header.get_header_length()+tls_handshake_header.get_data_length() > tls_handshake_header.get_header_buffer_length()
		|| tls_handshake_header.get_header_buffer(
			 tls_handshake_header.get_header_length()+tls_handshake_header.get_data_length()) == 0)
	{
		// Not enough data.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("TLS-handshake tls_handshake_header"),
		 tls_handshake_header.get_header_buffer(
			 tls_handshake_header.get_header_length()+tls_handshake_header.get_data_length()),
		 (tls_handshake_header.get_header_length()+tls_handshake_header.get_data_length())));

	eap_status_e status = eap_status_ok;

	u32_t counter = 0ul;


	while (tls_handshake_header.get_is_valid() == true
		&& data_start_offset < tls_protocol_messages_length)
	{
		const u32_t handshake_data_length = tls_handshake_header.get_data_length();
		if (handshake_data_length+data_start_offset > tls_protocol_messages_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: parse_function: parse_tls_protocol_handshake(): ")
			 EAPL("counter[%u] type = 0x%08x=%s.\n"),
			 (m_is_client == true ? "client": "server"),
			 counter,
			 tls_handshake_header.get_handshake_type(),
			 tls_handshake_header.get_tls_handshake_string()));

		status = tls_handshake_header.check_header(
			tls_handshake_header.get_handshake_type(),
			m_is_client);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (tls_handshake_header.get_header_length()+tls_handshake_header.get_data_length()
				> tls_handshake_header.get_header_buffer_length()
			|| tls_handshake_header.get_header_buffer(
				 tls_handshake_header.get_header_length()+tls_handshake_header.get_data_length()) == 0)
		{
			// Not enough data.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		bool add_to_message_hash = false;

		switch (tls_handshake_header.get_handshake_type())
		{
		case tls_handshake_type_hello_request:
			status = parse_handshake_type_hello_request(
				tls_record_message,
				&tls_handshake_header,
				handshake_data_length);
			add_to_message_hash = false;
			break;
		case tls_handshake_type_client_hello:
			status = parse_handshake_type_client_hello(
				tls_record_message,
				&tls_handshake_header,
				handshake_data_length);
			add_to_message_hash = true;
			break;
		case tls_handshake_type_server_hello:
			status = parse_handshake_type_server_hello(
				tls_record_message,
				&tls_handshake_header,
				handshake_data_length);
			add_to_message_hash = true;
			break;
		case tls_handshake_type_certificate:
			status = parse_handshake_type_certificate(
				tls_record_message,
				&tls_handshake_header,
				handshake_data_length);
			add_to_message_hash = true;
			break;
		case tls_handshake_type_server_key_exchange:
			status = parse_handshake_type_server_key_exchange(
				tls_record_message,
				&tls_handshake_header,
				handshake_data_length);
			add_to_message_hash = true;
			break;
		case tls_handshake_type_certificate_request:
			status = parse_handshake_type_certificate_request(
				tls_record_message,
				&tls_handshake_header,
				handshake_data_length);
			add_to_message_hash = true;
			break;
		case tls_handshake_type_server_hello_done:
			status = parse_handshake_type_server_hello_done(
				tls_record_message,
				&tls_handshake_header,
				handshake_data_length);
			add_to_message_hash = true;
			break;
		case tls_handshake_type_certificate_verify:
			status = parse_handshake_type_certificate_verify(
				tls_record_message,
				&tls_handshake_header,
				handshake_data_length);
			add_to_message_hash = true;
			break;
		case tls_handshake_type_client_key_exchange:
			status = parse_handshake_type_client_key_exchange(
				tls_record_message,
				&tls_handshake_header,
				handshake_data_length);
			add_to_message_hash = true;
			break;
		case tls_handshake_type_finished:
			status = parse_handshake_type_finished(
				tls_record_message,
				&tls_handshake_header,
				handshake_data_length);
			add_to_message_hash = true;
			break;
#if defined(USE_EAP_TLS_SESSION_TICKET)
		case tls_handshake_type_new_session_ticket:
			status = parse_handshake_type_new_session_ticket(
				tls_record_message,
				&tls_handshake_header,
				handshake_data_length);
			add_to_message_hash = true;
			break;
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
		default:
			return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
		} // switch()


		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		if (add_to_message_hash == true)
		{
			status = message_hash_update(
				true,
				tls_handshake_header.get_handshake_type(),
				tls_handshake_header.get_header_buffer(
					tls_handshake_header.get_header_length()
					+tls_handshake_header.get_data_length()),
				tls_handshake_header.get_header_length()
				+tls_handshake_header.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		data_start_offset += (tls_handshake_header.get_header_length()
							  +tls_handshake_header.get_data_length());

		if (data_start_offset > tls_protocol_messages_buffer->get_data_length())
		{
			// Parsed record length does not match with received record length.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		tls_handshake_header.set_header_buffer(
			tls_protocol_messages_buffer->get_data_offset(
				data_start_offset,
				tls_protocol_messages_buffer->get_data_length()-data_start_offset),
			tls_protocol_messages_buffer->get_data_length()-data_start_offset);
		// NOTE tls_handshake_header is checked in the begin of the loop.

		++counter;

	} // while()

	if (tls_protocol_messages_length != data_start_offset)
	{
		// Parsed record length does not match with received record length.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::parse_tls_protocol_application_data(
	tls_record_message_c * const tls_record_message,
	eap_variable_data_c * const tls_protocol_messages_buffer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::parse_tls_protocol_application_data()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::parse_tls_protocol_application_data()");

	tls_record_message->set_parsed_record();

	eap_status_e status = eap_status_not_supported;

	const u32_t tls_protocol_messages_length = tls_protocol_messages_buffer->get_data_length();

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("TLS-application data"),
		tls_protocol_messages_buffer->get_data(tls_protocol_messages_length),
		tls_protocol_messages_length));

	tls_application_data_message_c * const tls_application_data_message
		= new tls_application_data_message_c(m_am_tools, m_is_client);

		eap_automatic_variable_c<tls_application_data_message_c>
			automatic_tls_application_data_message(m_am_tools, tls_application_data_message);

	if (tls_application_data_message == 0
		|| tls_application_data_message->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t data_offset = 0ul;

	//----------------------------------------------------------

	{
		u8_t *p_application_data = tls_protocol_messages_buffer->get_data(
			tls_protocol_messages_length);
		if (p_application_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		status = tls_application_data_message->set_application_data(
			p_application_data,
			tls_protocol_messages_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data_offset += tls_protocol_messages_length;
	}

	//----------------------------------------------------------

	if (tls_protocol_messages_length != data_offset)
	{
		// Parsed record length does not match with received record length.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	if (status == eap_status_ok)
	{
		// Note add_application_data_message() frees message on any case.
		automatic_tls_application_data_message.do_not_free_variable();

		status = tls_record_message->add_application_data_message(
			tls_application_data_message, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::reassemble_tls_records(
	tls_record_message_c * const tls_record_message,
	tls_record_header_c * const next_tls_record_header)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TLS: this = 0x%08x, %s: starts: tls_record_c::reassemble_tls_records()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::reassemble_tls_records()");

	eap_status_e status = tls_record_message->get_record_message_data()->add_data(
		next_tls_record_header->get_data(next_tls_record_header->get_data_length()),
		next_tls_record_header->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = tls_record_message->add_data_length(next_tls_record_header->get_data_length());

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TLS: this = 0x%08x, %s: tls_record_c::reassemble_tls_records(): fragment %d bytes, ")
		 EAPL("message %d bytes.\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 next_tls_record_header->get_data_length(),
		 tls_record_message->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::process_tls_records()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::process_tls_records(): index = %d, record count = %d\n"),
		 (m_is_client == true ? "client": "server"),
		 m_received_tls_message.get_analyse_index(),
		 m_received_tls_message.get_record_message_count()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::process_tls_records()");

	if (m_already_in_process_tls_records == true)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		// This is recursive call of process_tls_records().
		// This MUST return eap_status_ok. Other return values will skip
		// further prosessing of TLS message.
		EAP_TRACE_DEBUG(
			m_am_tools, TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: send_function: process_tls_records(): skip recursion\n"),
			(m_is_client == true ? "client": "server")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_end_recursion);
	}
	m_already_in_process_tls_records = true;

	eap_automatic_simple_value_c<bool> restore_already_in_process_tls_records(
		m_am_tools,
		&m_already_in_process_tls_records,
		false);

	// One TLS-message could include many records. Each of records could
	// include many protocol messages.
	// +=================================================+
	// +=================================================+
	// | 1. tls_record_header_c                          |
	// | protocol tls_record_protocol_handshake          |
	// +-------------------------------------------------+
	// | 1a. tls_handshake_header_c                      |
	// +- - - - - - - - - - - - - - - - - - - - - - - - -+
	// | 1a. data of handshake                           |
	// +-------------------------------------------------+
	// | 1b. tls_handshake_header_c                      |
	// +- - - - - - - - - - - - - - - - - - - - - - - - -+
	// | 1b. data of handshake                           |
	// +=================================================+
	// +=================================================+
	// | 2. tls_record_header_c                          |
	// | protocol tls_record_protocol_change_cipher_spec |
	// +-------------------------------------------------+
	// | 2a. data of change_cipher_spec                  |
	// +=================================================+
	// +=================================================+
	// | 3. tls_record_header_c                          |
	// | protocol tls_record_protocol_handshake          |
	// +-------------------------------------------------+
	// | 3a. tls_handshake_header_c                      |
	// +- - - - - - - - - - - - - - - - - - - - - - - - -+
	// | 3a. data of handshake                           |
	// +=================================================+
	// +=================================================+

	// One protocol message could be fragmented to many records.
	// +=================================================+
	// +=================================================+
	// | 1. tls_record_header_c                          |
	// | protocol tls_record_protocol_handshake          |
	// +-------------------------------------------------+
	// | 1a. tls_handshake_header_c                      |
	// +- - - - - - - - - - - - - - - - - - - - - - - - -+
	// | 1a. data of handshake (1/2)                     |
	// +=================================================+
	// +=================================================+
	// | 2. tls_record_header_c                          |
	// | protocol tls_record_protocol_change_cipher_spec |
	// +-------------------------------------------------+
	// | 2a. data of handshake (2/2)                     |
	// +=================================================+
	// +=================================================+

	eap_status_e status = eap_status_ok;
	u32_t index = 0ul;
	bool analyse_messages = true;

	for (index = m_received_tls_message.get_analyse_index()
			 ; analyse_messages == true
			 && index < m_received_tls_message.get_record_message_count()
			 ; index++)
	{
		// This is used in EAP-FAST to see the next TLS message type.
		m_received_tls_message.save_analyse_index(index);

		tls_record_message_c * const tls_record_message
			= m_received_tls_message.get_record_message(index);
		if (tls_record_message == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
				m_am_tools,
				eap_status_too_short_message);
		}

		u32_t tls_record_length = tls_record_message->get_record_message_data()->get_data_length();

		tls_record_header_c tls_record_header(
			m_am_tools,
			tls_record_message->get_record_message_data()->get_data(
				tls_record_header_c::get_header_length()),
			tls_record_length);

		if (tls_record_header.get_is_valid() == false
			|| tls_record_length < tls_record_header.get_data_length())
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
				m_am_tools,
				eap_status_too_short_message);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("process TLS-record message"),
			 tls_record_header.get_header_buffer(tls_record_header.get_header_length()
												 + tls_record_header.get_data_length()),
			 tls_record_header.get_header_length()
			 + tls_record_header.get_data_length()));

		if ((tls_record_length)
			< (tls_record_header.get_header_length() + tls_record_header.get_data_length()))
		{
			// Record header indicates more data than the received buffer includes.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
				m_am_tools,
				eap_status_process_illegal_packet_error);
		}

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: parse_function: process_tls_records(): ")
			 EAPL("index[%u] protocol = 0x%08x=%s.\n"),
			(m_is_client == true ? "client": "server"),
			index,
			tls_record_header.get_protocol(),
			tls_record_header.get_tls_protocol_string()));


		if (tls_record_message->get_cipher_suite_applied() == false)
		{
			status = apply_receive_cipher_suite(tls_record_message->get_record_message_data());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
			}

			tls_record_message->set_cipher_suite_applied();

			tls_record_length = tls_record_message->get_record_message_data()->get_data_length();

			// We must query tls_record_header again,
			// memory buffer may be changed during apply_receive_cipher_suite() call.
			tls_record_header.set_header_buffer(
				tls_record_message->get_record_message_data()->get_data(
					tls_record_header_c::get_header_length()),
				tls_record_length);

			if (tls_record_header.get_is_valid() == false
				|| tls_record_length < tls_record_header.get_data_length()
				|| tls_record_length
				< tls_record_header.get_header_length()
				+ tls_record_header.get_data_length())
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
					m_am_tools,
					eap_status_too_short_message);
			}
		}


		while (index+1ul < m_received_tls_message.get_record_message_count())
		{
			tls_record_message_c * const next_tls_record_message
				= m_received_tls_message.get_record_message(index+1ul);
			if (next_tls_record_message != 0)
			{
				u32_t next_tls_record_length
					= next_tls_record_message->get_record_message_data()->get_data_length();

				tls_record_header_c next_tls_record_header(
					m_am_tools,
					next_tls_record_message->get_record_message_data()->get_data(
						tls_record_header_c::get_header_length()),
					next_tls_record_length);

				if (next_tls_record_header.get_is_valid() == false
					|| next_tls_record_length < next_tls_record_header.get_data_length())
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
						m_am_tools,
						eap_status_too_short_message);
				}

				if (tls_record_header.get_protocol() == next_tls_record_header.get_protocol())
				{
					// Reassembly checks this and the next TLS-records whether they are fragments
					// and it reassembles fragments to one TLS-record.
					// The easiest check does need only the TLS-protocol fields.
					// If TLS-protocol fields are the same those records could be reassembled.

					if (next_tls_record_message->get_cipher_suite_applied() == false)
					{
						status = apply_receive_cipher_suite(
							next_tls_record_message->get_record_message_data());
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
								m_am_tools,
								status);
						}
						
						next_tls_record_message->set_cipher_suite_applied();
					}

					next_tls_record_length
						= next_tls_record_message->get_record_message_data()->get_data_length();

					next_tls_record_header.set_header_buffer(
						next_tls_record_message->get_record_message_data()->get_data(
							tls_record_header_c::get_header_length()),
						next_tls_record_length);
					
					if (next_tls_record_header.get_is_valid() == false
						|| next_tls_record_length < next_tls_record_header.get_data_length())
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
							m_am_tools,
							eap_status_too_short_message);
					}

					status = reassemble_tls_records(tls_record_message, &next_tls_record_header);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
					}

					// If TLS-record is complete then it could be parsed and analysed.
					// TLS-record is complete when the next TLS-record is other type of protocol.
					// If TLS-record is NOT complete the next TLS-record must processed.
					// In a case the TLS-record cannot be reassemled the whole
					// TLS-message must be dropped.

					// Remove the next_tls_record_message.
					status = m_received_tls_message.remove_record_message(index+1ul);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
					}
				}
				else
				{
					break;
				}
			}
			else
			{
				break;
			}
		} // while()

		// NOTE at this point the length may be longer than 2^14 bytes.
		tls_record_length = tls_record_message->get_record_message_data()->get_data_length();

		// We must query tls_record_header again,
		// memory buffer may be changed during reassembly.
		tls_record_header.set_header_buffer(
			tls_record_message->get_record_message_data()->get_data(
				tls_record_length),
			tls_record_length);
		
		if (tls_record_header.get_is_valid() == false
			|| tls_record_length < tls_record_header.get_data_length()
			|| tls_record_length
			< tls_record_header.get_header_length()
			+ tls_record_header.get_data_length())
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
				m_am_tools,
				eap_status_too_short_message);
		}



		// Here we extract the protocol messages from the buffer.
		// Note the tls_record_header includes only the first protocol message,
		// that causes the use of tls_record_message->get_record_message_data().
		u32_t protocol_messages_length = tls_record_length - tls_record_header.get_header_length();
		eap_variable_data_c protocol_messages(m_am_tools);

		status = protocol_messages.set_buffer(
			tls_record_message->get_record_message_data()->get_data_offset(
				tls_record_header.get_header_length(),
				protocol_messages_length),
			protocol_messages_length,
			false,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("reassembled TLS-protocol messages"),
			 protocol_messages.get_data(
				 protocol_messages.get_data_length()),
			 protocol_messages.get_data_length()));

		switch(tls_record_header.get_protocol())
		{
		case tls_record_protocol_change_cipher_spec:
		{
			if (tls_record_message->get_parsed_record() == false)
			{
				status = parse_tls_protocol_change_cipher_spec(
					tls_record_message,
					&protocol_messages);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}

			status = analyse_tls_protocol_change_cipher_spec(
				tls_record_message);
			break;
		}
		case tls_record_protocol_alert:
		{
			if (tls_record_message->get_parsed_record() == false)
			{
				status = parse_tls_protocol_alert(
					tls_record_message,
					&protocol_messages);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}

			status = analyse_tls_protocol_alert(
				tls_record_message);
			break;
		}
		case tls_record_protocol_handshake:
		{
			if (tls_record_message->get_parsed_record() == false)
			{
				status = parse_tls_protocol_handshake(
					tls_record_message,
					&protocol_messages);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}

			status = analyse_tls_protocol_handshake(
				tls_record_message,
				m_received_tls_message.get_received_eap_identifier());
			break;
		}
		case tls_record_protocol_application_data:
		{
			if (tls_record_message->get_parsed_record() == false)
			{
				status = parse_tls_protocol_application_data(
					tls_record_message,
					&protocol_messages);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}

			status = analyse_tls_protocol_application_data(
				tls_record_message,
				m_received_tls_message.get_received_eap_identifier());
			break;
		}
		default:
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
				m_am_tools,
				eap_status_wrong_protocol);
		} // switch()


		// Save the analysed state. We will continue from the following record
		// after the pending request is completed.
		m_received_tls_message.save_analyse_index(index+1ul);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: parse_function: process_tls_records(): saves index+1 = %u.\n"),
			(m_is_client == true ? "client": "server"),
			index+1ul));


		if (status == eap_status_pending_request)
		{
			// Save analyse state. We will continue from the current record
			// after the pending request is completed.
			m_received_tls_message.save_analyse_index(index);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: parse_function: process_tls_records(): pending request, saves index = %u.\n"),
				(m_is_client == true ? "client": "server"),
				index));

			analyse_messages = false;
			
			eap_status_e compl_status = completion_action_add(
				tls_completion_action_process_tls_records);
			if (compl_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (status != eap_status_ok)
		{
			analyse_messages = false;
		}

		if ((get_is_tunneled_tls() == false
				&& m_tls_peap_state == tls_peap_state_tls_success)
			|| (get_is_tunneled_tls() == true
				&& m_tls_peap_state == tls_peap_state_peap_tunnel_ready))
		{
			// Authentication OK.

			if (m_eap_type == eap_type_peap
				&& m_peap_version == peap_version_2
				&& m_tls_peap_state == tls_peap_state_peap_tunnel_ready)
			{
				// PEAPv2 sends EAP-Request/Identity message
				// within the application data within the same message
				// with TLS hello finished.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: PEAPv2 tunnel ready, application data may follow.\n")));
			}
			else
			{
				analyse_messages = false;
				if ((index+1ul) != m_received_tls_message.get_record_message_count())
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: TLS: %s: parse_function: starts: tls_record_c::process_tls_records(): (index+1 = %d) != (record count = %d)\n"),
						 (m_is_client == true ? "client": "server"),
						 index+1,
						 m_received_tls_message.get_record_message_count()));
					// Authentication was successfull, but there are unused TLS-records to process.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
				}
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: tls_record_c::process_tls_records(): m_received_tls_message.reset().\n")));
				m_received_tls_message.reset();
			}
		}
	} // for()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::process_tls_message()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TLS: %s: parse_function: starts: tls_record_c::process_tls_message()\n"),
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::process_tls_message()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("TLS-message"),
		m_received_tls_message.get_tls_message_data()->get_data(
			m_received_tls_message.get_tls_message_data()->get_data_length()),
		m_received_tls_message.get_tls_message_data()->get_data_length()));

	u32_t next_start_offset = 0ul;
	u32_t tls_packet_length = m_received_tls_message.get_tls_message_data()->get_data_length();

	if (tls_packet_length < tls_record_header_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
			m_am_tools,
			eap_status_too_short_message);
	}

	tls_record_header_c tls_record_header(
		m_am_tools,
		m_received_tls_message.get_tls_message_data()->get_data_offset(
			next_start_offset,
			tls_record_header_c::get_header_length()),
		tls_packet_length);

	if (tls_record_header.get_is_valid() == false
		|| tls_packet_length < tls_record_header.get_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
			m_am_tools,
			eap_status_too_short_message);
	}

	eap_status_e status = eap_status_ok;
	u32_t counter = 0ul;

	// One TLS-message could include many records. Each of records
	// could include many protocol messages.
	// +=================================================+
	// +=================================================+
	// | 1. tls_record_header_c                          |
	// | protocol tls_record_protocol_handshake          |
	// +-------------------------------------------------+
	// | 1a. tls_handshake_header_c                      |
	// +- - - - - - - - - - - - - - - - - - - - - - - - -+
	// | 1a. data of handshake                           |
	// +-------------------------------------------------+
	// | 1b. tls_handshake_header_c                      |
	// +- - - - - - - - - - - - - - - - - - - - - - - - -+
	// | 1b. data of handshake                           |
	// +=================================================+
	// +=================================================+
	// | 2. tls_record_header_c                          |
	// | protocol tls_record_protocol_change_cipher_spec |
	// +-------------------------------------------------+
	// | 2a. data of change_cipher_spec                  |
	// +=================================================+
	// +=================================================+
	// | 3. tls_record_header_c                          |
	// | protocol tls_record_protocol_handshake          |
	// +-------------------------------------------------+
	// | 3a. tls_handshake_header_c                      |
	// +- - - - - - - - - - - - - - - - - - - - - - - - -+
	// | 3a. data of handshake                           |
	// +=================================================+
	// +=================================================+

	// One protocol message could be fragmented to many records.
	// +=================================================+
	// +=================================================+
	// | 1. tls_record_header_c                          |
	// | protocol tls_record_protocol_handshake          |
	// +-------------------------------------------------+
	// | 1a. tls_handshake_header_c                      |
	// +- - - - - - - - - - - - - - - - - - - - - - - - -+
	// | 1a. data of handshake (1/2)                     |
	// +=================================================+
	// +=================================================+
	// | 2. tls_record_header_c                          |
	// | protocol tls_record_protocol_change_cipher_spec |
	// +-------------------------------------------------+
	// | 2a. data of handshake (2/2)                     |
	// +=================================================+
	// +=================================================+

	while(status == eap_status_ok
		  && next_start_offset < tls_packet_length
		  && tls_record_header.get_is_valid() == true)
	{
		if ((tls_packet_length-next_start_offset)
			< (tls_record_header.get_header_length() + tls_record_header.get_data_length()))
		{
			// Record header indicates more data than the received buffer includes.
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: Record header indicates more data %u ")
				 EAPL("than the received buffer includes %u.\n"),
				 (tls_record_header.get_header_length() + tls_record_header.get_data_length()),
				 (tls_packet_length-next_start_offset)));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
				m_am_tools,
				eap_status_process_illegal_packet_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("process TLS-record"),
			 tls_record_header.get_header_buffer(
				 tls_record_header.get_header_length()
				 + tls_record_header.get_data_length()),
			 tls_record_header.get_header_length()
			 + tls_record_header.get_data_length()));

		u32_t tls_record_length = tls_record_header.get_header_length()
			+ tls_record_header.get_data_length();

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: parse_function: process_tls_message(): ")
			 EAPL("counter[%u] protocol = 0x%08x=%s.\n"),
			(m_is_client == true ? "client": "server"),
			counter,
			tls_record_header.get_protocol(),
			tls_record_header.get_tls_protocol_string()));

		tls_record_message_c * const tls_record_message
			= new tls_record_message_c(m_am_tools, this, m_is_client);

		eap_automatic_variable_c<tls_record_message_c>
			automatic_tls_record_message(m_am_tools, tls_record_message);

		if (tls_record_message == 0
			|| tls_record_message->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
				m_am_tools,
				eap_status_allocation_error);
		}

		tls_record_message->set_tls_record_header_is_included(true);

		status = tls_record_message->set_record_header_copy(&tls_record_header);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
		}

		tls_record_message->set_record_message_data(
			tls_record_header.get_header_buffer(tls_record_header.get_header_length()
												+ tls_record_header.get_data_length()),
			tls_record_header.get_header_length()
			+ tls_record_header.get_data_length());

		// Note m_received_tls_message frees message on any case.
		automatic_tls_record_message.do_not_free_variable();

		status = m_received_tls_message.add_record_message(
			tls_record_message,
			true,
			false // Here the TLS-Hello messages are not marked.
			);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
		}


		next_start_offset += tls_record_length;

		if (next_start_offset < tls_packet_length)
		{
			u32_t remain_data_length = tls_packet_length - next_start_offset;
			if (remain_data_length < tls_record_header_c::get_header_length())
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
					m_am_tools,
					eap_status_too_short_message);
			}

			tls_record_header.set_header_buffer(
				m_received_tls_message.get_tls_message_data()->get_data_offset(
					next_start_offset,
					tls_record_header_c::get_header_length()),
				remain_data_length);

			if (tls_record_header.get_is_valid() == false
				|| remain_data_length < tls_record_header.get_data_length())
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
					m_am_tools,
					eap_status_too_short_message);
			}
		}

		++counter;

	} // while()

	if (next_start_offset != tls_packet_length)
	{
		// Parsed packet length does not match with received packet length.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(
			m_am_tools,
			eap_status_process_illegal_packet_error);
	}

	status = process_tls_records();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::check_selected_cipher_suite(
	const tls_cipher_suites_e selected_cipher_suite)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: suite_function: starts: tls_record_c::check_selected_cipher_suite(): selected_cipher_suite=%d=%s\n"),
		 (m_is_client == true ? "client": "server"),
		 selected_cipher_suite,
		 eap_tls_trace_string_c::get_cipher_suite_string(selected_cipher_suite)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::check_selected_cipher_suite()");

	u16_t tmp_selected_cipher_suite = static_cast<u16_t>(selected_cipher_suite);

	i32_t index = find_simple<u16_t>(
		&m_proposed_cipher_suites,
		&tmp_selected_cipher_suite,
		m_am_tools);
	if (index == -1)
	{
		for (u32_t ind = 0ul; ind < m_proposed_cipher_suites.get_object_count(); ++ind)
		{
			u16_t * proposed_cipher_suite = m_proposed_cipher_suites.get_object(ind);
			if (proposed_cipher_suite != 0)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: %s: suite_function: check_selected_cipher_suite(): proposed cipher suite=%d=%s\n"),
					 (m_is_client == true ? "client": "server"),
					 *proposed_cipher_suite,
					 eap_tls_trace_string_c::get_cipher_suite_string(static_cast<tls_cipher_suites_e>(*proposed_cipher_suite))));
			}
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::check_selected_compression_method(
	const tls_compression_method_e selected_compression_method)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: suite_function: starts: tls_record_c::check_selected_compression_method(): %s\n"),
		 (m_is_client == true ? "client": "server"),
		 eap_tls_trace_string_c::get_compression_method_string(selected_compression_method)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::check_selected_compression_method()");

	if (selected_compression_method == tls_compression_method_null)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	u8_t tmp_selected_compression_method = static_cast<u8_t>(selected_compression_method);

	i32_t index = find_simple<u8_t>(
		&m_proposed_compression_methods,
		&tmp_selected_compression_method, m_am_tools);
	if (index == -1)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::u16_t_to_host_order(
	u16_t * const value,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	*value = eap_ntohs(*value);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::u16_t_to_network_order(
	u16_t * const value,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	*value = eap_htons(*value);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_handshake_type_hello_request(
	EAP_TEMPLATE_CONST tls_handshake_message_c * const /* handshake_message */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_handshake_type_hello_request()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_handshake_type_hello_request()");

	EAP_ASSERT(m_is_client == true);

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	set_tls_identity_privacy_handshake_state(tls_identity_privacy_handshake_state_runs);
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

	set_state(tls_peap_state_wait_handshake_type_server_hello);

	eap_status_e status = completion_action_add(tls_completion_action_create_handshake_type_client_hello);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_handshake_type_client_hello(
	EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_handshake_type_client_hello(): privacy_handshake_state=%d=%s, session_type=%s\n"),
		 (m_is_client == true ? "client": "server"),
		 m_tls_identity_privacy_handshake_state,
		 eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(m_tls_identity_privacy_handshake_state),
		 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type)
		));
#else
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_handshake_type_client_hello(): privacy_handshake_state=%d=%s\n"),
		(m_is_client == true ? "client": "server"),
		0,
		""
		));
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_handshake_type_client_hello()");

	EAP_ASSERT(m_is_client == false);

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                 | Version: 3    | Version: 1    |               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
	// |                                                               |
	// +                                                               +
	// |                                                               |
	// +                                                               +
	// |          ClientRandomValue                                    |
	// +              (32 bytes)                       +-+-+-+-+-+-+-+-+
	// |                                               | ID length     |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// +                                                               +
	// |                Session ID                                     |
	// +             (maximum 32 bytes)                                +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | CipherSuite length            | CipherSuite 1                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | CipherSuite 2                 | CipherSuite 3                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | CipherSuite 4                 | Cmp length    | Cmp 1         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Cmp 2         | Cmp 3         |  extensions ...               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	eap_status_e status = eap_status_not_supported;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (handshake_message->get_random_value() == 0
		|| handshake_message->get_random_value()->get_data_length()
		!= TLS_HANDSHAKE_RANDOM_VALUE_SIZE)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}


	status = m_client_handshake_random_value.set_copy_of_buffer(
		handshake_message->get_random_value());
	if (status != eap_status_ok
		|| m_client_handshake_random_value.get_data_length() != TLS_HANDSHAKE_RANDOM_VALUE_SIZE)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (handshake_message->get_session_id() == 0
		|| (handshake_message->get_session_id()->get_is_valid_data() == true
			&& handshake_message->get_session_id()->get_data_length() > TLS_SESSION_ID_SIZE))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	if (handshake_message->get_session_id()->get_is_valid_data() == true
		&& handshake_message->get_session_id()->get_data_length() > 0ul)
	{
		status = m_session_id.set_copy_of_buffer(handshake_message->get_session_id());
		if (status != eap_status_ok
			|| m_session_id.get_data_length() > TLS_SESSION_ID_SIZE)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		EAP_TEMPLATE_CONST eap_array_c<u16_t> * const cipher_suites
			= handshake_message->get_cipher_suites();

		if (cipher_suites->get_object_count() == 0ul)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		m_proposed_cipher_suites.reset();

		status = copy_simple<u16_t>(
			cipher_suites,
			&m_proposed_cipher_suites,
			m_am_tools,
			false);
		if (status != eap_status_ok
			|| m_proposed_cipher_suites.get_object_count() == 0ul)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		EAP_TEMPLATE_CONST eap_array_c<u8_t> * const compression_methods
			= handshake_message->get_compression_methods();

		status = copy_simple<u8_t>(
			compression_methods,
			&m_proposed_compression_methods,
			m_am_tools,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_TLS_SESSION_TICKET)

	{
		EAP_TEMPLATE_CONST eap_array_c<tls_extension_c> * const tls_extensions
			= handshake_message->get_tls_extensions();

		status = copy<tls_extension_c>(
			tls_extensions,
			&m_received_tls_extensions,
			m_am_tools,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	if (m_tls_session_type == tls_session_type_full_authentication
		&& m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_negotiates)
	{
		set_tls_identity_privacy_handshake_state(tls_identity_privacy_handshake_state_runs);
	}
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

	status = completion_action_add(tls_completion_action_create_handshake_type_server_hello);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	if (m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_none)
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	{
		status = m_am_tls_services->select_cipher_suite_and_check_session_id(
			&m_proposed_cipher_suites,
			&m_session_id
	#if defined(USE_EAP_TLS_SESSION_TICKET)
			, tls_extension_c::get_tls_extension(
				tls_extension_type_session_ticket,
				&m_received_tls_extensions,
				m_am_tools)
	#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
			);
		if (status == eap_status_pending_request)
		{
			// This is pending query, that will be completed by
			// complete_select_cipher_suite_and_check_session_id() call.
			m_pending_select_cipher_suite_and_check_session_id = true;
		}
		else if (status == eap_status_completed_request)
		{
			// This is already completed by complete_select_cipher_suite_and_check_session_id() call.
		}
		else if (status == eap_status_ok)
		{
			// This is also an error case, because this call is always completed on success. 
			status = eap_status_process_general_error;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else // All other status values means error, because this call is always completed on success.
		{
			// This is an error case.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
		}
	}
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	else if (m_tls_session_type == tls_session_type_full_authentication
		&& m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_runs)
	{
		if (m_tls_peap_server_authenticates_client_config_server == true)
		{
			set_state(tls_peap_state_wait_handshake_type_certificate);
		}
		else
		{
			set_state(tls_peap_state_wait_handshake_type_client_key_exchange);
		}

		status = completion_action_add(tls_completion_action_create_handshake_type_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (cipher_suite_is_TLS_DHE_DSS() == true
			|| cipher_suite_is_TLS_DHE_RSA() == true)
		{
			// Ephemeral DH key exchange causes creation of server_key_exchange message.
			// Server sends DH public key and related parameters to client.

			status = completion_action_add(tls_completion_action_query_dh_parameters);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = completion_action_add(
				tls_completion_action_create_handshake_type_server_key_exchange);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// This will complete creation of handshake_type_server_key_exchange message.
			status = completion_action_add(
				tls_completion_action_complete_create_handshake_type_server_key_exchange);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Also the other pending messages will be processed after this action is completed.
			eap_status_e compl_status = completion_action_add(
				tls_completion_action_process_tls_records);
			if (compl_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (m_tls_peap_server_authenticates_client_config_server == true)
		{
			// Server initiates client authentication.
			status = completion_action_add(
				tls_completion_action_create_handshake_type_certificate_request);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		
		status = completion_action_add(
			tls_completion_action_create_handshake_type_server_hello_done);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (/* status == eap_status_pending_request
		   || */ status == eap_status_completed_request)
	{
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_handshake_type_server_hello(
	EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_handshake_type_server_hello()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_handshake_type_server_hello()");

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                 | Version: 3    | Version: 1    |               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
	// |                                                               |
	// +                                                               +
	// |                                                               |
	// +                                                               +
	// |          ServerRandomValue                                    |
	// +              (32 bytes)                       +-+-+-+-+-+-+-+-+
	// |                                               | ID length     |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// +                                                               +
	// |                Session ID                                     |
	// +             (maximum 32 bytes)                                +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | CipherSuite                   | Cmp           | extensions ...|
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	eap_status_e status = eap_status_not_supported;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (handshake_message->get_random_value() == 0
		|| handshake_message->get_random_value()->get_data_length()
		!= TLS_HANDSHAKE_RANDOM_VALUE_SIZE)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	status = m_server_handshake_random_value.set_copy_of_buffer(
		handshake_message->get_random_value());
	if (status != eap_status_ok
		|| m_server_handshake_random_value.get_data_length() != TLS_HANDSHAKE_RANDOM_VALUE_SIZE)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_selected_cipher_suite(handshake_message->get_selected_cipher_suite());

	status = check_selected_cipher_suite(m_selected_cipher_suite);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s: TLS/PEAP selected cipher_suite %s\n"),
			 (m_is_client == true ? "client": "server"),
			 eap_tls_trace_string_c::get_cipher_suite_string(m_selected_cipher_suite)));
	}


	m_selected_compression_method = handshake_message->get_selected_compression_method();

	status = check_selected_compression_method(m_selected_compression_method);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (handshake_message->get_session_id() == 0
		|| (handshake_message->get_session_id()->get_is_valid_data() == true
		&& handshake_message->get_session_id()->get_data_length() > TLS_SESSION_ID_SIZE))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}


#if defined(USE_EAP_TLS_SESSION_TICKET)
	m_will_receive_new_session_ticket = false;
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)


#if defined(USE_FAST_EAP_TYPE)
	if (m_eap_type == eap_type_fast
		&& m_tls_session_type == tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP
		&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: message_function: analyse_handshake_type_server_hello(): ")
			 EAPL("EAP-FAST server unauthenticated provisioning mode\n"),
			 (m_is_client == true ? "client": "server")));
	}
	else
#endif //#if defined(USE_FAST_EAP_TYPE)
	if (handshake_message->get_session_id()->get_is_valid_data() == true
		&& handshake_message->get_session_id()->get_data_length() > 0ul
#if defined(USE_FAST_EAP_TYPE)
		// EAP-FAST specification says to watch the next message to see whether the session is resumed or not.
		// Original TLS is specified to correctly so the client know what happens when it receives ServerHello message.
		&& (m_eap_type != eap_type_fast
			|| (m_tls_session_type == tls_session_type_original_session_resumption
				|| m_tls_session_type == tls_session_type_full_authentication))
#endif //#if defined(USE_FAST_EAP_TYPE)
		)
	{

#if defined(USE_EAP_TLS_SESSION_TICKET)

		if (m_tls_session_type == tls_session_type_stateless_session_resumption)
		{
			m_received_tls_extensions.reset();
			
			const tls_extension_c * const supported_session_ticket_extension = tls_extension_c::get_tls_extension(
				tls_extension_type_session_ticket,
				&m_supported_tls_extensions,
				m_am_tools);

			if (supported_session_ticket_extension != 0)
			{
				EAP_TEMPLATE_CONST eap_array_c<tls_extension_c> * const tls_extensions
					= handshake_message->get_tls_extensions();

				const tls_extension_c * const received_session_ticket_extension = tls_extension_c::get_tls_extension(
					tls_extension_type_session_ticket,
					tls_extensions,
					m_am_tools);

				if (received_session_ticket_extension != 0)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("TLS: %s: message_function: analyse_handshake_type_server_hello(): ")
						 EAPL("SST: receives stateless session ticket: length = %d\n"),
						 (m_is_client == true ? "client": "server"),
						 received_session_ticket_extension->get_data_length()));

					eap_array_c<tls_extension_c> tmp_extensions(m_am_tools);

					tls_extension_c * const received_session_ticket_extension_copy = received_session_ticket_extension->copy();

					if (received_session_ticket_extension_copy != 0)
					{
						status = tmp_extensions.add_object(received_session_ticket_extension_copy, true);

						status = copy<tls_extension_c>(
							&tmp_extensions,
							&m_received_tls_extensions,
							m_am_tools,
							false);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
						}

						m_will_receive_new_session_ticket = true;
					}
				}
			}
		}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)


#if defined(USE_EAP_TLS_SESSION_TICKET)
		if (m_tls_session_type == tls_session_type_stateless_session_resumption)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: message_function: analyse_handshake_type_server_hello(): ")
				 EAPL("restores stateless session\n"),
				 (m_is_client == true ? "client": "server")));

			status = m_session_id.set_copy_of_buffer(handshake_message->get_session_id());
			if (status != eap_status_ok
				|| m_session_id.get_data_length() > TLS_SESSION_ID_SIZE)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			status = indicate_state_to_lower_layer(
				tls_peap_state_stateless_session_resumption);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
		/** @{ PEAPv2 does not support session resumption yet. } */
		if (((m_eap_type == eap_type_peap
				&& m_peap_version != peap_version_2)
			|| m_eap_type == eap_type_tls
			|| m_eap_type == eap_type_ttls
#if defined(USE_FAST_EAP_TYPE)
			|| m_eap_type == eap_type_fast
#endif //#if defined(USE_FAST_EAP_TYPE)
			)
			&& m_tls_session_type == tls_session_type_original_session_resumption
			&& m_resumed_cipher_suite == m_selected_cipher_suite
			&& handshake_message->get_session_id()->compare(&m_session_id) == 0)
		{
			// OK, previous session will be restored.

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: message_function: analyse_handshake_type_server_hello(): ")
				 EAPL("restores session\n"),
				 (m_is_client == true ? "client": "server")));


			eap_status_e notification_status = indicate_state_to_lower_layer(
				tls_peap_state_original_session_resumption);
			if (notification_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, notification_status);
			}
		}
		else
		{

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
			if (m_is_client == true
				&& m_tls_use_identity_privacy == true
				&& m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_none)
			{
				set_tls_identity_privacy_handshake_state(tls_identity_privacy_handshake_state_negotiates);
			}
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

			set_tls_session_type(tls_session_type_full_authentication);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: message_function: analyse_handshake_type_server_hello(): ")
				 EAPL("creates new session\n"),
				 (m_is_client == true ? "client": "server")));

			status = m_session_id.set_copy_of_buffer(handshake_message->get_session_id());
			if (status != eap_status_ok
				|| m_session_id.get_data_length() > TLS_SESSION_ID_SIZE)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			status = indicate_state_to_lower_layer(
				tls_peap_state_full_authentication);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else
	{
		// No session identifier.
#if defined(USE_FAST_EAP_TYPE)
		if (m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption
			&& get_next_tls_handshake_message_type() == tls_handshake_type_none
			&& get_next_tls_record_message_protocol() == tls_record_protocol_change_cipher_spec)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: message_function: analyse_handshake_type_server_hello(): ")
				 EAPL("EAP-FAST PAC session resumtion.\n"),
				 (m_is_client == true ? "client": "server")));

			// Generates master secret from PAC-Key.
			status = generate_eap_fast_master_secret_from_pac_key(
				&m_eap_fast_pac_key);

			m_eap_fast_pac_key.reset();

			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
#endif //#if defined(USE_FAST_EAP_TYPE)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: message_function: analyse_handshake_type_server_hello(): ")
				 EAPL("creates new session, no session identifier\n"),
				 (m_is_client == true ? "client": "server")));

#if defined(USE_FAST_EAP_TYPE)
			if (m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption)
			{
				// Server does not accept the Tunnel PAC.
				// We will remove the Tunnel PAC if server authenticates OK.
				m_remove_tunnel_pac = true;
			}
#endif //#if defined(USE_FAST_EAP_TYPE)

			set_tls_session_type(tls_session_type_full_authentication);
		}

	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_tls_session_type == tls_session_type_original_session_resumption
#if defined(USE_EAP_TLS_SESSION_TICKET)
		|| m_tls_session_type == tls_session_type_stateless_session_resumption
#if defined(USE_FAST_EAP_TYPE)
		|| m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption
#endif //#if defined(USE_FAST_EAP_TYPE)
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
		)
	{
		if (m_tls_session_type == tls_session_type_original_session_resumption
#if defined(USE_FAST_EAP_TYPE)
			|| m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption
#endif //#if defined(USE_FAST_EAP_TYPE)
			)
		{
			// We must generate the key material.
			status = generate_key_material();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		set_state(tls_peap_state_wait_change_cipher_spec);
	}
#if defined(USE_FAST_EAP_TYPE)
	else if (m_eap_type == eap_type_fast
			&& m_tls_session_type == tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP
			&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true)
	{
		set_state(tls_peap_state_wait_handshake_type_server_key_exchange);
	}
#endif //#if defined(USE_FAST_EAP_TYPE)
	else
	{
		set_state(tls_peap_state_wait_handshake_type_certificate);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_handshake_type_certificate(
	EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_handshake_type_certificate()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_handshake_type_certificate()");

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                 | Certificate Chain Length                      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Certificate 1 Length                          |               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
	// |                                                               |
	// +                                                               +
	// |          Certificate 1                                        |
	// +                                                               +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// .                    ...                                        .
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Certificate n Length                          |               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
	// |                                                               |
	// +                                                               +
	// |          Certificate n                                        |
	// +                                                               +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	eap_status_e status = eap_status_not_supported;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain
		= handshake_message->get_certificate_chain();

	if (m_is_client == false
		&& certificate_chain->get_object_count() == 0ul
		&& m_tls_peap_server_authenticates_client_policy_flag == false)
	{
		// Server allows server only authentication, client is anonymous.

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: pki_function: analyse_handshake_type_certificate(): ")
			 EAPL("Server allows anonymous client.\n"),
			(m_is_client == true ? "client": "server")));

		m_tls_peap_server_authenticates_client_action = false;
	}
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	else if (m_is_client == false
		&& m_tls_use_identity_privacy == true
		&& m_tls_session_type == tls_session_type_full_authentication
		&& m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_none
		&& certificate_chain->get_object_count() == 0ul)
	{
		// Server allows TLS identity privacy, at this point client is anonymous.

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: pki_function: analyse_handshake_type_certificate(): ")
			 EAPL("Server allows TLS identity privacy.\n"),
			(m_is_client == true ? "client": "server")));

		set_tls_identity_privacy_handshake_state(tls_identity_privacy_handshake_state_negotiates);
	}
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	else if (certificate_chain->get_object_count() == 0ul)
	{
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
#if defined(USE_FAST_EAP_TYPE)
		if (m_is_client == false
			&& m_tls_use_identity_privacy == false
			&& m_eap_type == eap_type_fast
			&& m_tls_session_type == tls_session_type_full_authentication)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: pki_function: analyse_handshake_type_certificate(): ")
				 EAPL("EAP-FAST %s allows anonymous client.\n"),
				(m_is_client == true ? "client": "server"),
				(m_is_client == true ? "client": "server")));

			m_tls_peap_server_authenticates_client_action = false;
			m_tls_identity_privacy_handshake_state = tls_identity_privacy_handshake_state_none;
		}
		else
#endif //#if defined(USE_FAST_EAP_TYPE)
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: pki_function: analyse_handshake_type_certificate(): ")
				 EAPL("TLS %s does NOT allow anonymous %s.\n"),
				(m_is_client == true ? "client": "server"),
				(m_is_client == true ? "client": "server"),
				(m_is_client == false ? "client": "server")));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_insufficient_security);
		}
	}
	else
	{
		status = copy<eap_variable_data_c>(
			certificate_chain,
			&m_peer_certificate_chain,
			m_am_tools,
			false);
		if (status != eap_status_ok
			|| m_peer_certificate_chain.get_object_count() == 0ul)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_is_client == true)
	{
		status = completion_action_add(tls_completion_action_verify_certificate_chain);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: pki_function: query_certificate_chain()\n"),
			(m_is_client == true ? "client": "server")));

		status = m_am_tls_services->query_certificate_chain(
			&m_peer_certificate_authorities,
			&m_peer_certificate_types,
			m_selected_cipher_suite);
		if (status == eap_status_pending_request)
		{
			// This is pending query, that will be completed by
			// complete_query_certificate_chain() call.
			m_pending_query_certificate_chain = true;
		}
		else if (status == eap_status_completed_request)
		{
			// This is already completed by complete_query_certificate_chain() call.
		}
		else if (status == eap_status_ok)
		{
			// This is also an error case, because this call is always completed on success. 
			status = eap_status_process_general_error;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else // All other status values means error, because this
			// call is always completed on success.
		{
			// This is an error case.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
		}
	}
	else if (m_is_client == false
			 && m_tls_peap_server_authenticates_client_action == true)
	{
		// This is server.

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		if (m_tls_session_type == tls_session_type_full_authentication
			&& m_tls_use_identity_privacy == true
			&& certificate_chain->get_object_count() == 0ul)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: pki_function: TLS identity privacy does not verify client certificate yet.\n"),
				 (m_is_client == true ? "client": "server")));
			status = eap_status_ok;
		}
		else
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: pki_function: verify_certificate_chain()\n"),
				 (m_is_client == true ? "client": "server")));

			status = m_am_tls_services->verify_certificate_chain(
				&m_peer_certificate_chain,
				m_selected_cipher_suite);
			if (status == eap_status_pending_request)
			{
				// This is pending query, that will be completed by
				// complete_verify_certificate_chain() call.
				m_pending_verify_certificate_chain = true;
			}
			else if (status == eap_status_completed_request)
			{
				// This is already completed by complete_verify_certificate_chain() call.
			}
			else if (status == eap_status_ok)
			{
				// This is also an error case, because this call is always completed on success. 
				status = eap_status_process_general_error;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else // All other status values means error, because this
				// call is always completed on success.
			{
				// This is an error case.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
			}
		}
	}
	else if (m_is_client == false
			 && m_tls_peap_server_authenticates_client_action == false)
	{
		// This is server. Server allows anonymous client.
		status = eap_status_ok;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (status == eap_status_completed_request)
	{
		status = eap_status_ok;
	}

	if (m_is_client == true)
	{
		if (cipher_suite_is_TLS_DHE_DSS() == true
			|| cipher_suite_is_TLS_DHE_RSA() == true)
		{
			set_state(tls_peap_state_wait_handshake_type_server_key_exchange);
		}
		else if (cipher_suite_is_TLS_RSA() == true)
		{
			set_state(tls_peap_state_wait_handshake_type_certificate_request_or_server_hello_done);
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
		}
	}
	else
	{
		// Server.
		set_state(tls_peap_state_wait_handshake_type_client_key_exchange);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_handshake_type_certificate_request(
	EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_handshake_type_certificate_request()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_handshake_type_certificate_request()");

	EAP_ASSERT_ALWAYS(m_is_client == true);

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                 | CT length     | CT 1          | CT 2          |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | CT 3          | CT 4          | CAs length                    |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | CA 1 length                   |                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
	// |                                                               |
	// +                                                               +
	// |      Distinguished name of Certificate Authority 1            |
	// +                                                               +
	// |                                                               |
	// +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                               | CA 2 length                   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// +                                                               +
	// |      Distinguished name of Certificate Authority 2            |
	// +                                                               +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	eap_status_e status = eap_status_not_supported;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		EAP_TEMPLATE_CONST eap_array_c<u8_t> * const certificate_types
			= handshake_message->get_certificate_types();

		if (certificate_types->get_object_count() == 0ul)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = copy_simple<u8_t>(
			certificate_types,
			&m_peer_certificate_types,
			m_am_tools,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		{
			for (u32_t ind = 0ul; ind < m_peer_certificate_types.get_object_count(); ++ind)
			{
				const u8_t * const certificate_type = m_peer_certificate_types.get_object(ind);
				if (certificate_type != 0)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("peer certificate type %d=0x%02x\n"),
						*certificate_type,
						*certificate_type));
				}
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_authorities
			= handshake_message->get_certificate_authorities();

		if (certificate_authorities->get_object_count() == 0ul
			&& m_client_allows_empty_certificate_authorities_list == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = copy<eap_variable_data_c>(
			certificate_authorities,
			&m_peer_certificate_authorities,
			m_am_tools,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		{
			for (u32_t ind = 0ul; ind < m_peer_certificate_authorities.get_object_count(); ++ind)
			{
				const eap_variable_data_c * const ca_authority = m_peer_certificate_authorities.get_object(ind);
				if (ca_authority != 0)
				{
					EAP_TRACE_DATA_DEBUG(
						m_am_tools,
						EAP_TRACE_FLAGS_MESSAGE_DATA,
						(EAPL("peer CA-authority"),
						 ca_authority->get_data(),
						 ca_authority->get_data_length()));
				}
			}
		}
	}

	m_tls_peap_server_requested_client_certificate = true;


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_state(tls_peap_state_wait_handshake_type_server_hello_done);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_handshake_type_server_hello_done(
	EAP_TEMPLATE_CONST tls_handshake_message_c * const /*handshake_message*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_handshake_type_server_hello_done()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_handshake_type_server_hello_done()");

	EAP_ASSERT(m_is_client == true);

	eap_status_e status = eap_status_process_general_error;

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//
	// ServerHelloDone message does not include payload.

	if (cipher_suite_is_TLS_DHE_DSS() == true
		|| cipher_suite_is_TLS_RSA() == true
		|| cipher_suite_is_TLS_DHE_RSA() == true
#if defined(USE_FAST_EAP_TYPE)
		|| (m_eap_type == eap_type_fast
			&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
			&& cipher_suite_is_TLS_DH_anon() == true)
#endif //#if defined(USE_FAST_EAP_TYPE)
		)
	{
		if (m_tls_peap_server_requested_client_certificate == true)
		{
			status = completion_action_add(tls_completion_action_create_handshake_type_certificate);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		status = completion_action_add(
			tls_completion_action_create_handshake_type_client_key_exchange);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = completion_action_add(
			tls_completion_action_complete_create_handshake_type_client_key_exchange);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (m_tls_peap_server_authenticates_client_action == true
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
			&& (
				m_tls_use_identity_privacy == false
				|| (m_tls_session_type == tls_session_type_full_authentication
					&& m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_runs))
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
			)
		{
			status = completion_action_add(
				tls_completion_action_create_handshake_type_certificate_verify);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// This will complete creation of handshake_type_certificate_verify message.
			status = completion_action_add(
				tls_completion_action_complete_create_handshake_type_certificate_verify);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Also the other pending messages will be processed after this action is completed.
			eap_status_e compl_status = completion_action_add(
				tls_completion_action_process_tls_records);
			if (compl_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		status = completion_action_add(
			tls_completion_action_create_change_cipher_spec_type_change_cipher_spec);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = completion_action_add(tls_completion_action_create_handshake_type_finished);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_state(tls_peap_state_wait_change_cipher_spec);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_handshake_type_server_key_exchange(
	EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_handshake_type_server_key_exchange()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_handshake_type_server_key_exchange()");

	eap_status_e status = eap_status_not_supported;

#if EAP_TLS_UNSUPPORTED_CIPHER_SUITE
	#error This one needs more code. RSA key exchange with different parameters is NOT supported.
	if (cipher_suite_is_TLS_RSA() == true)
	{
		// RSA modulus and exponent are included when selected cipher suite
		// is using RSA key exchange
		// and parameters are different than included in the certificate.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | rsa_modulus length            |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |          rsa_modulus                                          |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  rsa_exponent length          |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                  rsa_exponent                                 +
		// |                                                               |
		// +                                                               +
		// |                                                               |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                                                               +
		// |       digitally-signed MD5 hash 16 bytes                      |
		// +    (ClientHello.random + ServerHello.random + ServerParams)   +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                                                               +
		// |       digitally-signed SHA-1 hash 20 bytes                    |
		// +    (ClientHello.random + ServerHello.random + ServerParams)   +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}
	else
#endif
	if (cipher_suite_is_TLS_DHE_DSS() == true
		|| cipher_suite_is_TLS_DHE_RSA() == true)
	{
		// Diffie-Hellman prime modulus, generator and server's
		// Diffie-Hellman public value (g^X mod p)
		// are included when selected cipher suite is ephemeral Diffie-Hellman key exchange.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | DH p length                   |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |                DH p value (prime modulus)                     |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH g length                  |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH g value (generator)                         |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH Ys length                 |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH Ys value                                    |
		// +         (server's Diffie-Hellman public value)                +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                                                               +
		// |       digitally-signed SHA-1 hash 47 bytes                    |
		// +    (ClientHello.random + ServerHello.random + ServerParams)   +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (handshake_message->get_dhe_prime() == 0
			|| handshake_message->get_dhe_prime()->get_is_valid_data() == false
			|| handshake_message->get_dhe_prime()->get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (handshake_message->get_dhe_group_generator() == 0
			|| handshake_message->get_dhe_group_generator()->get_is_valid_data() == false
			|| handshake_message->get_dhe_group_generator()->get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (handshake_message->get_public_dhe_key() == 0
			|| handshake_message->get_public_dhe_key()->get_is_valid_data() == false
			|| handshake_message->get_public_dhe_key()->get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (handshake_message->get_signed_message_hash() == 0
			|| handshake_message->get_signed_message_hash()->get_is_valid_data() == false
			|| handshake_message->get_signed_message_hash()->get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		status = m_dhe_prime.set_copy_of_buffer(handshake_message->get_dhe_prime());
		if (status != eap_status_ok
			|| m_dhe_prime.get_is_valid_data() == false
			|| m_dhe_prime.get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = m_dhe_group_generator.set_copy_of_buffer(
			handshake_message->get_dhe_group_generator());
		if (status != eap_status_ok
			|| m_dhe_group_generator.get_is_valid_data() == false
			|| m_dhe_group_generator.get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = m_peer_public_dhe_key.set_copy_of_buffer(handshake_message->get_public_dhe_key());
		if (status != eap_status_ok
			|| m_peer_public_dhe_key.get_is_valid_data() == false
			|| m_peer_public_dhe_key.get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		if (cipher_suite_is_TLS_DHE_DSS() == true
			|| cipher_suite_is_TLS_DHE_RSA() == true)
		{
			// We must verify the signature of ServerKeyExchange.
			status = verify_signature_of_server_key_exchange(
				handshake_message->get_signed_message_hash());
			if (status == eap_status_pending_request)
			{
				// This is pending query, that will be completed by
				// complete_query_certificate_chain() call.
				m_pending_verify_with_public_key = true;
			}
			else if (status == eap_status_completed_request)
			{
				// This is already completed by complete_query_certificate_chain() call.
			}
			else if (status == eap_status_ok)
			{
				// This is also an error case, because this call is always completed on success. 
				status = eap_status_process_general_error;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else // All other status values means error, because this call
				// is always completed on success.
			{
				// This is an error case.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
		}
	}
#if defined(USE_FAST_EAP_TYPE)
	else if (m_eap_type == eap_type_fast
		&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
		&& cipher_suite_is_TLS_DH_anon() == true)
	{
		// Diffie-Hellman prime modulus, generator and server's
		// Diffie-Hellman public value (g^X mod p)
		// are included when selected cipher suite is ephemeral Diffie-Hellman key exchange.
		// NOTE: Here are no signed hash. This is not authenticated at all and vulnerable to
		// man-in-the-middle attacks.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | DH p length                   |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |                DH p value (prime modulus)                     |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH g length                  |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH g value (generator)                         |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH Ys length                 |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH Ys value                                    |
		// +         (server's Diffie-Hellman public value)                +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: analyse_handshake_type_server_key_exchange() no m_signed_message_hash\n")));

		if (handshake_message->get_dhe_prime() == 0
			|| handshake_message->get_dhe_prime()->get_is_valid_data() == false
			|| handshake_message->get_dhe_prime()->get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (handshake_message->get_dhe_group_generator() == 0
			|| handshake_message->get_dhe_group_generator()->get_is_valid_data() == false
			|| handshake_message->get_dhe_group_generator()->get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		if (handshake_message->get_public_dhe_key() == 0
			|| handshake_message->get_public_dhe_key()->get_is_valid_data() == false
			|| handshake_message->get_public_dhe_key()->get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		status = m_dhe_prime.set_copy_of_buffer(handshake_message->get_dhe_prime());
		if (status != eap_status_ok
			|| m_dhe_prime.get_is_valid_data() == false
			|| m_dhe_prime.get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = m_dhe_group_generator.set_copy_of_buffer(
			handshake_message->get_dhe_group_generator());
		if (status != eap_status_ok
			|| m_dhe_group_generator.get_is_valid_data() == false
			|| m_dhe_group_generator.get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = m_peer_public_dhe_key.set_copy_of_buffer(handshake_message->get_public_dhe_key());
		if (status != eap_status_ok
			|| m_peer_public_dhe_key.get_is_valid_data() == false
			|| m_peer_public_dhe_key.get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}
#endif //#if defined(USE_FAST_EAP_TYPE)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (/* status == eap_status_pending_request
		   ||*/ status == eap_status_completed_request)
	{
		status = eap_status_ok;
	}

	// Next we wait certificate_request or server_hello_done
	// If next message is certificate_request, server requires client authentication.
	// If next message is server_hello_done, server does NOT require client authentication.
	set_state(tls_peap_state_wait_handshake_type_certificate_request_or_server_hello_done);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_handshake_type_client_key_exchange(
	EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_handshake_type_client_key_exchange()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_handshake_type_client_key_exchange()");

	eap_status_e status = eap_status_not_supported;


	if (cipher_suite_is_TLS_RSA() == true)
	{
		// Encrypted premaster secret is included when selected cipher suite
		// is using RSA key exchange.
		// First two bytes are version of TLS.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 |                                               |
		// +-+-+-+-+-+-+-+-+                                               +
		// |                                                               |
		// +                                                               +
		// |                Encrypted Premaster Secret (48 bytes)          |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (handshake_message->get_encrypted_premaster_secret() == 0
			|| handshake_message->get_encrypted_premaster_secret()->get_is_valid_data() == false
			|| handshake_message->get_encrypted_premaster_secret()->get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s:     pki_function: rsa_decrypt_with_private_key()\n"),
			(m_is_client == true ? "client": "server")));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: analyse_handshake_type_client_key_exchange(): encrypted premaster_secret"),
			 handshake_message->get_encrypted_premaster_secret()->get_data(),
			 handshake_message->get_encrypted_premaster_secret()->get_data_length()));

		status = m_am_tls_services->rsa_decrypt_with_private_key(
			handshake_message->get_encrypted_premaster_secret());
		if (status == eap_status_pending_request)
		{
			// This is pending query, that will be completed by
			// complete_rsa_decrypt_with_private_key() call.
			m_pending_rsa_decrypt_with_private_key = true;
		}
		else if (status == eap_status_completed_request)
		{
			// This is already completed by complete_rsa_decrypt_with_private_key() call.
		}
		else if (status == eap_status_ok)
		{
			// This is also an error case, because this call is always completed on success. 
			status = eap_status_process_general_error;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else // All other status values means error, because this call
			// is always completed on success.
		{
			// This is an error case.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
		}
	}
	else if (cipher_suite_is_TLS_DHE_DSS() == true
		|| cipher_suite_is_TLS_DHE_RSA() == true
#if defined(USE_FAST_EAP_TYPE)
		|| (m_eap_type == eap_type_fast
			&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
			&& cipher_suite_is_TLS_DH_anon() == true)
#endif //#if defined(USE_FAST_EAP_TYPE)
		)
	{
		// Diffie-Hellman prime modulus, generator and server's
		// Diffie-Hellman public value (g^X mod p)
		// are included when selected cipher suite is ephemeral Diffie-Hellman key exchange.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | DH p length                   |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |                DH p value (prime modulus)                     |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH g length                  |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH g value (generator)                         |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH Ys length                 |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH Ys value                                    |
		// +         (server's Diffie-Hellman public value)                +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (handshake_message->get_public_dhe_key() == 0
			|| handshake_message->get_public_dhe_key()->get_is_valid_data() == false
			|| handshake_message->get_public_dhe_key()->get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		status = m_peer_public_dhe_key.set_copy_of_buffer(handshake_message->get_public_dhe_key());
		if (status != eap_status_ok
			|| m_peer_public_dhe_key.get_is_valid_data() == false
			|| m_peer_public_dhe_key.get_data_length() == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}


		// We must generate premaster secret.
		status = generate_premaster_secret();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		// We must generate master secret.
		status = generate_master_secret();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// We must generate the key material.
		status = generate_key_material();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (/*status == eap_status_pending_request
		  ||*/ status == eap_status_completed_request)
	{
		status = eap_status_ok;
	}

	if (m_tls_peap_server_authenticates_client_action == true)
	{
		set_state(tls_peap_state_wait_handshake_type_certificate_verify);
	}
	else
	{
		set_state(tls_peap_state_wait_change_cipher_spec);
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_handshake_type_certificate_verify(
	EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_handshake_type_certificate_verify()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_handshake_type_certificate_verify()");

	eap_status_e status = eap_status_not_supported;

	if (cipher_suite_is_TLS_RSA() == true
		|| cipher_suite_is_TLS_DHE_RSA() == true
		|| cipher_suite_is_TLS_DHE_DSS() == true)
	{
		// Signatures when RSA is used:
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 |                                               |
		// +-+-+-+-+-+-+-+-+                                               +
		// |                                                               |
		// +                   Signed MD5 hash                             +
		// |                    (16 bytes)                                 |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                   Signed SHA hash                             +
		// |                    (20 bytes)                                 |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		// Signature when DSA is used:
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 |                                               |
		// +-+-+-+-+-+-+-+-+                                               +
		// |                                                               |
		// +                   Signed SHA hash                             +
		// |                    (48 bytes)                                 |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		eap_variable_data_c signed_certificate_verify_hash(m_am_tools);

		status = signed_certificate_verify_hash.set_copy_of_buffer(
			handshake_message->get_signed_message_hash());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (signed_certificate_verify_hash.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eap_variable_data_c message_hash(m_am_tools);

		status = message_hash_create(
			true,
			tls_handshake_type_certificate_verify,
			&message_hash,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s:     pki_function: analyse_handshake_type_certificate_verify()\n"),
			(m_is_client == true ? "client": "server")));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: analyse_handshake_type_certificate_verify(): message_hash"),
			message_hash.get_data(message_hash.get_data_length()),
			message_hash.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: analyse_handshake_type_certificate_verify(): signed_certificate_verify_hash"),
			signed_certificate_verify_hash.get_data(
				signed_certificate_verify_hash.get_data_length()),
			signed_certificate_verify_hash.get_data_length()));

		status = m_am_tls_services->verify_with_public_key(
			&message_hash,
			&signed_certificate_verify_hash);
		if (status == eap_status_pending_request)
		{
			// This is pending query, that will be completed by
			// complete_query_certificate_chain() call.
			m_pending_verify_with_public_key = true;
		}
		else if (status == eap_status_completed_request)
		{
			// This is already completed by complete_query_certificate_chain() call.
			status = eap_status_ok;
		}
		else if (status == eap_status_ok)
		{
			// This is also an error case, because this call is always completed on success. 
			status = eap_status_process_general_error;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else // All other status values means error, because this call
			// is always completed on success.
		{
			// This is an error case.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_state(tls_peap_state_wait_change_cipher_spec);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_handshake_type_finished(
	EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_handshake_type_finished()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_handshake_type_finished()");

	eap_status_e status = eap_status_not_supported;


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (handshake_message->get_finished_data() == 0
		|| handshake_message->get_finished_data()->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_variable_data_c message_hash(m_am_tools);

	bool client_originated_message = true;
	if (m_is_client == true)
	{
		client_originated_message = false;
	}

	status = message_hash_create_finished(client_originated_message, &message_hash);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (message_hash.compare(handshake_message->get_finished_data()) != 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: TLS: %s: analyse_handshake_type_finished(): ")
			 EAPL("verify check finished data failed, m_tls_session_type=%d=%s.\n"),
			 (m_is_client == true ? "client": "server"),
			 m_tls_session_type,
			 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type)
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}
	else
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: message_function: analyse_handshake_type_finished(): ")
			 EAPL("verify check finished data OK, m_tls_session_type=%d=%s.\n"),
			 (m_is_client == true ? "client": "server"),
			 m_tls_session_type,
			 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if ((m_is_client == false
		 && m_tls_session_type == tls_session_type_full_authentication)
		|| (m_is_client == true
			&& (m_tls_session_type == tls_session_type_original_session_resumption
				|| m_tls_session_type == tls_session_type_stateless_session_resumption
#if defined(USE_FAST_EAP_TYPE)
				|| m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption
#endif //#if defined(USE_FAST_EAP_TYPE)
				)
			)
		)
	{
		// We need to send ChangeCipherSpec and Handshake/Finished.

#if defined(USE_EAP_TLS_SESSION_TICKET)
		if (
			m_is_client == false
#if defined(USE_FAST_EAP_TYPE)
			&& m_eap_type != eap_type_fast
#endif //#if defined(USE_FAST_EAP_TYPE)
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
			&& (m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_none
					|| m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_runs)
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
			&& m_tls_session_type == tls_session_type_full_authentication
			&& tls_extension_c::get_tls_extension(
						tls_extension_type_session_ticket,
						&m_supported_tls_extensions,
						m_am_tools) != 0)
		{
			{
				const tls_extension_c * const supported_session_ticket_extension = tls_extension_c::get_tls_extension(
						tls_extension_type_session_ticket,
						&m_supported_tls_extensions,
						m_am_tools);
				EAP_UNREFERENCED_PARAMETER(supported_session_ticket_extension);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: %s: message_function: analyse_handshake_type_finished(): ")
					 EAPL("SST: Server will send a new session ticket to client, length = %d.\n"),
					 (m_is_client == true ? "client": "server"),
					 supported_session_ticket_extension->get_data_length()));
			}

			// Server will send a new session ticket to client.
			status = completion_action_add(
				tls_completion_action_create_handshake_type_new_session_ticket);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

		status = completion_action_add(
			tls_completion_action_create_change_cipher_spec_type_change_cipher_spec);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = completion_action_add(tls_completion_action_create_handshake_type_finished);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		if (m_is_client == false
			&& m_tls_session_type == tls_session_type_full_authentication
			&& m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_negotiates)
		{
			status = completion_action_add(tls_completion_action_create_handshake_type_hello_request);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

		status = completion_action_add(tls_completion_action_check_sent_tls_message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#if defined(USE_FAST_EAP_TYPE)
	else if (m_is_client == false
				&& m_eap_type == eap_type_fast
				&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
				&& cipher_suite_is_TLS_DH_anon() == true)
	{
		status = completion_action_add(
			tls_completion_action_create_change_cipher_spec_type_change_cipher_spec);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = completion_action_add(tls_completion_action_create_handshake_type_finished);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = completion_action_add(tls_completion_action_check_sent_tls_message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#endif //#if defined(USE_FAST_EAP_TYPE)


#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	if (m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_none
			|| m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_runs
			|| m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_negotiates
		)
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	{
		// Authentication OK.
		status = completion_action_add(tls_completion_action_finish_handshake);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = completion_action_add(tls_completion_action_process_tls_records);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

#if defined(USE_FAST_EAP_TYPE)
		if (m_is_client == false
			&& m_eap_type == eap_type_fast
			&& m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption)
		{
			status = completion_action_add(tls_completion_action_check_tunnel_authentication_runs);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
#endif //#if defined(USE_FAST_EAP_TYPE)
	}

	m_received_eap_identifier = received_eap_identifier;


	set_state(tls_peap_state_process_pending_tls_completions);

	if (status == eap_status_ok)
	{
		status = check_sent_tls_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TLS_SESSION_TICKET)

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_handshake_type_new_session_ticket(
	EAP_TEMPLATE_CONST tls_handshake_message_c * const handshake_message,
	const u8_t /* received_eap_identifier */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_handshake_type_new_session_ticket()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_handshake_type_new_session_ticket()");

	eap_status_e status = eap_status_not_supported;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TEMPLATE_CONST eap_array_c<tls_extension_c> * const tls_extensions
		= handshake_message->get_tls_extensions();

	if (tls_extensions == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	const tls_extension_c * const session_ticket = tls_extension_c::get_tls_extension(
			tls_extension_type_session_ticket,
			tls_extensions,
			m_am_tools);

	if (session_ticket == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	m_received_tls_extensions.reset();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: analyse_handshake_type_new_session_ticket(): ")
		 EAPL("SST: session ticket received, length = %d.\n"),
		 (m_is_client == true ? "client": "server"),
		 session_ticket->get_data_length()));

	tls_extension_c * const copy_of_session_ticket = session_ticket->copy();

	if (copy_of_session_ticket == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = m_received_tls_extensions.add_object(copy_of_session_ticket, true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_tls_protocol_change_cipher_spec(
	const tls_record_message_c * const record)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_tls_protocol_change_cipher_spec()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_tls_protocol_change_cipher_spec()");

	eap_status_e status = eap_status_not_supported;

	u32_t ind_change_cipher_spec = 0ul;

	for (ind_change_cipher_spec = 0ul
			 ; ind_change_cipher_spec < record->get_change_cipher_spec_count()
			 ; ind_change_cipher_spec++)
	{
		const tls_change_cipher_spec_message_c * const change_cipher_spec_message
			= record->get_change_cipher_spec(ind_change_cipher_spec);

		switch (change_cipher_spec_message->get_change_cipher_spec_type())
		{
		case tls_change_cipher_spec_type_change_cipher_spec:

			if (m_tls_session_type == tls_session_type_stateless_session_resumption
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
				|| (m_tls_session_type == tls_session_type_full_authentication
					&& m_tls_use_identity_privacy == true
					&& m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_runs)
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
					)
			{
				// We must generate the key material.
				status = generate_key_material();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			// We change the receive cipher suite.
			status = change_cipher_spec(false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else
			{
				set_state(tls_peap_state_wait_handshake_type_finished);
			}

			break;

		default:

			set_state(tls_peap_state_failure);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
		} // switch()

	} // for()


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_tls_protocol_alert(
	const tls_record_message_c * const record)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_tls_protocol_alert()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_tls_protocol_alert()");

	eap_status_e status = eap_status_authentication_failure;

	u32_t ind_alert = 0ul;

	m_new_tls_message.reset();


	for (ind_alert = 0ul
			 ; ind_alert < record->get_alert_count()
			 ; ind_alert++)
	{
		const tls_alert_message_c * const alert_message
			= record->get_alert(ind_alert);

		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: %s: EAP_type_TLS_PEAP: Alert message %s:%s\n"),
			(m_is_client == true) ? "client": "server",
			eap_tls_trace_string_c::get_alert_level_string(alert_message->get_alert_level()),
			eap_tls_trace_string_c::get_alert_description_string(alert_message->get_alert_description())));

		if (m_application != 0)
		{
			// Indication to TLS-application.
			(void) m_application->alert_received(
				alert_message->get_alert_level(),
				alert_message->get_alert_description());
		}

		// indication to TLS AM.
		m_am_tls_services->alert_received(
			alert_message->get_alert_level(),
			alert_message->get_alert_description());

		switch (alert_message->get_alert_description())
		{
		case tls_alert_description_close_notify:
			break;
		case tls_alert_description_unexpected_message:
			// This message is always fatal.
			break;
		case tls_alert_description_bad_record_mac:
			// This message is always fatal.
			break;
		case tls_alert_description_decryption_failed:
			// This message is always fatal.
			break;
		case tls_alert_description_record_overflow:
			// This message is always fatal.
			break;
		case tls_alert_description_decompression_failure:
			// This message is always fatal.
			break;
		case tls_alert_description_handshake_failure:
			// This message is always fatal.
			break;
		case tls_alert_description_bad_certificate:
			break;
		case tls_alert_description_unsupported_certificate:
			break;
		case tls_alert_description_certificate_revoked:
			break;
		case tls_alert_description_certificate_expired:
			break;
		case tls_alert_description_certificate_unknown:
			break;
		case tls_alert_description_illegal_parameter:
			// This message is always fatal.
			break;
		case tls_alert_description_unknown_ca:
			// This message is always fatal.
			break;
		case tls_alert_description_access_denied:
			// This message is always fatal.
			break;
		case tls_alert_description_decode_error:
			// This message is always fatal.
			break;
		case tls_alert_description_decrypt_error:
			break;
		case tls_alert_description_export_restriction:
			// This message is always fatal.
			break;
		case tls_alert_description_protocol_version:
			// This message is always fatal.
			break;
		case tls_alert_description_insufficient_security:
			// This message is always fatal.
			break;
		case tls_alert_description_internal_error:
			// This message is always fatal.
			break;
		case tls_alert_description_user_canceled:
			break;
		case tls_alert_description_no_renegotiation:
			// This message is always a warning.
			break;
		case tls_alert_description_none:
			break;
		default:
			break;
		} // switch()

	} // for()


	set_state(tls_peap_state_failure);

	// This will cause the session terminate immediately.
	status = get_type_partner()->set_session_timeout(0ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	{
		eap_state_notification_c notification(
			m_am_tools,
			&m_send_network_id,
			m_is_client,
			eap_state_notification_generic,
			eap_protocol_layer_internal_type,
			0,
			tls_peap_state_none,
			eap_state_authentication_terminated_unsuccessfully,
			0,
			false);

		notification.set_authentication_error(eap_status_authentication_failure);

		get_type_partner()->state_notification(&notification);
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_record_protocol_e tls_record_c::get_next_tls_record_message_protocol()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::get_next_tls_record_message_protocol()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::get_next_tls_record_message_protocol()");

	tls_record_protocol_e record_protocol(tls_record_protocol_none);

	if (m_received_tls_message.get_record_message_count() <= m_received_tls_message.get_analyse_index()+1ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return record_protocol;
	}

	tls_record_message_c * const tls_record_message
		= m_received_tls_message.get_record_message(m_received_tls_message.get_analyse_index()+1ul);
	if (tls_record_message == 0
		|| tls_record_message->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return record_protocol;
	}

	const u32_t tls_record_length = tls_record_message->get_record_message_data()->get_data_length();

	if (tls_record_message->get_record_message_data()->get_data_length() < tls_record_header_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return record_protocol;
	}

	tls_record_header_c tls_record_header(
		m_am_tools,
		tls_record_message->get_record_message_data()->get_data(
			tls_record_header_c::get_header_length()),
		tls_record_length);

	if (tls_record_header.get_is_valid() == false
		|| tls_record_length < tls_record_header.get_data_length()
		|| tls_record_length
		< tls_record_header.get_header_length()
		+ tls_record_header.get_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return record_protocol;
	}

	record_protocol = tls_record_header.get_protocol();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: ends: tls_record_c::get_next_tls_record_message_protocol(): %d=%s\n"),
		(m_is_client == true ? "client": "server"),
		record_protocol,
		tls_record_header_c::get_tls_protocol_string(record_protocol)));
	

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return record_protocol;
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_handshake_type_e tls_record_c::get_next_tls_handshake_message_type()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::get_next_tls_handshake_message_type()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::get_next_tls_handshake_message_type()");

	tls_handshake_type_e handshake_type(tls_handshake_type_none);

	if (m_received_tls_message.get_record_message_count() <= m_received_tls_message.get_analyse_index())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return handshake_type;
	}

	tls_record_message_c * const tls_record_message
		= m_received_tls_message.get_record_message(m_received_tls_message.get_analyse_index());
	if (tls_record_message == 0
		|| tls_record_message->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return handshake_type;
	}

	const u32_t tls_record_length = tls_record_message->get_record_message_data()->get_data_length();

	if (tls_record_message->get_record_message_data()->get_data_length() < tls_record_header_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return handshake_type;
	}

	tls_record_header_c tls_record_header(
		m_am_tools,
		tls_record_message->get_record_message_data()->get_data(
			tls_record_header_c::get_header_length()),
		tls_record_length);

	if (tls_record_header.get_is_valid() == false
		|| tls_record_length < tls_record_header.get_data_length()
		|| tls_record_length
		< tls_record_header.get_header_length()
		+ tls_record_header.get_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return handshake_type;
	}

	tls_record_protocol_e tls_protocol(tls_record_header.get_protocol());

	if (tls_protocol == tls_record_protocol_handshake)
	{
		if (tls_record_message->get_handshake_count() <= tls_record_message->get_analyse_index()+1ul)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return handshake_type;
		}

		tls_handshake_message_c * const handshake_message = tls_record_message->get_handshake(tls_record_message->get_analyse_index()+1ul);

		if (handshake_message == 0
			|| handshake_message->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return handshake_type;
		}

		handshake_type = handshake_message->get_handshake_type();

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: message_function: ends: tls_record_c::get_next_tls_handshake_message_type(): %d=%s\n"),
			(m_is_client == true ? "client": "server"),
			handshake_type,
			tls_handshake_header_c::get_tls_handshake_string(handshake_type)));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return handshake_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_tls_protocol_handshake(
	tls_record_message_c * const record,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_tls_protocol_handshake()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_tls_protocol_handshake()");

	eap_status_e status = eap_status_ok;

	u32_t ind_handshake = 0ul;

	for (ind_handshake = record->get_analyse_index()
			 ; ind_handshake < record->get_handshake_count()
			 ; ind_handshake++)
	{
		// This is used in EAP-FAST to see the next TLS-handshake message type.
		record->save_analyse_index(ind_handshake);

		tls_handshake_message_c * const handshake_message = record->get_handshake(ind_handshake);

		if (handshake_message->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: message_function: analyse_tls_protocol_handshake(): ")
			 EAPL("handshake type %d, analysed %d\n"),
			 (m_is_client == true ? "client": "server"),
				handshake_message->get_handshake_type(),
				handshake_message->get_is_analysed()));

		if (handshake_message->get_is_analysed() == false)
		{
			handshake_message->set_is_analysed();

			switch (handshake_message->get_handshake_type())
			{
			case tls_handshake_type_hello_request:
				status = analyse_handshake_type_hello_request(
					handshake_message);
				break;
			case tls_handshake_type_client_hello:
				if (m_tls_peap_test_version == true
					&& verify_state(tls_peap_state_tls_success) == true)
				{
					// OK, this is test version.
				}
				else if (verify_state(tls_peap_state_wait_handshake_type_client_hello) == false)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: TLS: %s: function: verify_state(): current state %s != %s\n"),
						 (m_is_client == true ? "client": "server"),
						 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
						 eap_tls_trace_string_c::get_state_string(
							 tls_peap_state_wait_handshake_type_client_hello)));
					return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
				}

				status = analyse_handshake_type_client_hello(
					handshake_message);
				break;
			case tls_handshake_type_server_hello:
				if (verify_state(tls_peap_state_wait_handshake_type_server_hello) == false)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: TLS: %s: function: verify_state(): current state %s != %s\n"),
						 (m_is_client == true ? "client": "server"),
						 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
						 eap_tls_trace_string_c::get_state_string(
							 tls_peap_state_wait_handshake_type_server_hello)));
					return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
				}

				status = analyse_handshake_type_server_hello(
					handshake_message);
				break;
			case tls_handshake_type_certificate:
				if (m_tls_session_type == tls_session_type_stateless_session_resumption
					&& verify_state(tls_peap_state_wait_change_cipher_spec) == true)
				{
					// Server wish to initiate a full handshake.
					m_tls_session_type = tls_session_type_full_authentication;
					set_state(tls_peap_state_wait_handshake_type_certificate);
				}
				else if (verify_state(tls_peap_state_wait_handshake_type_certificate) == false)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: TLS: %s: function: verify_state(): current state %s != %s\n"),
						 (m_is_client == true ? "client": "server"),
						 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
						 eap_tls_trace_string_c::get_state_string(
							 tls_peap_state_wait_handshake_type_certificate)));
					return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
				}

				status = analyse_handshake_type_certificate(
					handshake_message);
				break;
			case tls_handshake_type_server_key_exchange:
				if (verify_state(tls_peap_state_wait_handshake_type_server_key_exchange) == false)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: TLS: %s: function: verify_state(): current state %s != %s\n"),
						 (m_is_client == true ? "client": "server"),
						 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
						 eap_tls_trace_string_c::get_state_string(
							 tls_peap_state_wait_handshake_type_server_key_exchange)));
					return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
				}

				status = analyse_handshake_type_server_key_exchange(
					handshake_message);
				break;
			case tls_handshake_type_certificate_request:
				if (verify_state(
						tls_peap_state_wait_handshake_type_certificate_request_or_server_hello_done)
					== false)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: TLS: %s: function: verify_state(): current state %s != %s\n"),
						 (m_is_client == true ? "client": "server"),
						 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
						 eap_tls_trace_string_c::get_state_string(
							 tls_peap_state_wait_handshake_type_certificate_request_or_server_hello_done)));
					return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
				}

				status = analyse_handshake_type_certificate_request(
					handshake_message);
				break;
			case tls_handshake_type_server_hello_done:

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: %s: message_function: analyse_tls_protocol_handshake(): m_tls_peap_server_authenticates_client_policy_flag=%d\n"),
					 (m_is_client == true ? "client": "server"),
					 m_tls_peap_server_authenticates_client_policy_flag));

				if (verify_state(
						tls_peap_state_wait_handshake_type_certificate_request_or_server_hello_done)
					== true)
				{
					if (m_tls_peap_server_authenticates_client_policy_flag == false)
					{
						// Client accepts server only authentication.
						m_tls_peap_server_authenticates_client_action = false;
					}
					else
					{
						// ERROR: Client does NOT accept server only authentication.
						EAP_TRACE_ERROR(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: TLS: %s: function: current state %s: ")
							 EAPL("Client does NOT accept server only authentication.\n"),
							 (m_is_client == true ? "client": "server"),
							 eap_tls_trace_string_c::get_state_string(m_tls_peap_state)));
						return EAP_STATUS_RETURN(m_am_tools, eap_status_insufficient_security);
					}
				}
				else if (verify_state(tls_peap_state_wait_handshake_type_server_hello_done)
						 == false)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: TLS: %s: function: verify_state(): current state %s != %s\n"),
						 (m_is_client == true ? "client": "server"),
						 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
						 eap_tls_trace_string_c::get_state_string(
							 tls_peap_state_wait_handshake_type_server_hello_done)));
					return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
				}

				status = analyse_handshake_type_server_hello_done(
					handshake_message);
				break;
			case tls_handshake_type_certificate_verify:
				if (verify_state(tls_peap_state_wait_handshake_type_certificate_verify) == false)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: TLS: %s: function: verify_state(): current state %s != %s\n"),
						 (m_is_client == true ? "client": "server"),
						 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
						 eap_tls_trace_string_c::get_state_string(
							 tls_peap_state_wait_handshake_type_certificate_verify)));
					return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
				}

				status = analyse_handshake_type_certificate_verify(
					handshake_message);
				break;
			case tls_handshake_type_client_key_exchange:
				if (verify_state(tls_peap_state_wait_handshake_type_client_key_exchange) == false)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: TLS: %s: function: verify_state(): current state %s != %s\n"),
						 (m_is_client == true ? "client": "server"),
						 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
						 eap_tls_trace_string_c::get_state_string(
							 tls_peap_state_wait_handshake_type_client_key_exchange)));
					return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
				}

				status = analyse_handshake_type_client_key_exchange(
					handshake_message);
				break;
			case tls_handshake_type_finished:
				if (verify_state(tls_peap_state_wait_handshake_type_finished) == false)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: TLS: %s: function: verify_state(): current state %s != %s\n"),
						 (m_is_client == true ? "client": "server"),
						 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
						 eap_tls_trace_string_c::get_state_string(
							 tls_peap_state_wait_handshake_type_finished)));
					return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
				}

				status = analyse_handshake_type_finished(
					handshake_message,
					received_eap_identifier);
				break;
#if defined(USE_EAP_TLS_SESSION_TICKET)
			case tls_handshake_type_new_session_ticket:
			{
				// Note This is optional Handshake message.

				const tls_extension_c * const supported_session_ticket_extension = tls_extension_c::get_tls_extension(
					tls_extension_type_session_ticket,
					&m_supported_tls_extensions,
					m_am_tools);

				if (supported_session_ticket_extension != 0
				&& (verify_state(tls_peap_state_wait_change_cipher_spec) == true
					|| verify_state(tls_peap_state_wait_handshake_type_new_session_ticket) == true))
				{
					// OK new Session ticket handshake allowed.
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("TLS: %s: function: verify_state(): SST: current state %s == %s: Session Ticket Handshake allowed, length = %d.\n"),
						 (m_is_client == true ? "client": "server"),
						 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
						 eap_tls_trace_string_c::get_state_string(
							 tls_peap_state_wait_handshake_type_new_session_ticket),
						 supported_session_ticket_extension->get_data_length()));
				}
				else if (verify_state(tls_peap_state_wait_handshake_type_new_session_ticket) == false)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: TLS: %s: function: verify_state(): SST: current state %s != %s\n"),
						 (m_is_client == true ? "client": "server"),
						 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
						 eap_tls_trace_string_c::get_state_string(
							 tls_peap_state_wait_handshake_type_new_session_ticket)));
					return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
				}

				status = analyse_handshake_type_new_session_ticket(
					handshake_message,
					received_eap_identifier);
				break;
			}
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
			default:
				return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
			} // switch()
		}

		if (status == eap_status_pending_request)
		{
			// Save pending state.
			record->save_analyse_index(ind_handshake);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if ((get_is_tunneled_tls() == false
				&& m_tls_peap_state == tls_peap_state_tls_success)
			|| (get_is_tunneled_tls() == true
				&& m_tls_peap_state == tls_peap_state_peap_tunnel_ready))
		{
			// Stop processing TLS-records.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	} // for()


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::analyse_tls_protocol_application_data(
	const tls_record_message_c * const record,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_tls_protocol_application_data()\n"),
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::analyse_tls_protocol_application_data()");

	eap_status_e status = eap_status_ok;

	u32_t ind;
	for (ind = 0ul
			; ind < record->get_application_data_count()
			; ind++)
	{
		tls_application_data_message_c * const application_data_message
			= record->get_application_data(ind);
		if (application_data_message == 0
			|| application_data_message->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (application_data_message->get_is_analysed() == false)
		{
			application_data_message->set_is_analysed();

			if (m_application == 0)
			{
				// ERROR: No application.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: TLS: %s: message_function: starts: tls_record_c::analyse_tls_protocol_application_data(): no application.\n"),
					 (m_is_client == true ? "client": "server")));
				status = eap_status_illegal_data_payload;
			}
			else
			{
				status = m_application->packet_process(
					application_data_message->get_application_data(),
					received_eap_identifier);
			}

			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: message_function: starts: tls_record_c::analyse_tls_protocol_application_data(): already analysed.\n"),
				 (m_is_client == true ? "client": "server")));
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::are_pending_queries_completed()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_pending_request;

	eap_status_string_c status_string;
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: pending_function: starts: tls_record_c::are_pending_queries_completed(): %s\n"),
		(m_is_client == true ? "client": "server"),
		status_string.get_status_string(status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::are_pending_queries_completed()");

	if (m_pending_query_certificate_authorities_and_types == false
		&& m_pending_query_certificate_chain == false
		&& m_pending_query_cipher_suites_and_previous_session == false
		&& m_pending_query_dh_parameters == false
		&& m_pending_query_realm == false
		&& m_pending_select_cipher_suite_and_check_session_id == false
		&& m_pending_verify_certificate_chain == false
		&& m_pending_rsa_decrypt_with_private_key == false
		&& m_pending_rsa_encrypt_with_public_key == false
		&& m_pending_sign_with_private_key == false
		&& m_pending_verify_with_public_key == false
		&& m_pending_query_tunnel_PAC == false)
	{
		status = eap_status_ok;
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: pending_function: are_pending_queries_completed(): %s\n"),
		(m_is_client == true ? "client": "server"),
		status_string.get_status_string(status)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::indicate_state_to_lower_layer(
	const tls_peap_state_e indicated_state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Notify lower layer the state of TLS.

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: state_function: starts: tls_record_c::indicate_state_to_lower_layer(): m_tls_session_type=%d=%s, state=%d=%s\n"),
		(m_is_client == true ? "client": "server"),
		m_tls_session_type,
		eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
		indicated_state,
		eap_tls_trace_string_c::get_state_string(indicated_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::indicate_state_to_lower_layer()");


#if defined(USE_EAP_TRACE_ALWAYS)

	if (m_tls_peap_state == tls_peap_state_tls_success)
	{

		tls_identity_privacy_handshake_state_e tmp_identity_privacy_handshake_state = 
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
			m_tls_identity_privacy_handshake_state;
#else
			tls_identity_privacy_handshake_state_none;
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s: indicate_state_to_lower_layer(): TLS/PEAP authentication ")
			 EAPL("SUCCESS: %s, %s, tunnel %d, tunneling type %s, tunneling version %s, cipher_suite %s, %s\n"),
			 (m_is_client == true ? "client": "server"),
			 (m_tls_peap_server_authenticates_client_action == true
			  ? "mutual": "anonymous client"),
			 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
			 get_is_tunneled_tls(),
			 eap_header_string_c::get_eap_type_string(m_eap_type),
			 eap_tls_trace_string_c::get_peap_version_string(m_peap_version),
			 eap_tls_trace_string_c::get_cipher_suite_string(m_selected_cipher_suite),
			 eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(tmp_identity_privacy_handshake_state)));
	}
	else if (m_tls_peap_state == tls_peap_state_peap_tunnel_ready
		|| m_tls_peap_state == tls_peap_state_wait_application_data)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s: indicate_state_to_lower_layer(): TLS/PEAP authentication ")
			 EAPL("tunnel ready: %s, %s, tunnel %d, tunneling type %s, tunneling version %s, cipher_suite %s\n"),
			 (m_is_client == true ? "client": "server"),
			 (m_tls_peap_server_authenticates_client_action == true
			  ? "mutual": "anonymous client"),
			 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
			 get_is_tunneled_tls(),
			 eap_header_string_c::get_eap_type_string(m_eap_type),
			 eap_tls_trace_string_c::get_peap_version_string(m_peap_version),
			 eap_tls_trace_string_c::get_cipher_suite_string(m_selected_cipher_suite)));

	}
	else if (m_tls_peap_state == tls_peap_state_failure)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s: indicate_state_to_lower_layer(): TLS/PEAP authentication ")
			 EAPL("FAILED: %s, %s, tunnel %d, tunneling type %s, tunneling version %s, cipher_suite %s\n"),
			 (m_is_client == true ? "client": "server"),
			 (m_tls_peap_server_authenticates_client_action == true ? "mutual": "anonymous client"),
			 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
			 get_is_tunneled_tls(),
			 eap_header_string_c::get_eap_type_string(m_eap_type),
			 eap_tls_trace_string_c::get_peap_version_string(m_peap_version),
			 eap_tls_trace_string_c::get_cipher_suite_string(m_selected_cipher_suite)));
	}

#endif //#if !defined(USE_EAP_TRACE_ALWAYS)

	
	eap_state_notification_c notification(
		m_am_tools,
		&m_send_network_id,
		m_is_client,
		eap_state_notification_generic,
		eap_protocol_layer_internal_type,
		0,
		tls_peap_state_none,
		indicated_state,
		0,
		false);
	get_type_partner()->state_notification(&notification);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::indicate_messages_processed()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Notify lower layer that TLS-messages are processed.

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: state_function: starts: tls_record_c::indicate_messages_processed(): %s\n"),
		(m_is_client == true ? "client": "server"),
		eap_tls_trace_string_c::get_state_string(m_tls_peap_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::indicate_messages_processed()");

	eap_state_notification_c notification(
		m_am_tools,
		&m_send_network_id,
		m_is_client,
		eap_state_notification_generic,
		eap_protocol_layer_internal_type,
		0,
		tls_peap_state_none,
		tls_peap_state_pending_tls_messages_processed,
		0,
		false);
	get_type_partner()->state_notification(&notification);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::send_tls_message()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: send_function: starts: tls_record_c::send_tls_message()\n"),
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::send_tls_message()");

	eap_variable_data_c tls_message_buffer(m_am_tools);

	bool includes_tls_handshake_message = false;

	eap_status_e status = m_new_tls_message.add_message_data(
		&tls_message_buffer,
		&includes_tls_handshake_message);
	if (status != eap_status_ok)
	{
		m_new_tls_message.reset();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	eap_buf_chain_wr_c sent_packet(
		eap_write_buffer,
		m_am_tools,
		tls_message_buffer.get_data(tls_message_buffer.get_data_length()),
		tls_message_buffer.get_data_length(),
		false,
		false,
		0ul);
	if (sent_packet.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("send TLS-message"),
		 sent_packet.get_data(sent_packet.get_data_length()),
		 sent_packet.get_data_length()));
	
	status = get_type_partner()->tls_peap_packet_send(
		&sent_packet,
		0ul,
		sent_packet.get_data_length(),
		sent_packet.get_data_length(),
		includes_tls_handshake_message
		);

	m_new_tls_message.reset();
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::check_sent_tls_message()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: send_function: starts: tls_record_c::check_sent_tls_message()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::check_sent_tls_message()");

	eap_status_e msg_status = eap_status_authentication_failure;

	if (m_already_in_completion_action_check == true)
	{
		// This is recursive call. Do not process yet.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	if (m_force_tls_message_send == true)
	{
		// There may be an alert message pending.
		msg_status = send_tls_message();
	}
	else
	{
		msg_status = are_pending_queries_completed();
		if (msg_status == eap_status_ok)
		{
			eap_status_e compl_status = completion_action_check();

			if (compl_status == eap_status_pending_request)
			{
				// Some asyncronous query is still pending.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, compl_status);
			}
			else if (compl_status != eap_status_ok)
			{
				// There may be Alert message to be sent.
				msg_status = compl_status;
			}


			if (m_allow_message_send == true)
			{
				if (msg_status == eap_status_ok
					&& m_new_tls_message.get_record_message_count() > 0ul)
				{
					// We could send the pending TLS-messages.
					msg_status = send_tls_message();
				}
				else if (m_force_tls_message_send == true // There may be Alert message to be sent.
					&& m_new_tls_message.get_record_message_count() > 0ul)
				{
					// We could send the pending TLS-messages.
					send_tls_message();
				}
				else
				{
					// No message to sent.
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("TLS: %s: send_function: check_sent_tls_message(), ")
						 EAPL("No message to sent.\n"),
						(m_is_client == true ? "client": "server")));
				}
			}

			if (msg_status == eap_status_ok
				&& m_allow_message_send == true)
			{
				eap_status_e indication_status = indicate_messages_processed();
				if (indication_status != eap_status_ok)
				{
					// This is an error case.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, indication_status);
				}
			}
		}
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, msg_status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::message_hash_init()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:    hash_function: starts: tls_record_c::message_hash_init()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::message_hash_init()");

	eap_status_e status = eap_status_not_supported;

	status = m_message_hash_md5.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_message_hash_sha1.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::message_hash_update(
	const bool true_when_parse_message,
	const tls_handshake_type_e type,
	u8_t * const tls_packet,
	const u32_t tls_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
#if !defined(USE_EAP_DEBUG_TRACE)
EAP_UNREFERENCED_PARAMETER(true_when_parse_message);
EAP_UNREFERENCED_PARAMETER(type);
#endif

	eap_status_e status = eap_status_not_supported;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TLS: %s:    hash_function: starts: tls_record_c::message_hash_update(): handshake type %s, %s\n"),
		 (m_is_client == true ? "client": "server"),
		 tls_handshake_header_c::get_tls_handshake_string(type),
		 (true_when_parse_message == true ? "parse": "create")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::message_hash_update()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA, 
		(EAPL("TLS: message_hash_update()"),
		 tls_packet,
		 tls_packet_length));

	if (tls_packet == 0
		|| tls_packet_length == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	status = m_message_hash_md5.hash_update(tls_packet, tls_packet_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_message_hash_sha1.hash_update(tls_packet, tls_packet_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::message_hash_create(
	const bool true_when_parse_message,
	const tls_handshake_type_e type,
	eap_variable_data_c * const message_hash,
	const bool client_originated)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
#if !defined(USE_EAP_DEBUG_TRACE)
EAP_UNREFERENCED_PARAMETER(true_when_parse_message);
#endif

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:    hash_function: starts: tls_record_c::message_hash_create(): handshake type %s, %s\n"),
		(m_is_client == true ? "client": "server"),
		tls_handshake_header_c::get_tls_handshake_string(type),
		(true_when_parse_message == true ? "parse": "create")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::message_hash_create()");

	eap_status_e status = eap_status_not_supported;

	eap_variable_data_c * message_hash_md5 = 0;
	eap_variable_data_c * message_hash_sha1 = 0;

	if (type == tls_handshake_type_certificate_verify)
	{
		message_hash_md5 = &m_message_hash_md5_certificate_verify;
		message_hash_sha1 = &m_message_hash_sha1_certificate_verify;
	}
	else if (type == tls_handshake_type_finished)
	{
		if (client_originated == true)
		{
			message_hash_md5 = &m_client_message_hash_md5_finished;
			message_hash_sha1 = &m_client_message_hash_sha1_finished;
		}
		else
		{
			message_hash_md5 = &m_server_message_hash_md5_finished;
			message_hash_sha1 = &m_server_message_hash_sha1_finished;
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_type);
	}

	u32_t md5_digest_length = message_hash_md5->get_data_length();

	u32_t sha1_digest_length = message_hash_sha1->get_data_length();

	if (cipher_suite_is_TLS_DHE_DSS() == true)
	{
		md5_digest_length = 0ul;
	}

	status = message_hash->set_buffer_length(md5_digest_length+sha1_digest_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	message_hash->set_data_length(0ul);



	if (type == tls_handshake_type_certificate_verify)
	{
		if (cipher_suite_is_TLS_RSA() == true
			|| cipher_suite_is_TLS_DHE_RSA() == true)
		{
			status = message_hash->add_data(message_hash_md5);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (cipher_suite_is_TLS_RSA() == true
			|| cipher_suite_is_TLS_DHE_DSS() == true
			|| cipher_suite_is_TLS_DHE_RSA() == true)
		{
			status = message_hash->add_data(message_hash_sha1);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else if (type == tls_handshake_type_finished)
	{
		status = message_hash->add_data(message_hash_md5);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message_hash->add_data(message_hash_sha1);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TLS: message_hash_create(): message_hash"),
		 message_hash->get_data(message_hash->get_data_length()),
		 message_hash->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::message_hash_final(
	eap_variable_data_c * const md5_digest,
	eap_variable_data_c * const sha1_digest)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:    hash_function: starts: tls_record_c::message_hash_final()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::message_hash_final()");

	eap_status_e status = eap_status_process_general_error;

	if (md5_digest == 0
		|| sha1_digest == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	{
		// The copy of hash context saves original hash context for later use. 
		// This way we do need store only one SHA1 and MD5 context for all handshake message hashes.
		abs_crypto_hash_algorithm_c * const copy_message_hash_md5 = m_message_hash_md5.copy();

		eap_automatic_variable_c<abs_crypto_hash_algorithm_c>
			deletes_copy_message_hash_md5(m_am_tools, copy_message_hash_md5);

		if (copy_message_hash_md5 == 0
			|| copy_message_hash_md5->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = md5_digest->set_buffer_length(copy_message_hash_md5->get_digest_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		md5_digest->set_data_length(copy_message_hash_md5->get_digest_length());

		u32_t digest_length = md5_digest->get_data_length();

		status = copy_message_hash_md5->hash_final(
			md5_digest->get_data(md5_digest->get_data_length()),
			&digest_length);
		if (digest_length != copy_message_hash_md5->get_digest_length())
		{
			status = eap_status_process_general_error;
		}
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	{
		// The copy of hash context saves original hash context for later use. 
		// This way we do need store only one SHA1 and MD5 context for all handshake message hashes.
		abs_crypto_hash_algorithm_c * const copy_message_hash_sha1 = m_message_hash_sha1.copy();

		eap_automatic_variable_c<abs_crypto_hash_algorithm_c>
			deletes_copy_message_hash_sha1(m_am_tools, copy_message_hash_sha1);

		if (copy_message_hash_sha1 == 0
			|| copy_message_hash_sha1->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = sha1_digest->set_buffer_length(copy_message_hash_sha1->get_digest_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		sha1_digest->set_data_length(copy_message_hash_sha1->get_digest_length());

		u32_t digest_length = sha1_digest->get_data_length();

		status = copy_message_hash_sha1->hash_final(
			sha1_digest->get_data(sha1_digest->get_data_length()),
			&digest_length);
		if (digest_length != copy_message_hash_sha1->get_digest_length())
		{
			status = eap_status_process_general_error;
		}
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::message_hash_save_certificate_verify()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:    hash_function: starts: tls_record_c::message_hash_save_certificate_verify()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::message_hash_save_certificate_verify()");

	eap_status_e status = eap_status_process_general_error;

	status = message_hash_final(
		&m_message_hash_md5_certificate_verify,
		&m_message_hash_sha1_certificate_verify);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::message_hash_save_finished(
	const bool client_originated)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:    hash_function: starts: tls_record_c::message_hash_save_finished()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::message_hash_save_finished()");

	eap_variable_data_c *message_hash_md5_finished = &m_client_message_hash_md5_finished;
	eap_variable_data_c *message_hash_sha1_finished = &m_client_message_hash_sha1_finished;

	eap_status_e status = eap_status_process_general_error;


	if (client_originated == false)
	{
		message_hash_md5_finished = &m_server_message_hash_md5_finished;
		message_hash_sha1_finished = &m_server_message_hash_sha1_finished;
	}

	status = message_hash_final(
		message_hash_md5_finished,
		message_hash_sha1_finished);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::message_hash_create_finished(
	const bool client_originated_message,
	eap_variable_data_c * const message_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:    hash_function: starts: tls_record_c::message_hash_create_finished()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::message_hash_create_finished()");

	eap_status_e status = eap_status_not_supported;

	eap_variable_data_c label_finished(m_am_tools);
	if (label_finished.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (client_originated_message == true)
	{
		status = label_finished.add_data(
			TLS_CLIENT_FINISHED_LABEL,
			TLS_CLIENT_FINISHED_LABEL_LENGTH);
	}
	else
	{
		status = label_finished.add_data(
			TLS_SERVER_FINISHED_LABEL,
			TLS_SERVER_FINISHED_LABEL_LENGTH);
	}

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c hash(m_am_tools);
	if (hash.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = message_hash_create(
		false,
		tls_handshake_type_finished,
		&hash,
		client_originated_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: message_hash_create_finished(): m_master_secret"),
		m_master_secret.get_data(),
		m_master_secret.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: message_hash_create_finished(): label_finished"),
		label_finished.get_data(),
		label_finished.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: message_hash_create_finished(): hash"),
		hash.get_data(),
		hash.get_data_length()));


	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:     prf_function: tls_prf.tls_prf_output()\n"),
		(m_is_client == true ? "client": "server")));

	crypto_tls_prf_c tls_prf(m_am_tools);

	status = tls_prf.tls_prf_init(
		&m_master_secret,
		&label_finished,
		&hash);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = message_hash->set_buffer_length(TLS_FINISHED_DATA_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	message_hash->set_data_length(TLS_FINISHED_DATA_SIZE);

	status = tls_prf.tls_prf_output(
		message_hash->get_data(message_hash->get_data_length()),
		message_hash->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: message_hash_create_finished(): message hash"),
		message_hash->get_data(),
		message_hash->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::packet_process(
	eap_variable_data_c * const tls_packet,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));

	tls_identity_privacy_handshake_state_e tmp_identity_privacy_handshake_state = 
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		m_tls_identity_privacy_handshake_state;
#else
		tls_identity_privacy_handshake_state_none;
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	EAP_UNREFERENCED_PARAMETER(tmp_identity_privacy_handshake_state);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::packet_process(): state %s, privacy_handshake_state=%d=%s, session_type=%s\n"),
		(m_is_client == true ? "client": "server"),
		eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
		 tmp_identity_privacy_handshake_state,
		 eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(tmp_identity_privacy_handshake_state),
		 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::packet_process()");

	m_received_tls_message.reset();

	eap_status_e status = m_received_tls_message.set_tls_message_data(
		tls_packet,
		received_eap_identifier);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_automatic_simple_value_c<bool> restore_allow_message_send(
		m_am_tools,
		&m_allow_message_send,
		true);

	// Packet send is delayed until after the process_tls_message() function returns.
	m_allow_message_send = false;

	status = process_tls_message();

	m_allow_message_send = true;


	if (status != eap_status_pending_request)
	{
		// Note this call will return eap_status_pending_request if any asyncronous call is pending.
		eap_status_e send_status = check_sent_tls_message();
		if (send_status != eap_status_ok)
		{
			status = send_status;
		}
	}

	if (status == eap_status_success
		&& m_tls_peap_state != tls_peap_state_tls_success)
	{
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::plain_eap_success_failure_packet_received(
	const eap_am_network_id_c * const receive_network_id,
	const eap_code_value_e received_eap_code,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::plain_eap_success_failure_packet_received(): state %s, m_tls_session_type=%s\n"),
		(m_is_client == true ? "client": "server"),
		eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
		eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::plain_eap_success_failure_packet_received()");

	eap_status_e status(eap_status_ok);

	if (received_eap_code == eap_code_success
		&& m_eap_type == eap_type_peap
		&& m_peap_version == peap_version_1
		&& m_use_tppd_tls_peap == true)
	{
		status = m_am_tls_services->save_tls_session(
			&m_session_id,
			&m_master_secret,
			m_selected_cipher_suite
#if defined(USE_EAP_TLS_SESSION_TICKET)
			, tls_extension_c::get_tls_extension(
				tls_extension_type_session_ticket,
				&m_received_tls_extensions,
				m_am_tools)
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
			);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#if defined(USE_FAST_EAP_TYPE)
	else if (m_eap_type == eap_type_fast)
	{
		if (received_eap_code == eap_code_success
			&& m_tls_peap_state == tls_peap_state_tls_success
			&& (m_tls_session_type == tls_session_type_original_session_resumption
				|| m_tls_session_type == tls_session_type_stateless_session_resumption))
		{
			eap_state_variable_e current_state(eap_state_authentication_finished_successfully);

			// Here we swap the addresses.
			eap_am_network_id_c send_network_id(m_am_tools,
				receive_network_id->get_destination_id(),
				receive_network_id->get_source_id(),
				receive_network_id->get_type());

			eap_state_notification_c notification(
				m_am_tools,
				&send_network_id,
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_eap,
				m_eap_type,
				eap_state_none,
				current_state,
				m_received_eap_identifier,
				false);

			state_notification(&notification);
		}
		else
		{
			status = m_application->plain_eap_success_failure_packet_received(
				receive_network_id,
				received_eap_code,
				received_eap_identifier);
		}
	}
#endif //#if defined(USE_FAST_EAP_TYPE)
	else if (m_eap_type == eap_type_peap
		|| m_eap_type == eap_type_ttls
		)
	{
		status = m_application->plain_eap_success_failure_packet_received(
			receive_network_id,
			received_eap_code,
			received_eap_identifier);
	}

	if (status != eap_status_pending_request)
	{
		// Note this call will return eap_status_pending_request if any asyncronous call is pending.
		eap_status_e send_status = check_sent_tls_message();
		if (send_status != eap_status_ok)
		{
			status = send_status;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::empty_ack_packet_received(
	const eap_am_network_id_c * const receive_network_id,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: starts: tls_record_c::empty_ack_packet_received(): state %s\n"),
		(m_is_client == true ? "client": "server"),
		eap_tls_trace_string_c::get_state_string(m_tls_peap_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::empty_ack_packet_received()");

	eap_status_e status(eap_status_not_supported);

	if (m_eap_type == eap_type_ttls)
	{
		status = m_application->empty_ack_packet_received(
			receive_network_id,
			received_eap_identifier);

		if (status != eap_status_pending_request)
		{
			// Note this call will return eap_status_pending_request if any asyncronous call is pending.
			eap_status_e send_status = check_sent_tls_message();
			if (send_status != eap_status_ok)
			{
				status = send_status;
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: function: starts: tls_record_c::reset()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::reset()");

	completion_action_clenup();

	{
		m_received_tls_message.reset();
		m_new_tls_message.reset();
		m_message_hash_md5.hash_cleanup();
		m_message_hash_sha1.hash_cleanup();
		m_message_hash_md5_certificate_verify.reset();
		m_message_hash_sha1_certificate_verify.reset();
		m_client_message_hash_md5_finished.reset();
		m_client_message_hash_sha1_finished.reset();
		m_server_message_hash_md5_finished.reset();
		m_server_message_hash_sha1_finished.reset();
		m_client_handshake_random_value.reset();
		m_server_handshake_random_value.reset();
		m_session_id.reset();
		m_master_secret.reset();
		m_eap_master_session_key.reset();
		m_send_mac_key.reset();
		m_receive_mac_key.reset();
		m_send_encryption_key.reset();
		m_receive_encryption_key.reset();
		m_send_iv.reset();
		m_receive_iv.reset();
		m_own_private_dhe_key.reset();
		m_own_public_dhe_key.reset();
		m_peer_public_dhe_key.reset();
		m_shared_dh_key.reset();
		m_dhe_prime.reset();
		m_dhe_group_generator.reset();
		m_signed_message_hash.reset();
		m_premaster_secret.reset();
#if defined(USE_FAST_EAP_TYPE)
		m_eap_fast_pac_key.reset();
#endif //#if defined(USE_FAST_EAP_TYPE)
		m_own_encrypted_premaster_secret.reset();
		m_proposed_cipher_suites.reset();
		m_proposed_compression_methods.reset();
		m_NAI_realm.reset();
		m_own_certificate_chain.reset();
		m_own_certificate_types.reset();
		m_own_certificate_authorities.reset();
		m_peer_certificate_chain.reset();
		m_peer_certificate_chain_result = eap_status_illegal_certificate;
		m_verify_signature = eap_status_authentication_failure;
		m_peer_certificate_types.reset();
		m_peer_certificate_authorities.reset();
	}

	eap_status_e status = message_hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_selected_cipher_suite(tls_cipher_suites_none);
	m_selected_compression_method = tls_compression_method_none;

	status = set_receive_cipher_suite(tls_cipher_suites_TLS_NULL_WITH_NULL_NULL);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	m_receive_compression_method = tls_compression_method_null;

	status = set_send_cipher_suite(tls_cipher_suites_TLS_NULL_WITH_NULL_NULL);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	m_send_compression_method = tls_compression_method_null;

	m_completion_queue.reset();

	m_send_record_sequence_number = 0ul;
	m_receive_record_sequence_number = 0ul;

	m_key_material_generated = false;

	m_force_tls_message_send = false;

	if (m_is_client == false)
	{
		// Server
		// NOTE: set_state() function cannot reset state.
		m_tls_peap_state = tls_peap_state_wait_handshake_type_client_hello;
	}
	else
	{
		// Client
		// NOTE: set_state() function cannot reset state.
		m_tls_peap_state = tls_peap_state_wait_tls_start;
	}

	m_tunneled_eap_type_authentication_state = eap_state_none;

	m_tls_peap_server_authenticates_client_action = true;
	if (m_is_client == false
		&& m_tls_peap_server_authenticates_client_config_server == false)
	{
		m_tls_peap_server_authenticates_client_action = false;
	}

	m_tls_peap_server_requested_client_certificate = false;

	m_could_send_fatal_alert_message = true;
	m_could_send_warning_alert_message = true;

	if (m_application != 0)
	{
		m_application->reset();
	}

	reset_block_ciphers(true);
	reset_block_ciphers(false);

	reset_stream_ciphers(true);
	reset_stream_ciphers(false);

	reset_hmac_algorithms(true);
	reset_hmac_algorithms(false);

	m_use_tppd_tls_peap = false;
	m_use_tppd_peapv1_acknowledge_hack = false;

	m_will_receive_new_session_ticket = false;

#if defined(USE_FAST_EAP_TYPE)
	m_remove_tunnel_pac = false;
#endif //#if defined(USE_FAST_EAP_TYPE)

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	set_tls_identity_privacy_handshake_state(tls_identity_privacy_handshake_state_none);
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


//--------------------------------------------------

EAP_FUNC_EXPORT u32_t tls_record_c::get_key_expansion_size(
	u32_t * const mac_key_length,
	u32_t * const encryption_key_length,
	u32_t * const iv_length,
	u32_t * const session_key_seed_length,
	u32_t * const mschapv2_challenges_length
	)
{
	u32_t length = 0ul;

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:     key_function: starts: tls_record_c::get_key_expansion_size()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::get_key_expansion_size()");

	*mac_key_length = 0ul;
	*encryption_key_length = 0ul;
	*iv_length = 0ul;
	*session_key_seed_length = 0ul;
	*mschapv2_challenges_length = 0ul;

	if (cipher_suite_is_3DES_EDE_CBC_SHA(m_selected_cipher_suite) == true)
	{
		crypto_3des_ede_c ede_3des(m_am_tools);

		crypto_sha1_c sha1(m_am_tools);
		crypto_hmac_c hmac_sha1(m_am_tools, &sha1, false);

		if (hmac_sha1.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}


		eap_variable_data_c tmp_key(m_am_tools);
		if (tmp_key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_status_e status = tmp_key.add_data("", 0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		status = hmac_sha1.hmac_set_key(&tmp_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		length = 2ul * hmac_sha1.get_digest_length()
			+ 2ul * ede_3des.get_key_length()
			+ 2ul * ede_3des.get_block_size();
		
		*mac_key_length = hmac_sha1.get_digest_length();
		*encryption_key_length = ede_3des.get_key_length();
		*iv_length = ede_3des.get_block_size();
	}
	else if (cipher_suite_is_AES_128_CBC_SHA(m_selected_cipher_suite) == true)
	{
		crypto_aes_c aes(m_am_tools);

		crypto_sha1_c sha1(m_am_tools);
		crypto_hmac_c hmac_sha1(m_am_tools, &sha1, false);

		if (hmac_sha1.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c tmp_key(m_am_tools);
		if (tmp_key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_status_e status = tmp_key.add_data("", 0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		status = hmac_sha1.hmac_set_key(&tmp_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		length = 2ul * hmac_sha1.get_digest_length()
			+ 2ul * aes.get_key_length()
			+ 2ul * aes.get_block_size();
		
		*mac_key_length = hmac_sha1.get_digest_length();
		*encryption_key_length = aes.get_key_length();
		*iv_length = aes.get_block_size();
	}
	else if (cipher_suite_is_RC4_128_MD5(m_selected_cipher_suite) == true)
	{
		crypto_md5_c md5(m_am_tools);
		crypto_hmac_c hmac_md5(m_am_tools, &md5, false);

		if (hmac_md5.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c tmp_key(m_am_tools);
		if (tmp_key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_status_e status = tmp_key.add_data("", 0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		status = hmac_md5.hmac_set_key(&tmp_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		length = 2ul * hmac_md5.get_digest_length()
			+ 2ul * TLS_RC4_128_KEY_LENGTH
			+ 2ul * TLS_RC4_128_IV_LENGTH;
		
		*mac_key_length = hmac_md5.get_digest_length();
		*encryption_key_length = TLS_RC4_128_KEY_LENGTH;
		*iv_length = TLS_RC4_128_IV_LENGTH;
	}
	else if (cipher_suite_is_RC4_128_SHA(m_selected_cipher_suite) == true)
	{
		crypto_sha1_c sha1(m_am_tools);
		crypto_hmac_c hmac_sha1(m_am_tools, &sha1, false);

		if (hmac_sha1.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c tmp_key(m_am_tools);
		if (tmp_key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_status_e status = tmp_key.add_data("", 0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		status = hmac_sha1.hmac_set_key(&tmp_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		length = 2ul * hmac_sha1.get_digest_length()
			+ 2ul * TLS_RC4_128_KEY_LENGTH
			+ 2ul * TLS_RC4_128_IV_LENGTH;
		
		*mac_key_length = hmac_sha1.get_digest_length();
		*encryption_key_length = TLS_RC4_128_KEY_LENGTH;
		*iv_length = TLS_RC4_128_IV_LENGTH;
	}

#if defined(USE_FAST_EAP_TYPE)
	if (m_eap_type == eap_type_fast)
	{
		*session_key_seed_length = EAP_FAST_SESSION_KEY_SEED_LENGTH;
		length += EAP_FAST_SESSION_KEY_SEED_LENGTH;

		if (m_tls_session_type == tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP
			&& m_selected_cipher_suite == tls_cipher_suites_TLS_DH_anon_WITH_AES_128_CBC_SHA)
		{
			*mschapv2_challenges_length = 2ul * EAP_FAST_MSCHAPV2_CHALLENGE_LENGTH;
			length += 2ul * EAP_FAST_MSCHAPV2_CHALLENGE_LENGTH;
		}
	}
#endif //#if defined(USE_FAST_EAP_TYPE)

	return length;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::cipher_suite_initialization_cbc(
	abs_crypto_cbc_block_algorithm_c ** const member_cbc_crypto_block_algorithm,
	abs_crypto_block_algorithm_c * const crypto_block_algorithm,
	const eap_variable_data_c * const member_iv,
	const eap_variable_data_c * const member_key,
	const bool true_when_encrypt)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:     key_function: starts: tls_record_c::cipher_suite_initialization_cbc()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::cipher_suite_initialization_cbc()");

	eap_automatic_variable_c<abs_crypto_block_algorithm_c>
		block_algorithm_remove(m_am_tools, crypto_block_algorithm);

	if (crypto_block_algorithm == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (crypto_block_algorithm->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (member_cbc_crypto_block_algorithm == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// After this point *member_cbc_crypto_block_algorithm will delete crypto_block_algorithm.
	block_algorithm_remove.do_not_free_variable();

	*member_cbc_crypto_block_algorithm = new crypto_cbc_c(
		m_am_tools,
		crypto_block_algorithm,
		true);

	if (*member_cbc_crypto_block_algorithm == 0
		|| (*member_cbc_crypto_block_algorithm)->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = eap_status_process_general_error;


	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CBC member_iv"),
		 member_iv->get_data(member_iv->get_data_length()),
		 member_iv->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CBC member_key"),
		 member_key->get_data(member_key->get_data_length()),
		 member_key->get_data_length()));


	if (true_when_encrypt == true)
	{
		status = (*member_cbc_crypto_block_algorithm)->set_encryption_key(
			member_iv->get_data(member_iv->get_data_length()),
			member_iv->get_data_length(),
			member_key->get_data(member_key->get_data_length()),
			member_key->get_data_length());
	}
	else
	{
		status = (*member_cbc_crypto_block_algorithm)->set_decryption_key(
			member_iv->get_data(member_iv->get_data_length()),
			member_iv->get_data_length(),
			member_key->get_data(member_key->get_data_length()),
			member_key->get_data_length());
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::cipher_suite_initialization_hmac(
	abs_crypto_hmac_algorithm_c * const member_hmac_algorithm,
	const eap_variable_data_c * const member_key)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:     key_function: starts: tls_record_c::cipher_suite_initialization_hmac()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::cipher_suite_initialization_hmac()");

	if (member_hmac_algorithm == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (member_hmac_algorithm->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("HMAC member_key"),
		 member_key->get_data(member_key->get_data_length()),
		 member_key->get_data_length()));

	status = member_hmac_algorithm->hmac_set_key(
		member_key);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::cipher_suite_initialization_stream(
	abs_crypto_stream_algorithm_c * const member_crypto_stream_algorithm,
	const eap_variable_data_c * const member_key,
	const bool /* true_when_encrypt */)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:     key_function: starts: tls_record_c::cipher_suite_initialization_stream()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::cipher_suite_initialization_stream()");

	if (member_crypto_stream_algorithm == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (member_crypto_stream_algorithm->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("STREAM member_key"),
		 member_key->get_data(member_key->get_data_length()),
		 member_key->get_data_length()));

	eap_status_e status = member_crypto_stream_algorithm->set_key(member_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::cipher_suite_initialization_hmac_sha1(const bool send_when_true)
{
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:     key_function: starts: tls_record_c::cipher_suite_initialization_hmac_sha1()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::cipher_suite_initialization_hmac_sha1()");

	reset_hmac_algorithms(send_when_true);

	eap_status_e status = eap_status_ok;

	if (send_when_true == true)
	{
		crypto_sha1_c * const sha1 = new crypto_sha1_c(m_am_tools);
		if (sha1 == 0)
		{
			delete sha1;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_send_hmac_algorithm = new crypto_hmac_c(m_am_tools, sha1, true);

		status = cipher_suite_initialization_hmac(
			m_send_hmac_algorithm,
			&m_send_mac_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}
	else
	{
		crypto_sha1_c * const sha1 = new crypto_sha1_c(m_am_tools);
		if (sha1 == 0)
		{
			delete sha1;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_receive_hmac_algorithm = new crypto_hmac_c(m_am_tools, sha1, true);

		status = cipher_suite_initialization_hmac(
			m_receive_hmac_algorithm,
			&m_receive_mac_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::cipher_suite_initialization_hmac_md5(const bool send_when_true)
{
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:     key_function: starts: cipher_suite_initialization_hmac_md5()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::cipher_suite_initialization_hmac_md5()");

	reset_hmac_algorithms(send_when_true);

	eap_status_e status = eap_status_ok;

	if (send_when_true == true)
	{
		crypto_md5_c * const md5 = new crypto_md5_c(m_am_tools);
		if (md5 == 0)
		{
			delete md5;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_send_hmac_algorithm = new crypto_hmac_c(m_am_tools, md5, true);

		status = cipher_suite_initialization_hmac(
			m_send_hmac_algorithm,
			&m_send_mac_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}
	else
	{
		crypto_md5_c * const md5 = new crypto_md5_c(m_am_tools);
		if (md5 == 0)
		{
			delete md5;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_receive_hmac_algorithm = new crypto_hmac_c(m_am_tools, md5, true);

		status = cipher_suite_initialization_hmac(
			m_receive_hmac_algorithm,
			&m_receive_mac_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::cipher_suite_initialization(
	const bool send_when_true)
{
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:     key_function: starts: tls_record_c::cipher_suite_initialization(), cipher suite %s: %s\n"),
		 (m_is_client == true ? "client": "server"),
		 eap_tls_trace_string_c::get_cipher_suite_string(m_selected_cipher_suite),
		 (send_when_true == true ? "send": "receive")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::cipher_suite_initialization()");

	reset_block_ciphers(send_when_true);

	reset_stream_ciphers(send_when_true);


	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_send_encryption_key"),
		 m_send_encryption_key.get_data(),
		 m_send_encryption_key.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_receive_encryption_key"),
		 m_receive_encryption_key.get_data(),
		 m_receive_encryption_key.get_data_length()));


	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_send_mac_key"),
		 m_send_mac_key.get_data(),
		 m_send_mac_key.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_receive_mac_key"),
		 m_receive_mac_key.get_data(),
		 m_receive_mac_key.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_send_iv"),
		 m_send_iv.get_data(),
		 m_send_iv.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_receive_iv"),
		 m_receive_iv.get_data(),
		 m_receive_iv.get_data_length()));


	eap_status_e status = eap_status_ok;

	if (cipher_suite_is_3DES_EDE_CBC_SHA(m_selected_cipher_suite) == true)
	{
		if (send_when_true == true)
		{
			crypto_3des_ede_c * des3 = new crypto_3des_ede_c(m_am_tools);

			status = cipher_suite_initialization_cbc(
				&m_send_block_cipher,
				des3,
				&m_send_iv,
				&m_send_encryption_key,
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
		}
		else
		{
			crypto_3des_ede_c * des3 = new crypto_3des_ede_c(m_am_tools);

			status = cipher_suite_initialization_cbc(
				&m_receive_block_cipher,
				des3,
				&m_receive_iv,
				&m_receive_encryption_key,
				false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
		}

		status = cipher_suite_initialization_hmac_sha1(send_when_true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (cipher_suite_is_AES_128_CBC_SHA(m_selected_cipher_suite) == true)
	{
		if (send_when_true == true)
		{
			crypto_aes_c * aes = new crypto_aes_c(m_am_tools);

			status = cipher_suite_initialization_cbc(
				&m_send_block_cipher,
				aes,
				&m_send_iv,
				&m_send_encryption_key,
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
		}
		else
		{
			crypto_aes_c * aes = new crypto_aes_c(m_am_tools);

			status = cipher_suite_initialization_cbc(
				&m_receive_block_cipher,
				aes,
				&m_receive_iv,
				&m_receive_encryption_key,
				false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
		}

		status = cipher_suite_initialization_hmac_sha1(send_when_true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (cipher_suite_is_RC4_128_MD5(m_selected_cipher_suite) == true)
	{
		if (send_when_true == true)
		{
			m_send_stream_cipher = new crypto_rc4_c(m_am_tools);

			status = cipher_suite_initialization_stream(
				m_send_stream_cipher,
				&m_send_encryption_key,
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
		}
		else
		{
			m_receive_stream_cipher = new crypto_rc4_c(m_am_tools);

			status = cipher_suite_initialization_stream(
				m_receive_stream_cipher,
				&m_receive_encryption_key,
				false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
		}

		status = cipher_suite_initialization_hmac_md5(send_when_true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (cipher_suite_is_RC4_128_SHA(m_selected_cipher_suite) == true)
	{
		if (send_when_true == true)
		{
			m_send_stream_cipher = new crypto_rc4_c(m_am_tools);

			status = cipher_suite_initialization_stream(
				m_send_stream_cipher,
				&m_send_encryption_key,
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
		}
		else
		{
			m_receive_stream_cipher = new crypto_rc4_c(m_am_tools);

			status = cipher_suite_initialization_stream(
				m_receive_stream_cipher,
				&m_receive_encryption_key,
				false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
		}

		status = cipher_suite_initialization_hmac_sha1(send_when_true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = eap_status_illegal_cipher_suite;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::generate_key_material()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:     tls_record_c::generate_key_material()\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::generate_key_material()");

	eap_status_e status = eap_status_illegal_cipher_suite;

	if (m_key_material_generated == true)
	{
		// Already generated.
		status = eap_status_ok;
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s:     key_function: starts: tls_record_c::generate_key_material()\n"),
			 (m_is_client == true) ? "client": "server"));

		if (m_master_secret.get_is_valid_data() == false
			|| m_client_handshake_random_value.get_is_valid_data() == false
			|| m_server_handshake_random_value.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u32_t mac_key_length = 0ul;
		u32_t encryption_key_length = 0ul;
		u32_t iv_length = 0ul;
		u32_t session_key_seed_length = 0ul;
		u32_t mschapv2_challenges_length = 0ul;

		u32_t key_expansion_size = get_key_expansion_size(
			&mac_key_length,
			&encryption_key_length,
			&iv_length,
			&session_key_seed_length,
			&mschapv2_challenges_length);

		if (key_expansion_size == 0ul)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
		}

		eap_variable_data_c label(m_am_tools);
		if (label.get_is_valid() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = label.add_data(
			TLS_PEAP_KEY_EXPANSION_LABEL,
			TLS_PEAP_KEY_EXPANSION_LABEL_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_variable_data_c seed(m_am_tools);
		if (seed.get_is_valid() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		status = seed.set_copy_of_buffer(&m_server_handshake_random_value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = seed.add_data(&m_client_handshake_random_value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s:     prf_function: tls_prf.tls_prf_output()\n"),
			(m_is_client == true ? "client": "server")));

		crypto_tls_prf_c tls_prf(m_am_tools);

		status = tls_prf.tls_prf_init(
			&m_master_secret,
			&label,
			&seed);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_variable_data_c key_expansion(m_am_tools);

		status = key_expansion.set_buffer_length(key_expansion_size);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		key_expansion.set_data_length(key_expansion_size);

		status = tls_prf.tls_prf_output(
			key_expansion.get_data(key_expansion.get_data_length()),
			key_expansion.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		u32_t key_offset = 0ul;

		eap_variable_data_c *send_mac_key = &m_new_send_mac_key;
		eap_variable_data_c *receive_mac_key = &m_new_receive_mac_key;
		eap_variable_data_c *send_encryption_key = &m_new_send_encryption_key;
		eap_variable_data_c *receive_encryption_key = &m_new_receive_encryption_key;
		eap_variable_data_c *send_iv = &m_new_send_iv;
		eap_variable_data_c *receive_iv = &m_new_receive_iv;

		if (m_is_client == false)
		{
			send_mac_key = &m_new_receive_mac_key;
			receive_mac_key = &m_new_send_mac_key;
			send_encryption_key = &m_new_receive_encryption_key;
			receive_encryption_key = &m_new_send_encryption_key;
			send_iv = &m_new_receive_iv;
			receive_iv = &m_new_send_iv;
		}

		status = send_mac_key->set_copy_of_buffer(
			key_expansion.get_data_offset(key_offset, mac_key_length),
			mac_key_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		key_offset += mac_key_length;

		status = receive_mac_key->set_copy_of_buffer(
			key_expansion.get_data_offset(key_offset, mac_key_length),
			mac_key_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		key_offset += mac_key_length;

		status = send_encryption_key->set_copy_of_buffer(
			key_expansion.get_data_offset(key_offset, encryption_key_length),
			encryption_key_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		key_offset += encryption_key_length;

		status = receive_encryption_key->set_copy_of_buffer(
			key_expansion.get_data_offset(key_offset, encryption_key_length),
			encryption_key_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		key_offset += encryption_key_length;

		if (iv_length > 0ul)
		{
			status = send_iv->set_copy_of_buffer(
				key_expansion.get_data_offset(key_offset, iv_length),
				iv_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			key_offset += iv_length;
		}
		else
		{
			status = send_iv->init(0ul);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			send_iv->set_is_valid();
		}

		if (iv_length > 0ul)
		{
			status = receive_iv->set_copy_of_buffer(
				key_expansion.get_data_offset(key_offset, iv_length),
				iv_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			key_offset += iv_length;
		}
		else
		{
			status = receive_iv->init(0ul);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			receive_iv->set_is_valid();
		}

#if defined(USE_FAST_EAP_TYPE)
		if (session_key_seed_length > 0ul)
		{
			status = m_session_key_seed.set_copy_of_buffer(
				key_expansion.get_data_offset(key_offset, session_key_seed_length),
				session_key_seed_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			key_offset += session_key_seed_length;
		}

		if (mschapv2_challenges_length > 0ul)
		{
			status = m_mschapv2_challenges.set_copy_of_buffer(
				key_expansion.get_data_offset(key_offset, mschapv2_challenges_length),
				mschapv2_challenges_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			key_offset += mschapv2_challenges_length;
		}
#endif //#if defined(USE_FAST_EAP_TYPE)

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: generate_key_material(): m_master_secret"),
			 m_master_secret.get_data(),
			 m_master_secret.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: generate_key_material(): m_client_handshake_random_value"),
			 m_client_handshake_random_value.get_data(),
			 m_client_handshake_random_value.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: generate_key_material(): m_server_handshake_random_value"),
			 m_server_handshake_random_value.get_data(),
			 m_server_handshake_random_value.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: generate_key_material(): key_expansion"),
			 key_expansion.get_data(),
			 key_expansion.get_data_length()));



		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: generate_key_material(): m_new_send_mac_key"),
			 m_new_send_mac_key.get_data(),
			 m_new_send_mac_key.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: generate_key_material(): m_new_receive_mac_key"),
			 m_new_receive_mac_key.get_data(),
			 m_new_receive_mac_key.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: generate_key_material(): m_new_send_encryption_key"),
			 m_new_send_encryption_key.get_data(),
			 m_new_send_encryption_key.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: generate_key_material(): m_new_receive_encryption_key"),
			 m_new_receive_encryption_key.get_data(),
			 m_new_receive_encryption_key.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: generate_key_material(): m_new_send_iv"),
			 m_new_send_iv.get_data(),
			 m_new_send_iv.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: generate_key_material(): m_new_receive_iv"),
			 m_new_receive_iv.get_data(),
			 m_new_receive_iv.get_data_length()));

		if (m_session_key_seed.get_is_valid_data() == true)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: generate_key_material(): m_session_key_seed"),
				 m_session_key_seed.get_data(),
				 m_session_key_seed.get_data_length()));
		}

#if defined(USE_FAST_EAP_TYPE)
		if (m_mschapv2_challenges.get_is_valid_data() == true)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: generate_key_material(): server_mschapv2_challenge"),
				 m_mschapv2_challenges.get_data(),
				 EAP_FAST_MSCHAPV2_CHALLENGE_LENGTH));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: generate_key_material(): client_mschapv2_challenge"),
				 m_mschapv2_challenges.get_data_offset(EAP_FAST_MSCHAPV2_CHALLENGE_LENGTH, EAP_FAST_MSCHAPV2_CHALLENGE_LENGTH),
				 EAP_FAST_MSCHAPV2_CHALLENGE_LENGTH));
		}
#endif //#if defined(USE_FAST_EAP_TYPE)

		m_key_material_generated = true;

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::set_tls_master_secret(
	const eap_variable_data_c * const master_secret,
	const eap_variable_data_c * const client_random,
	const eap_variable_data_c * const server_random)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s:     key_function: starts: tls_record_c::set_tls_master_secret()\n"),
		 this,
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::set_tls_master_secret()");

	eap_variable_data_c label(m_am_tools);
	if (label.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = eap_status_process_general_error;

	if (m_eap_type == eap_type_ttls)
	{
		status = label.add_data(
			EAP_TTLS_KEY_EXPANSION_LABEL,
			EAP_TTLS_KEY_EXPANSION_LABEL_LENGTH);
	}
	else if (m_eap_type == eap_type_peap
		&& m_peap_version == peap_version_1
		&& m_use_tppd_tls_peap == false)
	{
		status = label.add_data(
			EAP_TLS_PEAP_CLIENT_ENCRYPTION_LABEL_V1_DRAFT_5,
			EAP_TLS_PEAP_CLIENT_ENCRYPTION_LABEL_V1_DRAFT_5_LENGTH);
	}
	else
	{
		status = label.add_data(
			EAP_TLS_PEAP_CLIENT_ENCRYPTION_LABEL,
			EAP_TLS_PEAP_CLIENT_ENCRYPTION_LABEL_LENGTH);
	}

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = get_tls_prf_data(
		master_secret,
		client_random,
		server_random,
		&label,
		&m_eap_master_session_key,
		EAP_TLS_PEAP_MASTER_SESSION_KEY_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("tls_record_c::set_tls_master_secret(): TLS_MSK"),
		 m_eap_master_session_key.get_data(EAP_TLS_PEAP_MSK_SIZE),
		 EAP_TLS_PEAP_MSK_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("tls_record_c::set_tls_master_secret(): TLS_EMSK"),
		 m_eap_master_session_key.get_data_offset(EAP_TLS_PEAP_MSK_SIZE, EAP_TLS_PEAP_EMSK_SIZE),
		 EAP_TLS_PEAP_EMSK_SIZE));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::get_ttls_implicit_challenge(
	eap_variable_data_c * const ttls_implicit_challenge,
	const u32_t required_ttls_implicit_challenge_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s:     key_function: starts: tls_record_c::get_ttls_implicit_challenge()\n"),
		 this,
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::get_ttls_implicit_challenge()");

	eap_variable_data_c label(m_am_tools);
	if (label.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	eap_status_e status = eap_status_process_general_error;

	status = label.add_data(
		EAP_TTLS_IMPLICIT_CHALLENGE_LABEL,
		EAP_TTLS_IMPLICIT_CHALLENGE_LABEL_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = get_tls_prf_data(
		&m_master_secret,
		&m_client_handshake_random_value,
		&m_server_handshake_random_value,
		&label,
		ttls_implicit_challenge,
		required_ttls_implicit_challenge_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("tls_record_c::get_ttls_implicit_challenge(): ttls_implicit_challenge"),
		 ttls_implicit_challenge->get_data(),
		 ttls_implicit_challenge->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::get_tls_prf_data(
	const eap_variable_data_c * const master_secret,
	const eap_variable_data_c * const client_random,
	const eap_variable_data_c * const server_random,
	const eap_variable_data_c * const label,
	eap_variable_data_c * const prf_data,
	const u32_t required_prf_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s:     key_function: starts: tls_record_c::get_tls_prf_data()\n"),
		 this,
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::get_tls_prf_data()");

	eap_status_e status = eap_status_process_general_error;

	eap_variable_data_c seed(m_am_tools);
	if (seed.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = seed.set_copy_of_buffer(client_random);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = seed.add_data(server_random);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	crypto_tls_prf_c tls_prf(m_am_tools);

	status = tls_prf.tls_prf_init(
		master_secret,
		label,
		&seed);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = prf_data->set_buffer_length(
		required_prf_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	prf_data->set_data_length(required_prf_data_length);

	status = tls_prf.tls_prf_output(
		prf_data->get_data(),
		prf_data->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("tls_record_c::get_tls_prf_data(): prf_data"),
		 prf_data->get_data(),
		 prf_data->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::change_cipher_spec(
	const bool send_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: suite_function: starts: tls_record_c::change_cipher_spec(%s)\n"),
		 this,
		 (m_is_client == true) ? "client": "server",
		 (send_when_true == true) ? "send": "receive"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::change_cipher_spec()");

	eap_status_e status = eap_status_illegal_cipher_suite;

	if (m_selected_cipher_suite != tls_cipher_suites_none)
	{
		status = eap_status_ok;

		if (send_when_true == true)
		{
			status = set_send_cipher_suite(m_selected_cipher_suite);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(m_am_tools, 
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: change_cipher_spec(): send to %s\n"),
						eap_tls_trace_string_c::get_cipher_suite_string(m_send_cipher_suite)));

		}
		else
		{
			status = set_receive_cipher_suite(m_selected_cipher_suite);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(m_am_tools, 
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: change_cipher_spec(): receive to %s\n"),
						eap_tls_trace_string_c::get_cipher_suite_string(m_receive_cipher_suite)));
		}

		// This will initialize encryption, decryption and MAC algorithms.
		status = cipher_suite_initialization(send_when_true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (status == eap_status_ok)
	{
		if (send_when_true == true)
		{
			m_send_compression_method = m_selected_compression_method;

			EAP_TRACE_DEBUG(m_am_tools, 
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: change_cipher_spec() send to %s\n"),
						eap_tls_trace_string_c::get_compression_method_string(
							m_send_compression_method)));
		}
		else
		{
			m_receive_compression_method = m_selected_compression_method;

			EAP_TRACE_DEBUG(m_am_tools, 
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: change_cipher_spec() receive to %s\n"),
						eap_tls_trace_string_c::get_compression_method_string(
							m_receive_compression_method)));
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::new_record_message(
	tls_record_message_c ** const tls_record_message,
	const tls_record_protocol_e protocol)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: receive_function: starts: tls_record_c::new_record_message()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::new_record_message()");

	bool add_new_record = false;

	eap_automatic_variable_c<tls_record_message_c> automatic_tls_record_message(
		m_am_tools,
		0);

	eap_status_e status = eap_status_process_general_error;


	*tls_record_message = m_new_tls_message.get_last_record_message();
	if (*tls_record_message != 0
		&& (*tls_record_message)->get_protocol() != protocol)
	{
		// We need a new different protocol.
		*tls_record_message = 0;
	}

	if (m_use_separate_tls_record == true)
	{
		// Every message is in separate TLS-record.
		*tls_record_message = 0;
	}

	if (*tls_record_message == 0)
	{
		*tls_record_message = new tls_record_message_c(m_am_tools, this, m_is_client);
			
		automatic_tls_record_message.set_variable(*tls_record_message);
		
		if (*tls_record_message == 0
			|| (*tls_record_message)->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		
		status = (*tls_record_message)->set_protocol(protocol);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = (*tls_record_message)->set_version(tls_version_3_1);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		add_new_record = true;
	}
	
	if (add_new_record == true)
	{
		// Note m_new_tls_message free message on any case.
		automatic_tls_record_message.do_not_free_variable();

		bool includes_tls_handshake_message = false;

		if (protocol == tls_record_protocol_handshake)
		{
			includes_tls_handshake_message = true;
		}

		status = m_new_tls_message.add_record_message(
			(*tls_record_message),
			true,
			includes_tls_handshake_message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::add_record_message(
	tls_handshake_message_c * const tls_handshake_message)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: receive_function: starts: tls_record_c::add_record_message()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::add_record_message()");

	tls_record_message_c *tls_record_message = 0;

	eap_status_e status = new_record_message(
		&tls_record_message,
		tls_record_protocol_handshake);
	if (status != eap_status_ok
		|| tls_record_message == 0)
	{
		delete tls_handshake_message;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = tls_record_message->add_handshake_message(
		tls_handshake_message,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = tls_handshake_message->create_message_data();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::add_record_message(
	tls_change_cipher_spec_message_c * const change_cipher_spec_message)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: receive_function: starts: tls_record_c::add_record_message()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::add_record_message()");

	tls_record_message_c *tls_record_message = 0;

	eap_status_e status = new_record_message(
		&tls_record_message,
		tls_record_protocol_change_cipher_spec);
	if (status != eap_status_ok
		|| tls_record_message == 0)
	{
		delete change_cipher_spec_message;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = tls_record_message->add_change_cipher_spec_message(
		change_cipher_spec_message,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = change_cipher_spec_message->create_message_data();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::add_record_message(
	tls_alert_message_c * const alert_message)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: receive_function: starts: tls_record_c::add_record_message()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::add_record_message()");

	tls_record_message_c *tls_record_message = 0;

	eap_status_e status = new_record_message(
		&tls_record_message,
		tls_record_protocol_alert);
	if (status != eap_status_ok
		|| tls_record_message == 0)
	{
		delete alert_message;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = tls_record_message->add_alert_message(
		alert_message,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = alert_message->create_message_data();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::add_record_message(
	tls_application_data_message_c * const application_data_message)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: receive_function: starts: tls_record_c::add_record_message()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::add_record_message()");

	tls_record_message_c *tls_record_message = 0;

	eap_status_e status = new_record_message(
		&tls_record_message,
		tls_record_protocol_application_data);
	if (status != eap_status_ok
		|| tls_record_message == 0)
	{
		delete application_data_message;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = tls_record_message->add_application_data_message(
		application_data_message,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::allocate_handshake_message(
	tls_handshake_message_c ** const tls_handshake_message,
	eap_automatic_variable_c<tls_handshake_message_c> * const automatic_tls_handshake_message,
	const tls_handshake_type_e handshake_type)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: receive_function: starts: tls_record_c::allocate_handshake_message()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::allocate_handshake_message()");

	*tls_handshake_message
		= new tls_handshake_message_c(m_am_tools, this, m_is_client);
	
	automatic_tls_handshake_message->set_variable(*tls_handshake_message);

	if (*tls_handshake_message == 0
		|| (*tls_handshake_message)->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = (*tls_handshake_message)->set_handshake_type(
		handshake_type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_handshake_type_hello_request()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_handshake_type_hello_request()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_handshake_type_hello_request()");

	// This is an empty message.

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_type_hello_request);

	// Note add_record_message() frees message on any case.
	automatic_tls_handshake_message.do_not_free_variable();

	status = add_record_message(tls_handshake_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_state(tls_peap_state_wait_handshake_type_client_hello);

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_handshake_type_client_hello()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_handshake_type_client_hello(): privacy_handshake_state=%d=%s, session_type=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_tls_identity_privacy_handshake_state,
		 eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(m_tls_identity_privacy_handshake_state),
		 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type)));
#else
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_handshake_type_client_hello(): privacy_handshake_state=%d=%s\n"),
		this,
		(m_is_client == true ? "client": "server"),
		0,
		""));
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_handshake_type_client_hello()");

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                 | Version: 3    | Version: 1    |               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
	// |                                                               |
	// +                                                               +
	// |                                                               |
	// +                                                               +
	// |          ClientRandomValue                                    |
	// +              (32 bytes)                       +-+-+-+-+-+-+-+-+
	// |                                               | ID length     |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// +                                                               +
	// |                Session ID                                     |
	// +             (maximum 32 bytes)                                +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | CipherSuite length            | CipherSuite 1                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | CipherSuite 2                 | CipherSuite 3                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | CipherSuite 4                 | Cmp length    | Cmp 1         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Cmp 2         | Cmp 3         |  extensions ...               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	eap_status_e status(eap_status_ok);

	status = message_hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	status = allocate_handshake_message(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_type_client_hello);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t tmp_gmt_unix_time_network_order = eap_htonl(m_am_tools->get_gmt_unix_time());
	eap_variable_data_c tmp_client_random(m_am_tools);

	status = tmp_client_random.set_buffer_length(TLS_HANDSHAKE_RANDOM_VALUE_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	tmp_client_random.set_data_length(TLS_HANDSHAKE_RANDOM_VALUE_SIZE);

	crypto_random_c rand(m_am_tools);

	status = rand.get_rand_bytes(
		tmp_client_random.get_data(tmp_client_random.get_data_length()),
		tmp_client_random.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Sets the first bytes to GMT unix time.
	u8_t *p_gmt_unix_time = reinterpret_cast<u8_t *>(tmp_client_random.get_data(sizeof(u32_t)));
	if (p_gmt_unix_time == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	m_am_tools->memmove(p_gmt_unix_time, &tmp_gmt_unix_time_network_order, sizeof(tmp_gmt_unix_time_network_order));


	status = m_client_handshake_random_value.set_copy_of_buffer(
		&tmp_client_random);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = tls_handshake_message->set_random_value(
		&tmp_client_random);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_tls_session_type == tls_session_type_original_session_resumption
		&& m_session_id.get_is_valid_data() == true)
	{
		status = tls_handshake_message->set_session_id(
			&m_session_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// --------------------------------------------------------------------

	// This copies proposed cipher suites to tls_handshake_message.
	status = tls_handshake_message->set_cipher_suites(&m_proposed_cipher_suites);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	status = tls_handshake_message->set_compression_methods(&m_proposed_compression_methods);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

#if defined(USE_EAP_TLS_SESSION_TICKET)

	{
		status = tls_handshake_message->set_tls_extensions(&m_supported_tls_extensions);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

	// --------------------------------------------------------------------

	// Note add_record_message() frees message on any case.
	automatic_tls_handshake_message.do_not_free_variable();

	status = add_record_message(tls_handshake_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_handshake_type_server_hello(
	const u16_t /*selected_cipher_suite*/,
	const u8_t /*selected_compression_method*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_handshake_type_server_hello()\n"),
		 this,
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_handshake_type_server_hello()");

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                 | Version: 3    | Version: 1    |               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
	// |                                                               |
	// +                                                               +
	// |                                                               |
	// +                                                               +
	// |          ServerRandomValue                                    |
	// +              (32 bytes)                       +-+-+-+-+-+-+-+-+
	// |                                               | ID length     |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// +                                                               +
	// |                Session ID                                     |
	// +             (maximum 32 bytes)                                +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | CipherSuite                   | Cmp           | extensions ... 
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_type_server_hello);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	u32_t tmp_gmt_unix_time_network_order = eap_htonl(m_am_tools->get_gmt_unix_time());
	eap_variable_data_c tmp_server_random(m_am_tools);

	status = tmp_server_random.set_buffer_length(TLS_HANDSHAKE_RANDOM_VALUE_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	tmp_server_random.set_data_length(TLS_HANDSHAKE_RANDOM_VALUE_SIZE);

	crypto_random_c rand(m_am_tools);

	status = rand.get_rand_bytes(
		tmp_server_random.get_data(tmp_server_random.get_data_length()),
		tmp_server_random.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Sets the first bytes to GMT unix time.
	u8_t *p_gmt_unix_time = reinterpret_cast<u8_t *>(tmp_server_random.get_data(sizeof(u32_t)));
	if (p_gmt_unix_time == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	m_am_tools->memmove(p_gmt_unix_time, &tmp_gmt_unix_time_network_order, sizeof(tmp_gmt_unix_time_network_order));

	status = m_server_handshake_random_value.set_copy_of_buffer(
		&tmp_server_random);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	status = tls_handshake_message->set_random_value(
		&tmp_server_random);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	if ((m_tls_session_type == tls_session_type_full_authentication
#if defined(USE_FAST_EAP_TYPE)	
		 || m_tls_session_type == tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP
#endif //#if defined(USE_FAST_EAP_TYPE)		 
		 )		 
		&& m_server_offers_new_session_id == true)
	{
		// We create a new session.
		status = m_session_id.set_buffer_length(TLS_SESSION_ID_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		m_session_id.set_data_length(TLS_SESSION_ID_SIZE);

		status = rand.get_rand_bytes(
			m_session_id.get_data(m_session_id.get_data_length()),
			m_session_id.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// --------------------------------------------------------------------

	status = tls_handshake_message->set_session_id(
		&m_session_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s: TLS/PEAP selected cipher_suite %s\n"),
			 (m_is_client == true ? "client": "server"),
			 eap_tls_trace_string_c::get_cipher_suite_string(m_selected_cipher_suite)));
	}

	status = tls_handshake_message->set_selected_cipher_suite(
		m_selected_cipher_suite);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	status = tls_handshake_message->set_selected_compression_method(
		m_selected_compression_method);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

#if defined(USE_EAP_TLS_SESSION_TICKET)

#if defined(USE_FAST_EAP_TYPE)
	if (m_eap_type != eap_type_fast) // EAP-FAST does not use session ticket in ServerHello message.
#endif //#if defined(USE_FAST_EAP_TYPE)
	{
		status = tls_handshake_message->set_tls_extensions(&m_supported_tls_extensions);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

	// --------------------------------------------------------------------

	if (m_tls_session_type == tls_session_type_original_session_resumption
#if defined(USE_EAP_TLS_SESSION_TICKET)
		|| m_tls_session_type == tls_session_type_stateless_session_resumption
#if defined(USE_FAST_EAP_TYPE)
		|| m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption
#endif //#if defined(USE_FAST_EAP_TYPE)
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
		)
	{

#if defined(USE_FAST_EAP_TYPE)
		if (m_eap_type == eap_type_fast
			&& m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption)
		{
			// Generates master secret from PAC-Key.
			// Parameter resumed_master_secret includes PAC-Key.
			status = generate_eap_fast_master_secret_from_pac_key(
				&m_eap_fast_pac_key);

			m_eap_fast_pac_key.reset();

			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
#endif //#if defined(USE_FAST_EAP_TYPE)

		// We must generate the key material.
		status = generate_key_material();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}

	// --------------------------------------------------------------------

	// Note add_record_message() frees message on any case.
	automatic_tls_handshake_message.do_not_free_variable();

	status = add_record_message(tls_handshake_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_handshake_type_certificate(
	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));

	tls_identity_privacy_handshake_state_e tmp_identity_privacy_handshake_state = 
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		m_tls_identity_privacy_handshake_state;
#else
		tls_identity_privacy_handshake_state_none;
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	EAP_UNREFERENCED_PARAMETER(tmp_identity_privacy_handshake_state);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_handshake_type_certificate(): state=%d=%s, privacy_handshake_state=%d=%s, session_type=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_tls_peap_state,
		 eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
		 tmp_identity_privacy_handshake_state,
		 eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(tmp_identity_privacy_handshake_state),
		 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_handshake_type_certificate()");

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                 | Certificate Chain Length                      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Certificate 1 Length                          |               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
	// |                                                               |
	// +                                                               +
	// |          Certificate 1                                        |
	// +                                                               +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// .                    ...                                        .
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Certificate n Length                          |               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
	// |                                                               |
	// +                                                               +
	// |          Certificate n                                        |
	// +                                                               +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_type_certificate);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	// Certificate chain is included when TLS identity privacy is not used,
	// or send cipher is not NULL
	// or sender is server
	if (m_tls_session_type == tls_session_type_full_authentication
		&& (m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_none
			|| m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_runs
			|| m_is_client == false))
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	{
		status = tls_handshake_message->set_certificate_chain(
			certificate_chain);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// --------------------------------------------------------------------

	// Note add_record_message() frees message on any case.
	automatic_tls_handshake_message.do_not_free_variable();

	status = add_record_message(tls_handshake_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_handshake_type_certificate_request(
	EAP_TEMPLATE_CONST eap_array_c<u8_t> * const certificate_types,
	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_authorities)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_handshake_type_certificate_request()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_handshake_type_certificate_request()");

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                 | CT length     | CT 1          | CT 2          |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | CT 3          | CT 4          | CAs length                    |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | CA 1 length                   |                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
	// |                                                               |
	// +                                                               +
	// |      Distinguished name of Certificate Authority 1            |
	// +                                                               +
	// |                                                               |
	// +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                               | CA 2 length                   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// +                                                               +
	// |      Distinguished name of Certificate Authority 2            |
	// +                                                               +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_type_certificate_request);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = tls_handshake_message->set_certificate_types(
		certificate_types);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_server_sends_empty_certificate_authorities_list == false)
	{
		status = tls_handshake_message->set_certificate_authorities(
			certificate_authorities);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// --------------------------------------------------------------------

	// Note add_record_message() frees message on any case.
	automatic_tls_handshake_message.do_not_free_variable();

	status = add_record_message(tls_handshake_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_handshake_type_server_hello_done()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_handshake_type_server_hello_done()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_handshake_type_server_hello_done()");

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//
	// ServerHelloDone message does not include payload.

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_type_server_hello_done);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	// Note add_record_message() frees message on any case.
	automatic_tls_handshake_message.do_not_free_variable();

	status = add_record_message(tls_handshake_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_server_key_exchange_sha1_hash(
	const eap_variable_data_c * const dhe_prime,
	const eap_variable_data_c * const dhe_group_generator,
	const eap_variable_data_c * const public_dhe_key,
	eap_variable_data_c * const hash)
{
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s:    hash_function: starts: tls_record_c::create_server_key_exchange_sha1_hash()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_server_key_exchange_sha1_hash()");

	if (m_client_handshake_random_value.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_server_handshake_random_value.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u16_t dhe_prime_length_network_order 
		= eap_htons(static_cast<u16_t>(dhe_prime->get_data_length()));

	u16_t dhe_group_generator_length_network_order 
		= eap_htons(static_cast<u16_t>(dhe_group_generator->get_data_length()));

	u16_t public_dhe_key_length_network_order 
		= eap_htons(static_cast<u16_t>(public_dhe_key->get_data_length()));

	crypto_sha1_c sha1(m_am_tools);

	eap_status_e status = sha1.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_sha1_hash(): client random"),
		m_client_handshake_random_value.get_data(m_client_handshake_random_value.get_data_length()),
		m_client_handshake_random_value.get_data_length()));

	status = sha1.hash_update(
		m_client_handshake_random_value.get_data(m_client_handshake_random_value.get_data_length()),
		m_client_handshake_random_value.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_sha1_hash(): server random"),
		m_server_handshake_random_value.get_data(m_client_handshake_random_value.get_data_length()),
		m_server_handshake_random_value.get_data_length()));

	status = sha1.hash_update(
		m_server_handshake_random_value.get_data(m_client_handshake_random_value.get_data_length()),
		m_server_handshake_random_value.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_sha1_hash(): dhe_prime_length_network_order"),
		&dhe_prime_length_network_order,
		sizeof(dhe_prime_length_network_order)));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_sha1_hash(): dhe_prime"),
		dhe_prime->get_data(dhe_prime->get_data_length()),
		dhe_prime->get_data_length()));

	status = sha1.hash_update(
		&dhe_prime_length_network_order,
		sizeof(dhe_prime_length_network_order));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(
		dhe_prime->get_data(
			dhe_prime->get_data_length()),
		dhe_prime->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_sha1_hash(): ")
		 EAPL("dhe_group_generator_length_network_order"),
		&dhe_group_generator_length_network_order,
		sizeof(dhe_group_generator_length_network_order)));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_sha1_hash(): dhe_group_generator"),
		dhe_group_generator->get_data(dhe_group_generator->get_data_length()),
		dhe_group_generator->get_data_length()));

	status = sha1.hash_update(
		&dhe_group_generator_length_network_order,
		sizeof(dhe_group_generator_length_network_order));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(
		dhe_group_generator->get_data(
			dhe_group_generator->get_data_length()),
		dhe_group_generator->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_sha1_hash(): public_dhe_key_length_network_order"),
		&public_dhe_key_length_network_order,
		sizeof(public_dhe_key_length_network_order)));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_sha1_hash(): public_dhe_key"),
		public_dhe_key->get_data(public_dhe_key->get_data_length()),
		public_dhe_key->get_data_length()));

	status = sha1.hash_update(
		&public_dhe_key_length_network_order,
		sizeof(public_dhe_key_length_network_order));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(
		public_dhe_key->get_data(
			public_dhe_key->get_data_length()),
		public_dhe_key->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = hash->set_buffer_length(sha1.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	hash->set_data_length(sha1.get_digest_length());

	u32_t digest_length = hash->get_data_length();
	status = sha1.hash_final(
		hash->get_data(hash->get_data_length()),
		&digest_length);
	if (digest_length != sha1.get_digest_length())
	{
		status = eap_status_process_general_error;
	}
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_sha1_hash(): hash"),
		hash->get_data(hash->get_data_length()),
		hash->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_server_key_exchange_md5_hash(
	const eap_variable_data_c * const dhe_prime,
	const eap_variable_data_c * const dhe_group_generator,
	const eap_variable_data_c * const public_dhe_key,
	eap_variable_data_c * const hash)
{
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s:    hash_function: starts: tls_record_c::create_server_key_exchange_md5_hash()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_server_key_exchange_md5_hash()");

	if (m_client_handshake_random_value.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_server_handshake_random_value.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u16_t dhe_prime_length_network_order 
		= eap_htons(static_cast<u16_t>(dhe_prime->get_data_length()));

	u16_t dhe_group_generator_length_network_order 
		= eap_htons(static_cast<u16_t>(dhe_group_generator->get_data_length()));

	u16_t public_dhe_key_length_network_order 
		= eap_htons(static_cast<u16_t>(public_dhe_key->get_data_length()));

	crypto_md5_c md5(m_am_tools);

	eap_status_e status = md5.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_md5_hash(): client random"),
		m_client_handshake_random_value.get_data(m_client_handshake_random_value.get_data_length()),
		m_client_handshake_random_value.get_data_length()));

	status = md5.hash_update(
		m_client_handshake_random_value.get_data(m_client_handshake_random_value.get_data_length()),
		m_client_handshake_random_value.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_md5_hash(): server random"),
		m_server_handshake_random_value.get_data(m_client_handshake_random_value.get_data_length()),
		m_server_handshake_random_value.get_data_length()));

	status = md5.hash_update(
		m_server_handshake_random_value.get_data(m_client_handshake_random_value.get_data_length()),
		m_server_handshake_random_value.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_md5_hash(): dhe_prime_length_network_order"),
		&dhe_prime_length_network_order,
		sizeof(dhe_prime_length_network_order)));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_md5_hash(): dhe_prime"),
		dhe_prime->get_data(dhe_prime->get_data_length()),
		dhe_prime->get_data_length()));

	status = md5.hash_update(
		&dhe_prime_length_network_order,
		sizeof(dhe_prime_length_network_order));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = md5.hash_update(
		dhe_prime->get_data(
			dhe_prime->get_data_length()),
		dhe_prime->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_md5_hash(): ")
		 EAPL("dhe_group_generator_length_network_order"),
		&dhe_group_generator_length_network_order,
		sizeof(dhe_group_generator_length_network_order)));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_md5_hash(): dhe_group_generator"),
		dhe_group_generator->get_data(dhe_group_generator->get_data_length()),
		dhe_group_generator->get_data_length()));

	status = md5.hash_update(
		&dhe_group_generator_length_network_order,
		sizeof(dhe_group_generator_length_network_order));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = md5.hash_update(
		dhe_group_generator->get_data(
			dhe_group_generator->get_data_length()),
		dhe_group_generator->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_md5_hash(): public_dhe_key_length_network_order"),
		&public_dhe_key_length_network_order,
		sizeof(public_dhe_key_length_network_order)));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_md5_hash(): public_dhe_key"),
		public_dhe_key->get_data(public_dhe_key->get_data_length()),
		public_dhe_key->get_data_length()));

	status = md5.hash_update(
		&public_dhe_key_length_network_order,
		sizeof(public_dhe_key_length_network_order));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = md5.hash_update(
		public_dhe_key->get_data(
			public_dhe_key->get_data_length()),
		public_dhe_key->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = hash->set_buffer_length(md5.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	hash->set_data_length(md5.get_digest_length());

	u32_t digest_length = hash->get_data_length();
	status = md5.hash_final(
		hash->get_data(hash->get_data_length()),
		&digest_length);
	if (digest_length != md5.get_digest_length())
	{
		status = eap_status_process_general_error;
	}
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_server_key_exchange_md5_hash(): hash"),
		hash->get_data(hash->get_data_length()),
		hash->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::verify_signature_of_server_key_exchange(
	const eap_variable_data_c * const signed_server_key_exchange_hash)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s:    hash_function: starts: tls_record_c::verify_signature_of_server_key_exchange()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::verify_signature_of_server_key_exchange()");

	eap_status_e status = eap_status_not_supported;

	eap_variable_data_c hash(m_am_tools);


	if (cipher_suite_is_TLS_DHE_DSS() == true)
	{
		status = create_server_key_exchange_sha1_hash(
			&m_dhe_prime,
			&m_dhe_group_generator,
			&m_peer_public_dhe_key,
			&hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (cipher_suite_is_TLS_DHE_RSA() == true)
	{
		eap_variable_data_c md5_hash(m_am_tools);

		status = create_server_key_exchange_md5_hash(
			&m_dhe_prime,
			&m_dhe_group_generator,
			&m_peer_public_dhe_key,
			&md5_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_variable_data_c sha1_hash(m_am_tools);

		status = create_server_key_exchange_sha1_hash(
			&m_dhe_prime,
			&m_dhe_group_generator,
			&m_peer_public_dhe_key,
			&sha1_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = hash.add_data(&md5_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = hash.add_data(&sha1_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}


	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: verify_signature_of_server_key_exchange(): hash"),
		hash.get_data(hash.get_data_length()),
		hash.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: verify_signature_of_server_key_exchange(): signed_server_key_exchange_hash"),
		signed_server_key_exchange_hash->get_data(
			signed_server_key_exchange_hash->get_data_length()),
		signed_server_key_exchange_hash->get_data_length()));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:     pki_function: verify_with_public_key()\n"),
		(m_is_client == true ? "client": "server")));

	status = m_am_tls_services->verify_with_public_key(
		&hash,
		signed_server_key_exchange_hash);
	if (status == eap_status_pending_request)
	{
		// This is pending query, that will be completed by complete_query_certificate_chain() call.
		m_pending_verify_with_public_key = true;
	}
	else if (status == eap_status_completed_request)
	{
		// This is already completed by complete_query_certificate_chain() call.
	}
	else if (status == eap_status_ok)
	{
		// This is also an error case, because this call is always completed on success. 
		status = eap_status_process_general_error;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else // All other status values means error, because this call is always completed on success.
	{
		// This is an error case.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_create_handshake_type_server_key_exchange()
{
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: parse_function: starts: tls_record_c::complete_create_handshake_type_server_key_exchange()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_create_handshake_type_server_key_exchange()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_type_server_key_exchange);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if EAP_TLS_UNSUPPORTED_CIPHER_SUITE
	#error This one needs more code. RSA key exchange with different parameters is NOT supported.
	if (cipher_suite_is_TLS_RSA() == true)
	{
		// RSA modulus and exponent are included when selected cipher suite is
		// using RSA key exchange
		// and parameters are different than included in the certificate.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | rsa_modulus length            |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |          rsa_modulus                                          |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  rsa_exponent length          |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                  rsa_exponent                                 +
		// |                                                               |
		// +                                                               +
		// |                                                               |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                                                               +
		// |       digitally-signed MD5 hash 16 bytes                      |
		// +    (ClientHello.random + ServerHello.random + ServerParams)   +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                                                               +
		// |       digitally-signed SHA-1 hash 20 bytes                    |
		// +    (ClientHello.random + ServerHello.random + ServerParams)   +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}
	else
#endif
	if (cipher_suite_is_TLS_DHE_DSS() == true)
	{
		// Diffie-Hellman prime modulus, generator and server's
		// Diffie-Hellman public value (g^X mod p)
		// are included when selected cipher suite is ephemeral Diffie-Hellman key exchange.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | DH p length                   |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |                DH p value (prime modulus)                     |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH g length                  |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH g value (generator)                         |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH Ys length                 |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH Ys value                                    |
		// +         (server's Diffie-Hellman public value)                +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                                                               +
		// |       digitally-signed SHA-1 hash 47 bytes                    |
		// +    (ClientHello.random + ServerHello.random + ServerParams)   +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: complete_create_handshake_type_server_key_exchange(): m_signed_message_hash"),
			m_signed_message_hash.get_data(m_signed_message_hash.get_data_length()),
			m_signed_message_hash.get_data_length()));

		status = tls_handshake_message->set_signed_message_hash(
			&m_signed_message_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (cipher_suite_is_TLS_DHE_RSA() == true)
	{
		// Diffie-Hellman prime modulus, generator and server's
		// Diffie-Hellman public value (g^X mod p)
		// are included when selected cipher suite is ephemeral Diffie-Hellman key exchange.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | DH p length                   |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |                DH p value (prime modulus)                     |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH g length                  |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH g value (generator)                         |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH Ys length                 |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH Ys value                                    |
		// +         (server's Diffie-Hellman public value)                +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                                                               +
		// |       digitally-signed MD5 hash 16 bytes                      |
		// +    (ClientHello.random + ServerHello.random + ServerParams)   +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                                                               +
		// |       digitally-signed SHA-1 hash 47 bytes                    |
		// +    (ClientHello.random + ServerHello.random + ServerParams)   +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: complete_create_handshake_type_server_key_exchange(): m_signed_message_hash"),
			m_signed_message_hash.get_data(m_signed_message_hash.get_data_length()),
			m_signed_message_hash.get_data_length()));

		status = tls_handshake_message->set_signed_message_hash(
			&m_signed_message_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#if defined(USE_FAST_EAP_TYPE)
	else if (m_eap_type == eap_type_fast
		&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
		&& cipher_suite_is_TLS_DH_anon() == true)
	{
		// Diffie-Hellman prime modulus, generator and server's
		// Diffie-Hellman public value (g^X mod p)
		// are included when selected cipher suite is ephemeral Diffie-Hellman key exchange.
		// NOTE: Here are no signed hash. This is not authenticated at all and vulnerable to
		// man-in-the-middle attacks.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | DH p length                   |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |                DH p value (prime modulus)                     |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH g length                  |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH g value (generator)                         |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH Ys length                 |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH Ys value                                    |
		// +         (server's Diffie-Hellman public value)                +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: complete_create_handshake_type_server_key_exchange() no m_signed_message_hash\n")));
	}
#endif //#if defined(USE_FAST_EAP_TYPE)
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}

	// --------------------------------------------------------------------


	status = tls_handshake_message->set_dhe_prime(
		&m_dhe_prime);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = tls_handshake_message->set_dhe_group_generator(
		&m_dhe_group_generator);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = tls_handshake_message->set_public_dhe_key(
		&m_own_public_dhe_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	// Note add_record_message() frees message on any case.
	automatic_tls_handshake_message.do_not_free_variable();

	status = add_record_message(tls_handshake_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_handshake_type_server_key_exchange()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_handshake_type_server_key_exchange()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_handshake_type_server_key_exchange()");

	eap_status_e status = eap_status_process_general_error;
	eap_variable_data_c hash(m_am_tools);


#if EAP_TLS_UNSUPPORTED_CIPHER_SUITE
	#error This one needs more code. RSA key exchange with different parameters is NOT supported.
	if (cipher_suite_is_TLS_RSA() == true)
	{
		// RSA modulus and exponent are included when selected
		// cipher suite is using RSA key exchange
		// and parameters are different than included in the certificate.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | rsa_modulus length            |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |          rsa_modulus                                          |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  rsa_exponent length          |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                  rsa_exponent                                 +
		// |                                                               |
		// +                                                               +
		// |                                                               |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                                                               +
		// |       digitally-signed MD5 hash 16 bytes                      |
		// +    (ClientHello.random + ServerHello.random + ServerParams)   +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                                                               +
		// |       digitally-signed SHA-1 hash 20 bytes                    |
		// +    (ClientHello.random + ServerHello.random + ServerParams)   +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}
	else
#endif
	if (cipher_suite_is_TLS_DHE_DSS() == true)
	{
		// Diffie-Hellman prime modulus, generator and server's
		// Diffie-Hellman public value (g^X mod p)
		// are included when selected cipher suite is ephemeral Diffie-Hellman key exchange.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | DH p length                   |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |                DH p value (prime modulus)                     |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH g length                  |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH g value (generator)                         |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH Ys length                 |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH Ys value                                    |
		// +         (server's Diffie-Hellman public value)                +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                                                               +
		// |       digitally-signed SHA-1 hash 47 bytes                    |
		// +    (ClientHello.random + ServerHello.random + ServerParams)   +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		status = create_server_key_exchange_sha1_hash(
			&m_dhe_prime,
			&m_dhe_group_generator,
			&m_own_public_dhe_key,
			&hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: create_handshake_type_server_key_exchange(): hash"),
			hash.get_data(hash.get_data_length()),
			hash.get_data_length()));
	}
	else if (cipher_suite_is_TLS_DHE_RSA() == true)
	{
		// Diffie-Hellman prime modulus, generator and server's
		// Diffie-Hellman public value (g^X mod p)
		// are included when selected cipher suite is ephemeral Diffie-Hellman key exchange.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | DH p length                   |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |                DH p value (prime modulus)                     |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH g length                  |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH g value (generator)                         |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH Ys length                 |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH Ys value                                    |
		// +         (server's Diffie-Hellman public value)                +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                                                               +
		// |       digitally-signed MD5 hash 16 bytes                      |
		// +    (ClientHello.random + ServerHello.random + ServerParams)   +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                                                               +
		// |       digitally-signed SHA-1 hash 47 bytes                    |
		// +    (ClientHello.random + ServerHello.random + ServerParams)   +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		eap_variable_data_c md5_hash(m_am_tools);

		status = create_server_key_exchange_md5_hash(
			&m_dhe_prime,
			&m_dhe_group_generator,
			&m_own_public_dhe_key,
			&md5_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: create_handshake_type_server_key_exchange() md5_hash"),
			md5_hash.get_data(md5_hash.get_data_length()),
			md5_hash.get_data_length()));

		eap_variable_data_c sha1_hash(m_am_tools);

		status = create_server_key_exchange_sha1_hash(
			&m_dhe_prime,
			&m_dhe_group_generator,
			&m_own_public_dhe_key,
			&sha1_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: create_handshake_type_server_key_exchange() sha1_hash"),
			sha1_hash.get_data(sha1_hash.get_data_length()),
			sha1_hash.get_data_length()));

		status = hash.add_data(&md5_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = hash.add_data(&sha1_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: create_handshake_type_server_key_exchange(): hash"),
			hash.get_data(hash.get_data_length()),
			hash.get_data_length()));
	}
#if defined(USE_FAST_EAP_TYPE)
	else if (m_eap_type == eap_type_fast
		&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
		&& cipher_suite_is_TLS_DH_anon() == true)
	{
		// Diffie-Hellman prime modulus, generator and server's
		// Diffie-Hellman public value (g^X mod p)
		// are included when selected cipher suite is ephemeral Diffie-Hellman key exchange.
		// NOTE: Here are no signed hash. This is not authenticated at all and vulnerable to
		// man-in-the-middle attacks.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | DH p length                   |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |                DH p value (prime modulus)                     |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH g length                  |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH g value (generator)                         |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |  DH Ys length                 |                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
		// |                                                               |
		// +                                                               +
		// |                DH Ys value                                    |
		// +         (server's Diffie-Hellman public value)                +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


		// NOTE: Here the return value is eap_status_pending_request to avoid error after return.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_pending_request);
	}
#endif //#if defined(USE_FAST_EAP_TYPE)
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:     pki_function: create_handshake_type_server_key_exchange()\n"),
		(m_is_client == true ? "client": "server")));

	m_signed_message_hash.reset();

	// NOTE this function is asyncronous. This causes complex control flow.
	// This function call will be completed always.
	status = m_am_tls_services->sign_with_private_key(
		&hash);
	if (status == eap_status_pending_request)
	{
		// This is pending query, that will be completed by complete_sign_with_private_key() call.
		m_pending_sign_with_private_key = true;
	}
	else if (status == eap_status_completed_request)
	{
		// This is already completed by complete_sign_with_private_key() call.
	}
	else if (status == eap_status_ok)
	{
		// This is also an error case, because this call is always completed on success. 
		status = eap_status_process_general_error;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else // All other status values means error, because this call is always completed on success.
	{
		// This is an error case.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_create_handshake_type_client_key_exchange()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::complete_create_handshake_type_client_key_exchange(): cipher suite=%d=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_selected_cipher_suite,
		 eap_tls_trace_string_c::get_cipher_suite_string(m_selected_cipher_suite)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_create_handshake_type_client_key_exchange()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_type_client_key_exchange);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	if (cipher_suite_is_TLS_RSA() == true)
	{
		// Encrypted premaster secret is included when selected
		// cipher suite is using RSA key exchange.
		// First two bytes are version of TLS.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 |                                               |
		// +-+-+-+-+-+-+-+-+                                               +
		// |                                                               |
		// +                                                               +
		// |                Encrypted Premaster Secret (48 bytes)          |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (m_own_encrypted_premaster_secret.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: complete_create_handshake_type_client_key_exchange(): encrypted premaster_secret"),
			m_own_encrypted_premaster_secret.get_data(),
			m_own_encrypted_premaster_secret.get_data_length()));

		status = tls_handshake_message->set_encrypted_premaster_secret(
			&m_own_encrypted_premaster_secret);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (cipher_suite_is_TLS_DHE_DSS() == true
		|| cipher_suite_is_TLS_DHE_RSA() == true
#if defined(USE_FAST_EAP_TYPE)
		|| (m_eap_type == eap_type_fast
			&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
			&& cipher_suite_is_TLS_DH_anon() == true)
#endif //#if defined(USE_FAST_EAP_TYPE)
		)
	{
		// Diffie-Hellman Yc is included when selected cipher suite is
		// ephemeral Diffie-Hellman key exchange.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | DH Yc length                  |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |                DH Yc value                                    |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (m_own_public_dhe_key.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		status = tls_handshake_message->set_public_dhe_key(
			&m_own_public_dhe_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}

	// --------------------------------------------------------------------

	// Note add_record_message() frees message on any case.
	automatic_tls_handshake_message.do_not_free_variable();

	status = add_record_message(tls_handshake_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_handshake_type_client_key_exchange()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_handshake_type_client_key_exchange()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_handshake_type_client_key_exchange()");

	eap_status_e status = eap_status_process_general_error;

	if (cipher_suite_is_TLS_RSA() == true)
	{
		// Encrypted premaster secret is included when selected
		// cipher suite is using RSA key exchange.
		// First two bytes are version of TLS.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 |                                               |
		// +-+-+-+-+-+-+-+-+                                               +
		// |                                                               |
		// +                                                               +
		// |                Encrypted Premaster Secret (48 bytes)          |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (m_premaster_secret.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s:     pki_function: rsa_encrypt_with_public_key()\n"),
			(m_is_client == true ? "client": "server")));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: create_handshake_type_client_key_exchange(): premaster_secret"),
			 m_premaster_secret.get_data(),
			 m_premaster_secret.get_data_length()));

		status = m_am_tls_services->rsa_encrypt_with_public_key(
			&m_premaster_secret);

		if (status == eap_status_pending_request)
		{
			// This is pending query, that will be completed by
			// complete_rsa_encrypt_with_public_key() call.
			m_pending_rsa_encrypt_with_public_key = true;
		}
		else if (status == eap_status_completed_request)
		{
			// This is already completed by complete_rsa_encrypt_with_public_key() call.
		}
		else if (status == eap_status_ok)
		{
			// This is also an error case, because this call is always completed on success. 
			status = eap_status_process_general_error;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else // All other status values means error, because this
			// call is always completed on success.
		{
			// This is an error case.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
		}
	}
	else if (cipher_suite_is_TLS_DHE_DSS() == true
		|| cipher_suite_is_TLS_DHE_RSA() == true
#if defined(USE_FAST_EAP_TYPE)
		|| (m_eap_type == eap_type_fast
			&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
			&& cipher_suite_is_TLS_DH_anon() == true)
#endif //#if defined(USE_FAST_EAP_TYPE)
		)
	{
		// Diffie-Hellman Yc is included when selected cipher suite is
		// ephemeral Diffie-Hellman key exchange.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | DH Yc length                  |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |                DH Yc value                                    |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		// These cipher suites does not need asyncronous operations.
		// Still these cipher suites are completed in
		// complete_create_handshake_type_client_key_exchange().
		status = eap_status_ok;
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_create_handshake_type_certificate_verify()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::complete_create_handshake_type_certificate_verify()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_create_handshake_type_certificate_verify()");

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_type_certificate_verify);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: complete_create_handshake_type_certificate_verify(): m_signed_message_hash"),
		m_signed_message_hash.get_data(m_signed_message_hash.get_data_length()),
		m_signed_message_hash.get_data_length()));

	status = tls_handshake_message->set_signed_message_hash(
		&m_signed_message_hash);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	// Note add_record_message() frees message on any case.
	automatic_tls_handshake_message.do_not_free_variable();

	status = add_record_message(tls_handshake_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_handshake_type_certificate_verify()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_handshake_type_certificate_verify()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_handshake_type_certificate_verify()");

	// --------------------------------------------------------------------

	if (cipher_suite_is_TLS_RSA() == true)
	{
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 |                                               |
		// +-+-+-+-+-+-+-+-+                                               +
		// |                                                               |
		// +                   Signed MD5 hash                             +
		// |                    (16 bytes)                                 |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// +                   Signed SHA hash                             +
		// |                    (20 bytes)                                 |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		// this will be created in tls_handshake_message_c::add_message_data().
	}
	else if (cipher_suite_is_TLS_DHE_DSS() == true
		|| cipher_suite_is_TLS_DHE_RSA() == true)
	{
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 |                                               |
		// +-+-+-+-+-+-+-+-+                                               +
		// |                                                               |
		// +                   Signed SHA hash                             +
		// |                    (48 bytes)                                 |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		// this will be created in tls_handshake_message_c::add_message_data().
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}

	eap_status_e status = message_hash_save_certificate_verify();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c message_hash(m_am_tools);

	status = message_hash_create(
		false,
		tls_handshake_type_certificate_verify,
		&message_hash,
		m_is_client);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:     pki_function: sign_with_private_key()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: create_handshake_type_certificate_verify() message_hash"),
		message_hash.get_data(message_hash.get_data_length()),
		message_hash.get_data_length()));

	// NOTE this function is asyncronous. This causes complex control flow.
	status = m_am_tls_services->sign_with_private_key(
		&message_hash);
	if (status == eap_status_pending_request)
	{
		// This is pending query, that will be completed by complete_query_certificate_chain() call.
		m_pending_sign_with_private_key = true;
	}
	else if (status == eap_status_completed_request)
	{
		// This is already completed by complete_query_certificate_chain() call.
	}
	else if (status == eap_status_ok)
	{
		// This is also an error case, because this call is always completed on success. 
		status = eap_status_process_general_error;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else // All other status values means error, because this call is always completed on success.
	{
		// This is an error case.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_handshake_type_finished()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_handshake_type_finished()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_handshake_type_finished()");

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                 |                                               |
	// +-+-+-+-+-+-+-+-+                                               +
	// |                                                               |
	// +                                                               +
	// |         PRF(master_secret, finished_label,                    |
	// +             MD5(handshake_messages) +                         +
	// |             SHA-1(handshake_messages)) [0..11]                |
	// +                                                               +
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_type_finished);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	// Note add_record_message() frees message on any case.
	automatic_tls_handshake_message.do_not_free_variable();

	status = add_record_message(tls_handshake_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TLS_SESSION_TICKET)

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_handshake_type_new_session_ticket()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_handshake_type_new_session_ticket()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_handshake_type_new_session_ticket()");

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                 |      ticket lifetime hint (4 bytes)       ... |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | ...           | opaque ticket ...  n bytes                    
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	tls_handshake_message_c *tls_handshake_message = 0;

	eap_automatic_variable_c<tls_handshake_message_c>
		automatic_tls_handshake_message(m_am_tools);

	eap_status_e status = allocate_handshake_message(
		&tls_handshake_message,
		&automatic_tls_handshake_message,
		tls_handshake_type_new_session_ticket);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------


	const tls_extension_c * const p_new_session_ticket = tls_extension_c::get_tls_extension(
		tls_extension_type_session_ticket,
		&m_supported_tls_extensions,
		m_am_tools);

	if (p_new_session_ticket != 0)
	{
		eap_array_c<tls_extension_c> session_ticket_extension_array(m_am_tools);

		tls_extension_c * const p_new_session_ticket_copy = p_new_session_ticket->copy();
		if (p_new_session_ticket_copy == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = session_ticket_extension_array.add_object(p_new_session_ticket_copy, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = tls_handshake_message->set_tls_extensions(&session_ticket_extension_array);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// --------------------------------------------------------------------

	// Note add_record_message() frees message on any case.
	automatic_tls_handshake_message.do_not_free_variable();

	status = add_record_message(tls_handshake_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_change_cipher_spec_type_change_cipher_spec()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_change_cipher_spec_type_change_cipher_spec()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_change_cipher_spec_type_change_cipher_spec()");

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//                 +-+-+-+-+-+-+-+-+                                
	//                 | CCS: 1        |                                
	//                 +-+-+-+-+-+-+-+-+                                

	tls_change_cipher_spec_message_c * const tls_change_cipher_spec_message
		= new tls_change_cipher_spec_message_c(m_am_tools, this, m_is_client);

	eap_automatic_variable_c<tls_change_cipher_spec_message_c>
		automatic_tls_change_cipher_spec_message(
		m_am_tools, tls_change_cipher_spec_message);

	if (tls_change_cipher_spec_message == 0
		|| tls_change_cipher_spec_message->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = tls_change_cipher_spec_message->set_change_cipher_spec_type(
		tls_change_cipher_spec_type_change_cipher_spec);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	// Note add_record_message() frees message on any case.
	automatic_tls_change_cipher_spec_message.do_not_free_variable();

	status = add_record_message(tls_change_cipher_spec_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::finish_handshake()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::finish_handshake(): m_tls_session_type=%d=%s, state=%d=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_tls_session_type,
		 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
		 m_tls_peap_state,
		 eap_tls_trace_string_c::get_state_string(m_tls_peap_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::finish_handshake()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: finish_handshake(): m_master_secret"),
		 m_master_secret.get_data(),
		 m_master_secret.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: finish_handshake(): m_client_handshake_random_value"),
		 m_client_handshake_random_value.get_data(),
		 m_client_handshake_random_value.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: finish_handshake(): m_server_handshake_random_value"),
		 m_server_handshake_random_value.get_data(),
		 m_server_handshake_random_value.get_data_length()));


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	tls_identity_privacy_handshake_state_e tmp_identity_privacy_handshake_state = 
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		m_tls_identity_privacy_handshake_state;
#else
		tls_identity_privacy_handshake_state_none;
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)


#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	if (m_tls_use_identity_privacy == false
		|| tmp_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_runs
		|| m_tls_session_type != tls_session_type_full_authentication)
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	{
		status = set_tls_master_secret(
			&m_master_secret,
			&m_client_handshake_random_value,
			&m_server_handshake_random_value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_DEBUG_TRACE)
	// These are for debug break points.

	if (m_is_client == true)
	{
		if (m_tls_session_type == tls_session_type_full_authentication)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: client, m_tls_session_type=%d=%s, state=%d=%s, privacy_handshake_state=%d=%s\n"),
				m_tls_session_type,
				eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
				m_tls_peap_state,
				eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
				tmp_identity_privacy_handshake_state,
				eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(tmp_identity_privacy_handshake_state)));

		}
		else if (m_tls_session_type == tls_session_type_original_session_resumption)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: client, m_tls_session_type=%d=%s, state=%d=%s, privacy_handshake_state=%d=%s\n"),
				m_tls_session_type,
				eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
				m_tls_peap_state,
				eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
				tmp_identity_privacy_handshake_state,
				eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(tmp_identity_privacy_handshake_state)));

		}
		else if (m_tls_session_type == tls_session_type_stateless_session_resumption)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: client, m_tls_session_type=%d=%s, state=%d=%s, privacy_handshake_state=%d=%s\n"),
				m_tls_session_type,
				eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
				m_tls_peap_state,
				eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
				tmp_identity_privacy_handshake_state,
				eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(tmp_identity_privacy_handshake_state)));
		}
#if defined(USE_FAST_EAP_TYPE)
		else if (m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: client, m_tls_session_type=%d=%s, state=%d=%s, privacy_handshake_state=%d=%s\n"),
				m_tls_session_type,
				eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
				m_tls_peap_state,
				eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
				tmp_identity_privacy_handshake_state,
				eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(tmp_identity_privacy_handshake_state)));
		}
#endif //#if defined(USE_FAST_EAP_TYPE)
	}
	else // if (m_is_client == false)
	{
		if (m_tls_session_type == tls_session_type_full_authentication)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: server, m_tls_session_type=%d=%s, state=%d=%s, privacy_handshake_state=%d=%s\n"),
				m_tls_session_type,
				eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
				m_tls_peap_state,
				eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
				tmp_identity_privacy_handshake_state,
				eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(tmp_identity_privacy_handshake_state)));

		}
		else if (m_tls_session_type == tls_session_type_original_session_resumption)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: server, m_tls_session_type=%d=%s, state=%d=%s, privacy_handshake_state=%d=%s\n"),
				m_tls_session_type,
				eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
				m_tls_peap_state,
				eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
				tmp_identity_privacy_handshake_state,
				eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(tmp_identity_privacy_handshake_state)));

		}
		else if (m_tls_session_type == tls_session_type_stateless_session_resumption)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: server, m_tls_session_type=%d=%s, state=%d=%s, privacy_handshake_state=%d=%s\n"),
				m_tls_session_type,
				eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
				m_tls_peap_state,
				eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
				tmp_identity_privacy_handshake_state,
				eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(tmp_identity_privacy_handshake_state)));
		}
#if defined(USE_FAST_EAP_TYPE)
		else if (m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: server, m_tls_session_type=%d=%s, state=%d=%s, privacy_handshake_state=%d=%s\n"),
				m_tls_session_type,
				eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
				m_tls_peap_state,
				eap_tls_trace_string_c::get_state_string(m_tls_peap_state),
				tmp_identity_privacy_handshake_state,
				eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(tmp_identity_privacy_handshake_state)));
		}
#endif //#if defined(USE_FAST_EAP_TYPE)
	}
#endif //#if defined(USE_EAP_DEBUG_TRACE)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_application != 0)
	{
		m_application->set_tunneled_state(
			m_tls_session_type);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_FAST_EAP_TYPE)
	if (m_is_client == false
		&& m_eap_type == eap_type_fast
		&& m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption)
	{
		if (m_application == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		// This is server.
		// EAP-FAST is using Tunnel PAC.
		// Here we cannot start tunneled authentication immediately
		// because client migth have sent a User Authorization PAC.
		// We must process the optional TLS Application message(s)
		// to see did client send the User Authorization PAC.
		set_state(tls_peap_state_wait_tunneled_authentication_start);

		eap_status_e tunnel_ready_status = m_application->peap_tunnel_ready();
		if (tunnel_ready_status != eap_status_ok)
		{
			// This is an error case.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, tunnel_ready_status);
		}

		tunnel_ready_status = get_type_partner()->peap_tunnel_ready();
		if (tunnel_ready_status != eap_status_ok)
		{
			// This is an error case.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, tunnel_ready_status);
		}
	}
	else 
#endif //#if defined(USE_FAST_EAP_TYPE)
	if (get_is_tunneled_tls() == false
		|| ((m_tls_session_type == tls_session_type_original_session_resumption
				|| m_tls_session_type == tls_session_type_stateless_session_resumption)
			&& (
#if defined(USE_FAST_EAP_TYPE)
				m_eap_type == eap_type_fast
				|| 
#endif //#if defined(USE_FAST_EAP_TYPE)
				m_eap_type == eap_type_ttls
				|| (m_eap_type == eap_type_peap
#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
					&& m_peap_version > peap_version_1
#else
					&& m_peap_version > peap_version_0_xp
#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
					&&  m_peap_version < peap_version_2))))
	{
		if (m_tls_session_type == tls_session_type_full_authentication
			&& tmp_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_negotiates)
		{
			// TLS-privacy negotiation running.
		}
		else
		{
			set_state(tls_peap_state_tls_success);
		}

		// PEAPv2 does not use m_eap_master_session_key directly.
		// PEAPv2 does derive an other master session key.
		// EAP-TLS, PEAPv0 and PEAPv1 does use m_eap_master_session_key.
		if (m_eap_type == eap_type_tls // Plain EAP-TLS.
			|| m_eap_type == eap_type_ttls
#if defined(USE_FAST_EAP_TYPE)
			|| m_eap_type == eap_type_fast
#endif //#if defined(USE_FAST_EAP_TYPE)
			|| (m_eap_type == eap_type_peap
				&& (m_peap_version == peap_version_0_xp
					|| m_peap_version == peap_version_1)))
		{
			status = get_type_partner()->set_tls_master_secret(&m_eap_master_session_key);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if ((
#if defined(USE_FAST_EAP_TYPE)
			m_eap_type == eap_type_fast
				||
#endif //#if defined(USE_FAST_EAP_TYPE)
				m_eap_type == eap_type_ttls)
			&& (m_tls_session_type == tls_session_type_original_session_resumption
					|| m_tls_session_type == tls_session_type_stateless_session_resumption))
		{
			eap_status_e notification_status = indicate_state_to_lower_layer(m_tls_peap_state);
			if (notification_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, notification_status);
			}
		}
	}
	else if (tmp_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_none
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
		|| tmp_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_runs
#endif
		)
	{
		if ((m_eap_type == eap_type_peap
				&& m_peap_version >= peap_version_0_xp
				&& m_peap_version <= peap_version_2)
			|| m_eap_type == eap_type_ttls
#if defined(USE_FAST_EAP_TYPE)
			|| m_eap_type == eap_type_fast
#endif //#if defined(USE_FAST_EAP_TYPE)
			)
		{
			if (m_application == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
			}

			set_state(tls_peap_state_peap_tunnel_ready);

			eap_status_e tunnel_ready_status = m_application->peap_tunnel_ready();
			if (tunnel_ready_status != eap_status_ok)
			{
				// This is an error case.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, tunnel_ready_status);
			}

			tunnel_ready_status = get_type_partner()->peap_tunnel_ready();
			if (tunnel_ready_status != eap_status_ok)
			{
				// This is an error case.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, tunnel_ready_status);
			}

#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
			if ((m_tls_session_type == tls_session_type_original_session_resumption
					|| m_tls_session_type == tls_session_type_stateless_session_resumption)
				&& m_use_tppd_tls_peap == true
				&& m_peap_version == peap_version_1
				&& m_use_tppd_peapv1_acknowledge_hack == true)
			{
				status = get_type_partner()->set_tls_master_secret(&m_eap_master_session_key);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)


			if (m_is_client == true
				&& m_eap_type == eap_type_ttls)
			{
				// EAP-TTLS client starts the tunneled authentication.

				// Here we swap the addresses.
				eap_am_network_id_c receive_network_id(m_am_tools,
					m_send_network_id.get_destination_id(),
					m_send_network_id.get_source_id(),
					m_send_network_id.get_type());

				status = m_application->start_ttls_tunneled_authentication(
					&receive_network_id,
					m_received_eap_identifier);
				if (status != eap_status_ok
					&& status != eap_status_pending_request)
				{
					// This is an error case.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, tunnel_ready_status);
				}
			}


#if defined(USE_EAP_CORE_SERVER)
			if (m_is_client == false)
			{
				// Server

				if (
#if defined(USE_FAST_EAP_TYPE)
					m_eap_type == eap_type_fast
					|| 
#endif //#if defined(USE_FAST_EAP_TYPE)
					(m_eap_type == eap_type_peap
						&& (m_peap_version >= peap_version_2
							|| ((m_tls_session_type == tls_session_type_original_session_resumption
								|| m_tls_session_type == tls_session_type_stateless_session_resumption)
								&& (
									m_peap_version == peap_version_0_xp
#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
									|| m_peap_version == peap_version_1
#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
									)
								)
							)
						)
					)
				{
#if defined(USE_FAST_EAP_TYPE)
					if (m_eap_type == eap_type_fast
						&& m_send_piggypacked_eap_identity_request == false
						&& (m_tls_session_type == tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP
							|| m_tls_session_type == tls_session_type_full_authentication))
					{
						// Server does not start tunneled authentication yet.
						// Instead server waits empty EAP-FAST acnowledge message from client.

						eap_state_notification_c notification(
							m_am_tools,
							&m_send_network_id,
							m_is_client,
							eap_state_notification_eap,
							eap_protocol_layer_eap,
							m_eap_type,
							eap_state_none,
							eap_state_authentication_wait_eap_fast_empty_acknowledge,
							m_received_eap_identifier,
							false);
						get_type_partner()->state_notification(&notification);
						status = eap_status_ok;
					}
					else
#endif //#if defined(USE_FAST_EAP_TYPE)
					{
						// Here we swap the addresses.
						eap_am_network_id_c receive_network_id(m_am_tools,
							m_send_network_id.get_destination_id(),
							m_send_network_id.get_source_id(),
							m_send_network_id.get_type());

						set_state(tls_peap_state_wait_tunneled_authentication_start);

						// Here we must start the tunneled EAP-type.
						status = start_peap_tunneled_authentication(
							&receive_network_id,
							m_received_eap_identifier,
							m_tls_session_type);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
				}
			}
			else
#endif //#if defined(USE_EAP_CORE_SERVER)
			{
				// Client

#if defined(USE_FAST_EAP_TYPE)
				if (m_eap_type == eap_type_fast)
				{
					// Here we swap the addresses.
					eap_am_network_id_c receive_network_id(m_am_tools,
						m_send_network_id.get_destination_id(),
						m_send_network_id.get_source_id(),
						m_send_network_id.get_type());

					// Here we must start the tunneled EAP-type.
					status = start_peap_tunneled_authentication(
						&receive_network_id,
						m_received_eap_identifier,
						m_tls_session_type);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
#endif //#if defined(USE_FAST_EAP_TYPE)

			}


#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
			if ((m_tls_session_type == tls_session_type_original_session_resumption
					|| m_tls_session_type == tls_session_type_stateless_session_resumption)
				&& m_use_tppd_tls_peap == true
				&& m_peap_version == peap_version_1
				&& m_use_tppd_peapv1_acknowledge_hack == true)
			{
				if (m_is_client == true)
				{
					eap_state_notification_c notification(
						m_am_tools,
						&m_send_network_id,
						m_is_client,
						eap_state_notification_eap,
						eap_protocol_layer_internal_type,
						m_eap_type,
						eap_state_none,
						tls_peap_state_tppd_peapv1_waits_eap_success_or_tunneled_packet,
						m_received_eap_identifier,
						false);
					get_type_partner()->state_notification(&notification);
				}
			}
#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)

		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_tls_peap_state == tls_peap_state_tls_success)
	{
		// Notify lower layer that TLS/PEAP ended successfully

		if (get_is_tunneled_tls() == false
			|| (get_is_tunneled_tls() == true
				&& m_tunneled_eap_type_authentication_state
				== eap_state_authentication_finished_successfully)
			|| (get_is_tunneled_tls() == true
				&& m_tls_session_type == tls_session_type_original_session_resumption))
		{
			eap_status_e save_status = m_am_tls_services->save_tls_session(
				&m_session_id,
				&m_master_secret,
				m_selected_cipher_suite
#if defined(USE_EAP_TLS_SESSION_TICKET)
				, tls_extension_c::get_tls_extension(
					tls_extension_type_session_ticket,
					&m_received_tls_extensions,
					m_am_tools)
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
				);
			if (save_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, save_status);
			}

			eap_status_e notification_status = indicate_state_to_lower_layer(m_tls_peap_state);
			if (notification_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, notification_status);
			}
		}
	}
	else if (m_tls_peap_state == tls_peap_state_peap_tunnel_ready)
	{
		// Notify lower layer that TLS tunnel is ready.

		eap_status_e notification_status = indicate_state_to_lower_layer(m_tls_peap_state);
		if (notification_status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, notification_status);
		}

		// Change state that only one indication is sent to lower layer.
		if (m_is_client == true)
		{
			set_state(tls_peap_state_wait_application_data);
		}
		else
		{
			set_state(tls_peap_state_wait_tunneled_authentication_start);
		}
	}
	else if (m_tls_peap_state == tls_peap_state_failure)
	{
		eap_status_e notification_status = indicate_state_to_lower_layer(m_tls_peap_state);
		if (notification_status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, notification_status);
		}
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: tls_record_c::finish_handshake(): No notification, m_tls_session_type=%d=%s, state=%d=%s\n"),
			m_tls_session_type,
			eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
			m_tls_peap_state,
			eap_tls_trace_string_c::get_state_string(m_tls_peap_state)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_tls_protocol_alert(
	const tls_alert_description_e par_alert_description,
	const tls_alert_level_e par_alert_level,
	const eap_status_e par_result)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_tls_protocol_alert()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_tls_protocol_alert()");

	eap_status_e status = eap_status_authentication_failure;

	//--------------------------------------------------------------------

	tls_alert_level_e alert_level = par_alert_level;
	tls_alert_description_e alert_description = par_alert_description;

	if (alert_level == tls_alert_level_none)
	{
		alert_level = tls_alert_level_fatal;
	}

	if (alert_description == tls_alert_description_none)
	{
		// Examine par_result.
		switch(par_result)
		{
#if EAP_TLS_UNSUPPORTED_ALERT_DESCRIPTION
		#error Alert descriptions need more code.
		case :
			alert_description = tls_alert_description_close_notify;
			break;
#endif //#if EAP_TLS_UNSUPPORTED_ALERT_DESCRIPTION
		case eap_status_unexpected_message:
			alert_description = tls_alert_description_unexpected_message;
			break;
		case eap_status_authentication_failure:
			alert_description = tls_alert_description_bad_record_mac;
			break;
		case eap_status_decryption_failure:
		case eap_status_illegal_padding:
			alert_description = tls_alert_description_decryption_failed;
			break;
#if EAP_TLS_UNSUPPORTED_ALERT_DESCRIPTION
		case :
			alert_description = tls_alert_description_record_overflow;
			break;
		case :
			alert_description = tls_alert_description_decompression_failure;
			break;
#endif //#if EAP_TLS_UNSUPPORTED_ALERT_DESCRIPTION
		case eap_status_illegal_cipher_suite:
			alert_description = tls_alert_description_handshake_failure;
			break;
		case eap_status_illegal_certificate:
		case eap_status_bad_certificate:
			alert_description = tls_alert_description_bad_certificate;
#if defined(USE_FAST_EAP_TYPE)
			if (m_eap_type == eap_type_fast
				&& par_result == eap_status_bad_certificate)
			{
				alert_level = tls_alert_level_fatal;
			}
			else
#endif //#if defined(USE_FAST_EAP_TYPE)
			{
				alert_level = tls_alert_level_warning;
			}
			break;
		case eap_status_unsupported_certificate:
			alert_description = tls_alert_description_unsupported_certificate;
			alert_level = tls_alert_level_warning;
			break;
		case eap_status_certificate_revoked:
			alert_description = tls_alert_description_certificate_revoked;
			alert_level = tls_alert_level_warning;
			break;
		case eap_status_certificate_expired:
			alert_description = tls_alert_description_certificate_expired;
			alert_level = tls_alert_level_warning;
			break;
		case eap_status_user_certificate_unknown:
		case eap_status_ca_certificate_unknown:
			alert_description = tls_alert_description_certificate_unknown;
			alert_level = tls_alert_level_warning;
			break;
		case eap_status_illegal_encryption_parameter_size:
		case eap_status_illegal_parameter:
			alert_description = tls_alert_description_illegal_parameter;
			break;
		case eap_status_unknown_ca:
			alert_description = tls_alert_description_unknown_ca;
			break;
		case eap_status_access_denied:
			alert_description = tls_alert_description_access_denied;
			break;
		case eap_status_process_illegal_packet_error:
		case eap_status_illegal_eap_code:
		case eap_status_illegal_eap_type:
		case eap_status_illegal_eap_identity:
		case eap_status_too_short_message:
		case eap_status_too_long_message:
		case eap_status_wrong_protocol:
		case eap_status_wrong_type:
		case eap_status_data_length_not_aligned_to_block_size:
		case eap_status_illegal_data_payload:
		case eap_status_illegal_payload:
		case eap_status_header_corrupted:
		case eap_status_illegal_nai:
		case eap_status_illegal_nai_payload:
			alert_description = tls_alert_description_decode_error;
			break;
#if EAP_TLS_UNSUPPORTED_ALERT_DESCRIPTION
		case :
			alert_description = tls_alert_description_decrypt_error;
			break;
		case :
			alert_description = tls_alert_description_export_restriction;
			break;
#endif //#if EAP_TLS_UNSUPPORTED_ALERT_DESCRIPTION
		case eap_status_no_matching_protocol_version:
			alert_description = tls_alert_description_protocol_version;
			break;
		case eap_status_insufficient_security:
			alert_description = tls_alert_description_insufficient_security;
			break;
		case eap_status_allocation_error:
		case eap_status_not_supported:
		case eap_status_process_general_error:
		case eap_status_type_does_not_exists_error:
		case eap_status_timed_out:
		case eap_status_hardware_not_ready:
			alert_description = tls_alert_description_internal_error;
			break;
#if EAP_TLS_UNSUPPORTED_ALERT_DESCRIPTION
		case :
			alert_description = tls_alert_description_user_canceled;
			break;
		case :
			alert_description = tls_alert_description_no_renegotiation;
			break;
#endif //#if EAP_TLS_UNSUPPORTED_ALERT_DESCRIPTION
		default:
			alert_description = tls_alert_description_internal_error;
			break;
		}
	}
	else
	{
		alert_description = par_alert_description;
	}

	if (alert_level == tls_alert_level_fatal
		&& m_could_send_fatal_alert_message == false)
	{
		// If alert message is received or we have sent a fatal alert, we do not send alert anymore.

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: message_function: create_tls_protocol_alert(), ")
			 EAPL("do not send fatal alert message\n"),
			 (m_is_client == true ? "client": "server")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, par_result);
	}

	if (alert_level == tls_alert_level_warning
		&& m_could_send_warning_alert_message == false)
	{
		// If alert message is received or we have sent a warning alert,
		// we do not send alert anymore.

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: message_function: create_tls_protocol_alert(), ")
			 EAPL("do not send warning alert message\n"),
			 (m_is_client == true ? "client": "server")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, par_result);
	}

	//--------------------------------------------------------------------


	set_state(tls_peap_state_failure);

	// This will cause the session terminate immediately.
	status = get_type_partner()->set_session_timeout(0ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               
	//                 | alert level   | alert descrip.|               
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                

	tls_alert_message_c * const tls_alert_message
		= new tls_alert_message_c(m_am_tools, m_is_client);

	eap_automatic_variable_c<tls_alert_message_c>
		automatic_tls_alert_message(m_am_tools, tls_alert_message);

	if (tls_alert_message == 0
		|| tls_alert_message->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// --------------------------------------------------------------------

	EAP_TRACE_ERROR(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: create_tls_protocol_alert(): Alert message %s:%s\n"),
		(m_is_client == true ? "client": "server"),
		 eap_tls_trace_string_c::get_alert_level_string(alert_level),
		 eap_tls_trace_string_c::get_alert_description_string(alert_description)));


	status = tls_alert_message->set_alert_level(alert_level);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = tls_alert_message->set_alert_description(alert_description);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	// Note add_record_message() frees message on any case.
	automatic_tls_alert_message.do_not_free_variable();

	status = add_record_message(tls_alert_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	m_force_tls_message_send = true;

	if (alert_level == tls_alert_level_fatal)
	{
		m_could_send_fatal_alert_message = false;
	}

	if (alert_level == tls_alert_level_warning)
	{
		m_could_send_warning_alert_message = false;
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::create_tls_application_data(
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::create_tls_application_data()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::create_tls_application_data()");

	// 0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                 | Application data n bytes                      |
	//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	tls_application_data_message_c * const tls_application_data_message
		= new tls_application_data_message_c(m_am_tools, m_is_client);

	eap_automatic_variable_c<tls_application_data_message_c>
		automatic_tls_application_data_message(
			m_am_tools, tls_application_data_message);

	if (tls_application_data_message == 0
		|| tls_application_data_message->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (sent_packet->get_data_length() < header_offset)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	u32_t packet_length = sent_packet->get_data_length()-header_offset;

	eap_status_e status = tls_application_data_message->set_application_data(
		sent_packet->get_data_offset(header_offset, packet_length),
		packet_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	// Note add_record_message() frees message on any case.
	automatic_tls_application_data_message.do_not_free_variable();

	status = add_record_message(tls_application_data_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// --------------------------------------------------------------------

	if (status == eap_status_ok)
	{
		status = check_sent_tls_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// --------------------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_c::cipher_suite_is_3DES_EDE_CBC_SHA(
	tls_cipher_suites_e cipher_suite) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (cipher_suite == tls_cipher_suites_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
		|| cipher_suite == tls_cipher_suites_TLS_RSA_WITH_3DES_EDE_CBC_SHA
		|| cipher_suite == tls_cipher_suites_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA)
	{
		return true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_c::cipher_suite_is_AES_128_CBC_SHA(
	tls_cipher_suites_e cipher_suite) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (cipher_suite == tls_cipher_suites_TLS_DHE_DSS_WITH_AES_128_CBC_SHA
		|| cipher_suite == tls_cipher_suites_TLS_RSA_WITH_AES_128_CBC_SHA
		|| cipher_suite == tls_cipher_suites_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
#if defined(USE_FAST_EAP_TYPE)
		|| cipher_suite == tls_cipher_suites_TLS_DH_anon_WITH_AES_128_CBC_SHA
#endif //#if defined(USE_FAST_EAP_TYPE)
		)
	{
		return true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_c::cipher_suite_is_RC4_128_MD5(
	tls_cipher_suites_e cipher_suite) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (cipher_suite == tls_cipher_suites_TLS_RSA_WITH_RC4_128_MD5)
	{
		return true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_c::cipher_suite_is_RC4_128_SHA(
	tls_cipher_suites_e cipher_suite) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (cipher_suite == tls_cipher_suites_TLS_RSA_WITH_RC4_128_SHA)
	{
		return true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_c::cipher_suite_is_TLS_RSA() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_selected_cipher_suite == tls_cipher_suites_TLS_RSA_WITH_3DES_EDE_CBC_SHA
		|| m_selected_cipher_suite == tls_cipher_suites_TLS_RSA_WITH_AES_128_CBC_SHA
		|| m_selected_cipher_suite == tls_cipher_suites_TLS_RSA_WITH_RC4_128_MD5
		|| m_selected_cipher_suite == tls_cipher_suites_TLS_RSA_WITH_RC4_128_SHA)
	{
		return true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_c::cipher_suite_is_TLS_DHE_RSA() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_selected_cipher_suite == tls_cipher_suites_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
		|| m_selected_cipher_suite == tls_cipher_suites_TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
	{
		return true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_record_c::cipher_suite_is_TLS_DHE_DSS() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_selected_cipher_suite == tls_cipher_suites_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
		|| m_selected_cipher_suite == tls_cipher_suites_TLS_DHE_DSS_WITH_AES_128_CBC_SHA)
	{
		return true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return false;
}

//--------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

EAP_FUNC_EXPORT bool tls_record_c::cipher_suite_is_TLS_DH_anon() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_selected_cipher_suite == tls_cipher_suites_TLS_DH_anon_WITH_AES_128_CBC_SHA)
	{
		return true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return false;
}

#endif //#if defined(USE_FAST_EAP_TYPE)

//--------------------------------------------------

#if EAP_TLS_UNSUPPORTED_CIPHER_SUITE
#error This one needs more code. Diffie-Hellman sertificate key exchange with different parameters is NOT supported.
EAP_FUNC_EXPORT bool tls_record_c::cipher_suite_is_TLS_DH_DSS() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_selected_cipher_suite == tls_cipher_suites_TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA)
	{
		return true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return false;
}
#endif

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::generate_dhe_keys()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s:     key_function: starts: tls_record_c::generate_dhe_keys()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::generate_dhe_keys()");

	eap_status_e status = eap_status_not_supported;

	if (cipher_suite_is_TLS_DHE_DSS() == true
		|| cipher_suite_is_TLS_DHE_RSA() == true
#if defined(USE_FAST_EAP_TYPE)
		|| (m_eap_type == eap_type_fast
			&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
			&& cipher_suite_is_TLS_DH_anon() == true)
#endif //#if defined(USE_FAST_EAP_TYPE)
		)
	{
		if (m_dhe_prime.get_is_valid_data() == false
			|| m_dhe_group_generator.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		crypto_ephemeral_diffie_hellman_c dhe(m_am_tools);

		if (dhe.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s:     key_function: dhe.generate_diffie_hellman_keys()\n"),
			(m_is_client == true ? "client": "server")));

		status = dhe.generate_diffie_hellman_keys(
			&m_own_private_dhe_key,
			&m_own_public_dhe_key,
			m_dhe_prime.get_data(m_dhe_prime.get_data_length()),
			m_dhe_prime.get_data_length(),
			m_dhe_group_generator.get_data(m_dhe_group_generator.get_data_length()),
			m_dhe_group_generator.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::generate_premaster_secret()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s:     key_function: starts: tls_record_c::generate_premaster_secret()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::generate_premaster_secret()");

	eap_status_e status = eap_status_not_supported;

	m_key_material_generated = false;

	if (cipher_suite_is_TLS_RSA() == true)
	{
		// Encrypted premaster secret is included when selected
		// cipher suite is using RSA key exchange.
		// First two bytes are version of TLS.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 |                                               |
		// +-+-+-+-+-+-+-+-+                                               +
		// |                                                               |
		// +                                                               +
		// |                Encrypted Premaster Secret (48 bytes)          |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		crypto_random_c rand(m_am_tools);

		status = m_premaster_secret.set_buffer_length(TLS_PREMASTER_SECRET_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		m_premaster_secret.set_data_length(TLS_PREMASTER_SECRET_SIZE);

		u16_t version = eap_htons(tls_version_3_1);
		status = m_premaster_secret.add_data_to_offset(0ul, &version, sizeof(version));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (m_premaster_secret.get_data_length() < sizeof(version))
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = rand.get_rand_bytes(
			m_premaster_secret.get_data_offset(
				sizeof(version),
				m_premaster_secret.get_data_length()-sizeof(version)),
			m_premaster_secret.get_data_length()-sizeof(version));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: m_premaster_secret"),
			m_premaster_secret.get_data(m_premaster_secret.get_data_length()),
			m_premaster_secret.get_data_length()));
	}
	else if (cipher_suite_is_TLS_DHE_DSS() == true
		|| cipher_suite_is_TLS_DHE_RSA() == true
#if defined(USE_FAST_EAP_TYPE)
		|| (m_eap_type == eap_type_fast
			&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
			&& cipher_suite_is_TLS_DH_anon() == true)
#endif //#if defined(USE_FAST_EAP_TYPE)
		)
	{
		// Diffie-Hellman Yc is included when selected cipher suite is
		// ephemeral Diffie-Hellman key exchange.
		// 0                   1                   2                   3   
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		//                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//                 | DH Yc length                  |               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
		// |                                                               |
		// +                                                               +
		// |                DH Yc value                                    |
		// +                                                               +
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		if (m_dhe_prime.get_is_valid_data() == false
			|| m_dhe_group_generator.get_is_valid_data() == false
			|| m_peer_public_dhe_key.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		crypto_ephemeral_diffie_hellman_c dhe(m_am_tools);

		if (dhe.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s:     key_function: dhe.generate_g_power_to_xy()\n"),
			(m_is_client == true ? "client": "server")));

		status = dhe.generate_g_power_to_xy(
			&m_own_private_dhe_key,
			&m_peer_public_dhe_key,
			&m_premaster_secret,
			m_dhe_prime.get_data(m_dhe_prime.get_data_length()),
			m_dhe_prime.get_data_length(),
			m_dhe_group_generator.get_data(m_dhe_group_generator.get_data_length()),
			m_dhe_group_generator.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: m_premaster_secret"),
			m_premaster_secret.get_data(m_premaster_secret.get_data_length()),
			m_premaster_secret.get_data_length()));
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::generate_master_secret()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s:     key_function: starts: tls_record_c::generate_master_secret()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::generate_master_secret()");

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: tls_record_c::generate_master_secret(): m_premaster_secret"),
		m_premaster_secret.get_data(),
		m_premaster_secret.get_data_length()));

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: tls_record_c::generate_master_secret(): m_client_handshake_random_value"),
		m_client_handshake_random_value.get_data(),
		m_client_handshake_random_value.get_data_length()));

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: tls_record_c::generate_master_secret(): m_server_handshake_random_value"),
		m_server_handshake_random_value.get_data(),
		m_server_handshake_random_value.get_data_length()));

	if (m_premaster_secret.get_is_valid_data() == false
		|| m_client_handshake_random_value.get_is_valid_data() == false
		|| m_server_handshake_random_value.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = eap_status_not_supported;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s:     prf_function: tls_prf.tls_prf_output()\n"),
		(m_is_client == true ? "client": "server")));

	crypto_tls_prf_c tls_prf(m_am_tools);

	eap_variable_data_c label(m_am_tools);
	if (label.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = label.add_data(
		TLS_MASTER_SECRET_LABEL,
		TLS_MASTER_SECRET_LABEL_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c seed(m_am_tools);
	if (seed.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	status = seed.set_copy_of_buffer(&m_client_handshake_random_value);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = seed.add_data(&m_server_handshake_random_value);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = tls_prf.tls_prf_init(
		&m_premaster_secret,
		&label,
		&seed);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_master_secret.set_buffer_length(TLS_MASTER_SECRET_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	m_master_secret.set_data_length(TLS_MASTER_SECRET_SIZE);

	status = tls_prf.tls_prf_output(
		m_master_secret.get_data(m_master_secret.get_data_length()),
		m_master_secret.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: tls_record_c::generate_master_secret(): m_master_secret"),
		m_master_secret.get_data(),
		m_master_secret.get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

EAP_FUNC_EXPORT eap_status_e tls_record_c::generate_eap_fast_master_secret_from_pac_key(
	const eap_variable_data_c * const pac_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s:     key_function: starts: tls_record_c::generate_eap_fast_master_secret_from_pac_key()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::generate_eap_fast_master_secret_from_pac_key()");

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: tls_record_c::generate_eap_fast_master_secret_from_pac_key(): PAC_Key"),
		pac_key->get_data(),
		pac_key->get_data_length()));

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: tls_record_c::generate_eap_fast_master_secret_from_pac_key(): m_server_handshake_random_value"),
		m_server_handshake_random_value.get_data(),
		m_server_handshake_random_value.get_data_length()));

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: tls_record_c::generate_eap_fast_master_secret_from_pac_key(): m_client_handshake_random_value"),
		m_client_handshake_random_value.get_data(),
		m_client_handshake_random_value.get_data_length()));

	if (pac_key == 0
		|| pac_key->get_is_valid_data() == false
		|| m_client_handshake_random_value.get_is_valid_data() == false
		|| m_server_handshake_random_value.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_not_supported);

	
	crypto_eap_fast_hmac_sha1_prf_c tls_prf(m_am_tools);

	eap_variable_data_c label(m_am_tools);
	if (label.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = label.add_data(
		EAP_FAST_PAC_TO_MASTER_SECRET_LABEL,
		EAP_FAST_PAC_TO_MASTER_SECRET_LABEL_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c seed(m_am_tools);
	if (seed.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = seed.set_copy_of_buffer(&m_server_handshake_random_value);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = seed.add_data(&m_client_handshake_random_value);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = tls_prf.t_prf_init(
		pac_key,
		&label,
		&seed);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_master_secret.set_buffer_length(TLS_MASTER_SECRET_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	m_master_secret.set_data_length(TLS_MASTER_SECRET_SIZE);

	status = tls_prf.t_prf_output(
		m_master_secret.get_data(),
		static_cast<u16_t>(m_master_secret.get_data_length()));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("EAP-FAST: m_master_secret"),
		m_master_secret.get_data(),
		m_master_secret.get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_FAST_EAP_TYPE)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_query_cipher_suites_and_previous_session(
	const tls_session_type_e /* tls_session_type */,
	EAP_TEMPLATE_CONST eap_array_c<u16_t> * const cipher_suites,
	EAP_TEMPLATE_CONST eap_array_c<u8_t> * const compression_methods,
#if defined(USE_EAP_TLS_SESSION_TICKET)
	EAP_TEMPLATE_CONST eap_array_c<tls_extension_c> * const tls_extensions,
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
	const eap_variable_data_c * const resumed_session_id,
	const eap_variable_data_c * const resumed_master_secret,
	const tls_cipher_suites_e resumed_cipher_suite,
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::complete_query_cipher_suites_and_previous_session()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_query_cipher_suites_and_previous_session()");

	m_pending_query_cipher_suites_and_previous_session = false;

	m_proposed_cipher_suites.reset();
	m_proposed_compression_methods.reset();

	eap_status_e status = eap_status_process_general_error;


	if (completion_status != eap_status_ok)
	{
		status = create_tls_protocol_alert(
			tls_alert_description_none,
			tls_alert_level_none,
			completion_status);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = copy_simple<u16_t>(
			cipher_suites,
			&m_proposed_cipher_suites,
			m_am_tools,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = for_each<u16_t>(&m_proposed_cipher_suites, u16_t_to_host_order, m_am_tools, false);
		if (status != eap_status_ok
			|| m_proposed_cipher_suites.get_object_count() == 0ul)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

#if defined(USE_FAST_EAP_TYPE)
		if (m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == false)
		{
			// TLS_DH_anon_WITH_AES_128_CBC_SHA is allowed only with EAP-FAST unauthenticated provisioning mode.
			u16_t illegal_cipher_suite(static_cast<u16_t>(tls_cipher_suites_TLS_DH_anon_WITH_AES_128_CBC_SHA));

			i32_t index = find_simple(
				&m_proposed_cipher_suites,
				&illegal_cipher_suite,
				m_am_tools);
			if (index >= 0)
			{
				status = m_proposed_cipher_suites.remove_object(index);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
#endif //#if defined(USE_FAST_EAP_TYPE)

		status = copy_simple<u8_t>(
			compression_methods,
			&m_proposed_compression_methods,
			m_am_tools,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}



#if defined(USE_FAST_EAP_TYPE)
		if (m_eap_type == eap_type_fast
			&& m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption)
		{
			// Let's try tunnel PAC authentication.

			// We will use the first cipher suite as an default one.
			u16_t * cipher_suite = m_proposed_cipher_suites.get_object(0ul);
			if (cipher_suite != 0)
			{
				m_resumed_cipher_suite = static_cast<tls_cipher_suites_e>(*cipher_suite);
			}
			else
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}
		}
		else
#endif //#if defined(USE_FAST_EAP_TYPE)
		if (resumed_session_id != 0
			&& resumed_session_id->get_is_valid_data() == true
			&& resumed_session_id->get_data_length() > 0ul
			&& resumed_master_secret != 0
			&& resumed_master_secret->get_is_valid_data() == true
			&& resumed_master_secret->get_data_length() == TLS_MASTER_SECRET_SIZE
			&& resumed_cipher_suite != tls_cipher_suites_none)
		{
			// Resume previous session.

			status = m_session_id.set_copy_of_buffer(resumed_session_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_master_secret.set_copy_of_buffer(resumed_master_secret);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: message_function: complete_query_cipher_suites_and_previous_session(): ")
				 EAPL("Resume previous session.\n"),
				 (m_is_client == true ? "client": "server")));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: complete_query_cipher_suites_and_previous_session(): resumed m_master_secret"),
				 m_master_secret.get_data(m_master_secret.get_data_length()),
				 m_master_secret.get_data_length()));

			m_resumed_cipher_suite = resumed_cipher_suite;

			set_tls_session_type(tls_session_type_original_session_resumption);
		}
		else
		{

#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
			if (m_is_client == true
				&& m_tls_use_identity_privacy == true
				&& m_tls_identity_privacy_handshake_state == tls_identity_privacy_handshake_state_none)
			{
				set_tls_identity_privacy_handshake_state(tls_identity_privacy_handshake_state_negotiates);
			}
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)

			set_tls_session_type(tls_session_type_full_authentication);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: message_function: complete_query_cipher_suites_and_previous_session(): ")
				 EAPL("full authentication.\n"),
				 (m_is_client == true ? "client": "server")));

			eap_status_e notification_status = indicate_state_to_lower_layer(
				tls_peap_state_full_authentication);
			if (notification_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, notification_status);
			}
		}

#if defined(USE_EAP_TLS_SESSION_TICKET)
		if (tls_extensions != 0)
		{

#if defined(USE_FAST_EAP_TYPE)
			if (m_eap_type == eap_type_fast)
			{
				// Nothing to do.
			}
			else
#endif //#if defined(USE_FAST_EAP_TYPE)
			{
				status = copy<tls_extension_c>(
					tls_extensions,
					&m_supported_tls_extensions,
					m_am_tools,
					false);
			}

			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

#if defined(USE_FAST_EAP_TYPE)
			eap_fast_pac_type_e required_pac_type(eap_fast_pac_type_none);

			if (m_eap_type == eap_type_fast)
			{
				// In EAP-FAST we are interested only Tunnel PAC.
				required_pac_type = eap_fast_pac_type_tunnel_pac;
			}
#endif //#if defined(USE_FAST_EAP_TYPE)

			const tls_extension_c * const supported_session_ticket_extension = tls_extension_c::get_tls_extension(
				tls_extension_type_session_ticket,
#if defined(USE_FAST_EAP_TYPE)
				required_pac_type,
#endif //#if defined(USE_FAST_EAP_TYPE)
				&m_supported_tls_extensions,
				m_am_tools);

			if (supported_session_ticket_extension != 0
				&& supported_session_ticket_extension->get_is_valid_data() == true
				&& supported_session_ticket_extension->get_data_length() > 0ul)
			{
#if defined(USE_FAST_EAP_TYPE)
				if (m_eap_type == eap_type_fast)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("TLS: %s: message_function: complete_query_cipher_suites_and_previous_session(): ")
						 EAPL("SST: EAP-FAST PAC stateless session resumption, length = %d.\n"),
						 (m_is_client == true ? "client": "server"),
						 supported_session_ticket_extension->get_data_length()));
				}
				else
#endif //#if defined(USE_FAST_EAP_TYPE)
				//if (m_tls_session_type == tls_session_type_original_session_resumption)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("TLS: %s: message_function: complete_query_cipher_suites_and_previous_session(): ")
						 EAPL("SST: stateless session resumption, length = %d.\n"),
						 (m_is_client == true ? "client": "server"),
						 supported_session_ticket_extension->get_data_length()));

					set_tls_session_type(tls_session_type_stateless_session_resumption);
				}
			}
		}
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)


#if defined(USE_FAST_EAP_TYPE)
		if (m_eap_type == eap_type_fast
			//&& m_tls_session_type == tls_session_type_full_authentication
			&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true)
		{
			// Try dynamic provisioning of PAC.

			set_tls_session_type(tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: message_function: complete_query_cipher_suites_and_previous_session(): ")
				 EAPL("server unauthenticated provisioning mode ADHP.\n"),
				 (m_is_client == true ? "client": "server")));

			m_proposed_cipher_suites.reset();

			u16_t * const anonymous_cipher_suite = new u16_t;

			if (anonymous_cipher_suite == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			
			*anonymous_cipher_suite = static_cast<u16_t>(tls_cipher_suites_TLS_DH_anon_WITH_AES_128_CBC_SHA);

			status = m_proposed_cipher_suites.add_object(
				anonymous_cipher_suite,
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: complete_query_cipher_suites_and_previous_session(): ")
				 EAPL("m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP = %d.\n"),
				 (m_is_client == true ? "client": "server"),
				 m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP));
		}
#endif //#if defined(USE_FAST_EAP_TYPE)


	}


	if (status == eap_status_ok)
	{
		status = check_sent_tls_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_status_completed_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_select_cipher_suite_and_check_session_id(
	const tls_session_type_e tls_session_type,
	const u16_t selected_cipher_suite,
	const eap_variable_data_c * const resumed_session_id,
	const eap_variable_data_c * const resumed_master_secret,
#if defined(USE_EAP_TLS_SESSION_TICKET)
	const tls_extension_c * const new_session_ticket_or_null,
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::complete_select_cipher_suite_and_check_session_id()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_select_cipher_suite_and_check_session_id()");

	EAP_ASSERT_ALWAYS(m_is_client == false);

	eap_status_e status = eap_status_ok;

	m_pending_select_cipher_suite_and_check_session_id = false;


	if (completion_status != eap_status_ok)
	{
		status = create_tls_protocol_alert(
			tls_alert_description_none,
			tls_alert_level_none,
			completion_status);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		set_tls_session_type(tls_session_type);

		set_selected_cipher_suite(static_cast<tls_cipher_suites_e>(selected_cipher_suite));
		m_selected_compression_method = tls_compression_method_null;

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_FAST_EAP_TYPE)
		if (m_eap_type == eap_type_fast
			&& m_tls_session_type == tls_session_type_full_authentication
			&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == true
			&& m_selected_cipher_suite == tls_cipher_suites_TLS_DH_anon_WITH_AES_128_CBC_SHA)
		{
			// Try dynamic provisioning of PAC.

			set_tls_session_type(tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP);
		}
#endif //#if defined(USE_FAST_EAP_TYPE)

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_TLS_SESSION_TICKET)
		if (new_session_ticket_or_null != 0)
		{
			// We are using the session ticket payload.

			tls_extension_c * copy_of_new_session_ticket = new_session_ticket_or_null->copy();
			if (copy_of_new_session_ticket == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// Save the new session ticket to be included in next NewSessionTicket message.
			status = m_supported_tls_extensions.add_object(copy_of_new_session_ticket, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (m_tls_session_type == tls_session_type_stateless_session_resumption)
		{
			if (resumed_session_id != 0
				&& resumed_session_id->get_is_valid_data() == true)
			{
				// The session ID is needed if client did include it to the ClientHello.
				status = m_session_id.set_copy_of_buffer(resumed_session_id);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			if (resumed_master_secret != 0
				&& resumed_master_secret->get_is_valid_data() == true
				&& resumed_master_secret->get_data_length() == TLS_MASTER_SECRET_SIZE)
			{
				status = m_master_secret.set_copy_of_buffer(resumed_master_secret);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: complete_select_cipher_suite_and_check_session_id(): session ticket resumed m_master_secret"),
					 m_master_secret.get_data(m_master_secret.get_data_length()),
					 m_master_secret.get_data_length()));

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: %s: message_function: ")
					 EAPL("complete_select_cipher_suite_and_check_session_id(): restores session using session ticket\n"),
					 (m_is_client == true ? "client": "server")));

				eap_status_e notification_status = indicate_state_to_lower_layer(
					tls_peap_state_original_session_resumption);
				if (notification_status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, notification_status);
				}
			}
		}
		else
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
		if (m_tls_session_type == tls_session_type_original_session_resumption
			&& ((m_eap_type == eap_type_peap
				/** @{ PEAPv2 does not support session resumption yet. } */
				&& m_peap_version != peap_version_2)
				|| m_eap_type == eap_type_tls
				|| m_eap_type == eap_type_ttls
#if defined(USE_FAST_EAP_TYPE)
				|| m_eap_type == eap_type_fast
#endif //#if defined(USE_FAST_EAP_TYPE)
				)
			&& resumed_session_id != 0
			&& resumed_session_id->get_is_valid_data() == true
			&& resumed_session_id->get_data_length() > 0ul
			&& resumed_master_secret != 0
			&& resumed_master_secret->get_is_valid_data() == true
			&& resumed_master_secret->get_data_length() == TLS_MASTER_SECRET_SIZE
			)
		{
			// Restore previous session.

			status = m_session_id.set_copy_of_buffer(resumed_session_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_master_secret.set_copy_of_buffer(resumed_master_secret);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: complete_select_cipher_suite_and_check_session_id(): resumed m_master_secret"),
				 m_master_secret.get_data(m_master_secret.get_data_length()),
				 m_master_secret.get_data_length()));

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: message_function: ")
				 EAPL("complete_select_cipher_suite_and_check_session_id(): restores session\n"),
				 (m_is_client == true ? "client": "server")));

			eap_status_e notification_status = indicate_state_to_lower_layer(
				tls_peap_state_original_session_resumption);
			if (notification_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, notification_status);
			}
		}
#if defined(USE_FAST_EAP_TYPE)
		else if (m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: complete_select_cipher_suite_and_check_session_id(): EAP-FAST server: %s\n"),
				eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type)));

			// Parameter resumed_master_secret includes PAC-Key.
			status = m_eap_fast_pac_key.set_copy_of_buffer(resumed_master_secret);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: complete_select_cipher_suite_and_check_session_id(): resumed m_master_secret"),
				 m_master_secret.get_data(m_master_secret.get_data_length()),
				 m_master_secret.get_data_length()));

			eap_status_e notification_status = indicate_state_to_lower_layer(
				tls_peap_state_original_session_resumption);
			if (notification_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, notification_status);
			}
		}
		else if (m_tls_session_type == tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: complete_select_cipher_suite_and_check_session_id(): EAP-FAST server unauthenticated provisioning mode\n")));

			eap_status_e notification_status = indicate_state_to_lower_layer(
				tls_peap_state_full_authentication);
			if (notification_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, notification_status);
			}
		}
#endif //#if defined(USE_FAST_EAP_TYPE)
		else
		{
			set_tls_session_type(tls_session_type_full_authentication);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: complete_select_cipher_suite_and_check_session_id(): full authentication\n")));

			eap_status_e notification_status = indicate_state_to_lower_layer(
				tls_peap_state_full_authentication);
			if (notification_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, notification_status);
			}
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_TLS_SESSION_TICKET)

#if defined(USE_FAST_EAP_TYPE)
		if (m_eap_type != eap_type_fast)
#endif //#if defined(USE_FAST_EAP_TYPE)
		{
			if (m_tls_session_type == tls_session_type_original_session_resumption
				|| m_tls_session_type == tls_session_type_stateless_session_resumption)
			{
				const tls_extension_c * const supported_session_ticket_extension = tls_extension_c::get_tls_extension(
						tls_extension_type_session_ticket,
						&m_supported_tls_extensions,
						m_am_tools);
				if (supported_session_ticket_extension != 0)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("TLS: %s: message_function: complete_select_cipher_suite_and_check_session_id(): ")
						 EAPL("SST: Server will send a new session ticket to client, length = %d.\n"),
						 (m_is_client == true ? "client": "server"),
						 supported_session_ticket_extension->get_data_length()));

					// Server will send a new session ticket to client.
					status = completion_action_add(
						tls_completion_action_create_handshake_type_new_session_ticket);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
		}

#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)


		// The following sequence depends on whether the previous
		// session is restored and on the selected cipher suite.

		if (m_tls_session_type == tls_session_type_original_session_resumption
#if defined(USE_EAP_TLS_SESSION_TICKET)
			|| m_tls_session_type == tls_session_type_stateless_session_resumption
#if defined(USE_FAST_EAP_TYPE)
			|| m_tls_session_type == tls_session_type_eap_fast_pac_session_resumption
#endif //#if defined(USE_FAST_EAP_TYPE)
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
			)
		{
#if defined(USE_EAP_TLS_SESSION_TICKET)
			if (m_will_receive_new_session_ticket == true)
			{
				set_state(tls_peap_state_wait_handshake_type_new_session_ticket);
			}
			else
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
			{
				set_state(tls_peap_state_wait_change_cipher_spec);
			}

			status = completion_action_add(
				tls_completion_action_create_change_cipher_spec_type_change_cipher_spec);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = completion_action_add(tls_completion_action_create_handshake_type_finished);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
#if defined(USE_FAST_EAP_TYPE)
		else if (m_tls_session_type == tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP)
		{
			// Ephemeral DH key exchange causes creation of server_key_exchange message.
			// Server sends DH public key and related parameters to client.

			status = completion_action_add(tls_completion_action_query_dh_parameters);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = completion_action_add(
				tls_completion_action_create_handshake_type_server_key_exchange);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// This will complete creation of handshake_type_server_key_exchange message.
			status = completion_action_add(
				tls_completion_action_complete_create_handshake_type_server_key_exchange);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Also the other pending messages will be processed after this action is completed.
			eap_status_e compl_status = completion_action_add(
				tls_completion_action_process_tls_records);
			if (compl_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = completion_action_add(
				tls_completion_action_create_handshake_type_server_hello_done);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			set_state(tls_peap_state_wait_handshake_type_client_key_exchange);
		}
#endif //#if defined(USE_FAST_EAP_TYPE)
		else
		{
			if (m_tls_peap_server_authenticates_client_config_server == true)
			{
				set_state(tls_peap_state_wait_handshake_type_certificate);
			}
			else
			{
				set_state(tls_peap_state_wait_handshake_type_client_key_exchange);
			}

			status = completion_action_add(tls_completion_action_create_handshake_type_certificate);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (cipher_suite_is_TLS_DHE_DSS() == true
				|| cipher_suite_is_TLS_DHE_RSA() == true)
			{
				// Ephemeral DH key exchange causes creation of server_key_exchange message.
				// Server sends DH public key and related parameters to client.

				status = completion_action_add(tls_completion_action_query_dh_parameters);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = completion_action_add(
					tls_completion_action_create_handshake_type_server_key_exchange);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// This will complete creation of handshake_type_server_key_exchange message.
				status = completion_action_add(
					tls_completion_action_complete_create_handshake_type_server_key_exchange);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// Also the other pending messages will be processed after this action is completed.
				eap_status_e compl_status = completion_action_add(
					tls_completion_action_process_tls_records);
				if (compl_status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			if (m_tls_peap_server_authenticates_client_config_server == true)
			{
				// Server initiates client authentication.
				status = completion_action_add(
					tls_completion_action_create_handshake_type_certificate_request);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			
			status = completion_action_add(
				tls_completion_action_create_handshake_type_server_hello_done);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: pki_function: query_certificate_chain()\n"),
				(m_is_client == true ? "client": "server")));

			status = m_am_tls_services->query_certificate_chain(
				&m_own_certificate_authorities,
				&m_own_certificate_types,
				m_selected_cipher_suite);
			if (status == eap_status_pending_request)
			{
				// This is pending query, that will be completed by
				// complete_query_certificate_chain() call.
				m_pending_query_certificate_chain = true;
			}
			else if (status == eap_status_completed_request)
			{
				// This is already completed by complete_query_certificate_chain() call.
			}
			else if (status == eap_status_ok)
			{
				// This is also an error case, because this call is always completed on success. 
				status = eap_status_process_general_error;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else // All other status values means error, because this
				// call is always completed on success.
			{
				// This is an error case.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			if (m_tls_peap_server_authenticates_client_config_server == true)
			{
				// Server initiates client authentication.
				status = m_am_tls_services->query_certificate_authorities_and_types();
				if (status == eap_status_pending_request)
				{
					// This is pending query, that will be completed by
					// complete_query_certificate_authorities_and_types() call.
					m_pending_query_certificate_authorities_and_types = true;
				}
				else if (status == eap_status_completed_request)
				{
					// This is already completed by
					// complete_query_certificate_authorities_and_types() call.
				}
				else if (status == eap_status_ok)
				{
					// This is also an error case, because this call is
					// always completed on success. 
					status = eap_status_process_general_error;
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else // All other status values means error, because this
					// call is always completed on success.
				{
					// This is an error case.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN_AND_CREATE_TLS_PROTOCOL_ALERT(m_am_tools, status);
				}
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (status == eap_status_ok)
	{
		status = check_sent_tls_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_status_completed_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TLS_SESSION_TICKET)

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_query_new_session_ticket(
	const tls_extension_c * const new_session_ticket_or_null)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: pki_function: starts: tls_record_c::complete_query_new_session_ticket()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_query_new_session_ticket()");

	eap_status_e status(eap_status_ok);

	if (new_session_ticket_or_null != 0)
	{
		tls_extension_c * const copy_of_session_ticket = new_session_ticket_or_null->copy();

		if (copy_of_session_ticket == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = m_supported_tls_extensions.add_object(copy_of_session_ticket, true);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_verify_certificate_chain(
	const eap_status_e result)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: pki_function: starts: tls_record_c::complete_verify_certificate_chain()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_verify_certificate_chain()");

	eap_status_e status = result;

	m_pending_verify_certificate_chain = false;

	m_peer_certificate_chain_result = result;

	if (m_peer_certificate_chain_result == eap_status_ok)
	{
		// Ok certificate.
	}
	else
	{
		// Illegal certificate.

		status = create_tls_protocol_alert(
			tls_alert_description_none,
			tls_alert_level_none,
			m_peer_certificate_chain_result);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (status == eap_status_ok)
	{
		status = check_sent_tls_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_status_completed_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_query_certificate_chain(
	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain,
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::complete_query_certificate_chain()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_query_certificate_chain()");

	eap_status_e status = eap_status_not_supported;

	m_pending_query_certificate_chain = false;

	{
		if (completion_status != eap_status_ok
			|| certificate_chain == 0
			|| certificate_chain->get_object_count() == 0)
		{
			if (completion_status != eap_status_ok)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WARNING: TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::complete_query_certificate_chain(): No certificate chain configured.\n"),
					 this,
					 (m_is_client == true ? "client": "server")));
			}

			if (m_is_client == false)
			{
				// Server fails immediately.

				status = create_tls_protocol_alert(
					tls_alert_description_none,
					tls_alert_level_none,
					completion_status);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: TLS: %s: pki_function: complete_query_certificate_chain(): ")
					 EAPL("Server have illegal sertificate for this cipher suite.\n"),
					(m_is_client == true ? "client": "server")));
			}
			else
			{
				if (m_tls_peap_server_authenticates_client_policy_flag == true
					|| (m_tls_peap_server_authenticates_client_policy_flag == false
						&& completion_status != eap_status_illegal_certificate
						&& completion_status != eap_status_ca_certificate_unknown))
				{
					// Client does fail immediately.
					// This session could NOT use server only authentication.
					if (completion_status == eap_status_illegal_certificate)
					{
						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: TLS: %s: pki_function: complete_query_certificate_chain(): ")
							 EAPL("Client have illegal sertificate for this cipher suite.\n"),
							(m_is_client == true ? "client": "server")));

						status = eap_status_illegal_certificate;
						(void)EAP_STATUS_RETURN(m_am_tools, status);
					}
					else
					{
						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: TLS: %s: pki_function: complete_query_certificate_chain(): ")
							 EAPL("Client does NOT allow anonymous client.\n"),
							(m_is_client == true ? "client": "server")));

						status = eap_status_insufficient_security;
						(void)EAP_STATUS_RETURN(m_am_tools, status);
					}

					// This will cause the session terminate immediately.
					status = get_type_partner()->set_session_timeout(0ul);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

#if defined(USE_FAST_EAP_TYPE)
					if (m_eap_type == eap_type_fast)
					{
						send_error_notification(eap_status_no_pac_nor_certs_to_authenticate_with_provision_disabled);

						status = create_tls_protocol_alert(
								tls_alert_description_internal_error,
								tls_alert_level_fatal,
								status);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
					else
#endif //#if defined(USE_FAST_EAP_TYPE)
					{
						status = create_tls_protocol_alert(
								tls_alert_description_none,
								tls_alert_level_none,
								completion_status);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
				}
				else
				{

#if defined(USE_FAST_EAP_TYPE)
					if (m_eap_type == eap_type_fast
						&& m_eap_fast_allow_server_unauthenticated_provisioning_mode_ADHP == false
						&& m_fast_allow_server_authenticated_provisioning_mode == false)
					{
						// No PAC, no sertificate, no provision allowed.
						// This will cause the session terminate immediately.
						status = get_type_partner()->set_session_timeout(0ul);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						send_error_notification(eap_status_no_pac_nor_certs_to_authenticate_with_provision_disabled);

						status = create_tls_protocol_alert(
								tls_alert_description_internal_error,
								tls_alert_level_fatal,
								status);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
					else
#endif //#if defined(USE_FAST_EAP_TYPE)
					{
						// Client does not fail immediately.
						// This session could use server only authentication.
						// NOTE, in this case client must send empty certificate message to server.
						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("INFO: TLS: %s: pki_function: complete_query_certificate_chain(): ")
							 EAPL("Client allows anonymous client.\n"),
							(m_is_client == true ? "client": "server")));

						m_tls_peap_server_authenticates_client_action = false;
						status = eap_status_ok;
					}
				}
			}
		}
		else
		{
			status = copy<eap_variable_data_c>(
				certificate_chain,
				&m_own_certificate_chain,
				m_am_tools,
				false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	if (status == eap_status_ok)
	{
		status = check_sent_tls_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_status_completed_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_query_certificate_authorities_and_types(
	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_authorities,
	EAP_TEMPLATE_CONST eap_array_c<u8_t> * const certificate_types,
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::complete_query_certificate_authorities_and_types()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_query_certificate_authorities_and_types()");

	m_pending_query_certificate_authorities_and_types = false;

	eap_status_e status = eap_status_not_supported;

	if (completion_status != eap_status_ok)
	{
		status = create_tls_protocol_alert(
			tls_alert_description_none,
			tls_alert_level_none,
			completion_status);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = copy<eap_variable_data_c>(
			certificate_authorities,
			&m_own_certificate_authorities,
			m_am_tools,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = copy_simple<u8_t>(
			certificate_types,
			&m_own_certificate_types,
			m_am_tools,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	if (status == eap_status_ok)
	{
		status = check_sent_tls_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_status_completed_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_query_dh_parameters(
	const eap_variable_data_c * const dhe_prime,
	const eap_variable_data_c * const dhe_group_generator,
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: pki_function: starts: tls_record_c::complete_query_dh_parameters()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_query_dh_parameters()");

	m_pending_query_dh_parameters = false;

	eap_status_e status = eap_status_not_supported;

	if (completion_status != eap_status_ok)
	{
		status = create_tls_protocol_alert(
			tls_alert_description_none,
			tls_alert_level_none,
			completion_status);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = m_dhe_prime.set_copy_of_buffer(dhe_prime);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_dhe_group_generator.set_copy_of_buffer(dhe_group_generator);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (status == eap_status_ok)
	{
		status = check_sent_tls_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_status_completed_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_query_realm(
	const eap_variable_data_c * const realm,
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::complete_query_realm()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_query_realm()");

	m_pending_query_realm = false;

	eap_status_e status = eap_status_not_supported;

	if (completion_status != eap_status_ok)
	{
		status = create_tls_protocol_alert(
			tls_alert_description_none,
			tls_alert_level_none,
			completion_status);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = m_NAI_realm.set_copy_of_buffer(realm);
	}

	if (status == eap_status_ok)
	{
		status = check_sent_tls_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_status_completed_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_rsa_decrypt_with_private_key(
	const eap_variable_data_c * const premaster_secret,
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: pki_function: starts: tls_record_c::complete_rsa_decrypt_with_private_key()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_rsa_decrypt_with_private_key()");

	m_pending_rsa_decrypt_with_private_key = false;

	eap_status_e status = eap_status_not_supported;

	if (completion_status != eap_status_ok)
	{
		status = create_tls_protocol_alert(
			tls_alert_description_none,
			tls_alert_level_none,
			completion_status);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: complete_rsa_decrypt_with_private_key(): premaster_secret"),
			 premaster_secret->get_data(),
			 premaster_secret->get_data_length()));

		status = m_premaster_secret.set_copy_of_buffer(premaster_secret);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: m_premaster_secret"),
			m_premaster_secret.get_data(m_premaster_secret.get_data_length()),
			m_premaster_secret.get_data_length()));

		m_key_material_generated = false;

		// We must generate master secret.
		status = generate_master_secret();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// We must generate the key material.
		status = generate_key_material();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (status == eap_status_ok)
	{
		status = check_sent_tls_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_status_completed_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_rsa_encrypt_with_public_key(
	const eap_variable_data_c * const encrypted_premaster_secret,
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: pki_function: starts: tls_record_c::complete_rsa_encrypt_with_public_key()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_rsa_encrypt_with_public_key()");

	m_pending_rsa_encrypt_with_public_key = false;

	eap_status_e status = eap_status_not_supported;

	if (completion_status != eap_status_ok)
	{
		status = create_tls_protocol_alert(
			tls_alert_description_none,
			tls_alert_level_none,
			completion_status);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: complete_rsa_encrypt_with_public_key(): encrypted premaster_secret"),
			 encrypted_premaster_secret->get_data(),
			 encrypted_premaster_secret->get_data_length()));

		status = m_own_encrypted_premaster_secret.set_copy_of_buffer(encrypted_premaster_secret);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (status == eap_status_ok)
	{
		status = check_sent_tls_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_status_completed_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_sign_with_private_key(
	const eap_variable_data_c * const signed_message_hash,
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: pki_function: starts: tls_record_c::complete_sign_with_private_key()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_sign_with_private_key()");

	m_pending_sign_with_private_key = false;

	eap_status_e status = eap_status_not_supported;

	if (completion_status != eap_status_ok)
	{
		status = create_tls_protocol_alert(
			tls_alert_description_none,
			tls_alert_level_none,
			completion_status);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		if (signed_message_hash->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		status = m_signed_message_hash.set_copy_of_buffer(signed_message_hash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: complete_sign_with_private_key(): m_signed_message_hash"),
			m_signed_message_hash.get_data(m_signed_message_hash.get_data_length()),
			m_signed_message_hash.get_data_length()));
	}


	if (status == eap_status_ok)
	{
		status = check_sent_tls_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_status_completed_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_verify_with_public_key(
	const eap_status_e verify_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: pki_function: starts: tls_record_c::complete_verify_with_public_key()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_verify_with_public_key()");

	m_pending_verify_with_public_key = false;

	eap_status_e status = eap_status_ok;

	m_verify_signature = verify_status;

	if (m_verify_signature != eap_status_ok)
	{
		// Verification failed.

		status = create_tls_protocol_alert(
			tls_alert_description_none,
			tls_alert_level_none,
			m_verify_signature);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (status == eap_status_ok)
	{
		status = check_sent_tls_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_status_completed_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::get_eap_tls_master_session_key(
	eap_variable_data_c * const eap_tls_master_session_key,
	eap_variable_data_c * const mschapv2_challenges
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::get_eap_tls_master_session_key()\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::get_eap_tls_master_session_key()");

	eap_status_e status(eap_status_process_general_error);

#if defined(USE_FAST_EAP_TYPE)
	if (m_eap_type == eap_type_fast)
	{
		status = eap_tls_master_session_key->set_copy_of_buffer(&m_session_key_seed);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (mschapv2_challenges != 0
			&& mschapv2_challenges->get_is_valid() == true
			&& m_mschapv2_challenges.get_is_valid_data() == true)
		{
			status = mschapv2_challenges->set_copy_of_buffer(&m_mschapv2_challenges);
		}
	}
	else
#else
	EAP_UNREFERENCED_PARAMETER(mschapv2_challenges);
#endif //#if defined(USE_FAST_EAP_TYPE)
	{
		status = eap_tls_master_session_key->set_copy_of_buffer(&m_eap_master_session_key);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list)
{
	return EAP_STATUS_RETURN(m_am_tools, get_type_partner()->add_rogue_ap(rogue_ap_list));
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_record_c::set_session_timeout(
	const u32_t session_timeout_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_type_partner()->set_session_timeout(session_timeout_ms);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::set_tls_session_type(const tls_session_type_e tls_session_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::set_tls_session_type(): m_tls_session_type=%d=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 tls_session_type,
		 eap_tls_trace_string_c::get_tls_session_type_string(tls_session_type)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::set_tls_session_type()");

	m_tls_session_type = tls_session_type;

	eap_status_e status = get_type_partner()->set_tls_session_type(tls_session_type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_session_type_e tls_record_c::get_tls_session_type()
{
	return m_tls_session_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_c::set_tls_identity_privacy_handshake_state(const tls_identity_privacy_handshake_state_e state)
{
#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::set_tls_identity_privacy_handshake_state(): Changes from %d=%s to %d=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_tls_identity_privacy_handshake_state,
		 eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(m_tls_identity_privacy_handshake_state),
		 state,
		 eap_tls_trace_string_c::get_tls_identity_privacy_handshake_state_string(state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::set_tls_identity_privacy_handshake_state()");

	m_tls_identity_privacy_handshake_state = state;
#else
	EAP_UNREFERENCED_PARAMETER(state);
#endif //#if defined(USE_EAP_TLS_IDENTITY_PRIVACY)
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_record_c::set_selected_cipher_suite(const tls_cipher_suites_e cipher_suite)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: suite_function: starts: tls_record_c::set_selected_cipher_suite(): Changes from %d=%s to %d=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_selected_cipher_suite,
		 eap_tls_trace_string_c::get_cipher_suite_string(m_selected_cipher_suite),
		 cipher_suite,
		 eap_tls_trace_string_c::get_cipher_suite_string(cipher_suite)));

	m_selected_cipher_suite = cipher_suite;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::set_receive_cipher_suite(const tls_cipher_suites_e cipher_suite)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: suite_function: starts: tls_record_c::set_receive_cipher_suite(): Changes from %d=%s to %d=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_receive_cipher_suite,
		 eap_tls_trace_string_c::get_cipher_suite_string(m_receive_cipher_suite),
		 cipher_suite,
		 eap_tls_trace_string_c::get_cipher_suite_string(cipher_suite)));

	m_receive_cipher_suite = cipher_suite;

	m_receive_record_sequence_number = 0ul;


	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("set_receive_cipher_suite(): m_receive_encryption_key"),
		 m_receive_encryption_key.get_data(),
		 m_receive_encryption_key.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("set_receive_cipher_suite(): m_new_receive_encryption_key"),
		 m_new_receive_encryption_key.get_data(),
		 m_new_receive_encryption_key.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("set_receive_cipher_suite(): m_receive_mac_key"),
		 m_receive_mac_key.get_data(),
		 m_receive_mac_key.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("set_receive_cipher_suite(): m_new_receive_mac_key"),
		 m_new_receive_mac_key.get_data(),
		 m_new_receive_mac_key.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("set_receive_cipher_suite(): m_receive_iv"),
		 m_receive_iv.get_data(),
		 m_receive_iv.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("set_receive_cipher_suite(): m_new_receive_iv"),
		 m_new_receive_iv.get_data(),
		 m_new_receive_iv.get_data_length()));


	eap_status_e status = m_receive_mac_key.set_copy_of_buffer(&m_new_receive_mac_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_receive_encryption_key.set_copy_of_buffer(&m_new_receive_encryption_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_receive_iv.set_copy_of_buffer(&m_new_receive_iv);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::set_send_cipher_suite(const tls_cipher_suites_e cipher_suite)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: suite_function: starts: tls_record_c::set_send_cipher_suite(): Changes from %d=%s to %d=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_send_cipher_suite,
		 eap_tls_trace_string_c::get_cipher_suite_string(m_send_cipher_suite),
		 cipher_suite,
		 eap_tls_trace_string_c::get_cipher_suite_string(cipher_suite)));

	m_send_cipher_suite = cipher_suite;

	m_send_record_sequence_number = 0ul;


	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("set_send_cipher_suite(): m_send_encryption_key"),
		 m_send_encryption_key.get_data(),
		 m_send_encryption_key.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("set_send_cipher_suite(): m_new_send_encryption_key"),
		 m_new_send_encryption_key.get_data(),
		 m_new_send_encryption_key.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("set_send_cipher_suite(): m_send_mac_key"),
		 m_send_mac_key.get_data(),
		 m_send_mac_key.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("set_send_cipher_suite(): m_new_send_mac_key"),
		 m_new_send_mac_key.get_data(),
		 m_new_send_mac_key.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("set_send_cipher_suite(): m_send_iv"),
		 m_send_iv.get_data(),
		 m_send_iv.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("set_send_cipher_suite(): m_new_send_iv"),
		 m_new_send_iv.get_data(),
		 m_new_send_iv.get_data_length()));


	eap_status_e status = m_send_mac_key.set_copy_of_buffer(&m_new_send_mac_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_send_encryption_key.set_copy_of_buffer(&m_new_send_encryption_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_send_iv.set_copy_of_buffer(&m_new_send_iv);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::read_authority_identity(eap_variable_data_c * const authority_identity_payload)
{
	return m_application->read_authority_identity(authority_identity_payload);
}

//--------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_query_tunnel_PAC(
	const eap_status_e in_completion_status,
	const eap_fast_pac_type_e in_pac_type,
	const eap_fast_variable_data_c * const in_tunnel_PAC_key_tlv,
	const eap_fast_variable_data_c * const in_tunnel_PAC_opaque_tlv)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::complete_query_tunnel_PAC(): m_tls_session_type=%d=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_tls_session_type,
		 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_query_tunnel_PAC()");

	eap_status_e status(eap_status_process_general_error);

	m_pending_query_tunnel_PAC = false;

	if (in_completion_status == eap_status_ok)
	{
		tls_extension_c extension(m_am_tools);
		if (extension.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (in_tunnel_PAC_opaque_tlv != 0
			&& in_tunnel_PAC_opaque_tlv->get_is_valid_data() == true)
		{
			status = extension.set_copy_of_buffer(in_tunnel_PAC_opaque_tlv->get_full_tlv_buffer());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			extension.set_type(tls_extension_type_session_ticket);
			extension.set_pac_type(in_pac_type);

			status = m_supported_tls_extensions.add_object(extension.copy(), true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (in_tunnel_PAC_key_tlv != 0
			&& in_tunnel_PAC_key_tlv->get_is_valid_data() == true)
		{
			status = m_eap_fast_pac_key.set_copy_of_buffer(
				in_tunnel_PAC_key_tlv->get_data(in_tunnel_PAC_key_tlv->get_data_length()),
				in_tunnel_PAC_key_tlv->get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		set_tls_session_type(tls_session_type_eap_fast_pac_session_resumption);

		if (m_application != 0)
		{
			m_application->set_tunneled_state(get_tls_session_type());
		}
	}

	status = check_sent_tls_message();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_completed_request);
}

#endif //#if defined(USE_FAST_EAP_TYPE)

//--------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

eap_status_e tls_record_c::complete_start_initialize_PAC_store(
	const eap_fast_completion_operation_e /* completion_operation */,
	const eap_fast_initialize_pac_store_completion_e /* completion */)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: this = 0x%08x, %s: message_function: starts: tls_record_c::complete_start_initialize_PAC_store(): m_tls_session_type=%d=%s\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_tls_session_type,
		 eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_record_c::complete_start_initialize_PAC_store()");

	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

#endif //#if defined(USE_FAST_EAP_TYPE)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_record_c::query_ttls_pap_username_and_password(
	const eap_variable_data_c * const reply_message)
{
	eap_status_e status(eap_status_process_general_error);

	status = m_am_tls_services->query_ttls_pap_username_and_password(reply_message);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------


EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_query_ttls_pap_username_and_password(
	const eap_variable_data_c * const ttls_pap_username,
	const eap_variable_data_c * const ttls_pap_password,
	const eap_status_e query_result)
{
	eap_status_e status(eap_status_process_general_error);

	status = m_application->complete_query_ttls_pap_username_and_password(
		ttls_pap_username,
		ttls_pap_password,
		query_result);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------


EAP_FUNC_EXPORT eap_status_e tls_record_c::verify_ttls_pap_username_and_password(
	const eap_variable_data_c * const user_name,
	const eap_variable_data_c * const user_password)
{
	eap_status_e status(eap_status_process_general_error);

	status = m_am_tls_services->verify_ttls_pap_username_and_password(
		user_name,
		user_password);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------


EAP_FUNC_EXPORT eap_status_e tls_record_c::complete_verify_ttls_pap_username_and_password(
	const eap_status_e authentication_result,
	const eap_variable_data_c * const ttls_pap_reply_message)
{
	eap_status_e status(eap_status_process_general_error);

	status = m_application->complete_verify_ttls_pap_username_and_password(
		authentication_result,
		ttls_pap_reply_message);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

// End.
