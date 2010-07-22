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
* %version: 46 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 95 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "eap_am_memory.h"
#include "eap_state_notification.h"
#include "eap_type_mschapv2_header.h"
#include "eap_type_mschapv2.h"
#include "eap_type_mschapv2_credential_store.h"
#include "eap_buffer.h"
#include "eap_config.h"
#include "eap_master_session_key.h"
#include "eap_automatic_variable.h"

/**
* Constructor initializes all member attributes.
*/

EAP_FUNC_EXPORT eap_type_mschapv2_c::eap_type_mschapv2_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	eap_am_type_mschapv2_c * const am_type_mschapv2,
	const bool free_am_type_mschapv2,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id)
	: eap_base_type_c(tools, partner)
	, m_am_type_mschapv2(am_type_mschapv2)
	, m_am_tools(tools)
	, m_session(tools, is_client_when_true)
	, m_send_network_id(tools)
	, m_rand(tools)
	, m_username_utf8(tools)
	, m_password_utf8(tools)
	, m_old_password_utf8(tools)
	, m_password_hash(tools)
	, m_password_hash_hash(tools)
#if defined(USE_FAST_EAP_TYPE)
	, m_client_EAP_FAST_challenge(tools)
	, m_server_EAP_FAST_challenge(tools)
#endif //#if defined(USE_FAST_EAP_TYPE)
	, m_offset(0)
	, m_mtu_length(0)
	, m_trailer_length(0)
	, m_error_code(0)
	, m_is_valid(false)
	, m_is_client(is_client_when_true)
	, m_free_am_type_mschapv2(free_am_type_mschapv2)
	, m_is_pending(false)
	, m_identity_asked(false)
	, m_wait_eap_success(false)
	, m_wait_eap_success_packet(true)
	, m_is_reauthentication(false)
	, m_is_notification_sent(false)
	, m_shutdown_was_called(false)
	, m_password_prompt_enabled(true)
	, m_identifier(0)
	, m_mschapv2id(0)
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	, m_use_implicit_challenge(false)
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
#if defined(EAP_MSCHAPV2_SERVER)
	, m_do_password_expiration_tests(false)
	, m_password_expired(false)
#endif //#if defined(EAP_MSCHAPV2_SERVER)
	, m_do_wrong_password_tests(false)
	, m_use_eap_expanded_type(false)
#if defined(USE_FAST_EAP_TYPE)
	, m_use_EAP_FAST_full_key(false)
	, m_use_EAP_FAST_challenge(false)
#endif //#if defined(USE_FAST_EAP_TYPE)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::eap_type_mschapv2_c(): this = 0x%08x, ")
		 EAPL("partner 0x%08x, type partner 0x%08x, compiled %s %s\n"),
		 this,
		 partner,
		 get_type_partner(),
		__DATE__,
		__TIME__));

	m_am_type_mschapv2->set_am_partner(this);

	{
		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(m_am_tools,
			receive_network_id->get_destination_id(),
			receive_network_id->get_source_id(),
			receive_network_id->get_type());

		eap_status_e status = m_send_network_id.set_copy_of_network_id(&send_network_id);

		if (status != eap_status_ok
			|| m_send_network_id.get_is_valid_data() == false)
		{
			(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return;
		}
	}

	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_type_mschapv2_c::~eap_type_mschapv2_c()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::~eap_type_mschapv2_c(): this = 0x%08x\n"),
		this));

	EAP_ASSERT(m_shutdown_was_called == true);	

	if (m_free_am_type_mschapv2 == true)
	{
		delete m_am_type_mschapv2;
	}
	m_free_am_type_mschapv2 = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_mschapv2_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::shutdown(): this = 0x%08x, m_session.get_state()=%d, m_is_notification_sent=%d\n"),
		this,
		m_session.get_state(),
		m_is_notification_sent));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_mschapv2_c::shutdown()");

	m_am_type_mschapv2->shutdown();
	m_shutdown_was_called = true;

	if (m_session.get_state() != eap_type_mschapv2_state_none)
	{
		if (m_is_notification_sent == false)
		{
			finish_unsuccessful_authentication(false);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_type_mschapv2_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_type_mschapv2_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_type_mschapv2_c::get_is_client() 
{
	return m_is_client;
}

//--------------------------------------------------

void eap_type_mschapv2_c::send_error_notification(const eap_status_e error)
{
	// Notifies the lower level of an authentication error.
	eap_state_notification_c notification(
		m_am_tools,
		&m_send_network_id,
		m_is_client,
		eap_state_notification_eap,
		eap_protocol_layer_general,
		eap_type_mschapv2,
		eap_state_none,
		eap_general_state_authentication_error,
		0,
		false);

	notification.set_authentication_error(error);

	get_type_partner()->state_notification(&notification);
}

//--------------------------------------------------

eap_buf_chain_wr_c * eap_type_mschapv2_c::create_send_packet(u32_t length)
{
	eap_buf_chain_wr_c * packet = new eap_buf_chain_wr_c(
		eap_write_buffer, 
		m_am_tools,
		length + m_offset + m_trailer_length);
	if (!packet)
	{
		return 0;
	}
	if (packet->get_is_valid() == false)
	{
		delete packet;
		return 0;
	}
	packet->set_data_length(length + m_offset);

	return packet;
}

//--------------------------------------------------

eap_status_e eap_type_mschapv2_c::packet_send(
	eap_buf_chain_wr_c * const data,
	const u32_t data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	if (m_mtu_length < data_length)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (data->get_is_valid_data() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = get_type_partner()->packet_send(
		&m_send_network_id,
		data,
		m_offset,
		data_length,
		data->get_buffer_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_mschapv2_c::finish_successful_authentication()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: %s: EAP-SUCCESS: function: eap_type_mschapv2_c::finish_successful_authentication()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_mschapv2_c::finish_successful_authentication()");

	eap_state_notification_c notification(
		m_am_tools,
		&m_send_network_id,
		m_is_client,
		eap_state_notification_eap,
		eap_protocol_layer_eap,
		eap_type_mschapv2,
		eap_state_none,
		eap_state_authentication_finished_successfully,
		m_identifier,
		true);
	get_type_partner()->state_notification(&notification);

	// set notification flag
	m_is_notification_sent = true;

	// Store credential for reauthentication (client only)
	//if (m_is_client)
	{
		eap_variable_data_c key(m_am_tools);
		eap_status_e status = m_am_type_mschapv2->get_memory_store_key(&key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = key.add_data(
			&m_is_client,
			sizeof(m_is_client));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Remove the old data. Do not care status.
		(void) m_am_tools->memory_store_remove_data(&key);
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s: EAP_type_MSCHAPV2: finish_successful_authentication(): Credentials removed from mem store\n"),
			(m_is_client == true) ? "client": "server"));		

		// Store the creditials always, if the password prompt is NOT enabled or
		// if the Session is valid.
		
		if(m_password_prompt_enabled == false 
			|| m_am_type_mschapv2->is_session_valid() == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: EAP_type_MSCHAPV2: finish_successful_authentication(): Session valid or PW prompt disabled, Storing Credentials\n"),
				(m_is_client == true) ? "client": "server"));
		
			eap_tlv_message_data_c tlv_data(m_am_tools);

			status = tlv_data.add_message_data(
				eap_type_mschapv2_stored_username,
				m_username_utf8.get_data_length(),
				m_username_utf8.get_data());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = tlv_data.add_message_data(
				eap_type_mschapv2_stored_password,
				m_password_utf8.get_data_length(),
				m_password_utf8.get_data());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

#if defined(EAP_MSCHAPV2_SERVER)
			status = tlv_data.add_message_data(
				eap_type_mschapv2_stored_password_expired_flag,
				sizeof(m_password_expired),
				&m_password_expired);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
#endif //#if defined(EAP_MSCHAPV2_SERVER)

			status = m_am_tools->memory_store_add_data(
				&key,
				&tlv_data,
				eap_type_default_credential_timeout);
			if (status != eap_status_ok)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAP_type_MSCHAPV2: finish_successful_authentication(): cannot store credentials\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("%s: EAP_type_MSCHAPV2: finish_successful_authentication(): Credentials stored \n"),
				(m_is_client == true) ? "client": "server"));
			
		} // End of if(m_password_prompt_enabled == true ....

	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_mschapv2_c::finish_unsuccessful_authentication(
	const bool authentication_cancelled)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ERROR: %s: EAP_type_MSCHAPV2: FAILED: function: eap_type_mschapv2_c::finish_unsuccessful_authentication()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_mschapv2_c::finish_unsuccessful_authentication()");

	if (m_is_client == true)
	{
		if (authentication_cancelled == true)
		{
			eap_state_notification_c notification(
				m_am_tools,
				&m_send_network_id,
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_general, // This must be used with eap_general_state_authentication_cancelled.
				eap_type_mschapv2,
				eap_state_none,
				eap_general_state_authentication_cancelled,
				m_identifier,
				false);

			notification.set_authentication_error(eap_status_authentication_failure);

			get_type_partner()->state_notification(&notification);
		}
		else
		{			
			eap_state_notification_c notification(
				m_am_tools,
				&m_send_network_id,
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_eap,
				eap_type_mschapv2,
				eap_state_none,
				eap_state_authentication_terminated_unsuccessfully,
				m_identifier,
				false);

			notification.set_authentication_error(eap_status_authentication_failure);

			get_type_partner()->state_notification(&notification);
		}		

#if defined(USE_USER_NOTIFICATIONS)
		eap_variable_data_c string(m_am_tools);
		eap_status_e status = m_am_type_mschapv2->read_auth_failure_string(EAP_MSCHAPV2_ERROR_AUTHENTICATION_FAILURE, string);
		if (status == eap_status_ok)
		{
			eap_state_notification_c notification(
				m_am_tools,
				&m_send_network_id,
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_general, // This must be used with eap_general_state_show_notification_string.
				eap_type_mschapv2,
				eap_state_none,
				eap_general_state_show_notification_string,
				0,
				false);
			status = notification.set_notification_string(&string, true);
			if (status == eap_status_ok)
			{
				get_type_partner()->state_notification(&notification);
			}
		}
#endif //#if defined(USE_USER_NOTIFICATIONS)
	}
	else
	{			
		eap_state_notification_c notification(
			m_am_tools,
			&m_send_network_id,
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_eap,
			eap_type_mschapv2,
			eap_state_none,
			eap_state_authentication_terminated_unsuccessfully,
			m_identifier,
			false);

		notification.set_authentication_error(eap_status_authentication_failure);

		get_type_partner()->state_notification(&notification);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: EAP_type_MSCHAPV2: finish_unsuccessful_authentication(): EAP-FAILED\n"),
		(m_is_client == true) ? "client": "server"));

	// set notification flag
	m_is_notification_sent = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_mschapv2_c::packet_process(
	const eap_am_network_id_c * const /*receive_network_id*/,
	eap_header_wr_c * const received_eap,
	const u32_t eap_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_drop_packet_quietly;

	if (eap_packet_length > received_eap->get_header_buffer_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	if (eap_packet_length < eap_header_base_c::get_header_length()) // Without type code
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	if (received_eap->get_type() == eap_type_notification)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

#ifdef EAP_MSCHAPV2_SERVER
	if (m_is_client) // Client
	{
#endif

		status = client_packet_process(
			received_eap,
			eap_packet_length);

#ifdef EAP_MSCHAPV2_SERVER
	}
	else // Server
	{
		status = server_packet_process(
			received_eap,
			eap_packet_length);
	}
#endif

	if (status == eap_status_ok)
	{
		EAP_GENERAL_HEADER_SET_ERROR_DETECTED(received_eap, false);
	}

	if (status == eap_status_ok
		|| status == eap_status_pending_request
		|| status == eap_status_drop_packet_quietly)
	{    
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Internal error
	status = finish_unsuccessful_authentication(false);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_mschapv2_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::configure(): this = 0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_mschapv2_c::configure()");

	eap_status_e status = eap_status_process_general_error;

	status = m_am_type_mschapv2->configure();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_offset = get_type_partner()->get_header_offset(&m_mtu_length, &m_trailer_length);

	// read configures

	// Password promt
	eap_variable_data_c password_prompt(m_am_tools);

	status = m_am_type_mschapv2->type_configure_read(
		cf_str_EAP_MSCHAPV2_password_prompt.get_field(),
		&password_prompt);
	if (status == eap_status_ok)
	{
		const u32_t * const flag = reinterpret_cast<u32_t *>(
			password_prompt.get_data(sizeof(u32_t)));
		if (flag && *flag == 0)
		{
			m_password_prompt_enabled = false;
		}
		else
		{
			m_password_prompt_enabled = true;
		}
	}

	// Username
	eap_variable_data_c username_uc(m_am_tools);

	status = m_am_type_mschapv2->type_configure_read(
		cf_str_EAP_MSCHAPV2_username.get_field(),
		&m_username_utf8);
	if (status != eap_status_ok
		|| m_username_utf8.get_is_valid() == false)
	{
		// This is optional.
	}

	// Password
	status = m_am_type_mschapv2->type_configure_read(
		cf_str_EAP_MSCHAPV2_password.get_field(),
		&m_password_utf8);
	if (status != eap_status_ok
		|| m_password_utf8.get_is_valid() == false)
	{
		// This is optional.
	}

	if (m_is_client == true
		&& m_password_prompt_enabled == true)
	{
		m_password_utf8.reset();
	}



#if defined(EAP_MSCHAPV2_SERVER)
	{
		eap_variable_data_c do_password_expiration_tests(m_am_tools);

		status = m_am_type_mschapv2->type_configure_read(
			cf_str_EAP_MSCHAPV2_do_password_expiration_tests.get_field(),
			&do_password_expiration_tests);
		if (status == eap_status_ok)
		{
			const u32_t * const flag = reinterpret_cast<u32_t *>(
				do_password_expiration_tests.get_data(sizeof(u32_t)));
			if (flag != 0
				&& *flag == 0)
			{
				m_do_password_expiration_tests = false;
			}
			else
			{
				m_do_password_expiration_tests = true;
			}
		}
	}
#endif //#if defined(EAP_MSCHAPV2_SERVER)

	
	if (m_is_client == true)
	{
		eap_variable_data_c do_wrong_password_tests(m_am_tools);

		status = m_am_type_mschapv2->type_configure_read(
			cf_str_EAP_MSCHAPV2_do_wrong_password_tests.get_field(),
			&do_wrong_password_tests);
		if (status == eap_status_ok)
		{
			const u32_t * const flag = reinterpret_cast<u32_t *>(
				do_wrong_password_tests.get_data(sizeof(u32_t)));
			if (flag != 0
				&& *flag == 0)
			{
				m_do_wrong_password_tests = false;
			}
			else
			{
				m_do_wrong_password_tests = true;
			}
		}
	}

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	{
		eap_variable_data_c use_implicit_challenge(m_am_tools);

		status = m_am_type_mschapv2->type_configure_read(
			cf_str_EAP_MSCHAPV2_use_implicit_challenge.get_field(),
			&use_implicit_challenge);
		if (status == eap_status_ok)
		{
			const u32_t * const flag = reinterpret_cast<u32_t *>(
				use_implicit_challenge.get_data(sizeof(u32_t)));
			if (flag != 0 && *flag != 0)
			{
				m_use_implicit_challenge = true;
			}
			else
			{
				m_use_implicit_challenge = false;
			}
		}
	}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	//----------------------------------------------------------

	{
		eap_variable_data_c use_eap_expanded_type(m_am_tools);

		eap_status_e status = m_am_type_mschapv2->type_configure_read(
			cf_str_EAP_MSCHAPV2_use_eap_expanded_type.get_field(),
			&use_eap_expanded_type);

		if (status != eap_status_ok)
		{
			status = m_am_type_mschapv2->type_configure_read(
				cf_str_EAP_CORE_use_eap_expanded_type.get_field(),
				&use_eap_expanded_type);
		}

		if (status == eap_status_ok
			&& use_eap_expanded_type.get_data_length() == sizeof(u32_t)
			&& use_eap_expanded_type.get_data() != 0)
		{
			u32_t *flag = reinterpret_cast<u32_t *>(use_eap_expanded_type.get_data(use_eap_expanded_type.get_data_length()));

			if (flag != 0)
			{
				if ((*flag) != 0ul)
				{
					m_use_eap_expanded_type = true;
				}
				else
				{
					m_use_eap_expanded_type = false;
				}
			}
		}
	}

	//----------------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)
	
	{
		eap_variable_data_c use_EAP_FAST_challenge(m_am_tools);

		status = m_am_type_mschapv2->type_configure_read(
			cf_str_EAP_MSCHAPV2_use_EAP_FAST_challenge.get_field(),
			&use_EAP_FAST_challenge);
		if (status == eap_status_ok)
		{
			const u32_t * const flag = reinterpret_cast<u32_t *>(
				use_EAP_FAST_challenge.get_data(sizeof(u32_t)));
			if (flag != 0 && *flag != 0)
			{
				m_use_EAP_FAST_challenge = true;
			}
			else
			{
				m_use_EAP_FAST_challenge = false;
			}
		}
	}

	if (m_use_EAP_FAST_challenge == true)
	{
		status = m_am_type_mschapv2->type_configure_read(
			cf_str_EAP_MSCHAPV2_client_EAP_FAST_challenge.get_field(),
			&m_client_EAP_FAST_challenge);
		if (status != eap_status_ok
			|| m_client_EAP_FAST_challenge.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_type_mschapv2_c::configure(): m_client_EAP_FAST_challenge"),
			 m_client_EAP_FAST_challenge.get_data(),
			 m_client_EAP_FAST_challenge.get_data_length()));

		status = m_am_type_mschapv2->type_configure_read(
			cf_str_EAP_MSCHAPV2_server_EAP_FAST_challenge.get_field(),
			&m_server_EAP_FAST_challenge);
		if (status != eap_status_ok
			|| m_server_EAP_FAST_challenge.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_type_mschapv2_c::configure(): m_server_EAP_FAST_challenge"),
			 m_server_EAP_FAST_challenge.get_data(),
			 m_server_EAP_FAST_challenge.get_data_length()));
	}

	{
		eap_variable_data_c use_EAP_FAST_full_key(m_am_tools);

		status = m_am_type_mschapv2->type_configure_read(
			cf_str_EAP_MSCHAPV2_use_EAP_FAST_full_key.get_field(),
			&use_EAP_FAST_full_key);
		if (status == eap_status_ok)
		{
			const u32_t * const flag = reinterpret_cast<u32_t *>(
				use_EAP_FAST_full_key.get_data(sizeof(u32_t)));
			if (flag != 0 && *flag != 0)
			{
				m_use_EAP_FAST_full_key = true;
			}
			else
			{
				m_use_EAP_FAST_full_key = false;
			}
		}
	}


#endif //#if defined(USE_FAST_EAP_TYPE)

	//----------------------------------------------------------

	eap_variable_data_c wait_eap_success_prompt(m_am_tools);

	m_wait_eap_success = true;

	// Check if the case is reauthentication (client only)
	//if (m_is_client)
	{
		eap_variable_data_c key(m_am_tools);
		status = m_am_type_mschapv2->get_memory_store_key(&key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = key.add_data(
			&m_is_client,
			sizeof(m_is_client));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_tlv_message_data_c tlv_data(m_am_tools);

		status = m_am_tools->memory_store_get_data(
			&key,
			&tlv_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_MSCHAPV2: configure(): cannot get credentials\n")));
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_MSCHAPV2: configure: credentials found\n")));

			// Parse read data.
			eap_array_c<eap_tlv_header_c> tlv_blocks(m_am_tools);
				
			status = tlv_data.parse_message_data(&tlv_blocks);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			for (u32_t ind = 0ul; ind < tlv_blocks.get_object_count(); ind++)
			{
				eap_tlv_header_c * const tlv = tlv_blocks.get_object(ind);
				if (tlv != 0)
				{
					if (tlv->get_type() == eap_type_mschapv2_stored_username)
					{
						if (m_username_utf8.get_is_valid_data() == false)
						{
							status = m_username_utf8.set_copy_of_buffer(
								tlv->get_value(tlv->get_value_length()),
								tlv->get_value_length());
							if (status != eap_status_ok)
							{
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}
						}
					}
					else if (tlv->get_type() == eap_type_mschapv2_stored_password)
					{
						if (m_password_prompt_enabled == true
							|| m_password_utf8.get_is_valid_data() == false)
						{
							status = m_password_utf8.set_copy_of_buffer(
								tlv->get_value(tlv->get_value_length()),
								tlv->get_value_length());
							if (status != eap_status_ok)
							{
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}
						}
					}
#if defined(EAP_MSCHAPV2_SERVER)
					else if (tlv->get_type() == eap_type_mschapv2_stored_password_expired_flag)
					{
						bool * const password_expired = reinterpret_cast<bool *>(tlv->get_value(sizeof(*password_expired)));
						if (password_expired == 0)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
						}

						m_password_expired = *password_expired;
					}
#endif //#if defined(EAP_MSCHAPV2_SERVER)
					else
					{
						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("EAP_type_MSCHAPV2: unknown credential type %d, length %d\n"),
							 tlv->get_type(),
							 tlv->get_value_length()));
					}
				}
			}

			status = m_am_tools->memory_store_remove_data(&key);
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_MSCHAPV2: configure: credentials removed from eapol\n")));

			m_is_reauthentication = true;
			m_identity_asked = true;
		}
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: configure, username:"),
		m_username_utf8.get_data(),
		m_username_utf8.get_buffer_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: configure, password:"),
		m_password_utf8.get_data(),
		m_password_utf8.get_buffer_length()));


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// This function is to allow reuse of this object.
// The whole object state must be reset.
EAP_FUNC_EXPORT eap_status_e eap_type_mschapv2_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::reset(): this = 0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_type_mschapv2_c::reset()");

	m_session.reset();

	m_username_utf8.reset();
	eap_variable_data_c username_uc(m_am_tools);

	eap_status_e status = m_am_type_mschapv2->type_configure_read(
		cf_str_EAP_MSCHAPV2_username.get_field(),
		&m_username_utf8);
	if (status != eap_status_ok
		|| m_username_utf8.get_is_valid() == false)
	{
		// This is optional.
	}

	status = m_am_type_mschapv2->type_configure_read(
		cf_str_EAP_MSCHAPV2_password.get_field(),
		&m_password_utf8);
	if (status != eap_status_ok
		|| m_password_utf8.get_is_valid() == false)
	{
		// This is optional.
	}

	if (m_is_client == true
		&& m_password_prompt_enabled == true)
	{
		m_password_utf8.reset();
	}

	m_old_password_utf8.reset();

	m_is_notification_sent = false;
	m_is_reauthentication = false;

	m_is_pending = false;
	m_identity_asked = false;

	status = m_am_type_mschapv2->reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if defined(USE_FAST_EAP_TYPE)

	{
		eap_variable_data_c use_EAP_FAST_challenge(m_am_tools);

		status = m_am_type_mschapv2->type_configure_read(
			cf_str_EAP_MSCHAPV2_use_EAP_FAST_challenge.get_field(),
			&use_EAP_FAST_challenge);
		if (status == eap_status_ok)
		{
			const u32_t * const flag = reinterpret_cast<u32_t *>(
				use_EAP_FAST_challenge.get_data(sizeof(u32_t)));
			if (flag != 0 && *flag != 0)
			{
				m_use_EAP_FAST_challenge = true;
			}
			else
			{
				m_use_EAP_FAST_challenge = false;
			}
		}
	}

	if (m_use_EAP_FAST_challenge == true)
	{
		status = m_am_type_mschapv2->type_configure_read(
			cf_str_EAP_MSCHAPV2_client_EAP_FAST_challenge.get_field(),
			&m_client_EAP_FAST_challenge);
		if (status != eap_status_ok
			|| m_client_EAP_FAST_challenge.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_type_mschapv2_c::reset(): m_client_EAP_FAST_challenge"),
			 m_client_EAP_FAST_challenge.get_data(),
			 m_client_EAP_FAST_challenge.get_data_length()));

		status = m_am_type_mschapv2->type_configure_read(
			cf_str_EAP_MSCHAPV2_server_EAP_FAST_challenge.get_field(),
			&m_server_EAP_FAST_challenge);
		if (status != eap_status_ok
			|| m_server_EAP_FAST_challenge.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_type_mschapv2_c::reset(): m_server_EAP_FAST_challenge"),
			 m_server_EAP_FAST_challenge.get_data(),
			 m_server_EAP_FAST_challenge.get_data_length()));

	}

	{
		eap_variable_data_c use_EAP_FAST_full_key(m_am_tools);

		status = m_am_type_mschapv2->type_configure_read(
			cf_str_EAP_MSCHAPV2_use_EAP_FAST_full_key.get_field(),
			&use_EAP_FAST_full_key);
		if (status == eap_status_ok)
		{
			const u32_t * const flag = reinterpret_cast<u32_t *>(
				use_EAP_FAST_full_key.get_data(sizeof(u32_t)));
			if (flag != 0 && *flag != 0)
			{
				m_use_EAP_FAST_full_key = true;
			}
			else
			{
				m_use_EAP_FAST_full_key = false;
			}
		}
	}


#endif //#if defined(USE_FAST_EAP_TYPE)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e eap_type_mschapv2_c::mschapv2_convert_unicode_to_ascii(
	eap_variable_data_c & dest,
	const eap_variable_data_c & src)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::mschapv2_convert_unicode_to_ascii(): this = 0x%08x\n"),
		this));

	if (src.get_is_valid())
	{
		u32_t len = src.get_data_length();
		u8_t * ascii = new u8_t[len / 2];
		if (!ascii)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		u8_t * src_ptr = src.get_data(len);
		u32_t dest_len = len / 2;
		u32_t i;
		for (i = 0; i < dest_len; i++)
		{
			ascii[i] = src_ptr[i * 2];
		}

		return dest.set_buffer(ascii, dest_len, true, true);
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
}

//--------------------------------------------------

/* Pseudocode implementation can be found from       */
/* RFC 2759 Microsoft PPP CHAP Extensions, Version 2 */

//--------------------------------------------------

eap_status_e eap_type_mschapv2_c::generate_nt_response(
	const u8_t * const authenticator_challenge,
	const u8_t * const peer_challenge,
	const u8_t * const username_utf8,
	const u32_t username_size,
	const eap_variable_data_c * const password_hash,
	u8_t * const response)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::generate_nt_response(): this = 0x%08x\n"),
		this));

	if (!authenticator_challenge
		|| !peer_challenge
		|| !username_utf8
		|| username_size == 0
		|| username_size > EAP_MSCHAPV2_USERNAME_MAX_SIZE
		|| !password_hash
		|| !response)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: generate_nt_response, authenticator challenge:"),
		authenticator_challenge,
		EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: generate_nt_response, peer challenge:"),
		peer_challenge,
		 EAP_MSCHAPV2_PEER_CHALLENGE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: generate_nt_response, username_utf8:"),
		username_utf8,
		username_size));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: generate_nt_response, password_hash:"),
		password_hash->get_data(),
		password_hash->get_data_length()));

	u8_t * const challenge = new u8_t[8];
	if (!challenge)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = challenge_hash(
		peer_challenge,
		authenticator_challenge,
		username_utf8,
		username_size,
		challenge);
	if (status != eap_status_ok)
	{
		delete [] challenge;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: generate_nt_response, challenge_hash:"),
		challenge,
		EAP_MSCHAPV2_CHALLENGE_HASH_SIZE));

	status = challenge_response(
		challenge,
		password_hash->get_data(),
		response);
	delete [] challenge;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_type_mschapv2_c::challenge_hash(
	const u8_t * const peer_challenge,
	const u8_t * const authenticator_challenge,
	const u8_t * const username,
	const u32_t username_size,
	u8_t * const challenge)
{ 
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::challenge_hash(): this = 0x%08x\n"),
		this));

	if (!peer_challenge
		|| !authenticator_challenge
		|| !username
		|| username_size == 0
		|| username_size > EAP_MSCHAPV2_USERNAME_MAX_SIZE
		|| !challenge)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	
	crypto_sha1_c sha1(m_am_tools);

	eap_status_e status = sha1.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(peer_challenge, EAP_MSCHAPV2_MD4_DIGEST_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(authenticator_challenge, EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

    // username without domain part
    u32_t i;
    for (i = username_size; i > 0 && username[i - 1] != '\\'; i--)
	{
		// Nothing to do, the index is the output.
	}

    status = sha1.hash_update(username + i, username_size - i);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u8_t * const digest = new u8_t[EAP_MSCHAPV2_SHA1_DIGEST_SIZE];
	if (!digest)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	status = sha1.hash_final(digest, 0);
	if (status != eap_status_ok)
	{
		delete [] digest;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_am_tools->memmove(challenge, digest, EAP_MSCHAPV2_CHALLENGE_HASH_SIZE);

	delete [] digest;
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e eap_type_mschapv2_c::challenge_response(
	const u8_t * const challenge,     //  8 bytes
	const u8_t * const password_hash, // 16 bytes
	u8_t * const response)            // 24 bytes
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::challenge_response(): this = 0x%08x\n"),
		this));

	if (!challenge
		|| !password_hash
		|| !response)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	// 3rd 7-octets of password_hash has to be zero padded
	u8_t * zero_padded_password_hash_last_part = new u8_t[7];
	if (!zero_padded_password_hash_last_part)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_am_tools->memmove(
		zero_padded_password_hash_last_part,
		password_hash + 14, // 2 * 7 bytes
		2);                 // 16 - 2 * 7 bytes

	// Zero padding
	m_am_tools->memset(
		zero_padded_password_hash_last_part + 2, // 16 - 2 * 7
		0,                                       // 7 - 2
		5);

	eap_status_e status = des_encrypt(
		challenge,
		zero_padded_password_hash_last_part, // 3rd 7-octets of (zero_padded_)password_hash
		response + 16);                      // 3rd 8-octets of response

	delete [] zero_padded_password_hash_last_part;

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = des_encrypt(
		challenge,
		password_hash, // 1st 7-octets of password_hash
		response);     // 1st 8-octets of response

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = des_encrypt(
		challenge,
		password_hash + 7, // 2nd 7-octets of password_hash
		response + 8);     // 2nd 8-octets of response

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_type_mschapv2_c::des_crypt(
	const u8_t * const data_in, //  8 octets
	const u8_t * const key,     // 56 bits
	u8_t * const data_out,
	const bool is_encrypt)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::des_crypt(): this = 0x%08x\n"),
		this));

	if (!data_in
		|| !key
		|| !data_out)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	u8_t * const newkey = new u8_t[3 * EAP_MSCHAPV2_DES_KEY_SIZE]; // 3des key is triple size

	if (!newkey)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_am_tools->memset(newkey, 0, 3 * EAP_MSCHAPV2_DES_KEY_SIZE); // 3 * 8 bytes

	// Add parity bits to key, 56 -> 64 bits

	// First octet
	// key bit shifting [1, 7]
	// newkey copy bit shifting [1, 7], parity bit shifting 0

	// Second octet
	// key bit shifting for second octet [2, 7] and for first octet 0
	// newkey copy bit shifting [1, 7], parity bit shifting 0

	// Third octet
	// key bit shifting for second octet [3, 7] and for first octet [0, 1}
	// newkey copy bit shifting [1, 7], parity bit shifting 0

	// bit no: 7 6 5 4 3 2 1 0, 0 = parity bit
	{
		int newkey_byte, newkey_bit, newkey_bit_shifting,
			key_bit_no, key_byte, key_bit_shifting, bit_counter;

		for (newkey_byte = 0; newkey_byte < 8; newkey_byte++)
		{
			bit_counter = 0;

			for (newkey_bit = 0; newkey_bit < 7; newkey_bit++)
			{
				key_bit_no = newkey_byte * 7 + newkey_bit;
				key_byte = key_bit_no / 8;

				key_bit_shifting = 7 - (key_bit_no % 8);
				newkey_bit_shifting = 7 - (key_bit_no % 7);

				if (key[key_byte] & (1 << key_bit_shifting)) // If bit is 1...
				{
					newkey[newkey_byte] = static_cast<u8_t>(newkey[newkey_byte] | (1 << newkey_bit_shifting)); // ...set bit to 1
					bit_counter++;
				}
			}

			if (bit_counter % 2 == 0) // If even number of bits...
			{
				// Add parity bit
				newkey[newkey_byte] |= 1; // ...set the 1st bit to 1
			}
		}
	}

	// Copy key three times into triple size key because we are internally using 3des instead of des
	// des: Ek == 3des: Ek3(Dk2(Ek1)) when k == key1 == key2 == key3
	m_am_tools->memmove(newkey + EAP_MSCHAPV2_DES_KEY_SIZE, newkey, EAP_MSCHAPV2_DES_KEY_SIZE);
	m_am_tools->memmove(newkey + 2 * EAP_MSCHAPV2_DES_KEY_SIZE, newkey, EAP_MSCHAPV2_DES_KEY_SIZE);

	eap_status_e status;

	crypto_3des_ede_c des(m_am_tools);

	if (is_encrypt)
	{
		status = des.set_encryption_key(newkey, 3 * EAP_MSCHAPV2_DES_KEY_SIZE);

		if (status != eap_status_ok)
		{
			delete [] newkey;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = des.encrypt_block(data_in, data_out, EAP_MSCHAPV2_DES_BLOCK_SIZE);
	}

	else // Decrypt mode
	{
		status = des.set_decryption_key(newkey, 3 * EAP_MSCHAPV2_DES_KEY_SIZE);
		if (status != eap_status_ok)
		{
			delete [] newkey;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = des.decrypt_block(data_in, data_out, EAP_MSCHAPV2_DES_BLOCK_SIZE);
	}

	delete [] newkey;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

static const u8_t eap_type_mschapv2_magic1a[] = { 
	0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
	0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
	0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74 };

static const u8_t eap_type_mschapv2_magic2a[] = {
	0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
	0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
	0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
	0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
	0x6E };

eap_status_e eap_type_mschapv2_c::generate_authenticator_response(
	const u8_t * const password_hash_hash,
	const u8_t * const nt_response,
	const u8_t * const peer_challenge,
	const u8_t * const authenticator_challenge,
	const u8_t * const username,
	const u32_t username_size,
	u8_t * const authenticator_response)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::generate_authenticator_response(): this = 0x%08x\n"),
		this));

	if (!password_hash_hash
		|| !nt_response
		|| !peer_challenge
		|| !authenticator_challenge
		|| !username
		|| username_size == 0
		|| username_size > EAP_MSCHAPV2_USERNAME_MAX_SIZE
		|| !authenticator_response)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	crypto_sha1_c sha1(m_am_tools);

	eap_status_e status = sha1.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		status = sha1.hash_update(password_hash_hash, EAP_MSCHAPV2_MD4_DIGEST_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = sha1.hash_update(nt_response, EAP_MSCHAPV2_NT_RESPONSE_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(eap_type_mschapv2_magic1a, sizeof(eap_type_mschapv2_magic1a));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u8_t * const digest = new u8_t[EAP_MSCHAPV2_SHA1_DIGEST_SIZE];
	if (!digest)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = sha1.hash_final(digest, 0);

	if (status != eap_status_ok)
	{
		delete [] digest;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u8_t * const challenge = new u8_t[EAP_MSCHAPV2_CHALLENGE_HASH_SIZE];
	if (!challenge)
	{
		delete [] digest;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = challenge_hash(
		peer_challenge,
		authenticator_challenge,
		username,
		username_size,
		challenge);

	if (status != eap_status_ok)
	{
		delete [] digest;
		delete [] challenge;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	sha1.hash_cleanup();

	status = sha1.hash_init();
	if (status != eap_status_ok)
	{
		delete [] digest;
		delete [] challenge;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(digest, EAP_MSCHAPV2_SHA1_DIGEST_SIZE);

	if (status != eap_status_ok)
	{
		delete [] digest;
		delete [] challenge;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(challenge, EAP_MSCHAPV2_CHALLENGE_HASH_SIZE);

	delete [] challenge;

	if (status != eap_status_ok)
	{
		delete [] digest;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(eap_type_mschapv2_magic2a, sizeof(eap_type_mschapv2_magic2a));
	if (status != eap_status_ok)
	{
		delete [] digest;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_final(digest, 0);

	if (status != eap_status_ok)
	{
		delete [] digest;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_am_tools->memmove(authenticator_response, "S=", 2);
	u32_t length = EAP_MSCHAPV2_SHA1_DIGEST_SIZE * 2;
	(void)m_am_tools->convert_bytes_to_hex_ascii(
		digest, 
		EAP_MSCHAPV2_SHA1_DIGEST_SIZE,
		authenticator_response + 2,
		&length);

	m_am_tools->convert_ascii_to_uppercase(authenticator_response + 2, length);

	delete [] digest;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e eap_type_mschapv2_c::check_authenticator_response(
	const eap_variable_data_c * const password_hash_hash,
	const u8_t * const nt_response,
	const u8_t * const peer_challenge,
	const u8_t * const authenticator_challenge,
	const u8_t * const username,
	const u32_t username_size,
	const u8_t * const received_response,
	bool & response_ok)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::check_authenticator_response(): this = 0x%08x\n"),
		this));

	if (!password_hash_hash
		|| password_hash_hash->get_data_length() < EAP_MSCHAPV2_MD4_DIGEST_SIZE
		|| !nt_response
		|| !peer_challenge
		|| !authenticator_challenge
		|| !username
		|| username_size == 0
		|| username_size > EAP_MSCHAPV2_USERNAME_MAX_SIZE
		|| !received_response)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	response_ok = false;
	
	u8_t * const response = new u8_t[EAP_MSCHAPV2_AUTHENTICATOR_RESPONSE_SIZE];
	if (!response)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = generate_authenticator_response(
		password_hash_hash->get_data(),
		nt_response,
		peer_challenge,
		authenticator_challenge,
		username,
		username_size,
		response);
	if (status != eap_status_ok)
	{
		delete [] response;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("client_handle_success_request(): response"),
		 response,
		 EAP_MSCHAPV2_AUTHENTICATOR_RESPONSE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("client_handle_success_request(): received_response"),
		 received_response,
		 EAP_MSCHAPV2_AUTHENTICATOR_RESPONSE_SIZE));

	if (m_am_tools->memcmp(
			response,
			received_response,
			EAP_MSCHAPV2_AUTHENTICATOR_RESPONSE_SIZE)
		== 0)
	{
		response_ok = true;
	}
	else
	{
#if defined(USE_FAST_EAP_TYPE)
		if (m_use_EAP_FAST_challenge == true)
		{
			(void) send_error_notification(eap_status_tunnel_compromise_error);
		}
#endif //#if defined(USE_FAST_EAP_TYPE)
	}

	delete [] response;
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_type_mschapv2_c::new_password_encrypted_with_old_nt_password_hash(
	const eap_variable_data_c * const new_password_utf8,
	const eap_variable_data_c * const old_password_hash,
	u8_t * encrypted_pw_block)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::new_password_encrypted_with_old_nt_password_hash(): this = 0x%08x\n"),
		this));

	if (!new_password_utf8
		|| new_password_utf8->get_data_length() > EAP_MSCHAPV2_PASSWORD_MAX_SIZE
		|| !old_password_hash
		|| !encrypted_pw_block)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_status_e status = encrypt_pw_block_with_password_hash(
		new_password_utf8,
		old_password_hash->get_data(),
		encrypted_pw_block);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_type_mschapv2_c::encrypt_pw_block_with_password_hash(
	const eap_variable_data_c * const password_utf8,
	const u8_t * const password_hash,
	u8_t * pw_block)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::encrypt_pw_block_with_password_hash(): this = 0x%08x\n"),
		this));

	if (!password_utf8
		|| password_utf8->get_data_length() > EAP_MSCHAPV2_PASSWORD_MAX_SIZE
		|| !password_hash
		|| !pw_block
		|| !m_rand.get_is_valid())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_status_e status = m_rand.add_rand_seed_hw_ticks();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_rand.add_rand_seed(password_utf8->get_data(), password_utf8->get_data_length()); 
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	pw_block_s * clear_pw_block = new pw_block_s;
	if (!clear_pw_block)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c tmp_password_unicode(m_am_tools);
	status = m_am_tools->convert_utf8_to_unicode(tmp_password_unicode, *password_utf8);
	if (status != eap_status_ok)
	{
		delete clear_pw_block;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t pw_offset = EAP_MSCHAPV2_PASSWORD_MAX_SIZE - tmp_password_unicode.get_data_length();

	// Fill begin of clear_pw_block with random octet values
	status = m_rand.get_rand_bytes(clear_pw_block->password, pw_offset);
	if (status != eap_status_ok)
	{
		delete clear_pw_block;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	// Copy password to end of clear_pw_block
	m_am_tools->memmove(
		clear_pw_block->password + pw_offset,
		tmp_password_unicode.get_data(),
		tmp_password_unicode.get_data_length());

	// Password size must be little endian
#ifdef EAP_BIG_ENDIAN
	u8_t * pw_bytes = reinterpret_cast<u8_t *>(&pw_size);
	u8_t tmp;

	tmp = bytes[0];
	bytes[0] = bytes[3];
	bytes[3] = tmp;
	tmp = bytes[1];
	bytes[1] = bytes[2];
	bytes[2] = tmp;
#endif

	clear_pw_block->password_length = tmp_password_unicode.get_data_length();

	status = rc4_encrypt(
		reinterpret_cast<u8_t *>(clear_pw_block),
		sizeof(pw_block_s),
		password_hash,
		EAP_MSCHAPV2_MD4_DIGEST_SIZE,
		pw_block);

	delete clear_pw_block;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_type_mschapv2_c::rc4_encrypt(
	const u8_t * const clear,
	const u32_t clear_length,
	const u8_t * const key,
	const u32_t key_length,
	u8_t * const cypher)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::rc4_encrypt(): this = 0x%08x\n"),
		this));

	if (!clear
		|| clear_length == 0
		|| !key
		|| key_length == 0
		|| !cypher)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_variable_data_c v_key(m_am_tools);

	eap_status_e status = v_key.set_buffer(key, key_length, false, false); // Cannot fail
	if (status != eap_status_ok
		|| v_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	crypto_rc4_c rc4(m_am_tools);

	status = rc4.set_key(&v_key);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = rc4.encrypt_data(clear, cypher, clear_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_type_mschapv2_c::old_nt_password_hash_encrypted_with_new_nt_password_hash(
	const eap_variable_data_c * const new_password_hash,
	const eap_variable_data_c * const old_password_hash,
	eap_variable_data_c * const encrypted_password_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::old_nt_password_hash_encrypted_with_new_nt_password_hash(): this = 0x%08x\n"),
		this));

	if (!new_password_hash
		|| !old_password_hash
		|| !encrypted_password_hash)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_status_e status = nt_password_hash_encrypted_with_block(
		old_password_hash,
		new_password_hash,
		encrypted_password_hash);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_type_mschapv2_c::nt_password_hash_encrypted_with_block(
	const eap_variable_data_c * const password_hash,
	const eap_variable_data_c * const block,
	eap_variable_data_c * const cypher)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::nt_password_hash_encrypted_with_block(): this = 0x%08x\n"),
		this));

	if (!password_hash
		|| !block
		|| !cypher)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_status_e status = cypher->set_buffer_length(EAP_MSCHAPV2_MD4_DIGEST_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = cypher->set_data_length(EAP_MSCHAPV2_MD4_DIGEST_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = des_encrypt(
		password_hash->get_data(), // 1st 8-octets password_hash
		block->get_data(),         // 1st 7-octets block
		cypher->get_data(EAP_MSCHAPV2_DES_BLOCK_SIZE));       // giving 1st 8-octets cypher

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = des_encrypt(
		password_hash->get_data_offset(8,8), // 2nd 8-octets password_hash
		block->get_data_offset(7,7),         // 2nd 7-octets block
		cypher->get_data_offset(8,EAP_MSCHAPV2_DES_BLOCK_SIZE));       // giving 2nd 8-octets cypher

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_type_mschapv2_c::generate_session_key(
	eap_master_session_key_c * const key)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::generate_session_key(): this = 0x%08x\n"),
		this));

	eap_status_e status(eap_status_ok);

	eap_variable_data_c master_key(m_am_tools);
	if (master_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	crypto_nt_hash_c nt_hash(m_am_tools);
	if (nt_hash.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c nt_response(m_am_tools);
	if (nt_response.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = nt_response.set_buffer(
		m_nt_response,
		EAP_MSCHAPV2_NT_RESPONSE_SIZE,
		false,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = nt_hash.get_master_key(
		&m_password_hash_hash,
		&nt_response,
		&master_key,
		EAP_MSCHAPV2_MASTER_KEY_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: client_send_challenge_response(), master_key"),
		master_key.get_data(),
		master_key.get_data_length()));

	eap_variable_data_c asymmetric_start_key(m_am_tools);

	if (asymmetric_start_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


#if defined(USE_FAST_EAP_TYPE)
	if (m_use_EAP_FAST_full_key == true)
	{
		eap_variable_data_c session_key_2(m_am_tools);

		if (session_key_2.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = nt_hash.get_asymmetric_start_key(
			&master_key,
			&asymmetric_start_key,
			EAP_MSCHAPV2_MASTER_KEY_SIZE,
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
			(EAPL("EAP_type_MSCHAPV2: client_send_challenge_response(), asymmetric_start_key_1"),
			asymmetric_start_key.get_data(),
			asymmetric_start_key.get_data_length()));

		status = key->set_copy_of_buffer(&asymmetric_start_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = nt_hash.get_asymmetric_start_key(
			&master_key,
			&asymmetric_start_key,
			EAP_MSCHAPV2_MASTER_KEY_SIZE,
			true,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: client_send_challenge_response(), asymmetric_start_key_2"),
			asymmetric_start_key.get_data(),
			asymmetric_start_key.get_data_length()));

		status = key->add_data(&asymmetric_start_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}
	else
#endif //#if defined(USE_FAST_EAP_TYPE)
	{
		status = nt_hash.get_asymmetric_start_key(
			&master_key,
			&asymmetric_start_key,
			EAP_MSCHAPV2_MASTER_KEY_SIZE,
			true,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: client_send_challenge_response(), asymmetric_start_key_2"),
			asymmetric_start_key.get_data(),
			asymmetric_start_key.get_data_length()));

		status = key->set_copy_of_buffer(&asymmetric_start_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

// End of File
