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
	#define EAP_FILE_NUMBER_ENUM 94 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_base_type.h"
#include "eap_state_notification.h"
#include "eap_type_mschapv2.h"
#include "eap_am_type_mschapv2.h"
#include "eap_buffer.h"
#include "eap_master_session_key.h"
#include "eap_network_id_selector.h"
#include "eap_tlv_message_data.h"
#include "eap_config.h"


eap_status_e eap_type_mschapv2_c::client_packet_process(
	eap_header_wr_c * const received_eap,
	const u32_t eap_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::client_packet_process(): this = 0x%08x, m_session.get_state()=%d\n"),
		this,
		m_session.get_state()));

	eap_status_e status = eap_status_drop_packet_quietly;

	m_identifier = received_eap->get_identifier();

	if (received_eap->get_type() == eap_type_identity)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	if (received_eap->get_code() == eap_code_failure)
	{
		if (m_session.is_valid_state(eap_type_mschapv2_state_failure) == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}

		status = finish_unsuccessful_authentication(false);

		m_session.set_state(eap_type_mschapv2_state_failure);
	}
	else if (received_eap->get_code() == eap_code_success)
	{
		if (m_session.is_valid_state(eap_type_mschapv2_state_success) == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}

		eap_master_session_key_c key(
			m_am_tools,
			eap_type_mschapv2);
		if (key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = generate_session_key(&key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = get_type_partner()->packet_data_crypto_keys(&m_send_network_id, &key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Check wait for eap success

		status = finish_successful_authentication();

		m_session.set_state(eap_type_mschapv2_state_success);
	}
	else if (received_eap->get_code() == eap_code_request) // Request
	{
		// MsChapV2
		if (received_eap->get_type() == eap_type_mschapv2)
		{
			status = client_mschapv2_packet_process(
				received_eap,
				eap_packet_length);			    
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

eap_status_e eap_type_mschapv2_c::client_mschapv2_packet_process(
	eap_header_wr_c * const received_eap,
	const u32_t eap_packet_length)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::client_mschapv2_packet_process(): this = 0x%08x\n"),
		this));

	eap_status_e status = eap_status_drop_packet_quietly;

	if (eap_packet_length <= eap_header_base_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else if (eap_packet_length == received_eap->get_data_length())
	{
		// MsChapV2 packet without any data, unspecified packet?
		// lets finish unsuccesfully?
		if (m_session.is_valid_state(eap_type_mschapv2_state_failure) == true)
		{
			status = finish_unsuccessful_authentication(false);
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const u32_t type_data_length = received_eap->get_type_data_length();

	if (received_eap->get_type_data_offset(0, type_data_length) == 0)
	{
		// Not enough data.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		received_eap->get_type_data_offset(0, type_data_length),
		type_data_length);

	if (mschapv2_header.check_header() != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	switch (mschapv2_header.get_opcode())
	{
	case mschapv2_opcode_challenge:
		if (m_session.is_valid_state(eap_type_mschapv2_state_challenge_request) == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}
		status = client_handle_challenge_request(mschapv2_header);
		break;

	case mschapv2_opcode_success:
		if (m_session.is_valid_state(eap_type_mschapv2_state_success_request) == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}
		status = client_handle_success_request(mschapv2_header);
		break;

	case mschapv2_opcode_failure:
		if (m_session.is_valid_state(eap_type_mschapv2_state_failure_request) == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}
		status = client_handle_failure_request(mschapv2_header);
		break;

	default:
		break;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

eap_status_e eap_type_mschapv2_c::client_handle_challenge_request(mschapv2_header_c &challenge_request)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::client_handle_challenge_request(): this = 0x%08x\n"),
		this));

	eap_status_e status = eap_status_drop_packet_quietly;

	if (challenge_request.get_data_length() < mschapv2_challenge_c::get_header_minimum_size())
	{ 
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_mschapv2id = challenge_request.get_mschapv2_id();

	mschapv2_challenge_c challenge_payload(
		m_am_tools,
		challenge_request.get_data(),
		challenge_request.get_data_length());

	if (challenge_payload.check_header() != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("client_handle_challenge_request(): mschapv2id"),
		 &m_mschapv2id,
		 sizeof(m_mschapv2id)));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("client_handle_challenge_request(): m_authenticator_challenge"),
		 challenge_payload.get_challenge(),
		 EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));

	m_am_tools->memmove(
		m_authenticator_challenge,
		challenge_payload.get_challenge(),
		EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE);

#if defined(USE_FAST_EAP_TYPE)
	if (m_use_EAP_FAST_challenge == true)
	{
		// Note the received authenticator challenge is zero bytes in EAP-FAST.
		if (m_server_EAP_FAST_challenge.get_is_valid_data() == false
			|| m_server_EAP_FAST_challenge.get_data_length() != EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}

		m_am_tools->memmove(
			m_authenticator_challenge,
			m_server_EAP_FAST_challenge.get_data(),
			EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("client_handle_challenge_request(): EAP-FAST m_authenticator_challenge"),
			 m_authenticator_challenge,
			 EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));
	}
#endif //#if defined(USE_FAST_EAP_TYPE)

	// If no identity, ask it
	if (!m_identity_asked
		&& (m_password_prompt_enabled
			|| m_username_utf8.get_is_valid_data() == false))
	{
		// Prefill username with identity if it is possible
		if (m_username_utf8.get_is_valid_data() == false)
		{
			status = get_type_partner()->get_saved_eap_identity(&m_username_utf8);
		}

		// Open username/password dialog
		status = m_am_type_mschapv2->show_username_password_dialog(
			m_username_utf8,
			m_password_utf8,
			m_password_prompt_enabled,
			false);
	}
	else
	{
		status = client_send_challenge_response();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

eap_status_e eap_type_mschapv2_c::client_send_challenge_response()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::client_send_challenge_response(): this = 0x%08x\n"),
		this));

	eap_status_e status = m_rand.add_rand_seed_hw_ticks();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if defined(USE_FAST_EAP_TYPE)
	if (m_use_EAP_FAST_challenge == true
		&& m_client_EAP_FAST_challenge.get_is_valid_data() == true
		&& m_client_EAP_FAST_challenge.get_data_length() == EAP_MSCHAPV2_PEER_CHALLENGE_SIZE)
	{
		m_am_tools->memmove(
			m_peer_challenge,
			m_client_EAP_FAST_challenge.get_data(),
			EAP_MSCHAPV2_PEER_CHALLENGE_SIZE);
	}
	else
#endif //#if defined(USE_FAST_EAP_TYPE)
	{
		status = m_rand.get_rand_bytes(m_peer_challenge, EAP_MSCHAPV2_PEER_CHALLENGE_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	crypto_nt_hash_c nt_hash(m_am_tools);
	if (nt_hash.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_do_wrong_password_tests == true)
	{
		u8_t crap_from_stack;
		status = m_password_utf8.add_data(&crap_from_stack, sizeof(crap_from_stack));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = nt_hash.nt_password_hash(
		&m_password_utf8,
		&m_password_hash,
		EAP_MSCHAPV2_MD4_DIGEST_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = nt_hash.hash_nt_password_hash(
		&m_password_hash,
		&m_password_hash_hash,
		EAP_MSCHAPV2_MD4_DIGEST_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: client_send_challenge_response(), m_password_utf8"),
		m_password_utf8.get_data(),
		m_password_utf8.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: client_send_challenge_response(), m_authenticator_challenge"),
		m_authenticator_challenge,
		EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: client_send_challenge_response(), m_peer_challenge"),
		m_peer_challenge,
		EAP_MSCHAPV2_PEER_CHALLENGE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: client_send_challenge_response(), m_password_hash"),
		m_password_hash.get_data(),
		m_password_hash.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: client_send_challenge_response(), m_username_utf8"),
		m_username_utf8.get_data(),
		m_username_utf8.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: client_send_challenge_response(): m_authenticator_challenge"),
		 m_authenticator_challenge,
		 EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));

	status = generate_nt_response(
		m_authenticator_challenge,
		m_peer_challenge,
		m_username_utf8.get_data(),
		m_username_utf8.get_data_length(),
		&m_password_hash,
		m_nt_response);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: client_send_challenge_response(), m_nt_response:"),
		m_nt_response,
		EAP_MSCHAPV2_NT_RESPONSE_SIZE));

	// Send response

	const u32_t type_data_length = EAP_MSCHAPV2_HEADER_SIZE // OpCode, MS-CHAPv2-ID and MS-Length
		+ mschapv2_response_c::get_header_minimum_size()
		+ m_username_utf8.get_data_length();

	const u32_t packet_length
		= eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
		+ type_data_length;

	eap_buf_chain_wr_c * packet = create_send_packet(packet_length);
	if (!packet)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_header_base_c eap_header(
		m_am_tools,
		packet->get_data_offset(m_offset, packet_length),
		packet_length);
	if (eap_header.get_is_valid() == false)
	{
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	eap_header.set_code(eap_code_response);
	eap_header.set_identifier(m_identifier);
	eap_header.set_length(
		static_cast<u16_t>(packet_length),
		m_use_eap_expanded_type);
	eap_header.set_type(
		eap_type_mschapv2,
		m_use_eap_expanded_type);

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		eap_header.get_type_data_offset(0, eap_header.get_type_data_length()),
		eap_header.get_type_data_length());

	mschapv2_header.set_opcode(mschapv2_opcode_response);
	mschapv2_header.set_mschapv2_id(m_mschapv2id);
	mschapv2_header.set_ms_length(static_cast<u16_t>(type_data_length));

	mschapv2_response_c response(
		m_am_tools,
		mschapv2_header.get_data(),
		mschapv2_header.get_data_length());
	if (response.get_is_valid() == false)
	{
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = response.set_constants();
	if (status != eap_status_ok)
	{
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


#if defined(USE_FAST_EAP_TYPE)
	if (m_use_EAP_FAST_challenge == true)
	{
		// EAP-FAST sends peer challenge containing only zeroes.
		response.set_peer_challenge(EAP_MSCHAPV2_ZERO_CHALLENGE);
	}
	else
#endif //#if defined(USE_FAST_EAP_TYPE)
	{
		response.set_peer_challenge(m_peer_challenge);
	}

	response.set_nt_response(m_nt_response);

	// Copy username to end of response packet
	u32_t username_ascii_size = m_username_utf8.get_data_length();
	response.set_name(m_username_utf8.get_data(username_ascii_size));

	// Send
	status = packet_send(packet, packet_length);

	delete packet;

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_session.set_state(eap_type_mschapv2_state_challenge_request);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

eap_status_e eap_type_mschapv2_c::client_handle_success_request(mschapv2_header_c & success_request)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::client_handle_success_request(): this = 0x%08x\n"),
		this));

	eap_status_e status = eap_status_drop_packet_quietly;

	if (success_request.get_data_length() < EAP_MSCHAPV2_SUCCESS_REQUEST_MESSAGE_MIN_LENGTH) // Check this out
	{ 
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_mschapv2id = success_request.get_mschapv2_id();

	u8_t * success_payload = success_request.get_data();
	bool response_check;

	eap_variable_data_c new_password_hash(m_am_tools);
	eap_variable_data_c new_password_hash_hash(m_am_tools);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("client_handle_success_request(): m_authenticator_challenge"),
		 m_authenticator_challenge,
		 EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("client_handle_success_request(): m_peer_challenge"),
		 m_peer_challenge,
		 EAP_MSCHAPV2_PEER_CHALLENGE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("client_handle_success_request(): m_nt_response"),
		 m_nt_response,
		 EAP_MSCHAPV2_NT_RESPONSE_SIZE));

	if (m_session.get_state() == eap_type_mschapv2_state_change_password_request)
	{
		// Here we need to generate password hashes from new_password

		crypto_nt_hash_c nt_hash(m_am_tools);
		if (nt_hash.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = nt_hash.nt_password_hash(
			&m_password_utf8,
			&new_password_hash,
			EAP_MSCHAPV2_MD4_DIGEST_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = nt_hash.hash_nt_password_hash(
			&new_password_hash,
			&new_password_hash_hash,
			EAP_MSCHAPV2_MD4_DIGEST_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = check_authenticator_response(
			&new_password_hash_hash,
			m_nt_response,
			m_peer_challenge,
			m_authenticator_challenge,
			m_username_utf8.get_data(),
			m_username_utf8.get_data_length(),
			success_payload,
			response_check);
	}
	else
	{
		status = check_authenticator_response(
			&m_password_hash_hash,
			m_nt_response,
			m_peer_challenge,
			m_authenticator_challenge,
			m_username_utf8.get_data(),
			m_username_utf8.get_data_length(),
			success_payload,
			response_check);
	}
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (response_check)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: client_handle_success_request(): mschapv2_opcode_success, authenticator_response correct\n")));

		// Check if earlier state was password change
		if (m_session.get_state() == eap_type_mschapv2_state_change_password_request)
		{
			if (m_password_prompt_enabled == false)
			{
				// Save new password
				status = m_am_type_mschapv2->update_username_password();
			}

			// Save new hashes
			status = m_password_hash.set_copy_of_buffer(&new_password_hash);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_password_hash_hash.set_copy_of_buffer(&new_password_hash_hash);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// Send success response

		// Return value will be not checked. If fails we still try to finish authentication
		status = send_success_failure_response(true);

		if (m_wait_eap_success == false)
		{
			status = finish_successful_authentication();
			m_session.set_state(eap_type_mschapv2_state_success);
		}
		else
		{
			m_session.set_state(eap_type_mschapv2_state_success_request);
		}
	}
	else // drop
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: client_handle_success_request(): mschapv2_opcode_success, authenticator_response incorrect\n")));

		status = eap_status_drop_packet_quietly;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

eap_status_e eap_type_mschapv2_c::client_handle_failure_request(mschapv2_header_c & failure_request)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::client_handle_failure_request(): this = 0x%08x\n"),
		this));

	eap_status_e status = eap_status_drop_packet_quietly;

	u32_t buffer_left = failure_request.get_data_length();
	if (buffer_left < EAP_MSCHAPV2_FAILURE_MIN_SIZE)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	m_mschapv2id = failure_request.get_mschapv2_id();

	const u8_t * buffer_ptr = failure_request.get_data();

	// "E="
	if (*buffer_ptr != 'E' || *(buffer_ptr + 1) != '=')
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	buffer_ptr += 2;
	buffer_left -= 2;

	while (buffer_left && *buffer_ptr == '0')
	{
		buffer_ptr++;
		buffer_left--;
	}

	if (buffer_left == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	const u8_t * error_code_str = buffer_ptr;

	while (buffer_left && *buffer_ptr != ' ')
	{
		if (*buffer_ptr < '0' || *buffer_ptr > '9')
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}
		buffer_ptr++;
		buffer_left--;
	}

	u32_t error_code_str_len = buffer_ptr - error_code_str;
	if (buffer_left < 43 || error_code_str_len != 3 || *buffer_ptr != ' ') // " R=x C=<32 bytes> V=x", min 43 bytes
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	buffer_ptr++;
	buffer_left--;

	// "R="
	if (*buffer_ptr != 'R' || *(buffer_ptr + 1) != '=')
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	bool retry_allowed = true; // value = 1
	if (*(buffer_ptr + 2) == '0')
	{
		retry_allowed = false;
	}
	else if (*(buffer_ptr + 2) != '1')
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	buffer_ptr += 4;
	buffer_left -= 4;

	// "C="
	if (*buffer_ptr != 'C' || *(buffer_ptr + 1) != '=')
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	buffer_ptr += 2;
	buffer_left -= 2;

	const u8_t * challenge_str = buffer_ptr;
	u32_t i;
	for (i = 0; i < EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE * 2; i++)
	{
		if ((*(buffer_ptr + i) >= '0' && *(buffer_ptr + i) <= '9')
			||
			(*(buffer_ptr + i) >= 'A' && *(buffer_ptr + i) <= 'F'))
		{
			continue;
		}
		break;
	}
	if (i != EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE * 2)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	buffer_ptr += EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE * 2;
	buffer_left -= EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE * 2;

	if (*buffer_ptr != ' '
		|| *(buffer_ptr + 1) != 'V' // " V="
		|| *(buffer_ptr + 2) != '=')
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	buffer_ptr += 3;
	buffer_left -= 3;

	while (buffer_left && *buffer_ptr == '0')
	{
		buffer_ptr++;
		buffer_left--;
	}

	if (buffer_left == 0
		|| *buffer_ptr != '3') // Version must be 3
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	u32_t error_code = 
		(*error_code_str - '0') * 100
		+ (*(error_code_str + 1) - '0') * 10
		+ (*(error_code_str + 2) - '0');
	m_error_code = error_code;

	{
		u32_t length = EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE;

		status = m_am_tools->convert_hex_ascii_to_bytes(
			challenge_str,
			EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE * 2,
			m_authenticator_challenge,
			&length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (length != EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: client_handle_failure_request(): client got auth_challenge:"),
			m_authenticator_challenge,
			EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: client_handle_failure_request(): client has peer_challenge:"),
			m_peer_challenge,
			EAP_MSCHAPV2_PEER_CHALLENGE_SIZE));
	}

#if defined(USE_USER_NOTIFICATIONS)
	// Notification to user
	eap_variable_data_c string(m_am_tools);
	status = m_am_type_mschapv2->read_auth_failure_string(static_cast<eap_mschapv2_error_e> (m_error_code), string);
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
			m_identifier,
			false);
		notification.set_notification_string(&string, true);
		get_type_partner()->state_notification(&notification);
	}
#endif //#if defined(USE_USER_NOTIFICATIONS)

	switch (m_error_code)
	{

	case EAP_MSCHAPV2_ERROR_RESTRICTED_LOGON_HOURS:
	case EAP_MSCHAPV2_ERROR_ACCT_DISABLED:
	case EAP_MSCHAPV2_ERROR_NO_DIALIN_PERMISSION:

		// Notification to user
		if (m_error_code == EAP_MSCHAPV2_ERROR_RESTRICTED_LOGON_HOURS)
		{
			send_error_notification(eap_status_restricted_logon_hours);
		}
		else if (m_error_code == EAP_MSCHAPV2_ERROR_ACCT_DISABLED)
		{
			send_error_notification(eap_status_account_disabled);
		}
		else if (m_error_code == EAP_MSCHAPV2_ERROR_NO_DIALIN_PERMISSION)
		{
			send_error_notification(eap_status_no_dialin_permission);
		}

		// Send failure response
		status = send_success_failure_response(false); // failure
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		break;

	case EAP_MSCHAPV2_ERROR_AUTHENTICATION_FAILURE:

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: client_handle_failure_request(): EAP_MSCHAPV2_ERROR_AUTHENTICATION_FAILURE\n")));

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: client_handle_failure_request(): m_use_implicit_challenge = %d\n"),
			m_use_implicit_challenge));
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

		if (retry_allowed == true
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
			// Note, retry is supported only inside EAP-MsChapv2.
			// Note, inside TTLS/plain-MsChapv2 the retry is not supported. Authentication will fail immediately.
			&& m_use_implicit_challenge == false
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
			)
		{
			m_is_pending = true;

			// Prompt for username/password
			status = m_am_type_mschapv2->show_username_password_dialog(
				m_username_utf8,
				m_password_utf8,
				m_password_prompt_enabled,
				false);
		}
		else
		{
			// Notification to user
			send_error_notification(eap_status_authentication_failure);

			// Send failure response
			status = send_success_failure_response(false);
		}
		break;

	case EAP_MSCHAPV2_ERROR_PASSWD_EXPIRED:
	case EAP_MSCHAPV2_ERROR_CHANGING_PASSWORD:

		if (m_error_code == EAP_MSCHAPV2_ERROR_PASSWD_EXPIRED)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_MSCHAPV2: client_handle_failure_request(): EAP_MSCHAPV2_ERROR_PASSWD_EXPIRED\n")));
		}
		else if (m_error_code == EAP_MSCHAPV2_ERROR_CHANGING_PASSWORD)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_MSCHAPV2: client_handle_failure_request(): EAP_MSCHAPV2_ERROR_CHANGING_PASSWORD\n")));
		}

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: client_handle_failure_request(): m_use_implicit_challenge = %d\n"),
			m_use_implicit_challenge));
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

		if (
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
			m_use_implicit_challenge == false
			&&
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
				(m_error_code == EAP_MSCHAPV2_ERROR_PASSWD_EXPIRED 
				|| (m_error_code == EAP_MSCHAPV2_ERROR_CHANGING_PASSWORD && retry_allowed)))
		{
			m_old_password_utf8.set_copy_of_buffer(&m_password_utf8);

			m_is_pending = true;

			m_session.set_state(eap_type_mschapv2_state_failure_request);

			// Prompt for password change
			status = m_am_type_mschapv2->show_change_password_dialog(
				m_username_utf8,
				m_old_password_utf8,
				m_password_utf8,
				m_password_prompt_enabled);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else // Retry not allowed
		{
			send_error_notification(eap_status_password_expired);

			status = send_success_failure_response(false);

			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			// Show message without retry
		}
		break;

	default:
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	};

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_status_e eap_type_mschapv2_c::eap_acknowledge(
	const eap_am_network_id_c * const /* receive_network_id */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::eap_acknowledge(): this = 0x%08x\n"),
		this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

EAP_FUNC_EXPORT eap_status_e eap_type_mschapv2_c::set_initial_eap_identifier(
	const eap_am_network_id_c * const /*receive_network_id*/,
	const u8_t /*initial_identifier*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::set_initial_eap_identifier(): this = 0x%08x\n"),
		this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

EAP_FUNC_EXPORT eap_status_e eap_type_mschapv2_c::query_eap_identity(
	const bool /*must_be_synchronous*/,
	eap_variable_data_c * const identity,
	const eap_am_network_id_c * const receive_network_id,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::query_eap_identity(): this = 0x%08x\n"),
		this));

	if (m_session.is_valid_state(eap_type_mschapv2_state_identity_request) == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());

	m_identifier = eap_identifier;

	eap_status_e status;

	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, (
		EAPL("eap_type_mschapv2_c::query_eap_identity: m_identity_asked=%d, m_password_prompt_enabled=%d\n"),
		m_identity_asked, m_password_prompt_enabled));

	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, (
		EAPL("eap_type_mschapv2_c::query_eap_identity: user name length=%d, PW length=%d, m_is_pending=%d\n"),
		m_username_utf8.get_data_length(), m_password_utf8.get_data_length(), m_is_pending));

	if (m_identity_asked == false && // Only at first time username/password dialog is shown if needed
		(m_username_utf8.get_is_valid_data() == false
        || m_username_utf8.get_data_length() == 0
		|| m_password_prompt_enabled == true))
	{
		// Ask username and password

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: query_eap_identity(): m_username_utf8:"),
			m_username_utf8.get_data(),
			m_username_utf8.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: query_eap_identity(): m_password_utf8:"),
			 m_password_utf8.get_data(),
			 m_password_utf8.get_data_length()));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: query_eap_identity(): password length %d\n"),
			m_password_utf8.get_buffer_length()));

		if (m_is_pending == false)
		{
			m_is_pending = true;
			status = m_am_type_mschapv2->show_username_password_dialog(
				m_username_utf8,
				m_password_utf8,
				m_password_prompt_enabled,
				true);
			if (status == eap_status_pending_request
				|| status == eap_status_completed_request)
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
				(EAPL("EAP_type_MSCHAPV2: query_eap_identity(): identity query is already pending!.\n")));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_pending_request);
		}
	}

	m_identity_asked = true;

	// If this is not the first query, use already stored identity information for reply
	status = identity->set_copy_of_buffer(&m_username_utf8);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: query_eap_identity(): identity:"),
		identity->get_data(),
		identity->get_data_length()));

	m_session.set_state(eap_type_mschapv2_state_identity_request);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_status_e eap_type_mschapv2_c::complete_eap_identity_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: complete_eap_identity_query() m_username_utf8:"),
		m_username_utf8.get_data(),
		m_username_utf8.get_data_length()));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: complete_eap_identity_query(), password length %d\n"),
		m_password_utf8.get_buffer_length()));

	m_identity_asked = true;

	m_session.set_state(eap_type_mschapv2_state_identity_request);

	eap_status_e status = get_type_partner()->complete_eap_identity_query(
		&m_send_network_id,
		&m_username_utf8,
		m_identifier);
	if (status != eap_status_ok)
	{
		m_session.set_state(eap_type_mschapv2_state_failure);
	}

	m_is_pending = false;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

eap_status_e eap_type_mschapv2_c::send_success_failure_response(bool is_success_response)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::send_success_failure_response(): this = 0x%08x\n"),
		this));

	eap_status_e status = eap_status_allocation_error;
   
	u32_t packet_length
		= EAP_MSCHAPV2_OPCODE_SIZE // OpCode is the only payload
		+ eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type);

	eap_buf_chain_wr_c * packet = create_send_packet(packet_length);
	if (!packet)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_header_base_c eap_header(
		m_am_tools,
		packet->get_data_offset(m_offset, packet_length),
		packet_length);
	if (eap_header.get_is_valid() == false)
	{
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	eap_header.set_code(eap_code_response);
	eap_header.set_identifier(m_identifier);
	eap_header.set_length(
		static_cast<u16_t>(packet_length),
		m_use_eap_expanded_type);
	eap_header.set_type(
		eap_type_mschapv2,
		m_use_eap_expanded_type);

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		eap_header.get_type_data_offset(0, eap_header.get_type_data_length()),
		eap_header.get_type_data_length());

	if (is_success_response)
	{
		mschapv2_header.set_opcode(mschapv2_opcode_success);
		m_session.set_state(eap_type_mschapv2_state_success_request);
	}
	else
	{
		mschapv2_header.set_opcode(mschapv2_opcode_failure);
		m_session.set_state(eap_type_mschapv2_state_failure_request);
	}

	status = packet_send(packet, packet_length);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: send_success_failure_response():\n")));

	delete packet;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_status_e eap_type_mschapv2_c::complete_failure_retry_response()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::complete_failure_retry_response(): this = 0x%08x\n"),
		this));

	m_is_pending = false;

	eap_status_e status = m_rand.add_rand_seed_hw_ticks();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_rand.add_rand_seed(
		m_password_utf8.get_data(),
		m_password_utf8.get_data_length()); 
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if defined(USE_FAST_EAP_TYPE)
	if (m_use_EAP_FAST_challenge == true
		&& m_client_EAP_FAST_challenge.get_is_valid_data() == true
		&& m_client_EAP_FAST_challenge.get_data_length() == EAP_MSCHAPV2_PEER_CHALLENGE_SIZE)
	{
		m_am_tools->memmove(
			m_peer_challenge,
			m_client_EAP_FAST_challenge.get_data(),
			EAP_MSCHAPV2_PEER_CHALLENGE_SIZE);
	}
	else
#endif //#if defined(USE_FAST_EAP_TYPE)
	{
		status = m_rand.get_rand_bytes(
			m_peer_challenge,
			EAP_MSCHAPV2_PEER_CHALLENGE_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	crypto_nt_hash_c nt_hash(m_am_tools);
	if (nt_hash.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = nt_hash.nt_password_hash(
		&m_password_utf8,
		&m_password_hash,
		EAP_MSCHAPV2_MD4_DIGEST_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = nt_hash.hash_nt_password_hash(
		&m_password_hash,
		&m_password_hash_hash,
		EAP_MSCHAPV2_MD4_DIGEST_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: complete_failure_retry_response(), m_password_utf8"),
		m_password_utf8.get_data(),
		m_password_utf8.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: complete_failure_retry_response(), m_authenticator_challenge"),
		m_authenticator_challenge,
		EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: complete_failure_retry_response(), m_peer_challenge"),
		m_peer_challenge,
		EAP_MSCHAPV2_PEER_CHALLENGE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: complete_failure_retry_response(), m_password_hash"),
		m_password_hash.get_data(),
		m_password_hash.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: complete_failure_retry_response(), m_username_utf8"),
		m_username_utf8.get_data(),
		m_username_utf8.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: complete_failure_retry_response(): m_authenticator_challenge"),
		 m_authenticator_challenge,
		 EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));


	status = generate_nt_response(
		m_authenticator_challenge,
		m_peer_challenge,
		m_username_utf8.get_data(),
		m_username_utf8.get_data_length(),
		&m_password_hash,
		m_nt_response);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: complete_failure_retry_response(), m_nt_response:"),
		m_nt_response,
		EAP_MSCHAPV2_NT_RESPONSE_SIZE));

	// Send response

	const u32_t type_data_length = EAP_MSCHAPV2_HEADER_SIZE // OpCode, MS-CHAPv2-ID and MS-Length
		+ mschapv2_response_c::get_header_minimum_size()
		+ m_username_utf8.get_data_length();

	const u32_t packet_length = eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
		+ type_data_length;

	eap_buf_chain_wr_c * packet = create_send_packet(packet_length);

	if (!packet)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	

	eap_header_base_c eap_header(
		m_am_tools,
		packet->get_data_offset(m_offset, packet_length),
		packet_length);
	if (eap_header.get_is_valid() == false)
	{
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	eap_header.set_code(eap_code_response);
	eap_header.set_identifier(m_identifier);
	eap_header.set_length(
		static_cast<u16_t>(packet_length),
		m_use_eap_expanded_type);
	eap_header.set_type(
		eap_type_mschapv2,
		m_use_eap_expanded_type);

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		eap_header.get_type_data_offset(0, eap_header.get_type_data_length()),
		eap_header.get_type_data_length());

	mschapv2_header.set_opcode(mschapv2_opcode_response);
	mschapv2_header.set_mschapv2_id(++m_mschapv2id);
	mschapv2_header.set_ms_length(static_cast<u16_t>(type_data_length));

	mschapv2_response_c response(
		m_am_tools,
		mschapv2_header.get_data(),
		mschapv2_header.get_data_length());
	if (response.get_is_valid() == false)
	{
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = response.set_constants();
	if (status != eap_status_ok)
	{
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	response.set_nt_response(m_nt_response);
	response.set_peer_challenge(m_peer_challenge);
	response.set_name(m_username_utf8.get_data());

	// Send
	status = packet_send(packet, packet_length);
	delete packet;

	m_session.set_state(eap_type_mschapv2_state_challenge_request);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_status_e eap_type_mschapv2_c::complete_change_password_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::complete_change_password_query(): this = 0x%08x\n"),
		this));

	eap_status_e status = eap_status_process_general_error;

	m_is_pending = false;

	status = m_rand.add_rand_seed_hw_ticks();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_rand.add_rand_seed(
		m_password_utf8.get_data(),
		m_password_utf8.get_data_length()); 
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if defined(USE_FAST_EAP_TYPE)
	if (m_use_EAP_FAST_challenge == true
		&& m_client_EAP_FAST_challenge.get_is_valid_data() == true
		&& m_client_EAP_FAST_challenge.get_data_length() == EAP_MSCHAPV2_PEER_CHALLENGE_SIZE)
	{
		m_am_tools->memmove(
			m_peer_challenge,
			m_client_EAP_FAST_challenge.get_data(),
			EAP_MSCHAPV2_PEER_CHALLENGE_SIZE);
	}
	else
#endif //#if defined(USE_FAST_EAP_TYPE)
	{
		status = m_rand.get_rand_bytes(m_peer_challenge, EAP_MSCHAPV2_PEER_CHALLENGE_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	u8_t * encrypted_pw_block = new u8_t[sizeof(pw_block_s)];
	if (!encrypted_pw_block)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c new_password_hash(m_am_tools);

	crypto_nt_hash_c nt_hash(m_am_tools);
	if (nt_hash.get_is_valid() == false)
	{
		delete [] encrypted_pw_block;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = nt_hash.nt_password_hash(
		&m_password_utf8,
		&new_password_hash,
		EAP_MSCHAPV2_MD4_DIGEST_SIZE);
	if (status != eap_status_ok)
	{
		delete [] encrypted_pw_block;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = new_password_encrypted_with_old_nt_password_hash(
		&m_password_utf8,
		&m_password_hash,
		encrypted_pw_block);
	if (status != eap_status_ok)
	{
		delete [] encrypted_pw_block;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c encrypted_pw_hash(m_am_tools);

	status = old_nt_password_hash_encrypted_with_new_nt_password_hash(
		&new_password_hash,
		&m_password_hash,
		&encrypted_pw_hash);
	if (status != eap_status_ok)
	{
		delete [] encrypted_pw_block;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("complete_change_password_query(): m_authenticator_challenge"),
		 m_authenticator_challenge,
		 EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));

	status = generate_nt_response(
		m_authenticator_challenge,
		m_peer_challenge,
		m_username_utf8.get_data(),
		m_username_utf8.get_data_length(),
		&new_password_hash,
		m_nt_response);
	if (status != eap_status_ok)
	{
		delete [] encrypted_pw_block;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const u32_t type_data_length = EAP_MSCHAPV2_HEADER_SIZE // OpCode, MS-CHAPv2-ID and MS-Length
		+ mschapv2_change_password_c::get_header_minimum_size();

	const u32_t packet_length
		= eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
		+ type_data_length;


	eap_buf_chain_wr_c * packet = create_send_packet(packet_length);
	if (!packet)
	{
		delete [] encrypted_pw_block;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_header_base_c eap_header(
		m_am_tools,
		packet->get_data_offset(m_offset, packet_length),
		packet_length);
	if (eap_header.get_is_valid() == false)
	{
		delete [] encrypted_pw_block;
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	eap_header.set_code(eap_code_response);
	eap_header.set_identifier(m_identifier);
	eap_header.set_length(
		static_cast<u16_t>(packet_length),
		m_use_eap_expanded_type);
	eap_header.set_type(
		eap_type_mschapv2,
		m_use_eap_expanded_type);

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		eap_header.get_type_data_offset(0, eap_header.get_type_data_length()),
		eap_header.get_type_data_length());

	mschapv2_header.set_opcode(mschapv2_opcode_change_password);
	mschapv2_header.set_mschapv2_id(static_cast<u8_t>((++m_mschapv2id)));
	mschapv2_header.set_ms_length(static_cast<u16_t>(type_data_length));

	mschapv2_change_password_c response(
		m_am_tools,
		mschapv2_header.get_data(),
		mschapv2_header.get_data_length());
	if (response.get_is_valid() == false)
	{
		delete [] encrypted_pw_block;
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = response.set_constants();
	if (status != eap_status_ok)
	{
		delete [] encrypted_pw_block;
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	response.set_encrypted_pw_block(encrypted_pw_block);
	delete [] encrypted_pw_block;
	response.set_encrypted_hash(encrypted_pw_hash.get_data());
	response.set_peer_challenge(m_peer_challenge);
	response.set_nt_response(m_nt_response);

	// Send change password response
	status = packet_send(packet, packet_length);
	delete packet;
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_session.set_state(eap_type_mschapv2_state_change_password_request);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

// End of file.
