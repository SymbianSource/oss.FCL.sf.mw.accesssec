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
	#define EAP_FILE_NUMBER_ENUM 99 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_type_mschapv2.h"
#include "eap_buffer.h"
#include "eap_master_session_key.h"
#include "eap_network_id_selector.h"
#include "eap_tlv_message_data.h"
#include "eap_automatic_variable.h"


#if defined(EAP_MSCHAPV2_SERVER)

eap_status_e eap_type_mschapv2_c::server_packet_process(
	eap_header_wr_c * const received_eap,
	const u32_t eap_packet_length)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_drop_packet_quietly;

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	if (m_session.get_state() != eap_type_mschapv2_state_none
		&& m_use_implicit_challenge == false
		&& m_identifier != received_eap->get_identifier())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else
	{
		m_identifier = received_eap->get_identifier();
	}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	if (received_eap->get_type() == eap_type_identity)
	{
		status = handle_identity_response_message();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (received_eap->get_code() == eap_code_success
		|| received_eap->get_code() == eap_code_failure)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else if (received_eap->get_code() == eap_code_response) // Response
	{
		if (eap_packet_length <= eap_header_base_c::get_header_length())
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}

		// MsChapV2
		if (received_eap->get_type() == eap_type_mschapv2)
		{
			status = server_mschapv2_packet_process(
				received_eap,
				eap_packet_length);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_MSCHAPV2_SERVER)


#if defined(EAP_MSCHAPV2_SERVER)

eap_status_e eap_type_mschapv2_c::server_mschapv2_packet_process(
	eap_header_wr_c * const received_eap,
	const u32_t eap_packet_length)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_drop_packet_quietly;

	u32_t type_data_length = received_eap->get_type_data_length();

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		received_eap->get_type_data_offset(0, type_data_length),
		type_data_length);

	if (mschapv2_header.check_header() != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	if (eap_packet_length <= eap_header_base_c::get_header_length())
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("EAP_type_MSCHAPV2: illegal mschapv2 packet length\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	if ((mschapv2_header.get_opcode() == mschapv2_opcode_response
		|| mschapv2_header.get_opcode() == mschapv2_opcode_change_password)
		&& type_data_length != mschapv2_header.get_ms_length())
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("EAP_type_MSCHAPV2: illegal mschapv2 packet length\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	switch (mschapv2_header.get_opcode())
	{
	case mschapv2_opcode_response:
		status = server_handle_challenge_response(mschapv2_header);
		break;

	case mschapv2_opcode_success:
		status = server_handle_success_response();
		break;

	case mschapv2_opcode_failure:
		status = server_handle_failure_response();
		break;

	case mschapv2_opcode_change_password:
		status = server_handle_password_change(mschapv2_header);
		break;

	default:
		break;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_MSCHAPV2_SERVER)


#if defined(EAP_MSCHAPV2_SERVER)

bool eap_type_mschapv2_c::check_expired_password()
{
	if (m_do_password_expiration_tests == true)
	{
		if (m_password_expired == false)
		{
			m_password_expired = true;
		}
		else
		{
			m_password_expired = false;
		}

		return m_password_expired;
	}

	return false;
}

#endif //#if defined(EAP_MSCHAPV2_SERVER)


#if defined(EAP_MSCHAPV2_SERVER)

static const u8_t eap_mschapv2_challenge_response_message[] = "Message1";
static const u8_t eap_mschapv2_failure_message[] = "Message3";


eap_status_e eap_type_mschapv2_c::server_handle_challenge_response(mschapv2_header_c &machapv2_packet)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_header_corrupted;
	
	mschapv2_response_c response(
		m_am_tools,
		machapv2_packet.get_data(),
		machapv2_packet.get_data_length());
	if (response.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: server_handle_challenge_response(): response packet:"),
		response.get_header_buffer(response.get_header_buffer_length()),
		response.get_header_buffer_length()));

	if (response.check_header() != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	
	if (!m_session.is_valid_state(eap_type_mschapv2_state_challenge_response))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	// Check username
	m_am_tools->memmove(
		m_peer_challenge,
		response.get_peer_challenge(),
		EAP_MSCHAPV2_PEER_CHALLENGE_SIZE);

#if defined(USE_FAST_EAP_TYPE)
	if (m_use_EAP_FAST_challenge == true)
	{
		// Note the received authenticator challenge is zero bytes in EAP-FAST.
		if (m_client_EAP_FAST_challenge.get_is_valid_data() == false
			|| m_client_EAP_FAST_challenge.get_data_length() != EAP_MSCHAPV2_PEER_CHALLENGE_SIZE)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}

		m_am_tools->memmove(
			m_peer_challenge,
			m_client_EAP_FAST_challenge.get_data(),
			EAP_MSCHAPV2_PEER_CHALLENGE_SIZE);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("client_handle_challenge_request(): EAP-FAST m_peer_challenge"),
			 m_peer_challenge,
			 EAP_MSCHAPV2_PEER_CHALLENGE_SIZE));
	}
#endif //#if defined(USE_FAST_EAP_TYPE)

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
		(EAPL("EAP_type_MSCHAPV2: server_handle_challenge_response(): m_password_utf8"),
		m_password_utf8.get_data(),
		m_password_utf8.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: server_handle_challenge_response(): m_authenticator_challenge"),
		m_authenticator_challenge,
		EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: server_handle_challenge_response(): m_peer_challenge"),
		m_peer_challenge,
		EAP_MSCHAPV2_PEER_CHALLENGE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: server_handle_challenge_response(): m_password_hash"),
		m_password_hash.get_data(),
		m_password_hash.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: server_handle_challenge_response(): m_username_utf8"),
		m_username_utf8.get_data(),
		m_username_utf8.get_data_length()));

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
		(EAPL("EAP_type_MSCHAPV2: server_handle_challenge_response(): m_nt_response:"),
		m_nt_response,
		EAP_MSCHAPV2_NT_RESPONSE_SIZE));

	// Check peer_response == nt_response
	if (m_am_tools->memcmp(
		m_nt_response,
		response.get_nt_response(),
		EAP_MSCHAPV2_NT_RESPONSE_SIZE)
		== 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: server_handle_challenge_response(): correct password\n")));

		// Is password expired?
		if (check_expired_password() == true)
		{
			m_error_code = EAP_MSCHAPV2_ERROR_PASSWD_EXPIRED;
			bool retry_allowed = true; // ?

			u32_t message_length = sizeof(eap_mschapv2_challenge_response_message) - 1;

			status = send_failure_request(
				retry_allowed,
				eap_mschapv2_challenge_response_message,
				message_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		  
			m_session.set_state(eap_type_mschapv2_state_challenge_response, eap_type_mschapv2_state_change_password_response);
			
			  // Any other restrictions?
			status = eap_status_ok;
		}
		else
		{
			u32_t message_length = sizeof(eap_mschapv2_challenge_response_message) - 1;

			status = send_success_request(
				eap_mschapv2_challenge_response_message,
				message_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		
			m_session.set_state(eap_type_mschapv2_state_challenge_response, eap_type_mschapv2_state_success_response);
			status = eap_status_ok;
		}
	}
	else // Incorrect password
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: EAP_type_MSCHAPV2: server_handle_challenge_response(): incorrect password\n")));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: server_handle_challenge_response(): m_nt_response:"),
			m_nt_response,
			EAP_MSCHAPV2_NT_RESPONSE_SIZE));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: server_handle_challenge_response(): response.get_nt_response():"),
			response.get_nt_response(),
			EAP_MSCHAPV2_NT_RESPONSE_SIZE));
		
		m_error_code = EAP_MSCHAPV2_ERROR_AUTHENTICATION_FAILURE;
		
		bool retry_allowed = true; // TEST
		
		u32_t message_length = sizeof(eap_mschapv2_failure_message) - 1;
		
		status = send_failure_request(
			retry_allowed,
			eap_mschapv2_failure_message,
			message_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
#if defined(USE_FAST_EAP_TYPE)
		if (m_use_EAP_FAST_challenge == true)
		{
			(void) send_error_notification(eap_status_tunnel_compromise_error);
		}
#endif //#if defined(USE_FAST_EAP_TYPE)

		m_session.set_state(eap_type_mschapv2_state_challenge_response, eap_type_mschapv2_state_challenge_response);
		status = eap_status_ok;
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_MSCHAPV2_SERVER)


#if defined(EAP_MSCHAPV2_SERVER)

eap_status_e eap_type_mschapv2_c::server_handle_success_response()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_drop_packet_quietly;

	if (m_session.is_valid_state(eap_type_mschapv2_state_success_response))
	{
		eap_master_session_key_c key(
			m_am_tools,
			eap_type_mschapv2);

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

		status = finish_successful_authentication();

		m_session.set_state(eap_type_mschapv2_state_success_response);

		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_MSCHAPV2_SERVER)


#if defined(EAP_MSCHAPV2_SERVER)

eap_status_e eap_type_mschapv2_c::server_handle_failure_response()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	if (m_session.is_valid_state(eap_type_mschapv2_state_failure_response))
	{
		finish_unsuccessful_authentication(false);
		m_session.set_state(eap_type_mschapv2_state_failure_response);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
}

#endif //#if defined(EAP_MSCHAPV2_SERVER)


#if defined(EAP_MSCHAPV2_SERVER)

static const u8_t eap_mschapv2_password_change_message[] = "Message4";

eap_status_e eap_type_mschapv2_c::server_handle_password_change(mschapv2_header_c &machapv2_packet)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	if (!m_session.is_valid_state(eap_type_mschapv2_state_change_password_response))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	
	if (machapv2_packet.get_data_length() < mschapv2_change_password_c::get_header_minimum_size()) 
	{ 
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
		
	mschapv2_change_password_c change_password_payload(
		m_am_tools,
		machapv2_packet.get_data(),
		machapv2_packet.get_data_length());
	if (change_password_payload.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	if (change_password_payload.check_header() != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	m_am_tools->memmove(
		m_peer_challenge,
		change_password_payload.get_peer_challenge(),
		EAP_MSCHAPV2_PEER_CHALLENGE_SIZE);
	
#if defined(USE_FAST_EAP_TYPE)
	if (m_use_EAP_FAST_challenge == true)
	{
		if (m_client_EAP_FAST_challenge.get_is_valid_data() == false
			|| m_client_EAP_FAST_challenge.get_data_length() != EAP_MSCHAPV2_PEER_CHALLENGE_SIZE
			|| m_client_EAP_FAST_challenge.compare(m_peer_challenge, EAP_MSCHAPV2_PEER_CHALLENGE_SIZE) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
	}
#endif //#if defined(USE_FAST_EAP_TYPE)

	// Encypted-Password has been made by NewPasswordEncryptedWithOldNtPassword()
	eap_variable_data_c old_password_hash(m_am_tools);
	
	crypto_nt_hash_c nt_hash(m_am_tools);
	if (nt_hash.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = nt_hash.nt_password_hash(
		&m_password_utf8,
		&old_password_hash,
		EAP_MSCHAPV2_MD4_DIGEST_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	
	eap_variable_data_c tmp_password_unicode(
		m_am_tools);

	eap_variable_data_c tmp_password_utf8(
		m_am_tools);

	u8_t * new_password = 0;
	
	u32_t pw_size;
	
	{
		pw_block_s * new_pw_block = new pw_block_s;

		eap_automatic_variable_c<pw_block_s> automatic_new_pw_block(m_am_tools, new_pw_block);

		if (!new_pw_block)
		{
			status = eap_status_allocation_error;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = rc4_decrypt(
			change_password_payload.get_encrypted_pw_block(), // cypher
			sizeof(pw_block_s),
			old_password_hash.get_data(EAP_MSCHAPV2_MD4_DIGEST_SIZE), // key
			EAP_MSCHAPV2_MD4_DIGEST_SIZE,
			reinterpret_cast<u8_t *>(new_pw_block)); // plain

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

#ifdef EAP_BIG_ENDIAN        
		pw_size = eap_ntohl(new_pw_block->password_length);
#else
		pw_size = new_pw_block->password_length;
#endif
		if (pw_size > EAP_MSCHAPV2_PASSWORD_MAX_SIZE)
		{
			const u32_t message_length = sizeof(eap_mschapv2_password_change_message) - 1;
			m_error_code = EAP_MSCHAPV2_ERROR_CHANGING_PASSWORD;
			bool retry_allowed = true;
		
			status = send_failure_request(
				retry_allowed,
				eap_mschapv2_password_change_message,
				message_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
	
			m_session.set_state(eap_type_mschapv2_state_change_password_response, eap_type_mschapv2_state_change_password_response);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}

		status = tmp_password_unicode.set_copy_of_buffer(
			(reinterpret_cast<u8_t *>(new_pw_block)) + EAP_MSCHAPV2_PASSWORD_MAX_SIZE - pw_size, // offset,
			pw_size);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_am_tools->convert_unicode_to_utf8(tmp_password_utf8, tmp_password_unicode);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	
	// Encrypted-Hash has been made by old_nt_password_hash_encrypted_with_new_password_hash()
	
	eap_variable_data_c new_password_hash(m_am_tools);

	status = nt_hash.nt_password_hash(
		&tmp_password_utf8,
		&new_password_hash,
		EAP_MSCHAPV2_MD4_DIGEST_SIZE);
	if (status != eap_status_ok)
	{
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
		delete [] new_password;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
		
	if (m_am_tools->memcmp(
		encrypted_pw_hash.get_data(EAP_MSCHAPV2_MD4_DIGEST_SIZE),
		change_password_payload.get_encrypted_hash(),
		EAP_MSCHAPV2_MD4_DIGEST_SIZE) == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: server_handle_password_change(): password change accepted\n")));
		
		// Checked
		
		// Store new password
		status = m_password_utf8.set_copy_of_buffer(&tmp_password_utf8);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_password_hash.set_copy_of_buffer(&new_password_hash);
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
			(EAPL("server_handle_password_change(): m_authenticator_challenge"),
			m_authenticator_challenge,
			EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("server_handle_password_change(): m_peer_challenge"),
			 m_peer_challenge,
			 EAP_MSCHAPV2_PEER_CHALLENGE_SIZE));

		// Generate new nt_response
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

		// Send Success request
		
	   u8_t message[] = "";
		u32_t message_length = 0;
		
		status = send_success_request(
			message,
			message_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		m_session.set_state(eap_type_mschapv2_state_change_password_response, eap_type_mschapv2_state_success_response);
	}
	else // Challenge response didn't match
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_MSCHAPV2: server_handle_password_change(): password change NOT accepted\n")));

		delete [] new_password;
		
		u32_t message_length = sizeof(eap_mschapv2_password_change_message) - 1;
		m_error_code = EAP_MSCHAPV2_ERROR_CHANGING_PASSWORD;
		bool retry_allowed = true;
		
		status = send_failure_request(
			retry_allowed,
			eap_mschapv2_password_change_message,
			message_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		m_session.set_state(eap_type_mschapv2_state_change_password_response, eap_type_mschapv2_state_failure_response);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif //#if defined(EAP_MSCHAPV2_SERVER)


#if defined(EAP_MSCHAPV2_SERVER)

EAP_FUNC_EXPORT eap_status_e eap_type_mschapv2_c::handle_identity_response_message()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	// Send challenge

	status = m_rand.add_rand_seed_hw_ticks();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


#if defined(USE_FAST_EAP_TYPE)
	if (m_use_EAP_FAST_challenge == true
		&& m_server_EAP_FAST_challenge.get_is_valid_data() == true
		&& m_server_EAP_FAST_challenge.get_data_length() == EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE)
	{
		m_am_tools->memmove(
			m_authenticator_challenge,
			m_server_EAP_FAST_challenge.get_data(),
			EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE);
	}
	else
#endif //#if defined(USE_FAST_EAP_TYPE)
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	if (m_use_implicit_challenge == true)
	{
		eap_variable_data_c memory_store_key(m_am_tools);

		eap_status_e status = memory_store_key.set_copy_of_buffer(
			EAP_MSCHAPV2_IMPLICIT_CHALLENGE_HANDLE_KEY,
			sizeof(EAP_MSCHAPV2_IMPLICIT_CHALLENGE_HANDLE_KEY));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = memory_store_key.add_data(
			&m_is_client,
			sizeof(m_is_client));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_am_network_id_c receive_network_id(m_am_tools,
			m_send_network_id.get_destination_id(),
			m_send_network_id.get_source_id(),
			m_send_network_id.get_type());

		eap_network_id_selector_c state_selector(
			m_am_tools,
			&receive_network_id);

		status = memory_store_key.add_data(
			&state_selector);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_tlv_message_data_c tlv_data(m_am_tools);

		status = m_am_tools->memory_store_get_data(
			&memory_store_key,
			&tlv_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_MSCHAPV2: handle_identity_response_message(): cannot get credentials\n")));
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_MSCHAPV2: handle_identity_response_message(): credentials found\n")));

			// Parse read data.
			eap_array_c<eap_tlv_header_c> tlv_blocks(m_am_tools);
				
			status = tlv_data.parse_message_data(&tlv_blocks);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			bool implicit_challenge_read(false);

			for (u32_t ind = 0ul; ind < tlv_blocks.get_object_count(); ind++)
			{
				eap_tlv_header_c * const tlv = tlv_blocks.get_object(ind);
				if (tlv != 0)
				{
					if (tlv->get_type() == eap_type_mschapv2_implicit_challenge)
					{
						m_am_tools->memmove(
							m_authenticator_challenge,
							tlv->get_value(tlv->get_value_length()),
							tlv->get_value_length());

						implicit_challenge_read = true;
					}
				}
			} // for()

			if (implicit_challenge_read == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}
		}
	}
	else
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	{
		status = m_rand.get_rand_bytes(m_authenticator_challenge, EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("handle_identity_response_message(): m_authenticator_challenge"),
		m_authenticator_challenge,
		EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));

	const u32_t name_length = m_username_utf8.get_data_length();

	const u32_t type_data_length = EAP_MSCHAPV2_HEADER_SIZE // OpCode, MS-CHAPv2-ID and MS-Length
		+ mschapv2_challenge_c::get_header_minimum_size()
		+ name_length;

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
		packet = 0;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	eap_header.set_code(eap_code_request);
	eap_header.set_identifier(++m_identifier);
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

	mschapv2_header.set_opcode(mschapv2_opcode_challenge);
	mschapv2_header.set_mschapv2_id(static_cast<u8_t>(++m_mschapv2id));
	mschapv2_header.set_ms_length(static_cast<u16_t>(type_data_length));

	mschapv2_challenge_c challenge_packet(
		m_am_tools,
		mschapv2_header.get_data(),
		mschapv2_header.get_data_length());
	if (challenge_packet.get_is_valid() == false)
	{
		delete packet;
		packet = 0;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

#if defined(USE_FAST_EAP_TYPE)
	if (m_use_EAP_FAST_challenge == true)
	{
		// EAP-FAST sends authenticator challenge containing only zeroes.
		challenge_packet.set_challenge(EAP_MSCHAPV2_ZERO_CHALLENGE);
	}
	else
#endif //#if defined(USE_FAST_EAP_TYPE)
	{
		challenge_packet.set_challenge(m_authenticator_challenge);
	}

	challenge_packet.set_value_size();
	challenge_packet.set_name(m_username_utf8.get_data(name_length));

	// This must be set before packet_send() call to allow
	// the plain MsChapv2 to work.
	m_session.set_state(eap_type_mschapv2_state_identity_response);

	// Send packet
	status = packet_send(packet, packet_length);

	delete packet;
	packet = 0;

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_MSCHAPV2_SERVER)


#if defined(EAP_MSCHAPV2_SERVER)

eap_status_e eap_type_mschapv2_c::send_failure_request(
	const bool retry_allowed,
	const u8_t * const message,
	const u32_t message_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("EAP_type_MSCHAPV2: send_failure_request\n")));

	u32_t retry = 0;
	if (retry_allowed)
	{
		retry = 1;
	}

	// Generate new auth_challenge

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
		status = m_rand.get_rand_bytes(m_authenticator_challenge, EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: send_failure_request(): m_authenticator_challenge"),
		m_authenticator_challenge,
		EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: send_failure_request(): m_peer_challenge"),
		 m_peer_challenge,
		 EAP_MSCHAPV2_PEER_CHALLENGE_SIZE));

	u8_t * auth_challenge_str = new u8_t[EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE * 2];
	if (!auth_challenge_str)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t length = 2 * EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE;

	status = m_am_tools->convert_bytes_to_hex_ascii(
		m_authenticator_challenge,
		EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE,
		auth_challenge_str,
		&length);
	if (status != eap_status_ok
		|| length != 2 * EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE)
	{
		delete [] auth_challenge_str;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	m_am_tools->convert_ascii_to_uppercase(auth_challenge_str, length);

	const u32_t type_data_length = 
		+ EAP_MSCHAPV2_HEADER_SIZE // OpCode, MS-CHAPv2-ID and MS-Length
		+ EAP_MSCHAPV2_FAILURE_REQUEST_SIZE
		+ message_length;

	const u32_t packet_length
		= eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
		+ type_data_length;

	eap_buf_chain_wr_c * packet = create_send_packet(packet_length);
	if (!packet)
	{
		delete [] auth_challenge_str;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_header_base_c eap_header(
		m_am_tools,
		packet->get_data_offset(m_offset, packet_length),
		packet_length);
	if (eap_header.get_is_valid() == false)
	{
		delete [] auth_challenge_str;
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	eap_header.set_code(eap_code_request);
	eap_header.set_identifier(++m_identifier);
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

	mschapv2_header.set_opcode(mschapv2_opcode_failure);
	mschapv2_header.set_mschapv2_id(static_cast<u8_t>(++m_mschapv2id));
	mschapv2_header.set_ms_length(static_cast<u16_t>(type_data_length));

	u8_t * failure_data = mschapv2_header.get_data(); // @{...}
	if (failure_data == 0)
	{
		delete [] auth_challenge_str;
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	if (m_am_tools->snprintf(
		failure_data,
		EAP_MSCHAPV2_FAILURE_REQUEST_SIZE,
		"E=%010u R=%1u C=12345678901234567890123456789012 V=%010u M=", // auth_challenge will be set by memcpy
		m_error_code,
		retry,
		3L) != EAP_MSCHAPV2_FAILURE_REQUEST_SIZE)
	{
		delete [] auth_challenge_str;
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_am_tools->memmove(
		failure_data + 12 + 1 + 3 + 1 + 2, // pointer to just after "C="
		auth_challenge_str,
		EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE * 2);

	delete [] auth_challenge_str;

	if (message_length != 0)
	{
		// Copy message to end of packet
		m_am_tools->memmove(
			failure_data + EAP_MSCHAPV2_FAILURE_REQUEST_SIZE,
			message,
			message_length);
	}

	status = packet_send(packet, packet_length);
	delete packet;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_MSCHAPV2_SERVER)


#if defined(EAP_MSCHAPV2_SERVER)

eap_status_e eap_type_mschapv2_c::send_success_request(
	const u8_t * const message,
	const u32_t message_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("EAP_type_MSCHAPV2: send_success_request\n")));

	u8_t * auth_response = new u8_t[EAP_MSCHAPV2_AUTHENTICATOR_RESPONSE_SIZE];
	if (!auth_response)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send_success_request(): m_authenticator_challenge"),
		m_authenticator_challenge,
		EAP_MSCHAPV2_AUTHENTICATOR_CHALLENGE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send_success_request(): m_peer_challenge"),
		 m_peer_challenge,
		 EAP_MSCHAPV2_PEER_CHALLENGE_SIZE));

	eap_status_e status = generate_authenticator_response(
		m_password_hash_hash.get_data(EAP_MSCHAPV2_MD4_DIGEST_SIZE),
		m_nt_response,
		m_peer_challenge,
		m_authenticator_challenge,
		m_username_utf8.get_data(),
		m_username_utf8.get_data_length(),
		auth_response);
	if (status != eap_status_ok)
	{
		delete [] auth_response;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const u32_t ms_data_length
		= EAP_MSCHAPV2_HEADER_SIZE
		+ EAP_MSCHAPV2_AUTHENTICATOR_RESPONSE_SIZE
		+ EAP_MSCHAPV2_MESSAGE_PREFIX_SIZE
		+ message_length;

	const u32_t packet_length
		= eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
		+ ms_data_length;

	eap_buf_chain_wr_c * packet = create_send_packet(packet_length);
	if (!packet)
	{
		delete [] auth_response;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_header_base_c eap_header(
		m_am_tools,
		packet->get_data_offset(m_offset, packet_length),
		packet_length);
	if (eap_header.get_is_valid() == false)
	{
		delete [] auth_response;
		delete packet;
		packet = 0;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	eap_header.set_code(eap_code_request);
	eap_header.set_identifier(++m_identifier);
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

	mschapv2_header.set_opcode(mschapv2_opcode_success);
	mschapv2_header.set_mschapv2_id(static_cast<u8_t>(++m_mschapv2id));
	mschapv2_header.set_ms_length(static_cast<u16_t>(ms_data_length));

	u8_t * success_data = mschapv2_header.get_data();
	if (success_data == 0)
	{
		delete [] auth_response;
		delete packet;
		packet = 0;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// Copy auth string after headers
	m_am_tools->memmove(
		success_data,
		auth_response,
		EAP_MSCHAPV2_AUTHENTICATOR_RESPONSE_SIZE);

	delete [] auth_response;

	// Copy message after auth string
	m_am_tools->memmove(
		success_data + EAP_MSCHAPV2_AUTHENTICATOR_RESPONSE_SIZE,
		EAP_MSCHAPV2_MESSAGE_PREFIX,
		EAP_MSCHAPV2_MESSAGE_PREFIX_SIZE);

	if (message_length != 0)
	{
		m_am_tools->memmove(
			success_data + EAP_MSCHAPV2_AUTHENTICATOR_RESPONSE_SIZE + EAP_MSCHAPV2_MESSAGE_PREFIX_SIZE,
			message,
			message_length);
	}

	status = packet_send(packet, packet_length);
	delete packet;
	packet = 0;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_MSCHAPV2_SERVER)


#if defined(EAP_MSCHAPV2_SERVER)

eap_status_e eap_type_mschapv2_c::rc4_decrypt(
	const u8_t * const cypher,
	const u32_t cypher_length,
	const u8_t * const key,
	const u32_t key_length,
	u8_t * const clear)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	if (!cypher
		|| cypher_length == 0
		|| !key
		|| key_length == 0
		|| !clear)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_variable_data_c v_key(m_am_tools);

	eap_status_e status = v_key.set_buffer(key, key_length, false, false); // Cannot fail
	if (status != eap_status_ok
		|| v_key.get_is_valid_data() == false)
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

	status = rc4.decrypt_data(cypher, clear, cypher_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_MSCHAPV2_SERVER)

// end
