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
* %version: 20.1.4 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 70 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_type_aka.h"
#include "eap_type_aka_header.h"
#include "eap_type_aka_payloads.h"
#include "abs_eap_am_type_aka.h"
#include "eap_crypto_api.h"
#include "eap_state_notification.h"
#include "eap_automatic_variable.h"
#include "eap_buffer.h"


//--------------------------------------------------

/** @file */

//--------------------------------------------------


//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::add_mac_payload(
	aka_header_c * const aka,
	const u32_t aka_buffer_length,
	const u32_t eap_header_size,
	u32_t * const aka_data_offset,
	u32_t * const aka_data_free,
	u32_t * const packet_buffer_free,
	u32_t * const packet_buffer_offset,
	u8_t ** const MAC_data,
	u32_t * const MAC_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	aka_payload_AT_header_c gp_MAC(
		m_am_tools,
		aka->get_data_offset(
			*aka_data_offset, *aka_data_free),
		*aka_data_free);

	if (gp_MAC.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	u32_t eap_type_aka_mac_size = EAP_TYPE_AKA_MAC_SIZE;

	gp_MAC.reset_header(static_cast<u16_t>(eap_type_aka_mac_size));
	gp_MAC.set_data_length(static_cast<u16_t>(eap_type_aka_mac_size));
	gp_MAC.set_current_payload(aka_payload_AT_MAC);

	*MAC_data = gp_MAC.get_data(eap_type_aka_mac_size);
	if (*MAC_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	*MAC_data_length = eap_type_aka_mac_size;

	m_am_tools->memset(*MAC_data, 0, eap_type_aka_mac_size);

	// MAC is calculated later using call create_message_authentication_code().

	update_payload_indexes(
		aka_buffer_length,
		eap_header_size,
		gp_MAC.get_header_length()+gp_MAC.get_data_length(),
		aka_data_offset,
		aka_data_free,
		packet_buffer_offset,
		packet_buffer_free);

	EAP_AKA_TRACE_PAYLOAD("Payload added", &gp_MAC);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::add_padding_payload(
	aka_header_c * const aka,
	const u32_t aka_buffer_length,
	const u32_t eap_header_size,
	u32_t * const aka_data_offset,
	u32_t * const aka_data_free,
	u32_t * const packet_buffer_free,
	u32_t * const packet_buffer_offset,
	const u32_t plaintext_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	aka_payload_AT_header_c gp_padding(
		m_am_tools,
		aka->get_data_offset(
			*aka_data_offset, *aka_data_free),
		*aka_data_free);

	if (gp_padding.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	crypto_aes_c aes(m_am_tools);
	crypto_cbc_c cbc_aes(m_am_tools, &aes, false);

	if (cbc_aes.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if ((plaintext_length % cbc_aes.get_block_size()) == 0ul)
	{
		// We do not need padding, because plaintext length is multiple of
		// block size.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	u32_t cbc_aes_data_length = cbc_aes.aligned_data_length(plaintext_length);
	u32_t padding_bytes_length = 0u;

	if (cbc_aes_data_length
		> plaintext_length+aka_payload_AT_header_c::get_header_length())
	{
		// Fill with zero (0x00) bytes.
		padding_bytes_length
			= cbc_aes_data_length
			- (plaintext_length
			   +aka_payload_AT_header_c::get_header_length());
	}

	u32_t padding_payload_length
		= aka_payload_AT_header_c::get_header_length()
		+padding_bytes_length;

	if ((padding_payload_length % EAP_TYPE_AKA_PADDING_MODULUS) != 0)
	{
		// ERROR
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
	}

	if (padding_payload_length > EAP_TYPE_AKA_PADDING_MAX_VALUE)
	{
		padding_payload_length = 0ul;
		padding_bytes_length = 0ul;
	}

	// Note the reserved field is the begin of padding.
	// The reserved field is set zero in reset_header() function.
	gp_padding.reset_header(static_cast<u16_t>(padding_payload_length));
	gp_padding.set_data_length(static_cast<u16_t>(padding_bytes_length));
	gp_padding.set_current_payload(aka_payload_AT_PADDING);

	if (padding_bytes_length > 0ul)
	{
		u8_t *padding = gp_padding.get_data(padding_bytes_length);
		if (padding == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		cbc_aes.add_padding_bytes(
			padding,
			padding_bytes_length,
			0ul);
	}

	update_payload_indexes(
		aka_buffer_length,
		eap_header_size,
		gp_padding.get_header_length()+gp_padding.get_data_length(),
		aka_data_offset,
		aka_data_free,
		packet_buffer_offset,
		packet_buffer_free);

	EAP_AKA_TRACE_PAYLOAD("Padding payload added", &gp_padding);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::encrypt_DATA_payload(
	u8_t * const data,
	const u32_t cbc_aes_data_length,
	const eap_variable_data_c * const IV,
	const eap_variable_data_c * const encryption_key
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	if (data == 0
		|| cbc_aes_data_length == 0
		|| IV == 0
		|| IV->get_is_valid_data() == false
		|| encryption_key == 0
		|| encryption_key->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	
	crypto_aes_c aes(m_am_tools);
	crypto_cbc_c cbc_aes(m_am_tools, &aes, false);

	if (cbc_aes.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t aes_key_length = aes.get_key_length();
	if (encryption_key->get_data_length() < aes_key_length)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	status = cbc_aes.set_encryption_key(
		IV->get_data(IV->get_data_length()),
		IV->get_data_length(),
		encryption_key->get_data(encryption_key->get_data_length()),
		aes_key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = cbc_aes.encrypt_data(
		data,
		cbc_aes_data_length);

	store_last_encryption_iv(cbc_aes.get_tmp_IV());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::send_reauthentication_request_message(
	const eap_variable_data_c * const username,
	const bool pseudonym_decode_failed,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(pseudonym_decode_failed);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("    send: handler 0x%08x, AKA-subtype %10s, %s, state %2d=%s\n"),
		 this,
		 EAPL("aka_subtype_Re_authentication"),
		 EAPL("server"),
		 get_state(),
		 get_state_string()
		 ));


	eap_variable_data_c checkcode_digest(m_am_tools);

	if (checkcode_digest.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = eap_status_process_general_error;

	status = checkcode_final(
		&checkcode_digest);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	eap_buf_chain_wr_c request_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (request_packet.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means AKA does process every re-transmitted EAP-Request.
		request_packet.set_do_packet_retransmission(false);
	}

	EAP_ASSERT_ALWAYS(EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH >= (m_aka_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_aka_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_aka_header_offset+m_MTU;
	}

	aka_header_c aka_response(
		m_am_tools,
		request_packet.get_data_offset(
			m_aka_header_offset,
			(packet_buffer_free-m_aka_header_offset)),
		(packet_buffer_free-m_aka_header_offset));

	if (aka_response.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("send_reauthentication_request_message: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	aka_response.reset_header(
		packet_buffer_free-m_aka_header_offset,
		m_use_eap_expanded_type);
	aka_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_code(eap_code_request);
	aka_response.set_identifier(eap_identifier);
	aka_response.set_type(
		eap_type_aka,
		m_use_eap_expanded_type);
	aka_response.set_subtype(aka_subtype_Re_authentication);

	update_buffer_indexes(
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		m_aka_header_offset+aka_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::send_reauthentication_request_message(0x%08x).\n"),
		this));

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t aka_data_free = packet_buffer_free;
	u32_t aka_data_offset = 0u;

	eap_variable_data_c orig_XKEY(m_am_tools);
	eap_variable_data_c orig_K_aut(m_am_tools);
	eap_variable_data_c orig_K_encr(m_am_tools);

	if (orig_XKEY.get_is_valid() == false
		|| orig_K_aut.get_is_valid() == false
		|| orig_K_encr.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t reauth_counter = 0u;

	eap_variable_data_c reauth_nonce_s(m_am_tools);

	if (reauth_nonce_s.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	// In order to use re-authentication, the client and the server need to
	// store the following values: original XKEY, K_aut, K_encr, latest
	// counter value and the next re-authentication identity.
	status = m_am_type_aka->query_reauth_parameters(
		&orig_XKEY,
		&orig_K_aut,
		&orig_K_encr,
		&reauth_counter);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = generate_nonce(EAP_TYPE_AKA_NONCE_MT_SIZE, &reauth_nonce_s);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = get_NONCE_S()->set_copy_of_buffer(&reauth_nonce_s);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c master_session_key(m_am_tools);

	if (master_session_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = generate_reauth_shared_secred_keys(
		EAP_TYPE_AKA_KEYMAT_SIZE,
		&orig_XKEY,
		reauth_counter,
		username,
		&reauth_nonce_s,
		&master_session_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	m_use_result_indication = m_allow_use_result_indication;

	if (m_use_result_indication == true)
	{
		// We support use of protected success indications.
		status = add_simple_payload(
			&aka_response,
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			aka_payload_AT_RESULT_IND);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_variable_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		&checkcode_digest,
		aka_payload_AT_CHECKCODE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	crypto_aes_c aes(m_am_tools);

	if (aes.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = m_am_type_aka->generate_encryption_IV(
		get_IV()->get_payload_buffer(),
		aes.get_block_size());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_variable_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		get_IV()->get_payload_buffer(),
		aka_payload_AT_IV);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	u8_t *MAC_data = 0;
	u32_t MAC_data_length = 0u;
	eap_type_aka_MAC_attributes_c MAC_attributes;

	// Encrypted data.
	{
		aka_payload_AT_header_c gp_encrypted_data(
			m_am_tools,
			aka_response.get_data_offset(
				aka_data_offset, 
				aka_data_free),
			aka_data_free);
		if (aka_response.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		// Initialize the length of encrypted data to maximum length.
		// Later this will be set to correct length.
		gp_encrypted_data.reset_header(aka_payload_AT_header_c::get_max_payload_data_length());
		gp_encrypted_data.set_current_payload(aka_payload_AT_ENCR_DATA);

		update_payload_indexes(
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			gp_encrypted_data.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_offset,
			&packet_buffer_free);

		u32_t encrypted_data_offset_begin = packet_buffer_offset;

		// -   -   -   -   -   -   -   -   -   -   -   -

		status = add_counter_payload(
			&aka_response,
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			static_cast<u16_t>(reauth_counter));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// -   -   -   -   -   -   -   -   -   -   -   -

		status = add_variable_payload(
			&aka_response,
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			&reauth_nonce_s,
			aka_payload_AT_NONCE_S);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// -   -   -   -   -   -   -   -   -   -   -   -

		status = m_am_type_aka->generate_reauthentication_id(
			get_send_network_id(),
			get_IMSI(),
			get_reauthentication_identity(),
			EAP_TYPE_AKA_MAX_NAI_LENGTH);
		if (status == eap_status_ok)
		{
			status = add_pseudonym_or_imsi_payload(
				&aka_response,
				EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
				aka_response.get_header_length(),
				&aka_data_offset,
				&aka_data_free,
				&packet_buffer_free,
				&packet_buffer_offset,
				get_reauthentication_identity(),
				aka_payload_AT_NEXT_REAUTH_ID);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// -   -   -   -   -   -   -   -   -   -   -   -

		status = add_padding_payload(
			&aka_response,
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			(packet_buffer_offset - encrypted_data_offset_begin) // Length of the plain text.
			);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		gp_encrypted_data.set_data_length(
			static_cast<u16_t>(packet_buffer_offset - encrypted_data_offset_begin));

		// -   -   -   -   -   -   -   -   -   -   -   -

		status = encrypt_DATA_payload(
			gp_encrypted_data.get_data(gp_encrypted_data.get_data_length()),
			gp_encrypted_data.get_data_length(),
			get_IV()->get_payload_buffer(),
			&orig_K_encr);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_AKA_TRACE_PAYLOAD("Payload added", &gp_encrypted_data);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_mac_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		&MAC_data,
		&MAC_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	aka_response.set_data_length(
		aka_data_offset,
		m_use_eap_expanded_type);
	request_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
		== packet_buffer_offset);

	// -   -   -   -   -   -   -   -   -   -   -   -

	MAC_attributes.init(
		MAC_data,
		MAC_data_length,
		aka_response.get_header_buffer(aka_response.get_length()),
		aka_response.get_length());

	status = create_message_authentication_code(
		&MAC_attributes,
		aka_response.get_subtype(),
		aka_response.get_code(),
		&orig_K_aut);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	aka_response.set_data_length(
		aka_data_offset,
		m_use_eap_expanded_type);
	request_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
		== packet_buffer_offset);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::send_reauthentication_request_message()\n")));

	status = packet_send(
		get_send_network_id(),
		&request_packet,
		m_aka_header_offset,
		aka_response.get_header_length()+aka_response.get_data_length(),
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		status = get_master_session_key()->set_copy_of_buffer(&master_session_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		set_state(eap_type_aka_state_waiting_for_reauth_response);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::send_aka_identity_request_message(
	const bool pseudonym_decode_failed,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("    send: handler 0x%08x, %s, AKA-subtype %10s, %s, state %2d=%s\n"),
		 this,
		 EAPL("initiator"),
		 EAPL("aka_subtype_Identity"),
		 EAPL("server"),
		 get_state(),
		 get_state_string()
		 ));

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::send_aka_identity_request_message(): ")
		 EAPL("requested identity payload is %d=%s, state %d=%s, pseudonym decode %d.\n"),
		 get_aka_identity_response_includes_identity(),
		 aka_payload_AT_header_c::get_payload_AT_string(get_aka_identity_response_includes_identity()),
		 get_state(),
		 get_state_string(),
		 pseudonym_decode_failed));

	eap_status_e status = eap_status_process_general_error;

	eap_buf_chain_wr_c request_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (request_packet.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means AKA does process every re-transmitted EAP-Request.
		request_packet.set_do_packet_retransmission(false);
	}

	EAP_ASSERT_ALWAYS(EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH >= (m_aka_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_aka_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_aka_header_offset+m_MTU;
	}

	aka_header_c aka_response(
		m_am_tools,
		request_packet.get_data_offset(
			m_aka_header_offset,
			(packet_buffer_free-m_aka_header_offset)),
		(packet_buffer_free-m_aka_header_offset));

	if (aka_response.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("send_aka_identity_request_message: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	aka_response.reset_header(
		packet_buffer_free-m_aka_header_offset,
		m_use_eap_expanded_type);
	aka_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_code(eap_code_request);
	aka_response.set_identifier(eap_identifier);
	aka_response.set_type(
		eap_type_aka,
		m_use_eap_expanded_type);
	aka_response.set_subtype(aka_subtype_Identity);

	update_buffer_indexes(
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		m_aka_header_offset+aka_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::send_aka_identity_request_message(0x%08x).\n"),
		 this));

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t aka_data_free = packet_buffer_free;
	u32_t aka_data_offset = 0u;

	if (pseudonym_decode_failed == true)
	{
		aka_payload_AT_type_e next_identity_request = aka_payload_NONE;
		eap_type_aka_state_variable_e next_state = eap_type_aka_state_failure;

		if (get_identity()->get_is_valid_data() == true)
		{
			if (get_aka_identity_response_includes_identity() == aka_payload_AT_FULLAUTH_ID_REQ)
			{
				next_identity_request = aka_payload_AT_FULLAUTH_ID_REQ;
				next_state = eap_type_aka_state_waiting_for_aka_identity_response_with_at_full_auth_identity;
			}
			else if (get_aka_identity_response_includes_identity() == aka_payload_AT_PERMANENT_ID_REQ)
			{
				next_identity_request = aka_payload_AT_PERMANENT_ID_REQ;
				next_state = eap_type_aka_state_waiting_for_aka_identity_response_with_at_permanent_identity;
			}
			else if (get_aka_identity_response_includes_identity() == aka_payload_AT_ANY_ID_REQ)
			{
				next_identity_request = aka_payload_AT_ANY_ID_REQ;
				next_state = eap_type_aka_state_waiting_for_aka_identity_response_with_at_any_identity;
			}
			else
			{
				// We drop this message because no real identity is received from client.
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_AKA_ERROR, (EAPL("ERROR: send_aka_identity_request_message: no real identity received.\n")));
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
			}
		}
		else
		{
			next_identity_request = aka_payload_AT_ANY_ID_REQ;
			next_state = eap_type_aka_state_waiting_for_aka_identity_response_with_at_any_identity;
		}

		status = add_variable_payload(
			&aka_response,
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			0,
			next_identity_request);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		set_state(next_state);
	}
	else
	{
		set_state(eap_type_aka_state_waiting_for_aka_identity_response);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	aka_response.set_data_length(
		aka_data_offset,
		m_use_eap_expanded_type);
	request_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
		== packet_buffer_offset);

	status = checkcode_save_message_server(
		aka_response.get_header_buffer(
			aka_response.get_header_length()
			+aka_response.get_data_length()),
		aka_response.get_header_length()
		+aka_response.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::send_aka_identity_request_message()\n")));

	status = packet_send(
		get_send_network_id(),
		&request_packet,
		m_aka_header_offset,
		aka_response.get_header_length()+aka_response.get_data_length(),
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::send_challenge_request_message(
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("    send: handler 0x%08x, AKA-type %10s, %s, state %2d=%s\n"),
		 this,
		 EAPL("aka_subtype_Challenge"),
		 (get_is_client()) ? EAPL("client") : EAPL("server"),
		 get_state(),
		 get_state_string()
		 ));

	eap_variable_data_c checkcode_digest(m_am_tools);

	if (checkcode_digest.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = eap_status_process_general_error;

	status = checkcode_final(
		&checkcode_digest);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	eap_buf_chain_wr_c aka_initial_reply(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (aka_initial_reply.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means AKA does process every re-transmitted EAP-Request.
		aka_initial_reply.set_do_packet_retransmission(false);
	}

	EAP_ASSERT_ALWAYS(EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH >= (m_aka_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_aka_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_aka_header_offset+m_MTU;
	}

	aka_header_c aka_response(
		m_am_tools,
		aka_initial_reply.get_data_offset(
			m_aka_header_offset,
			(packet_buffer_free-m_aka_header_offset)),
		(packet_buffer_free-m_aka_header_offset));

	if (aka_response.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	aka_response.reset_header(
		packet_buffer_free-m_aka_header_offset,
		m_use_eap_expanded_type);
	aka_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_code(eap_code_request);
	aka_response.set_identifier(eap_identifier);
	aka_response.set_type(
		eap_type_aka,
		m_use_eap_expanded_type);

	aka_response.set_subtype(aka_subtype_Challenge);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::send_challenge_request_message(0x%08x).\n"),
		this));

	update_buffer_indexes(
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		m_aka_header_offset+aka_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t aka_data_free = packet_buffer_free;
	u32_t aka_data_offset = 0u;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	if (get_authentication_vector()->get_RAND()->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (get_authentication_vector()->get_AUTN()->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (get_authentication_vector()->get_RES()->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (get_authentication_vector()->get_CK()->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (get_authentication_vector()->get_IK()->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}



	if (get_identity()->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (get_IMSI()->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("RAND"),
		get_authentication_vector()->get_RAND()->get_data(
			get_authentication_vector()->get_RAND()->get_data_length()),
		get_authentication_vector()->get_RAND()->get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AUTN"),
		get_authentication_vector()->get_AUTN()->get_data(
			get_authentication_vector()->get_AUTN()->get_data_length()),
		get_authentication_vector()->get_AUTN()->get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("RES"),
		get_authentication_vector()->get_RES()->get_data(
			get_authentication_vector()->get_RES()->get_data_length()),
		get_authentication_vector()->get_RES()->get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CK"),
		get_authentication_vector()->get_CK()->get_data(
			get_authentication_vector()->get_CK()->get_data_length()),
		get_authentication_vector()->get_CK()->get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("IK"),
		get_authentication_vector()->get_IK()->get_data(
			get_authentication_vector()->get_IK()->get_data_length()),
		get_authentication_vector()->get_IK()->get_data_length()));

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("identity"),
		get_identity()->get_data(get_identity()->get_data_length()),
		get_identity()->get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("IMSI"),
		get_IMSI()->get_data(get_IMSI()->get_data_length()),
		get_IMSI()->get_data_length()));

	eap_variable_data_c XKEY(m_am_tools);
	eap_variable_data_c K_encr(m_am_tools);
	eap_variable_data_c K_aut(m_am_tools);
	eap_variable_data_c master_session_key(m_am_tools);

	if (XKEY.get_is_valid() == false
		|| K_encr.get_is_valid() == false
		|| K_aut.get_is_valid() == false
		|| master_session_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = generate_shared_secred_keys(
		EAP_TYPE_AKA_KEYMAT_SIZE,
		get_authentication_vector()->get_CK(),
		get_authentication_vector()->get_IK(),
		&XKEY,
		&K_encr,
		&K_aut,
		&master_session_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	m_use_result_indication = m_allow_use_result_indication;

	if (m_use_result_indication == true)
	{
		// We support use of protected success indications.
		status = add_simple_payload(
			&aka_response,
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			aka_payload_AT_RESULT_IND);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_variable_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		&checkcode_digest,
		aka_payload_AT_CHECKCODE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_variable_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		get_authentication_vector()->get_RAND(),
		aka_payload_AT_RAND);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_variable_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		get_authentication_vector()->get_AUTN(),
		aka_payload_AT_AUTN);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	u8_t *MAC_data = 0;
	u32_t MAC_data_length = 0u;
	eap_type_aka_MAC_attributes_c MAC_attributes;

	if (m_use_pseudonym_identity == true
		|| m_use_reauthentication_identity == true)
	{
		u32_t saved_aka_data_offset = aka_data_offset;
		u32_t saved_aka_data_free = aka_data_free;
		u32_t saved_packet_buffer_offset = packet_buffer_offset;
		u32_t saved_packet_buffer_free = packet_buffer_free;

		crypto_aes_c aes(m_am_tools);

		if (aes.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = m_am_type_aka->generate_encryption_IV(
			get_IV()->get_payload_buffer(),
			aes.get_block_size());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		status = add_variable_payload(
			&aka_response,
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			get_IV()->get_payload_buffer(),
			aka_payload_AT_IV);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		// Encrypted data.
		{
			aka_payload_AT_header_c gp_encrypted_data(
				m_am_tools,
				aka_response.get_data_offset(
					aka_data_offset, 
					aka_data_free),
				aka_data_free);
			if (gp_encrypted_data.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			// Initialize the length of encrypted data to maximum length.
			// Later this will be set to correct length.
			gp_encrypted_data.reset_header(aka_payload_AT_header_c::get_max_payload_data_length());
			gp_encrypted_data.set_current_payload(aka_payload_AT_ENCR_DATA);

			update_payload_indexes(
				EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
				aka_response.get_header_length(),
				gp_encrypted_data.get_header_length(),
				&aka_data_offset,
				&aka_data_free,
				&packet_buffer_offset,
				&packet_buffer_free);

			u32_t encrypted_data_offset_begin = packet_buffer_offset;

			// -   -   -   -   -   -   -   -   -   -   -   -

			if (m_use_pseudonym_identity == true)
			{
				status = m_am_type_aka->generate_pseudonym_id(
					get_send_network_id(),
					get_IMSI(),
					get_pseudonym(),
					EAP_TYPE_AKA_MAX_NAI_LENGTH);
				if (status == eap_status_ok)
				{
					status = add_pseudonym_or_imsi_payload(
						&aka_response,
						EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
						aka_response.get_header_length(),
						&aka_data_offset,
						&aka_data_free,
						&packet_buffer_free,
						&packet_buffer_offset,
						get_pseudonym(),
						aka_payload_AT_NEXT_PSEUDONYM);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}

			// -   -   -   -   -   -   -   -   -   -   -   -

			if (m_use_reauthentication_identity == true)
			{
				status = m_am_type_aka->generate_reauthentication_id(
					get_send_network_id(),
					get_IMSI(),
					get_reauthentication_identity(),
					EAP_TYPE_AKA_MAX_NAI_LENGTH);
				if (status == eap_status_ok)
				{
					status = add_pseudonym_or_imsi_payload(
						&aka_response,
						EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
						aka_response.get_header_length(),
						&aka_data_offset,
						&aka_data_free,
						&packet_buffer_free,
						&packet_buffer_offset,
						get_reauthentication_identity(),
						aka_payload_AT_NEXT_REAUTH_ID);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}

			// -   -   -   -   -   -   -   -   -   -   -   -

			u32_t plain_text_length = packet_buffer_offset - encrypted_data_offset_begin;

			if (plain_text_length > 0ul)
			{
				status = add_padding_payload(
					&aka_response,
					EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
					aka_response.get_header_length(),
					&aka_data_offset,
					&aka_data_free,
					&packet_buffer_free,
					&packet_buffer_offset,
					plain_text_length // Length of the plain text.
					);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// Re calculate after adding the padding.
				plain_text_length = packet_buffer_offset - encrypted_data_offset_begin;

				gp_encrypted_data.set_data_length(
					static_cast<u16_t>(plain_text_length));

				// -   -   -   -   -   -   -   -   -   -   -   -

				status = encrypt_DATA_payload(
					gp_encrypted_data.get_data(gp_encrypted_data.get_data_length()),
					gp_encrypted_data.get_data_length(),
					get_IV()->get_payload_buffer(),
					&K_encr);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_AKA_TRACE_PAYLOAD("Payload added", &gp_encrypted_data);
			}
			else
			{
				// No encrypted data, remove AT_ENCR_DATA header.
				aka_data_offset = saved_aka_data_offset;
				aka_data_free = saved_aka_data_free;
				packet_buffer_offset = saved_packet_buffer_offset;
				packet_buffer_free = saved_packet_buffer_free;
			}
		}
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_mac_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		&MAC_data,
		&MAC_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	aka_response.set_data_length(
		aka_data_offset,
		m_use_eap_expanded_type);
	aka_initial_reply.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
		== packet_buffer_offset);

	// -   -   -   -   -   -   -   -   -   -   -   -

	MAC_attributes.init(
		MAC_data,
		MAC_data_length,
		aka_response.get_header_buffer(aka_response.get_length()),
		aka_response.get_length());

	status = create_message_authentication_code(
		&MAC_attributes,
		aka_response.get_subtype(),
		aka_response.get_code(),
		&K_aut);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	aka_response.set_data_length(
		aka_data_offset,
		m_use_eap_expanded_type);
	aka_initial_reply.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
		== packet_buffer_offset);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = packet_send(
		get_send_network_id(),
		&aka_initial_reply,
		m_aka_header_offset,
		aka_response.get_header_length()+aka_response.get_data_length(),
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		// Store keys.
		status = get_XKEY()->set_copy_of_buffer(&XKEY);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		status = get_K_encr()->set_copy_of_buffer(&K_encr);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		status = get_K_aut()->set_copy_of_buffer(&K_aut);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		status = get_master_session_key()->set_copy_of_buffer(&master_session_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::send_aka_notification_request(
	const eap_aka_notification_codes_e notification_code,
	const bool add_at_counter_attribute)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: handler 0x%08x, AKA-type %10s, %s, state %2d=%s, notification_code = %d\n"),
		 this,
		 EAPL("send_aka_notification_request"),
		 (get_is_client()) ? EAPL("client") : EAPL("server"),
		 get_state(),
		 get_state_string(),
		 notification_code
		 ));

	eap_buf_chain_wr_c eap_notification_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_notification_packet.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means AKA does process every re-transmitted EAP-Request.
		eap_notification_packet.set_do_packet_retransmission(false);
	}

	EAP_ASSERT_ALWAYS(EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH >= (m_aka_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_aka_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_aka_header_offset+m_MTU;
	}

	aka_header_c aka_response(
		m_am_tools,
		eap_notification_packet.get_data_offset(
			m_aka_header_offset,
			(packet_buffer_free-m_aka_header_offset)),
		(packet_buffer_free-m_aka_header_offset));

	if (aka_response.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	set_last_eap_identifier(static_cast<u8_t>(get_last_eap_identifier()+1u));

	aka_response.reset_header(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_code(eap_code_request);
	aka_response.set_identifier(get_last_eap_identifier());
	aka_response.set_type(
		eap_type_aka,
		m_use_eap_expanded_type);
	aka_response.set_subtype(aka_subtype_Notification);


	update_buffer_indexes(
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		m_aka_header_offset+aka_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t aka_data_free = packet_buffer_free;
	u32_t aka_data_offset = 0u;

	eap_status_e status = add_notification_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		notification_code);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	eap_variable_data_c * K_aut = 0;

	eap_variable_data_c orig_K_aut(m_am_tools);

	if (orig_K_aut.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (get_aka_notification_code_P_bit(notification_code) == false)
	{
		u8_t *MAC_data = 0;
		u32_t MAC_data_length = 0u;
		eap_type_aka_MAC_attributes_c MAC_attributes;

		if (add_at_counter_attribute == true)
		{
			// If EAP-Request/AKA/Notification is used on fast a re-authentication
			// exchange, and if the P bit in AT_NOTIFICATION is set to zero, then
			// AT_COUNTER is used for replay protection. In this case, the
			// AT_ENCR_DATA and AT_IV attributes MUST be included, and the
			// encapsulated plaintext attributes MUST include the AT_COUNTER
			// attribute. The counter value included in AT_COUNTER MUST be the same
			// as in the EAP-Request/AKA/Re-authentication packet on the same fast
			// re-authentication exchange.

			// - - - - - - - - - - - - - - - - - - - - - - - -

			eap_variable_data_c orig_XKEY(m_am_tools);
			eap_variable_data_c orig_K_encr(m_am_tools);

			if (orig_XKEY.get_is_valid() == false
				|| orig_K_encr.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u32_t reauth_counter = 0u;

			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_aka->query_reauth_parameters(
				&orig_XKEY,
				&orig_K_aut,
				&orig_K_encr,
				&reauth_counter);
			if (status != eap_status_ok)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			K_aut = &orig_K_aut;

			// -   -   -   -   -   -   -   -   -   -   -   -

			crypto_aes_c aes(m_am_tools);

			if (aes.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = m_am_type_aka->generate_encryption_IV(
				get_IV()->get_payload_buffer(),
				aes.get_block_size());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}


			status = add_variable_payload(
				&aka_response,
				EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
				aka_response.get_header_length(),
				&aka_data_offset,
				&aka_data_free,
				&packet_buffer_free,
				&packet_buffer_offset,
				get_IV()->get_payload_buffer(),
				aka_payload_AT_IV);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}


			// Encrypted data.
			{
				aka_payload_AT_header_c gp_encrypted_data(
					m_am_tools,
					aka_response.get_data_offset(
						aka_data_offset, 
						aka_data_free),
					aka_data_free);
				if (aka_response.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
				}

				// Initialize the length of encrypted data to maximum length.
				// Later this will be set to correct length.
				gp_encrypted_data.reset_header(aka_payload_AT_header_c::get_max_payload_data_length());
				gp_encrypted_data.set_current_payload(aka_payload_AT_ENCR_DATA);

				update_payload_indexes(
					EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
					aka_response.get_header_length(),
					gp_encrypted_data.get_header_length(),
					&aka_data_offset,
					&aka_data_free,
					&packet_buffer_offset,
					&packet_buffer_free);

				u32_t encrypted_data_offset_begin = packet_buffer_offset;

				// -   -   -   -   -   -   -   -   -   -   -   -

				status = add_counter_payload(
					&aka_response,
					EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
					aka_response.get_header_length(),
					&aka_data_offset,
					&aka_data_free,
					&packet_buffer_free,
					&packet_buffer_offset,
					static_cast<u16_t>(reauth_counter));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// -   -   -   -   -   -   -   -   -   -   -   -

				status = add_padding_payload(
					&aka_response,
					EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
					aka_response.get_header_length(),
					&aka_data_offset,
					&aka_data_free,
					&packet_buffer_free,
					&packet_buffer_offset,
					(packet_buffer_offset - encrypted_data_offset_begin) // Length of the plain text.
					);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				gp_encrypted_data.set_data_length(
					static_cast<u16_t>(packet_buffer_offset - encrypted_data_offset_begin));

				// -   -   -   -   -   -   -   -   -   -   -   -

				status = encrypt_DATA_payload(
					gp_encrypted_data.get_data(gp_encrypted_data.get_data_length()),
					gp_encrypted_data.get_data_length(),
					get_IV()->get_payload_buffer(),
					&orig_K_encr);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_AKA_TRACE_PAYLOAD("Payload added", &gp_encrypted_data);
			}

		}
		else
		{
			K_aut = get_K_aut();
		} // if (add_counter_payload == true)

		// -   -   -   -   -   -   -   -   -   -   -   -

		// Add AT_MAC attribute.
		status = add_mac_payload(
			&aka_response,
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			&MAC_data,
			&MAC_data_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// -   -   -   -   -   -   -   -   -   -   -   -

		aka_response.set_data_length(
			aka_data_offset,
			m_use_eap_expanded_type);
		eap_notification_packet.set_data_length(packet_buffer_offset);

		EAP_ASSERT_ALWAYS(
			m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
			== packet_buffer_offset);

		// -   -   -   -   -   -   -   -   -   -   -   -

		MAC_attributes.init(
			MAC_data,
			MAC_data_length,
			aka_response.get_header_buffer(aka_response.get_length()),
			aka_response.get_length());

		status = create_message_authentication_code(
			&MAC_attributes,
			aka_response.get_subtype(),
			aka_response.get_code(),
			K_aut);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}
	else
	{
		aka_response.set_data_length(
			aka_data_offset,
			m_use_eap_expanded_type);
		eap_notification_packet.set_data_length(packet_buffer_offset);

		EAP_ASSERT_ALWAYS(
			m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
			== packet_buffer_offset);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_notification_packet.set_data_length(packet_buffer_offset);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send_aka_notification_request: aka_subtype_Notification packet"),
		aka_response.get_header_buffer(aka_response.get_length()),
		aka_response.get_length()));

	status = packet_send(
		get_send_network_id(),
		&eap_notification_packet,
		m_aka_header_offset,
		aka_response.get_length(),
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::query_AKA_authentication_vector(
	const u8_t next_eap_identifier,
	eap_type_aka_identity_type * const identity_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_type_aka_authentication_vector_c authentication_vector(m_am_tools);

	set_state(eap_type_aka_state_pending_authentication_vector_query);

	eap_status_e status = m_am_type_aka->query_AKA_authentication_vector(
		get_identity(), // This is username part from payload AT_IDENTITY.
		next_eap_identifier,
		get_IMSI(), // This is the real IMSI. If this is uninitialized get_identity() must be initialized, imsi will be initialized after this call is complete.
		&authentication_vector,
		identity_type);

	if (status == eap_status_pending_request)
	{
		// This is pending query, that will be completed by complete_AKA_authentication_vector_query() call.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status == eap_status_completed_request)
	{
		// This query was already completed by complete_AKA_authentication_vector_query() call.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status != eap_status_ok)
	{
		// Some error occurred.
		restore_saved_previous_state();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_authentication_vector(authentication_vector.copy());
	if (get_authentication_vector() == 0
		|| get_authentication_vector()->get_is_valid() == false)
	{
		restore_saved_previous_state();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::complete_AKA_authentication_vector_query(
	eap_type_aka_authentication_vector_c * const authentication_vector,
	const eap_variable_data_c * const IMSI,
	const eap_aka_authentication_vector_status_e authentication_vector_status,
	const eap_type_aka_identity_type identity_type,
	const eap_status_e completion_status,
	const u8_t next_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::complete_AKA_authentication_vector_query(): ")
		 EAPL("EAP-identity is %d=%s, identity payload was %d=%s, state %d=%s.\n"),
		 identity_type,
		 get_identity_string(identity_type),
		 get_aka_identity_response_includes_identity(),
		 aka_payload_AT_header_c::get_payload_AT_string(get_aka_identity_response_includes_identity()),
		 get_state(),
		 get_state_string()));

	if (completion_status != eap_status_ok
		|| authentication_vector == 0)
	{
		set_state(eap_type_aka_state_failure);

		// The eap_status_process_general_error error value is more important
		// than return value of set_session_timeout().
		(void) get_type_partner()->set_session_timeout(0ul);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}


	if (get_state() != eap_type_aka_state_pending_authentication_vector_query)
	{
		// Authentication is terminated or state is wrong. Cannot continue.
		set_state(eap_type_aka_state_failure);

		// The eap_status_handler_does_not_exists_error error value is more important
		// than return value of set_session_timeout().
		(void) get_type_partner()->set_session_timeout(0ul);

		return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
	}

	eap_status_e status = eap_status_process_general_error;

	if (m_identity_type != AKA_IDENTITY_TYPE_RE_AUTH_ID)
	{
		set_identity_type(identity_type);
	}

	if (m_identity_type == AKA_IDENTITY_TYPE_IMSI_ID
		&& IMSI->get_is_valid_data() == true)
	{
		status = m_IMSI.set_copy_of_buffer(IMSI);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (authentication_vector_status == eap_aka_authentication_vector_status_ok)
	{
		// First check the identity type is correct.
		if ((m_identity_type == AKA_IDENTITY_TYPE_IMSI_ID
				&& (get_aka_identity_response_includes_identity() == aka_payload_AT_PERMANENT_ID_REQ
					|| get_aka_identity_response_includes_identity() == aka_payload_AT_FULLAUTH_ID_REQ
					|| get_aka_identity_response_includes_identity() == aka_payload_AT_ANY_ID_REQ))
			|| (m_identity_type == AKA_IDENTITY_TYPE_PSEUDONYM_ID
				&& (get_aka_identity_response_includes_identity() == aka_payload_AT_FULLAUTH_ID_REQ
					|| get_aka_identity_response_includes_identity() == aka_payload_AT_ANY_ID_REQ))
			|| (m_identity_type == AKA_IDENTITY_TYPE_RE_AUTH_ID
				&& get_aka_identity_response_includes_identity() == aka_payload_AT_ANY_ID_REQ)
			|| get_aka_identity_response_includes_identity() == aka_payload_NONE)
		{
			// OK, correct identity received.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::complete_AKA_authentication_vector_query(): OK\n")));
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::complete_AKA_authentication_vector_query(): ")
				 EAPL("EAP-identity is wrong, state %d=%s.\n"),
				 get_state(), get_state_string()));

			if (get_aka_identity_response_includes_identity() == aka_payload_AT_PERMANENT_ID_REQ)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_AKA_ERROR, 
					(EAPL("ERROR: eap_type_aka_c::complete_AKA_authentication_vector_query(): ")
					 EAPL("permanent identity was required, %d=%s was get.\n"),
					 m_identity_type,
					 get_identity_string(m_identity_type)));
			}
			else if (get_aka_identity_response_includes_identity() == aka_payload_AT_FULLAUTH_ID_REQ)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_AKA_ERROR, 
					(EAPL("ERROR: eap_type_aka_c::complete_AKA_authentication_vector_query(): ")
					 EAPL("full authentication identity was required, %d=%s was get.\n"),
					 m_identity_type,
					 get_identity_string(m_identity_type)));
			}
			else if (get_aka_identity_response_includes_identity() == aka_payload_AT_ANY_ID_REQ)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_AKA_ERROR, 
					(EAPL("ERROR: eap_type_aka_c::complete_AKA_authentication_vector_query(): ")
					 EAPL("any identity was required, %d=%s was get.\n"),
					 m_identity_type,
					 get_identity_string(m_identity_type)));
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_AKA_ERROR, 
					(EAPL("ERROR: eap_type_aka_c::complete_AKA_authentication_vector_query(): ")
					 EAPL("no special identity was required, %d=%s was get.\n"),
					 m_identity_type,
					 get_identity_string(m_identity_type)));
			}
			
			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR, wrong identity"),
				get_NAI()->get_data(get_NAI()->get_data_length()),
				get_NAI()->get_data_length()));

			restore_saved_previous_state();

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}

		if (get_IMSI()->get_is_valid_data() == false
			&& IMSI != get_IMSI())
		{
			// We must copy queried IMSI.
			status = get_IMSI()->set_copy_of_buffer(IMSI);
			if (status != eap_status_ok)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		set_authentication_vector(authentication_vector->copy());
		if (get_authentication_vector() == 0
		|| get_authentication_vector()->get_is_valid() == false)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = send_challenge_request_message(
			next_eap_identifier);
		if (status != eap_status_ok)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		set_last_eap_identifier(next_eap_identifier);
		set_state(eap_type_aka_state_waiting_for_challenge_response);
	}
	else
	{
		// Error occurred in tripler query.
		// We must send EAP-Notification message.
		// 

		// eap_aka_notification_no_F_no_P_users_calls_are_barred and eap_aka_notification_no_F_no_P_user_has_not_subscribed_to_the_requested_service cannot be used because P bit is not set.

		m_aka_notification_code = eap_aka_notification_no_F_P_set_general_failure;

		status = initialize_notification_message();

		set_last_eap_identifier(static_cast<u8_t>(get_last_eap_identifier()+1u));

		set_state(eap_type_aka_state_waiting_for_notification_response_failure);
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_type_aka_c::randomly_refuse_eap_identity()
{
	bool skip_query_imsi_from_username = false;

	if (m_aka_test_version == true
		&& m_aka_randomly_refuse_eap_identity == true)
	{
		crypto_random_c rand(m_am_tools);

		if (rand.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return false;
		}

		u32_t random_guard;

		eap_status_e status = rand.get_rand_bytes(
			reinterpret_cast<u8_t *>(&random_guard),
			sizeof(random_guard));
		if (status != eap_status_ok)
		{
			return false;
		}

		if ((random_guard % 2) == 0)
		{
			// Note, this is just for testing.
			skip_query_imsi_from_username = true;

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("TEST: eap_type_aka_c::randomly_refuse_eap_identity(): ")
				 EAPL("randomly fails EAP-Identity.\n")));
		}
	}

	return skip_query_imsi_from_username;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_identity_response_message(
	eap_header_rd_c * const eap_header,
	const u32_t aka_packet_length)
{
	eap_status_e status = eap_status_process_general_error;

	if (get_state() == eap_type_aka_state_waiting_for_identity_response
		|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response
		|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_any_identity
		|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_full_auth_identity
		|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_permanent_identity
		// In test version new authentication could start from this state.
		|| (m_aka_test_version == true
			&& get_state() == eap_type_aka_state_success) // This one is for testing purposes.
		)
	{
		// OK correct state.
	}
	else
	{
		// Wrong state, dischard packet.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_identity_response_message(): ")
			 EAPL("EAP-Response/Identity received in wrong state %d=%s. This EAP-packet is dropped.\n"),
			 get_state(), get_state_string()));
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: erroneous EAP packet: code=0x%02x, ")
			 EAPL("identifier=0x%02x, length=0x%04x, type=0x%08x, client %d\n"),
			 eap_header->get_code(),
			 eap_header->get_identifier(),
			 eap_header->get_length(),
			 convert_eap_type_to_u32_t(eap_header->get_type()),
			 get_is_client()));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (m_check_identifier_of_eap_identity_response == true)
	{
		if (get_state() == eap_type_aka_state_waiting_for_identity_response
		&& eap_header->get_identifier() != get_last_eap_identifier())
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_identity_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
				 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
				 eap_header->get_identifier(),
				 get_last_eap_identifier(), 
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}
		else if ((get_state() == eap_type_aka_state_waiting_for_aka_identity_response
			|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_any_identity
			|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_full_auth_identity
			|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_permanent_identity
			)
		&& eap_header->get_identifier() != get_last_eap_identifier()-1u)
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_identity_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
				 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
				 eap_header->get_identifier(),
				 get_last_eap_identifier()-1u, 
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}
		// In test version new authentication could start from this state.
		else if (m_aka_test_version == true
			&& get_state() == eap_type_aka_state_success) // This one is for testing purposes.
		{
			// NOTE here we can not check the EAP-identifier.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: eap_type_aka_c::handle_identity_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is not checked in eap_type_aka_state_variable_e %d=%s.\n"),
				 eap_header->get_identifier(),
				 get_state(),
				 get_state_string()));
		}
	}

	{
		// This could be first or retransmission request.

		if (eap_header->get_type_data_length() > aka_packet_length)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}

		status = parse_identity(
			eap_header->get_type_data(
				eap_header->get_type_data_length()),
			eap_header->get_type_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT,
			(EAPL("AKA received EAP-identity NAI"),
			 get_NAI()->get_data(get_NAI()->get_data_length()),
			 get_NAI()->get_data_length()));

		u8_t next_eap_identifier = static_cast<u8_t>(eap_header->get_identifier()+1u);

		if (get_state() == eap_type_aka_state_waiting_for_aka_identity_response
		|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_any_identity
		|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_full_auth_identity
		|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_permanent_identity
		)
		{
			// This is retransmission, so the EAP-identifier is not increased.
			next_eap_identifier = get_last_eap_identifier();
		}
		// In test version new authentication could start from this state.
		else if (m_aka_test_version == true
			&& get_state() == eap_type_aka_state_success) // This one is for testing purposes.
		{
			// NOTE here we can not check the EAP-identifier.
			next_eap_identifier = static_cast<u8_t>(eap_header->get_identifier()+1u);
			set_state(eap_type_aka_state_waiting_for_identity_response);
			get_IMSI()->reset();
		}

		save_current_state();
		set_state(eap_type_aka_state_pending_pseudonym_decode_query);

		eap_type_aka_identity_type identity_type = AKA_IDENTITY_TYPE_NONE;

		if (m_accept_eap_identity_response == true)
		{
			if (randomly_refuse_eap_identity() == false)
			{
				status = m_am_type_aka->query_imsi_from_username(
					next_eap_identifier,
					get_send_network_id(),
					get_identity(),
					get_IMSI(),
					&identity_type,
					eap_type_aka_complete_handle_imsi_from_username);
			}
			else
			{
				status = eap_status_illegal_eap_identity;
			}

			if (status == eap_status_pending_request)
			{
				// This is pending query, that will be completed by complete_imsi_from_username() call.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
			else if (status == eap_status_completed_request)
			{
				// This is already completed by complete_imsi_from_username() call.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
			else if (status != eap_status_ok)
			{
				// Identity decoding failed.
				// We must query IMSI of client.

				if (m_use_manual_username == true)
				{
					// We reset the illegal identity.
					// EAP-AKA/request/start will query identity.
					get_identity()->reset();
				}
			}
			else // status == eap_status_ok
			{
				// The query_imsi_from_username() function call was synchronous.
				// We must call send_aka_identity_request_message().
			}
		}


		{
			status = handle_imsi_from_username(
				next_eap_identifier,
				get_send_network_id(),
				get_identity(),
				get_IMSI(),
				identity_type);
			if (status != eap_status_ok)
			{
				// ERROR in handle_imsi_from_username().
				// This will return error status of handle_imsi_from_username() call.
			}
			else
			{
				// OK handle_imsi_from_username().
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_imsi_from_username(
	const u8_t next_eap_identifier,
	const eap_am_network_id_c * const network_id,
	const eap_variable_data_c * const username,
	const eap_variable_data_c * const imsi, ///< The result is stored to imsi parameter.
	const eap_type_aka_identity_type received_identity_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(username);
	EAP_UNREFERENCED_PARAMETER(network_id);

	EAP_ASSERT(received_identity_type == AKA_IDENTITY_TYPE_IMSI_ID
		|| received_identity_type == AKA_IDENTITY_TYPE_PSEUDONYM_ID
		|| received_identity_type == AKA_IDENTITY_TYPE_RE_AUTH_ID
		|| received_identity_type == AKA_IDENTITY_TYPE_NONE);

	if (get_state() != eap_type_aka_state_pending_pseudonym_decode_query)
	{
		// State is wrong. Cannot continue.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_gsmsim_state);
	}

	eap_status_e status = eap_status_process_general_error;
	bool pseudonym_decode_failed = true;

	//eap_type_aka_identity_type local_identity_type = identity_type;
	set_identity_type(received_identity_type);

	if (imsi != 0
		&& imsi->get_is_valid_data() == true)
	{
		pseudonym_decode_failed = false;
		status = get_IMSI()->set_copy_of_buffer(imsi);
		if (status != eap_status_ok)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (received_identity_type == AKA_IDENTITY_TYPE_NONE)
		{
			set_identity_type(AKA_IDENTITY_TYPE_IMSI_ID);
		}
	}
	else
	{
		get_IMSI()->reset();
	}

	if (received_identity_type == AKA_IDENTITY_TYPE_IMSI_ID)
	{
		m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;
		set_identity_type(received_identity_type);
		set_aka_identity_response_includes_identity(aka_payload_AT_ANY_ID_REQ);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
			(EAPL("Identity: IMSI\n")));
	}
	else if (received_identity_type == AKA_IDENTITY_TYPE_PSEUDONYM_ID)
	{
		m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;
		set_identity_type(received_identity_type);
		set_aka_identity_response_includes_identity(aka_payload_AT_ANY_ID_REQ);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
			(EAPL("Identity: pseudonym\n")));
	}
	else if (received_identity_type == AKA_IDENTITY_TYPE_RE_AUTH_ID)
	{
		m_authentication_type = AKA_AUTHENTICATION_TYPE_REAUTHENTICATION;
		set_identity_type(received_identity_type);
		set_aka_identity_response_includes_identity(aka_payload_AT_ANY_ID_REQ);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
			(EAPL("Identity: re-authentication\n")));
	}
	else
	{
		m_authentication_type = AKA_AUTHENTICATION_TYPE_NONE;

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
			(EAPL("Identity: other\n")));
	}


	if (m_authentication_type == AKA_AUTHENTICATION_TYPE_FULL_AUTH
		&& ((m_identity_type == AKA_IDENTITY_TYPE_IMSI_ID
			&& (get_saved_previous_state() == eap_type_aka_state_waiting_for_identity_response
				|| get_saved_previous_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_permanent_identity
				|| get_saved_previous_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_full_auth_identity
				|| get_saved_previous_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_any_identity
				|| get_saved_previous_state() == eap_type_aka_state_waiting_for_aka_identity_response))
		|| (m_identity_type == AKA_IDENTITY_TYPE_PSEUDONYM_ID
			&& (get_saved_previous_state() == eap_type_aka_state_waiting_for_identity_response
				|| get_saved_previous_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_permanent_identity
				|| get_saved_previous_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_any_identity
				|| get_saved_previous_state() == eap_type_aka_state_waiting_for_aka_identity_response)))
		)
	{
		eap_type_aka_identity_type local_identity_type = m_identity_type;

		eap_status_e local_status = query_AKA_authentication_vector(next_eap_identifier, &local_identity_type);
		if (local_status == eap_status_pending_request)
		{
			// Request will be completed later with complete_AKA_authentication_vector_query() function.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
		else if (local_status == eap_status_completed_request)
		{
			// Request was already completed with complete_AKA_authentication_vector_query() function.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
		else if (local_status != eap_status_ok)
		{
			// This is an error case.
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, local_status);
		}
		else //if (local_status == eap_status_ok)
		{
			// The query_AKA_authentication_vector() function call is synchronous.
			// We must call send_challenge_request_message().
		}

		const u8_t local_eap_identifier = static_cast<u8_t>(get_last_eap_identifier()+1u);

		local_status = send_challenge_request_message(
			local_eap_identifier);
		if (local_status != eap_status_ok)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, local_status);
		}

		set_last_eap_identifier(local_eap_identifier);
		set_state(eap_type_aka_state_waiting_for_challenge_response);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, local_status);
	}
	else if (m_identity_type == AKA_IDENTITY_TYPE_RE_AUTH_ID
		&& (get_saved_previous_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_any_identity
			|| get_saved_previous_state() == eap_type_aka_state_waiting_for_identity_response
			|| get_saved_previous_state() == eap_type_aka_state_waiting_for_aka_identity_response))
	{
		// Here we need to send EAP-Request/Re-authentication
		status = send_reauthentication_request_message(
			get_NAI(),
			pseudonym_decode_failed,
			next_eap_identifier);
	}
	else if (m_identity_type == AKA_IDENTITY_TYPE_NONE
		&& get_saved_previous_state() == eap_type_aka_state_waiting_for_identity_response)
	{
		set_aka_identity_response_includes_identity(aka_payload_AT_ANY_ID_REQ);

		status = send_aka_identity_request_message(
			pseudonym_decode_failed,
			next_eap_identifier);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_imsi_from_username(): ")
			 EAPL("EAP-Identity type 0x%02x is wrong in eap_type_aka_state_variable_e %d=%s.\n"),
			m_identity_type,
			get_saved_previous_state(),
			get_saved_previous_state_string()));

		status = eap_status_illegal_eap_identity;
	}

	if (status != eap_status_ok)
	{
		restore_saved_previous_state();
	}
	else
	{
		set_last_eap_identifier(next_eap_identifier);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::complete_imsi_from_username(
	const u8_t next_eap_identifier,
	const eap_am_network_id_c * const network_id,
	const eap_variable_data_c * const username,
	const eap_variable_data_c * const imsi, ///< The result is stored to imsi parameter.
	const eap_type_aka_identity_type identity_type,
	const eap_status_e completion_status,
	const eap_type_aka_complete_e completion_action)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::complete_imsi_from_username(): ")
		 EAPL("EAP-identity is %d=%s, identity payload was %d=%s, state %d=%s.\n"),
		 identity_type,
		 get_identity_string(identity_type),
		 get_aka_identity_response_includes_identity(),
		 aka_payload_AT_header_c::get_payload_AT_string(get_aka_identity_response_includes_identity()),
		 get_state(),
		 get_state_string()));

	EAP_UNREFERENCED_PARAMETER(username);
	EAP_UNREFERENCED_PARAMETER(network_id);

	if (get_state() == eap_type_aka_state_none)
	{
		// The eap_status_handler_does_not_exists_error error value is more important
		// than return value of set_session_timeout().
		(void) get_type_partner()->set_session_timeout(0ul);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
	}

	if (completion_status != eap_status_ok)
	{
		set_state(eap_type_aka_state_failure);

		// The completion_status error value is more important
		// than return value of set_session_timeout().
		(void) get_type_partner()->set_session_timeout(0ul);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, completion_status);
	}

	eap_status_e status = eap_status_not_supported;

	if (completion_action == eap_type_aka_complete_handle_imsi_from_username)
	{
		status = handle_imsi_from_username(
			next_eap_identifier,
			network_id,
			username,
			imsi, ///< The result is stored to imsi parameter.
			identity_type);

		status = eap_status_completed_request;
	}
	else if (completion_action == eap_type_aka_complete_handle_aka_identity_response_message_completion)
	{
		// NOTE the identity_payload_was_included parameter is
		// true in this completion.
		status = handle_aka_identity_response_message_completion(
			next_eap_identifier,
			completion_status,
			identity_type,
			true);

		status = eap_status_completed_request;
	}
	else
	{
		// Unknown completion.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::complete_imsi_from_username(): ")
			 EAPL("Unknown eap_type_aka_complete_e %d in eap_type_aka_state_variable_e %d=%s.\n"),
			completion_action,
			get_saved_previous_state(),
			get_saved_previous_state_string()));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::check_synchronization_failure_response_message(
	const eap_am_network_id_c * const /* receive_network_id */,
	aka_header_c * const /*received_aka*/,
	const u32_t /*aka_packet_length*/,
	aka_payloads_c * const p_aka_payloads)
{
	eap_status_e status = eap_status_process_general_error;

		// Checks the payloads existence.
		if (p_aka_payloads->check_payloads(
				aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
				aka_payloads_c::eap_aka_payload_status_must_not_be, // MAC
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ENCR_DATA
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
				aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
				aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
				aka_payloads_c::eap_aka_payload_status_must_be,     // AUTS
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
				aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IV
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NOTIFICATION
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
				aka_payloads_c::eap_aka_payload_status_must_not_be, // CLIENT_ERROR_CODE
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RESULT_IND
				aka_payloads_c::eap_aka_payload_status_must_not_be  // CHECKCODE
				) == true
			)
		{
			const u8_t next_eap_identifier = static_cast<u8_t>(get_last_eap_identifier()+1u);

			save_current_state();
			set_state(eap_type_aka_state_pending_re_syncronization_query);

			// - - - - - - - - - - - - - - - - - - - - - - - -

			eap_type_aka_authentication_vector_c authentication_vector(m_am_tools);

			status = authentication_vector.get_AUTS()->set_copy_of_buffer(
				p_aka_payloads->get_AUTS()->get_payload_buffer());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = authentication_vector.get_RAND()->set_copy_of_buffer(get_authentication_vector()->get_RAND());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_am_type_aka->query_re_syncronization(
				next_eap_identifier,
				&authentication_vector);
			if (status == eap_status_pending_request)
			{
				// Request will be completed later using complete_re_syncronization_query() function.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
			else if (status == eap_status_completed_request)
			{
				// Request was already completed by AM using complete_re_syncronization_query() function.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
			else if (status == eap_status_success)
			{
				// eap_status_success means the authentication was successful.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else if (status == eap_status_ok)
			{
				// The query_re_syncronization() function call is synchronous.
				// We must call process_re_syncronization().
			}
			else
			{
				// This is an error case.
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// eap_status_ok status value means n_kc and n_sres were read but not processed.
			// Next we must call process_re_syncronization().

			// - - - - - - - - - - - - - - - - - - - - - - - -

			status = process_re_syncronization(
				next_eap_identifier,
				&authentication_vector);

			if (status != eap_status_ok
				&& status != eap_status_success)
			{
				restore_saved_previous_state();
			}

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			// Not correct AKA-payloads are included.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_challenge_request_message(6): ")
				 EAPL("Not correct AKA-payloads are included in eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::complete_re_syncronization_query(
	const u8_t next_eap_identifier,
	const eap_type_aka_authentication_vector_c * const authentication_vector)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	if (get_state() != eap_type_aka_state_pending_re_syncronization_query
		|| authentication_vector == 0
		|| authentication_vector->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	status = process_re_syncronization(
		next_eap_identifier,
		authentication_vector);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::process_re_syncronization(
	const u8_t next_eap_identifier,
	const eap_type_aka_authentication_vector_c * const authentication_vector)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	if (get_state() != eap_type_aka_state_pending_re_syncronization_query
		|| authentication_vector == 0
		|| authentication_vector->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	set_authentication_vector(authentication_vector->copy());
	if (get_authentication_vector() == 0
		|| get_authentication_vector()->get_is_valid() == false)
	{
		restore_saved_previous_state();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = send_challenge_request_message(
		next_eap_identifier);
	if (status != eap_status_ok)
	{
		restore_saved_previous_state();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_last_eap_identifier(next_eap_identifier);
	set_state(eap_type_aka_state_waiting_for_challenge_response);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_synchronization_failure_response_message(
	const eap_am_network_id_c * const receive_network_id,
	aka_header_c * const received_aka,
	const u32_t aka_packet_length,
	aka_payloads_c * const p_aka_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	if (get_state() == eap_type_aka_state_waiting_for_challenge_response)
	{
		// This could be first or retransmission request.
		if (received_aka->get_identifier() != get_last_eap_identifier())
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_synchronization_failure_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
				 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
				 received_aka->get_identifier(),
				 get_last_eap_identifier(), 
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}

		status = check_synchronization_failure_response_message(
			receive_network_id,
			received_aka,
			aka_packet_length,
			p_aka_payloads);
	}
	else if (get_state() == eap_type_aka_state_success)
	{
		if (received_aka->get_identifier() != get_last_eap_identifier()-1u)
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_synchronization_failure_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
				 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
				 received_aka->get_identifier(),
				 get_last_eap_identifier()-1u, 
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}

		status = check_synchronization_failure_response_message(
			receive_network_id,
			received_aka,
			aka_packet_length,
			p_aka_payloads);
	}
	else if (get_state() == eap_type_aka_state_pending_re_syncronization_query)
	{
		// This is re-transmitted EAP-Response/AKA/Challenge.
		// We dischard it quietly.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eap_type_aka_c::handle_challenge_response_message(): ")
			 EAPL("Re-transmitted message %d=%s dropped in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_challenge_request_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_aka_identity_response_message_completion(
	const u8_t next_eap_identifier,
	const eap_status_e identity_status,
	eap_type_aka_identity_type received_identity_type,
	const bool identity_payload_was_included)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::handle_aka_identity_response_message_completion(): ")
		 EAPL("received_identity_type %d=%s, identity payload was %d=%s, state %d=%s.\n"),
		 received_identity_type,
		 get_identity_string(received_identity_type),
		 get_aka_identity_response_includes_identity(),
		 aka_payload_AT_header_c::get_payload_AT_string(get_aka_identity_response_includes_identity()),
		 get_state(),
		 get_state_string()));

	if (get_state() == eap_type_aka_state_none)
	{
		// Authentication is terminated or state is wrong. Cannot continue.

		// The eap_status_handler_does_not_exists_error error value is more important
		// than return value of set_session_timeout().
		(void) get_type_partner()->set_session_timeout(0ul);

		return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
	}

	if (identity_payload_was_included == true)
	{
		if (identity_status != eap_status_ok
			|| received_identity_type == AKA_IDENTITY_TYPE_NONE)
		{
			// We did not get valid identity.
			set_identity_type(AKA_IDENTITY_TYPE_NONE);
			if (get_aka_identity_response_includes_identity() == aka_payload_AT_ANY_ID_REQ)
			{
				set_aka_identity_response_includes_identity(aka_payload_AT_FULLAUTH_ID_REQ);
			}
			else // if (get_aka_identity_response_includes_identity() == aka_payload_AT_FULLAUTH_ID_REQ)
			{
				set_aka_identity_response_includes_identity(aka_payload_AT_PERMANENT_ID_REQ);
			}
		}
		else
		{
			// We receive an identity.
			set_identity_type(received_identity_type);
		}

		if (m_identity_type == AKA_IDENTITY_TYPE_IMSI_ID)
		{
			m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("Identity: IMSI\n")));
		}
		else if (m_identity_type == AKA_IDENTITY_TYPE_PSEUDONYM_ID)
		{
			m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("Identity: pseudonym\n")));
		}
		else if (m_identity_type == AKA_IDENTITY_TYPE_RE_AUTH_ID)
		{
			m_authentication_type = AKA_AUTHENTICATION_TYPE_REAUTHENTICATION;

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("Identity: re-authentication\n")));
		}
		else
		{
			m_authentication_type = AKA_AUTHENTICATION_TYPE_NONE;

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("Identity: other\n")));
		}
	}
	else
	{
		// No AT_IDENTITY payload.
		// We may have identity already.
		if (get_identity()->get_is_valid_data() == true
			&& m_authentication_type != AKA_AUTHENTICATION_TYPE_NONE
			&& m_identity_type != AKA_IDENTITY_TYPE_NONE)
		{
			// OK identity is known.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::handle_aka_identity_response_message_completion(): ")
				 EAPL("Known  m_identity_type %d=%s, identity payload was %d=%s, state %d=%s.\n"),
				 m_identity_type,
				 get_identity_string(m_identity_type),
				 get_aka_identity_response_includes_identity(),
				 aka_payload_AT_header_c::get_payload_AT_string(get_aka_identity_response_includes_identity()),
				 get_state(),
				 get_state_string()));
		}
		else
		{
			// ERROR no accepted identity.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_response_message_completion(5): ")
				EAPL("No correct AKA-identity were received in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				get_state(),
				get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}

	save_current_state();

	u8_t local_eap_identifier = 0u;

	if (get_saved_previous_state() == eap_type_aka_state_waiting_for_challenge_response)
	{
		// Do not increase EAP-Identifier, this was re-transmission.
		local_eap_identifier = get_last_eap_identifier();
	}
	else
	{
		local_eap_identifier = static_cast<u8_t>(get_last_eap_identifier()+1u);
	}

	if (m_identity_type == AKA_IDENTITY_TYPE_NONE)
	{
		eap_status_e local_status = send_aka_identity_request_message(
			true,
			local_eap_identifier);
		if (local_status != eap_status_ok)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, local_status);
		}
		set_last_eap_identifier(local_eap_identifier);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, local_status);
	}
	else if (m_identity_type == AKA_IDENTITY_TYPE_IMSI_ID
		|| m_identity_type == AKA_IDENTITY_TYPE_PSEUDONYM_ID
		|| (m_identity_type == AKA_IDENTITY_TYPE_RE_AUTH_ID
			&& m_authentication_type == AKA_AUTHENTICATION_TYPE_FULL_AUTH))
	{
		eap_type_aka_identity_type local_identity_type = m_identity_type;

		eap_status_e local_status = query_AKA_authentication_vector(
			next_eap_identifier,
			&local_identity_type);
		if (local_status == eap_status_pending_request)
		{
			// Request will be completed later with complete_AKA_authentication_vector_query() function.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
		else if (local_status == eap_status_completed_request)
		{
			// Request was already completed with complete_AKA_authentication_vector_query() function.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
		else if (local_status != eap_status_ok)
		{
			// This is an error case.
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, local_status);
		}
		else //if (local_status == eap_status_ok)
		{
			// The query_AKA_authentication_vector() function call is synchronous.
			// We must call send_challenge_request_message().
		}

		local_status = send_challenge_request_message(
			local_eap_identifier);
		if (local_status != eap_status_ok)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, local_status);
		}

		set_last_eap_identifier(local_eap_identifier);
		set_state(eap_type_aka_state_waiting_for_challenge_response);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, local_status);
	}
	else if (m_identity_type == AKA_IDENTITY_TYPE_RE_AUTH_ID
		&& m_authentication_type == AKA_AUTHENTICATION_TYPE_REAUTHENTICATION)
	{
		// Here we need to send EAP-Request/Re-authentication
		eap_status_e local_status = send_reauthentication_request_message(
			get_NAI(),
			false,
			local_eap_identifier);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, local_status);
	}
	else
	{
		// Unnown identity type, do nothing.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
	}

}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_aka_identity_response_message(
	aka_header_c * const received_aka,
	const u32_t aka_packet_length,
	aka_payloads_c * const p_aka_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::handle_aka_identity_response_message(): ")
		 EAPL("m_identity_type %d=%s, identity payload was %d=%s, state %d=%s.\n"),
		 m_identity_type,
		 get_identity_string(m_identity_type),
		 get_aka_identity_response_includes_identity(),
		 aka_payload_AT_header_c::get_payload_AT_string(get_aka_identity_response_includes_identity()),
		 get_state(),
		 get_state_string()));

	if (aka_packet_length < received_aka->get_length())
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_response_message(): ")
			 EAPL("aka_packet_length < received_aka->get_length().\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (get_state() == eap_type_aka_state_waiting_for_aka_identity_response
		|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_any_identity
		|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_full_auth_identity
		|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_permanent_identity
		|| get_state() == eap_type_aka_state_waiting_for_challenge_response
		)
	{
		if (get_state() == eap_type_aka_state_waiting_for_aka_identity_response
			|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_any_identity
			|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_full_auth_identity
			|| get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_permanent_identity
			)
		{
			if (received_aka->get_identifier() != get_last_eap_identifier())
			{
				// Wrong EAP-Identifier in this state.
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_AKA_ERROR, 
					(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_response_message(): ")
					 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
					 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
					 received_aka->get_identifier(),
					 get_last_eap_identifier(), 
					 get_state(),
					 get_state_string()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
			}
		}
		else // if (get_state() == eap_type_aka_state_waiting_for_challenge_response)
		{
			// This might be retransmission response.
			if (received_aka->get_identifier() != get_last_eap_identifier()-1u)
			{
				// Wrong EAP-Identifier in this state.
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_AKA_ERROR, 
					(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_response_message(): ")
					 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
					 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
					 received_aka->get_identifier(),
					 get_last_eap_identifier()-1u, 
					 get_state(),
					 get_state_string()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
			}
		}


		// Checks the payloads existence.
		if (p_aka_payloads->check_payloads(
				aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
				aka_payloads_c::eap_aka_payload_status_must_not_be, // MAC
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ENCR_DATA
				aka_payloads_c::eap_aka_payload_status_optional,    // IDENTITY
				aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
				aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
				aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IV
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NOTIFICATION
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
				aka_payloads_c::eap_aka_payload_status_must_not_be, // CLIENT_ERROR_CODE
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RESULT_IND
				aka_payloads_c::eap_aka_payload_status_must_not_be  // CHECKCODE
				) == true
			)
		{
			if (get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_permanent_identity)
			{
				if (p_aka_payloads->get_IDENTITY_payload()->get_payload_included() == true)
				{
					// OK, NAI identity is included.
					// Identity must be IMSI. query_AKA_authentication_vector() must decode identity.

					set_aka_identity_response_includes_identity(aka_payload_AT_PERMANENT_ID_REQ);
				}
				else
				{
					// AT_IDENTITY is missing.
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_AKA_ERROR, 
						(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_response_message(0x%08x), ")
						 EAPL("AT_IDENTITY is missing in state %s.\n"),
						 this,
						 get_state_string()));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}
			}
			else if (get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_full_auth_identity)
			{
				if (p_aka_payloads->get_IDENTITY_payload()->get_payload_included() == true)
				{
					// OK, NAI identity is included.
					// Identity must be IMSI or pseudonym identity. query_AKA_authentication_vector() must decode identity.

					set_aka_identity_response_includes_identity(aka_payload_AT_FULLAUTH_ID_REQ);
				}
				else
				{
					// AT_IDENTITY is missing.
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_AKA_ERROR, 
						(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_response_message(0x%08x), ")
						 EAPL("AT_IDENTITY is missing in state %s.\n"),
						 this,
						 get_state_string()));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}
			}			
			else if (get_state() == eap_type_aka_state_waiting_for_aka_identity_response_with_at_any_identity)
			{
				if (p_aka_payloads->get_IDENTITY_payload()->get_payload_included() == true)
				{
					// OK, NAI identity is included.
					// Identity must be IMSI, pseudonym or re-authentication identity. query_AKA_authentication_vector() must decode identity.

					set_aka_identity_response_includes_identity(aka_payload_AT_ANY_ID_REQ);
				}
				else
				{
					// AT_IDENTITY is missing.
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_AKA_ERROR, 
						(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_response_message(0x%08x), ")
						 EAPL("AT_IDENTITY is missing in state %s.\n"),
						 this,
						 get_state_string()));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}
			}
			else if (get_state() == eap_type_aka_state_waiting_for_challenge_response)
			{
				// This is re-transmission.
				if (p_aka_payloads->get_IDENTITY_payload()->get_payload_included() == true)
				{
					if (get_aka_identity_response_includes_identity() == aka_payload_AT_PERMANENT_ID_REQ
						|| get_aka_identity_response_includes_identity() == aka_payload_AT_FULLAUTH_ID_REQ
						|| get_aka_identity_response_includes_identity() == aka_payload_AT_ANY_ID_REQ)
					{
						// OK, NAI identity is included.
					}
					else
					{
						// Illegal IDENTITY is included.
						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_AKA_ERROR, 
							(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_response_message(0x%08x), ")
							 EAPL("illegal AT_IDENTITY included in state %s.\n"),
							 this,
							 get_state_string()));
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
					}
				}
			}
			else
			{
				if (p_aka_payloads->get_IDENTITY_payload()->get_payload_included() == true)
				{
					// Illegal IDENTITY is included.
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_AKA_ERROR, 
						(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_response_message(0x%08x), ")
						 EAPL("illegal AT_IDENTITY included in state %s.\n"),
						 this,
						 get_state_string()));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}
			}


			status = checkcode_update_saved_message();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = checkcode_update(
				received_aka->get_header_buffer(
					received_aka->get_header_length()
					+received_aka->get_data_length()),
				received_aka->get_header_length()
				+received_aka->get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}


			eap_type_aka_identity_type identity_type = AKA_IDENTITY_TYPE_NONE;
			bool identity_payload_was_included = false;
			const u8_t next_eap_identifier = static_cast<u8_t>(received_aka->get_identifier()+1u);

			if (p_aka_payloads->get_IDENTITY_payload()->get_payload_included() == true)
			{
				status = parse_identity(
					p_aka_payloads->get_IDENTITY_payload()->get_data(p_aka_payloads->get_IDENTITY_payload()->get_data_length()),
					p_aka_payloads->get_IDENTITY_payload()->get_data_length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				identity_payload_was_included = true;

				// We must ask AM module whether the identity is IMSI, pseudonym or re-authentication identity.
				// If we have re-authentication identity we must send re-authentication query.

				if (randomly_refuse_eap_identity() == false)
				{
					status = m_am_type_aka->query_imsi_from_username(
						next_eap_identifier,
						get_send_network_id(),
						get_identity(),
						get_IMSI(),
						&identity_type,
						eap_type_aka_complete_handle_aka_identity_response_message_completion);
					if (status == eap_status_pending_request)
					{
						// This is pending query, that will be completed by complete_imsi_from_username() call.
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_pending_request);
					}
					else if (status == eap_status_completed_request)
					{
						// This is already completed by complete_imsi_from_username() call.
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
					}
					else if (status != eap_status_ok)
					{
						// ERROR in query_imsi_from_username().
						// This will return error status of query_imsi_from_username() call.
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
					else // status == eap_status_ok
					{
						// The query_imsi_from_username() function call was synchronous.
						// We must call send_aka_identity_request_message().
					}
				}
				else
				{
					status = eap_status_illegal_eap_identity;
				}
			}


			status = handle_aka_identity_response_message_completion(
				next_eap_identifier,
				status,
				identity_type,
				identity_payload_was_included);


		}
		else
		{
			// Not correct AKA-payloads are included.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_response_message(4): ")
				 EAPL("Not correct AKA-payloads are included in eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else if (get_state() == eap_type_aka_state_pending_authentication_vector_query)
	{
		// This is retransmission of EAP-Response/AKA/Start.
		// Triplet query is already initialized.
		// We will drop this message quietly.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eap_type_aka_c::handle_aka_identity_response_message(5): ")
			 EAPL("Retransmission of EAP-Response/AKA/Start in eap_type_aka_state_variable_e %d=%s.\n"),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_response_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_notification_response_message_reauthentication(
	const eap_am_network_id_c * const receive_network_id,
	aka_header_c * const received_aka,
	const u32_t /*aka_packet_length*/,
	aka_payloads_c * const p_aka_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: handler 0x%08x, AKA-type %10s, %s, state %2d=%s\n"),
		 this,
		 EAPL("handle_notification_response_message_reauthentication"),
		 (get_is_client()) ? EAPL("client") : EAPL("server"),
		 get_state(),
		 get_state_string()
		 ));

	// The second most significant bit of the notification code is called
	// the Phase bit (P bit). It specifies at which phase of the EAP-AKA
	// exchange the notification can be used.
	if (get_aka_notification_code_P_bit(m_aka_notification_code) == false)
	{
		// If the P bit is set to zero,
		// the notification can only be used after a successful EAP/AKA/
		// Challenge round in full authentication or a successful EAP/AKA/
		// Re-authentication round in reautentication. A re-authentication round
		// is considered successful only if the peer has successfully verified
		// AT_MAC and AT_COUNTER attributes, and does not include the
		// AT_COUNTER_TOO_SMALL attribute in EAP-Response/AKA/Re-authentication.

		// The AT_MAC attribute MUST beincluded if the P bit of the notification
		// code in AT_NOTIFICATION is set to zero, and MUST NOT be included in
		// cases when the P bit is set to one. The P bit is discussed in Section
		// 4.4.

		// Checks the payloads existence.
		if (p_aka_payloads->check_payloads(
				aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
				aka_payloads_c::eap_aka_payload_status_must_be,     // MAC
				aka_payloads_c::eap_aka_payload_status_must_be,     // ENCR_DATA
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
				aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
				aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
				aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_be,     // IV
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NOTIFICATION
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
				aka_payloads_c::eap_aka_payload_status_must_not_be,  // CLIENT_ERROR_CODE
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RESULT_IND
				aka_payloads_c::eap_aka_payload_status_must_not_be  // CHECKCODE
				) == true
			)
		{
			eap_variable_data_c orig_XKEY(m_am_tools);
			eap_variable_data_c orig_K_aut(m_am_tools);
			eap_variable_data_c orig_K_encr(m_am_tools);

			if (orig_XKEY.get_is_valid() == false
				|| orig_K_aut.get_is_valid() == false
				|| orig_K_encr.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u32_t reauth_counter = 0u;

			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_aka->query_reauth_parameters(
				&orig_XKEY,
				&orig_K_aut,
				&orig_K_encr,
				&reauth_counter);
			if (status != eap_status_ok)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = check_message_authentication_code(
				&orig_K_aut,
				p_aka_payloads,
				received_aka,
				received_aka->get_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			bool authentication_ok = true;

			// Decrypt and parse encrypted payload.
			{
				aka_payloads_c * const l_aka_payloads = new aka_payloads_c(m_am_tools);
				eap_automatic_variable_c<aka_payloads_c> l_aka_payloads_automatic(m_am_tools, l_aka_payloads);

				if (l_aka_payloads == 0
					|| l_aka_payloads->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = decrypt_DATA_payload(
					p_aka_payloads,
					&orig_K_encr);
				if (status != eap_status_ok)
				{
					restore_saved_previous_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				u32_t state_payload_buffer_length = p_aka_payloads->get_ENCR_DATA()->get_data_length();
				const aka_payload_AT_header_c gp_data_payload(
					m_am_tools,
					p_aka_payloads->get_ENCR_DATA()->get_data(state_payload_buffer_length),
					state_payload_buffer_length);

				status = parse_aka_payload(
					&gp_data_payload,
					&state_payload_buffer_length,
					l_aka_payloads,
					received_aka->get_subtype());
				if (status != eap_status_ok)
				{
					restore_saved_previous_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}


				if (l_aka_payloads->get_COUNTER()->get_payload_included() == false)
				{
					restore_saved_previous_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
				}

				u32_t counter = l_aka_payloads->get_COUNTER()->get_original_header()->get_reserved();

				if (counter == reauth_counter)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_notification_response_message_reauthentication(): ")
						EAPL("reauth counter %d OK, %d=%s.\n"),
						reauth_counter,
						get_state(),
						get_state_string()));
				}
				else
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_AKA_ERROR, 
						(EAPL("ERROR: eap_type_aka_c::handle_notification_response_message_reauthentication(): ")
						EAPL("reauth counter %d wrong, should be %d, %d=%s.\n"),
						counter,
						reauth_counter,
						get_state(),
						get_state_string()));

					authentication_ok = false;
				}
			}

			// The most significant bit is called the Failure bit (F bit).
			// The F bit specifies whether the notification implies failure.
			if (authentication_ok == false
				|| get_aka_notification_code_F_bit(m_aka_notification_code) == false)
			{
				// The code values with the F bit set to zero (code values 0...32767)
				// are used on unsuccessful cases.
				// The receipt of a notification code from this range implies failed EAP
				// exchange, so the peer can use the notification as a failure indication.

				set_last_eap_identifier(static_cast<u8_t>(get_last_eap_identifier()+1u));
				set_state(eap_type_aka_state_failure);

				// This will terminate session immediately.
				(void) get_type_partner()->set_session_timeout(0UL);

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
			else //if (get_aka_notification_code_F_bit(m_aka_notification_code) == true)
			{
				// The receipt of a notification code with the F bit set to one (values
				// 32768...65536) does not imply failure. Notification code 32768 has
				// been reserved as a general notification code to indicate successful
				// authentication.
				if (m_aka_notification_code == eap_aka_notification_F_set_no_P_user_authenticated)
				{
					status = finish_successful_authentication(
						receive_network_id);

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
				}
			}
		}
		else
		{
			// Not correct AKA-payloads are included.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_notification_response_message_reauthentication(): ")
				 EAPL("Not correct AKA-payloads are included ")
				 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else //if (get_aka_notification_code_P_bit(m_aka_notification_code) == true)
	{
		// Checks the payloads existence.
		if (p_aka_payloads->check_payloads(
				aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
				aka_payloads_c::eap_aka_payload_status_must_not_be, // MAC
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ENCR_DATA
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
				aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
				aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
				aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IV
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NOTIFICATION
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
				aka_payloads_c::eap_aka_payload_status_must_not_be, // CLIENT_ERROR_CODE
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RESULT_IND
				aka_payloads_c::eap_aka_payload_status_must_not_be  // CHECKCODE
				) == true
			)
		{
			// If the P bit is set to one, the notification can only by used before
			// the EAP/AKA/Challenge round in full authentication, or before the
			// EAP/AKA/Re-authentication round in reauthentication.

			// The most significant bit is called the Failure bit (F bit).
			// The F bit specifies whether the notification implies failure.
			if (get_aka_notification_code_F_bit(m_aka_notification_code) == false)
			{
				// The code values with the F bit set to zero (code values 0...32767)
				// are used on unsuccessful cases.
				// The receipt of a notification code from this range implies failed EAP
				// exchange, so the peer can use the notification as a failure indication.
			}
			else //if (get_aka_notification_code_F_bit(m_aka_notification_code) == true)
			{
				// The receipt of a notification code with the F bit set to one (values
				// 32768...65536) does not imply failure. Notification code 32768 has
				// been reserved as a general notification code to indicate successful
				// authentication.
			}

			status = initialize_error_message(
				eap_status_process_general_error);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			// Not correct AKA-payloads are included.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_notification_response_message_reauthentication(): ")
				 EAPL("Not correct AKA-payloads are included ")
				 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_notification_response_message_full_authentication(
	const eap_am_network_id_c * const receive_network_id,
	aka_header_c * const received_aka,
	const u32_t /*aka_packet_length*/,
	aka_payloads_c * const p_aka_payloads)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: handler 0x%08x, AKA-type %10s, %s, state %2d=%s\n"),
		 this,
		 EAPL("handle_notification_response_message_full_authentication"),
		 (get_is_client()) ? EAPL("client") : EAPL("server"),
		 get_state(),
		 get_state_string()
		 ));

	// The second most significant bit of the notification code is called
	// the Phase bit (P bit). It specifies at which phase of the EAP-AKA
	// exchange the notification can be used.
	if (get_aka_notification_code_P_bit(m_aka_notification_code) == false)
	{
		// If the P bit is set to zero,
		// the notification can only be used after a successful EAP/AKA/
		// Challenge round in full authentication or a successful EAP/AKA/
		// Re-authentication round in reautentication. A re-authentication round
		// is considered successful only if the peer has successfully verified
		// AT_MAC and AT_COUNTER attributes, and does not include the
		// AT_COUNTER_TOO_SMALL attribute in EAP-Response/AKA/Re-authentication.

		// The AT_MAC attribute MUST beincluded if the P bit of the notification
		// code in AT_NOTIFICATION is set to zero, and MUST NOT be included in
		// cases when the P bit is set to one. The P bit is discussed in Section
		// 4.4.

		// Checks the payloads existence.
		if (p_aka_payloads->check_payloads(
				aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
				aka_payloads_c::eap_aka_payload_status_must_be,     // MAC
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ENCR_DATA
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
				aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
				aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
				aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IV
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NOTIFICATION
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
				aka_payloads_c::eap_aka_payload_status_must_not_be, // CLIENT_ERROR_CODE
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RESULT_IND
				aka_payloads_c::eap_aka_payload_status_must_not_be  // CHECKCODE
				) == true
			)
		{
			eap_status_e status = check_message_authentication_code(
				get_K_aut(),
				p_aka_payloads,
				received_aka,
				received_aka->get_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// The most significant bit is called the Failure bit (F bit).
			// The F bit specifies whether the notification implies failure.
			if (get_aka_notification_code_F_bit(m_aka_notification_code) == false)
			{
				// The code values with the F bit set to zero (code values 0...32767)
				// are used on unsuccessful cases.
				// The receipt of a notification code from this range implies failed EAP
				// exchange, so the peer can use the notification as a failure indication.

				set_last_eap_identifier(static_cast<u8_t>(get_last_eap_identifier()+1u));
				set_state(eap_type_aka_state_failure);

				// This will terminate session immediately.
				(void) get_type_partner()->set_session_timeout(0UL);

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
			else //if (get_aka_notification_code_F_bit(m_aka_notification_code) == true)
			{
				// The receipt of a notification code with the F bit set to one (values
				// 32768...65536) does not imply failure. Notification code 32768 has
				// been reserved as a general notification code to indicate successful
				// authentication.
				if (m_aka_notification_code == eap_aka_notification_F_set_no_P_user_authenticated)
				{
					status = finish_successful_authentication(
						receive_network_id);

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
				}
			}
		}
		else
		{
			// Not correct AKA-payloads are included.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_notification_response_message_full_authentication(): ")
				 EAPL("Not correct AKA-payloads are included ")
				 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else //if (get_aka_notification_code_P_bit(m_aka_notification_code) == true)
	{
		// Checks the payloads existence.
		if (p_aka_payloads->check_payloads(
				aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
				aka_payloads_c::eap_aka_payload_status_must_not_be, // MAC
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ENCR_DATA
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
				aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
				aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
				aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IV
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NOTIFICATION
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
				aka_payloads_c::eap_aka_payload_status_must_not_be, // CLIENT_ERROR_CODE
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RESULT_IND
				aka_payloads_c::eap_aka_payload_status_must_not_be  // CHECKCODE
				) == true
			)
		{
			// If the P bit is set to one, the notification can only by used before
			// the EAP/AKA/Challenge round in full authentication, or before the
			// EAP/AKA/Re-authentication round in reauthentication.

			// The most significant bit is called the Failure bit (F bit).
			// The F bit specifies whether the notification implies failure.
			if (get_aka_notification_code_F_bit(m_aka_notification_code) == false)
			{
				// The code values with the F bit set to zero (code values 0...32767)
				// are used on unsuccessful cases.
				// The receipt of a notification code from this range implies failed EAP
				// exchange, so the peer can use the notification as a failure indication.
			}
			else //if (get_aka_notification_code_F_bit(m_aka_notification_code) == true)
			{
				// The receipt of a notification code with the F bit set to one (values
				// 32768...65536) does not imply failure. Notification code 32768 has
				// been reserved as a general notification code to indicate successful
				// authentication.
			}

			eap_status_e status = initialize_error_message(
				eap_status_process_general_error);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			// Not correct AKA-payloads are included.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_notification_response_message_full_authentication(): ")
				 EAPL("Not correct AKA-payloads are included ")
				 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_notification_response_message(
	const eap_am_network_id_c * const receive_network_id,
	aka_header_c * const received_aka,
	const u32_t aka_packet_length,
	aka_payloads_c * const p_aka_payloads)
{
	if (aka_packet_length < received_aka->get_length())
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_notification_response_message(): ")
			 EAPL("aka_packet_length < received_aka->get_length().\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	eap_status_e status = eap_status_process_general_error;

	if (get_state() == eap_type_aka_state_waiting_for_notification_response_success
		|| get_state() == eap_type_aka_state_waiting_for_notification_response_failure)
	{
		// NOTE, this message is unauthenticated. Anybody could sent this message.

		if (received_aka->get_identifier() != get_last_eap_identifier())
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_notification_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
				 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
				 received_aka->get_identifier(), get_last_eap_identifier(), 
				 get_state(), get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}


		if (m_authentication_type == AKA_AUTHENTICATION_TYPE_REAUTHENTICATION)
		{
			status = handle_notification_response_message_reauthentication(
				receive_network_id,
				received_aka,
				aka_packet_length,
				p_aka_payloads);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			status = handle_notification_response_message_full_authentication(
				receive_network_id,
				received_aka,
				aka_packet_length,
				p_aka_payloads);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_notification_response_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::check_challenge_response_message(
	const eap_am_network_id_c * const receive_network_id,
	aka_header_c * const received_aka,
	const u32_t aka_packet_length,
	aka_payloads_c * const p_aka_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	// Checks the payloads existence.
	if (p_aka_payloads->check_payloads(
			aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
			aka_payloads_c::eap_aka_payload_status_must_be,     // MAC
			aka_payloads_c::eap_aka_payload_status_must_not_be, // ENCR_DATA
			aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
			aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
			aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
			aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
			aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
			aka_payloads_c::eap_aka_payload_status_must_be,     // RES
			aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
			aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
			aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
			aka_payloads_c::eap_aka_payload_status_must_not_be, // IV
			aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
			aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
			aka_payloads_c::eap_aka_payload_status_must_not_be, // NOTIFICATION
			aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
			aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
			aka_payloads_c::eap_aka_payload_status_must_not_be, // CLIENT_ERROR_CODE
			aka_payloads_c::eap_aka_payload_status_optional,    // RESULT_IND
			aka_payloads_c::eap_aka_payload_status_optional     // CHECKCODE
			) == true
		)
	{
		save_current_state();
		set_state(eap_type_aka_state_analyses_challenge_response);

		status = get_saved_EAP_packet()->set_buffer(
			received_aka->get_header_buffer(aka_packet_length),
			aka_packet_length,
			false,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = check_message_authentication_code(
			get_K_aut(),
			p_aka_payloads,
			received_aka,
			aka_packet_length);

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (p_aka_payloads->get_CHECKCODE()->get_payload_included() == true)
		{
			// Verify AT_CHECKCODE.
			status = checkcode_verify(
				p_aka_payloads->get_CHECKCODE()->get_payload_buffer());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (status == eap_status_ok)
		{
			// Ok, client successfully authenticated.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("Authentication OK.\n")));

			if (m_use_result_indication == false
				&& p_aka_payloads->get_RESULT_IND()->get_payload_included() == true)
			{
				// ERROR: We did not send AT_RESULT_IND and client responds with it.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
			else if (m_use_result_indication == true
				&& p_aka_payloads->get_RESULT_IND()->get_payload_included() == false)
			{
				// Client does not expect result indication.
				m_use_result_indication = false;
			}

			// Here we swap the addresses.
			eap_am_network_id_c send_network_id(m_am_tools,
				receive_network_id->get_destination_id(),
				receive_network_id->get_source_id(),
				receive_network_id->get_type());

			if (get_master_session_key()->get_is_valid_data() == false
				|| get_master_session_key()->get_data_length() == 0u)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
			}

			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_aka->store_reauth_parameters(
				get_XKEY(),
				get_K_aut(),
				get_K_encr(),
				EAP_TYPE_AKA_INITIAL_REAUTH_COUNTER);
			if (status != eap_status_ok)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (m_use_result_indication == true)
			{
				// Send EAP-Request/AKA/Notification.
				m_aka_notification_code = eap_aka_notification_F_set_no_P_user_authenticated;

				status = send_aka_notification_request(
					m_aka_notification_code,
					false);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				set_state(eap_type_aka_state_waiting_for_notification_response_success);
			}
			else
			{
				if (m_randomly_fail_successfull_authentication == true
					&& random_selection() == true)
				{
					// This is for testing.
					m_aka_notification_code = eap_aka_notification_no_F_no_P_general_failure;

					status = initialize_notification_message();
				}
				else
				{
					// Note the EAP-Identifier of EAP-Success must be the same as
					// EAP-Identifier in the last EAP-Request - EAP-Response roundtrip.
					status = finish_successful_authentication(
						receive_network_id);
				}
			}
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		// Not correct AKA-payloads are included.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_challenge_response_message(6): ")
			 EAPL("Not correct AKA-payloads are included in eap_type_aka_state_variable_e %d=%s.\n"),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_challenge_response_message(
	const eap_am_network_id_c * const receive_network_id,
	aka_header_c * const received_aka,
	const u32_t aka_packet_length,
	aka_payloads_c * const p_aka_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	if (get_state() == eap_type_aka_state_waiting_for_challenge_response)
	{
		if (received_aka->get_identifier() != get_last_eap_identifier())
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_challenge_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
				 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
				 received_aka->get_identifier(), get_last_eap_identifier(), 
				 get_state(), get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}

		status = check_challenge_response_message(
			receive_network_id,
			received_aka,
			aka_packet_length,
			p_aka_payloads);
	}
	else if (get_state() == eap_type_aka_state_success)
	{
		if (received_aka->get_identifier() != get_last_eap_identifier()-1u)
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_challenge_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
				 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
				 received_aka->get_identifier(),
				 get_last_eap_identifier()-1u, 
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}

		status = check_challenge_response_message(
			receive_network_id,
			received_aka,
			aka_packet_length,
			p_aka_payloads);
	}
	else if (get_state() == eap_type_aka_state_pending_authentication_vector_query)
	{
		// This is re-transmitted EAP-Response/AKA/Challenge.
		// We dischard it quietly.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eap_type_aka_c::handle_challenge_response_message(): ")
			 EAPL("Re-transmitted message %d=%s dropped in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_challenge_response_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_reauthentication_response_message(
	const eap_am_network_id_c * const receive_network_id,
	aka_header_c * const received_aka,
	const u32_t aka_packet_length,
	aka_payloads_c * const p_aka_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_type_aka_c::handle_reauthentication_response_message(): %s, m_identity_type %d=%s, identity payload was %d=%s.\n"),
		 (m_is_client == true ? "client": "server"),
		 m_identity_type,
		 get_identity_string(m_identity_type),
		 get_aka_identity_response_includes_identity(),
		 aka_payload_AT_header_c::get_payload_AT_string(get_aka_identity_response_includes_identity())));

	if (get_state() == eap_type_aka_state_waiting_for_reauth_response)
	{
		// This could be first or retransmission request.

		// Checks the payloads existence.
		if (p_aka_payloads->check_payloads(
				aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
				aka_payloads_c::eap_aka_payload_status_must_be,     // MAC
				aka_payloads_c::eap_aka_payload_status_must_be,     // ENCR_DATA
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
				aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
				aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
				aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_be,     // IV
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NOTIFICATION
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
				aka_payloads_c::eap_aka_payload_status_must_not_be, // CLIENT_ERROR_CODE
				aka_payloads_c::eap_aka_payload_status_optional,    // RESULT_IND
				aka_payloads_c::eap_aka_payload_status_optional     // CHECKCODE
				) == true
			)
		{

			set_last_eap_identifier(received_aka->get_identifier());

			save_current_state();
			set_state(eap_type_aka_state_analyses_reauthentication_response);

			// - - - - - - - - - - - - - - - - - - - - - - - -

			eap_variable_data_c orig_XKEY(m_am_tools);
			eap_variable_data_c orig_K_aut(m_am_tools);
			eap_variable_data_c orig_K_encr(m_am_tools);

			if (orig_XKEY.get_is_valid() == false
				|| orig_K_aut.get_is_valid() == false
				|| orig_K_encr.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u32_t reauth_counter = 0u;
			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_aka->query_reauth_parameters(
				&orig_XKEY,
				&orig_K_aut,
				&orig_K_encr,
				&reauth_counter);
			if (status != eap_status_ok)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = check_message_authentication_code(
				&orig_K_aut,
				p_aka_payloads,
				received_aka,
				aka_packet_length);
			if (status != eap_status_ok)
			{
				restore_saved_previous_state();

				eap_status_string_c status_string;
				EAP_UNREFERENCED_PARAMETER(status_string);
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_AKA_ERROR, 
					(EAPL("ERROR: Re-authentication failed: %s, state %s\n"),
					 status_string.get_status_string(status),
					 get_state_string()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (p_aka_payloads->get_CHECKCODE()->get_payload_included() == true)
			{
				// Verify AT_CHECKCODE.
				status = checkcode_verify(
					p_aka_payloads->get_CHECKCODE()->get_payload_buffer());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			// Decrypt and parse encrypted payload.
			if (p_aka_payloads->get_IV()->get_payload_included() == true
			|| p_aka_payloads->get_ENCR_DATA()->get_payload_included() == true)
			{
				if (p_aka_payloads->get_IV()->get_payload_included() == true
				&& p_aka_payloads->get_ENCR_DATA()->get_payload_included() == true
				&& p_aka_payloads->get_MAC()->get_payload_included() == true)
				{
					if (m_use_result_indication == false
						&& p_aka_payloads->get_RESULT_IND()->get_payload_included() == true)
					{
						// ERROR: We did not send AT_RESULT_IND and client responds with it.
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
					}
					else if (m_use_result_indication == true
						&& p_aka_payloads->get_RESULT_IND()->get_payload_included() == false)
					{
						// Client does not expect result indication.
						m_use_result_indication = false;
					}

					aka_payloads_c * const l_aka_payloads = new aka_payloads_c(m_am_tools);
					eap_automatic_variable_c<aka_payloads_c> l_aka_payloads_automatic(m_am_tools, l_aka_payloads);

					if (l_aka_payloads == 0
						|| l_aka_payloads->get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					status = decrypt_DATA_payload(
						p_aka_payloads,
						&orig_K_encr);
					if (status != eap_status_ok)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					u32_t state_payload_buffer_length = p_aka_payloads->get_ENCR_DATA()->get_data_length();

					const aka_payload_AT_header_c gp_data_payload(
						m_am_tools,
						p_aka_payloads->get_ENCR_DATA()->get_data(state_payload_buffer_length),
						state_payload_buffer_length);

					if (gp_data_payload.get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
					}

					status = parse_aka_payload(
						&gp_data_payload,
						&state_payload_buffer_length,
						l_aka_payloads,
						received_aka->get_subtype());
					if (status != eap_status_ok)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					if (l_aka_payloads->get_counter_too_small()->get_payload_included() == true)
					{
						// When the client detects that the
						// counter value is not fresh, it includes the AT_COUNTER_TOO_SMALL
						// attribute in EAP-Response/AKA/Re-authentication. This attribute
						// doesn't contain any data but it is a request for the server to
						// initiate full authentication.

						// The full authentication must follow.
						m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;
						set_aka_identity_response_includes_identity(aka_payload_NONE);

						bool pseudonym_decode_failed = false;

						if (get_identity()->get_is_valid_data() == false
							|| (m_identity_type != AKA_IDENTITY_TYPE_IMSI_ID
								&& m_identity_type != AKA_IDENTITY_TYPE_PSEUDONYM_ID
								&& m_identity_type != AKA_IDENTITY_TYPE_RE_AUTH_ID))
						{
							// We do not have any identity of the client.
							set_aka_identity_response_includes_identity(aka_payload_AT_FULLAUTH_ID_REQ);
							set_identity_type(AKA_IDENTITY_TYPE_NONE);
							(void) get_identity()->reset();
							pseudonym_decode_failed = true;
						}

						status = send_aka_identity_request_message(
							pseudonym_decode_failed,
							static_cast<u8_t>(received_aka->get_identifier()+1u));
						if (status == eap_status_ok)
						{
							set_last_eap_identifier(static_cast<u8_t>(received_aka->get_identifier()+1u));
						}

						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}


					if (l_aka_payloads->get_COUNTER()->get_payload_included() == false)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
					}

					u32_t counter = l_aka_payloads->get_COUNTER()->get_original_header()->get_reserved();

					if (counter != reauth_counter)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
					}

					// OK, client re-authenticates corretly.

					if (m_use_result_indication == true)
					{
						// Send EAP-Request/AKA/Notification.
						m_aka_notification_code = eap_aka_notification_F_set_no_P_user_authenticated;

						status = send_aka_notification_request(
							m_aka_notification_code,
							true);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						set_state(eap_type_aka_state_waiting_for_notification_response_success);

						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
							(EAPL("EAP_type_AKA: %s, re-authentication OK, waits result indication\n"),
							 (m_is_client == true) ? "client": "server"));
					}
					else
					{
						if (m_randomly_fail_successfull_authentication == true
							&& random_selection() == true)
						{
							// This is for testing.
							m_aka_notification_code = eap_aka_notification_no_F_no_P_general_failure;

							status = initialize_notification_message();
						}
						else
						{
							// Note the EAP-Identifier of EAP-Success must be the same as
							// EAP-Identifier in the last EAP-Request - EAP-Response roundtrip.
							status = finish_successful_authentication(
								receive_network_id);
						}
					}
					
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else
				{
					// All of these must be included
					// or none of these must be included.
					restore_saved_previous_state();
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
				}
			}
			else
			{
				// Not correct AKA-payloads are included.
				restore_saved_previous_state();
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_AKA_ERROR, 
					(EAPL("ERROR: eap_type_aka_c::handle_reauthentication_response_message(6): ")
					 EAPL("Not correct AKA-payloads are included in eap_type_aka_state_variable_e %d=%s.\n"),
					 get_state(),
					 get_state_string()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}
		}
		else
		{
			// Not correct AKA-payloads are included.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_reauthentication_response_message(6): ")
				 EAPL("Not correct AKA-payloads are included in eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_reauthentication_response_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_client_error_response_message(
	const eap_am_network_id_c * const /* receive_network_id */,
	aka_header_c * const received_aka,
	const u32_t aka_packet_length,
	aka_payloads_c * const p_aka_payloads)
{
	EAP_UNREFERENCED_PARAMETER(aka_packet_length);
	EAP_UNREFERENCED_PARAMETER(received_aka);

	eap_status_e status = eap_status_process_general_error;

	// This could be first, retransmission request
	// or some nasty attacker to make denial of service.

	// Checks the payloads existence.
	if (p_aka_payloads->check_payloads(
			aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
			aka_payloads_c::eap_aka_payload_status_must_not_be, // MAC
			aka_payloads_c::eap_aka_payload_status_must_not_be, // ENCR_DATA
			aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
			aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
			aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
			aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
			aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
			aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
			aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
			aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
			aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
			aka_payloads_c::eap_aka_payload_status_must_not_be, // IV
			aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
			aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
			aka_payloads_c::eap_aka_payload_status_must_not_be, // NOTIFICATION
			aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
			aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
			aka_payloads_c::eap_aka_payload_status_must_be,     // CLIENT_ERROR_CODE
			aka_payloads_c::eap_aka_payload_status_must_not_be, // RESULT_IND
			aka_payloads_c::eap_aka_payload_status_must_not_be  // CHECKCODE
			) == true
		)
	{
		eap_status_e client_status = eap_status_process_general_error;

		/** @{ Add some use for the Client Error Code. } */
		eap_aka_client_error_code_e client_error_code
			= static_cast<eap_aka_client_error_code_e>(p_aka_payloads->get_CLIENT_ERROR_CODE()
				->get_original_header()->get_reserved());

		EAP_UNREFERENCED_PARAMETER(client_error_code);
		
		status = initialize_error_message(
			client_status);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		// Not correct AKA-payloads are included.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_client_error_response_message(): ")
			 EAPL("Not correct AKA-payloads are included in eap_type_aka_state_variable_e %d=%s.\n"),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::check_NAI(
	const u8_t * const identity,
	const u32_t identity_length,
	const u8_t * const at_character)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	bool includes_at = false;
	bool includes_dot = false;
	u32_t username_length = 0u;
	u32_t realm_length = 0u;

	for (u32_t ind = 0; ind < identity_length; ind++)
	{
		const u8_t character = identity[ind];

		if (includes_at == false)
		{
			if (character != AKA_NAI_AT_BYTE)
			{
				++username_length;
			}
		}
		else
		{
			++realm_length;
		}


		if ('0' <= character && character <= '9')
		{
			// OK.
		}
		else if ('a' <= character && character <= 'z')
		{
			// OK.
		}
		else if ('A' <= character && character <= 'Z')
		{
			// OK.
		}
		else if (character == AKA_NAI_AT_BYTE)
		{
			if (includes_at == false)
			{
				includes_at = true;
			}
			else
			{
				// Second at ('@').
				EAP_TRACE_DATA_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("Illegal NAI, includes second at \'@\' character."),
					identity,
					identity_length));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_nai);
			}
		}
		else if (character == '.')
		{
			if (includes_at == true)
			{
				// OK.
				includes_dot = true;
			}
			else
			{
				// dot ('.') within username
				EAP_TRACE_DATA_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("Illegal NAI, dot \'.\' within username."),
					identity,
					identity_length));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_nai);
			}
		}
		else if (character == '<'
			|| character == '>'
			|| character == '('
			|| character == ')'
			|| character == '['
			|| character == ']'
			|| character == '\\'
			|| character == '.'
			|| character == ','
			|| character == ';'
			|| character == ':'
			|| character == AKA_NAI_AT_BYTE
			|| character == ' ' // space
			|| character <= 0x1f // Ctrl
			|| character >= 0x7f) // extented characters
		{
			// Illegal character.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: Illegal NAI, includes illegal character 0x%02x=%c.\n"),
				 character,
				 character));
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("Illegal NAI, includes illegal character."),
				 identity,
				 identity_length));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_nai);
		}
		else
		{
			// All other ascii values are OK.
		}
	}

	// Note the username could be zero length.
	if ((realm_length == 1u && includes_at == true) // one at ('@') is illegal.
		|| (realm_length == 2u && includes_at == true && includes_dot == true)) //  one at ('@') and one dot is illegal.
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, (EAPL("Illegal NAI."),
			identity,
			identity_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_nai);
	}

	if (m_check_nai_realm == true)
	{
		if (at_character == 0
			&& realm_length == 0
			&& get_nai_realm()->get_data_length() == 0)
		{
			// OK, no realm.
		}
		else if (at_character == 0
			|| realm_length != get_nai_realm()->get_data_length()
			|| m_am_tools->memcmp(
				at_character+1u,
				get_nai_realm()->get_data(get_nai_realm()->get_data_length()),
				get_nai_realm()->get_data_length()) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("Illegal NAI, realm unknown."),
				identity,
				identity_length));
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("NAI should be"),
				get_nai_realm()->get_data(get_nai_realm()->get_data_length()),
				get_nai_realm()->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_nai);
		}
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::parse_identity(
	const u8_t * const identity,
	const u32_t identity_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	if (identity_length < 1u)
	{
		status = get_identity()->init(0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = get_NAI()->init(0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	const u8_t *at_character = reinterpret_cast<const u8_t *>(m_am_tools->memchr(
		identity,
		AKA_AT_CHARACTER[0],
		identity_length));

	// NOTE, at_character could be NULL. Realm is optional.

	status = check_NAI(identity, identity_length, at_character);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = eap_status_process_general_error;

	u32_t username_length = identity_length;
	if (at_character != 0)
	{
		username_length = static_cast<u32_t>(at_character-identity);
	}

	status = get_identity()->set_copy_of_buffer(
		identity, // Note we do store whole IMSI or pseudonym including possible prefix.
		username_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = get_NAI()->set_copy_of_buffer(identity, identity_length);
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
