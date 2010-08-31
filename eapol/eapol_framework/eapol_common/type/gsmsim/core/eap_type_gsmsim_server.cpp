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
* %version: 18.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 82 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_type_gsmsim.h"
#include "eap_type_gsmsim_header.h"
#include "eap_type_gsmsim_payloads.h"
#include "eap_type_gsmsim_mac_attributes.h"
#include "abs_eap_am_type_gsmsim.h"
#include "eap_crypto_api.h"
#include "eap_state_notification.h"
#include "eap_automatic_variable.h"
#include "eap_am_type_gsmsim.h"


//--------------------------------------------------

/** @file */

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::add_n_rand_payload(
	gsmsim_header_c * const gsmsim,
	const u32_t gsmsim_buffer_length,
	const u32_t eap_header_size,
	u32_t * const gsmsim_data_offset,
	u32_t * const gsmsim_data_free,
	u32_t * const packet_buffer_free,
	u32_t * const packet_buffer_offset,
	eap_type_sim_triplet_array_c * const triplets)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;
	gsmsim_payload_AT_header_c gp_n_rands(
		m_am_tools,
		gsmsim->get_data_offset(*gsmsim_data_offset, *gsmsim_data_free),
		*gsmsim_data_free);

	if (gp_n_rands.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	u32_t rand_data_length = triplets->get_triplet_count() * SIM_RAND_LENGTH;


	gp_n_rands.reset_header(static_cast<u16_t>(rand_data_length));
	gp_n_rands.set_current_payload(gsmsim_payload_AT_RAND);

	u8_t *n_rands = gp_n_rands.get_data(rand_data_length);
	if (n_rands == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	for (u32_t ind = 0u; ind < triplets->get_triplet_count(); ind++)
	{
		eap_type_saesim_triplet_c *triplet = triplets->get_triplet(m_am_tools, ind);

		u8_t * const source = triplet->get_rand()->get_data();
		if (source == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_am_tools->memmove(
			n_rands+(ind*SIM_RAND_LENGTH),
			source,
			triplet->get_rand()->get_data_length());
	}

	status = eap_status_ok;

	update_payload_indexes(
		gsmsim_buffer_length,
		eap_header_size,
		gp_n_rands.get_header_length()+gp_n_rands.get_data_length(),
		gsmsim_data_offset,
		gsmsim_data_free,
		packet_buffer_offset,
		packet_buffer_free);

	EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_n_rands);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::send_reauthentication_request_message(
	const eap_variable_data_c * const username,
	const bool pseudonym_decode_failed,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(pseudonym_decode_failed);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("    send: GSMSIM-subtype %10s, %s, state %2d=%s\n"),
		 EAPL("gsmsim_subtype_Re_authentication"),
		 EAPL("server"),
		 m_state,
		 get_state_string()
		 ));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_type_gsmsim_c::send_reauthentication_request_message(): %s, m_identity_type %d=%s, requested identity payload is %d=%s.\n"),
		 (m_is_client == true ? "client": "server"),
		 m_identity_type,
		 get_identity_string(m_identity_type),
		 m_start_response_includes_identity,
		 gsmsim_payload_AT_header_c::get_payload_AT_string(m_start_response_includes_identity)));

	eap_status_e status = eap_status_process_general_error;

	eap_buf_chain_wr_c request_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (request_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)
	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means GSMSIM does process every re-transmitted EAP-Request.
		request_packet.set_do_packet_retransmission(false);
	}
#endif //#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)

	EAP_ASSERT_ALWAYS(EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH >= (m_gsmsim_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_gsmsim_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_gsmsim_header_offset+m_MTU;
	}

	gsmsim_header_c gsmsim_response(
		m_am_tools,
		request_packet.get_data_offset(
			m_gsmsim_header_offset,
			(packet_buffer_free-m_gsmsim_header_offset)),
		(packet_buffer_free-m_gsmsim_header_offset));

	if (gsmsim_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("send_reauthentication_request_message: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	gsmsim_response.reset_header(
		packet_buffer_free-m_gsmsim_header_offset,
		m_use_eap_expanded_type);
	gsmsim_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_gsmsim_header_offset),
		m_use_eap_expanded_type);
	gsmsim_response.set_code(eap_code_request);
	gsmsim_response.set_identifier(eap_identifier);
	gsmsim_response.set_type(
		eap_type_gsmsim,
		m_use_eap_expanded_type);
	gsmsim_response.set_subtype(gsmsim_subtype_Re_authentication);

	update_buffer_indexes(
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		m_gsmsim_header_offset+gsmsim_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::send_reauthentication_request_message(0x%08x).\n"),
		this));

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t gsmsim_data_free = packet_buffer_free;
	u32_t gsmsim_data_offset = 0u;

	eap_variable_data_c orig_XKEY(m_am_tools);
	eap_variable_data_c orig_K_aut(m_am_tools);
	eap_variable_data_c orig_K_encr(m_am_tools);
	u32_t reauth_counter = 0u;
	eap_variable_data_c reauth_nonce_s(m_am_tools);


	// In order to use re-authentication, the client and the server need to
	// store the following values: original XKEY, K_aut, K_encr, latest
	// counter value and the next re-authentication identity.
	status = m_am_type_gsmsim->query_reauth_parameters(
		&orig_XKEY,
		&orig_K_aut,
		&orig_K_encr,
		&reauth_counter);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_type_gsmsim_c::send_reauthentication_request_message(): %s, m_saved_reauth_counter %d.\n"),
		 (m_is_client == true ? "client": "server"),
		 reauth_counter));

	status = generate_nonce(EAP_TYPE_GSMSIM_NONCE_MT_SIZE, &reauth_nonce_s);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_nonce_s.set_copy_of_buffer(&reauth_nonce_s);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c master_session_key(m_am_tools);

	status = generate_reauth_shared_secred_keys(
		EAP_TYPE_GSMSIM_KEYMAT_SIZE,
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
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			gsmsim_payload_AT_RESULT_IND);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	crypto_aes_c aes(m_am_tools);

	if (aes.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = m_am_type_gsmsim->generate_encryption_IV(
		m_IV.get_payload_buffer(),
		aes.get_block_size());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_variable_payload(
		&gsmsim_response,
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		gsmsim_response.get_header_length(),
		&gsmsim_data_offset,
		&gsmsim_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		m_IV.get_payload_buffer(),
		gsmsim_payload_AT_IV);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	u8_t *MAC_data = 0;
	u32_t MAC_data_length = 0u;
	eap_type_gsmsim_MAC_attributes_c MAC_attributes;

	// Encrypted data.
	{
		gsmsim_payload_AT_header_c gp_encrypted_data(
			m_am_tools,
			gsmsim_response.get_data_offset(
				gsmsim_data_offset, 
				gsmsim_data_free),
			gsmsim_data_free);
		if (gsmsim_response.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		// Initialize the length of encrypted data to maximum length.
		// Later this will be set to correct length.
		gp_encrypted_data.reset_header(gsmsim_payload_AT_header_c::get_max_payload_data_length());
		gp_encrypted_data.set_current_payload(gsmsim_payload_AT_ENCR_DATA);

		update_payload_indexes(
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			gp_encrypted_data.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
			&packet_buffer_offset,
			&packet_buffer_free);

		u32_t encrypted_data_offset_begin = packet_buffer_offset;

		// -   -   -   -   -   -   -   -   -   -   -   -

		status = add_counter_payload(
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
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
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			&reauth_nonce_s,
			gsmsim_payload_AT_NONCE_S);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// -   -   -   -   -   -   -   -   -   -   -   -

		status = m_am_type_gsmsim->generate_reauthentication_id(
			&m_send_network_id,
			&m_IMSI,
			&m_reauthentication_identity,
			EAP_TYPE_GSMSIM_MAX_NAI_LENGTH);
		if (status == eap_status_ok)
		{
			status = add_pseudonym_or_imsi_payload(
				&gsmsim_response,
				EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
				gsmsim_response.get_header_length(),
				&gsmsim_data_offset,
				&gsmsim_data_free,
				&packet_buffer_free,
				&packet_buffer_offset,
				&m_reauthentication_identity,
				gsmsim_payload_AT_NEXT_REAUTH_ID);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// -   -   -   -   -   -   -   -   -   -   -   -

		status = add_padding_payload(
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
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
			m_IV.get_payload_buffer(),
			&orig_K_encr);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_encrypted_data);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_mac_payload(
		&gsmsim_response,
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		gsmsim_response.get_header_length(),
		&gsmsim_data_offset,
		&gsmsim_data_free,
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

	gsmsim_response.set_data_length(
		gsmsim_data_offset,
		m_use_eap_expanded_type);

	request_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
		== packet_buffer_offset);

	// -   -   -   -   -   -   -   -   -   -   -   -

	MAC_attributes.init(
		MAC_data,
		MAC_data_length,
		gsmsim_response.get_header_buffer(gsmsim_response.get_length()),
		gsmsim_response.get_length());

	status = create_message_authentication_code(
		&MAC_attributes,
		gsmsim_response.get_subtype(),
		gsmsim_response.get_code(),
		&orig_K_aut);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	gsmsim_response.set_data_length(
		gsmsim_data_offset,
		m_use_eap_expanded_type);

	request_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
		== packet_buffer_offset);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::send_reauthentication_request_message()\n")));

	status = packet_send(
		&m_send_network_id,
		&request_packet,
		m_gsmsim_header_offset,
		gsmsim_response.get_header_length()+gsmsim_response.get_data_length(),
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		status = m_master_session_key.set_copy_of_buffer(&master_session_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		set_state(eap_type_gsmsim_state_waiting_for_reauth_response);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::send_start_request_message(
	const bool pseudonym_decode_failed,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("    send: %s, GSMSIM-subtype %10s, %s, state %2d=%s\n"),
		 EAPL("initiator"),
		 EAPL("gsmsim_subtype_Start"),
		 EAPL("server"),
		 m_state,
		 get_state_string()
		 ));

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::send_start_request_message(): ")
		 EAPL("m_identity_type %d=%s, requested identity payload is %d=%s, state %d=%s, pseudonym decode %d.\n"),
		 m_identity_type,
		 get_identity_string(m_identity_type),
		 m_start_response_includes_identity,
		 gsmsim_payload_AT_header_c::get_payload_AT_string(m_start_response_includes_identity),
		 m_state,
		 get_state_string(),
		 pseudonym_decode_failed));

	eap_status_e status = eap_status_process_general_error;

	eap_buf_chain_wr_c request_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (request_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)
	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means GSMSIM does process every re-transmitted EAP-Request.
		request_packet.set_do_packet_retransmission(false);
	}
#endif //#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)

	EAP_ASSERT_ALWAYS(EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH >= (m_gsmsim_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_gsmsim_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_gsmsim_header_offset+m_MTU;
	}

	gsmsim_header_c gsmsim_response(
		m_am_tools,
		request_packet.get_data_offset(
			m_gsmsim_header_offset,
			(packet_buffer_free-m_gsmsim_header_offset)),
		(packet_buffer_free-m_gsmsim_header_offset));

	if (gsmsim_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("send_start_request_message: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	gsmsim_response.reset_header(
		packet_buffer_free-m_gsmsim_header_offset,
		m_use_eap_expanded_type);
	gsmsim_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_gsmsim_header_offset),
		m_use_eap_expanded_type);
	gsmsim_response.set_code(eap_code_request);
	gsmsim_response.set_identifier(eap_identifier);
	gsmsim_response.set_type(
		eap_type_gsmsim,
		m_use_eap_expanded_type);
	gsmsim_response.set_subtype(gsmsim_subtype_Start);

	update_buffer_indexes(
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		m_gsmsim_header_offset+gsmsim_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::send_start_request_message(0x%08x).\n"),
		 this));

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t gsmsim_data_free = packet_buffer_free;
	u32_t gsmsim_data_offset = 0u;

	if (pseudonym_decode_failed == true)
	{
		gsmsim_payload_AT_type_e next_identity_request = gsmsim_payload_NONE;
		eap_type_gsmsim_state_variable_e next_state = eap_type_gsmsim_state_failure;

		if (m_identity.get_is_valid_data() == true)
		{
			if (m_start_response_includes_identity == gsmsim_payload_AT_FULLAUTH_ID_REQ)
			{
				next_identity_request = gsmsim_payload_AT_FULLAUTH_ID_REQ;
				next_state = eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity;
			}
			else if (m_start_response_includes_identity == gsmsim_payload_AT_PERMANENT_ID_REQ)
			{
				next_identity_request = gsmsim_payload_AT_PERMANENT_ID_REQ;
				next_state = eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity;
			}
			else if (m_start_response_includes_identity == gsmsim_payload_AT_ANY_ID_REQ)
			{
				next_identity_request = gsmsim_payload_AT_ANY_ID_REQ;
				next_state = eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity;
			}
			else
			{
				// We drop this message because no real identity is received from client.
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_GSMSIM_ERROR, (EAPL("ERROR: send_start_request_message: no real identity received.\n")));
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
			}
		}
		else
		{
			next_identity_request = gsmsim_payload_AT_ANY_ID_REQ;
			next_state = eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity;
		}

		status = add_variable_payload(
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
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
		set_state(eap_type_gsmsim_state_waiting_for_start_response);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -


	eap_gsmsim_version version_list = GSMSIM_VERSION_1;

	status = add_version_list(
		&gsmsim_response,
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		gsmsim_response.get_header_length(),
		&gsmsim_data_offset,
		&gsmsim_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		&version_list,
		sizeof(version_list)/sizeof(eap_gsmsim_version),
		gsmsim_payload_AT_VERSION_LIST);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	// - - - - - - - - - - - - - - - - - - - - - - - -

	gsmsim_response.set_data_length(
		gsmsim_data_offset,
		m_use_eap_expanded_type);

	request_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
		== packet_buffer_offset);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::send_start_request_message()\n")));

	status = packet_send(
		&m_send_network_id,
		&request_packet,
		m_gsmsim_header_offset,
		gsmsim_response.get_header_length()+gsmsim_response.get_data_length(),
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::send_challenge_request_message(
		const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("    send: GSMSIM-type %10s, %s, state %2d=%s\n"),
		 EAPL("gsmsim_subtype_Challenge"),
		 (m_is_client) ? EAPL("client") : EAPL("server"),
		 m_state,
		 get_state_string()
		 ));

	eap_buf_chain_wr_c gsmsim_initial_reply(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (gsmsim_initial_reply.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)
	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means GSMSIM does process every re-transmitted EAP-Request.
		gsmsim_initial_reply.set_do_packet_retransmission(false);
	}
#endif //#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)

	EAP_ASSERT_ALWAYS(EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH >= (m_gsmsim_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_gsmsim_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_gsmsim_header_offset+m_MTU;
	}

	gsmsim_header_c gsmsim_response(
		m_am_tools,
		gsmsim_initial_reply.get_data_offset(
			m_gsmsim_header_offset,
			(packet_buffer_free-m_gsmsim_header_offset)),
		(packet_buffer_free-m_gsmsim_header_offset));

	if (gsmsim_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	gsmsim_response.reset_header(
		packet_buffer_free-m_gsmsim_header_offset,
		m_use_eap_expanded_type);
	gsmsim_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_gsmsim_header_offset),
		m_use_eap_expanded_type);
	gsmsim_response.set_code(eap_code_request);
	gsmsim_response.set_identifier(eap_identifier);
	gsmsim_response.set_type(
		eap_type_gsmsim,
		m_use_eap_expanded_type);

	gsmsim_response.set_subtype(gsmsim_subtype_Challenge);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::send_challenge_request_message(0x%08x).\n"),
		this));

	update_buffer_indexes(
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		m_gsmsim_header_offset+gsmsim_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t gsmsim_data_free = packet_buffer_free;
	u32_t gsmsim_data_offset = 0u;
	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c n_rand(m_am_tools);
	eap_variable_data_c n_kc(m_am_tools);

	u32_t count = m_triplets->get_triplet_count();

	if (count == 0u)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	status = n_rand.init(SIM_RAND_LENGTH*count);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	n_rand.set_is_valid();
	n_rand.set_data_length(0u);

	status = n_kc.init(SIM_KC_LENGTH*count);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	n_kc.set_is_valid();
	n_kc.set_data_length(0u);

	status = m_n_sres.init(SIM_KC_LENGTH*count);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	m_n_sres.set_is_valid();
	m_n_sres.set_data_length(0u);

	u32_t ind;
	for (ind = 0u; ind < count; ind++)
	{
		eap_type_saesim_triplet_c *tripl = m_triplets->get_triplet(m_am_tools, ind);
		if (tripl == 0
			|| tripl->get_rand()->get_data_length() == 0u
			|| tripl->get_kc()->get_data_length() == 0u
			|| tripl->get_sres()->get_data_length() == 0u)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		n_rand.add_data(
			tripl->get_rand()->get_data(),
			tripl->get_rand()->get_data_length());

		n_kc.add_data(
			tripl->get_kc()->get_data(),
			tripl->get_kc()->get_data_length());

		m_n_sres.add_data(
			tripl->get_sres()->get_data(),
			tripl->get_sres()->get_data_length());
	} // for()


	if (n_rand.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (n_kc.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (m_n_sres.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (m_identity.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (m_IMSI.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (m_nonce_mt.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("n*RAND"),
		n_rand.get_data(),
		n_rand.get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("n*KC"),
		n_kc.get_data(),
		n_kc.get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("n*SRES"),
		m_n_sres.get_data(),
		m_n_sres.get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("identity"),
		m_identity.get_data(),
		m_identity.get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("IMSI"),
		m_IMSI.get_data(),
		m_IMSI.get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("NONCE MT"),
		m_nonce_mt.get_data(),
		m_nonce_mt.get_data_length()));


	eap_variable_data_c XKEY(m_am_tools);
	eap_variable_data_c K_encr(m_am_tools);
	eap_variable_data_c K_aut(m_am_tools);
	eap_variable_data_c master_session_key(m_am_tools);

	status = generate_shared_secred_keys(
		EAP_TYPE_GSMSIM_KEYMAT_SIZE,
		&n_kc,
		&m_n_sres,
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
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			gsmsim_payload_AT_RESULT_IND);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_n_rand_payload(
		&gsmsim_response,
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		gsmsim_response.get_header_length(),
		&gsmsim_data_offset,
		&gsmsim_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		m_triplets);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	u8_t *MAC_data = 0;
	u32_t MAC_data_length = 0u;
	eap_type_gsmsim_MAC_attributes_c MAC_attributes;

	if (m_use_pseudonym_identity == true
		|| m_use_reauthentication_identity == true)
	{
		u32_t saved_gsmsim_data_offset = gsmsim_data_offset;
		u32_t saved_gsmsim_data_free = gsmsim_data_free;
		u32_t saved_packet_buffer_offset = packet_buffer_offset;
		u32_t saved_packet_buffer_free = packet_buffer_free;

		crypto_aes_c aes(m_am_tools);

		if (aes.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = m_am_type_gsmsim->generate_encryption_IV(
			m_IV.get_payload_buffer(),
			aes.get_block_size());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		status = add_variable_payload(
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			m_IV.get_payload_buffer(),
			gsmsim_payload_AT_IV);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		// Encrypted data.
		{
			gsmsim_payload_AT_header_c gp_encrypted_data(
				m_am_tools,
				gsmsim_response.get_data_offset(
					gsmsim_data_offset, 
					gsmsim_data_free),
				gsmsim_data_free);
			if (gp_encrypted_data.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			// Initialize the length of encrypted data to maximum length.
			// Later this will be set to correct length.
			gp_encrypted_data.reset_header(gsmsim_payload_AT_header_c::get_max_payload_data_length());
			gp_encrypted_data.set_current_payload(gsmsim_payload_AT_ENCR_DATA);

			update_payload_indexes(
				EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
				gsmsim_response.get_header_length(),
				gp_encrypted_data.get_header_length(),
				&gsmsim_data_offset,
				&gsmsim_data_free,
				&packet_buffer_offset,
				&packet_buffer_free);

			u32_t encrypted_data_offset_begin = packet_buffer_offset;

			// -   -   -   -   -   -   -   -   -   -   -   -

			if (m_use_pseudonym_identity == true)
			{
				status = m_am_type_gsmsim->generate_pseudonym_id(
					&m_send_network_id,
					&m_IMSI,
					&m_pseudonym,
					EAP_TYPE_GSMSIM_MAX_NAI_LENGTH);
				if (status == eap_status_ok)
				{
					status = add_pseudonym_or_imsi_payload(
						&gsmsim_response,
						EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
						gsmsim_response.get_header_length(),
						&gsmsim_data_offset,
						&gsmsim_data_free,
						&packet_buffer_free,
						&packet_buffer_offset,
						&m_pseudonym,
						gsmsim_payload_AT_NEXT_PSEUDONYM);
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
				status = m_am_type_gsmsim->generate_reauthentication_id(
					&m_send_network_id,
					&m_IMSI,
					&m_reauthentication_identity,
					EAP_TYPE_GSMSIM_MAX_NAI_LENGTH);
				if (status == eap_status_ok)
				{
					status = add_pseudonym_or_imsi_payload(
						&gsmsim_response,
						EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
						gsmsim_response.get_header_length(),
						&gsmsim_data_offset,
						&gsmsim_data_free,
						&packet_buffer_free,
						&packet_buffer_offset,
						&m_reauthentication_identity,
						gsmsim_payload_AT_NEXT_REAUTH_ID);
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
					&gsmsim_response,
					EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
					gsmsim_response.get_header_length(),
					&gsmsim_data_offset,
					&gsmsim_data_free,
					&packet_buffer_free,
					&packet_buffer_offset,
					plain_text_length
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
					m_IV.get_payload_buffer(),
					&K_encr);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_encrypted_data);
			}
			else
			{
				// No encrypted data, remove AT_ENCR_DATA header.
				gsmsim_data_offset = saved_gsmsim_data_offset;
				gsmsim_data_free = saved_gsmsim_data_free;
				packet_buffer_offset = saved_packet_buffer_offset;
				packet_buffer_free = saved_packet_buffer_free;
			}
		}
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_mac_payload(
		&gsmsim_response,
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		gsmsim_response.get_header_length(),
		&gsmsim_data_offset,
		&gsmsim_data_free,
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

	gsmsim_response.set_data_length(
		gsmsim_data_offset,
		m_use_eap_expanded_type);

	gsmsim_initial_reply.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
		== packet_buffer_offset);

	// -   -   -   -   -   -   -   -   -   -   -   -

	MAC_attributes.init(
		MAC_data,
		MAC_data_length,
		gsmsim_response.get_header_buffer(gsmsim_response.get_length()),
		gsmsim_response.get_length());

	status = create_message_authentication_code(
		&MAC_attributes,
		gsmsim_response.get_subtype(),
		gsmsim_response.get_code(),
		&K_aut);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	gsmsim_response.set_data_length(
		gsmsim_data_offset,
		m_use_eap_expanded_type);

	gsmsim_initial_reply.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
		== packet_buffer_offset);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = packet_send(
		&m_send_network_id,
		&gsmsim_initial_reply,
		m_gsmsim_header_offset,
		gsmsim_response.get_header_length()+gsmsim_response.get_data_length(),
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		// Store keys.
		status = m_XKEY.set_copy_of_buffer(&XKEY);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		status = m_K_encr.set_copy_of_buffer(&K_encr);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		status = m_K_aut.set_copy_of_buffer(&K_aut);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		status = m_master_session_key.set_copy_of_buffer(&master_session_key);
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::send_gsmsim_notification_request(
	const eap_gsmsim_notification_codes_e notification_code,
	const bool add_at_counter_attribute)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: GSMSIM-type %10s, %s, state %2d=%s, notification_code = %d\n"),
		 EAPL("send_gsmsim_notification_request"),
		 (m_is_client) ? EAPL("client") : EAPL("server"),
		 m_state,
		 get_state_string(),
		 notification_code
		 ));

	eap_buf_chain_wr_c eap_notification_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_notification_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)
	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means GSMSIM does process every re-transmitted EAP-Request.
		eap_notification_packet.set_do_packet_retransmission(false);
	}
#endif //#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)

	EAP_ASSERT_ALWAYS(EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH >= (m_gsmsim_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_gsmsim_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_gsmsim_header_offset+m_MTU;
	}

	gsmsim_header_c gsmsim_response(
		m_am_tools,
		eap_notification_packet.get_data_offset(
			m_gsmsim_header_offset,
			(packet_buffer_free-m_gsmsim_header_offset)),
		(packet_buffer_free-m_gsmsim_header_offset));

	if (gsmsim_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	m_last_eap_identifier = static_cast<u8_t>(m_last_eap_identifier+1u);

	gsmsim_response.reset_header(
		static_cast<u16_t>(packet_buffer_free-m_gsmsim_header_offset),
		m_use_eap_expanded_type);
	gsmsim_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_gsmsim_header_offset),
		m_use_eap_expanded_type);
	gsmsim_response.set_code(eap_code_request);
	gsmsim_response.set_identifier(m_last_eap_identifier);
	gsmsim_response.set_type(
		eap_type_gsmsim,
		m_use_eap_expanded_type);
	gsmsim_response.set_subtype(gsmsim_subtype_Notification);


	update_buffer_indexes(
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		m_gsmsim_header_offset+gsmsim_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t gsmsim_data_free = packet_buffer_free;
	u32_t gsmsim_data_offset = 0u;

	eap_status_e status = add_notification_payload(
		&gsmsim_response,
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		gsmsim_response.get_header_length(),
		&gsmsim_data_offset,
		&gsmsim_data_free,
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

	if (get_gsmsim_notification_code_P_bit(notification_code) == false)
	{
		u8_t *MAC_data = 0;
		u32_t MAC_data_length = 0u;
		eap_type_gsmsim_MAC_attributes_c MAC_attributes;

		if (add_at_counter_attribute == true)
		{
			// If EAP-Request/SIM/Notification is used on fast a re-authentication
			// exchange, and if the P bit in AT_NOTIFICATION is set to zero, then
			// AT_COUNTER is used for replay protection. In this case, the
			// AT_ENCR_DATA and AT_IV attributes MUST be included, and the
			// encapsulated plaintext attributes MUST include the AT_COUNTER
			// attribute. The counter value included in AT_COUNTER MUST be the same
			// as in the EAP-Request/SIM/Re-authentication packet on the same fast
			// re-authentication exchange.

			// - - - - - - - - - - - - - - - - - - - - - - - -

			eap_variable_data_c orig_XKEY(m_am_tools);
			eap_variable_data_c orig_K_encr(m_am_tools);
			u32_t reauth_counter = 0u;

			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_gsmsim->query_reauth_parameters(
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

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_type_gsmsim_c::send_gsmsim_notification_request(): %s, m_saved_reauth_counter %d.\n"),
				 (m_is_client == true ? "client": "server"),
				 reauth_counter));

			K_aut = &orig_K_aut;

			// -   -   -   -   -   -   -   -   -   -   -   -

			crypto_aes_c aes(m_am_tools);

			if (aes.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = m_am_type_gsmsim->generate_encryption_IV(
				m_IV.get_payload_buffer(),
				aes.get_block_size());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}


			status = add_variable_payload(
				&gsmsim_response,
				EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
				gsmsim_response.get_header_length(),
				&gsmsim_data_offset,
				&gsmsim_data_free,
				&packet_buffer_free,
				&packet_buffer_offset,
				m_IV.get_payload_buffer(),
				gsmsim_payload_AT_IV);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}


			// Encrypted data.
			{
				gsmsim_payload_AT_header_c gp_encrypted_data(
					m_am_tools,
					gsmsim_response.get_data_offset(
						gsmsim_data_offset, 
						gsmsim_data_free),
					gsmsim_data_free);
				if (gsmsim_response.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
				}

				// Initialize the length of encrypted data to maximum length.
				// Later this will be set to correct length.
				gp_encrypted_data.reset_header(gsmsim_payload_AT_header_c::get_max_payload_data_length());
				gp_encrypted_data.set_current_payload(gsmsim_payload_AT_ENCR_DATA);

				update_payload_indexes(
					EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
					gsmsim_response.get_header_length(),
					gp_encrypted_data.get_header_length(),
					&gsmsim_data_offset,
					&gsmsim_data_free,
					&packet_buffer_offset,
					&packet_buffer_free);

				u32_t encrypted_data_offset_begin = packet_buffer_offset;

				// -   -   -   -   -   -   -   -   -   -   -   -

				status = add_counter_payload(
					&gsmsim_response,
					EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
					gsmsim_response.get_header_length(),
					&gsmsim_data_offset,
					&gsmsim_data_free,
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
					&gsmsim_response,
					EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
					gsmsim_response.get_header_length(),
					&gsmsim_data_offset,
					&gsmsim_data_free,
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
					m_IV.get_payload_buffer(),
					&orig_K_encr);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_encrypted_data);
			}

		}
		else
		{
			K_aut = &m_K_aut;
		} // if (add_counter_payload == true)

		// -   -   -   -   -   -   -   -   -   -   -   -

		// Add AT_MAC attribute.
		status = add_mac_payload(
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
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

		gsmsim_response.set_data_length(
			gsmsim_data_offset,
			m_use_eap_expanded_type);

		eap_notification_packet.set_data_length(packet_buffer_offset);

		EAP_ASSERT_ALWAYS(
			m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
			== packet_buffer_offset);

		// -   -   -   -   -   -   -   -   -   -   -   -

		MAC_attributes.init(
			MAC_data,
			MAC_data_length,
			gsmsim_response.get_header_buffer(gsmsim_response.get_length()),
			gsmsim_response.get_length());

		status = create_message_authentication_code(
			&MAC_attributes,
			gsmsim_response.get_subtype(),
			gsmsim_response.get_code(),
			K_aut);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}
	else
	{
		gsmsim_response.set_data_length(
			gsmsim_data_offset,
			m_use_eap_expanded_type);

		eap_notification_packet.set_data_length(packet_buffer_offset);

		EAP_ASSERT_ALWAYS(
			m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
			== packet_buffer_offset);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_notification_packet.set_data_length(packet_buffer_offset);

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("    send: EAP-Response/Notification packet"),
		gsmsim_response.get_header_buffer(gsmsim_response.get_length()),
		gsmsim_response.get_length()));

	status = packet_send(
		&m_send_network_id,
		&eap_notification_packet,
		m_gsmsim_header_offset,
		gsmsim_response.get_length(),
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::query_SIM_triplets(
		eap_type_gsmsim_identity_type * const identity_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_type_sim_triplet_array_c triplets(m_am_tools);

	set_state(eap_type_gsmsim_state_pending_triplet_query);

	eap_status_e status = m_am_type_gsmsim->query_SIM_triplets(
		false,
		&m_identity, // This is username part from payload AT_IDENTITY.
		&m_IMSI, // This is the real IMSI. If this is uninitialized get_identity() must be initialized, imsi will be initialized after this call is complete.
		&triplets,
		identity_type);

	if (status == eap_status_pending_request)
	{
		// This is pending query, that will be completed by complete_SIM_triplets() call.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status == eap_status_completed_request)
	{
		// This query was already completed by complete_SIM_triplets() call.
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

	set_triplets(triplets.copy());
	if (m_triplets == 0
		|| m_triplets->get_triplet_count() == 0)
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::complete_SIM_triplets(
	eap_type_sim_triplet_array_c * const triplets,
	const eap_variable_data_c * const IMSI,
	const eap_gsmsim_triplet_status_e triplet_status,
	const eap_type_gsmsim_identity_type identity_type,
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
		(EAPL("eap_type_gsmsim_c::complete_SIM_triplets(): identity_type %d=%s, requested identity payload is %d=%s, state %d=%s\n"),
		 identity_type,
		 get_identity_string(identity_type),
		 m_start_response_includes_identity,
		 gsmsim_payload_AT_header_c::get_payload_AT_string(m_start_response_includes_identity),
		 m_state,
		 get_state_string()));

	if (completion_status != eap_status_ok
		|| triplets == 0)
	{
		set_state(eap_type_gsmsim_state_failure);

		// The eap_status_process_general_error error value is more important
		// than return value of set_session_timeout().
		get_type_partner()->set_session_timeout(0ul);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}


	if (m_state != eap_type_gsmsim_state_pending_triplet_query)
	{
		// Authentication is terminated or state is wrong. Cannot continue.
		set_state(eap_type_gsmsim_state_failure);

		// The eap_status_handler_does_not_exists_error error value is more important
		// than return value of set_session_timeout().
		get_type_partner()->set_session_timeout(0ul);

		return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
	}

	eap_status_e status = eap_status_process_general_error;

	if (m_identity_type != GSMSIM_IDENTITY_TYPE_RE_AUTH_ID)
	{
		set_identity_type(identity_type);
	}

	if (m_identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID
		&& IMSI->get_is_valid_data() == true)
	{
		status = m_IMSI.set_copy_of_buffer(IMSI);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (triplet_status == eap_gsmsim_triplet_status_ok)
	{
		// First check the identity type is correct.
		if ((m_identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID
				&& (m_start_response_includes_identity == gsmsim_payload_AT_PERMANENT_ID_REQ
					|| m_start_response_includes_identity == gsmsim_payload_AT_FULLAUTH_ID_REQ
					|| m_start_response_includes_identity == gsmsim_payload_AT_ANY_ID_REQ))
			|| (m_identity_type == GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID
				&& (m_start_response_includes_identity == gsmsim_payload_AT_FULLAUTH_ID_REQ
					|| m_start_response_includes_identity == gsmsim_payload_AT_ANY_ID_REQ))
			|| (m_identity_type == GSMSIM_IDENTITY_TYPE_RE_AUTH_ID
				&& m_start_response_includes_identity == gsmsim_payload_AT_ANY_ID_REQ)
			|| m_start_response_includes_identity == gsmsim_payload_NONE)
		{
			// OK, correct identity received.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::complete_SIM_triplets(): OK\n")));
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::complete_SIM_triplets(): ")
				 EAPL("EAP-identity is wrong, state %d=%s.\n"),
				 m_state, get_state_string()));

			if (m_start_response_includes_identity == gsmsim_payload_AT_PERMANENT_ID_REQ)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: eap_type_gsmsim_c::complete_SIM_triplets(): ")
					 EAPL("permanent identity was required, %d=%s was get.\n"),
					 m_identity_type,
					 get_identity_string(m_identity_type)));
			}
			else if (m_start_response_includes_identity == gsmsim_payload_AT_FULLAUTH_ID_REQ)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: eap_type_gsmsim_c::complete_SIM_triplets(): ")
					 EAPL("full authentication identity was required, %d=%s was get.\n"),
					 m_identity_type,
					 get_identity_string(m_identity_type)));
			}
			else if (m_start_response_includes_identity == gsmsim_payload_AT_ANY_ID_REQ)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: eap_type_gsmsim_c::complete_SIM_triplets(): ")
					 EAPL("any identity was required, %d=%s was get.\n"),
					 m_identity_type,
					 get_identity_string(m_identity_type)));
			}
			else
			{
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: eap_type_gsmsim_c::complete_SIM_triplets(): ")
					 EAPL("no special identity was required, %d=%s was get.\n"),
					 m_identity_type,
					 get_identity_string(m_identity_type)));
			}
			
			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR, wrong identity"),
				m_NAI.get_data(),
				m_NAI.get_data_length()));

			restore_saved_previous_state();

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}

		if (m_IMSI.get_is_valid_data() == false
			&& IMSI != &m_IMSI)
		{
			// We must copy queried IMSI.
			status = m_IMSI.set_copy_of_buffer(IMSI);
			if (status != eap_status_ok)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		set_triplets(triplets->copy());
		if (m_triplets == 0
			|| m_triplets->get_triplet_count() == 0)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u8_t local_eap_identifier;

		if (m_saved_previous_state == eap_type_gsmsim_state_waiting_for_challenge_response)
		{
			// Do not increase EAP-Identifier, this was re-transmission.
			local_eap_identifier = m_last_eap_identifier;
		}
		else
		{
			local_eap_identifier = static_cast<u8_t>(m_last_eap_identifier+1u);
		}

		status = send_challenge_request_message(
			local_eap_identifier);
		if (status != eap_status_ok)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_last_eap_identifier = local_eap_identifier;
		set_state(eap_type_gsmsim_state_waiting_for_challenge_response);
	}
	else
	{
		// Error occurred in tripler query.
		// We must send EAP-Notification message.
		// 
		// eap_gsmsim_notification_no_F_no_P_users_calls_are_barred and eap_gsmsim_notification_no_F_no_P_user_has_not_subscribed_to_the_requested_service cannot be used because P bit is not set.
		m_gsmsim_notification_code = eap_gsmsim_notification_no_F_P_set_general_failure;

		status = initialize_notification_message();

		m_last_eap_identifier = static_cast<u8_t>(m_last_eap_identifier+1u);

		set_state(eap_type_gsmsim_state_waiting_for_notification_response_failure);
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_type_gsmsim_c::randomly_refuse_eap_identity()
{
	bool skip_query_imsi_from_username = false;

	if (m_gsmsim_test_version == true
		&& m_gsmsim_randomly_refuse_eap_identity == true)
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
				(EAPL("TEST: eap_type_gsmsim_c::randomly_refuse_eap_identity(): ")
				 EAPL("randomly fails EAP-Identity.\n")));
		}
	}

	return skip_query_imsi_from_username;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_identity_response_message(
	eap_header_rd_c * const eap_header,
	const u32_t gsmsim_packet_length)
{
	eap_status_e status = eap_status_process_general_error;

#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	const eap_type_gsmsim_state_variable_e gsmsim_identity_response_states_1[] =
	{
		eap_type_gsmsim_state_waiting_for_identity_response,
		eap_type_gsmsim_state_waiting_for_start_response,
		eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity,
		eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity,
		eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity,
	};

	const eap_type_gsmsim_state_variable_e gsmsim_identity_response_states_2[] =
	{
		eap_type_gsmsim_state_waiting_for_start_response,
		eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity,
		eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity,
		eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity,
	};

	if (verify_states(gsmsim_identity_response_states_1, GSMSIM_STATE_COUNT(gsmsim_identity_response_states_1)) == true
		// In test version new authentication could start from this state.
		|| (m_gsmsim_test_version == true
			&& m_state == eap_type_gsmsim_state_success) // This one is for testing purposes.
		)
#else
	if (m_state == eap_type_gsmsim_state_waiting_for_identity_response
		|| m_state == eap_type_gsmsim_state_waiting_for_start_response
		|| m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity
		|| m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity
		|| m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity
		// In test version new authentication could start from this state.
		|| (m_gsmsim_test_version == true
			&& m_state == eap_type_gsmsim_state_success) // This one is for testing purposes.
		)
#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	{
		// OK correct state.
	}
	else
	{
		// Wrong state, dischard packet.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_identity_response_message(): ")
			 EAPL("EAP-Response/Identity received in wrong state %d=%s. This EAP-packet is dropped.\n"),
			 m_state, get_state_string()));
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
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
		if (m_state == eap_type_gsmsim_state_waiting_for_identity_response
		&& eap_header->get_identifier() != m_last_eap_identifier)
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_identity_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
				 EAPL("in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 eap_header->get_identifier(),
				 m_last_eap_identifier, 
				 m_state,
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}
#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
		else if (verify_states(gsmsim_identity_response_states_2, GSMSIM_STATE_COUNT(gsmsim_identity_response_states_2)) == true
				 && eap_header->get_identifier() != m_last_eap_identifier-1u)
#else
		else if ((m_state == eap_type_gsmsim_state_waiting_for_start_response
				  || m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity
				  || m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity
				  || m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity
				  )
				 && eap_header->get_identifier() != m_last_eap_identifier-1u)
#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_identity_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
				 EAPL("in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 eap_header->get_identifier(),
				 m_last_eap_identifier-1u, 
				 m_state,
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}
		// In test version new authentication could start from this state.
		else if (m_gsmsim_test_version == true
			&& m_state == eap_type_gsmsim_state_success) // This one is for testing purposes.
		{
			// NOTE here we can not check the EAP-identifier.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: eap_type_gsmsim_c::handle_identity_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is not checked in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 eap_header->get_identifier(),
				 m_state,
				 get_state_string()));
		}
	}

	{
		// This could be first or retransmission request.

		if (eap_header->get_type_data_length() > gsmsim_packet_length)
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
			(EAPL("GSMSIM received EAP-identity NAI"),
			 m_NAI.get_data(),
			 m_NAI.get_data_length()));

		u8_t next_eap_identifier = static_cast<u8_t>(eap_header->get_identifier()+1u);

#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
		if (verify_states(gsmsim_identity_response_states_2, GSMSIM_STATE_COUNT(gsmsim_identity_response_states_2)) == true)
#else
		if (m_state == eap_type_gsmsim_state_waiting_for_start_response
			|| m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity
			|| m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity
			|| m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity
			)
#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
		{
			// This is retransmission, so the EAP-identifier is not increased.
			next_eap_identifier = m_last_eap_identifier;
		}
		// In test version new authentication could start from this state.
		else if (m_gsmsim_test_version == true
			&& m_state == eap_type_gsmsim_state_success) // This one is for testing purposes.
		{
			// NOTE here we can not check the EAP-identifier.
			next_eap_identifier = static_cast<u8_t>(eap_header->get_identifier()+1u);
			set_state(eap_type_gsmsim_state_waiting_for_identity_response);
			m_IMSI.reset();
		}

		save_current_state();
		set_state(eap_type_gsmsim_state_pending_pseudonym_decode_query);

		eap_type_gsmsim_identity_type identity_type = GSMSIM_IDENTITY_TYPE_NONE;

		if (m_accept_eap_identity_response == true)
		{
			if (randomly_refuse_eap_identity() == false)
			{
				status = m_am_type_gsmsim->query_imsi_from_username(
					false,
					next_eap_identifier,
					&m_send_network_id,
					&m_identity,
					&m_IMSI,
					&identity_type,
					eap_type_gsmsim_complete_handle_imsi_from_username);
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
					// EAP-SIM/request/start will query identity.
					m_identity.reset();
				}
			}
			else // status == eap_status_ok
			{
				// The query_imsi_from_username() function call was synchronous.
				// We must call send_start_request_message().
			}
		}


		{
			status = handle_imsi_from_username(
				next_eap_identifier,
				&m_send_network_id,
				&m_identity,
				&m_IMSI,
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_imsi_from_username(
	const u8_t next_eap_identifier,
	const eap_am_network_id_c * const network_id,
	const eap_variable_data_c * const username,
	const eap_variable_data_c * const imsi, ///< The result is stored to imsi parameter.
	const eap_type_gsmsim_identity_type received_identity_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(username);
	EAP_UNREFERENCED_PARAMETER(network_id);

	EAP_ASSERT(received_identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID
		|| received_identity_type == GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID
		|| received_identity_type == GSMSIM_IDENTITY_TYPE_RE_AUTH_ID
		|| received_identity_type == GSMSIM_IDENTITY_TYPE_NONE);

	if (m_state != eap_type_gsmsim_state_pending_pseudonym_decode_query)
	{
		// State is wrong. Cannot continue.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_gsmsim_state);
	}

	eap_status_e status = eap_status_process_general_error;
	bool pseudonym_decode_failed = true;

	set_identity_type(received_identity_type);

	if (imsi != 0
		&& imsi->get_is_valid_data() == true)
	{
		pseudonym_decode_failed = false;
		status = m_IMSI.set_copy_of_buffer(imsi);
		if (status != eap_status_ok)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (received_identity_type == GSMSIM_IDENTITY_TYPE_NONE)
		{
			set_identity_type(GSMSIM_IDENTITY_TYPE_IMSI_ID);
		}
	}
	else
	{
		m_IMSI.reset();
	}

	if (m_identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID)
	{
		m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
			(EAPL("Identity: IMSI\n")));
	}
	else if (m_identity_type == GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID)
	{
		m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
			(EAPL("Identity: pseudonym\n")));
	}
	else if (m_identity_type == GSMSIM_IDENTITY_TYPE_RE_AUTH_ID)
	{
		m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_REAUTHENTICATION;

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
			(EAPL("Identity: re-authentication\n")));
	}
	else
	{
		m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_NONE;

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
			(EAPL("Identity: other\n")));
	}

	if ((m_identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID
			&& (m_saved_previous_state == eap_type_gsmsim_state_waiting_for_identity_response
				|| m_saved_previous_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity
				|| m_saved_previous_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity
				|| m_saved_previous_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity
				|| m_saved_previous_state == eap_type_gsmsim_state_waiting_for_start_response))
		|| (m_identity_type == GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID
			&& (m_saved_previous_state == eap_type_gsmsim_state_waiting_for_identity_response
				|| m_saved_previous_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity
				|| m_saved_previous_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity
				|| m_saved_previous_state == eap_type_gsmsim_state_waiting_for_start_response))
		|| m_identity_type == GSMSIM_IDENTITY_TYPE_NONE)
	{

		if (m_identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID)
		{
			set_start_response_includes_identity(gsmsim_payload_AT_PERMANENT_ID_REQ);
		}
		else if (m_identity_type == GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID)
		{
			set_start_response_includes_identity(gsmsim_payload_AT_FULLAUTH_ID_REQ);
		}
		else if (m_identity_type == GSMSIM_IDENTITY_TYPE_NONE)
		{
			set_start_response_includes_identity(gsmsim_payload_AT_ANY_ID_REQ);
			pseudonym_decode_failed = true;
		}

		status = send_start_request_message(
			pseudonym_decode_failed,
			next_eap_identifier);
	}
	else if (m_identity_type == GSMSIM_IDENTITY_TYPE_RE_AUTH_ID
		&& (m_saved_previous_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity
			|| m_saved_previous_state == eap_type_gsmsim_state_waiting_for_identity_response
			|| m_saved_previous_state == eap_type_gsmsim_state_waiting_for_start_response))
	{
		// Here we need to send EAP-Request/Re-authentication
		status = send_reauthentication_request_message(
			&m_NAI,
			pseudonym_decode_failed,
			next_eap_identifier);
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_imsi_from_username(): ")
			 EAPL("EAP-Identity type 0x%02x is wrong in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			m_identity_type,
			m_saved_previous_state,
			get_saved_previous_state_string()));

		status = eap_status_illegal_eap_identity;
	}

	if (status != eap_status_ok)
	{
		restore_saved_previous_state();
	}
	else
	{
		m_last_eap_identifier = next_eap_identifier;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::complete_imsi_from_username(
	const u8_t next_eap_identifier,
	const eap_am_network_id_c * const network_id,
	const eap_variable_data_c * const username,
	const eap_variable_data_c * const imsi, ///< The result is stored to imsi parameter.
	const eap_type_gsmsim_identity_type identity_type,
	const eap_status_e completion_status,
	const eap_type_gsmsim_complete_e completion_action)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
		(EAPL("eap_type_gsmsim_c::complete_imsi_from_username(): identity_type %d=%s, requested identity payload is %d=%s\n"),
		 identity_type,
		 get_identity_string(identity_type),
		 m_start_response_includes_identity,
		 gsmsim_payload_AT_header_c::get_payload_AT_string(m_start_response_includes_identity)));

	EAP_UNREFERENCED_PARAMETER(username);
	EAP_UNREFERENCED_PARAMETER(network_id);

	if (completion_status != eap_status_ok)
	{
		set_state(eap_type_gsmsim_state_failure);

		// The completion_status error value is more important
		// than return value of set_session_timeout().
		get_type_partner()->set_session_timeout(0ul);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, completion_status);
	}

	eap_status_e status = eap_status_not_supported;

	if (completion_action == eap_type_gsmsim_complete_handle_imsi_from_username)
	{
		status = handle_imsi_from_username(
			next_eap_identifier,
			network_id,
			username,
			imsi, ///< The result is stored to imsi parameter.
			identity_type);

		status = eap_status_completed_request;
	}
	else if (completion_action == eap_type_gsmsim_complete_handle_start_response_message_completion)
	{
		// NOTE the identity_payload_was_included parameter is
		// true in this completion.
		status = handle_start_response_message_completion(
			next_eap_identifier,
			completion_status,
			identity_type,
			true);

		status = eap_status_completed_request;
	}
	else
	{
		// Unknown completion.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::complete_imsi_from_username(): ")
			 EAPL("Unknown eap_type_gsmsim_complete_e %d in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			completion_action,
			m_saved_previous_state,
			get_saved_previous_state_string()));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_start_response_message_completion(
	const u8_t next_eap_identifier,
	const eap_status_e identity_status,
	eap_type_gsmsim_identity_type received_identity_type,
	const bool identity_payload_was_included)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
		(EAPL("eap_type_gsmsim_c::handle_start_response_message_completion(): received_identity_type %d=%s, requested identity payload is %d=%s\n"),
		 received_identity_type,
		 get_identity_string(received_identity_type),
		 m_start_response_includes_identity,
		 gsmsim_payload_AT_header_c::get_payload_AT_string(m_start_response_includes_identity)));

	if (m_state == eap_type_gsmsim_state_none)
	{
		// Authentication is terminated or state is wrong. Cannot continue.

		// The eap_status_handler_does_not_exists_error error value is more important
		// than return value of set_session_timeout().
		get_type_partner()->set_session_timeout(0ul);

		return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
	}

	if (identity_payload_was_included == true)
	{
		if (identity_status != eap_status_ok
			|| received_identity_type == GSMSIM_IDENTITY_TYPE_NONE)
		{
			// We did not get valid identity.
			set_identity_type(GSMSIM_IDENTITY_TYPE_NONE);
			received_identity_type = GSMSIM_IDENTITY_TYPE_NONE;

			if (m_start_response_includes_identity == gsmsim_payload_AT_ANY_ID_REQ)
			{
				set_start_response_includes_identity(gsmsim_payload_AT_FULLAUTH_ID_REQ);
			}
			else // if (m_start_response_includes_identity == gsmsim_payload_AT_FULLAUTH_ID_REQ)
			{
				set_start_response_includes_identity(gsmsim_payload_AT_PERMANENT_ID_REQ);
			}
		}
		else
		{
			set_identity_type(received_identity_type);
		}

		if (m_identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID)
		{
			m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("Identity: IMSI\n")));
		}
		else if (m_identity_type == GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID)
		{
			m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("Identity: pseudonym\n")));
		}
		else if (m_identity_type == GSMSIM_IDENTITY_TYPE_RE_AUTH_ID)
		{
			m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_REAUTHENTICATION;

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("Identity: re-authentication\n")));

			// Here nonce_mt and SELECTED_VERSION MUST NOT be included.
			// Note nonce_mt is copied earlier to handler.
			if (m_nonce_mt.get_is_valid_data() == true
				|| m_gsmsim_selected_version != GSMSIM_ILLEGAL_VERSION)
			{
				// Not correct GSMSIM-payloads are included.
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: eap_type_gsmsim_c::handle_start_response_message_completion(4): ")
					 EAPL("Not correct GSMSIM-payloads are included in eap_type_gsmsim_state_variable_e %d=%s.\n"),
					 m_state,
					get_state_string()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}
		}
		else
		{
			m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_NONE;

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
		if (m_identity.get_is_valid_data() == true
			&& m_authentication_type != GSMSIM_AUTHENTICATION_TYPE_NONE
			&& m_identity_type != GSMSIM_IDENTITY_TYPE_NONE)
		{
			// OK identity is known.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("eap_type_gsmsim_c::handle_start_response_message_completion(): Known m_identity_type %d=%s, requested identity payload is %d=%s\n"),
				 m_identity_type,
				 get_identity_string(m_identity_type),
				 m_start_response_includes_identity,
				 gsmsim_payload_AT_header_c::get_payload_AT_string(m_start_response_includes_identity)));
		}
		else
		{
			// ERROR no accepted identity.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_start_response_message_completion(5): ")
				 EAPL("No correct GSMSIM-identity were received in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}



	save_current_state();

	u8_t local_eap_identifier(next_eap_identifier);

	if (m_identity_type == GSMSIM_IDENTITY_TYPE_NONE)
	{
		// This will send EAP-Request/SIM/Start with identity request.
		eap_status_e local_status = send_start_request_message(
			true,
			local_eap_identifier);
		if (local_status != eap_status_ok)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, local_status);
		}
		m_last_eap_identifier = local_eap_identifier;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, local_status);
	}
	else if (m_identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID
		|| m_identity_type == GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID
		|| (m_identity_type == GSMSIM_IDENTITY_TYPE_RE_AUTH_ID
			&& m_authentication_type == GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH))
	{
		eap_type_gsmsim_identity_type local_identity_type = m_identity_type;

		eap_status_e local_status = query_SIM_triplets(&local_identity_type);
		if (local_status == eap_status_pending_request)
		{
			// Request will be completed later with complete_SIM_triplets() function.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
		else if (local_status == eap_status_completed_request)
		{
			// Request was already completed with complete_SIM_triplets() function.
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
			// The query_SIM_triplets() function call is synchronous.
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

		m_last_eap_identifier = local_eap_identifier;
		set_state(eap_type_gsmsim_state_waiting_for_challenge_response);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, local_status);
	}
	else if (m_identity_type == GSMSIM_IDENTITY_TYPE_RE_AUTH_ID
			&& m_authentication_type == GSMSIM_AUTHENTICATION_TYPE_REAUTHENTICATION)
	{
		// Here we need to send EAP-Request/Re-authentication
		eap_status_e local_status = send_reauthentication_request_message(
			&m_NAI,
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_start_response_message(
	gsmsim_header_c * const received_gsmsim,
	const u32_t gsmsim_packet_length,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
		(EAPL("eap_type_gsmsim_c::handle_start_response_message(): m_identity_type %d=%s, requested identity payload is %d=%s\n"),
		 m_identity_type,
		 get_identity_string(m_identity_type),
		 m_start_response_includes_identity,
		 gsmsim_payload_AT_header_c::get_payload_AT_string(m_start_response_includes_identity)));

	if (gsmsim_packet_length < received_gsmsim->get_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_start_response_message(): ")
			 EAPL("gsmsim_packet_length < received_gsmsim->get_length().\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	const eap_type_gsmsim_state_variable_e gsmsim_start_response_states_1[] =
	{
		eap_type_gsmsim_state_waiting_for_start_response,
		eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity,
		eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity,
		eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity,
		eap_type_gsmsim_state_waiting_for_challenge_response,
	};

	const eap_type_gsmsim_state_variable_e gsmsim_start_response_states_2[] =
	{
		eap_type_gsmsim_state_waiting_for_start_response,
		eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity,
		eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity,
		eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity,
	};

	if (verify_states(gsmsim_start_response_states_1, GSMSIM_STATE_COUNT(gsmsim_start_response_states_1)) == true)
#else
	if (m_state == eap_type_gsmsim_state_waiting_for_start_response
		|| m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity
		|| m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity
		|| m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity
		|| m_state == eap_type_gsmsim_state_waiting_for_challenge_response
		)
#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	{
#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
		if (verify_states(gsmsim_start_response_states_2, GSMSIM_STATE_COUNT(gsmsim_start_response_states_2)) == true)
#else
		if (m_state == eap_type_gsmsim_state_waiting_for_start_response
			|| m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity
			|| m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity
			|| m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity
			)
#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
		{
			if (received_gsmsim->get_identifier() != m_last_eap_identifier)
			{
				// Wrong EAP-Identifier in this state.
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: eap_type_gsmsim_c::handle_start_response_message(): ")
					 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
					 EAPL("in eap_type_gsmsim_state_variable_e %d=%s.\n"),
					 received_gsmsim->get_identifier(),
					 m_last_eap_identifier, 
					 m_state,
					 get_state_string()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
			}
		}
		else // if (m_state == eap_type_gsmsim_state_waiting_for_challenge_response)
		{
			// This might be retransmission response.
			if (received_gsmsim->get_identifier() != m_last_eap_identifier-1u)
			{
				// Wrong EAP-Identifier in this state.
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: eap_type_gsmsim_c::handle_start_response_message(): ")
					 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
					 EAPL("in eap_type_gsmsim_state_variable_e %d=%s.\n"),
					 received_gsmsim->get_identifier(),
					 m_last_eap_identifier-1u, 
					 m_state,
					 get_state_string()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
			}
		}


		// Checks the payloads existence.
		if (p_gsmsim_payloads->check_payloads(
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional,     // nonce_mt, not included in re-authentication
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // MAC
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ENCR_DATA
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional,    // IDENTITY
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // n_RANDs
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // PERMANENT_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // FULLAUTH_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ANY_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IV
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NOTIFICATION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // VERSION_LIST
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional,     // SELECTED_VERSION, not included in re-authentication
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be,  // CLIENT_ERROR_CODE
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be  // RESULT_IND
				) == true
			)
		{
			if (m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_permanent_identity)
			{
				if (p_gsmsim_payloads->get_IDENTITY_payload()->get_payload_included() == true)
				{
					// OK, NAI identity is included.
					// Identity must be IMSI. query_SIM_triplets() must decode identity.

					set_start_response_includes_identity(gsmsim_payload_AT_PERMANENT_ID_REQ);
				}
				else
				{
					// AT_IDENTITY is missing.
					EAP_TRACE_ERROR(
						m_am_tools, 
						TRACE_FLAGS_GSMSIM_ERROR, 
						(EAPL("ERROR: eap_type_gsmsim_c::handle_start_response_message(0x%08x), ")
						 EAPL("AT_IDENTITY is missing.\n"),
						 this));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}
			}
			else if (m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_full_auth_identity)
			{
				if (p_gsmsim_payloads->get_IDENTITY_payload()->get_payload_included() == true)
				{
					// OK, NAI identity is included.
					// Identity must be IMSI or pseudonym identity. query_SIM_triplets() must decode identity.

					set_start_response_includes_identity(gsmsim_payload_AT_FULLAUTH_ID_REQ);
				}
				else
				{
					// AT_IDENTITY is missing.
					EAP_TRACE_ERROR(
						m_am_tools, 
						TRACE_FLAGS_GSMSIM_ERROR, 
						(EAPL("ERROR: eap_type_gsmsim_c::handle_start_response_message(0x%08x), ")
						 EAPL("AT_IDENTITY is missing.\n"),
						 this));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}
			}			
			else if (m_state == eap_type_gsmsim_state_waiting_for_start_response_with_at_any_identity)
			{
				if (p_gsmsim_payloads->get_IDENTITY_payload()->get_payload_included() == true)
				{
					// OK, NAI identity is included.
					// Identity must be IMSI, pseudonym or re-authentication identity. query_SIM_triplets() must decode identity.

					set_start_response_includes_identity(gsmsim_payload_AT_ANY_ID_REQ);
				}
				else
				{
					// AT_IDENTITY is missing.
					EAP_TRACE_ERROR(
						m_am_tools, 
						TRACE_FLAGS_GSMSIM_ERROR, 
						(EAPL("ERROR: eap_type_gsmsim_c::handle_start_response_message(0x%08x), ")
						 EAPL("AT_IDENTITY is missing.\n"),
						 this));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}
			}
			else if (m_state == eap_type_gsmsim_state_waiting_for_challenge_response)
			{
				// This is re-transmission.
				if (p_gsmsim_payloads->get_IDENTITY_payload()->get_payload_included() == true)
				{
					if (m_start_response_includes_identity == gsmsim_payload_AT_PERMANENT_ID_REQ
						|| m_start_response_includes_identity == gsmsim_payload_AT_FULLAUTH_ID_REQ
						|| m_start_response_includes_identity == gsmsim_payload_AT_ANY_ID_REQ)
					{
						// OK, NAI identity is included.
					}
					else
					{
						// Illegal IDENTITY is included.
						EAP_TRACE_ERROR(
							m_am_tools, 
							TRACE_FLAGS_GSMSIM_ERROR, 
							(EAPL("ERROR: eap_type_gsmsim_c::handle_start_response_message(0x%08x), ")
							 EAPL("illegal AT_IDENTITY included.\n"),
							 this));
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
					}
				}
			}
			else
			{
				if (p_gsmsim_payloads->get_IDENTITY_payload()->get_payload_included() == true)
				{
					// Illegal IDENTITY is included.
					EAP_TRACE_ERROR(
						m_am_tools, 
						TRACE_FLAGS_GSMSIM_ERROR, 
						(EAPL("ERROR: eap_type_gsmsim_c::handle_start_response_message(0x%08x), ")
						 EAPL("illegal AT_IDENTITY included.\n"),
						 this));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}
			}


			if (p_gsmsim_payloads->get_NONCE_MT()->get_payload_included() == true)
			{
				// NOTE on re-authentication Start-message does not include NONCE_MT.
				eap_status_e local_status = m_nonce_mt.set_copy_of_buffer(
					p_gsmsim_payloads->get_NONCE_MT()->get_payload_buffer());
				if (local_status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, local_status);
				}
			}


			if (p_gsmsim_payloads->get_SELECTED_VERSION()->get_payload_included() == true)
			{
				// NOTE on re-authentication Start-message does not include SELECTED_VERSION.
				const eap_gsmsim_version selected_version
					= static_cast<eap_gsmsim_version>(p_gsmsim_payloads
					->get_SELECTED_VERSION()->get_original_header()->get_reserved());

				u16_t supported_versions[GSMSIM_LAST_VERSION];

				for (u32_t ind = 0u; ind < GSMSIM_LAST_VERSION; ind++)
				{
					supported_versions[ind] = eap_htons(static_cast<u16_t>(m_supported_versions[ind]));
				}

				{
					eap_status_e local_status = save_version(
						supported_versions,
						GSMSIM_LAST_VERSION,
						selected_version);
					if (local_status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, local_status);
					}
				}

				if (p_gsmsim_payloads->get_includes_unknown_attribute() != gsmsim_payload_NONE
					&& selected_version == GSMSIM_VERSION_1)
				{
					// EAP-SIM version 1 must NOT include unknown attributes.
					EAP_TRACE_ERROR(
						m_am_tools, 
						TRACE_FLAGS_GSMSIM_ERROR, 
						(EAPL("ERROR: eap_type_gsmsim_c::handle_start_response_message(0x%08x), illegal payload %d=0x%04x.\n"),
						this,
						p_gsmsim_payloads->get_includes_unknown_attribute(),
						p_gsmsim_payloads->get_includes_unknown_attribute()));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}
			}


			eap_type_gsmsim_identity_type identity_type = GSMSIM_IDENTITY_TYPE_NONE;
			bool identity_payload_was_included = false;
			const u8_t next_eap_identifier = static_cast<u8_t>(received_gsmsim->get_identifier()+1u);

			if (p_gsmsim_payloads->get_IDENTITY_payload()->get_payload_included() == true)
			{
				status = parse_identity(
					p_gsmsim_payloads->get_IDENTITY_payload()->get_data(p_gsmsim_payloads->get_IDENTITY_payload()->get_data_length()),
					p_gsmsim_payloads->get_IDENTITY_payload()->get_data_length());
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
					status = m_am_type_gsmsim->query_imsi_from_username(
						false,
						next_eap_identifier,
						&m_send_network_id,
						&m_identity,
						&m_IMSI,
						&identity_type,
						eap_type_gsmsim_complete_handle_start_response_message_completion);
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

						// Let handle_start_response_message_completion() handle error cases.
					}
					else // status == eap_status_ok
					{
						// The query_imsi_from_username() function call was synchronous.
						// We must call handle_start_response_message_completion().
					}
				}
				else
				{
					status = eap_status_illegal_eap_identity;
				}
			}


			status = handle_start_response_message_completion(
				next_eap_identifier,
				status,
				identity_type,
				identity_payload_was_included);


		}
		else
		{
			// Not correct GSMSIM-payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_start_response_message(4): ")
				 EAPL("Not correct GSMSIM-payloads are included in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else if (m_state == eap_type_gsmsim_state_pending_triplet_query)
	{
		// This is retransmission of EAP-Response/SIM/Start.
		// Triplet query is already initialized.
		// We will drop this message quietly.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eap_type_gsmsim_c::handle_start_response_message(5): ")
			 EAPL("Retransmission of EAP-Response/SIM/Start in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_start_response_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 received_gsmsim->get_subtype(),
			 received_gsmsim->get_subtype_string(),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_notification_response_message_reauthentication(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t /*gsmsim_packet_length*/,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: GSMSIM-type %10s, %s, state %2d=%s\n"),
		 EAPL("handle_notification_response_message_reauthentication"),
		 (m_is_client) ? EAPL("client") : EAPL("server"),
		 m_state,
		 get_state_string()
		 ));

	// The second most significant bit of the notification code is called
	// the Phase bit (P bit). It specifies at which phase of the EAP-SIM
	// exchange the notification can be used.
	if (get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code) == false)
	{
		// If the P bit is set to zero,
		// the notification can only be used after a successful EAP/SIM/
		// Challenge round in full authentication or a successful EAP/SIM/
		// Re-authentication round in reautentication. A re-authentication round
		// is considered successful only if the peer has successfully verified
		// AT_MAC and AT_COUNTER attributes, and does not include the
		// AT_COUNTER_TOO_SMALL attribute in EAP-Response/SIM/Re-authentication.

		// The AT_MAC attribute MUST be included if the P bit of the notification
		// code in AT_NOTIFICATION is set to zero, and MUST NOT be included in
		// cases when the P bit is set to one. The P bit is discussed in Section
		// 4.4.

		// Checks the payloads existence.
		if (p_gsmsim_payloads->check_payloads(
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_mt
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // MAC
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // ENCR_DATA
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IDENTITY
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // n_RANDs
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // PERMANENT_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // FULLAUTH_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ANY_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // IV
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NOTIFICATION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // VERSION_LIST
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // SELECTED_VERSION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be,  // CLIENT_ERROR_CODE
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be  // RESULT_IND
				) == true
			)
		{
			eap_variable_data_c orig_XKEY(m_am_tools);
			eap_variable_data_c orig_K_aut(m_am_tools);
			eap_variable_data_c orig_K_encr(m_am_tools);
			u32_t reauth_counter = 0u;

			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_gsmsim->query_reauth_parameters(
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

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_type_gsmsim_c::handle_notification_response_message_reauthentication(): %s, m_saved_reauth_counter %d.\n"),
				 (m_is_client == true ? "client": "server"),
				 reauth_counter));

			status = check_message_authentication_code(
				&orig_K_aut,
				p_gsmsim_payloads,
				received_gsmsim,
				received_gsmsim->get_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			bool authentication_ok = true;

			// Decrypt and parse encrypted payload.
			{
				gsmsim_payloads_c * const l_gsmsim_payloads = new gsmsim_payloads_c(m_am_tools);
				eap_automatic_variable_c<gsmsim_payloads_c> l_gsmsim_payloads_automatic(m_am_tools, l_gsmsim_payloads);

				if (l_gsmsim_payloads == 0
					|| l_gsmsim_payloads->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = decrypt_DATA_payload(
					p_gsmsim_payloads,
					&orig_K_encr);
				if (status != eap_status_ok)
				{
					restore_saved_previous_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				u32_t state_payload_buffer_length = p_gsmsim_payloads->get_ENCR_DATA()->get_data_length();
				const gsmsim_payload_AT_header_c gp_data_payload(
					m_am_tools,
					p_gsmsim_payloads->get_ENCR_DATA()->get_data(state_payload_buffer_length),
					state_payload_buffer_length);

				status = parse_gsmsim_payload(
					&gp_data_payload,
					&state_payload_buffer_length,
					l_gsmsim_payloads,
					received_gsmsim->get_subtype());
				if (status != eap_status_ok)
				{
					restore_saved_previous_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}


				if (l_gsmsim_payloads->get_COUNTER()->get_payload_included() == false)
				{
					restore_saved_previous_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
				}

				u32_t counter = l_gsmsim_payloads->get_COUNTER()->get_original_header()->get_reserved();

				if (counter == reauth_counter)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_notification_response_message_reauthentication(): ")
						EAPL("reauth counter %d OK, %d=%s.\n"),
						reauth_counter,
						m_state,
						get_state_string()));
				}
				else
				{
					EAP_TRACE_ERROR(
						m_am_tools, 
						TRACE_FLAGS_GSMSIM_ERROR, 
						(EAPL("ERROR: eap_type_gsmsim_c::handle_notification_response_message_reauthentication(): ")
						EAPL("reauth counter %d wrong, should be %d, %d=%s.\n"),
						counter,
						reauth_counter,
						m_state,
						get_state_string()));

					authentication_ok = false;
				}
			}

			// The most significant bit is called the Failure bit (F bit).
			// The F bit specifies whether the notification implies failure.
			if (authentication_ok == false
				|| get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == false)
			{
				// The code values with the F bit set to zero (code values 0...32767)
				// are used on unsuccessful cases.
				// The receipt of a notification code from this range implies failed EAP
				// exchange, so the peer can use the notification as a failure indication.

				m_last_eap_identifier = static_cast<u8_t>(m_last_eap_identifier+1u);
				set_state(eap_type_gsmsim_state_failure);

				// This will terminate session immediately.
				get_type_partner()->set_session_timeout(0UL);

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
			else //if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == true)
			{
				// The receipt of a notification code with the F bit set to one (values
				// 32768...65536) does not imply failure. Notification code 32768 has
				// been reserved as a general notification code to indicate successful
				// authentication.
				if (m_gsmsim_notification_code == eap_gsmsim_notification_F_set_no_P_user_authenticated)
				{
					// In order to use re-authentication, the client and the server need to
					// update re-authentication counter value.
					status = m_am_type_gsmsim->increase_reauth_counter();
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

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
			// Not correct GSMSIM-payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_notification_response_message_reauthentication(): ")
				 EAPL("Not correct GSMSIM-payloads are included ")
				 EAPL("in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else //if (get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code) == true)
	{
		// Checks the payloads existence.
		if (p_gsmsim_payloads->check_payloads(
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_mt
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // MAC
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ENCR_DATA
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IDENTITY
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // n_RANDs
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // PERMANENT_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // FULLAUTH_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ANY_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IV
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NOTIFICATION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // VERSION_LIST
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // SELECTED_VERSION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be,  // CLIENT_ERROR_CODE
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be  // RESULT_IND
				) == true
			)
		{
			// If the P bit is set to one, the notification can only by used before
			// the EAP/SIM/Challenge round in full authentication, or before the
			// EAP/SIM/Re-authentication round in reauthentication.

			// The most significant bit is called the Failure bit (F bit).
			// The F bit specifies whether the notification implies failure.
			if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == false)
			{
				// The code values with the F bit set to zero (code values 0...32767)
				// are used on unsuccessful cases.
				// The receipt of a notification code from this range implies failed EAP
				// exchange, so the peer can use the notification as a failure indication.
			}
			else //if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == true)
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
			// Not correct GSMSIM-payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_notification_response_message_reauthentication(): ")
				 EAPL("Not correct GSMSIM-payloads are included ")
				 EAPL("in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_notification_response_message_full_authentication(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t /*gsmsim_packet_length*/,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: GSMSIM-type %10s, %s, state %2d=%s\n"),
		 EAPL("handle_notification_response_message_full_authentication"),
		 (m_is_client) ? EAPL("client") : EAPL("server"),
		 m_state,
		 get_state_string()
		 ));

	// The second most significant bit of the notification code is called
	// the Phase bit (P bit). It specifies at which phase of the EAP-SIM
	// exchange the notification can be used.
	if (get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code) == false)
	{
		// If the P bit is set to zero,
		// the notification can only be used after a successful EAP/SIM/
		// Challenge round in full authentication or a successful EAP/SIM/
		// Re-authentication round in reautentication. A re-authentication round
		// is considered successful only if the peer has successfully verified
		// AT_MAC and AT_COUNTER attributes, and does not include the
		// AT_COUNTER_TOO_SMALL attribute in EAP-Response/SIM/Re-authentication.

		// The AT_MAC attribute MUST be included if the P bit of the notification
		// code in AT_NOTIFICATION is set to zero, and MUST NOT be included in
		// cases when the P bit is set to one. The P bit is discussed in Section
		// 4.4.

		// Checks the payloads existence.
		if (p_gsmsim_payloads->check_payloads(
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_mt
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // MAC
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ENCR_DATA
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IDENTITY
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // n_RANDs
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // PERMANENT_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // FULLAUTH_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ANY_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IV
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NOTIFICATION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // VERSION_LIST
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // SELECTED_VERSION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be,  // CLIENT_ERROR_CODE
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be  // RESULT_IND
				) == true
			)
		{
			eap_status_e status = check_message_authentication_code(
				&m_K_aut,
				p_gsmsim_payloads,
				received_gsmsim,
				received_gsmsim->get_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// The most significant bit is called the Failure bit (F bit).
			// The F bit specifies whether the notification implies failure.
			if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == false)
			{
				// The code values with the F bit set to zero (code values 0...32767)
				// are used on unsuccessful cases.
				// The receipt of a notification code from this range implies failed EAP
				// exchange, so the peer can use the notification as a failure indication.

				m_last_eap_identifier = static_cast<u8_t>(m_last_eap_identifier+1u);
				set_state(eap_type_gsmsim_state_failure);

				// This will terminate session immediately.
				get_type_partner()->set_session_timeout(0UL);

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
			else //if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == true)
			{
				// The receipt of a notification code with the F bit set to one (values
				// 32768...65536) does not imply failure. Notification code 32768 has
				// been reserved as a general notification code to indicate successful
				// authentication.
				if (m_gsmsim_notification_code == eap_gsmsim_notification_F_set_no_P_user_authenticated)
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
			// Not correct GSMSIM-payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_notification_response_message_full_authentication(): ")
				 EAPL("Not correct GSMSIM-payloads are included ")
				 EAPL("in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else //if (get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code) == true)
	{
		// Checks the payloads existence.
		if (p_gsmsim_payloads->check_payloads(
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_mt
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // MAC
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ENCR_DATA
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IDENTITY
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // n_RANDs
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // PERMANENT_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // FULLAUTH_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ANY_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IV
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NOTIFICATION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // VERSION_LIST
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // SELECTED_VERSION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be,  // CLIENT_ERROR_CODE
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be  // RESULT_IND
				) == true
			)
		{
			// If the P bit is set to one, the notification can only by used before
			// the EAP/SIM/Challenge round in full authentication, or before the
			// EAP/SIM/Re-authentication round in reauthentication.

			// The most significant bit is called the Failure bit (F bit).
			// The F bit specifies whether the notification implies failure.
			if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == false)
			{
				// The code values with the F bit set to zero (code values 0...32767)
				// are used on unsuccessful cases.
				// The receipt of a notification code from this range implies failed EAP
				// exchange, so the peer can use the notification as a failure indication.
			}
			else //if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == true)
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
			// Not correct GSMSIM-payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_notification_response_message_full_authentication(): ")
				 EAPL("Not correct GSMSIM-payloads are included ")
				 EAPL("in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_notification_response_message(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t gsmsim_packet_length,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	if (gsmsim_packet_length < received_gsmsim->get_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_notification_response_message(): ")
			 EAPL("gsmsim_packet_length < received_gsmsim->get_length().\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	eap_status_e status = eap_status_process_general_error;

	if (m_state == eap_type_gsmsim_state_waiting_for_notification_response_success
		|| m_state == eap_type_gsmsim_state_waiting_for_notification_response_failure)
	{
		// NOTE, this message is unauthenticated. Anybody could sent this message.

		if (received_gsmsim->get_identifier() != m_last_eap_identifier)
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_notification_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
				 EAPL("in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 received_gsmsim->get_identifier(), m_last_eap_identifier, 
				 m_state, get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}


		if (m_authentication_type == GSMSIM_AUTHENTICATION_TYPE_REAUTHENTICATION)
		{
			status = handle_notification_response_message_reauthentication(
				receive_network_id,
				received_gsmsim,
				gsmsim_packet_length,
				p_gsmsim_payloads);
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
				received_gsmsim,
				gsmsim_packet_length,
				p_gsmsim_payloads);
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
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_notification_response_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 received_gsmsim->get_subtype(),
			 received_gsmsim->get_subtype_string(),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::check_challenge_response_message(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t gsmsim_packet_length,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	// Checks the payloads existence.
	if (p_gsmsim_payloads->check_payloads(
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_mt
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // MAC
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ENCR_DATA
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IDENTITY
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // n_RANDs
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // PERMANENT_ID_REQ
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // FULLAUTH_ID_REQ
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ANY_ID_REQ
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IV
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NOTIFICATION
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // VERSION_LIST
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // SELECTED_VERSION
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // CLIENT_ERROR_CODE
			gsmsim_payloads_c::eap_gsmsim_payload_status_optional     // RESULT_IND
			) == true
		)
	{
		save_current_state();
		set_state(eap_type_gsmsim_state_analyses_challenge_response);

		status = m_saved_EAP_packet.set_buffer(
			received_gsmsim->get_header_buffer(gsmsim_packet_length),
			gsmsim_packet_length,
			false,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = check_message_authentication_code(
			&m_K_aut,
			p_gsmsim_payloads,
			received_gsmsim,
			gsmsim_packet_length);

		if (status == eap_status_ok)
		{
			// Ok, client successfully authenticated.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("Authentication OK.\n")));

			if (m_use_result_indication == false
				&& p_gsmsim_payloads->get_RESULT_IND()->get_payload_included() == true)
			{
				// ERROR: We did not send AT_RESULT_IND and client responds with it.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
			else if (m_use_result_indication == true
				&& p_gsmsim_payloads->get_RESULT_IND()->get_payload_included() == false)
			{
				// Client does not expect result indication.
				m_use_result_indication = false;
			}

			// Here we swap the addresses.
			eap_am_network_id_c send_network_id(m_am_tools,
				receive_network_id->get_destination_id(),
				receive_network_id->get_source_id(),
				receive_network_id->get_type());

			if (m_master_session_key.get_is_valid_data() == false
				|| m_master_session_key.get_data_length() == 0u)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
			}

			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_gsmsim->store_reauth_parameters(
				&m_XKEY,
				&m_K_aut,
				&m_K_encr,
				EAP_TYPE_GSMSIM_INITIAL_REAUTH_COUNTER);
			if (status != eap_status_ok)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (m_use_result_indication == true)
			{
				// Send EAP-Request/SIM/Notification.

				eap_type_gsmsim_state_variable_e next_state = eap_type_gsmsim_state_failure;

				if (m_randomly_fail_successfull_authentication == true
					&& random_selection() == true)
				{
					m_gsmsim_notification_code = eap_gsmsim_notification_no_F_P_set_general_failure;
					next_state = eap_type_gsmsim_state_waiting_for_notification_response_failure;
				}
				else
				{
					m_gsmsim_notification_code = eap_gsmsim_notification_F_set_no_P_user_authenticated;
					next_state = eap_type_gsmsim_state_waiting_for_notification_response_success;
				}

				status = send_gsmsim_notification_request(
					m_gsmsim_notification_code,
					false);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				set_state(next_state);
			}
			else
			{
				if (m_randomly_fail_successfull_authentication == true
					&& random_selection() == true)
				{
					// This is for testing.
					m_gsmsim_notification_code = eap_gsmsim_notification_no_F_no_P_general_failure;

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
		// Not correct GSMSIM-payloads are included.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::check_challenge_response_message(6): ")
			 EAPL("Not correct GSMSIM-payloads are included in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_challenge_response_message(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t gsmsim_packet_length,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	if (m_state == eap_type_gsmsim_state_waiting_for_challenge_response)
	{
		if (received_gsmsim->get_identifier() != m_last_eap_identifier)
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_challenge_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
				 EAPL("in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 received_gsmsim->get_identifier(), m_last_eap_identifier, 
				 m_state, get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}

		status = check_challenge_response_message(
			receive_network_id,
			received_gsmsim,
			gsmsim_packet_length,
			p_gsmsim_payloads);
	}
	else if (m_state == eap_type_gsmsim_state_success)
	{
		if (received_gsmsim->get_identifier() != m_last_eap_identifier-1u)
		{
			// Wrong EAP-Identifier in this state.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_challenge_response_message(): ")
				 EAPL("EAP-Identifier 0x%02x is wrong (0x%02x is correct) ")
				 EAPL("in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 received_gsmsim->get_identifier(),
				 m_last_eap_identifier-1u, 
				 m_state,
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}

		status = check_challenge_response_message(
			receive_network_id,
			received_gsmsim,
			gsmsim_packet_length,
			p_gsmsim_payloads);
	}
	else if (m_state == eap_type_gsmsim_state_pending_triplet_query)
	{
		// This is re-transmitted EAP-Response/SIM/Challenge.
		// We dischard it quietly.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eap_type_gsmsim_c::handle_challenge_response_message(): ")
			 EAPL("Re-transmitted message %d=%s dropped in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 received_gsmsim->get_subtype(),
			 received_gsmsim->get_subtype_string(),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_challenge_response_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 received_gsmsim->get_subtype(),
			 received_gsmsim->get_subtype_string(),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_reauthentication_response_message(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t gsmsim_packet_length,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_type_gsmsim_c::handle_reauthentication_response_message(): %s, m_identity_type %d=%s, requested identity payload is %d=%s.\n"),
		 (m_is_client == true ? "client": "server"),
		 m_identity_type,
		 get_identity_string(m_identity_type),
		 m_start_response_includes_identity,
		 gsmsim_payload_AT_header_c::get_payload_AT_string(m_start_response_includes_identity)));

	if (m_state == eap_type_gsmsim_state_waiting_for_reauth_response)
	{
		// This could be first or retransmission request.

		// Checks the payloads existence.
		if (p_gsmsim_payloads->check_payloads(
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_mt
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // MAC
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // ENCR_DATA
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IDENTITY
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // n_RANDs
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // PERMANENT_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // FULLAUTH_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ANY_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // IV
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NOTIFICATION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // VERSION_LIST
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // SELECTED_VERSION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // CLIENT_ERROR_CODE
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional     // RESULT_IND
				) == true
			)
		{

			m_last_eap_identifier = received_gsmsim->get_identifier();

			save_current_state();
			set_state(eap_type_gsmsim_state_analyses_reauthentication_response);

			// - - - - - - - - - - - - - - - - - - - - - - - -

			eap_variable_data_c orig_XKEY(m_am_tools);
			eap_variable_data_c orig_K_aut(m_am_tools);
			eap_variable_data_c orig_K_encr(m_am_tools);
			u32_t reauth_counter = 0u;
			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_gsmsim->query_reauth_parameters(
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

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_type_gsmsim_c::handle_reauthentication_response_message(): %s, m_saved_reauth_counter %d.\n"),
				 (m_is_client == true ? "client": "server"),
				 reauth_counter));

			status = check_message_authentication_code(
				&orig_K_aut,
				p_gsmsim_payloads,
				received_gsmsim,
				gsmsim_packet_length);
			if (status != eap_status_ok)
			{
				restore_saved_previous_state();

				eap_status_string_c status_string;
				EAP_UNREFERENCED_PARAMETER(status_string);
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: Re-authentication failed: %s, state %s\n"),
					 status_string.get_status_string(status),
					 get_state_string()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Decrypt and parse encrypted payload.
			if (p_gsmsim_payloads->get_IV()->get_payload_included() == true
			|| p_gsmsim_payloads->get_ENCR_DATA()->get_payload_included() == true)
			{
				if (p_gsmsim_payloads->get_IV()->get_payload_included() == true
				&& p_gsmsim_payloads->get_ENCR_DATA()->get_payload_included() == true
				&& p_gsmsim_payloads->get_MAC()->get_payload_included() == true)
				{
					if (m_use_result_indication == false
						&& p_gsmsim_payloads->get_RESULT_IND()->get_payload_included() == true)
					{
						// ERROR: We did not send AT_RESULT_IND and client responds with it.
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
					}
					else if (m_use_result_indication == true
						&& p_gsmsim_payloads->get_RESULT_IND()->get_payload_included() == false)
					{
						// Client does not expect result indication.
						m_use_result_indication = false;
					}

					gsmsim_payloads_c * const l_gsmsim_payloads = new gsmsim_payloads_c(m_am_tools);
					eap_automatic_variable_c<gsmsim_payloads_c> l_gsmsim_payloads_automatic(m_am_tools, l_gsmsim_payloads);

					if (l_gsmsim_payloads == 0
						|| l_gsmsim_payloads->get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					status = decrypt_DATA_payload(
						p_gsmsim_payloads,
						&orig_K_encr);
					if (status != eap_status_ok)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					u32_t state_payload_buffer_length = p_gsmsim_payloads->get_ENCR_DATA()->get_data_length();

					const gsmsim_payload_AT_header_c gp_data_payload(
						m_am_tools,
						p_gsmsim_payloads->get_ENCR_DATA()->get_data(state_payload_buffer_length),
						state_payload_buffer_length);

					if (gp_data_payload.get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
					}

					status = parse_gsmsim_payload(
						&gp_data_payload,
						&state_payload_buffer_length,
						l_gsmsim_payloads,
						received_gsmsim->get_subtype());
					if (status != eap_status_ok)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					if (l_gsmsim_payloads->get_counter_too_small()->get_payload_included() == true)
					{
						// When the client detects that the
						// counter value is not fresh, it includes the AT_COUNTER_TOO_SMALL
						// attribute in EAP-Response/SIM/Re-authentication. This attribute
						// doesn't contain any data but it is a request for the server to
						// initiate full authentication.

						// The full authentication must follow.
						m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;
						set_start_response_includes_identity(gsmsim_payload_NONE);

						bool pseudonym_decode_failed = false;

						if (m_identity.get_is_valid_data() == false
							|| (m_identity_type != GSMSIM_IDENTITY_TYPE_IMSI_ID
								&& m_identity_type != GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID
								&& m_identity_type != GSMSIM_IDENTITY_TYPE_RE_AUTH_ID))
						{
							// We do not have any identity of the client.
							set_start_response_includes_identity(gsmsim_payload_AT_FULLAUTH_ID_REQ);
							set_identity_type(GSMSIM_IDENTITY_TYPE_NONE);
							(void) m_identity.reset();
							pseudonym_decode_failed = true;
						}

						status = send_start_request_message(
							pseudonym_decode_failed,
							static_cast<u8_t>(received_gsmsim->get_identifier()+1u));
						if (status == eap_status_ok)
						{
							m_last_eap_identifier = static_cast<u8_t>(received_gsmsim->get_identifier()+1u);
						}

						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}


					if (l_gsmsim_payloads->get_COUNTER()->get_payload_included() == false)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
					}

					u32_t counter = l_gsmsim_payloads->get_COUNTER()->get_original_header()->get_reserved();

					if (counter != reauth_counter)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
					}

					// OK, client re-authenticates correctly.

					if (m_use_result_indication == true)
					{
						// Send EAP-Request/SIM/Notification.
						m_gsmsim_notification_code = eap_gsmsim_notification_F_set_no_P_user_authenticated;

						status = send_gsmsim_notification_request(
							m_gsmsim_notification_code,
							true);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						set_state(eap_type_gsmsim_state_waiting_for_notification_response_success);

						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
							(EAPL("EAP_type_GSMSIM: %s, re-authentication OK, waits result indication\n"),
							 (m_is_client == true) ? "client": "server"));
					}
					else
					{
						if (m_randomly_fail_successfull_authentication == true
							&& random_selection() == true)
						{
							// This is for testing.
							m_gsmsim_notification_code = eap_gsmsim_notification_no_F_no_P_general_failure;

							status = initialize_notification_message();
						}
						else
						{
							// In order to use re-authentication, the client and the server need to
							// update re-authentication counter value.
							status = m_am_type_gsmsim->increase_reauth_counter();
							if (status != eap_status_ok)
							{
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}

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
				// Not correct GSMSIM-payloads are included.
				restore_saved_previous_state();
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: eap_type_gsmsim_c::handle_reauthentication_response_message(6): ")
					 EAPL("Not correct GSMSIM-payloads are included in eap_type_gsmsim_state_variable_e %d=%s.\n"),
					 m_state,
					 get_state_string()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}
		}
		else
		{
			// Not correct GSMSIM-payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_reauthentication_response_message(6): ")
				 EAPL("Not correct GSMSIM-payloads are included in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_reauthentication_response_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 received_gsmsim->get_subtype(),
			 received_gsmsim->get_subtype_string(),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_client_error_response_message(
	const eap_am_network_id_c * const /* receive_network_id */,
	gsmsim_header_c * const received_gsmsim,
	const u32_t gsmsim_packet_length,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	EAP_UNREFERENCED_PARAMETER(gsmsim_packet_length);
	EAP_UNREFERENCED_PARAMETER(received_gsmsim);

	eap_status_e status = eap_status_process_general_error;

	// This could be first, retransmission request
	// or some nasty attacker to make denial of service.

	// Checks the payloads existence.
	if (p_gsmsim_payloads->check_payloads(
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_mt
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // MAC
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ENCR_DATA
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IDENTITY
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // n_RANDs
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // PERMANENT_ID_REQ
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // FULLAUTH_ID_REQ
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ANY_ID_REQ
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be,     // IV
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NOTIFICATION
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // VERSION_LIST
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // SELECTED_VERSION
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // CLIENT_ERROR_CODE
			gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be  // RESULT_IND
			) == true
		)
	{
		eap_status_e client_status = eap_status_process_general_error;

		/** @{ Add some use for the Client Error Code. } */
		eap_gsmsim_client_error_code_e client_error_code
			= static_cast<eap_gsmsim_client_error_code_e>(p_gsmsim_payloads->get_CLIENT_ERROR_CODE()
				->get_original_header()->get_reserved());

		EAP_UNREFERENCED_PARAMETER(client_error_code);
		
		status = initialize_error_message(
			client_status);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		// Not correct GSMSIM-payloads are included.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_client_error_response_message(): ")
			 EAPL("Not correct GSMSIM-payloads are included in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::check_NAI(
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
			if (character != GSMSIM_NAI_AT_BYTE)
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
		else if (character == GSMSIM_NAI_AT_BYTE)
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
			|| character == GSMSIM_NAI_AT_BYTE
			|| character == ' ' // space
			|| character <= 0x1f // Ctrl
			|| character >= 0x7f) // extented characters
		{
			// Illegal character.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: Illegal NAI, includes illegal character 0x%02x=%c.\n"),
				 character,
				 character));
			EAP_TRACE_DATA_ERROR(
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
				get_nai_realm()->get_data(),
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
				get_nai_realm()->get_data(),
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::parse_identity(
	const u8_t * const identity,
	const u32_t identity_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	if (identity_length < 1u)
	{
		status = m_identity.init(0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_NAI.init(0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	const u8_t *at_character = reinterpret_cast<const u8_t *>(m_am_tools->memchr(
		identity,
		GSMSIM_AT_CHARACTER[0],
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

	status = m_identity.set_copy_of_buffer(
		identity, // Note we do store whole IMSI or pseudonym including possible prefix.
		username_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_NAI.set_copy_of_buffer(identity, identity_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)



// End.
