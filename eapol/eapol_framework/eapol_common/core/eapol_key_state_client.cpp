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
* %version: 57.1.6 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 49 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eapol_key_state.h"
#include "eapol_key_header.h"
#include "eap_crypto_api.h"
#include "abs_eap_am_mutex.h"
#include "eap_state_notification.h"
#include "eap_automatic_variable.h"
#include "eapol_rsna_key_data_gtk_header.h"
#include "eap_buffer.h"
#include "eapol_rsna_key_data_payloads.h"
#include "abs_eapol_key_state.h"
#include "eapol_rc4_key_header.h"
#include "eapol_key_state_string.h"

//--------------------------------------------------
//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::create_4_way_handshake_message_2(
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t eapol_header_offset,
	u32_t * const data_length,
	u32_t * const buffer_length,
	const u64_t received_key_replay_counter,
	const eapol_protocol_version_e received_eapol_version,
	const eapol_key_descriptor_type_e received_key_descriptor_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::create_4_way_handshake_message_2()\n"),
		(m_is_client == true ? "client": "server")));

	// Only client (Supplicant) could create 4-Way Handshake message 2.
	EAP_ASSERT_ALWAYS(m_is_client == true);

	if (sent_packet == 0
		|| sent_packet->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_SNonce.get_is_valid_data() == false
		|| m_SNonce.get_data_length() != eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::create_4_way_handshake_message_2(): ")
			 EAPL("m_SNonce is missing or corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_supplicant_RSNA_IE.get_is_valid_data() == false
		|| m_supplicant_RSNA_IE.get_data_length() == 0ul
		|| m_supplicant_RSNA_IE.get_data_length()
		> eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_DATA_MAXIMUM_RSN_IE_SIZE)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::create_4_way_handshake_message_2(): ")
			 EAPL("m_supplicant_RSNA_IE is missing or corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	u32_t eapol_key_data_length
		= eapol_RSNA_key_header_c::get_header_length()
		+ m_supplicant_RSNA_IE.get_data_length();

	*buffer_length
		= eapol_header_offset
		+ eapol_key_data_length;

	status = sent_packet->set_buffer_length(
		*buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	sent_packet->set_data_length(
		sent_packet->get_buffer_length());

	eapol_RSNA_key_header_c eapol_key_message(
		m_am_tools,
		get_is_RSNA(),
		get_is_WPXM(),
		sent_packet->get_data_offset(eapol_header_offset, eapol_key_data_length),
		sent_packet->get_data_length());

	if (eapol_key_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	status = eapol_key_message.reset_header(
		0ul,
		m_authentication_type,
		m_eapol_pairwise_cipher,
		received_key_replay_counter,
		true, // Pairwise key type bit is on.
		false, // Install bit is NOT set.
		false, // Key Ack bit is NOT set.
		true, // Key MIC bit is on.
		false, // Secure bit is NOT set.
		false, // Error bit is NOT set.
		false, // Request bit is NOT set.
		false, // STAKey bit is NOT set.
		false, // Encrypted Key Data bit is NOT set.
		received_eapol_version,
		received_key_descriptor_type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	{
		// Add SNonce.
		u8_t * const nonce_field = eapol_key_message.get_key_NONCE();
		if (nonce_field == 0
			|| m_SNonce.get_data_length() != eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		m_am_tools->memmove(
			nonce_field,
			m_SNonce.get_data(eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE),
			eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE);
	}


	u32_t total_key_data_length(0ul);

	status = add_RSN_IE_payload(
		&eapol_key_message,
		&m_supplicant_RSNA_IE,
		&total_key_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (total_key_data_length > 0xffff)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
	}

	status = eapol_key_message.set_key_data_length(
		static_cast<u16_t>(total_key_data_length));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	*data_length
		= eapol_key_message.get_header_length()
		+ eapol_key_message.get_key_data_length();

	status = eapol_key_message.set_eapol_packet_body_length(
		static_cast<u16_t>(*data_length - eapol_header_base_c::get_header_length()));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const eap_variable_data_c * confirmation_key = &m_confirmation_KCK;
#if defined(EAP_USE_WPXM)
	if (get_is_WPXM() == true)
	{
		confirmation_key = &m_WPXM_WPXK1;
	}
#endif //#if defined(EAP_USE_WPXM)

	status = create_key_mic(
		&eapol_key_message,
		confirmation_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if defined(USE_EAPOL_KEY_TEST_FAILURES)
	if (m_create_key_failure == eapol_key_state_wait_4_way_handshake_message_1)
	{
		m_create_key_failure = eapol_key_state_wait_4_way_handshake_message_3;

		status = eapol_key_message.zero_key_MIC(m_am_tools);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: EAPOL_KEY: %s: error generated in eapol_key_state_c::create_4_way_handshake_message_2()\n"),
			 (m_is_client == true ? "client": "server")));
	}
#endif //#if defined(USE_EAPOL_KEY_TEST_FAILURES)

	sent_packet->set_data_length(
		eapol_header_offset + *data_length);

	TRACE_EAPOL_KEY_MESSAGE(
		"Send 4-Way Handshake Message 2",
		&eapol_key_message);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::create_4_way_handshake_message_4(
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t eapol_header_offset,
	u32_t * const data_length,
	u32_t * const buffer_length,
	const u64_t received_key_replay_counter,
	const bool received_secure_bit,
	const eapol_protocol_version_e received_eapol_version,
	const eapol_key_descriptor_type_e received_key_descriptor_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::create_4_way_handshake_message_4()\n"),
		(m_is_client == true ? "client": "server")));

	// Only client (Supplicant) could create 4-Way Handshake message 4.
	EAP_ASSERT_ALWAYS(m_is_client == true);

	if (sent_packet == 0
		|| sent_packet->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t eapol_key_data_length
		= eapol_RSNA_key_header_c::get_header_length();

	*buffer_length
		= eapol_header_offset
		+ eapol_key_data_length;

	status = sent_packet->set_buffer_length(
		*buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	sent_packet->set_data_length(
		sent_packet->get_buffer_length());

	eapol_RSNA_key_header_c eapol_key_message(
		m_am_tools,
		get_is_RSNA(),
		get_is_WPXM(),
		sent_packet->get_data_offset(eapol_header_offset, eapol_key_data_length),
		sent_packet->get_data_length());

	if (eapol_key_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	bool secure_bit = received_secure_bit; // Secure bit is the same as in the received WPA 4-Way Handshake message 3.

	if (get_is_RSNA() == true)
	{
		secure_bit = true; // Secure bit is on in RSNA.
	}

	status = eapol_key_message.reset_header(
		0ul,
		m_authentication_type,
		m_eapol_pairwise_cipher,
		received_key_replay_counter,
		true, // Pairwise key type bit is on.
		false, // Install bit is NOT set.
		false, // Key Ack bit is NOT set.
		true, // Key MIC bit is on.
		secure_bit,
		false, // Error bit is NOT set.
		false, // Request bit is NOT set.
		false, // STAKey bit is NOT set.
		false, // Encrypted Key Data bit is NOT set.
		received_eapol_version,
		received_key_descriptor_type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = eapol_key_message.set_key_data_length(0ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	*data_length
		= eapol_key_message.get_header_length()
		+ eapol_key_message.get_key_data_length();

	status = eapol_key_message.set_eapol_packet_body_length(
		static_cast<u16_t>(*data_length - eapol_header_base_c::get_header_length()));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = create_key_mic(
		&eapol_key_message,
		&m_confirmation_KCK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if defined(USE_EAPOL_KEY_TEST_FAILURES)
	if (m_create_key_failure == eapol_key_state_wait_4_way_handshake_message_3)
	{
		m_create_key_failure = eapol_key_state_4_way_handshake_successfull;

		status = eapol_key_message.zero_key_MIC(m_am_tools);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: EAPOL_KEY: %s: error generated in eapol_key_state_c::create_4_way_handshake_message_4()\n"),
			 (m_is_client == true ? "client": "server")));
	}
#endif //#if defined(USE_EAPOL_KEY_TEST_FAILURES)

	sent_packet->set_data_length(
		eapol_header_offset + *data_length);

	TRACE_EAPOL_KEY_MESSAGE(
		"Send 4-Way Handshake Message 4",
		&eapol_key_message);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_4_way_handshake_message_1(
	const eap_am_network_id_c * const receive_network_id,
	eapol_RSNA_key_header_c * const eapol_key_message,
	const u32_t /* packet_length */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::process_4_way_handshake_message_1(): eapol_key_descriptor_type = %s = 0x%02x\n"),
		(m_is_client == true ? "client": "server"),
		eapol_key_state_string_c::get_eapol_key_descriptor_type_string(eapol_key_message->get_key_descriptor_type()),
		eapol_key_message->get_key_descriptor_type()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_key_state_c::process_4_way_handshake_message_1()");

	// Only client (supplicant) could receive 4-Way Handshake message 1.
	EAP_ASSERT_ALWAYS(m_is_client == true);

#if 0
	if (m_eapol_key_handshake_type == eapol_key_handshake_type_none)
	{
		// 4-Way Handshake started again.
		m_eapol_key_handshake_type = eapol_key_handshake_type_4_way_handshake;
		set_eapol_key_state(eapol_key_state_wait_4_way_handshake_message_1);

		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: %s: process_4_way_handshake_message_1(): 4-Way Handshake restarted.\n"),
			(m_is_client == true ? "client": "server")));
	}
#endif

	if (get_eapol_key_state() != eapol_key_state_wait_4_way_handshake_message_1
		&& get_eapol_key_state() != eapol_key_state_wait_4_way_handshake_message_3
		&& get_eapol_key_state() != eapol_key_state_4_way_handshake_successfull
		&& get_eapol_key_state() != eapol_key_state_group_key_handshake_successfull
		&& get_eapol_key_state() != eapol_key_state_preauthenticated
#if defined(EAP_USE_WPXM)
		&& get_eapol_key_state() != eapol_key_state_wpxm_reassociation_finished_successfull
#endif //#if defined(EAP_USE_WPXM)
		)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: process_4_way_handshake_message_1(): wrong state %s\n"),
			(m_is_client == true ? "client": "server"),
			eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state())));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	// Some APs seems to behave incorrectly and
	// fills the IV field with non-zero stuff. For this reason don't verify the field to be 0.

	status = verify_field_is_zero(
		eapol_key_message->get_key_RSC(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RSC_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	/**
	 * @{ In 802.11i D3.0 this field is Key ID instead of STA MAC address. }
	 */
	status = verify_field_is_zero(
		eapol_key_message->get_key_STA_MAC_address(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_STA_MAC_ADDRESS_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_allow_non_zero_mic_and_reserved_in_message_1 == false)
	{
		status = verify_field_is_zero(
			eapol_key_message->get_key_reserved(),
			eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RESERVED_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = verify_field_is_zero(
			eapol_key_message->get_key_MIC(),
			eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_MIC_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// Save ANonce.
	const u8_t * const ANonce = eapol_key_message->get_key_NONCE();
	if (ANonce == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	status = m_ANonce.set_copy_of_buffer(
		ANonce,
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	if (get_is_RSNA() == true)
	{
		u32_t received_buffer_length = eapol_key_message->get_key_data_length();

		if (m_allow_missing_PMKID_in_message_1 == false
			&& received_buffer_length == 0u)
		{
			// No payload in this packet.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
		}
		
		if (received_buffer_length > 0u)
		{
			if (received_buffer_length > eapol_key_message->get_header_buffer_length()
				|| eapol_key_message->get_key_data(received_buffer_length) == 0)
			{
				// Not enough payload in this packet.
				return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
			}

			eapol_rsna_key_data_payloads_c key_data_payloads(
				m_am_tools,
				get_is_RSNA(),
				get_is_WPXM());

			eapol_rsna_key_data_header_c key_data(
				m_am_tools,
				get_is_RSNA(),
				get_is_WPXM(),
				eapol_key_message->get_key_data(received_buffer_length),
				received_buffer_length);
			if (key_data.get_is_valid() == false)
			{
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
					(EAPL("ERROR: EAPOL_KEY: No EAPOL-Key data payloads.\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = key_data.check_header();
			if (status != eap_status_ok)
			{
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
					(EAPL("ERROR: EAPOL_KEY: EAPOL-Key data payload header corrupted.\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = parse_key_data(
				eapol_key_message->get_key_descriptor_type(),
				&key_data,
				&received_buffer_length,
				&key_data_payloads,
				eapol_key_state_wait_4_way_handshake_message_1,
				eapol_key_message->get_key_information_key_descriptor_version());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_e PMKID_existence(
				eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_be);

			if (m_allow_missing_PMKID_in_message_1 == true)
			{
				PMKID_existence = eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_optional;
			}

			// Check the valid payload is included.
			if (false == key_data_payloads.check_payloads(
				eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_not_be, // key_id_and_group_key
				eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_not_be, // STAKey
				PMKID_existence, // PMKID
				eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_not_be // One or more RSN IE
				))
			{
				// Not correct EAPOL Key Data payloads are included.
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_1(): ")
					 EAPL("Not correct EAPOL Key Data payloads are included.\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			if (key_data_payloads.get_PMKID()->get_is_valid_data() == true)
			{
				// We do have the expected PMKID, save it.
				status = get_received_PMKID()->set_copy_of_buffer(key_data_payloads.get_PMKID());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				// We do not get mandatory PMKID.
				// Access point is broken and cached PMKSA is not used.
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("WARNING: EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_1(): ")
					 EAPL("Not correct EAPOL Key Data payloads are included, mandatory PMKID is missing.\n")));
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_1(): ")
				 EAPL("Not correct EAPOL Key Data payloads are included, mandatory PMKID is missing.\n")));
		}
	}

#if defined(EAP_USE_WPXM)
	if (get_is_WPXM() == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_1(): ")
			 EAPL("m_WPXM_WPXC=%d.\n"),
			 m_WPXM_WPXC));

		status = derive_WPXM_WPXK1_WPXK2();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = derive_WPXM_PTK(eapol_key_constant_wpxm_initial_wpxc_counter_value);
	}
	else
#endif //#if defined(EAP_USE_WPXM)
	{
		status = derive_PTK();
	}

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_buf_chain_wr_c sent_packet(
		eap_write_buffer,
		m_am_tools);

	if (sent_packet.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t send_data_length = 0ul;
	u32_t send_buffer_length = 0ul;

	status = create_4_way_handshake_message_2(
		&sent_packet,
		m_eapol_header_offset,
		&send_data_length,
		&send_buffer_length,
		eapol_key_message->get_key_replay_counter(),
		eapol_key_message->get_eapol_protocol_version(),
		eapol_key_message->get_key_descriptor_type());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = packet_send(
		&m_send_network_id,
		&sent_packet,
		m_eapol_header_offset,
		send_data_length,
		send_buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	cancel_4_way_handshake_start_timeout();

	set_eapol_key_state(eapol_key_state_wait_4_way_handshake_message_3);

	m_eapol_key_handshake_type = eapol_key_handshake_type_4_way_handshake;

	set_key_reply_counter(eapol_key_message->get_key_replay_counter());

	status = init_handshake_timeout(m_handshake_timeout);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		// This is notification to eapol_core_c object.
		// 4-Way Handshake started successfully.
		eap_state_notification_c * notification = new eap_state_notification_c(
			m_am_tools,
			&m_send_network_id,
			m_is_client,
			eap_state_notification_generic,
			eap_protocol_layer_eapol_key,
			eapol_key_handshake_type_4_way_handshake,
			eapol_key_state_4_way_handshake_running,
			eapol_key_state_4_way_handshake_running,
			0ul,
			false);
		if (notification == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		m_key_state_partner->state_notification(notification);

		delete notification;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_4_way_handshake_message_3_payloads_a(
	const eap_am_network_id_c * const receive_network_id,
	eapol_RSNA_key_header_c * const eapol_key_message,
	const u32_t packet_length,
	bool * const group_key_received)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

	eap_status_e status = eap_status_process_general_error;

	// Only client (supplicant) could receive 4-Way Handshake message 3.
	EAP_ASSERT_ALWAYS(m_is_client == true);


	{
		u32_t received_buffer_length = eapol_key_message->get_key_data_length();

		if (received_buffer_length > eapol_key_message->get_header_buffer_length()
			|| eapol_key_message->get_key_data(received_buffer_length) == 0)
		{
			// Not enough payload in this packet.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
		}

		eapol_rsna_key_data_payloads_c key_data_payloads(
			m_am_tools,
			get_is_RSNA(),
			get_is_WPXM());

		eapol_rsna_key_data_header_c key_data(
			m_am_tools,
			get_is_RSNA(),
			get_is_WPXM(),
			eapol_key_message->get_key_data(received_buffer_length),
			packet_length);
		if (key_data.get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
				(EAPL("ERROR: EAPOL_KEY: No EAPOL-Key data payloads.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = key_data.check_header();
		if (status != eap_status_ok)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
				(EAPL("ERROR: EAPOL_KEY: EAPOL-Key data payload header corrupted.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = parse_key_data(
			eapol_key_message->get_key_descriptor_type(),
			&key_data,
			&received_buffer_length,
			&key_data_payloads,
			eapol_key_state_wait_4_way_handshake_message_3,
			eapol_key_message->get_key_information_key_descriptor_version());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Check the valid payload is included.
		if (false == key_data_payloads.check_payloads(
			eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_optional, // key_id_and_group_key
			eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_not_be, // STAKey
			eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_not_be, // PMKID
			eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_be // One or more RSN IE
			))
		{
			// Not correct EAPOL Key Data payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
				(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_3_payloads_a(): ")
				 EAPL("Not correct EAPOL Key Data payloads are included.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// We do have the expected RSN IE, compare it.
		if (get_authenticator_RSNA_IE()->compare(
				key_data_payloads.get_RSN_IE()->get_object(0ul)) != 0)
		{
			// Illegal RSN IE.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
				(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_3_payloads_a(): ")
				 EAPL("Not correct RSN IE received.\n")));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
				(EAPL("   Local RSN IE"),
				get_authenticator_RSNA_IE()->get_data(
					get_authenticator_RSNA_IE()->get_data_length()),
				get_authenticator_RSNA_IE()->get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
				(EAPL("Received RSN IE"),
				key_data_payloads.get_RSN_IE()->get_object(0ul)->get_data(
					key_data_payloads.get_RSN_IE()->get_object(0ul)->get_data_length()),
				key_data_payloads.get_RSN_IE()->get_object(0ul)->get_data_length()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// Check the optional second RSN IE.
		if (key_data_payloads.get_RSN_IE()->get_object_count() > 1ul
			&& key_data_payloads.get_RSN_IE()->get_object(1ul) != 0
			&& key_data_payloads.get_RSN_IE()->get_object(1ul)->get_is_valid_data() == true)
		{
			// If a second RSN IE is provided in the message, the Supplicant shall use
			// the unicast cipher suite specified in the second RSN IE or deauthenticate.
			status = get_unicast_cipher_suite_RSNA_IE()->set_copy_of_buffer(
				key_data_payloads.get_RSN_IE()->get_object(1ul));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}


		if (get_is_RSNA() == true
			|| (get_is_WPXM() == true
				&& eapol_key_message->get_key_descriptor_type() == eapol_key_descriptor_type_RSNA))
		{
			if (m_eapol_group_cipher != eapol_RSNA_key_header_c::eapol_RSNA_cipher_none
			&& key_data_payloads.get_group_key()->get_is_valid_data() == true)
			{
				// We do have the expected GTK, save it.
				status = m_group_GTK.set_copy_of_buffer(
					key_data_payloads.get_group_key());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				m_group_GTK_ID = key_data_payloads.get_group_key_id();
				m_group_GTK_Tx_bit = key_data_payloads.get_group_key_tx();

				*group_key_received = true;
			}
			else if (m_eapol_group_cipher != eapol_RSNA_key_header_c::eapol_RSNA_cipher_none
				&& key_data_payloads.get_group_key()->get_is_valid_data() == false
				&& eapol_key_message->get_key_descriptor_type() == eapol_key_descriptor_type_RSNA)
			{
				// ERROR, required GTK is missing.
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_3_payloads_a(): ")
					 EAPL("Required GTK is missing.\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}
			else if (m_eapol_group_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_none
				&& key_data_payloads.get_group_key()->get_is_valid_data() == true)
			{
				// ERROR, unexpected GTK received.
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_3_payloads_a(): ")
					 EAPL("Unexpected GTK received.\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}
		}
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_4_way_handshake_message_3_payloads_b(
	const eap_am_network_id_c * const receive_network_id,
	eapol_RSNA_key_header_c * const eapol_key_message,
	const u32_t /* packet_length */,
	const bool group_key_received)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

	eap_status_e status = eap_status_process_general_error;

	// Only client (supplicant) could receive 4-Way Handshake message 3.
	EAP_ASSERT_ALWAYS(m_is_client == true);

	{
		eap_buf_chain_wr_c sent_packet(
			eap_write_buffer,
			m_am_tools);

		if (sent_packet.get_is_valid() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t send_data_length = 0ul;
		u32_t send_buffer_length = 0ul;

		status = create_4_way_handshake_message_4(
			&sent_packet,
			m_eapol_header_offset,
			&send_data_length,
			&send_buffer_length,
			eapol_key_message->get_key_replay_counter(),
			eapol_key_message->get_key_information_secure(),
			eapol_key_message->get_eapol_protocol_version(),
			eapol_key_message->get_key_descriptor_type());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = packet_send(
			&m_send_network_id,
			&sent_packet,
			m_eapol_header_offset,
			send_data_length,
			send_buffer_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (get_eapol_key_state() == eapol_key_state_wait_4_way_handshake_message_3)
	{
		// We set the keys only on the first received 4-Way Handshake Message 3.

		status = packet_data_session_key(
			&m_temporal_TK,
			eapol_key_type_unicast,
			0ul,
			false,
			eapol_key_message->get_key_RSC(),
			eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RSC_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		{
			// This notification to eapol_core_c object.
			// 4-Way Handshake finished successfully.
			eap_state_notification_c * notification = new eap_state_notification_c(
				m_am_tools,
				&m_send_network_id,
				m_is_client,
				eap_state_notification_generic,
				eap_protocol_layer_eapol_key,
				eapol_key_handshake_type_4_way_handshake,
				get_eapol_key_state(),
				eapol_key_state_4_way_handshake_successfull,
				0ul,
				false);
			if (notification == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			m_key_state_partner->state_notification(notification);

			delete notification;
		}


		if ((get_is_RSNA() == true
				&& m_eapol_group_cipher != eapol_RSNA_key_header_c::eapol_RSNA_cipher_none)
			|| (get_is_WPXM() == true
					&& eapol_key_message->get_key_descriptor_type() == eapol_key_descriptor_type_RSNA))
		{
			if (group_key_received == true)
			{
				// We do have the expected GTK, pass it to lower layers.
				status = packet_data_session_key(
					&m_group_GTK,
					eapol_key_type_broadcast,
					m_group_GTK_ID,
					m_group_GTK_Tx_bit,
					eapol_key_message->get_key_RSC(),
					eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RSC_SIZE);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				{
					// This notification to eapol_core_c object.
					// Group Key Handshake finished successfully.
					eap_state_notification_c * notification = new eap_state_notification_c(
						m_am_tools,
						&m_send_network_id,
						m_is_client,
						eap_state_notification_generic,
						eap_protocol_layer_eapol_key,
						eapol_key_handshake_type_group_key_handshake,
						get_eapol_key_state(),
						eapol_key_state_group_key_handshake_successfull,
						0ul,
						false);
					if (notification == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}
					m_key_state_partner->state_notification(notification);

					delete notification;
				}
			}
			else
			{
				// ERROR, no GTK received.
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_3_payloads_b(): ")
					 EAPL("No GTK received.\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}
		}
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_3_payloads_b(): ")
			 EAPL("No keys are set on state %d=%s.\n"),
			 get_eapol_key_state(),
			 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state())));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_4_way_handshake_message_3(
	const eap_am_network_id_c * const receive_network_id,
	eapol_RSNA_key_header_c * const eapol_key_message,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::process_4_way_handshake_message_3(): eapol_key_descriptor_type = %s = 0x%02x\n"),
		(m_is_client == true ? "client": "server"),
		eapol_key_state_string_c::get_eapol_key_descriptor_type_string(eapol_key_message->get_key_descriptor_type()),
		eapol_key_message->get_key_descriptor_type()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_key_state_c::process_4_way_handshake_message_3()");

	// Only client (supplicant) could receive 4-Way Handshake message 3.
	EAP_ASSERT_ALWAYS(m_is_client == true);

	// NOTE, this could be re-transmitted message.
	// Authenticator did not get the 4-Way Handshake message 4.
	if (m_eapol_key_handshake_type != eapol_key_handshake_type_4_way_handshake
		&& m_eapol_key_handshake_type != eapol_key_handshake_type_group_key_handshake)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: process_4_way_handshake_message_3(): wrong handshake type %s\n"),
			(m_is_client == true ? "client": "server"),
			eapol_key_state_string_c::get_eapol_key_handshake_type_string(m_eapol_key_handshake_type)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	if (get_eapol_key_state() != eapol_key_state_wait_4_way_handshake_message_3
		&& get_eapol_key_state() != eapol_key_state_4_way_handshake_successfull
#if defined(EAP_USE_WPXM)
		&& get_eapol_key_state() != eapol_key_state_wpxm_reassociation_finished_successfull
#endif //#if defined(EAP_USE_WPXM)
		)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: process_4_way_handshake_message_3(): wrong state %s\n"),
			(m_is_client == true ? "client": "server"),
			eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state())));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	// We do have the expected ANonce, compare it.
	if (m_am_tools->memcmp(
			get_ANonce()->get_data(
				get_ANonce()->get_data_length()),
			eapol_key_message->get_key_NONCE(),
			get_ANonce()->get_data_length()) != 0)
	{
		// Illegal ANonce.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_3(): ")
			 EAPL("Not correct ANonce received.\n")));
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("Local ANonce   "),
			get_ANonce()->get_data(
				get_ANonce()->get_data_length()),
			get_ANonce()->get_data_length()));
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("Received ANonce"),
			eapol_key_message->get_key_NONCE(),
			get_ANonce()->get_data_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	u32_t received_data_length = eapol_key_message->get_key_data_length();

	if (received_data_length == 0u)
	{
		// No payload in this packet.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (received_data_length > eapol_key_message->get_header_buffer_length()
			|| eapol_key_message->get_key_data(received_data_length) == 0)
	{
		// Not enough payload in this packet.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (m_eapol_pairwise_cipher
			 == eapol_RSNA_key_header_c::eapol_RSNA_cipher_TKIP)
	{
		status = m_EAPOL_key_IV.set_copy_of_buffer(
			eapol_key_message->get_EAPOL_key_IV(),
			eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		if (m_allow_non_zero_mic_and_reserved_in_message_1 == false)
		{
			status = verify_field_is_zero(
				eapol_key_message->get_EAPOL_key_IV(),
				eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	status = verify_field_is_zero(
		eapol_key_message->get_key_STA_MAC_address(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_STA_MAC_ADDRESS_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_key_reserved(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RESERVED_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = verify_key_mic(
		eapol_key_message,
		&m_confirmation_KCK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	if ((get_is_RSNA() == true
			|| get_is_WPXM() == true)
		&& eapol_key_message->get_key_information_encrypted_key_data() == true)
	{
		status = decrypt_key_data(eapol_key_message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Decryption may change data length.
		received_data_length = eapol_key_message->get_key_data_length();

		if (received_data_length > eapol_key_message->get_header_buffer_length()
			|| eapol_key_message->get_key_data(received_data_length) == 0)
		{
			// Not enough payload in this packet.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
		}
	}


	// This split of process_4_way_handshake_message_3_payloads() function
	// is fix internal compiler error.
	bool group_key_received(false);

	status = process_4_way_handshake_message_3_payloads_a(
		receive_network_id,
		eapol_key_message,
		packet_length,
		&group_key_received);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = process_4_way_handshake_message_3_payloads_b(
		receive_network_id,
		eapol_key_message,
		packet_length,
		group_key_received);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	if (get_eapol_key_state() == eapol_key_state_wait_4_way_handshake_message_3)
	{
		if (get_is_RSNA() == true
			|| (get_is_WPXM() == true
					&& eapol_key_message->get_key_descriptor_type() == eapol_key_descriptor_type_RSNA))
		{
			if (m_indicate_pmkid_to_lower_layer == true)
			{
				// In some platforms lower layers uses PMKID.
				status = create_PMKID();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = packet_data_session_key(
					&m_PMKID,
					eapol_key_type_pmkid,
					0ul,
					false,
					0,
					0ul);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}


			{
				// This notification to eapol_core_c object.
				// 802.11i authentication finished successfully.
				eap_state_notification_c * notification = new eap_state_notification_c(
					m_am_tools,
					&m_send_network_id,
					m_is_client,
					eap_state_notification_generic,
					eap_protocol_layer_eapol_key,
					eapol_key_handshake_type_802_11i_handshake,
					get_eapol_key_state(),
					eapol_key_state_802_11i_authentication_finished_successfull,
					0ul,
					false);
				if (notification == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}
				m_key_state_partner->state_notification(notification);

				delete notification;
			}

			cancel_handshake_timeout();
		}
		else
		{
			// Note the WPA version always does separate Group Key Handshake.
			// Authentication is successfull after the Group Key Handshake
			// Finishes successfully.
		}

		set_eapol_key_state(eapol_key_state_4_way_handshake_successfull);

		// A new Group Key Handshake can happen at any time.
		m_eapol_key_handshake_type = eapol_key_handshake_type_group_key_handshake;

		set_key_reply_counter(eapol_key_message->get_key_replay_counter());


		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: %s: 4-Way Handshake SUCCESS\n"),
			(m_is_client == true ? "client": "server")));
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_3(): ")
			 EAPL("No keys are set on state %d=%s.\n"),
			 get_eapol_key_state(),
			 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state())));
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::create_eapol_key_handshake_message_0(
	const bool true_when_4_way_handshake, ///< With false initiates Group Key Handshake.
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t eapol_header_offset,
	u32_t * const data_length,
	u32_t * const buffer_length,
	const u64_t received_key_replay_counter,
	const eapol_protocol_version_e received_eapol_version)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::create_eapol_key_handshake_message_0()\n"),
		(m_is_client == true ? "client": "server")));

	// Only client (Supplicant) could create 4-Way or Group Key Handshake message 0.
	EAP_ASSERT_ALWAYS(m_is_client == true);

	u32_t eapol_key_data_length
		= eapol_RSNA_key_header_c::get_header_length();

	*buffer_length
		= eapol_header_offset
		+ eapol_key_data_length;

	status = sent_packet->set_buffer_length(
		*buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	sent_packet->set_data_length(
		sent_packet->get_buffer_length());

	eapol_RSNA_key_header_c eapol_key_message(
		m_am_tools,
		get_is_RSNA(),
		get_is_WPXM(),
		sent_packet->get_data_offset(eapol_header_offset, eapol_key_data_length),
		sent_packet->get_data_length());

	if (eapol_key_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	status = eapol_key_message.reset_header(
		0ul,
		m_authentication_type,
		m_eapol_pairwise_cipher,
		received_key_replay_counter,
		true_when_4_way_handshake,
		false, // Install bit is NOT set.
		false, // Key Ack bit is NOT set.
		true, // Key MIC bit is set on
		false, // Secure bit is NOT set.
		false, // Error bit is NOT set.
		true, // Request bit is set on.
		false, // STAKey bit is NOT set.
		false, // Encrypted Key Data bit is NOT set.
		received_eapol_version,
#if defined(EAP_USE_WPXM)
		m_EAPOL_WPXM_key_descriptor_type
#else
		eapol_key_descriptor_type_RSNA
#endif //#if defined(EAP_USE_WPXM)
		);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = eapol_key_message.set_key_data_length(0ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	*data_length
		= eapol_key_message.get_header_length()
		+ eapol_key_message.get_key_data_length();

	status = eapol_key_message.set_eapol_packet_body_length(
		static_cast<u16_t>(*data_length - eapol_header_base_c::get_header_length()));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	sent_packet->set_data_length(
		eapol_header_offset + *data_length);

	if (true_when_4_way_handshake == true)
	{
		TRACE_EAPOL_KEY_MESSAGE(
			"Send 4-Way Handshake Message 0",
			&eapol_key_message);
	}
	else
	{
		status = create_key_mic(
			&eapol_key_message,
			&m_confirmation_KCK);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		TRACE_EAPOL_KEY_MESSAGE(
			"Send Group Key Handshake Message 0",
			&eapol_key_message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::create_group_key_handshake_message_2(
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t eapol_header_offset,
	u32_t * const data_length,
	u32_t * const buffer_length,
	const u64_t received_key_replay_counter,
	const eapol_protocol_version_e received_eapol_version,
	const eapol_key_descriptor_type_e received_key_descriptor_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::create_group_key_handshake_message_2()\n"),
		(m_is_client == true ? "client": "server")));

	// Only client (Supplicant) could create Group Key Handshake message 2.
	EAP_ASSERT_ALWAYS(m_is_client == true);

	if (sent_packet == 0
		|| sent_packet->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t eapol_key_data_length
		= eapol_RSNA_key_header_c::get_header_length();

	*buffer_length
		= eapol_header_offset
		+ eapol_key_data_length;

	status = sent_packet->set_buffer_length(
		*buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	sent_packet->set_data_length(
		sent_packet->get_buffer_length());

	eapol_RSNA_key_header_c eapol_key_message(
		m_am_tools,
		get_is_RSNA(),
		get_is_WPXM(),
		sent_packet->get_data_offset(eapol_header_offset, eapol_key_data_length),
		sent_packet->get_data_length());

	if (eapol_key_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	status = eapol_key_message.reset_header(
		m_group_GTK_ID,
		m_authentication_type,
		m_eapol_pairwise_cipher,
		received_key_replay_counter,
		false, // Pairwise key type bit NOT set.
		false, // Install bit is NOT set.
		false, // Key Ack bit is NOT set.
		true, // Key MIC bit is on.
		true, // Secure bit is on.
		false, // Error bit is NOT set.
		false, // Request bit is NOT set.
		false, // STAKey bit is NOT set.
		false, // Encrypted Key Data bit is NOT set.
		received_eapol_version,
		received_key_descriptor_type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = eapol_key_message.set_key_data_length(0ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	*data_length
		= eapol_key_message.get_header_length()
		+ eapol_key_message.get_key_data_length();

	status = eapol_key_message.set_eapol_packet_body_length(
		static_cast<u16_t>(*data_length - eapol_header_base_c::get_header_length()));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = create_key_mic(
		&eapol_key_message,
		&m_confirmation_KCK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if defined(USE_EAPOL_KEY_TEST_FAILURES)
	if (m_create_key_failure == eapol_key_state_4_way_handshake_successfull)
	{
		m_create_key_failure = eapol_key_state_group_key_handshake_successfull;

		status = eapol_key_message.zero_key_MIC(m_am_tools);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: EAPOL_KEY: %s: error generated in eapol_key_state_c::create_group_key_handshake_message_2()\n"),
			 (m_is_client == true ? "client": "server")));
	}
#endif //#if defined(USE_EAPOL_KEY_TEST_FAILURES)

	sent_packet->set_data_length(
		eapol_header_offset + *data_length);

	TRACE_EAPOL_KEY_MESSAGE(
		"Send Group Key Handshake Message 2",
		&eapol_key_message);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_group_key_handshake_message_1(
	const eap_am_network_id_c * const receive_network_id,
	eapol_RSNA_key_header_c * const eapol_key_message,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::process_group_key_handshake_message_1()\n"),
		(m_is_client == true ? "client": "server")));

	// Only client (supplicant) could receive Group Key Handshake message 1.
	EAP_ASSERT_ALWAYS(m_is_client == true);

	if (get_eapol_key_state() == eapol_key_state_4_way_handshake_successfull
		|| get_eapol_key_state() == eapol_key_state_group_key_handshake_successfull
#if defined(EAP_USE_WPXM)
		|| get_eapol_key_state() == eapol_key_state_wpxm_reassociation_finished_successfull
#endif //#if defined(EAP_USE_WPXM)
		)
	{
		// At this point we know the 4-Way handshake or Group key handshake was successfull.
		m_eapol_key_handshake_type = eapol_key_handshake_type_group_key_handshake;
	}

	if (m_eapol_key_handshake_type != eapol_key_handshake_type_none
		&& m_eapol_key_handshake_type != eapol_key_handshake_type_group_key_handshake)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: start_group_key_handshake(): wrong handshake type %s\n"),
			(m_is_client == true ? "client": "server"),
			eapol_key_state_string_c::get_eapol_key_handshake_type_string(m_eapol_key_handshake_type)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	if (get_eapol_key_state() != eapol_key_state_4_way_handshake_successfull
		&& get_eapol_key_state() != eapol_key_state_group_key_handshake_successfull
		&& get_eapol_key_state() != eapol_key_state_preauthenticated
#if defined(EAP_USE_WPXM)
		&& get_eapol_key_state() != eapol_key_state_wpxm_reassociation_finished_successfull
#endif //#if defined(EAP_USE_WPXM)
		)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: process_group_key_handshake_message_1(): wrong state %s\n"),
			(m_is_client == true ? "client": "server"),
			eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state())));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	u32_t received_data_length = eapol_key_message->get_key_data_length();

	if (received_data_length == 0u)
	{
		// No payload in this packet.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (received_data_length > eapol_key_message->get_header_buffer_length()
		|| eapol_key_message->get_key_data(received_data_length) == 0)
	{
		// Not enough payload in this packet.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}


	if (get_is_RSNA() == true)
	{
		if (m_allow_non_zero_mic_and_reserved_in_message_1 == false)
		{
			status = verify_field_is_zero(
				eapol_key_message->get_key_NONCE(),
				eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else
	{
		// WPA sends GNonse for debugging purposes.
	}


	status = verify_field_is_zero(
		eapol_key_message->get_key_STA_MAC_address(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_STA_MAC_ADDRESS_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_key_reserved(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RESERVED_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	if (m_eapol_group_cipher
			== eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP
		|| m_eapol_group_cipher
			== eapol_RSNA_key_header_c::eapol_RSNA_cipher_TKIP
		|| m_eapol_group_cipher
			== eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_40
		|| m_eapol_group_cipher
			== eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_104)
	{
		status = m_EAPOL_key_IV.set_copy_of_buffer(
			eapol_key_message->get_EAPOL_key_IV(),
			eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = verify_field_is_zero(
			eapol_key_message->get_EAPOL_key_IV(),
			eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	status = verify_key_mic(
		eapol_key_message,
		&m_confirmation_KCK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = decrypt_key_data(eapol_key_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Decryption may change data length.
	received_data_length = eapol_key_message->get_key_data_length();

	if (received_data_length > eapol_key_message->get_header_buffer_length()
		|| eapol_key_message->get_key_data(received_data_length) == 0)
	{
		// Not enough payload in this packet.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}


	if (get_is_RSNA() == true)
	{
		eapol_rsna_key_data_payloads_c key_data_payloads(
			m_am_tools,
			get_is_RSNA(),
			get_is_WPXM());

		eapol_rsna_key_data_header_c key_data(
			m_am_tools,
			get_is_RSNA(),
			get_is_WPXM(),
			eapol_key_message->get_key_data(received_data_length),
			packet_length);
		if (key_data.get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
				(EAPL("ERROR: EAPOL_KEY: No EAPOL-Key data payloads.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = key_data.check_header();
		if (status != eap_status_ok)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
				(EAPL("ERROR: EAPOL_KEY: EAPOL-Key data payload header corrupted.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = parse_key_data(
			eapol_key_message->get_key_descriptor_type(),
			&key_data,
			&received_data_length,
			&key_data_payloads,
			eapol_key_state_wait_group_key_handshake_message_1,
			eapol_key_message->get_key_information_key_descriptor_version());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Check the valid payload is included.
		if (false == key_data_payloads.check_payloads(
			eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_be, // key_id_and_group_key
			eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_not_be, // STAKey
			eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_not_be, // PMKID
			eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_not_be // One or more RSN IE
			))
		{
			// Not correct EAPOL Key Data payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
				(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::process_group_key_handshake_message_1(): ")
				 EAPL("Not correct EAPOL Key Data payloads are included.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// We do have the expected GTK, save it.
		status = m_group_GTK.set_copy_of_buffer(
			key_data_payloads.get_group_key());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_group_GTK_ID = key_data_payloads.get_group_key_id();
		m_group_GTK_Tx_bit = key_data_payloads.get_group_key_tx();
	}
	else
	{
		// WPA
		EAP_UNREFERENCED_PARAMETER(packet_length);

		// According to Draft 3 the GTK is not encapsulated in any way.
		status = m_group_GTK.set_copy_of_buffer(
			eapol_key_message->get_key_data(received_data_length),
			received_data_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_group_GTK_ID = eapol_key_message->get_key_information_key_index();
	}


	eap_buf_chain_wr_c sent_packet(
		eap_write_buffer,
		m_am_tools);

	if (sent_packet.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t send_data_length = 0ul;
	u32_t send_buffer_length = 0ul;

	u64_t reply_counter(eapol_key_message->get_key_replay_counter());

	if (get_is_WPXM() == true
		&& reply_counter == 0ul)
	{
		// Here we must increase the saved Reply Counter.
		// WPXM seems to work against RSN specification that says
		// every packet must be sent with new Reply Counter.
		// WPXM starts Group Key Handshake with Reply Counter 0 after successfull
		// 4-Way Handshake.
		reply_counter = get_key_reply_counter() + 1ul;
	}

	status = create_group_key_handshake_message_2(
		&sent_packet,
		m_eapol_header_offset,
		&send_data_length,
		&send_buffer_length,
		reply_counter,
		eapol_key_message->get_eapol_protocol_version(),
		eapol_key_message->get_key_descriptor_type());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = packet_send(
		&m_send_network_id,
		&sent_packet,
		m_eapol_header_offset,
		send_data_length,
		send_buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (get_eapol_key_state() == eapol_key_state_4_way_handshake_successfull
		|| get_eapol_key_state() == eapol_key_state_preauthenticated
		|| get_eapol_key_state() == eapol_key_state_group_key_handshake_successfull
#if defined(EAP_USE_WPXM)
		|| get_eapol_key_state() == eapol_key_state_wpxm_reassociation_finished_successfull
#endif //#if defined(EAP_USE_WPXM)
		)
	{
		status = packet_data_session_key(
			&m_group_GTK,
			eapol_key_type_broadcast,
			m_group_GTK_ID,
			m_group_GTK_Tx_bit,
			eapol_key_message->get_key_RSC(),
			eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RSC_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// This is notification to eapol_core_c object.
		// Group Key Handshake finished successfully.
		eap_state_notification_c notification(
			m_am_tools,
			&m_send_network_id,
			m_is_client,
			eap_state_notification_generic,
			eap_protocol_layer_eapol_key,
			eapol_key_handshake_type_group_key_handshake,
			get_eapol_key_state(),
			eapol_key_state_group_key_handshake_successfull,
			0ul,
			false);
		m_key_state_partner->state_notification(&notification);

		if (get_is_RSNA() == false)
		{
			// Note the WPA version always does separate Group Key Handshake.
			// Authentication is successfull after the Group Key Handshake
			// Finishes successfully.

			{
				// This notification to eapol_core_c object.
				// WPA authentication finished successfully.
				eap_state_notification_c * notification = new eap_state_notification_c(
					m_am_tools,
					&m_send_network_id,
					m_is_client,
					eap_state_notification_generic,
					eap_protocol_layer_eapol_key,
					eapol_key_handshake_type_802_11i_handshake,
					get_eapol_key_state(),
					eapol_key_state_802_11i_authentication_finished_successfull,
					0ul,
					false);
				if (notification == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}
				m_key_state_partner->state_notification(notification);

				delete notification;
			}
		}

		set_eapol_key_state(eapol_key_state_group_key_handshake_successfull);

		m_eapol_key_handshake_type = eapol_key_handshake_type_authenticated;

		if (get_is_WPXM() == true)
		{
			// Here we must increase the Reply Counter.
			// WPXM seems to work against RSN specification that says
			// every packet must be sent with new Reply Counter.
			// WPXM starts Group Key Handshake with Reply Counter 0 after successfull
			// 4-Way Handshake.
			set_key_reply_counter(get_key_reply_counter() + 1ul);
		}
		else
		{
			set_key_reply_counter(eapol_key_message->get_key_replay_counter());
		}

		cancel_handshake_timeout();

		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: %s: Group Key Handshake SUCCESS\n"),
			(m_is_client == true ? "client": "server")));
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: EAPOL_KEY: eapol_key_state_c::process_group_key_handshake_message_1(): ")
			 EAPL("No keys are set on state %d=%s.\n"),
			 get_eapol_key_state(),
			 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state())));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_RC4_key_descriptor(
	const eap_am_network_id_c * const receive_network_id,
	eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

	eap_status_e status = eap_status_process_general_error;

	if (packet_length < eapol_RC4_key_header_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	if (m_eapol_key_handshake_type != eapol_key_handshake_type_dynamic_WEP)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: EAPOL_KEY: %s: process_RC4_key_descriptor(): wrong handshake type %s\n"),
			(m_is_client == true ? "client": "server"),
			eapol_key_state_string_c::get_eapol_key_handshake_type_string(m_eapol_key_handshake_type)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	if (get_eapol_key_state() != eapol_key_state_wait_rc4_key_message)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: process_RC4_key_descriptor(): wrong state %s\n"),
			(m_is_client == true ? "client": "server"),
			eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state())));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	eapol_RC4_key_header_c eapol_key_message(
		m_am_tools,
		packet_data->get_header_buffer(packet_data->get_header_buffer_length()),
		packet_data->get_header_buffer_length());
	if (eapol_key_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (eapol_key_message.check_header() != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	// Check the packet length
	u32_t rc4_packet_data_length = eapol_header_base_c::get_header_length()
		+ static_cast<u32_t>(eapol_key_message.get_eapol_packet_body_length());

	if (eapol_RC4_key_header_c::get_header_length() > packet_length
		|| rc4_packet_data_length > packet_length)
	{
		// ERROR.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: Illegal EAPOL-Key frame length, ")
			EAPL("eapol_key_message.get_header_length() %d, eapol_key_message.get_packet_body_length() %d, packet_length %d\n"),
			eapol_key_message.get_header_length(),
			eapol_key_message.get_eapol_packet_body_length(),
			packet_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	// Get MS-MPPE-Recv-Key and MS-MPPE-Send-Key	
	eap_variable_data_c mppe_recv_key(m_am_tools);
	eap_variable_data_c mppe_send_key(m_am_tools);

	if (m_pairwise_PMK_WPXK3.get_data_length() == eapol_key_state_mppe_key_length_leap)
	{
		// LEAP only generates 16 bytes PMK. Also with LEAP the receive and send keys are the same.
		status = mppe_recv_key.set_buffer(
			m_pairwise_PMK_WPXK3.get_data(
			eapol_key_state_mppe_key_length_leap),
			eapol_key_state_mppe_key_length_leap,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = mppe_send_key.set_buffer(
			m_pairwise_PMK_WPXK3.get_data(
			eapol_key_state_mppe_key_length_leap),
			eapol_key_state_mppe_key_length_leap,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
	}
	else if (m_pairwise_PMK_WPXK3.get_data_length() >= 64ul)
	{
		// Usually types generate at least 64 bytes PMK.
		// Recv-Key is the first 32 bytes of master session key and Send-Key is the next 32 bytes.
		status = mppe_recv_key.set_buffer(
			m_pairwise_PMK_WPXK3.get_data(
			eapol_key_state_mppe_key_length),
			eapol_key_state_mppe_key_length,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = mppe_send_key.set_buffer(
			m_pairwise_PMK_WPXK3.get_data_offset(
				eapol_key_state_mppe_key_length,
				eapol_key_state_mppe_key_length),
			eapol_key_state_mppe_key_length,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: Unsupported PMK key length for RC4 EAPOL-key handshake.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);	
	}
	
	// Verify the the MD5 signature in Eapol-Key
	crypto_md5_c md5(m_am_tools);
	crypto_hmac_c hmac_md5(m_am_tools, &md5, false);
	if (hmac_md5.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (hmac_md5.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// MPPE-Send-Key is used as the signature key.
	if (hmac_md5.hmac_set_key(&mppe_send_key) != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// Save the signature from the packet
	eap_variable_data_c signature(m_am_tools);
	status = signature.set_copy_of_buffer(
		eapol_key_message.get_key_signature(),
		EAPOL_RC4_KEY_SIGNATURE_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Replace the signature with zeros.
	eapol_key_message.zero_key_signature(m_am_tools);

	// Send the data to HMAC-MD5 module
	if (hmac_md5.hmac_update(
			eapol_key_message.get_header_buffer(rc4_packet_data_length),
			rc4_packet_data_length)
		!= eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);		
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	// Get the calculated signature
	u8_t tmp_signature[EAPOL_RC4_KEY_SIGNATURE_LENGTH];
	u32_t length;
	if (hmac_md5.hmac_final(tmp_signature, &length) != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	
	// Compare the calculated and original signature
	if (m_am_tools->memcmp(
		tmp_signature,
		signature.get_data(
			EAPOL_RC4_KEY_SIGNATURE_LENGTH),
			EAPOL_RC4_KEY_SIGNATURE_LENGTH) != 0)
	{
		// Signatures did not match. Something's wrong.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL_KEY: EAPOL-Key HMAC-MD5 check passed.\n")));

	eap_variable_data_c key_out(m_am_tools);
	// Decrypt the RC4 encrypted key
	if (eapol_key_message.get_key() == 0)
	{
		// EAPOL-Key does not contain the key. This means that we should use
		// the first bytes from MS-MPPE-Recv-Key as the key. There is a slight 
		// confusion in draft-congdon-radius-8021x-23.txt regarding this but this is how
		// it works.
		if (eapol_key_message.get_key_length() > 0)
		{
			status = key_out.set_copy_of_buffer(
				mppe_recv_key.get_data(
					eapol_key_message.get_key_length()),
				eapol_key_message.get_key_length());	
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		} 
		else
		{
			// Key message with no key length?
			// Just ignore the message.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_KEY: Got empty WEP unicast key message.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
	} 
	else
	{
		// Set-up RC4 key. Key is the IV and the MS-MPPE-Recv-Key truncated together.
		eap_variable_data_c rc4_key(m_am_tools);
		status = rc4_key.set_copy_of_buffer(eapol_key_message.get_key_IV(), EAPOL_RC4_KEY_IV_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = rc4_key.add_data(&mppe_recv_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Set-up RC4 module
		crypto_rc4_c rc4(m_am_tools);
		if (rc4.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Set the key for RC4
		if (rc4.set_key(&rc4_key) != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		// Decrypt the key to key_out
		status = key_out.set_buffer_length(eapol_key_message.get_key_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		status = rc4.decrypt_data(
			eapol_key_message.get_key(),
			key_out.get_buffer(
				eapol_key_message.get_key_length()),
			eapol_key_message.get_key_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = key_out.set_data_length(eapol_key_message.get_key_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// Find out the key type. At the moment only WEP keys are supported.
	eapol_key_type_e key_type;
	switch (eapol_key_message.get_key_flag())
	{
	case eapol_RC4_key_flag_broadcast:
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("EAPOL_KEY: Got WEP broadcast key\n")));
		key_type = eapol_key_type_broadcast;
		m_received_802_1x_keys[eapol_key_type_broadcast] = true;
		break;
	case eapol_RC4_key_flag_unicast:
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("EAPOL_KEY: Got WEP unicast key\n")));
		key_type = eapol_key_type_unicast;
		m_received_802_1x_keys[eapol_key_type_unicast] = true;
		break;
	default:
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("RC4 Key"),
		key_out.get_data(key_out.get_data_length()),
		key_out.get_data_length()));

	status = packet_data_session_key(
		&key_out,
		key_type,
		eapol_key_message.get_key_index(),
		true,
		0,
		0ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	{
		bool finished_keys(true);

		for (u32_t key_type = 0ul; key_type <= eapol_key_type_unicast; key_type++)
		{
			if (m_received_802_1x_keys[key_type] == false)
			{
				// Not all keys are received.
				finished_keys = false;
				break;
			}
		}

		if (finished_keys == true)
		{
			// This is notification to eapol_core_c object.
			// Dynamic WEP (802.1x) authentication finished successfully.
			eap_state_notification_c * notification = new eap_state_notification_c(
				m_am_tools,
				&m_send_network_id,
				m_is_client,
				eap_state_notification_generic,
				eap_protocol_layer_eapol_key,
				eapol_key_handshake_type_dynamic_WEP,
				get_eapol_key_state(),
				eapol_key_state_802_11i_authentication_finished_successfull,
				0ul,
				false);
			if (notification == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			m_key_state_partner->state_notification(notification);

			delete notification;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::initialize_4_way_handshake(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_protocol_version_e used_eapol_version)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

	eap_status_e status = eap_status_process_general_error;

	// Only client (supplicant) could call this.
	EAP_ASSERT_ALWAYS(m_is_client == true);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::initialize_4_way_handshake(): m_eapol_key_handshake_type=%d=%s, m_eapol_key_state=%d=%s\n"),
		(m_is_client == true ? "client": "server"),
		m_eapol_key_handshake_type,
		eapol_key_state_string_c::get_eapol_key_handshake_type_string(m_eapol_key_handshake_type),
		m_eapol_key_state,
		eapol_key_state_string_c::get_eapol_key_state_string(m_eapol_key_state)));

	if (m_eapol_key_handshake_type != eapol_key_handshake_type_none
		&& m_eapol_key_handshake_type != eapol_key_handshake_type_authenticated
		&& m_eapol_key_handshake_type != eapol_key_handshake_type_group_key_handshake
		&& m_eapol_key_handshake_type != eapol_key_handshake_type_4_way_handshake)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: initialize_4_way_handshake(): wrong handshake type %s\n"),
			(m_is_client == true ? "client": "server"),
			eapol_key_state_string_c::get_eapol_key_handshake_type_string(m_eapol_key_handshake_type)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	eap_buf_chain_wr_c sent_packet(
		eap_write_buffer,
		m_am_tools);

	if (sent_packet.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t send_data_length = 0ul;
	u32_t send_buffer_length = 0ul;

	status = create_eapol_key_handshake_message_0(
		true,
		&sent_packet,
		m_eapol_header_offset,
		&send_data_length,
		&send_buffer_length,
		m_client_send_key_reply_counter,
		used_eapol_version);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = packet_send(
		&m_send_network_id,
		&sent_packet,
		m_eapol_header_offset,
		send_data_length,
		send_buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
		
	set_eapol_key_state(eapol_key_state_wait_4_way_handshake_message_1);

	m_eapol_key_handshake_type = eapol_key_handshake_type_4_way_handshake;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------


// End.
