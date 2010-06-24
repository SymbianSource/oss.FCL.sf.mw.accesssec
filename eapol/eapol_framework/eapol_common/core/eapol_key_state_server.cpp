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
* %version: 49 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 51 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#if !defined(NO_EAPOL_KEY_STATE_SERVER)

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
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::create_4_way_handshake_message_1(
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t eapol_header_offset,
	u32_t * const data_length,
	u32_t * const buffer_length,
	const eapol_protocol_version_e used_eapol_version,
	const eapol_key_descriptor_type_e received_key_descriptor_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::create_4_way_handshake_message_1()\n"),
		(m_is_client == true ? "client": "server")));

	// Only server (Authenticator) could create 4-Way Handshake message 1.
	EAP_ASSERT_ALWAYS(m_is_client == false);

	if (sent_packet == 0
		|| sent_packet->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_ANonce.get_is_valid_data() == false
		|| m_ANonce.get_data_length() != eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::create_4_way_handshake_message_1(): ")
			 EAPL("m_ANonce is missing or corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_PMKID.get_is_valid_data() == false
		|| m_PMKID.get_data_length()
		!= eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_DATA_PMKID_SIZE)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::create_4_way_handshake_message_1(): ")
			 EAPL("m_PMKID is missing or corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	u32_t eapol_key_data_length
		= eapol_RSNA_key_header_c::get_header_length();

	if (get_is_RSNA() == true)
	{
		eapol_key_data_length += EAPOL_RSNA_4_WAY_HANDSHAKE_MESSAGE_1_KEY_DATA_LENGTH_BYTES;
	}

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
		get_key_reply_counter(),
		true, // Pairwise key type bit is on.
		false, // Install bit is NOT set.
		true, // Key Ack bit is on.
		false, // Key MIC bit is NOT set.
		false, // Secure bit is NOT set.
		false, // Error bit is NOT set.
		false, // Request bit is NOT set.
		false, // STAKey bit is NOT set.
		false, // Encrypted Key Data bit is NOT set.
		used_eapol_version,
		received_key_descriptor_type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	{
		// Add ANonce.
		u8_t * const nonce_field = eapol_key_message.get_key_NONCE();
		if (nonce_field == 0
			|| m_ANonce.get_data_length() != eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		m_am_tools->memmove(
			nonce_field,
			m_ANonce.get_data(eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE),
			eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE);
	}


	if (get_is_RSNA() == true)
	{
		if (m_skip_PMKID_key_data_in_message_1 == false)
		{
			// Add PMKID to Key Data.
			eapol_rsna_key_data_header_c key_data_header(
				m_am_tools,
				get_is_RSNA(),
				get_is_WPXM(),
				eapol_key_message.get_key_data(
						EAPOL_RSNA_4_WAY_HANDSHAKE_MESSAGE_1_KEY_DATA_LENGTH_BYTES),
				EAPOL_RSNA_4_WAY_HANDSHAKE_MESSAGE_1_KEY_DATA_LENGTH_BYTES);
			if (key_data_header.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = key_data_header.reset_header();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Here Type and Length fields are NOT included.
			status = key_data_header.set_length(
				EAPOL_RSNA_4_WAY_HANDSHAKE_MESSAGE_1_KEY_DATA_LENGTH_BYTES - 2ul);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = key_data_header.set_payload_type(eapol_RSNA_key_payload_type_pmkid);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			u8_t * const PMKID_field = key_data_header.get_key_data_payload(
				eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_DATA_PMKID_SIZE);
			if (PMKID_field == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
				(EAPL("EAPOL_KEY: PMKID_field = 0x%08x\n"),
				PMKID_field));

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
				(EAPL("m_PMKID"),
				m_PMKID.get_data(eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_DATA_PMKID_SIZE),
				eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_DATA_PMKID_SIZE));

			m_am_tools->memmove(
				PMKID_field,
				m_PMKID.get_data(eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_DATA_PMKID_SIZE),
				eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_DATA_PMKID_SIZE);

			EAPOL_RSNA_KEY_DATA_TRACE_PAYLOAD(
				get_is_RSNA(),
				get_is_WPXM(),
				eapol_key_message.get_key_descriptor_type(),
				"Added EAPOL Key Data key_data_payload",
				&key_data_header,
				0ul);

			status = eapol_key_message.set_key_data_length(
				EAPOL_RSNA_4_WAY_HANDSHAKE_MESSAGE_1_KEY_DATA_LENGTH_BYTES);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}


		u16_t key_length(0ul);

		status = get_key_length(
			m_eapol_pairwise_cipher,
			&key_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eapol_key_message.set_key_length(key_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
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

	TRACE_EAPOL_KEY_MESSAGE(
		"Send 4-Way Handshake Message 1",
		&eapol_key_message);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::create_4_way_handshake_message_3(
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t eapol_header_offset,
	u32_t * const data_length,
	u32_t * const buffer_length,
	const eapol_protocol_version_e used_eapol_version,
	const eapol_key_descriptor_type_e received_key_descriptor_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::create_4_way_handshake_message_3()\n"),
		(m_is_client == true ? "client": "server")));

	// Only server (Authenticator) could create 4-Way Handshake message 3.
	EAP_ASSERT_ALWAYS(m_is_client == false);

	if (m_ANonce.get_is_valid_data() == false
		|| m_ANonce.get_data_length() != eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::create_4_way_handshake_message_3(): ")
			 EAPL("m_ANonce is missing or corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_authenticator_RSNA_IE.get_is_valid_data() == false
		|| m_authenticator_RSNA_IE.get_data_length() == 0ul
		|| m_authenticator_RSNA_IE.get_data_length()
		> eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_DATA_MAXIMUM_RSN_IE_SIZE)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::create_4_way_handshake_message_3(): ")
			 EAPL("m_authenticator_RSNA_IE is missing or corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	u32_t eapol_key_data_length
		= eapol_RSNA_key_header_c::get_header_length()
		+ m_authenticator_RSNA_IE.get_data_length();

	u32_t extra_encryption_padding_and_block(0ul);

	//if (m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP
	//	|| m_eapol_group_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP)
	{
		extra_encryption_padding_and_block = 2ul * EAP_CRYPTO_AES_WRAP_BLOCK_SIZE;
	}

	if ((get_is_RSNA() == true
			&& m_eapol_group_cipher != eapol_RSNA_key_header_c::eapol_RSNA_cipher_none)
		|| (get_is_WPXM() == true
				&& received_key_descriptor_type == eapol_key_descriptor_type_RSNA))
	{
		u16_t GTK_length = 0ul;

		status = get_key_length(m_eapol_group_cipher, &GTK_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Creates GTK.
		status = create_nonce(&m_group_GTK, GTK_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eapol_key_data_length +=
			eapol_rsna_key_data_header_c::EAPOL_RSNA_KEY_HEADER_LENGTH
			+ eapol_rsna_key_data_header_c::EAPOL_RSNA_KEY_ID_AND_GROUP_KEY_HEADER_SIZE
			+ m_group_GTK.get_data_length();
	}


	*buffer_length
		= eapol_header_offset
		+ eapol_key_data_length
		+ extra_encryption_padding_and_block;

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


	bool secure_bit = false; // Secure bit is NOT set in WPA.
	bool encrypted_key_data = false; // Encrypted Key Data bit is NOT set in WPA.

	if (get_is_RSNA() == true
		|| (get_is_WPXM() == true
				&& received_key_descriptor_type == eapol_key_descriptor_type_RSNA))
	{
		secure_bit = true; // Secure bit is on in RSNA.
		encrypted_key_data = true; // Encrypted Key Data bit is on in RSNA.
	}


	status = eapol_key_message.reset_header(
		0ul,
		m_authentication_type,
		m_eapol_pairwise_cipher,
		get_key_reply_counter(),
		true, // Pairwise key type bit is on.
		true, // Install bit is on. /** @{ This could be false when AP does not support key mapping keys. } */
		true, // Key Ack bit is on.
		true, // Key MIC bit is on.
		secure_bit,
		false, // Error bit is NOT set.
		false, // Request bit is NOT set.
		false, // STAKey bit is NOT set.
		encrypted_key_data,
		used_eapol_version,
		received_key_descriptor_type);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	{
		// Add ANonce.
		u8_t * const nonce_field = eapol_key_message.get_key_NONCE();
		if (nonce_field == 0
			|| m_ANonce.get_data_length() != eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_am_tools->memmove(
			nonce_field,
			m_ANonce.get_data(eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE),
			eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE);
	}

	if (m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_TKIP)
	{
		// Add Key IV.
		// Creates EAPOL-Key IV.
		status = create_nonce(&m_EAPOL_key_IV, eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u8_t * const key_iv_field = eapol_key_message.get_EAPOL_key_IV();
		if (key_iv_field == 0
			|| m_EAPOL_key_IV.get_data_length() < eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Note only the lower sixteen octets of the counter are value are used.
		u32_t offset = m_EAPOL_key_IV.get_data_length() - eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE;
		u8_t * const iv_data = m_EAPOL_key_IV.get_data_offset(offset, eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);

		if (iv_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		m_am_tools->memmove(
			key_iv_field,
			iv_data,
			eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
	}

	/**
	 * @{ Missing payload: starting sequence Authenticator's STA will use in packets protected by GTK. }
	 */

	u32_t total_key_data_length(0ul);

	status = add_RSN_IE_payload(
		&eapol_key_message,
		&m_authenticator_RSNA_IE,
		&total_key_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	/**
	 * @{ Missing payload: a second RSN IE that is Authenticator's unicast cipher suite assigment. }
	 */

	/**
	 * @{ Missing payload: GTK when multicast cipher has been negotiated. }
	 */

	if ((get_is_RSNA() == true
			&& m_eapol_group_cipher != eapol_RSNA_key_header_c::eapol_RSNA_cipher_none)
		|| (get_is_WPXM() == true
				&& received_key_descriptor_type == eapol_key_descriptor_type_RSNA))
	{
		status = add_RSN_GTK_payload(
			&eapol_key_message,
			&m_group_GTK,
			&total_key_data_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
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


	if (get_is_RSNA() == true
		|| (get_is_WPXM() == true
				&& received_key_descriptor_type == eapol_key_descriptor_type_RSNA))
	{
		status = encrypt_key_data(&eapol_key_message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// NOTE the encryption may increase length of the key data field.
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
	}


	status = create_key_mic(
		&eapol_key_message,
		&m_confirmation_KCK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Encryption may change the length of EAPOL-Key data.
	*data_length
		= eapol_key_message.get_header_length()
		+ eapol_key_message.get_key_data_length();

	sent_packet->set_data_length(
		eapol_header_offset + *data_length);

	TRACE_EAPOL_KEY_MESSAGE(
		"Send 4-Way Handshake Message 3",
		&eapol_key_message);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eapol_key_state_c::send_RC4_eapol_key_message(
	const eapol_RC4_key_flags_e flags)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	u8_t unicast_test_key[] = "12345";
	u32_t unicast_test_key_length = sizeof(unicast_test_key)-1ul;

	const u32_t eapol_key_data_length
		= eapol_RC4_key_header_c::get_header_length()
		+ unicast_test_key_length;

	const u32_t buffer_length
		= m_eapol_header_offset
		+ eapol_key_data_length;

	eap_buf_chain_wr_c sent_packet(
		eap_write_buffer,
		m_am_tools);
	if (sent_packet.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = sent_packet.set_buffer_length(
		buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	sent_packet.set_data_length(
		sent_packet.get_buffer_length());

	eapol_RC4_key_header_c eapol_key_message(
		m_am_tools,
		sent_packet.get_data_offset(m_eapol_header_offset, eapol_key_data_length),
		sent_packet.get_data_length());
	if (eapol_key_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create IV.
	eap_variable_data_c RC4_IV(m_am_tools);

	status = create_nonce(&RC4_IV, EAPOL_RC4_KEY_IV_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_am_tools->memmove(eapol_key_message.get_key_IV(), RC4_IV.get_data(), EAPOL_RC4_KEY_IV_LENGTH);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eapol_key_message.set_eapol_protocol_version(eapol_protocol_version_1);

	eapol_key_message.set_eapol_packet_type(eapol_packet_type_key);

	eapol_key_message.set_eapol_packet_body_length(static_cast<u16_t>(eapol_key_data_length - eapol_header_base_c::get_header_length()));

	eapol_key_message.set_key_descriptor_type(eapol_key_descriptor_type_RC4);

	m_am_tools->memset(eapol_key_message.get_replay_counter(), 0, EAPOL_RC4_KEY_REPLAY_COUNTER_LENGTH);

	eapol_key_message.set_key_flag(flags);

	eapol_key_message.set_key_index(0ul);

	eapol_key_message.set_key_length(static_cast<u16_t>(unicast_test_key_length));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
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

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

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
	status = rc4.encrypt_data(
		unicast_test_key,
		eapol_key_message.get_key(),
		unicast_test_key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}		

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Create the the MD5 signature in Eapol-Key

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

	// Replace the signature with zeros.
	eapol_key_message.zero_key_signature(m_am_tools);

	// Send the data to HMAC-MD5 module
	if (hmac_md5.hmac_update(
			eapol_key_message.get_header_buffer(eapol_key_data_length),
			eapol_key_data_length)
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
	
	// Copy the calculated signature to message.
	m_am_tools->memmove(
		eapol_key_message.get_key_signature(),
		tmp_signature,
		EAPOL_RC4_KEY_SIGNATURE_LENGTH);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = packet_send(
		&m_send_network_id,
		&sent_packet,
		m_eapol_header_offset,
		eapol_key_data_length,
		sent_packet.get_buffer_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}



	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::send_RC4_eapol_key_messages()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	status = send_RC4_eapol_key_message(eapol_RC4_key_flag_unicast);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = send_RC4_eapol_key_message(eapol_RC4_key_flag_broadcast);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

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

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::start_4_way_handshake(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::start_4_way_handshake()\n"),
		(m_is_client == true ? "client": "server")));

	// Only server (Authenticator) could start 4-Way Handshake.
	EAP_ASSERT_ALWAYS(m_is_client == false);

	// First check do we need 4-Way Handshake.
	if (get_is_RSNA() == true
		|| get_is_WPA() == true
#if defined(EAP_USE_WPXM)
		|| get_is_WPXM() == true
#endif //#if defined(EAP_USE_WPXM)
		)
	{
		// OK, we need 4-Way Handshake.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAPOL_KEY: %s: eapol_key_state_c::start_4_way_handshake(): ")
			 EAPL("Start 4-Way Handshake, m_authentication_type=%d=%s\n"),
			 (m_is_client == true ? "client": "server"),
			 m_authentication_type,
			 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));
	}
	else if (m_authentication_type == eapol_key_authentication_type_dynamic_WEP
			|| m_authentication_type == eapol_key_authentication_type_EAP_authentication_no_encryption
			)
	{
		// No 4-Way Handshake needed.
		// AP will send unicast and broad cast keys in EAPOL key messages.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAPOL_KEY: %s: eapol_key_state_c::start_4_way_handshake(): ")
			 EAPL("Dynamic WEP, m_authentication_type=%d=%s\n"),
			(m_is_client == true ? "client": "server"),
			m_authentication_type,
			eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

		m_eapol_key_handshake_type = eapol_key_handshake_type_dynamic_WEP;

		send_RC4_eapol_key_messages();

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		// No 4-Way Handshake needed.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAPOL_KEY: %s: eapol_key_state_c::start_4_way_handshake(): ")
			 EAPL("No 4-Way Handshake, m_authentication_type=%d=%s\n"),
			(m_is_client == true ? "client": "server"),
			m_authentication_type,
			eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	if (m_eapol_key_handshake_type != eapol_key_handshake_type_none
		&& m_eapol_key_handshake_type != eapol_key_handshake_type_authenticated
		&& m_eapol_key_handshake_type != eapol_key_handshake_type_4_way_handshake)
	{
		eapol_key_state_string_c state_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: start_4_way_handshake(): wrong handshake type m_eapol_key_handshake_type=%d=%s\n"),
			(m_is_client == true ? "client": "server"),
			m_eapol_key_handshake_type,
			state_string.get_eapol_key_handshake_type_string(m_eapol_key_handshake_type)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	if (get_eapol_key_state() != eapol_key_state_none
		&& get_eapol_key_state() != eapol_key_state_preauthenticated
		&& get_eapol_key_state() != eapol_key_state_group_key_handshake_successfull)
	{
		eapol_key_state_string_c state_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: start_4_way_handshake(): wrong state %s\n"),
			(m_is_client == true ? "client": "server"),
			state_string.get_eapol_key_state_string(get_eapol_key_state())));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	// Creates ANonce.
	status = create_nonce(&m_ANonce, EAPOL_RSNA_NONCE_LENGTH_BYTES);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ANonce"),
		m_ANonce.get_data(
			m_ANonce.get_data_length()),
		m_ANonce.get_data_length()));

	// Create PMKID.
	status = create_PMKID();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_key_reply_counter(0ul);
	increase_key_reply_counter();

	eap_buf_chain_wr_c sent_packet(
		eap_write_buffer,
		m_am_tools);

	if (sent_packet.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t send_data_length = 0ul;
	u32_t send_buffer_length = 0ul;

	status = create_4_way_handshake_message_1(
		&sent_packet,
		m_eapol_header_offset,
		&send_data_length,
		&send_buffer_length,
		eapol_protocol_version_2,
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

	status = init_handshake_timeout(m_handshake_timeout);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_eapol_key_state(eapol_key_state_wait_4_way_handshake_message_2);

	m_eapol_key_handshake_type = eapol_key_handshake_type_4_way_handshake;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_4_way_handshake_message_2_payloads(
	const eap_am_network_id_c * const receive_network_id,
	eapol_RSNA_key_header_c * const eapol_key_message,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

	eap_status_e status = eap_status_process_general_error;

	u32_t received_buffer_length = eapol_key_message->get_key_data_length();

	if (received_buffer_length == 0u)
	{
		// No payload in this packet.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

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
		eapol_key_state_wait_4_way_handshake_message_2,
		eapol_key_message->get_key_information_key_descriptor_version());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Check the valid payload is included.
	if (false == key_data_payloads.check_payloads(
		eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_not_be, // key_id_and_group_key
		eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_not_be, // STAKey
		eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_not_be, // PMKID
		eapol_rsna_key_data_payloads_c::eapol_rsna_key_data_payload_status_must_be // One or more RSN IE
		))
	{
		// Not correct EAPOL Key Data payloads are included.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_2_payloads(): ")
			 EAPL("Not correct EAPOL Key Data payloads are included.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

#if defined(EAP_USE_WPXM)
	// Derive PTK.
	if (get_is_WPXM() == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_2_payloads(): ")
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

	const eap_variable_data_c * confirmation_key = &m_confirmation_KCK;
#if defined(EAP_USE_WPXM)
	if (get_is_WPXM() == true)
	{
		confirmation_key = &m_WPXM_WPXK1;
	}
#endif //#if defined(EAP_USE_WPXM)

	// Check MIC.
	status = verify_key_mic(
		eapol_key_message,
		confirmation_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	// We do have the expected RSN IE, compare it.
	if (get_supplicant_RSNA_IE()->compare(
			key_data_payloads.get_RSN_IE()->get_object(0ul)) != 0)
	{
		// Illegal RSN IE.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::process_4_way_handshake_message_2_payloads(): ")
			 EAPL("Not correct RSN IE received.\n")));
		EAP_TRACE_DATA_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("Supplicant RSN IE"),
			get_supplicant_RSNA_IE()->get_data(
				get_supplicant_RSNA_IE()->get_data_length()),
			get_supplicant_RSNA_IE()->get_data_length()));
		EAP_TRACE_DATA_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("Received RSN IE"),
			key_data_payloads.get_RSN_IE()->get_object(0ul)->get_data(
				key_data_payloads.get_RSN_IE()->get_object(0ul)->get_data_length()),
			key_data_payloads.get_RSN_IE()->get_object(0ul)->get_data_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_4_way_handshake_message_0(
	const eap_am_network_id_c * const receive_network_id,
	eapol_RSNA_key_header_c * const eapol_key_message,
	const u32_t /* packet_length */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

	eap_status_e status = eap_status_process_general_error;

	eapol_key_state_string_c state_string;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::process_4_way_handshake_message_0(): eapol_key_descriptor_type = %s = 0x%02x\n"),
		(m_is_client == true ? "client": "server"),
		state_string.get_eapol_key_descriptor_type_string(eapol_key_message->get_key_descriptor_type()),
		eapol_key_message->get_key_descriptor_type()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_key_state_c::process_4_way_handshake_message_0()");

	// Only server (Authenticator) could receive 4-Way Handshake message 0.
	// Client initializes the 4-Way Handshake with this message.
	EAP_ASSERT_ALWAYS(m_is_client == false);

	if (m_eapol_key_handshake_type == eapol_key_handshake_type_none)
	{
		m_eapol_key_handshake_type = eapol_key_handshake_type_4_way_handshake;
	}
	else if (m_eapol_key_handshake_type != eapol_key_handshake_type_4_way_handshake)
	{
		eapol_key_state_string_c state_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: process_4_way_handshake_message_0(): wrong handshake type %s\n"),
			(m_is_client == true ? "client": "server"),
			state_string.get_eapol_key_handshake_type_string(m_eapol_key_handshake_type)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	if (get_eapol_key_state() != eapol_key_state_none
		&& get_eapol_key_state() != eapol_key_state_preauthenticated
		&& get_eapol_key_state() != eapol_key_state_group_key_handshake_successfull
		)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: process_4_way_handshake_message_0(): wrong state %s\n"),
			(m_is_client == true ? "client": "server"),
			state_string.get_eapol_key_state_string(get_eapol_key_state())));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	if (eapol_key_message->get_key_length() != 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_EAPOL_key_IV(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_key_RSC(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RSC_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
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

	status = start_4_way_handshake(
		receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_4_way_handshake_message_2(
	const eap_am_network_id_c * const receive_network_id,
	eapol_RSNA_key_header_c * const eapol_key_message,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

	eap_status_e status = eap_status_process_general_error;

	eapol_key_state_string_c state_string;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::process_4_way_handshake_message_2(): eapol_key_descriptor_type = %s = 0x%02x\n"),
		(m_is_client == true ? "client": "server"),
		state_string.get_eapol_key_descriptor_type_string(eapol_key_message->get_key_descriptor_type()),
		eapol_key_message->get_key_descriptor_type()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_key_state_c::process_4_way_handshake_message_2()");

	// Only server (Authenticator) could receive 4-Way Handshake message 2.
	EAP_ASSERT_ALWAYS(m_is_client == false);

	if (m_eapol_key_handshake_type != eapol_key_handshake_type_4_way_handshake)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: process_4_way_handshake_message_0(): wrong handshake type %s\n"),
			(m_is_client == true ? "client": "server"),
			state_string.get_eapol_key_handshake_type_string(m_eapol_key_handshake_type)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	if (get_eapol_key_state() != eapol_key_state_wait_4_way_handshake_message_2)
	{
		eapol_key_state_string_c state_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: process_4_way_handshake_message_2(): wrong state %s\n"),
			(m_is_client == true ? "client": "server"),
			state_string.get_eapol_key_state_string(get_eapol_key_state())));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	if (eapol_key_message->get_key_length() != 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_EAPOL_key_IV(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_key_RSC(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RSC_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
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


	// Save SNonce.
	const u8_t * const SNonce = eapol_key_message->get_key_NONCE();
	if (SNonce == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	status = m_SNonce.set_copy_of_buffer(
		SNonce,
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = process_4_way_handshake_message_2_payloads(
		receive_network_id,
		eapol_key_message,
		packet_length);
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

	increase_key_reply_counter();

	status = create_4_way_handshake_message_3(
		&sent_packet,
		m_eapol_header_offset,
		&send_data_length,
		&send_buffer_length,
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

	set_eapol_key_state(eapol_key_state_wait_4_way_handshake_message_4);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_4_way_handshake_message_4(
	const eap_am_network_id_c * const receive_network_id,
	eapol_RSNA_key_header_c * const eapol_key_message,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(packet_length);

	eap_status_e status = eap_status_process_general_error;

	eapol_key_state_string_c state_string;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::process_4_way_handshake_message_4(): eapol_key_descriptor_type = %s = 0x%02x\n"),
		(m_is_client == true ? "client": "server"),
		state_string.get_eapol_key_descriptor_type_string(eapol_key_message->get_key_descriptor_type()),
		eapol_key_message->get_key_descriptor_type()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_key_state_c::process_4_way_handshake_message_4()");

	// Only server (Authenticator) could receive 4-Way Handshake message 4.
	EAP_ASSERT_ALWAYS(m_is_client == false);

	if (m_eapol_key_handshake_type != eapol_key_handshake_type_4_way_handshake)
	{
		eapol_key_state_string_c state_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: start_4_way_handshake(): wrong handshake type %s\n"),
			(m_is_client == true ? "client": "server"),
			state_string.get_eapol_key_handshake_type_string(m_eapol_key_handshake_type)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	if (get_eapol_key_state() != eapol_key_state_wait_4_way_handshake_message_4)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: process_4_way_handshake_message_4(): wrong state %s\n"),
			(m_is_client == true ? "client": "server"),
			state_string.get_eapol_key_state_string(get_eapol_key_state())));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	if (eapol_key_message->get_key_length() != 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_key_NONCE(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_EAPOL_key_IV(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_key_RSC(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RSC_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
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

	if (eapol_key_message->get_key_data_length() != 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
	}


	status = verify_key_mic(
		eapol_key_message,
		&m_confirmation_KCK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


#if defined(EAP_USE_WPXM)
	if (get_is_WPXM() == true)
	{
		status = packet_data_session_key(
			&m_WPXM_WPXK1,
			eapol_key_type_wpxm_wpxk1,
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
#endif //#if defined(EAP_USE_WPXM)


	status = packet_data_session_key(
		&m_temporal_TK,
		eapol_key_type_unicast,
		0ul,
		false,
		0,
		0ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	{
		// This is notification to eapol_core_c object.
		// 4-Way Handshake finished successfully.
		eap_state_notification_c notification(
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
		m_key_state_partner->state_notification(&notification);
	}


	if (get_is_RSNA() == true
		&& m_eapol_group_cipher != eapol_RSNA_key_header_c::eapol_RSNA_cipher_none
		&& m_group_GTK.get_is_valid_data() == true)
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
		}
	}

	if (get_is_RSNA() == true)
	{
		{
			// This is notification to eapol_core_c object.
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

	m_eapol_key_handshake_type = eapol_key_handshake_type_authenticated;

	cancel_retransmission();

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL_KEY: %s: 4-Way Handshake SUCCESS\n"),
		(m_is_client == true ? "client": "server")));

	status = start_group_key_handshake(
		receive_network_id,
		eapol_key_message->get_eapol_protocol_version(),
		eapol_key_message->get_key_descriptor_type());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::create_group_key_handshake_message_1(
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t eapol_header_offset,
	u32_t * const data_length,
	u32_t * const buffer_length,
	const eapol_protocol_version_e used_eapol_version,
	const eapol_key_descriptor_type_e received_key_descriptor_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::create_group_key_handshake_message_1()\n"),
		(m_is_client == true ? "client": "server")));

	// Only server (Authenticator) could create Group Key Handshake message 1.
	EAP_ASSERT_ALWAYS(m_is_client == false);

	if (m_confirmation_KCK.get_is_valid_data() == false
		|| m_confirmation_KCK.get_data_length() == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::create_group_key_handshake_message_1(): ")
			 EAPL("m_confirmation_KCK is missing or corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_encryption_KEK.get_is_valid_data() == false
		|| m_encryption_KEK.get_data_length() == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::create_group_key_handshake_message_1(): ")
			 EAPL("m_encryption_KEK is missing or corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u16_t GTK_length = 0ul;

	status = get_key_length(m_eapol_group_cipher, &GTK_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Creates GTK.
	status = create_nonce(&m_group_GTK, GTK_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	u32_t eapol_key_data_length
		= eapol_RSNA_key_header_c::get_header_length()
		+ eapol_rsna_key_data_header_c::EAPOL_RSNA_KEY_HEADER_LENGTH
		+eapol_rsna_key_data_header_c::EAPOL_RSNA_KEY_ID_AND_GROUP_KEY_HEADER_SIZE
		+GTK_length;


	u32_t extra_encryption_padding_and_block(0ul);

	if (m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP
		|| m_eapol_group_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP)
	{
		extra_encryption_padding_and_block = 2ul * EAP_CRYPTO_AES_WRAP_BLOCK_SIZE;
	}


	*buffer_length
		= eapol_header_offset
		+ eapol_key_data_length
		+ extra_encryption_padding_and_block;

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
		1ul,
		m_authentication_type,
		m_eapol_pairwise_cipher,
		get_key_reply_counter(),
		false, // Pairwise key type bit is NOT set.
		true, // Install bit is on. Use group key for send and receive.
		true, // Key Ack bit is on.
		true, // Key MIC bit is on.
		true, // Secure bit is on.
		false, // Error bit is NOT set.
		false, // Request bit is NOT set.
		false, // STAKey bit is NOT set.
		true, // Encrypted Key Data bit is on.
		used_eapol_version,
		received_key_descriptor_type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	if (m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_TKIP)
	{
		// Add Key IV.
		// Creates EAPOL-Key IV.
		status = create_nonce(&m_EAPOL_key_IV, eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u8_t * const key_iv_field = eapol_key_message.get_EAPOL_key_IV();
		if (key_iv_field == 0
			|| m_EAPOL_key_IV.get_data_length() < eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Note only the lower sixteen octets of the counter are value are used.
		u32_t offset = m_EAPOL_key_IV.get_data_length() - eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE;

		u8_t * const iv_data = m_EAPOL_key_IV.get_data_offset(offset, eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
		if (iv_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		m_am_tools->memmove(
			key_iv_field,
			iv_data,
			eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
	}

	/**
	 * @{ Missing payload: last transmit sequence number for GTK. }
	 */


	u32_t eapol_data_length(0ul);
	
	if (get_is_RSNA() == true)
	{
		status = add_RSN_GTK_payload(
			&eapol_key_message,
			&m_group_GTK,
			&eapol_data_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		// Add authenticator GTK to Key Data.
		u8_t * data_field_of_GTK
			= eapol_key_message.get_key_data(
					GTK_length);
		if (data_field_of_GTK == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_am_tools->memmove(
			data_field_of_GTK,
			m_group_GTK.get_data(GTK_length),
			GTK_length);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("send WPA Group Key"),
			 m_group_GTK.get_data(GTK_length),
			GTK_length));

		eapol_data_length = GTK_length;
	}



	if (eapol_data_length > 0xffff)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
	}

	status = eapol_key_message.set_key_data_length(
		static_cast<u16_t>(eapol_data_length));
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

	status = encrypt_key_data(&eapol_key_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// NOTE the encryption may increase length of the key data field.
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

	// Encryption may change the length of EAPOL-Key data.
	*data_length
		= eapol_key_message.get_header_length()
		+ eapol_key_message.get_key_data_length();

	sent_packet->set_data_length(
		eapol_header_offset + *data_length);

	TRACE_EAPOL_KEY_MESSAGE(
		"Send Group Key Handshake Message 1",
		&eapol_key_message);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_group_key_handshake_message_0(
	const eap_am_network_id_c * const receive_network_id,
	eapol_RSNA_key_header_c * const eapol_key_message,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(packet_length);
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::process_group_key_handshake_message_0()\n"),
		(m_is_client == true ? "client": "server")));

	// Only server (Authenticator) could receive Group Key Handshake message 0.
	EAP_ASSERT_ALWAYS(m_is_client == false);

	if (m_eapol_key_handshake_type != eapol_key_handshake_type_none)
	{
		eapol_key_state_string_c state_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: process_group_key_handshake_message_0(): wrong handshake type %s\n"),
			(m_is_client == true ? "client": "server"),
			state_string.get_eapol_key_handshake_type_string(m_eapol_key_handshake_type)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	if (get_eapol_key_state() != eapol_key_state_4_way_handshake_successfull
		&& get_eapol_key_state() != eapol_key_state_group_key_handshake_successfull)
	{
		eapol_key_state_string_c state_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: process_group_key_handshake_message_0(): wrong state %s\n"),
			(m_is_client == true ? "client": "server"),
			state_string.get_eapol_key_state_string(get_eapol_key_state())));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}


	if (eapol_key_message->get_key_length() != 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_key_NONCE(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_EAPOL_key_IV(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_key_RSC(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RSC_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
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

	if (eapol_key_message->get_key_data_length() != 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
	}


	status = verify_key_mic(
		eapol_key_message,
		&m_confirmation_KCK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = start_group_key_handshake(
		receive_network_id,
		eapol_key_message->get_eapol_protocol_version(),
		eapol_key_message->get_key_descriptor_type());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_group_key_handshake_message_2(
	const eap_am_network_id_c * const receive_network_id,
	eapol_RSNA_key_header_c * const eapol_key_message,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);
	EAP_UNREFERENCED_PARAMETER(packet_length);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::process_group_key_handshake_message_2()\n"),
		(m_is_client == true ? "client": "server")));

	// Only server (Authenticator) could receive Group Key Handshake message 2.
	EAP_ASSERT_ALWAYS(m_is_client == false);

	if (m_eapol_key_handshake_type != eapol_key_handshake_type_group_key_handshake)
	{
		eapol_key_state_string_c state_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: start_group_key_handshake(): wrong handshake type %s\n"),
			(m_is_client == true ? "client": "server"),
			state_string.get_eapol_key_handshake_type_string(m_eapol_key_handshake_type)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	if (get_eapol_key_state() != eapol_key_state_wait_group_key_handshake_message_2)
	{
		eapol_key_state_string_c state_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: process_group_key_handshake_message_2(): wrong state %s\n"),
			(m_is_client == true ? "client": "server"),
			state_string.get_eapol_key_state_string(get_eapol_key_state())));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}


	if (eapol_key_message->get_key_length() != 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_key_NONCE(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_EAPOL_key_IV(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = verify_field_is_zero(
		eapol_key_message->get_key_RSC(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RSC_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
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

	if (eapol_key_message->get_key_data_length() != 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
	}

	
	status = verify_key_mic(
		eapol_key_message,
		&m_confirmation_KCK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

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


		cancel_group_key_update_timeout();

		if (m_server_TEST_group_key_update == true)
		{
			init_group_key_update_timeout(EAPOL_KEY_STATE_TIMER_GROUP_KEY_UPDATE_TIMEOUT);
		}
	}

	if (get_is_RSNA() == false)
	{
		// Note the WPA version always does separate Group Key Handshake.
		// Authentication is successfull after the Group Key Handshake
		// Finishes successfully.

		{
			// This is notification to eapol_core_c object.
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

	cancel_retransmission();
	cancel_handshake_timeout();

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL_KEY: %s: Group Key Handshake SUCCESS\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if !defined(NO_EAPOL_KEY_STATE_SERVER)

//--------------------------------------------------

// End.
