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
* %version: 135 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 50 
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
#include "abs_eapol_core.h"
#include "abs_eapol_key_state.h"
#include "eap_core_retransmission.h"
#include "eapol_rsna_key_data_payloads.h"
#include "eap_buffer.h"
#include "eapol_session_key.h"
#include "eapol_key_state_string.h"

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::save_parameters(
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const authenticator_RSNA_IE,
	const eap_variable_data_c * const supplicant_RSNA_IE,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_pairwise_cipher,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_group_cipher)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	m_authentication_type = authentication_type;
	m_eapol_pairwise_cipher = eapol_pairwise_cipher;
	m_eapol_group_cipher = eapol_group_cipher;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::save_parameters(): m_authentication_type=%s, ")
		 EAPL("m_eapol_pairwise_cipher=%d, m_eapol_group_cipher=%d.\n"),
		 (m_is_client == true) ? "client": "server",
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type),
		 m_eapol_pairwise_cipher,
		 m_eapol_group_cipher));
	

	if (get_is_RSNA() == true
		|| get_is_WPA() == true
#if defined(EAP_USE_WPXM)
		|| get_is_WPXM() == true
#endif //#if defined(EAP_USE_WPXM)
		)
	{
		if (authenticator_RSNA_IE->get_is_valid_data() == true)
		{
			status = m_authenticator_RSNA_IE.set_copy_of_buffer(
				authenticator_RSNA_IE);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Authenticator RSN IE"),
				 get_authenticator_RSNA_IE()->get_data(
					 get_authenticator_RSNA_IE()->get_data_length()),
				 get_authenticator_RSNA_IE()->get_data_length()));
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		if (supplicant_RSNA_IE->get_is_valid_data() == true)
		{
			status = m_supplicant_RSNA_IE.set_copy_of_buffer(
				supplicant_RSNA_IE);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Supplicant RSN IE"),
				get_supplicant_RSNA_IE()->get_data(
					get_supplicant_RSNA_IE()->get_data_length()),
				get_supplicant_RSNA_IE()->get_data_length()));
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::initialize(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const authenticator_RSNA_IE,
	const eap_variable_data_c * const supplicant_RSNA_IE,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_pairwise_cipher,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_group_cipher,
	const eap_variable_data_c * const pre_shared_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = save_parameters(
		authentication_type,
		authenticator_RSNA_IE,
		supplicant_RSNA_IE,
		eapol_pairwise_cipher,
		eapol_group_cipher);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if ((m_authentication_type == eapol_key_authentication_type_RSNA_PSK
		 || m_authentication_type == eapol_key_authentication_type_WPA_PSK)
		&& (pre_shared_key == 0
			|| pre_shared_key->get_is_valid_data() == false
			|| pre_shared_key->get_data_length() < EAPOL_RSNA_PMK_LENGTH_BYTES))
	{
		if (pre_shared_key != 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
				(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::initialize(): illegal pre shared key 0x%08x, PSK length %d.\n"),
				 pre_shared_key->get_data(pre_shared_key->get_data_length()),
				pre_shared_key->get_data_length()));
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}
	else if (m_authentication_type == eapol_key_authentication_type_RSNA_EAP
		&& (m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_none))
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::initialize(): illegal pairwise cipher suite %d.\n"),
			m_eapol_pairwise_cipher));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}
	else if (m_authentication_type == eapol_key_authentication_type_RSNA_EAP
		&& (m_eapol_group_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_none))
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::initialize(): illegal group cipher suite %d.\n"),
			m_eapol_group_cipher));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}
	else if (m_authentication_type == eapol_key_authentication_type_WPA_EAP
		&& (m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_none))
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::initialize(): illegal pairwise cipher suite %d.\n"),
			m_eapol_pairwise_cipher));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}
	else if (m_authentication_type == eapol_key_authentication_type_WPA_EAP
		&& (m_eapol_group_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_none))
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::initialize(): illegal group cipher suite %d.\n"),
			m_eapol_group_cipher));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}
	else if (m_authentication_type == eapol_key_authentication_type_dynamic_WEP
		|| m_authentication_type == eapol_key_authentication_type_EAP_authentication_no_encryption
	)
	{
		// OK, cannot check the pairwise and group ciphers.
		// AP will tell these in the EAPOL RC4 Key message.
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = set_mac_addresses(receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_eapol_key_state(eapol_key_state_none);
	m_eapol_key_handshake_type = eapol_key_handshake_type_none;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_authentication_type == eapol_key_authentication_type_RSNA_PSK
		|| m_authentication_type == eapol_key_authentication_type_WPA_PSK)
	{
		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(
			m_am_tools,
			receive_network_id->get_destination_id(),
			receive_network_id->get_source_id(),
			receive_network_id->get_type());
		if (send_network_id.get_is_valid_data() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = set_pairwise_PMK(
			pre_shared_key,
			&send_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		m_is_associated = true;

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAPOL_KEY: %s: eapol_key_state_c::initialize(): m_is_associated=%s.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_associated == true) ? "true": "false"));
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::initialize(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	reset();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	m_authentication_type = authentication_type;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = set_mac_addresses(receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_eapol_key_state(eapol_key_state_none);
	m_eapol_key_handshake_type = eapol_key_handshake_type_none;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Creates SNonce. This is done here in early phase of authentication.
	// This will reduce the CPU load when time critical first message
	// of 4-Way handshake is processed.
	status = create_nonce(&m_SNonce, EAPOL_RSNA_NONCE_LENGTH_BYTES);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// 
eap_status_e eapol_key_state_c::set_mac_addresses(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		const eap_variable_data_c * authenticator_MAC_address = 0;
		const eap_variable_data_c * supplicant_MAC_address = 0;

		if (m_is_client == true)
		{
			authenticator_MAC_address = receive_network_id->get_source_id();
			supplicant_MAC_address = receive_network_id->get_destination_id();
		}
		else
		{
			authenticator_MAC_address = receive_network_id->get_destination_id();
			supplicant_MAC_address = receive_network_id->get_source_id();
		}


		status = m_authenticator_MAC_address.set_copy_of_buffer(
			authenticator_MAC_address);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_supplicant_MAC_address.set_copy_of_buffer(
			supplicant_MAC_address);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		const eap_variable_data_c * destination = 0;
		const eap_variable_data_c * source = 0;

		if (m_is_client == true)
		{
			destination = &m_authenticator_MAC_address;
			source = &m_supplicant_MAC_address;
		}
		else
		{
			destination = &m_supplicant_MAC_address;
			source = &m_authenticator_MAC_address;
		}


		eap_am_network_id_c send_network_id(m_am_tools,
			source,
			destination,
			eapol_ethernet_type_pae);

		status = m_send_network_id.set_copy_of_network_id(&send_network_id);
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

// 
EAP_FUNC_EXPORT eapol_key_state_c::~eapol_key_state_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: eapol_key_state_c::~eapol_key_state_c(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	EAP_ASSERT(m_shutdown_was_called == true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_key_state_c::eapol_key_state_c(
	abs_eap_am_tools_c * const tools,
	abs_eapol_key_state_c * const key_state_partner,
	abs_eapol_core_c * const eapol_partner,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const authenticator_RSNA_IE,
	const eap_variable_data_c * const supplicant_RSNA_IE,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_pairwise_cipher,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_group_cipher,
	const eap_variable_data_c * const pre_shared_key)
	: m_am_tools(tools)
	, m_key_state_partner(key_state_partner)
	, m_eapol_partner(eapol_partner)
	, m_send_network_id(tools)
	, m_authenticator_RSNA_IE(tools)
	, m_unicast_cipher_suite_RSNA_IE(tools)
	, m_supplicant_RSNA_IE(tools)
	, m_received_PMKID(tools)
	, m_supplicant_MAC_address(tools)
	, m_authenticator_MAC_address(tools)
	, m_ANonce(tools)
	, m_SNonce(tools)
	, m_EAPOL_key_IV(tools)
	, m_pairwise_PMK_WPXK3(tools)
	, m_PMKID(tools)
	, m_transient_PTK(tools)
	, m_confirmation_KCK(tools)
	, m_encryption_KEK(tools)
	, m_temporal_TK(tools)
	, m_group_GTK(tools)
#if defined(EAP_USE_WPXM)
	, m_WPXM_WPXK1(tools)
	, m_WPXM_WPXK2(tools)
	, m_WPXM_WPXC(eapol_key_constant_wpxm_initial_wpxc_counter_value)
#endif //#if defined(EAP_USE_WPXM)
	, m_group_GTK_ID(0u)
	, m_group_GTK_Tx_bit(false)
	, m_eapol_header_offset(0ul)
	, m_MTU(0ul)
	, m_trailer_length(0ul)
	, m_retransmission(0)
	, m_retransmission_time(EAPOL_KEY_STATE_TIMER_RETRANSMISSION_TIMEOUT)
	, m_retransmission_counter(EAPOL_KEY_STATE_RETRANSMISSION_COUNTER)
	, m_handshake_timeout(EAPOL_KEY_STATE_TIMER_HANDSHAKE_TIMEOUT_TIMEOUT)
#if defined(EAP_USE_WPXM)
	, m_wpxm_reassociate_timeout(EAPOL_KEY_STATE_TIMER_REASSOCIATE_TIMEOUT)
	, m_EAPOL_WPXM_key_descriptor_type(eapol_key_descriptor_type_none)
#endif //#if defined(EAP_USE_WPXM)
	, m_authentication_type(authentication_type)
	, m_eapol_pairwise_cipher(eapol_pairwise_cipher)
	, m_eapol_group_cipher(eapol_group_cipher)
	, m_eapol_key_state(eapol_key_state_none)
	, m_eapol_key_handshake_type(eapol_key_handshake_type_none)
	, m_create_key_failure(eapol_key_state_none)
	, m_pmksa_caching_timeout(EAPOL_KEY_STATE_TIMER_PMKSA_CACHING_TIMEOUT)
	, m_key_reply_counter(0ul)
	, m_client_send_key_reply_counter(0ul)
	, m_is_client(is_client_when_true)
	, m_is_valid(false)
	, m_marked_removed(false)
	, m_shutdown_was_called(false)
	, m_allow_missing_PMKID_in_message_1(false)
	, m_skip_PMKID_key_data_in_message_1(false)
	, m_allow_non_zero_mic_and_reserved_in_message_1(false)
	, m_indicate_pmkid_to_lower_layer(false)
	, m_handshake_timeout_set(false)
	, m_server_TEST_group_key_update(false)
	, m_is_associated(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(receive_network_id);
	EAP_UNREFERENCED_PARAMETER(authenticator_RSNA_IE);
	EAP_UNREFERENCED_PARAMETER(supplicant_RSNA_IE);
	EAP_UNREFERENCED_PARAMETER(pre_shared_key);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_key_state_c::eapol_key_state_c(1): %s\n"),
		 (m_is_client == true) ? "client": "server"));

	for (u32_t key_type = 0ul; key_type < eapol_key_type_last_type; key_type++)
	{
		m_received_802_1x_keys[key_type] = false;
	}


	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_key_state_c::eapol_key_state_c(
	abs_eap_am_tools_c * const tools,
	abs_eapol_key_state_c * const key_state_partner,
	abs_eapol_core_c * const eapol_partner,
	const bool is_client_when_true,
	const eap_am_network_id_c * const /* receive_network_id */,
	const eapol_key_authentication_type_e authentication_type)
	: m_am_tools(tools)
	, m_key_state_partner(key_state_partner)
	, m_eapol_partner(eapol_partner)
	, m_send_network_id(tools)
	, m_authenticator_RSNA_IE(tools)
	, m_unicast_cipher_suite_RSNA_IE(tools)
	, m_supplicant_RSNA_IE(tools)
	, m_received_PMKID(tools)
	, m_supplicant_MAC_address(tools)
	, m_authenticator_MAC_address(tools)
	, m_ANonce(tools)
	, m_SNonce(tools)
	, m_EAPOL_key_IV(tools)
	, m_pairwise_PMK_WPXK3(tools)
	, m_PMKID(tools)
	, m_transient_PTK(tools)
	, m_confirmation_KCK(tools)
	, m_encryption_KEK(tools)
	, m_temporal_TK(tools)
	, m_group_GTK(tools)
#if defined(EAP_USE_WPXM)
	, m_WPXM_WPXK1(tools)
	, m_WPXM_WPXK2(tools)
	, m_WPXM_WPXC(eapol_key_constant_wpxm_initial_wpxc_counter_value)
#endif //#if defined(EAP_USE_WPXM)
	, m_group_GTK_ID(0u)
	, m_group_GTK_Tx_bit(false)
	, m_eapol_header_offset(0ul)
	, m_MTU(0ul)
	, m_trailer_length(0ul)
	, m_retransmission(0)
	, m_retransmission_time(EAPOL_KEY_STATE_TIMER_RETRANSMISSION_TIMEOUT)
	, m_retransmission_counter(EAPOL_KEY_STATE_RETRANSMISSION_COUNTER)
	, m_handshake_timeout(EAPOL_KEY_STATE_TIMER_HANDSHAKE_TIMEOUT_TIMEOUT)
#if defined(EAP_USE_WPXM)
	, m_wpxm_reassociate_timeout(EAPOL_KEY_STATE_TIMER_REASSOCIATE_TIMEOUT)
	, m_EAPOL_WPXM_key_descriptor_type(eapol_key_descriptor_type_none)
#endif //#if defined(EAP_USE_WPXM)
	, m_authentication_type(authentication_type)
	, m_eapol_pairwise_cipher(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none)
	, m_eapol_group_cipher(eapol_RSNA_key_header_c::eapol_RSNA_cipher_none)
	, m_eapol_key_state(eapol_key_state_none)
	, m_eapol_key_handshake_type(eapol_key_handshake_type_none)
	, m_create_key_failure(eapol_key_state_none)
	, m_pmksa_caching_timeout(EAPOL_KEY_STATE_TIMER_PMKSA_CACHING_TIMEOUT)
	, m_key_reply_counter(0ul)
	, m_client_send_key_reply_counter(0ul)
	, m_is_client(is_client_when_true)
	, m_is_valid(false)
	, m_marked_removed(false)
	, m_shutdown_was_called(false)
	, m_allow_missing_PMKID_in_message_1(false)
	, m_skip_PMKID_key_data_in_message_1(false)
	, m_allow_non_zero_mic_and_reserved_in_message_1(false)
	, m_indicate_pmkid_to_lower_layer(false)
	, m_handshake_timeout_set(false)
	, m_server_TEST_group_key_update(false)
	, m_is_associated(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_key_state_c::eapol_key_state_c(2): %s\n"),
		 (m_is_client == true) ? "client": "server"));

	for (u32_t key_type = 0ul; key_type < eapol_key_type_last_type; key_type++)
	{
		m_received_802_1x_keys[key_type] = false;
	}

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_key_state_c::configure(): %s\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	m_eapol_header_offset = m_eapol_partner->get_header_offset(&m_MTU, &m_trailer_length);

	for (u32_t key_type = 0ul; key_type < eapol_key_type_last_type; key_type++)
	{
		m_received_802_1x_keys[key_type] = false;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_is_client == false)
	{
		eap_variable_data_c retransmission_time(m_am_tools);

		eap_status_e status = m_key_state_partner->read_configure(
			cf_str_EAPOL_key_state_retransmission_time.get_field(),
			&retransmission_time);
		if (status == eap_status_ok
			&& retransmission_time.get_is_valid_data() == true)
		{
			u32_t *retransmission_time_value = reinterpret_cast<u32_t *>(
				retransmission_time.get_data(sizeof(u32_t)));
			if (retransmission_time_value != 0)
			{
				m_retransmission_time = *retransmission_time_value;
			}
			else
			{
				m_retransmission_time = EAPOL_KEY_STATE_TIMER_RETRANSMISSION_TIMEOUT;
			}
		}
		else
		{
			m_retransmission_time = EAPOL_KEY_STATE_TIMER_RETRANSMISSION_TIMEOUT;
		}
	}

	if (m_is_client == false)
	{
		eap_variable_data_c retransmission_counter(m_am_tools);

		eap_status_e status = m_key_state_partner->read_configure(
			cf_str_EAPOL_key_state_retransmission_counter.get_field(),
			&retransmission_counter);
		if (status == eap_status_ok
			&& retransmission_counter.get_is_valid_data() == true)
		{
			u32_t *retransmission_counter_value = reinterpret_cast<u32_t *>(
				retransmission_counter.get_data(sizeof(u32_t)));
			if (retransmission_counter_value != 0)
			{
				m_retransmission_counter = *retransmission_counter_value;
			}
		}
	}

	
	{
		eap_variable_data_c session_timeout(m_am_tools);

		eap_status_e status = m_key_state_partner->read_configure(
			cf_str_EAPOL_key_state_handshake_timeout.get_field(),
			&session_timeout);
		if (status == eap_status_ok
			&& session_timeout.get_is_valid_data() == true)
		{
			u32_t *handler_timeout = reinterpret_cast<u32_t *>(
				session_timeout.get_data(sizeof(u32_t)));
			if (handler_timeout != 0)
			{
				m_handshake_timeout = *handler_timeout;
			}
		}
	}


#if defined(EAP_USE_WPXM)

	{
		eap_variable_data_c wpxm_reassociation_timeout(m_am_tools);

		eap_status_e status = m_key_state_partner->read_configure(
			cf_str_EAPOL_key_state_wpxm_reassociate_timeout.get_field(),
			&wpxm_reassociation_timeout);
		if (status == eap_status_ok
			&& wpxm_reassociation_timeout.get_is_valid_data() == true)
		{
			u32_t *handler_timeout = reinterpret_cast<u32_t *>(
				wpxm_reassociation_timeout.get_data(sizeof(u32_t)));
			if (handler_timeout != 0)
			{
				m_wpxm_reassociate_timeout = *handler_timeout;
			}
		}
	}


	if (m_is_client == false)
	{
		eap_variable_data_c EAPOL_WPXM_type(m_am_tools);

		eap_status_e status = m_key_state_partner->read_configure(
			cf_str_EAPOL_WPXM_type.get_field(),
			&EAPOL_WPXM_type);
		if (status == eap_status_ok
			&& EAPOL_WPXM_type.get_is_valid() == true
			&& EAPOL_WPXM_type.get_data_length() > 0ul
			&& EAPOL_WPXM_type.get_data(
				EAPOL_WPXM_type.get_data_length()) != 0)
		{
			if (cf_str_EAPOL_key_authentication_type_config_value_RSNA_EAP
				.get_field()->compare(
					m_am_tools,
					&EAPOL_WPXM_type) == true)
			{
				m_EAPOL_WPXM_key_descriptor_type = eapol_key_descriptor_type_RSNA;
			}
			else if (cf_str_EAPOL_key_authentication_type_config_value_WPA_EAP
					 .get_field()->compare(
						 m_am_tools,
						 &EAPOL_WPXM_type) == true)
			{
				m_EAPOL_WPXM_key_descriptor_type = eapol_key_descriptor_type_WPA;
			}
		}
	}

#endif //#if defined(EAP_USE_WPXM)


	{
		eap_variable_data_c pmksa_caching_timeout(m_am_tools);

		eap_status_e status = m_key_state_partner->read_configure(
			cf_str_EAPOL_key_state_pmksa_caching_timeout.get_field(),
			&pmksa_caching_timeout);
		if (status == eap_status_ok
			&& pmksa_caching_timeout.get_is_valid_data() == true)
		{
			u32_t *handler_timeout = reinterpret_cast<u32_t *>(
				pmksa_caching_timeout.get_data(sizeof(u32_t)));
			if (handler_timeout != 0)
			{
				m_pmksa_caching_timeout = *handler_timeout;
			}
		}
	}


	if (m_is_client == true)
	{
		{
			eap_variable_data_c allow_missing_PMKID_in_message_1(m_am_tools);

			eap_status_e status = m_key_state_partner->read_configure(
				cf_str_EAPOL_key_state_allow_missing_PMKID_in_message_1.get_field(),
				&allow_missing_PMKID_in_message_1);
			if (status == eap_status_ok
				&& allow_missing_PMKID_in_message_1.get_is_valid_data() == true)
			{
				u32_t *flag = reinterpret_cast<u32_t *>(
					allow_missing_PMKID_in_message_1.get_data(sizeof(u32_t)));
				if (flag != 0
					&& *flag != 0)
				{
					m_allow_missing_PMKID_in_message_1 = true;
				}
			}
		}

		{
			eap_variable_data_c allow_non_zero_mic_in_message_1(m_am_tools);

			eap_status_e status = m_key_state_partner->read_configure(
				cf_str_EAPOL_key_state_allow_non_zero_mic_in_message_1.get_field(),
				&allow_non_zero_mic_in_message_1);
			if (status == eap_status_ok
				&& allow_non_zero_mic_in_message_1.get_is_valid_data() == true)
			{
				u32_t *flag = reinterpret_cast<u32_t *>(
					allow_non_zero_mic_in_message_1.get_data(sizeof(u32_t)));
				if (flag != 0
					&& *flag != 0)
				{
					m_allow_non_zero_mic_and_reserved_in_message_1 = true;
				}
			}
		}

		{
			eap_variable_data_c indicate_pmkid_to_lower_layer(m_am_tools);

			eap_status_e status = m_key_state_partner->read_configure(
				cf_str_EAPOL_key_state_indicate_pmkid_to_lower_layer.get_field(),
				&indicate_pmkid_to_lower_layer);
			if (status == eap_status_ok
				&& indicate_pmkid_to_lower_layer.get_is_valid_data() == true)
			{
				u32_t *flag = reinterpret_cast<u32_t *>(
					indicate_pmkid_to_lower_layer.get_data(sizeof(u32_t)));
				if (flag != 0
					&& *flag != 0)
				{
					m_indicate_pmkid_to_lower_layer = true;
				}
			}
		}

	}

	if (m_is_client == false)
	{
		{
			eap_variable_data_c skip_PMKID_key_data_in_message_1(m_am_tools);

			eap_status_e status = m_key_state_partner->read_configure(
				cf_str_EAPOL_key_state_skip_PMKID_key_data_in_message_1.get_field(),
				&skip_PMKID_key_data_in_message_1);
			if (status == eap_status_ok
				&& skip_PMKID_key_data_in_message_1.get_is_valid_data() == true)
			{
				u32_t *flag = reinterpret_cast<u32_t *>(
					skip_PMKID_key_data_in_message_1.get_data(sizeof(u32_t)));
				if (flag != 0
					&& *flag != 0)
				{
					m_skip_PMKID_key_data_in_message_1 = true;
				}
			}
		}

		{
			eap_variable_data_c EAPOL_key_state_TEST_group_key_update(m_am_tools);

			eap_status_e status = m_key_state_partner->read_configure(
				cf_str_EAPOL_key_state_TEST_group_key_update.get_field(),
				&EAPOL_key_state_TEST_group_key_update);
			if (status == eap_status_ok
				&& EAPOL_key_state_TEST_group_key_update.get_is_valid_data() == true)
			{
				u32_t *flag = reinterpret_cast<u32_t *>(
					EAPOL_key_state_TEST_group_key_update.get_data(sizeof(u32_t)));
				if (flag != 0
					&& *flag != 0)
				{
					m_server_TEST_group_key_update = true;
				}
			}
		}

	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eapol_key_state_c::send_error_notification(const eap_status_e error)
{
	// Notifies the lower level of an authentication error.
	eap_state_notification_c notification(
		m_am_tools,
		&m_send_network_id,
		m_is_client,
		eap_state_notification_generic,
		eap_protocol_layer_general,
		eapol_key_handshake_type_none,
		eap_state_none,
		eap_general_state_authentication_error,
		0,
		false);

	notification.set_authentication_error(error);

	m_key_state_partner->state_notification(&notification);
}

//--------------------------------------------------

//
eap_status_e eapol_key_state_c::set_reassociation_parameters(
	const eap_variable_data_c * const pairwise_PMK_WPXK3,
	const eap_variable_data_c * const PMKID,
	const eap_variable_data_c * const transient_PTK,
	const eap_variable_data_c * const confirmation_KCK,
	const eap_variable_data_c * const encryption_KEK,
	const eap_variable_data_c * const temporal_TK,
	const eap_variable_data_c * const WPXM_WPXK1,
	const eap_variable_data_c * const WPXM_WPXK2,
	const u32_t WPXM_WPXC,
	const eapol_key_handshake_type_e eapol_key_handshake_type,
	const eapol_key_authentication_type_e authentication_type
	)
{
	EAP_UNREFERENCED_PARAMETER(eapol_key_handshake_type);
	EAP_UNREFERENCED_PARAMETER(authentication_type);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::set_reassociation_parameters(): this = 0x%08x, state %d=%s, m_authentication_type %d=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 get_eapol_key_state(),
		 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state()),
		 m_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

	eap_status_e status = m_pairwise_PMK_WPXK3.set_copy_of_buffer(pairwise_PMK_WPXK3);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_PMKID.set_copy_of_buffer(PMKID);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_transient_PTK.set_copy_of_buffer(transient_PTK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_confirmation_KCK.set_copy_of_buffer(confirmation_KCK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_encryption_KEK.set_copy_of_buffer(encryption_KEK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_temporal_TK.set_copy_of_buffer(temporal_TK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if defined(EAP_USE_WPXM)
	status = m_WPXM_WPXK1.set_copy_of_buffer(WPXM_WPXK1);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_WPXM_WPXK2.set_copy_of_buffer(WPXM_WPXK2);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_WPXM_WPXC = WPXM_WPXC;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: eapol_key_state_c::set_reassociation_parameters(): ")
		 EAPL("Set m_WPXM_WPXC=%d.\n"),
		 m_WPXM_WPXC));


	m_eapol_key_handshake_type = eapol_key_handshake_type;
	m_authentication_type = authentication_type;
#else
	EAP_UNREFERENCED_PARAMETER(WPXM_WPXK1);
	EAP_UNREFERENCED_PARAMETER(WPXM_WPXK2);
	EAP_UNREFERENCED_PARAMETER(WPXM_WPXC);
#endif //#if defined(EAP_USE_WPXM)

	set_eapol_key_state(eapol_key_state_preauthenticated);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::set_reassociation_parameters(): m_authentication_type=%s, ")
		 EAPL("m_eapol_pairwise_cipher=%d, m_eapol_group_cipher=%d.\n"),
		 (m_is_client == true) ? "client": "server",
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type),
		 m_eapol_pairwise_cipher,
		 m_eapol_group_cipher));
	

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::started_eap_authentication()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_key_state_c::started_eap_authentication(): %s\n"),
		 (m_is_client == true) ? "client": "server"));

	(void) cancel_handshake_timeout();
	(void) cancel_reassociate_timeout();
	(void) cancel_pmksa_caching_timeout();
	(void) cancel_4_way_handshake_start_timeout();


	{
		// Indicates lower layers the EAP authentication is running.
		eap_state_notification_c * notification = new eap_state_notification_c(
			m_am_tools,
			&m_send_network_id,
			m_is_client,
			eap_state_notification_generic,
			eap_protocol_layer_eapol_key,
			eapol_key_handshake_type_none,
			eapol_key_state_eap_authentication_running,
			eapol_key_state_eap_authentication_running,
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
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eapol_key_state_c *eapol_key_state_c::copy(const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eapol_key_state_c * const new_state = new eapol_key_state_c(
		m_am_tools,
		m_key_state_partner,
		m_eapol_partner,
		m_is_client,
		receive_network_id,
		m_authentication_type,
		&m_authenticator_RSNA_IE,
		&m_supplicant_RSNA_IE,
		m_eapol_pairwise_cipher,
		m_eapol_group_cipher,
		&m_pairwise_PMK_WPXK3);

	if (new_state == 0)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return 0;
	}

	if (new_state->get_is_valid() == false)
	{
		new_state->shutdown();
		delete new_state;
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return 0;
	}

	eap_status_e status = new_state->configure();
	if (status != eap_status_ok)
	{
		new_state->shutdown();
		delete new_state;
		(void) EAP_STATUS_RETURN(m_am_tools, status);
		return 0;
	}


	status = new_state->initialize(
		receive_network_id,
		m_authentication_type);
	if (status != eap_status_ok)
	{
		new_state->shutdown();
		delete new_state;
		(void) EAP_STATUS_RETURN(m_am_tools, status);
		return 0;
	}

	eapol_key_handshake_type_e eapol_key_handshake_type(m_eapol_key_handshake_type);

	eapol_key_authentication_type_e authentication_type(m_authentication_type);

#if defined(EAP_USE_WPXM)
	if (authentication_type == eapol_key_authentication_type_WPXM)
	{
		eapol_key_handshake_type = eapol_key_handshake_type_WPXM_reassociation;
	}
#endif //#if defined(EAP_USE_WPXM)


	status = new_state->set_reassociation_parameters(
		&m_pairwise_PMK_WPXK3,
		&m_PMKID,
		&m_transient_PTK,
		&m_confirmation_KCK,
		&m_encryption_KEK,
		&m_temporal_TK,
#if defined(EAP_USE_WPXM)
		&m_WPXM_WPXK1,
		&m_WPXM_WPXK2,
		m_WPXM_WPXC,
#else
		0,
		0,
		0ul,
#endif //#if defined(EAP_USE_WPXM)
		eapol_key_handshake_type,
		authentication_type
		);
	if (status != eap_status_ok)
	{
		new_state->shutdown();
		delete new_state;
		(void) EAP_STATUS_RETURN(m_am_tools, status);
		return 0;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return new_state;
}

//--------------------------------------------------

//
eap_status_e eapol_key_state_c::handshake_failure_notification()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eapol_key_state_string_c eapol_key_state_string;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_key_state_c::handshake_failure_notification(): %s, m_eapol_key_handshake_type=%d=%s, get_eapol_key_state()=%d=%s\n"),
		 (m_is_client == true) ? "client": "server",
		 m_eapol_key_handshake_type,
		 eapol_key_state_string.get_eapol_key_handshake_type_string(m_eapol_key_handshake_type),
		 get_eapol_key_state(),
		 eapol_key_state_string.get_eapol_key_state_string(get_eapol_key_state())));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (m_eapol_key_handshake_type == eapol_key_handshake_type_4_way_handshake)
	{
		if (get_eapol_key_state() == eapol_key_state_preauthenticated)
		{
			// Do not notify lower layer.
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_KEY: %s: eapol_key_state_c::handshake_failure_notification(): Does not notify pre-authenticated state.\n"),
				(m_is_client == true ? "client": "server")));
		}
		else if (get_eapol_key_state() == eapol_key_state_none)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_KEY: %s: eapol_key_state_c::handshake_failure_notification(): Unused EAPOL Key state.\n"),
				(m_is_client == true ? "client": "server")));
		}
		else if (get_eapol_key_state() != eapol_key_state_4_way_handshake_successfull)
		{
			// This is notification to eapol_core_c object.
			// 4-Way Handshake terminated unsuccessfully.
			eap_state_notification_c notification(
				m_am_tools,
				&m_send_network_id,
				m_is_client,
				eap_state_notification_generic,
				eap_protocol_layer_eapol_key,
				eapol_key_handshake_type_4_way_handshake,
				eapol_key_state_4_way_handshake_failed,
				eapol_key_state_802_11i_authentication_terminated_unsuccessfull,
				0ul,
				false);

			notification.set_authentication_error(eap_status_authentication_failure);

			m_key_state_partner->state_notification(&notification);

			set_eapol_key_state(eapol_key_state_4_way_handshake_failed);

			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_KEY: %s: eapol_key_state_c::handshake_failure_notification(): 4-Way Handshake FAILED\n"),
				(m_is_client == true ? "client": "server")));
		}
	}
	else if (m_eapol_key_handshake_type == eapol_key_handshake_type_group_key_handshake)
	{
		if (get_eapol_key_state() == eapol_key_state_preauthenticated)
		{
			// Do not notify lower layer.
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_KEY: %s: eapol_key_state_c::handshake_failure_notification(): Does not notify pre-authenticated state.\n"),
				(m_is_client == true ? "client": "server")));
		}
		else if (get_eapol_key_state() == eapol_key_state_none)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_KEY: %s: eapol_key_state_c::handshake_failure_notification(): Unused EAPOL Key state.\n"),
				(m_is_client == true ? "client": "server")));
		}
		else if (get_eapol_key_state() != eapol_key_state_group_key_handshake_successfull)
		{
			// This is notification to eapol_core_c object.
			// Group Key Handshake terminated unsuccessfully.
			eap_state_notification_c notification(
				m_am_tools,
				&m_send_network_id,
				m_is_client,
				eap_state_notification_generic,
				eap_protocol_layer_eapol_key,
				eapol_key_handshake_type_group_key_handshake,
				eapol_key_state_group_key_handshake_failed,
				eapol_key_state_802_11i_authentication_terminated_unsuccessfull,
				0ul,
				false);

			notification.set_authentication_error(eap_status_authentication_failure);

			m_key_state_partner->state_notification(&notification);

			set_eapol_key_state(eapol_key_state_4_way_handshake_failed);

			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_KEY: %s: eapol_key_state_c::handshake_failure_notification(): Group Key Handshake FAILED\n"),
				(m_is_client == true ? "client": "server")));
		}
	}
	else if (m_eapol_key_handshake_type == eapol_key_handshake_type_none
		|| m_eapol_key_handshake_type == eapol_key_handshake_type_authenticated)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: %s: eapol_key_state_c::handshake_failure_notification(): Unused EAPOL Key state.\n"),
			(m_is_client == true ? "client": "server")));
	}
	else
	{
		EAP_UNREFERENCED_PARAMETER(eapol_key_state_string);

		set_eapol_key_state(eapol_key_state_4_way_handshake_failed);

		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: %s: eapol_key_state_c::handshake_failure_notification(): Unknown Handshake FAILED\n"),
			(m_is_client == true ? "client": "server")));
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_key_state_c::shutdown(): %s\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (m_shutdown_was_called == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eapol_key_state_c::shutdown(): Already called.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	// This will cancel all timers of this object.
	cancel_retransmission();
	cancel_handshake_timeout();
	cancel_pmksa_caching_timeout();
	cancel_reassociate_timeout();
	cancel_4_way_handshake_start_timeout();

	eap_status_e status = handshake_failure_notification();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::set_s_nonce(
	const eap_variable_data_c * const s_nonce)
{
	eap_status_e status = m_SNonce.set_copy_of_buffer(s_nonce);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::check_pmksa_cache(
	const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_key_state_c::check_pmksa_cache(): %s\n"),
		 (m_is_client == true) ? "client": "server"));

	eap_status_e status = eap_status_ok;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::check_pmksa_cache(): this = 0x%08x, state %d=%s,\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 get_eapol_key_state(),
		 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state())));

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::check_pmksa_cache(): selected_eapol_key_authentication_type %d=%s, m_authentication_type %d=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 selected_eapol_key_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(selected_eapol_key_authentication_type),
		 m_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));


	if (selected_eapol_key_authentication_type != eapol_key_authentication_type_RSNA_EAP
		&& selected_eapol_key_authentication_type != eapol_key_authentication_type_RSNA_PSK
		&& selected_eapol_key_authentication_type != eapol_key_authentication_type_WPXM)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}
	else if (selected_eapol_key_authentication_type != m_authentication_type
		|| pairwise_key_cipher_suite != m_eapol_pairwise_cipher
		|| group_key_cipher_suite != m_eapol_group_cipher)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::initialize_preauthentication(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::initialize_preauthentication(): this = 0x%08x, state %d=%s, m_authentication_type %d=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 get_eapol_key_state(),
		 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state()),
		 m_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_authentication_type != authentication_type)
	{
		// Illegal authentication type, must be the same as previously used.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_authentication_type == eapol_key_authentication_type_none
		|| m_authentication_type == eapol_key_authentication_type_RSNA_PSK
		|| m_authentication_type == eapol_key_authentication_type_WPA_PSK
		|| m_authentication_type == eapol_key_authentication_type_dynamic_WEP
		|| m_authentication_type == eapol_key_authentication_type_EAP_authentication_no_encryption
		)
	{
		// Illegal authentication type.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	set_eapol_key_state(eapol_key_state_none);
	m_eapol_key_handshake_type = eapol_key_handshake_type_none;

	reset();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = set_mac_addresses(receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_eapol_key_state(eapol_key_state_none);
	m_eapol_key_handshake_type = eapol_key_handshake_type_none;

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::read_reassociation_parameters(
	const eap_am_network_id_c * const /* receive_network_id */, ///< source includes remote address, destination includes local address.
	const eapol_key_authentication_type_e required_authentication_type,
	eap_variable_data_c * const PMKID,
	const eap_variable_data_c * const received_WPA_ie,
	const eap_variable_data_c * const sent_WPA_ie)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::read_reassociation_parameters(): this = 0x%08x, state %d=%s, m_authentication_type %d=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 get_eapol_key_state(),
		 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state()),
		 m_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));


	(void) cancel_pmksa_caching_timeout();
	(void) cancel_handshake_timeout();
	(void) cancel_reassociate_timeout();
	(void) cancel_4_way_handshake_start_timeout();

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (received_WPA_ie != 0
		&& received_WPA_ie->get_is_valid_data() == true)
	{
		status = m_authenticator_RSNA_IE.set_copy_of_buffer(received_WPA_ie);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (sent_WPA_ie != 0
		&& sent_WPA_ie->get_is_valid_data() == true)
	{
		status = m_supplicant_RSNA_IE.set_copy_of_buffer(sent_WPA_ie);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Creates SNonce. This is done here in early phase of authentication.
	// This will reduce the CPU load when time critical first message
	// of 4-Way handshake is processed.
	status = create_nonce(&m_SNonce, EAPOL_RSNA_NONCE_LENGTH_BYTES);
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


	if (get_eapol_key_state() != eapol_key_state_preauthenticated
		|| m_authentication_type != required_authentication_type)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: EAPOL_KEY: %s: eapol_key_state_c::read_reassociation_parameters(): this = 0x%08x, (get_eapol_key_state()=%d=%s) != (eapol_key_state_preauthenticated)\n"),
			 (m_is_client == true) ? "client": "server",
			 this,
			 get_eapol_key_state(),
			 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state())));

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: EAPOL_KEY: %s: || (m_authentication_type=%d=%s) != (required_authentication_type=%d=%s)\n"),
			 (m_is_client == true) ? "client": "server",
			 m_authentication_type,
			 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type),
			 required_authentication_type,
			 eapol_key_state_string_c::get_eapol_key_authentication_type_string(required_authentication_type)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	if (get_is_RSNA() == true)
	{
		if (m_pairwise_PMK_WPXK3.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}

		status = create_PMKID();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		status = PMKID->set_copy_of_buffer(&m_PMKID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#if defined(EAP_USE_WPXM)
	else if (get_is_WPXM() == true)
	{
		// We need to create a new PTKn.
		++m_WPXM_WPXC;

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAPOL_KEY: eapol_key_state_c::read_reassociation_parameters(): ")
			 EAPL("m_WPXM_WPXC=%d.\n"),
			 m_WPXM_WPXC));		
		
		status = derive_WPXM_PTK(m_WPXM_WPXC);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = init_reassociate_timeout(m_wpxm_reassociate_timeout);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
#endif //#if defined(EAP_USE_WPXM)
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::complete_reassociation(
	const eapol_wlan_authentication_state_e reassociation_result,
	const eap_am_network_id_c * const /* receive_network_id */,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const received_WPA_IE,
	const eap_variable_data_c * const sent_WPA_IE,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_key_state_c::complete_reassociation(): %s\n"),
		 (m_is_client == true) ? "client": "server"));

	eap_status_e status(eap_status_process_general_error);

	if (get_eapol_key_state() != eapol_key_state_preauthenticated
		|| m_authentication_type != authentication_type)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	if (reassociation_result == eapol_wlan_authentication_state_association_ok)
	{
		if (get_is_RSNA() == true)
		{
			status = allow_4_way_handshake();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = save_parameters(
				authentication_type,
				received_WPA_IE,
				sent_WPA_IE,
				pairwise_key_cipher_suite,
				group_key_cipher_suite);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
#if defined(EAP_USE_WPXM)
		else if (get_is_WPXM() == true)
		{
			// OK, nothing to do here.
			status = eap_status_ok;
		}
#endif //#if defined(EAP_USE_WPXM)
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}

		{
			m_is_associated = true;

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("EAPOL_KEY: %s: eapol_key_state_c::complete_reassociation(): m_is_associated=%s.\n"),
				 (m_is_client == true) ? "client": "server",
				 (m_is_associated == true) ? "true": "false"));
		}
	}
	else
	{
		// Reassociation failed, clean-up state.
		reset();

		// Timeout value zero will remove state immediately.
		status = init_handshake_timeout(0ul);
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

//
EAP_FUNC_EXPORT bool eapol_key_state_c::get_is_RSNA()
{
	return (m_authentication_type == eapol_key_authentication_type_RSNA_EAP
		|| m_authentication_type == eapol_key_authentication_type_RSNA_PSK);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eapol_key_state_c::get_is_WPA()
{
	return (m_authentication_type == eapol_key_authentication_type_WPA_EAP
		|| m_authentication_type == eapol_key_authentication_type_WPA_PSK);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::asynchronous_init_remove_eapol_key_state()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = handshake_failure_notification();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_key_state_partner->asynchronous_init_remove_eapol_key_state(
		&m_send_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(data);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: EAPOL_KEY: %s: [0x%08x]->eapol_key_state_c::timer_expired(id 0x%02x, data 0x%08x).\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 id,
		 data));

	if (id == EAPOL_KEY_STATE_TIMER_HANDSHAKE_TIMEOUT_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_HANDSHAKE_TIMEOUT_ID expired, eapol_key_state=%d=%s\n"),
			 (m_is_client == true ? "client": "server"),
			 get_eapol_key_state(),
			 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state())));

		if ((m_is_client == true
			&& get_eapol_key_state() == eapol_key_state_wait_4_way_handshake_message_3)
			|| (m_is_client == false
				&& get_eapol_key_state() == eapol_key_state_wait_4_way_handshake_message_2))
		{
			if (m_authentication_type == eapol_key_authentication_type_RSNA_PSK
				|| m_authentication_type == eapol_key_authentication_type_WPA_PSK)
			{
				// Most propably the PSK is incorrect.
				// There could be other problems too.
				send_error_notification(eap_status_wrong_password);
			}
			else if (m_authentication_type == eapol_key_authentication_type_RSNA_EAP
					|| m_authentication_type == eapol_key_authentication_type_WPA_EAP
					|| m_authentication_type == eapol_key_authentication_type_dynamic_WEP
					|| m_authentication_type == eapol_key_authentication_type_WPXM
					|| m_authentication_type == eapol_key_authentication_type_EAP_authentication_no_encryption
					)
			{
				send_error_notification(eap_status_authentication_failure);
			}
		}
		else if (get_eapol_key_state() != eapol_key_state_none)
		{
			send_error_notification(eap_status_authentication_failure);
		}

		// Terminate the session.
		status = asynchronous_init_remove_eapol_key_state();
	}
	else if (id == EAPOL_KEY_STATE_TIMER_RETRANSMISSION_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_RETRANSMISSION_ID elapsed.\n"),
			 (m_is_client == true ? "client": "server")));

		if (m_retransmission != 0
			&& m_retransmission->get_is_valid() == true
			&& m_retransmission->get_retransmission_counter() > 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TIMER: EAPOL_KEY: new retransmission, m_retransmission->get_is_valid()=%d, ")
				 EAPL("m_retransmission->get_retransmission_counter()=%d.\n"),
				m_retransmission->get_is_valid(),
				m_retransmission->get_retransmission_counter()));

			// This packet send is initialized by timer event.
			status = resend_packet(
				m_retransmission->get_send_network_id(),
				m_retransmission->get_sent_packet(),
				m_retransmission->get_header_offset(),
				m_retransmission->get_data_length(),
				m_retransmission->get_buffer_size()
				);

			if (status == eap_status_ok)
			{
				if (m_retransmission->get_retransmission_counter() > 0u)
				{
					// OK, initialize the next time to retransmit.
					u32_t next_retransmission_time(m_retransmission->get_next_retransmission_time());

					status = m_key_state_partner->set_timer(this, EAPOL_KEY_STATE_TIMER_RETRANSMISSION_ID, 0,
						next_retransmission_time);
					if (status != eap_status_ok)
					{
						delete m_retransmission;
						m_retransmission = 0;
					}
					else
					{
						m_retransmission->get_next_retransmission_counter(); // This decrements the counter.

						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("TIMER: EAPOL_KEY: EAPOL_KEY_STATE_TIMER_RETRANSMISSION_ID set %d ms, retransmission_counter %d.\n"),
							next_retransmission_time,
							m_retransmission->get_retransmission_counter()));
					}
				}

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else
			{
				delete m_retransmission;
				m_retransmission = 0;

				status = eap_status_ok;

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("TIMER: EAPOL_KEY: no retransmission, m_retransmission=0x%08x.\n"),
				m_retransmission));
			if (m_retransmission != 0)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("TIMER: EAPOL_KEY: no retransmission, m_retransmission->get_is_valid()=%d, ")
					 EAPL("m_retransmission->get_retransmission_counter()=%d.\n"),
					m_retransmission->get_is_valid(),
					m_retransmission->get_retransmission_counter()));
			}

			// No good EAPOL-Key-Response received to EAPOL-Key-Requests.
			// Terminate the session.
			status = asynchronous_init_remove_eapol_key_state();
		}
	}
	else if (id == EAPOL_KEY_STATE_TIMER_PMKSA_CACHING_TIMEOUT_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_PMKSA_CACHING_TIMEOUT_ID expired.\n"),
			 (m_is_client == true ? "client": "server")));

		// Caching timeout.
		// Remove the cached session.
		status = asynchronous_init_remove_eapol_key_state();
	}
#if defined(EAP_USE_WPXM)
	else if (id == EAPOL_KEY_STATE_TIMER_REASSOCIATE_TIMEOUT_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_REASSOCIATE_TIMEOUT_ID expired.\n"),
			 (m_is_client == true ? "client": "server")));

			eap_state_notification_c notification(
				m_am_tools,
				&m_send_network_id,
				m_is_client,
				eap_state_notification_generic,
				eap_protocol_layer_eapol_key,
				eapol_key_handshake_type_WPXM_reassociation,
				get_eapol_key_state(),
				eapol_key_state_reassociation_failed,
				0ul,
				false);

			notification.set_authentication_error(eap_status_authentication_failure);

			m_key_state_partner->state_notification(&notification);

		// Remove the cached session.
		status = asynchronous_init_remove_eapol_key_state();
	}
#endif //#if defined(EAP_USE_WPXM)
	else if (id == EAPOL_KEY_STATE_TIMER_GROUP_KEY_UPDATE_TIMEOUT_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_GROUP_KEY_UPDATE_TIMEOUT_ID expired.\n"),
			 (m_is_client == true ? "client": "server")));
		
		// Here we swap the addresses.
		eap_am_network_id_c receive_network_id(m_am_tools,
			m_send_network_id.get_destination_id(),
			m_send_network_id.get_source_id(),
			m_send_network_id.get_type());
		if (receive_network_id.get_is_valid_data() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = start_group_key_handshake(
			&receive_network_id,
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
	}
	else if (id == EAPOL_KEY_STATE_TIMER_INITIALIZE_4_WAY_HANDSHAKE_TIMEOUT_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_INITIALIZE_4_WAY_HANDSHAKE_TIMEOUT_ID expired.\n"),
			 (m_is_client == true ? "client": "server")));
		
		// Here we swap the addresses.
		eap_am_network_id_c receive_network_id(m_am_tools,
			m_send_network_id.get_destination_id(),
			m_send_network_id.get_source_id(),
			m_send_network_id.get_type());
		if (receive_network_id.get_is_valid_data() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = initialize_4_way_handshake(
			&receive_network_id,
			eapol_protocol_version_2);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(data);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: EAPOL_KEY: %s: [0x%08x]->eapol_key_state_c::timer_delete_data(id 0x%02x, data 0x%08x).\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 id,
		 data));
	
	if (id == EAPOL_KEY_STATE_TIMER_HANDSHAKE_TIMEOUT_ID)
	{
		// Nothing to delete.
	}
	else if (id == EAPOL_KEY_STATE_TIMER_RETRANSMISSION_ID)
	{
		if (m_retransmission != 0
			&& m_retransmission->get_is_valid() == true
			&& m_retransmission->get_retransmission_counter() > 0)
		{
			// Do not delete yet.
			// cancel_retransmission() will delete m_retransmission.
		}
		else if (m_retransmission != 0)
		{
			delete m_retransmission;
			m_retransmission = 0;
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------


//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::trace_eapol_key_message(
	const i8_t * const prefix,
	eapol_RSNA_key_header_c * const eapol_key_message)
{
	EAP_UNREFERENCED_PARAMETER(prefix);
	EAP_UNREFERENCED_PARAMETER(eapol_key_message);

#if defined(USE_EAP_TRACE)

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	u32_t  key_replay_counter_high = static_cast<u32_t>(eap_shift_right_64_bit(
		eapol_key_message->get_key_replay_counter(), 32));
	u32_t  key_replay_counter_low = static_cast<u32_t>(eapol_key_message->get_key_replay_counter());

	EAP_UNREFERENCED_PARAMETER(key_replay_counter_high);
	EAP_UNREFERENCED_PARAMETER(key_replay_counter_low);

	if (get_is_RSNA() == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): eapol version 0x%02x, eapol packet type 0x%02x, ")
			 EAPL("eapol packet body length 0x%04x\n"),
			 prefix,
			 (eapol_key_message),
			 (eapol_key_message)->get_eapol_protocol_version(),
			 (eapol_key_message)->get_eapol_packet_type(),
			 (eapol_key_message)->get_eapol_packet_body_length()
			 ));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): eapol key descriptor type 0x%02x, ")
			 EAPL("key information 0x%04x, ")
			 EAPL("key information key descriptor version 0x%01x\n"),
			 prefix,
			 (eapol_key_message),
			 (eapol_key_message)->get_key_descriptor_type(),
			 (eapol_key_message)->get_key_information(),
			 (eapol_key_message)->get_key_information_key_descriptor_version()
			 ));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): key information key type 0x%01x, ")
			 EAPL("key information reserved 0x%01x, ")
			 EAPL("key information install 0x%01x\n"),
			 prefix,
			 (eapol_key_message),
			 (eapol_key_message)->get_key_information_key_type(),
			 (eapol_key_message)->get_key_information_reserved_a(),
			 (eapol_key_message)->get_key_information_install()
			 ));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): key information key ack 0x%01x, ")
			 EAPL("key information key MIC 0x%01x, ")
			 EAPL("key information secure 0x%01x\n"),
			 prefix,
			 (eapol_key_message),
			 (eapol_key_message)->get_key_information_key_ack(),
			 (eapol_key_message)->get_key_information_key_MIC(),
			 (eapol_key_message)->get_key_information_secure()
			 ));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): key information error 0x%01x, ")
			 EAPL("key information request 0x%01x, ")
			 EAPL("key information encrypted key data 0x%01x\n"),
			 prefix,
			 (eapol_key_message),
			 (eapol_key_message)->get_key_information_error(),
			 (eapol_key_message)->get_key_information_request(),
			 (eapol_key_message)->get_key_information_encrypted_key_data()
			 ));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): key information reserved 0x%01x, ")
			 EAPL("key length 0x%04x, key reply counter 0x%08x%08x\n"),
			 prefix,
			 (eapol_key_message),
			 (eapol_key_message)->get_key_information_reserved_b(),
			 (eapol_key_message)->get_key_length(),
			 key_replay_counter_high,
			 key_replay_counter_low
			 ));
	}
	else if (get_is_WPA() == true
#if defined(EAP_USE_WPXM)
		|| get_is_WPXM() == true
#endif //#if defined(EAP_USE_WPXM)
		)
	{
		// According to 802.11i D3.0

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): eapol version 0x%02x, eapol packet type 0x%02x, ")
			 EAPL("eapol packet body length 0x%04x\n"),
			 prefix,
			 (eapol_key_message),
			 (eapol_key_message)->get_eapol_protocol_version(),
			 (eapol_key_message)->get_eapol_packet_type(),
			 (eapol_key_message)->get_eapol_packet_body_length()
			 ));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): eapol key descriptor type 0x%02x, ")
			 EAPL("key information 0x%04x, ")
			 EAPL("key information key descriptor version 0x%01x\n"),
			 prefix,
			 (eapol_key_message),
			 (eapol_key_message)->get_key_descriptor_type(),
			 (eapol_key_message)->get_key_information(),
			 (eapol_key_message)->get_key_information_key_descriptor_version()
			 ));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): key information key type 0x%01x, ")
			 EAPL("key information key index 0x%01x, ")
			 EAPL("key information install 0x%01x\n"),
			 prefix,
			 (eapol_key_message),
			 (eapol_key_message)->get_key_information_key_type(),
			 (eapol_key_message)->get_key_information_key_index(),
			 (eapol_key_message)->get_key_information_install()
			 ));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): key information key ack 0x%01x, ")
			 EAPL("key information key MIC 0x%01x, ")
			 EAPL("key information secure 0x%01x\n"),
			 prefix,
			 (eapol_key_message),
			 (eapol_key_message)->get_key_information_key_ack(),
			 (eapol_key_message)->get_key_information_key_MIC(),
			 (eapol_key_message)->get_key_information_secure()
			 ));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): key information error 0x%01x, ")
			 EAPL("key information request 0x%01x, ")
			 EAPL("key information encrypted key data 0x%01x\n"),
			 prefix,
			 (eapol_key_message),
			 (eapol_key_message)->get_key_information_error(),
			 (eapol_key_message)->get_key_information_request(),
			 (eapol_key_message)->get_key_information_encrypted_key_data()
			 ));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): key information reserved 0x%02x, ")
			 EAPL("key length 0x%04x, key reply counter 0x%08x%08x\n"),
			 prefix,
			 (eapol_key_message),
			 (eapol_key_message)->get_key_information_reserved_b(),
			 (eapol_key_message)->get_key_length(),
			 key_replay_counter_high,
			 key_replay_counter_low
			 ));
	}
	else
	{
		// ERROR.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("key nonce"),
		 (eapol_key_message)->get_key_NONCE(),
		 eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_NONCE_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("EAPOL-Key IV"),
		 (eapol_key_message)->get_EAPOL_key_IV(),
		 eapol_RSNA_key_header_c::EAPOL_RSNA_EAPOL_KEY_IV_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("Key RSC"),
		 (eapol_key_message)->get_key_RSC(),
		 eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RSC_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("STA MAC address"),
		 (eapol_key_message)->get_key_STA_MAC_address(),
		 eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_STA_MAC_ADDRESS_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("reserved"),
		 (eapol_key_message)->get_key_reserved(),
		 eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_RESERVED_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("Key MIC"),
		 (eapol_key_message)->get_key_MIC(),
		 eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_MIC_SIZE));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("Key Data"),
		 (eapol_key_message)->get_key_data((eapol_key_message)->get_key_data_length()),
		 (eapol_key_message)->get_key_data_length()));

#endif //#if defined(USE_EAP_TRACE)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


//--------------------------------------------------


//
eap_status_e eapol_key_state_c::trace_eapol_rsna_key_data_payload(
	const bool is_RSNA,
	const bool is_WPXM,
	const eapol_key_descriptor_type_e eapol_key_descriptor_type,
	const i8_t * const prefix,
	const eapol_rsna_key_data_header_c * const key_data_payload,
	const u32_t buffer_length)
{
	EAP_UNREFERENCED_PARAMETER(is_RSNA);
	EAP_UNREFERENCED_PARAMETER(prefix);
	EAP_UNREFERENCED_PARAMETER(key_data_payload);
	EAP_UNREFERENCED_PARAMETER(buffer_length);
	EAP_UNREFERENCED_PARAMETER(is_WPXM);
	EAP_UNREFERENCED_PARAMETER(eapol_key_descriptor_type);

#if defined(USE_EAP_TRACE)

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if ((is_RSNA == true
			|| (is_WPXM == true && eapol_key_descriptor_type == eapol_key_descriptor_type_RSNA))
		&& key_data_payload->get_descriptor_type() == eapol_RSNA_key_data_type_RSN_key_data)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): descriptor type 0x%04x=%s\n"),
			prefix,
			key_data_payload,
			key_data_payload->get_descriptor_type(),
			key_data_payload->get_descriptor_type_string()));

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): key_data_payload 0x%04x=%s\n"),
			prefix,
			key_data_payload,
			key_data_payload->get_payload_type(),
			key_data_payload->get_payload_type_string()));

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): payload length 0x%04x, buffer length 0x%04x.\n"),
			prefix,
			key_data_payload,
			key_data_payload->get_header_and_body_length(),
			buffer_length));

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: key_data_payload"),
			(key_data_payload->get_header_buffer(key_data_payload->get_header_buffer_length())),
			key_data_payload->get_header_buffer_length()));
	}
	else if ((is_RSNA == true
				|| (is_WPXM == true && eapol_key_descriptor_type == eapol_key_descriptor_type_RSNA))
		&& key_data_payload->get_descriptor_type() == eapol_RSNA_key_data_type_RSN_IE)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): descriptor type 0x%04x=%s.\n"),
			prefix,
			key_data_payload,
			key_data_payload->get_descriptor_type(),
			key_data_payload->get_descriptor_type_string()));

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): payload length 0x%04x, buffer length 0x%04x, RSN IE.\n"),
			prefix,
			key_data_payload,
			key_data_payload->get_header_and_body_length(),
			buffer_length));

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: RSN IE"),
			(key_data_payload->get_header_buffer(key_data_payload->get_header_buffer_length())),
			key_data_payload->get_header_buffer_length()));
	}
	else if (key_data_payload->get_descriptor_type() == eapol_RSNA_key_data_type_WPA_IE
		&& eapol_key_descriptor_type == eapol_key_descriptor_type_WPA)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): descriptor type 0x%04x=%s.\n"),
			prefix,
			key_data_payload,
			key_data_payload->get_descriptor_type(),
			key_data_payload->get_descriptor_type_string()));

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): payload length 0x%04x, buffer length 0x%04x, WPA IE.\n"),
			prefix,
			key_data_payload,
			key_data_payload->get_header_and_body_length(),
			buffer_length));

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: WPA IE"),
			(key_data_payload->get_header_buffer(key_data_payload->get_header_buffer_length())),
			key_data_payload->get_header_buffer_length()));
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): descriptor type 0x%04x=%s.\n"),
			prefix,
			key_data_payload,
			key_data_payload->get_descriptor_type(),
			key_data_payload->get_descriptor_type_string()));

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: %s (0x%08x): payload length 0x%04x, buffer length 0x%04x, Unknown data.\n"),
			prefix,
			key_data_payload,
			key_data_payload->get_header_and_body_length(),
			buffer_length));

		u32_t max_length = (buffer_length < key_data_payload->get_header_buffer_length())
			? buffer_length : key_data_payload->get_header_buffer_length();

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("EAPOL_KEY: Unknown data"),
			(key_data_payload->get_header_buffer(max_length)),
			max_length));
	}

#endif //#if defined(USE_EAP_TRACE)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_variable_data_c * eapol_key_state_c::get_authenticator_RSNA_IE()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_authenticator_RSNA_IE;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_variable_data_c * eapol_key_state_c::get_unicast_cipher_suite_RSNA_IE()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_unicast_cipher_suite_RSNA_IE;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_variable_data_c * eapol_key_state_c::get_supplicant_RSNA_IE()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_supplicant_RSNA_IE;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_variable_data_c * eapol_key_state_c::get_received_PMKID()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_received_PMKID;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_variable_data_c * eapol_key_state_c::get_supplicant_MAC_address()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_supplicant_MAC_address;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_variable_data_c * eapol_key_state_c::get_authenticator_MAC_address()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_authenticator_MAC_address;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT u64_t eapol_key_state_c::get_key_reply_counter()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_key_reply_counter;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eapol_key_state_c::increase_key_reply_counter()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	++m_key_reply_counter;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
		(EAPL("Incresed Local Reply Counter"),
		&m_key_reply_counter,
		sizeof(m_key_reply_counter)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eapol_key_state_c::set_key_reply_counter(const u64_t reply_counter)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_key_reply_counter = reply_counter;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
		(EAPL("Set Local Reply Counter"),
		&m_key_reply_counter,
		sizeof(m_key_reply_counter)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT u64_t eapol_key_state_c::get_client_send_key_reply_counter()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_client_send_key_reply_counter;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eapol_key_state_c::increase_client_send_key_reply_counter()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	++m_client_send_key_reply_counter;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
		(EAPL("Increased Client Send Reply Counter"),
		&m_client_send_key_reply_counter,
		sizeof(m_client_send_key_reply_counter)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eapol_key_state_c::set_client_send_key_reply_counter(const u64_t reply_counter)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_client_send_key_reply_counter = reply_counter;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
		(EAPL("Set Client Send Reply Counter"),
		&m_client_send_key_reply_counter,
		sizeof(m_client_send_key_reply_counter)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_variable_data_c * eapol_key_state_c::get_ANonce()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_ANonce;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_variable_data_c * eapol_key_state_c::get_SNonce()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_SNonce;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_variable_data_c * eapol_key_state_c::get_confirmation_KCK()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_confirmation_KCK;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_variable_data_c * eapol_key_state_c::get_encryption_KEK()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return &m_encryption_KEK;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::check_is_aes_key_wrap_padding(
	const eapol_RSNA_key_descriptor_type_e /* current_key_data_type */,
	eapol_rsna_key_data_header_c * const key_data_payload,
	const u32_t key_data_max_length
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (key_data_max_length > 1ul)
	{
		u8_t * const data = key_data_payload->get_header_buffer(key_data_max_length);

		// The first byte is eapol_RSNA_key_data_type_RSN_key_data.
		// The following padding bytes are zero bytes.
		for (u32_t ind = 1ul; ind < key_data_max_length; ind++)
		{
			if (data[ind] != 0ul)
			{
				// Padding must be zero byte.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return eap_status_illegal_padding;
			}
		} // for()
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::parse_generic_key_data_payload(
	const eapol_key_descriptor_type_e eapol_key_descriptor_type,
	const eapol_RSNA_key_descriptor_type_e current_key_descriptor_type,
	eapol_rsna_key_data_header_c * const key_data_payload,
	u32_t * const key_data_max_length,
	eapol_rsna_key_data_payloads_c * const p_rsna_key_data_payloads,
	const eapol_key_state_e expected_key_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAPOL_RSNA_KEY_DATA_TRACE_PAYLOAD(
		get_is_RSNA(),
		get_is_WPXM(),
		eapol_key_descriptor_type,
		"eapol_key_state_c::parse_generic_key_data_payload(): Parsing EAPOL Key Data key_data_payload",
		key_data_payload,
		*key_data_max_length);

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_key_state_c::parse_generic_key_data_payload()");

	{
		eapol_key_state_string_c debug_string;
		EAP_UNREFERENCED_PARAMETER(debug_string);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
			 EAPL("current key_data_payload_type 0x%04x=%s.\n"),
			 key_data_payload,
			 current_key_descriptor_type,
			 key_data_payload->get_descriptor_type_string()));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
			 EAPL("eapol_key_descriptor_type 0x%02x=%s.\n"),
			 key_data_payload,
			 eapol_key_descriptor_type,
			 debug_string.get_eapol_key_descriptor_type_string(eapol_key_descriptor_type)));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
			 EAPL("payload length is 0x%04x, key_data_max_length is 0x%08x.\n"),
			 key_data_payload,
			 key_data_payload->get_header_and_body_length(),
			 *key_data_max_length));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
			 EAPL("expected_key_message = %s = 0x%08x.\n"),
			 key_data_payload,
			 debug_string.get_eapol_key_state_string(expected_key_message),
			 expected_key_message));
	}

	if (current_key_descriptor_type == eapol_RSNA_key_data_type_RSN_key_data
		&& check_is_aes_key_wrap_padding(
			current_key_descriptor_type,
			key_data_payload,
			*key_data_max_length) == eap_status_ok)
	{
		if (get_is_RSNA() == false)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): AES key wrapping padding in non RSNA\n"),
				 key_data_payload));
		}

		if (eapol_key_descriptor_type != eapol_key_descriptor_type_RSNA)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): AES key wrapping padding in non RSNA, eapol_key_descriptor_type=%d\n"),
				 key_data_payload,
				 eapol_key_descriptor_type));
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): AES key wrapping padding, %d bytes\n"),
			 key_data_payload,
			 *key_data_max_length));

		// This is AES key wrap padding.
		*key_data_max_length = 0ul;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else if (*key_data_max_length < eapol_rsna_key_data_header_c::EAPOL_RSNA_IE_MINIMUM_SIZE
		|| key_data_payload->get_header_and_body_length() == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
			 EAPL("current key_data_payload_type 0x%04x=%s, payload length is 0x%04x, key_data_max_length is 0x%08x.\n"),
			 key_data_payload,
			 current_key_descriptor_type,
			 key_data_payload->get_descriptor_type_string(),
			 key_data_payload->get_header_and_body_length(),
			 *key_data_max_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);		
	}


	if ((get_is_RSNA() == true
			|| get_is_WPXM() == true)
		&& eapol_key_descriptor_type == eapol_key_descriptor_type_RSNA
		&& current_key_descriptor_type == eapol_RSNA_key_data_type_RSN_key_data)
	{
		eapol_RSNA_key_payload_type_e current_key_data_type = key_data_payload->get_payload_type();

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): current_key_data_type = %s = 0x%02x\n"),
			 key_data_payload,
			 key_data_payload->get_payload_type_string(),
			 current_key_data_type));

		if (current_key_data_type == eapol_RSNA_key_payload_type_group_key_and_id
			&& m_is_client == true
			&& (expected_key_message == eapol_key_state_wait_4_way_handshake_message_3
				|| expected_key_message == eapol_key_state_wait_group_key_handshake_message_1))
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): Key ID and Group Key\n"),
				 key_data_payload));

			/*  Key ID and Group Key:
			 *  0                   1                   2                   3
			 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * | Type = 0xdd   | Length        | OUI 3 octets               ...|
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * | ... OUI       | Data Type 1   | Key ID and Tx | Reserved 0    |
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * | GTK (Length - 6) octets                                       |
			 * +-                                                             -+
			 * :                                                               :
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 */
			if (key_data_payload->get_key_data_payload_length()
				< eapol_rsna_key_data_header_c::EAPOL_RSNA_KEY_ID_AND_GROUP_KEY_MINIMUM_SIZE)
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
					 EAPL("current key_data_payload 0x%04x=%s, data length incorrect 0x%04x.\n"),
					 key_data_payload,
					 current_key_data_type,
					 key_data_payload->get_descriptor_type_string(),
					 key_data_payload->get_key_data_payload_length()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}


			const u32_t buffer_length = key_data_payload->get_key_data_payload_length();

			u8_t * const buffer
				= static_cast<u8_t *>(key_data_payload->get_key_data_payload(buffer_length));

			if (buffer == 0)
			{
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
					 EAPL("current key_data_payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
					 key_data_payload,
					 current_key_data_type,
					 key_data_payload->get_payload_type_string(),
					 key_data_payload->get_key_data_payload_length()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}


			eapol_rsna_key_data_gtk_header_c gtk_header(
				m_am_tools,
				buffer,
				buffer_length);
			if (gtk_header.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_status_e status = gtk_header.check_header();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			p_rsna_key_data_payloads->set_group_key_id(gtk_header.get_key_index());
			p_rsna_key_data_payloads->set_group_key_tx(gtk_header.get_tx_bit());

			u32_t group_key_header_length = eapol_rsna_key_data_gtk_header_c::get_header_length();

			// Note here we get a reference to the data bytes of the received packet.
			status = p_rsna_key_data_payloads->get_group_key()->set_buffer(
				key_data_payload,
				gtk_header.get_gtk(key_data_payload->get_key_data_payload_length()-group_key_header_length),
				key_data_payload->get_key_data_payload_length()-group_key_header_length,
				false,
				false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("received RSN Group Key ID %d, Tx %d\n"),
				 p_rsna_key_data_payloads->get_group_key_id(),
				 p_rsna_key_data_payloads->get_group_key_tx()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("received RSN Group Key"),
				 p_rsna_key_data_payloads->get_group_key()->get_data(
					 p_rsna_key_data_payloads->get_group_key()->get_data_length()),
				 p_rsna_key_data_payloads->get_group_key()->get_data_length()));
		}
		else if (current_key_data_type == eapol_RSNA_key_payload_type_sta_key)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): STAKey\n"),
				 key_data_payload));

			/*  STAKey:
			 *  0                   1                   2                   3
			 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * | Type = 0xdd   | Length        | OUI 3 octets               ...|
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * | ... OUI       | Data Type 2   | Ecrypted STAKey               |
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-                             -+
			 * :      (Length - 4) octets                                      :
			 * +-                                                             -+
			 * |                                                               |
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 */
			if (key_data_payload->get_key_data_payload_length() < eapol_rsna_key_data_header_c::EAPOL_RSNA_STAKEY_MINIMUM_SIZE)
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
					 EAPL("current key_data_payload 0x%04x=%s, data length incorrect 0x%04x.\n"),
					 key_data_payload, current_key_data_type, key_data_payload->get_payload_type_string(),
					 key_data_payload->get_key_data_payload_length()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			u8_t * buffer
				= static_cast<u8_t *>(key_data_payload->get_key_data_payload(
										  key_data_payload->get_key_data_payload_length()));

			if (buffer == 0)
			{
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
					 EAPL("current key_data_payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
					 key_data_payload,
					 current_key_data_type,
					 key_data_payload->get_payload_type_string(),
					 key_data_payload->get_key_data_payload_length()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			// Note here we get a reference to the data bytes of the received packet.
			eap_status_e status = p_rsna_key_data_payloads->get_STAKey()->set_buffer(
				key_data_payload, buffer, key_data_payload->get_key_data_payload_length(), false, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (current_key_data_type == eapol_RSNA_key_payload_type_pmkid)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): PMKID\n"),
				 key_data_payload));

			/*  PMKID:
			 *  0                   1                   2                   3
			 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * | Type = 0xdd   | Length        | OUI 3 octets               ...|
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * | ... OUI       | Data Type 3   | PMKID  plaintext              |
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-                             -+
			 * :      (Length - 4) octets                                      :
			 * +-                                                             -+
			 * |                                                               |
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 */
			if (key_data_payload->get_key_data_payload_length() < eapol_rsna_key_data_header_c::EAPOL_RSNA_PMKID_MINIMUM_SIZE)
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
					 EAPL("current key_data_payload 0x%04x=%s, data length incorrect 0x%04x.\n"),
					 key_data_payload, current_key_data_type, key_data_payload->get_payload_type_string(),
					 key_data_payload->get_key_data_payload_length()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			u8_t * buffer
				= static_cast<u8_t *>(key_data_payload->get_key_data_payload(
										  key_data_payload->get_key_data_payload_length()));

			if (buffer == 0)
			{
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
					 EAPL("current key_data_payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
					 key_data_payload,
					 current_key_data_type,
					 key_data_payload->get_payload_type_string(),
					 key_data_payload->get_key_data_payload_length()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			// Note here we get a reference to the data bytes of the received packet.
			eap_status_e status = p_rsna_key_data_payloads->get_PMKID()->set_buffer(
				key_data_payload, buffer, key_data_payload->get_key_data_payload_length(), false, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (current_key_descriptor_type == eapol_RSNA_key_data_type_WPA_IE
			&& key_data_payload->get_header_and_body_length() >= eapol_rsna_key_data_header_c::EAPOL_RSNA_IE_MINIMUM_SIZE)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): WPA Information element\n"),
				 key_data_payload));

			/* This is WPA Information element. NOTE the 2 first bytes match with
			 * EAPOL Key Data Encapsulation format.
			 * 
			 *      0       1       2       3       4       5       6       7
			 *  +-------+-------+-------+-------+-------+-------+-------+-------+
			 *  |     Element ID 48=0x30 (WPA 221=0xdd)   1 octet               |
			 *  +-------+-------+-------+-------+-------+-------+-------+-------+
			 *  |                           Length        1 octet               |
			 *  +-------+-------+-------+-------+-------+-------+-------+-------+
			 *  |                         Version 2 octets                      |
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +-------+-------+-------+-------+-------+-------+-------+-------+
			 *  |  Group Key Cipher Suite  4 octets                             |
			 *  +-                                                             -+
			 *  |                   optional                                    |
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +-------+-------+-------+-------+-------+-------+-------+-------+
			 *  |  Pairwise Key Cipher Suite Count (m) 2 octets                 |
			 *  +-                                                             -+
			 *  |                    optional                                   |
			 *  +-------+-------+-------+-------+-------+-------+-------+-------+
			 *  |  Pairwise Key Cipher Suite List m*4 octets                    |
			 *  +-                                                             -+
			 *  |                    optional                                   |
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +-------+-------+-------+-------+-------+-------+-------+-------+
			 *  |  Authentication and Key Management Suite Count (n) 2 octets   |
			 *  +-                                                             -+
			 *  |                    optional                                   |
			 *  +-------+-------+-------+-------+-------+-------+-------+-------+
			 *  |  Authentication and Key Management Suite List n*4 octets      |
			 *  +-                                                             -+
			 *  |                    optional                                   |
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +-------+-------+-------+-------+-------+-------+-------+-------+
			 *  |  RSN Capabilities 2 octets                                    |
			 *  +-                                                             -+
			 *  |                    optional                                   |
			 *  +-------+-------+-------+-------+-------+-------+-------+-------+
			 *  |  PMKID Count (s) 2 octets                                     |
			 *  +-                                                             -+
			 *  |                    optional                                   |
			 *  +-------+-------+-------+-------+-------+-------+-------+-------+
			 *  |  PMKID List s*16 octets                                       |
			 *  +-                                                             -+
			 *  :                    optional                                   :
			 *  +-                                                             -+
			 *  |                                                               |
			 *  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			 */

			// The second byte is the length of the RSN IE. Also the Type and Length fields are included.
			const u32_t length_of_the_RSN_IE = key_data_payload->get_header_and_body_length();

			if (length_of_the_RSN_IE < eapol_rsna_key_data_header_c::EAPOL_RSNA_IE_MINIMUM_SIZE)
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
					 EAPL("RSN IE length 0x%04x too less, at least 0x%04x bytes required.\n"),
					 key_data_payload,
					 length_of_the_RSN_IE,
					 eapol_rsna_key_data_header_c::EAPOL_RSNA_IE_MINIMUM_SIZE));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}


			// RSN IE is the whole key_data_payload.
			u8_t * buffer = reinterpret_cast<u8_t *>(key_data_payload->get_header_buffer(length_of_the_RSN_IE));

			if (buffer == 0)
			{
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
					 EAPL("current key_data_payload length 0x%04x data buffer incorrect.\n"),
					key_data_payload,
					length_of_the_RSN_IE));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			eap_variable_data_c * const rsn_ie = new eap_variable_data_c(m_am_tools);
			if (rsn_ie == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Parsed WPA IE"),
				buffer,
				length_of_the_RSN_IE));

			// Note here we get a reference to the data bytes of the received packet.
			eap_status_e status = rsn_ie->set_buffer(
				buffer,
				length_of_the_RSN_IE,
				false,
				false);
			if (status != eap_status_ok)
			{
				delete rsn_ie;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// eap_array_c object will free rsn_ie.
			status = p_rsna_key_data_payloads->get_RSN_IE()->add_object(rsn_ie, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			// Unknown payloads are quietly ignored.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(): ")
				 EAPL("Ignores unknown EAPOL Key Data type %d=0x%08x and payload %d=0x%08x, length %d.\n"),
				current_key_descriptor_type,
				current_key_descriptor_type,
				current_key_data_type,
				current_key_data_type,
				key_data_payload->get_header_and_body_length()));
		}

		*key_data_max_length -= key_data_payload->get_header_and_body_length();

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else if (get_is_WPA() == true
		&& eapol_key_descriptor_type == eapol_key_descriptor_type_WPA
		&& expected_key_message == eapol_key_state_wait_group_key_handshake_message_1)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): GTK\n"),
			 key_data_payload));

		// Data includes GTK.
		// key_data_payload points to the GTK of length (*key_data_max_length).

		u8_t * const buffer
			= reinterpret_cast<u8_t *>(key_data_payload);

		if (buffer == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
				(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
				 EAPL("length 0x%04x, data buffer incorrect.\n"),
				 key_data_payload,
				 *key_data_max_length));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// Note here we get a reference to the data bytes of the received packet.
		eap_status_e status = p_rsna_key_data_payloads->get_group_key()->set_buffer(
			key_data_payload, buffer,
			*key_data_max_length, false, false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("received WPA Group Key"),
			 p_rsna_key_data_payloads->get_group_key()->get_data(
				 p_rsna_key_data_payloads->get_group_key()->get_data_length()),
			 p_rsna_key_data_payloads->get_group_key()->get_data_length()));

		*key_data_max_length = 0ul;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else if ((get_is_RSNA() == true
			&& eapol_key_descriptor_type == eapol_key_descriptor_type_RSNA
			&& current_key_descriptor_type == eapol_RSNA_key_data_type_RSN_IE)
		|| (get_is_WPA() == true
				&& eapol_key_descriptor_type == eapol_key_descriptor_type_WPA
				&& current_key_descriptor_type == eapol_RSNA_key_data_type_WPA_IE)
#if defined(EAP_USE_WPXM)
		|| (get_is_WPXM() == true
			&& (current_key_descriptor_type == eapol_RSNA_key_data_type_RSN_IE
				|| current_key_descriptor_type == eapol_RSNA_key_data_type_WPA_IE))
#endif //#if defined(EAP_USE_WPXM)
			)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): RSN Information element\n"),
			 key_data_payload));

		/* This is RSN or WPA Information element. NOTE the 2 first bytes match with
		 * EAPOL Key Data Encapsulation format.
		 * 
		 *      0       1       2       3       4       5       6       7
		 *  +-------+-------+-------+-------+-------+-------+-------+-------+
		 *  |     Element ID 48=0x30 (WPA 221=0xdd)   1 octet               |
		 *  +-------+-------+-------+-------+-------+-------+-------+-------+
		 *  |                           Length        1 octet               |
		 *  +-------+-------+-------+-------+-------+-------+-------+-------+
		 *  |                         Version 2 octets                      |
		 *  +-                                                             -+
		 *  |                                                               |
		 *  +-------+-------+-------+-------+-------+-------+-------+-------+
		 *  |  Group Key Cipher Suite  4 octets                             |
		 *  +-                                                             -+
		 *  |                   optional                                    |
		 *  +-                                                             -+
		 *  |                                                               |
		 *  +-                                                             -+
		 *  |                                                               |
		 *  +-------+-------+-------+-------+-------+-------+-------+-------+
		 *  |  Pairwise Key Cipher Suite Count (m) 2 octets                 |
		 *  +-                                                             -+
		 *  |                    optional                                   |
		 *  +-------+-------+-------+-------+-------+-------+-------+-------+
		 *  |  Pairwise Key Cipher Suite List m*4 octets                    |
		 *  +-                                                             -+
		 *  |                    optional                                   |
		 *  +-                                                             -+
		 *  |                                                               |
		 *  +-                                                             -+
		 *  |                                                               |
		 *  +-------+-------+-------+-------+-------+-------+-------+-------+
		 *  |  Authentication and Key Management Suite Count (n) 2 octets   |
		 *  +-                                                             -+
		 *  |                    optional                                   |
		 *  +-------+-------+-------+-------+-------+-------+-------+-------+
		 *  |  Authentication and Key Management Suite List n*4 octets      |
		 *  +-                                                             -+
		 *  |                    optional                                   |
		 *  +-                                                             -+
		 *  |                                                               |
		 *  +-                                                             -+
		 *  |                                                               |
		 *  +-------+-------+-------+-------+-------+-------+-------+-------+
		 *  |  RSN Capabilities 2 octets                                    |
		 *  +-                                                             -+
		 *  |                    optional                                   |
		 *  +-------+-------+-------+-------+-------+-------+-------+-------+
		 *  |  PMKID Count (s) 2 octets                                     |
		 *  +-                                                             -+
		 *  |                    optional                                   |
		 *  +-------+-------+-------+-------+-------+-------+-------+-------+
		 *  |  PMKID List s*16 octets                                       |
		 *  +-                                                             -+
		 *  :                    optional                                   :
		 *  +-                                                             -+
		 *  |                                                               |
		 *  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
		 */

		// The second byte is the length of the RSN IE. Also the Type and Length fields are included.
		const u32_t length_of_the_RSN_IE = key_data_payload->get_header_and_body_length();

		if (length_of_the_RSN_IE < eapol_rsna_key_data_header_c::EAPOL_RSNA_IE_MINIMUM_SIZE)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
				(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
				 EAPL("RSN IE length 0x%04x too less, at least 0x%04x bytes required.\n"),
				 key_data_payload,
				 length_of_the_RSN_IE,
				 eapol_rsna_key_data_header_c::EAPOL_RSNA_IE_MINIMUM_SIZE));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}


		// RSN IE is the whole key_data_payload.
		u8_t * buffer = reinterpret_cast<u8_t *>(key_data_payload->get_header_buffer(length_of_the_RSN_IE));

		if (buffer == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR, 
				(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(0x%08x): ")
				 EAPL("current key_data_payload length 0x%04x data buffer incorrect.\n"),
				key_data_payload,
				length_of_the_RSN_IE));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		eap_variable_data_c * const rsn_ie = new eap_variable_data_c(m_am_tools);
		if (rsn_ie == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Parsed RSN IE"),
			buffer,
			length_of_the_RSN_IE));

		// Note here we get a reference to the data bytes of the received packet.
		eap_status_e status = rsn_ie->set_buffer(
			buffer,
			length_of_the_RSN_IE,
			false,
			false);
		if (status != eap_status_ok)
		{
			delete rsn_ie;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// eap_array_c object will free rsn_ie.
		status = p_rsna_key_data_payloads->get_RSN_IE()->add_object(rsn_ie, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		buffer += length_of_the_RSN_IE;

		*key_data_max_length -= length_of_the_RSN_IE;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		// Unknown payloads are quietly ignored.
		eapol_RSNA_key_payload_type_e current_key_data_type = key_data_payload->get_payload_type();
		EAP_UNREFERENCED_PARAMETER(current_key_data_type);

		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: EAPOL_KEY: eapol_key_state_c::parse_generic_key_data_payload(): ")
			 EAPL("Unknown EAPOL Key Data type %d=0x%08x and payload %d=0x%08x, length %d.\n"),
			current_key_descriptor_type,
			current_key_descriptor_type,
			current_key_data_type,
			current_key_data_type,
			key_data_payload->get_header_and_body_length()));

		*key_data_max_length -= key_data_payload->get_header_and_body_length();

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::parse_key_data(
	const eapol_key_descriptor_type_e eapol_key_descriptor_type,
	const eapol_rsna_key_data_header_c * const p_payload,
	u32_t * const buffer_length,
	eapol_rsna_key_data_payloads_c * const p_rsna_key_data_payloads,
	const eapol_key_state_e expected_key_message,
	const eapol_RSNA_key_header_c::key_descriptor_version_e key_descriptor_version)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL_KEY: eapol_key_state_c::parse_key_data()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_key_state_c::parse_key_data()");

	eapol_rsna_key_data_header_c payload(
		m_am_tools,
		get_is_RSNA(),
		get_is_WPXM(),
		p_payload->get_header_buffer(*buffer_length),
		*buffer_length); // Const correctness is gone.

	eapol_RSNA_key_descriptor_type_e current_payload = payload.get_descriptor_type();

	eap_status_e status = eap_status_header_corrupted;

	if (payload.get_is_valid() == true
		&& current_payload != eapol_RSNA_key_data_type_none)
	{

		if (get_is_RSNA() == true
			|| expected_key_message != eapol_key_state_wait_group_key_handshake_message_1 // WPA must check the expected message.
			)
		{
			if (*buffer_length < payload.get_header_and_body_length())
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_key_data(0x%08x): ")
					 EAPL("current payload 0x%04x=%s, payload length 0x%04x, buffer length 0x%04x.\n"),
					 payload.get_header_buffer(0ul),
					 current_payload,
					 payload.get_payload_type_string(),
					 payload.get_header_and_body_length(),
					 *buffer_length));
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_key_data(): ")
					 EAPL("EAPOl Key Data-payload header is corrupted.\n")));
				EAP_TRACE_DATA_ERROR(
					m_am_tools,
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
					(EAPL("payload"),
					payload.get_header_buffer(*buffer_length),
					*buffer_length));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}
		}

		status = parse_generic_key_data_payload(
			eapol_key_descriptor_type,
			current_payload,
			&payload,
			buffer_length,
			p_rsna_key_data_payloads,
			expected_key_message);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		while(*buffer_length >= payload.get_header_length()
			&& payload.get_is_valid() == true
			&& payload.get_header_buffer_length()
			  >= (payload.get_header_and_body_length()))
		{
			payload.set_header_buffer(
					payload.get_next_header(),
					payload.get_header_buffer_length()
					-(payload.get_header_and_body_length()));
			if (payload.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			current_payload = payload.get_descriptor_type();

			if (*buffer_length < payload.get_header_and_body_length())
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_key_data(0x%08x): ")
					 EAPL("current payload 0x%04x=%s, payload length 0x%04x, buffer length 0x%04x.\n"),
					 payload.get_header_buffer(0ul),
					 current_payload,
					 payload.get_payload_type_string(),
					 payload.get_header_and_body_length(),
					 *buffer_length));
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
					(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_key_data(): ")
					 EAPL("EAPOl Key Data-payload header is corrupted.\n")));
				EAP_TRACE_DATA_ERROR(
					m_am_tools,
					TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
					(EAPL("payload"),
					payload.get_header_buffer(*buffer_length),
					*buffer_length));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			status = parse_generic_key_data_payload(
				eapol_key_descriptor_type,
				current_payload,
				&payload,
				buffer_length,
				p_rsna_key_data_payloads,
				expected_key_message);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	if (*buffer_length != 0u)
	{
		// Check is this padding.
		const u8_t * const padding = payload.get_header_offset(payload.get_header_and_body_length(), *buffer_length);

		status = check_padding(padding, *buffer_length);

		if (status != eap_status_ok
			&& key_descriptor_version == eapol_RSNA_key_header_c::m_key_descriptor_version_1)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
				(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::parse_key_data(): ")
				 EAPL("EAPOl Key Data-header is corrupted. Buffer length ")
				 EAPL("and payload length does not match. %d illegal bytes.\n"),
				 *buffer_length));
			EAP_TRACE_DATA_ERROR(
				m_am_tools,
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
				(EAPL("ERROR: illegal padding"),
				padding,
				*buffer_length));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::rsna_prf(
	const eap_variable_data_c * const key_K,
	const eap_variable_data_c * const label_A,
	const eap_variable_data_c * const input_B,
	const u32_t output_length_bits,
	eap_variable_data_c * const output
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	crypto_sha1_c sha1(m_am_tools);
	status = sha1.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	crypto_hmac_c hmac(m_am_tools, &sha1, false);

	if (hmac.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t required_digest_count = (output_length_bits+159)/160;
	u32_t required_buffer_length = hmac.get_digest_length()*required_digest_count;
	u32_t required_octet_count = output_length_bits/8ul;

	output->reset();
	status = output->set_buffer_length(required_buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	output->set_data_length(output->get_buffer_length());

	eap_variable_data_c input(m_am_tools);
	if (input.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u8_t zero = 0ul;

	status = input.set_buffer_length(
		label_A->get_data_length()
		+ sizeof(zero)
		+ input_B->get_data_length()
		+ sizeof(u8_t));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	for (u8_t ind = 0ul; ind < required_digest_count; ind++)
	{
		status = input.reset_start_offset_and_data_length();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = hmac.hmac_set_key(key_K);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (label_A->get_is_valid_data() == true)
		{
			status = input.add_data(label_A);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = input.add_data(&zero, sizeof(zero));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		status = input.add_data(input_B);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = input.add_data(&ind, sizeof(ind));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = hmac.hmac_update(
			input.get_data(input.get_data_length()),
			input.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u32_t md_length = hmac.get_digest_length();

		status = hmac.hmac_final(
			output->get_data_offset(
				ind*hmac.get_digest_length(),
				hmac.get_digest_length()),
			&md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
	} // for()

	output->set_data_length(required_octet_count);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::select_minimum(
	const eap_variable_data_c * const input_a,
	const eap_variable_data_c * const input_b,
	const eap_variable_data_c ** const minimum,
	const eap_variable_data_c ** const maximum)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (input_a == 0
		|| input_b == 0
		|| minimum == 0
		|| maximum == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (input_a->get_data_length() > input_b->get_data_length())
	{
		*minimum = input_b;
		*maximum = input_a;
	}
	else if (input_a->get_data_length() < input_b->get_data_length())
	{
		*minimum = input_a;
		*maximum = input_b;
	}
	else
	{
		const i32_t cmp = input_a->compare(input_b);
		if (cmp < 0)
		{
			*minimum = input_a;
			*maximum = input_b;
		}
		else // if (cmp >= 0) NOTE this includes equal case too.
		{
			*minimum = input_b;
			*maximum = input_a;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::derive_PTK()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_key_state_c::derive_PTK(): %s\n"),
		 (m_is_client == true) ? "client": "server"));

	eap_status_e status = eap_status_process_general_error;

	if (m_pairwise_PMK_WPXK3.get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::derive_PTK(): ")
			 EAPL("Pairwise Master Key (PMK) is missing.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_supplicant_MAC_address.get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::derive_PTK(): ")
			 EAPL("Supplicant MAC address is missing.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_authenticator_MAC_address.get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::derive_PTK(): ")
			 EAPL("Authenticator MAC address is missing.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_ANonce.get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::derive_PTK(): ")
			 EAPL("Authenticator nonce (ANonce) is missing.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_SNonce.get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::derive_PTK(): ")
			 EAPL("Supplicant nonce (m_SNonce) is missing.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL-Key m_supplicant_MAC_address"),
		 m_supplicant_MAC_address.get_data(m_supplicant_MAC_address.get_data_length()),
		 m_supplicant_MAC_address.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL-Key m_authenticator_MAC_address"),
		 m_authenticator_MAC_address.get_data(m_authenticator_MAC_address.get_data_length()),
		 m_authenticator_MAC_address.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL-Key m_SNonce"),
		 m_SNonce.get_data(m_SNonce.get_data_length()),
		 m_SNonce.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL-Key m_ANonce"),
		 m_ANonce.get_data(m_ANonce.get_data_length()),
		 m_ANonce.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL-Key m_pairwise_PMK_WPXK3"),
		 m_pairwise_PMK_WPXK3.get_data(m_pairwise_PMK_WPXK3.get_data_length()),
		 m_pairwise_PMK_WPXK3.get_data_length()));


	const eap_variable_data_c * minimum_MAC_address = 0;
	const eap_variable_data_c * maximum_MAC_address = 0;
	const eap_variable_data_c * minimum_nonce = 0;
	const eap_variable_data_c * maximum_nonce = 0;

	status = select_minimum(
		&m_supplicant_MAC_address,
		&m_authenticator_MAC_address,
		&minimum_MAC_address,
		&maximum_MAC_address);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = select_minimum(
		&m_ANonce,
		&m_SNonce,
		&minimum_nonce,
		&maximum_nonce);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}



	eap_variable_data_c input(m_am_tools);

	status = input.set_buffer_length(
		minimum_MAC_address->get_data_length()
		+ maximum_MAC_address->get_data_length()
		+ minimum_nonce->get_data_length()
		+ maximum_nonce->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = input.add_data(minimum_MAC_address);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = input.add_data(maximum_MAC_address);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = input.add_data(minimum_nonce);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = input.add_data(maximum_nonce);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Default is TKIP.
	u32_t PTK_length = EAPOL_RSNA_TKIP_PTK_LENGTH_BITS;
	u32_t tk_length_bytes = EAPOL_RSNA_TKIP_TK_LENGTH_BYTES;

	if (m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP)
	{
		PTK_length = EAPOL_RSNA_CCMP_PTK_LENGTH_BITS;
		tk_length_bytes = EAPOL_RSNA_CCMP_TK_LENGTH_BYTES;
	}
	else if (m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_40)
	{
		tk_length_bytes = eapol_RSNA_key_header_c::eapol_RSNA_cipher_key_length_WEP_40;
	}
	else if (m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_104)
	{
		tk_length_bytes = eapol_RSNA_key_header_c::eapol_RSNA_cipher_key_length_WEP_104;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c label(m_am_tools);

	status = label.set_copy_of_buffer(
			EAPOL_RSNA_PAIRWISE_KEY_EXPANSION_LABEL,
			EAPOL_RSNA_PAIRWISE_KEY_EXPANSION_LABEL_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = rsna_prf(
		&m_pairwise_PMK_WPXK3,
		&label,
		&input,
		PTK_length,
		&m_transient_PTK);
	if (status != eap_status_ok)
	{
		m_transient_PTK.reset();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Split PTK to KCK, KEK and TK.
	status = m_confirmation_KCK.set_buffer(
		m_transient_PTK.get_data_offset(EAPOL_RSNA_KCK_OFFSET_BYTES, EAPOL_RSNA_KCK_LENGTH_BYTES),
		EAPOL_RSNA_KCK_LENGTH_BYTES,
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_encryption_KEK.set_buffer(
		m_transient_PTK.get_data_offset(EAPOL_RSNA_KEK_OFFSET_BYTES, EAPOL_RSNA_KEK_LENGTH_BYTES),
		EAPOL_RSNA_KEK_LENGTH_BYTES,
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_temporal_TK.set_buffer(
		m_transient_PTK.get_data_offset(EAPOL_RSNA_TK_OFFSET_BYTES, tk_length_bytes),
		tk_length_bytes,
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
		(EAPL("EAPOL-Key KCK"),
		 m_confirmation_KCK.get_data(m_confirmation_KCK.get_data_length()),
		 m_confirmation_KCK.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL-Key KEK"),
		 m_encryption_KEK.get_data(m_encryption_KEK.get_data_length()),
		 m_encryption_KEK.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL-Key TK"),
		 m_temporal_TK.get_data(m_temporal_TK.get_data_length()),
		 m_temporal_TK.get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::create_nonce(
	eap_variable_data_c * const nonce,	const u32_t nonce_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_key_state_c::create_nonce(): %s\n"),
		 (m_is_client == true) ? "client": "server"));

	eap_status_e status = eap_status_process_general_error;

	status = nonce->set_buffer_length(nonce_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	nonce->set_data_length(nonce_length);

	crypto_random_c rand(m_am_tools);

	if (rand.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = rand.get_rand_bytes(
		nonce->get_data(nonce->get_data_length()),
		nonce->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL-Key new nonce"),
		 nonce->get_data(nonce->get_data_length()),
		 nonce->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::create_PMKID()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	if (m_pairwise_PMK_WPXK3.get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::create_PMKID(): ")
			 EAPL("Pairwise Master Key (PMK) is missing.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_supplicant_MAC_address.get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::create_PMKID(): ")
			 EAPL("Supplicant MAC address is missing.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_authenticator_MAC_address.get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::create_PMKID(): ")
			 EAPL("Authenticator MAC address is missing.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	crypto_sha1_c sha1(m_am_tools);

	status = sha1.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	crypto_hmac_c hmac(m_am_tools, &sha1, false);

	if (hmac.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = hmac.hmac_set_key(&m_pairwise_PMK_WPXK3);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = hmac.hmac_update(
		EAPOL_RSNA_PMK_NAME_LABEL,
		EAPOL_RSNA_PMK_NAME_LABEL_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = hmac.hmac_update(
		m_authenticator_MAC_address.get_data(m_authenticator_MAC_address.get_data_length()),
		m_authenticator_MAC_address.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = hmac.hmac_update(
		m_supplicant_MAC_address.get_data(m_supplicant_MAC_address.get_data_length()),
		m_supplicant_MAC_address.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	{
		m_PMKID.reset();

		status = m_PMKID.set_buffer_length(hmac.get_digest_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		m_PMKID.set_data_length(hmac.get_digest_length());

		u32_t md_length = hmac.get_digest_length();

		status = hmac.hmac_final(
			m_PMKID.get_data(hmac.get_digest_length()),
			&md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (md_length < eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_DATA_PMKID_SIZE)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
		}

		// This cuts the PMKID to 128 bits.
		m_PMKID.set_data_length(eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_DATA_PMKID_SIZE);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL-Key PMKID"),
			 m_PMKID.get_data(),
			 m_PMKID.get_data_length()));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::encrypt_key_data(
	eapol_RSNA_key_header_c * const eapol_key_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	if (m_encryption_KEK.get_is_valid_data() == false
		|| m_encryption_KEK.get_data_length() == 0ul)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::encrypt_key_data(): ")
			 EAPL("m_encryption_KEK is missing or corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	crypto_aes_wrap_c aes_wrap(m_am_tools);

	if (aes_wrap.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t padding_length(0ul);
	u32_t min_key_data_length = 2ul * aes_wrap.get_block_size();

	if (eapol_key_message->get_key_data_length() < min_key_data_length)
	{
		padding_length = min_key_data_length - eapol_key_message->get_key_data_length();
	}
	else if ((eapol_key_message->get_key_data_length() % aes_wrap.get_block_size()) != 0)
	{
		padding_length = aes_wrap.get_block_size()
			- (eapol_key_message->get_key_data_length() % aes_wrap.get_block_size());
	}

	u32_t padding_offset = eapol_key_message->get_key_data_length();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_eapol_pairwise_cipher
		== eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP
		|| m_eapol_group_cipher
		== eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: AES-WRAP encryption algorithm.\n")));

		status = aes_wrap.set_encryption_key(
			m_encryption_KEK.get_data(),
			m_encryption_KEK.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// AES-Wrap increases message length with one block.
		status = eapol_key_message->set_key_data_length(
			static_cast<u16_t>(eapol_key_message->get_key_data_length()
			+ padding_length
			+ aes_wrap.get_block_size()));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (padding_length > 0ul)
		{
			aes_wrap.add_padding_bytes(
				eapol_key_message->get_key_data_offset(
					padding_offset,
					padding_length),
				padding_length);
		}

		if (eapol_key_message->get_key_data_length() < aes_wrap.get_block_size())
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = aes_wrap.encrypt_block(
			eapol_key_message->get_key_data(eapol_key_message->get_key_data_length()),
			eapol_key_message->get_key_data_length()-aes_wrap.get_block_size(),
			eapol_key_message->get_key_data(eapol_key_message->get_key_data_length()),
			eapol_key_message->get_key_data_length());

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_TKIP
			 || m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_40
			 || m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_104)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: RC4 encryption algorithm.\n")));

		if (m_EAPOL_key_IV.get_is_valid_data() == false
			|| m_EAPOL_key_IV.get_data_length() == 0ul)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
				(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::encrypt_key_data(): ")
				 EAPL("m_EAPOL_key_IV is missing or corrupted.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		abs_crypto_stream_algorithm_c * const rc4 = new crypto_rc4_c(m_am_tools);
		eap_automatic_variable_c<abs_crypto_stream_algorithm_c> automatic_rc4(m_am_tools, rc4);

		if (rc4 == 0
			|| rc4->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c key(m_am_tools);

		status = key.set_copy_of_buffer(&m_EAPOL_key_IV);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = key.add_data(&m_encryption_KEK);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL-Key encrypt key"),
			 key.get_data(key.get_data_length()),
			 key.get_data_length()));

		status = rc4->set_key(&key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// The first 256 octets of RC4 key stream are discarded.
		status = rc4->discard_stream(EAPOL_RSNA_RC4_KEY_STREAM_DISCARD_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (padding_length > 0ul)
		{
			// Of course some access points use padding also with RC4 encryption. It is required only with AES-wrap algorithm.
			crypto_aes_wrap_c aes_wrap(m_am_tools);

			if (aes_wrap.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			aes_wrap.add_padding_bytes(
				eapol_key_message->get_key_data_offset(
					padding_offset,
					padding_length),
				padding_length);

			status = eapol_key_message->set_key_data_length(
				static_cast<u16_t>(eapol_key_message->get_key_data_length()
				+ padding_length));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL-Key plaintext data"),
			 eapol_key_message->get_key_data(eapol_key_message->get_key_data_length()),
			 eapol_key_message->get_key_data_length()));

		status = rc4->encrypt_data(
			eapol_key_message->get_key_data(eapol_key_message->get_key_data_length()),
			eapol_key_message->get_key_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL-Key encrypted data"),
			 eapol_key_message->get_key_data(eapol_key_message->get_key_data_length()),
			 eapol_key_message->get_key_data_length()));

	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::decrypt_key_data(
	eapol_RSNA_key_header_c * const eapol_key_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;


	if (m_eapol_pairwise_cipher
		== eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP
		|| m_eapol_group_cipher
		== eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: AES-WRAP decryption algorithm.\n")));

		crypto_aes_wrap_c aes_wrap(m_am_tools);

		if (aes_wrap.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = aes_wrap.set_decryption_key(
			m_encryption_KEK.get_data(),
			m_encryption_KEK.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = aes_wrap.decrypt_block(
			eapol_key_message->get_key_data(eapol_key_message->get_key_data_length()),
			eapol_key_message->get_key_data_length(),
			eapol_key_message->get_key_data(eapol_key_message->get_key_data_length()),
			eapol_key_message->get_key_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// AES-Wrap increases message length with one block.
		// Here we remove the block.
		status = eapol_key_message->set_key_data_length(
			static_cast<u16_t>(eapol_key_message->get_key_data_length()
			- aes_wrap.get_block_size()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_TKIP
			 || m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_40
			 || m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_104)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: RC4 decryption algorithm.\n")));

		abs_crypto_stream_algorithm_c * const rc4 = new crypto_rc4_c(m_am_tools);
		eap_automatic_variable_c<abs_crypto_stream_algorithm_c> automatic_rc4(m_am_tools, rc4);

		if (rc4 == 0
			|| rc4->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c key(m_am_tools);

		status = key.set_copy_of_buffer(&m_EAPOL_key_IV);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = key.add_data(&m_encryption_KEK);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL-Key decrypt key"),
			 key.get_data(key.get_data_length()),
			 key.get_data_length()));

		status = rc4->set_key(&key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// The first 256 octets of RC4 key stream are discarded.
		status = rc4->discard_stream(EAPOL_RSNA_RC4_KEY_STREAM_DISCARD_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL-Key encrypted data"),
			 eapol_key_message->get_key_data(eapol_key_message->get_key_data_length()),
			 eapol_key_message->get_key_data_length()));

		status = rc4->decrypt_data(
			eapol_key_message->get_key_data(eapol_key_message->get_key_data_length()),
			eapol_key_message->get_key_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL-Key plaintext data"),
			 eapol_key_message->get_key_data(eapol_key_message->get_key_data_length()),
			 eapol_key_message->get_key_data_length()));

	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------


//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::create_key_mic(
	eapol_RSNA_key_header_c * const eapol_key_message,
	const eap_variable_data_c * const confirmation_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	if (eapol_key_message == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (confirmation_key->get_is_valid_data() == false
		|| confirmation_key->get_data_length() == 0ul)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: eapol_key_state_c::create_key_mic(): ")
			 EAPL("confirmation_key is missing or corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	status = eapol_key_message->zero_key_MIC(m_am_tools);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	crypto_hmac_c * hmac = 0;
	abs_crypto_hash_algorithm_c * hash = 0;

	if (m_eapol_pairwise_cipher
		== eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP
		|| m_eapol_group_cipher
		== eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: HMAC-SHA1 MIC algorithm.\n")));

		hash = new crypto_sha1_c(m_am_tools);
	}
	else if (m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_TKIP
			 || m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_40
			 || m_eapol_pairwise_cipher == eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_104)
	{		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: HMAC-MD5 MIC algorithm.\n")));

		hash = new crypto_md5_c(m_am_tools);
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
	}

	eap_automatic_variable_c<abs_crypto_hash_algorithm_c> automatic_hash(m_am_tools, hash);

	if (hash == 0
		|| hash->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	hmac = new crypto_hmac_c(m_am_tools, hash, true);
	automatic_hash.do_not_free_variable();
	eap_automatic_variable_c<crypto_hmac_c> automatic_hmac(m_am_tools, hmac);
	if (hmac == 0
		|| hmac->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL-Key MIC key"),
		 confirmation_key->get_data(),
		 confirmation_key->get_data_length()));

	status = hmac->hmac_set_key(confirmation_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// MIC is calculated over the whole EAPOL-Key message.
	status = hmac->hmac_update(
		eapol_key_message->get_header_buffer(
			eapol_key_message->get_header_buffer_length()),
		eapol_key_message->get_eapol_packet_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL-Key MIC data"),
		eapol_key_message->get_header_buffer(
			eapol_key_message->get_header_buffer_length()),
		eapol_key_message->get_eapol_packet_length()));


	{
		eap_variable_data_c mic(m_am_tools);

		status = mic.set_buffer_length(hmac->get_digest_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		mic.set_data_length(hmac->get_digest_length());

		u32_t md_length = hmac->get_digest_length();

		status = hmac->hmac_final(
			mic.get_data(hmac->get_digest_length()),
			&md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (md_length < eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_MIC_SIZE)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
		}

		// This cuts the PMKID to 128 bits.
		mic.set_data_length(eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_MIC_SIZE);

		// Copy MIC to EAPOL-Key message.
		m_am_tools->memmove(
			eapol_key_message->get_key_MIC(),
			mic.get_data(eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_MIC_SIZE),
			eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_MIC_SIZE);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL-Key message"),
			 eapol_key_message->get_header_buffer(
				 eapol_key_message->get_header_buffer_length()),
			 eapol_key_message->get_eapol_packet_length()));
	}
	

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::verify_key_mic(
	eapol_RSNA_key_header_c * const eapol_key_message,
	const eap_variable_data_c * const confirmation_key)
{
	eap_variable_data_c original_MIC(m_am_tools);

	// Here we save the original received MIC.
	eap_status_e status = original_MIC.set_copy_of_buffer(
		eapol_key_message->get_key_MIC(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_MIC_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// This function writes a new MIC to message.
	status = create_key_mic(
		eapol_key_message,
		confirmation_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// This will compare the saved original MIC and new created MIC are the same.
	if (m_am_tools->memcmp(
		original_MIC.get_data(original_MIC.get_data_length()),
		eapol_key_message->get_key_MIC(),
		eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_MIC_SIZE) != 0)
	{
		// MIC failure.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: MIC failed.\n")));
		EAP_TRACE_DATA_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("Received MIC"),
			 original_MIC.get_data(original_MIC.get_data_length()),
			 original_MIC.get_data_length()));
		EAP_TRACE_DATA_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("   Local MIC"),
			 eapol_key_message->get_key_MIC(),
			 eapol_RSNA_key_header_c::EAPOL_RSNA_KEY_MIC_SIZE));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL_KEY: MIC OK.\n")));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::add_RSN_GTK_payload(
	const eapol_RSNA_key_header_c * const eapol_key_message,
	eap_variable_data_c * const group_GTK,
	u32_t * const eapol_data_length)
{
	// Add GTK to Key Data.

	if (eapol_key_message == 0
		|| eapol_key_message->get_is_valid() == false
		|| group_GTK == 0
		|| group_GTK->get_is_valid_data() == false
		|| eapol_data_length == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t GTK_length = group_GTK->get_data_length();

	u32_t gtk_data_length =
		eapol_rsna_key_data_header_c::EAPOL_RSNA_KEY_ID_AND_GROUP_KEY_HEADER_SIZE
		+ GTK_length;

	u32_t key_data_buffer_length =
		eapol_rsna_key_data_header_c::EAPOL_RSNA_KEY_HEADER_LENGTH
		+ gtk_data_length;

	eapol_rsna_key_data_header_c key_data_header(
		m_am_tools,
		get_is_RSNA(),
		get_is_WPXM(),
		eapol_key_message->get_key_data_offset(*eapol_data_length, key_data_buffer_length),
		key_data_buffer_length);
	if (key_data_header.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = key_data_header.reset_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		// Here Type and Length fields are NOT included.
		u32_t key_data_length =
			key_data_buffer_length
			- 2ul;

		if (key_data_length > 0xff)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_long_message);
		}

		status = key_data_header.set_length(
			static_cast<u8_t>(key_data_length));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = key_data_header.set_payload_type(eapol_RSNA_key_payload_type_group_key_and_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("RSN Group Key"),
		 group_GTK->get_data(GTK_length),
		GTK_length));

	if (gtk_data_length == GTK_length + eapol_rsna_key_data_gtk_header_c::get_header_length())
	{
		// Add authenticator GTK to Key Data.
		eapol_rsna_key_data_gtk_header_c gtk_header(
			m_am_tools,
			key_data_header.get_key_data_payload(gtk_data_length),
			gtk_data_length);
		if (gtk_header.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = gtk_header.reset_header();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_group_GTK_ID = 1ul;
		status = gtk_header.set_key_index(m_group_GTK_ID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_group_GTK_Tx_bit = true;
		status = gtk_header.set_tx(m_group_GTK_Tx_bit);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u8_t * data_field_of_GTK
			= gtk_header.get_gtk(GTK_length);
		if (data_field_of_GTK == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_am_tools->memmove(
			data_field_of_GTK,
			group_GTK->get_data(GTK_length),
			GTK_length);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("send RSN Group Key ID %d, Tx %d\n"),
			 gtk_header.get_key_index(),
			 gtk_header.get_tx_bit()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("send RSN Group Key payload"),
			 gtk_header.get_header_buffer(gtk_header.get_header_buffer_length()),
			 gtk_header.get_header_buffer_length()));
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	*eapol_data_length += key_data_buffer_length;

	EAPOL_RSNA_KEY_DATA_TRACE_PAYLOAD(
		get_is_RSNA(),
		get_is_WPXM(),
		eapol_key_message->get_key_descriptor_type(),
		"Added EAPOL Key Data key_data_payload",
		&key_data_header,
		*eapol_data_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::add_RSN_IE_payload(
	const eapol_RSNA_key_header_c * const eapol_key_message,
	eap_variable_data_c * const RSNA_IE,
	u32_t * const eapol_data_length)
{
	// Add RSN IE to Key Data.

	if (eapol_key_message == 0
		|| eapol_key_message->get_is_valid() == false
		|| RSNA_IE == 0
		|| RSNA_IE->get_is_valid_data() == false
		|| eapol_data_length == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t rsn_ie_data_length(RSNA_IE->get_data_length());

	u8_t * const data_field_of_RSN_IE
		= reinterpret_cast<u8_t *>(
			eapol_key_message->get_key_data_offset(*eapol_data_length, rsn_ie_data_length));
	if (data_field_of_RSN_IE == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_am_tools->memmove(
		data_field_of_RSN_IE,
		RSNA_IE->get_data(rsn_ie_data_length),
		rsn_ie_data_length);

	// NOTE, only two first bytes of RSN IE match with EAPOL Key Data.
	eapol_rsna_key_data_header_c key_data_header(
		m_am_tools,
		get_is_RSNA(),
		get_is_WPXM(),
		data_field_of_RSN_IE,
		rsn_ie_data_length);
	if (key_data_header.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	*eapol_data_length += rsn_ie_data_length;

	EAPOL_RSNA_KEY_DATA_TRACE_PAYLOAD(
		get_is_RSNA(),
		get_is_WPXM(),
		eapol_key_message->get_key_descriptor_type(),
		"Added EAPOL RSN IE",
		&key_data_header,
		*eapol_data_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_eapol_key_frame(
	const eap_am_network_id_c * const receive_network_id,
	eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::process_eapol_key_frame(): ")
		 EAPL("m_authentication_type=%d=%s, m_eapol_key_state=%d=%s\n"),
		(m_is_client == true ? "client": "server"),
		m_authentication_type,
		eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type),
		m_eapol_key_state,
		eapol_key_state_string_c::get_eapol_key_state_string(m_eapol_key_state)));

	eap_status_e status = eap_status_not_supported;

	if (packet_length < eapol_header_wr_c::get_header_length()
		|| packet_data->get_header_buffer_length() < eapol_header_wr_c::get_header_length()
		|| packet_data->get_header_buffer_length() < packet_length)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	if (m_pairwise_PMK_WPXK3.get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, 
				(EAPL("EAPOL_KEY: eapol_key_state_c: process_eapol_key_frame(): m_pairwise_PMK_WPXK3 is not valid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_found);
	}

	eapol_header_wr_c eapol_header(
		m_am_tools,
		packet_data->get_header_buffer(packet_data->get_header_buffer_length()),
		packet_data->get_header_buffer_length());
	if (eapol_header.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
	else if (eapol_header.check_header() != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Data length must be at least size of Descriptor Type.
	const u32_t EAPOL_DESCRIPTOR_TYPE_LENGTH = sizeof(u8_t);
	if (eapol_header.get_data_length() < EAPOL_DESCRIPTOR_TYPE_LENGTH)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	const u8_t * const descriptor_type = eapol_header.get_data(EAPOL_DESCRIPTOR_TYPE_LENGTH);
	if (descriptor_type == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	switch(static_cast<eapol_key_descriptor_type_e>(*descriptor_type))
	{
	case eapol_key_descriptor_type_RC4:
		status = process_RC4_key_descriptor(receive_network_id, packet_data, packet_length);
		break;
	case eapol_key_descriptor_type_RSNA:
	case eapol_key_descriptor_type_WPA:
		status = process_RSNA_key_descriptor(receive_network_id, packet_data, packet_length);
		break;
	default:
		status = eap_status_not_supported;
		break;
	}

	if (status == eap_status_ok)
	{
		EAP_GENERAL_HEADER_SET_ERROR_DETECTED(packet_data, false);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eapol_key_state_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eapol_key_state_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eapol_key_state_c::object_increase_reference_count()
{
	// Do nothing.
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eapol_key_state_c::object_decrease_reference_count()
{
	// Do nothing.
	return 0ul;
}


//--------------------------------------------------

EAP_FUNC_EXPORT bool eapol_key_state_c::get_is_encryption_on()
{
	/**
	 * @{ Add functionality of get_is_encryption_on() function }
	 */
	return false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eapol_key_state_c::get_is_associated()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::get_is_associated(): m_is_associated=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 (m_is_associated == true) ? "true": "false"));

	return m_is_associated;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eapol_key_state_c::set_eapol_key_state(const eapol_key_state_e state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::set_eapol_key_state(): set_eapol_key_state() from %s to %s\n"),
		(m_is_client == true ? "client": "server"),
		eapol_key_state_string_c::get_eapol_key_state_string(m_eapol_key_state),
		eapol_key_state_string_c::get_eapol_key_state_string(state)));

	m_eapol_key_state = state;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eapol_key_state_e eapol_key_state_c::get_eapol_key_state() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_eapol_key_state;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::packet_send(
	const eap_am_network_id_c * const send_network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	cancel_retransmission();

	if (m_is_client == false
		&& sent_packet->get_do_packet_retransmission() == true)
	{
		// Only EAPOL-server initializes re-transmission.
		// EAPOL-server will re-transmit the packet when timer elapses and no response is received.
		init_retransmission(
			send_network_id,
			sent_packet,
			header_offset,
			data_length,
			eap_code_none,
			0ul,
			eap_type_none);
	}


	// NOTE: send packet directly to partner object of eapol_core_c object.
	eap_status_e status = m_eapol_partner->packet_send(
		send_network_id,
		sent_packet,
		header_offset,
		data_length,
		buffer_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::resend_packet(
	const eap_am_network_id_c * const send_network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("<- EAPOL_KEY: %s: eapol_key_state_c::resend_packet().\n"),
		 (m_is_client == true) ? "client": "server"));

	// We make a copy because random error test may corrupt the data.
	eap_buf_chain_wr_c * const copy_packet = sent_packet->copy();

	if (copy_packet == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT(m_eapol_header_offset < sent_packet->get_data_length());
	EAP_ASSERT(data_length <= sent_packet->get_data_length());
	EAP_ASSERT(sent_packet->get_data_length() <= buffer_length);

	// NOTE: send packet directly to partner object of eapol_core_c object.
	// This will skip initialization of re-transmission for re-transmitted packet.
	eap_status_e status = m_eapol_partner->packet_send(
		send_network_id, 
		copy_packet, 
		header_offset, 
		data_length,
		buffer_length
		);

	delete copy_packet;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::cancel_handshake_timeout()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_handshake_timeout_set = false;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::cancel_handshake_timeout(): this = 0x%08x.\n"),
		 (m_is_client == true) ? "client": "server",
		 this));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	m_key_state_partner->cancel_timer(this, EAPOL_KEY_STATE_TIMER_HANDSHAKE_TIMEOUT_ID);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_HANDSHAKE_TIMEOUT_ID cancelled.\n"),
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::init_handshake_timeout(
	const u32_t timeout)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::init_handshake_timeout(): this = 0x%08x, state %d=%s, m_authentication_type %d=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 get_eapol_key_state(),
		 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state()),
		 m_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

	if (m_handshake_timeout_set == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: EAPOL_KEY: eapol_key_state_c::init_handshake_timeout(): Already active.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	m_handshake_timeout_set = true;

	eap_status_e status = m_key_state_partner->set_timer(
		this,
		EAPOL_KEY_STATE_TIMER_HANDSHAKE_TIMEOUT_ID, 
		0,
		timeout);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_HANDSHAKE_TIMEOUT_ID set %d ms.\n"),
		 (m_is_client == true ? "client": "server"),
		 timeout));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eapol_key_state_c::cancel_reassociate_timeout()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::cancel_reassociate_timeout(): this = 0x%08x.\n"),
		 (m_is_client == true) ? "client": "server",
		 this));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	m_key_state_partner->cancel_timer(this, EAPOL_KEY_STATE_TIMER_REASSOCIATE_TIMEOUT_ID);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_REASSOCIATE_TIMEOUT_ID cancelled.\n"),
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e eapol_key_state_c::init_reassociate_timeout(
	const u32_t timeout)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::init_reassociate_timeout(): this = 0x%08x, state %d=%s, m_authentication_type %d=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 get_eapol_key_state(),
		 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state()),
		 m_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

	eap_status_e status = m_key_state_partner->set_timer(
		this,
		EAPOL_KEY_STATE_TIMER_REASSOCIATE_TIMEOUT_ID, 
		0,
		timeout);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_REASSOCIATE_TIMEOUT_ID set %d ms.\n"),
		 (m_is_client == true ? "client": "server"),
		 timeout));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eapol_key_state_c::cancel_4_way_handshake_start_timeout()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::cancel_4_way_handshake_start_timeout(): this = 0x%08x.\n"),
		 (m_is_client == true) ? "client": "server",
		 this));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	m_key_state_partner->cancel_timer(this, EAPOL_KEY_STATE_TIMER_INITIALIZE_4_WAY_HANDSHAKE_TIMEOUT_ID);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_INITIALIZE_4_WAY_HANDSHAKE_TIMEOUT_ID cancelled.\n"),
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e eapol_key_state_c::init_4_way_handshake_start_timeout()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::init_4_way_handshake_start_timeout(): this = 0x%08x, state %d=%s, m_authentication_type %d=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 get_eapol_key_state(),
		 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state()),
		 m_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

	eap_status_e status = m_key_state_partner->set_timer(
		this,
		EAPOL_KEY_STATE_TIMER_INITIALIZE_4_WAY_HANDSHAKE_TIMEOUT_ID, 
		0,
		EAPOL_KEY_STATE_TIMER_INITIALIZE_4_WAY_HANDSHAKE_TIMEOUT);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_INITIALIZE_4_WAY_HANDSHAKE_TIMEOUT_ID set %d ms.\n"),
		 (m_is_client == true ? "client": "server"),
		 EAPOL_KEY_STATE_TIMER_INITIALIZE_4_WAY_HANDSHAKE_TIMEOUT));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::cancel_pmksa_caching_timeout()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::cancel_pmksa_caching_timeout(): this = 0x%08x.\n"),
		 (m_is_client == true) ? "client": "server",
		 this));

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	m_key_state_partner->cancel_timer(this, EAPOL_KEY_STATE_TIMER_PMKSA_CACHING_TIMEOUT_ID);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_PMKSA_CACHING_TIMEOUT_ID cancelled.\n"),
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::cancel_authentication_session()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::cancel_authentication_session(): this = 0x%08x, state %d=%s, m_authentication_type %d=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 get_eapol_key_state(),
		 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state()),
		 m_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

	eap_status_e status(eap_status_process_general_error);

	// RSNA could cache the current PMKSA.
	status = init_pmksa_caching_timeout();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::init_pmksa_caching_timeout()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::init_pmksa_caching_timeout(): this = 0x%08x, state %d=%s, m_authentication_type %d=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 get_eapol_key_state(),
		 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state()),
		 m_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

	eap_status_e status(eap_status_process_general_error);

	{
		m_is_associated = false;

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAPOL_KEY: %s: eapol_key_state_c::init_pmksa_caching_timeout(): m_is_associated=%s.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_associated == true) ? "true": "false"));
	}

	if ((m_authentication_type == eapol_key_authentication_type_RSNA_EAP
#if defined(EAP_USE_WPXM)
			|| get_is_WPXM() == true
#endif //#if defined(EAP_USE_WPXM)
			)
		&& (get_eapol_key_state() == eapol_key_state_4_way_handshake_successfull
			|| get_eapol_key_state() == eapol_key_state_group_key_handshake_successfull
			|| get_eapol_key_state() == eapol_key_state_preauthenticated
#if defined(EAP_USE_WPXM)
			|| get_eapol_key_state() == eapol_key_state_wpxm_reassociation_finished_successfull
#endif //#if defined(EAP_USE_WPXM)
			))
	{
		set_eapol_key_state(eapol_key_state_preauthenticated);
		reset_cached_pmksa();

		u32_t timeout(m_pmksa_caching_timeout);

#if defined(EAP_USE_WPXM)
		if (get_is_WPXM() == true)
		{
			timeout = EAPOL_KEY_STATE_TIMER_WPXM_CACHE_TIMEOUT;
		}
#endif //#if defined(EAP_USE_WPXM)

		status = m_key_state_partner->set_timer(
			this,
			EAPOL_KEY_STATE_TIMER_PMKSA_CACHING_TIMEOUT_ID, 
			0,
			timeout);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_PMKSA_CACHING_TIMEOUT_ID set %d ms.\n"),
			 (m_is_client == true ? "client": "server"),
			 m_pmksa_caching_timeout));

		set_eapol_key_state(eapol_key_state_preauthenticated);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s: Removes PMKSA cache\n"),
			 (m_is_client == true ? "client": "server")));

		// Other authentication modes do not use PMKSA cache, clean-up state.
		reset();

		// Timeout value zero will remove state immediately.
		status = init_handshake_timeout(0ul);
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

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::cancel_retransmission()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (m_is_client == false)
	{
		// Only EAP-server uses timer to re-transmits EAP-packets.
		m_key_state_partner->cancel_timer(this, EAPOL_KEY_STATE_TIMER_RETRANSMISSION_ID);
	}

	if (m_retransmission != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: EAPOL_KEY: EAPOL_KEY_STATE_TIMER_RETRANSMISSION_ID cancelled.\n")));

		if (m_retransmission != 0)
		{
			delete m_retransmission;
			m_retransmission = 0;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::init_retransmission(
	const eap_am_network_id_c * const send_network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const eap_code_value_e eap_code,
	const u8_t eap_identifier,
	const eap_type_value_e eap_type
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (m_retransmission_time == 0u
		|| m_retransmission_counter == 0u)
	{
		// No retransmission.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	EAP_ASSERT(send_network_id->get_source() != 0);
	EAP_ASSERT(send_network_id->get_destination() != 0);

	if (m_is_client == false)
	{
		// Only EAP-server uses timer to re-transmits EAP-packets.
		m_key_state_partner->cancel_timer(this, EAPOL_KEY_STATE_TIMER_RETRANSMISSION_ID);
	}

	if (m_retransmission != 0)
	{
		delete m_retransmission;
		m_retransmission = 0;
	}

	m_retransmission = new eap_core_retransmission_c(
		m_am_tools, 
		send_network_id, 
		sent_packet, 
		header_offset, 
		data_length, 
		m_retransmission_time, 
		m_retransmission_counter,
		eap_code,
		eap_identifier,
		eap_type
		);

	if (m_retransmission == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_retransmission->get_is_valid() == true)
	{
		// Because this object do re-transmission other layers must not do re-transmission of this packet.
		sent_packet->set_do_packet_retransmission(false);

		if (m_is_client == false)
		{
			// Only EAP-server uses timer to re-transmits EAP-packets.
			u32_t next_retransmission_time(m_retransmission->get_next_retransmission_time());

			eap_status_e status = m_key_state_partner->set_timer(this, EAPOL_KEY_STATE_TIMER_RETRANSMISSION_ID, 0,
				next_retransmission_time);
			if (status != eap_status_ok)
			{
				delete m_retransmission;
				m_retransmission = 0;
			}

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("TIMER: EAPOL_KEY: EAPOL_KEY_STATE_TIMER_RETRANSMISSION_ID set %d ms.\n"),
				next_retransmission_time));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
	}
	else
	{
		delete m_retransmission;
		m_retransmission = 0;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::cancel_group_key_update_timeout()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::cancel_group_key_update_timeout(): this = 0x%08x.\n"),
		 (m_is_client == true) ? "client": "server",
		 this));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	m_key_state_partner->cancel_timer(this, EAPOL_KEY_STATE_TIMER_GROUP_KEY_UPDATE_TIMEOUT_ID);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_GROUP_KEY_UPDATE_TIMEOUT_ID cancelled.\n"),
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::init_group_key_update_timeout(
	const u32_t timeout)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::init_group_key_update_timeout(): this = 0x%08x, state %d=%s, m_authentication_type %d=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 get_eapol_key_state(),
		 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state()),
		 m_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

	eap_status_e status = m_key_state_partner->set_timer(
		this,
		EAPOL_KEY_STATE_TIMER_GROUP_KEY_UPDATE_TIMEOUT_ID, 
		0,
		timeout);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: EAPOL_KEY: %s: EAPOL_KEY_STATE_TIMER_GROUP_KEY_UPDATE_TIMEOUT_ID set %d ms.\n"),
		 (m_is_client == true ? "client": "server"),
		 timeout));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eapol_key_state_c::get_marked_removed()
{
	return m_marked_removed;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eapol_key_state_c::set_marked_removed()
{
	m_marked_removed = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eapol_key_state_c::unset_marked_removed()
{
	m_marked_removed = false;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::reset_cached_pmksa()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::reset_cached_pmksa(): this = 0x%08x, state %d=%s, m_authentication_type %d=%s.\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 get_eapol_key_state(),
		 eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state()),
		 m_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

	eap_status_e status = eap_status_ok;

	for (u32_t key_type = 0ul; key_type < eapol_key_type_last_type; key_type++)
	{
		m_received_802_1x_keys[key_type] = false;
	}

	(void) cancel_retransmission();
	(void) cancel_handshake_timeout();
	(void) cancel_pmksa_caching_timeout();
	(void) cancel_reassociate_timeout();
	(void) cancel_4_way_handshake_start_timeout();

	if (get_eapol_key_state() == eapol_key_state_preauthenticated)
	{
		// We must save the preauthenticated PMK and authentication type.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAPOL_KEY: %s: eapol_key_state_c::reset_cached_pmksa(): OK save PMKSA.\n"),
			 (m_is_client == true) ? "client": "server"));
	}
	else
	{
		// In other states PMK and authentication type is reset.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: EAPOL_KEY: %s: eapol_key_state_c::reset_cached_pmksa(): removes PMKSA.\n"),
			 (m_is_client == true) ? "client": "server"));

		if (m_is_client == true)
		{
			// Only client resets these pameters, test server will need these parameters.

			m_pairwise_PMK_WPXK3.reset();

			// Cannot reset m_authentication_type and m_eapol_key_state. These are needed later when possible error notification is send to lower layer.

			m_supplicant_MAC_address.reset();
			m_authenticator_MAC_address.reset();

			m_eapol_pairwise_cipher = eapol_RSNA_key_header_c::eapol_RSNA_cipher_none;
			m_eapol_group_cipher = eapol_RSNA_key_header_c::eapol_RSNA_cipher_none;

			m_authenticator_RSNA_IE.reset();
			m_supplicant_RSNA_IE.reset();

#if defined(EAP_USE_WPXM)
			m_WPXM_WPXK1.reset();
			m_WPXM_WPXK2.reset();
			m_WPXM_WPXC = eapol_key_constant_wpxm_initial_wpxc_counter_value;

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("EAPOL_KEY: eapol_key_state_c::reset_cached_pmksa(): ")
				 EAPL("Reset m_WPXM_WPXC=%d.\n"),
				 m_WPXM_WPXC));
#endif //#if defined(EAP_USE_WPXM)

		}
		else
		{
			set_eapol_key_state(eapol_key_state_none);
		}

		m_PMKID.reset();
		m_transient_PTK.reset();
		m_confirmation_KCK.reset();
		m_encryption_KEK.reset();
		m_temporal_TK.reset();

		// Cannot remove m_send_network_id because it is used
		// as a reference of this eapol_key_state_c object.

		m_ANonce.reset();
		m_SNonce.reset();

	}

	m_received_PMKID.reset();
	m_unicast_cipher_suite_RSNA_IE.reset();
	m_EAPOL_key_IV.reset();

	if (m_is_client == true)
	{
		set_key_reply_counter(0ul);
		set_client_send_key_reply_counter(0ul);

		// Cannot reset m_eapol_key_handshake_type. This is needed later when possible error notification is send to lower layer.
	}
	else
	{
		m_eapol_key_handshake_type = eapol_key_handshake_type_none;
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::reset(): this = 0x%08x.\n"),
		 (m_is_client == true) ? "client": "server",
		 this));

	eap_status_e status = reset_cached_pmksa();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::create_tkip_mic_failure_message(
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t eapol_header_offset,
	u32_t * const data_length,
	u32_t * const buffer_length,
	const eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e tkip_mic_failure_type,
	const eapol_protocol_version_e received_eapol_version)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::create_tkip_mic_failure_message()\n"),
		(m_is_client == true ? "client": "server")));

	// Only client (Supplicant) could create TKIP MIC failure message.
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

	bool pairwise_key = true;
	if (tkip_mic_failure_type == eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_group_key)
	{
		pairwise_key = false;
	}

	status = eapol_key_message.reset_header(
		0ul,
		m_authentication_type,
		m_eapol_pairwise_cipher,
		get_client_send_key_reply_counter(),
		pairwise_key, // Pairwise key type bit.
		false, // Install bit is NOT set.
		false, // Key Ack bit is NOT set.
		true, // Key MIC bit is on.
		false, // Secure bit is NOT set.
		true, // Error bit is on.
		true, // Request bit is on.
		false, // STAKey bit is NOT set.
		false, // Encrypted Key Data bit is NOT set.
		received_eapol_version,
		eapol_key_descriptor_type_none);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	increase_client_send_key_reply_counter();

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

	status = create_key_mic(&eapol_key_message, &m_confirmation_KCK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	sent_packet->set_data_length(
		eapol_header_offset + *data_length);

	TRACE_EAPOL_KEY_MESSAGE(
		"Send TKIP MIC failure Message",
		&eapol_key_message);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::tkip_mic_failure(
	const bool fatal_failure_when_true,
	const eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e tkip_mic_failure_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(fatal_failure_when_true);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::tkip_mic_failure(%d, %d).\n"),
		fatal_failure_when_true,
		tkip_mic_failure_type));

	eap_status_e status = eap_status_not_supported;

	eap_buf_chain_wr_c sent_packet(
		eap_write_buffer,
		m_am_tools);

	if (sent_packet.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t send_data_length = 0ul;
	u32_t send_buffer_length = 0ul;

	status = create_tkip_mic_failure_message(
		&sent_packet,
		m_eapol_header_offset,
		&send_data_length,
		&send_buffer_length,
		tkip_mic_failure_type,
		eapol_protocol_version_2);
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

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::set_pairwise_PMK(
	const eap_variable_data_c * const key,
	const eap_am_network_id_c * const send_network_id)
{
	if (key == 0
		|| key->get_is_valid_data() == false
		|| key->get_data_length() == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t pmk_key_length = key->get_data_length();

	if (m_authentication_type == eapol_key_authentication_type_none)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	else if (m_authentication_type != eapol_key_authentication_type_dynamic_WEP
		&& m_authentication_type != eapol_key_authentication_type_EAP_authentication_no_encryption
	)
	{
		// Truncate PMK only in WPA and RSN case
		if (pmk_key_length > EAPOL_RSNA_PMK_LENGTH_BYTES)
		{
			pmk_key_length = EAPOL_RSNA_PMK_LENGTH_BYTES;
		}
		else if (pmk_key_length < EAPOL_RSNA_PMK_LENGTH_BYTES)
		{
			// No need to expand key. The short key is used as is.
		}
	}


	if (send_network_id->get_type() == eapol_ethernet_type_preauthentication)
	{
		set_eapol_key_state(eapol_key_state_preauthenticated);
	}


	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_key_state_c::set_pairwise_PMK(): key"),
		key->get_data(pmk_key_length),
		pmk_key_length));

	eap_status_e status = m_pairwise_PMK_WPXK3.set_copy_of_buffer(
		key->get_data(pmk_key_length),
		pmk_key_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::verify_field_is_zero(
		const u8_t * const field,
		const u32_t field_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok;

	for (u32_t ind = 0ul; ind < field_length; ind++)
	{
		if (field[ind] != 0)
		{
			status = eap_status_illegal_padding;
			break;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::check_padding(
		const u8_t * const field,
		const u32_t field_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok;

	if (field == 0
		|| field_length == 0ul
		|| field[0] != eapol_RSNA_key_data_type_RSN_key_data
		|| verify_field_is_zero(
			field+1,
			field_length-1) != eap_status_ok)
	{
		status = eap_status_illegal_padding;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eapol_key_state_c::packet_data_session_key(
	eap_variable_data_c * const key, ///< Here is the key.
	const eapol_key_type_e key_type, ///< This the type of the key.
	const u32_t key_index, ///< This is the index of the key.
	const bool key_tx_bit, ///< This is the TX bit of the key.
	const u8_t * const key_RSC, ///< This is the RSC counter
	const u32_t key_RSC_size ///< This is the size of RSC counter
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eapol_session_key_c * eapol_session_key = new eapol_session_key_c(
		m_am_tools,
		key,
		key_type,
		key_index,
		key_tx_bit,
		key_RSC,
		key_RSC_size
		);
	if (eapol_session_key == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (eapol_session_key->get_is_valid() == false)
	{
		delete eapol_session_key;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	eap_status_e status = m_key_state_partner->packet_data_session_key(
		&m_send_network_id,
		eapol_session_key);

	delete eapol_session_key;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::allow_4_way_handshake()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::allow_4_way_handshake()\n"),
		(m_is_client == true ? "client": "server")));

	// Only client (supplicant) could allow 4-Way Handshake.
	EAP_ASSERT_ALWAYS(m_is_client == true);
	
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
			(EAPL("EAPOL_KEY: %s: eapol_key_state_c::allow_4_way_handshake(): ")
			 EAPL("Allow 4-Way Handshake, m_authentication_type=%d=%s\n"),
			(m_is_client == true ? "client": "server"),
			m_authentication_type,
			eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

		m_eapol_key_handshake_type = eapol_key_handshake_type_4_way_handshake;
		m_eapol_key_state = eapol_key_state_wait_4_way_handshake_message_1;
	}
	else if (m_authentication_type == eapol_key_authentication_type_dynamic_WEP)
	{
		// No 4-Way Handshake needed.
		// AP will send unicast and broad cast keys in EAPOL key RC4 messages.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAPOL_KEY: %s: eapol_key_state_c::allow_4_way_handshake(): ")
			 EAPL("Dynamic WEP, m_authentication_type=%d=%s\n"),
			(m_is_client == true ? "client": "server"),
			m_authentication_type,
			eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

		m_eapol_key_handshake_type = eapol_key_handshake_type_dynamic_WEP;
		m_eapol_key_state = eapol_key_state_wait_rc4_key_message;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else if (m_authentication_type == eapol_key_authentication_type_EAP_authentication_no_encryption
			)
	{
		// No 4-Way Handshake needed.
		// AP will send unicast and broad cast keys in EAPOL key messages.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAPOL_KEY: %s: eapol_key_state_c::allow_4_way_handshake(): ")
			 EAPL("Dynamic WEP, m_authentication_type=%d\n"),
			(m_is_client == true ? "client": "server"),
			m_authentication_type));

		m_eapol_key_handshake_type = eapol_key_handshake_type_EAP_authentication_no_encryption;
		m_eapol_key_state = eapol_key_state_802_11i_authentication_finished_successfull;

		{
			// This is notification to eapol_core_c object.
			// EAP authentication without encryption finished successfully.
			eap_state_notification_c * notification = new eap_state_notification_c(
				m_am_tools,
				&m_send_network_id,
				m_is_client,
				eap_state_notification_generic,
				eap_protocol_layer_eapol_key,
				eapol_key_authentication_type_EAP_authentication_no_encryption,
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

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		// No 4-Way Handshake needed.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAPOL_KEY: %s: eapol_key_state_c::allow_4_way_handshake(): ")
			 EAPL("No 4-Way Handshake, m_authentication_type=%d=%s\n"),
			(m_is_client == true ? "client": "server"),
			m_authentication_type,
			eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_authentication_type)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	
	status = init_handshake_timeout(m_handshake_timeout);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if defined(USE_EAPOL_KEY_TEST_FAILURES)
	#pragma message ( "WARNING: USE_EAPOL_KEY_TEST_FAILURES compiler flag used. This is test code, NOT for final release." )
	m_create_key_failure = eapol_key_state_wait_4_way_handshake_message_3;
#endif //#if defined(USE_EAPOL_KEY_TEST_FAILURES)

	status = eap_status_ok;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::start_group_key_handshake(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_protocol_version_e received_eapol_version,
	const eapol_key_descriptor_type_e received_key_descriptor_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

	eap_status_e status = eap_status_process_general_error;

	// server and client could call this.

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("EAPOL_KEY: %s: eapol_key_state_c::start_group_key_handshake()\n"),
		(m_is_client == true ? "client": "server")));

	if (m_eapol_key_handshake_type != eapol_key_handshake_type_authenticated
		&& m_eapol_key_handshake_type != eapol_key_handshake_type_group_key_handshake
		&& m_eapol_key_handshake_type != eapol_key_handshake_type_4_way_handshake)
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
		&& get_eapol_key_state() != eapol_key_state_group_key_handshake_successfull)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: EAPOL_KEY: %s: start_group_key_handshake(): wrong state %s\n"),
			(m_is_client == true ? "client": "server"),
			eapol_key_state_string_c::get_eapol_key_state_string(get_eapol_key_state())));

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
	eapol_key_state_e next_state = eapol_key_state_group_key_handshake_failed;

	if (m_is_client == true)
	{
		status = create_eapol_key_handshake_message_0(
			false,
			&sent_packet,
			m_eapol_header_offset,
			&send_data_length,
			&send_buffer_length,
			0ul,
			received_eapol_version);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		next_state = eapol_key_state_wait_group_key_handshake_message_1;
	}
	else
	{

#if !defined(NO_EAPOL_KEY_STATE_SERVER)

		increase_key_reply_counter();

		status = create_group_key_handshake_message_1(
			&sent_packet,
			m_eapol_header_offset,
			&send_data_length,
			&send_buffer_length,
			received_eapol_version,
			received_key_descriptor_type);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		next_state = eapol_key_state_wait_group_key_handshake_message_2;
#else

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);

#endif //#if !defined(NO_EAPOL_KEY_STATE_SERVER)
	
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
		
	set_eapol_key_state(next_state);

	m_eapol_key_handshake_type = eapol_key_handshake_type_group_key_handshake;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::get_key_length(
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e cipher,
	u16_t * const key_length)
{
	if (cipher
		== eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP)
	{
		*key_length = eapol_RSNA_key_header_c::eapol_RSNA_cipher_key_length_CCMP;
	}
	else if (cipher
			 == eapol_RSNA_key_header_c::eapol_RSNA_cipher_TKIP)
	{
		*key_length = eapol_RSNA_key_header_c::eapol_RSNA_cipher_key_length_TKIP;
	}
	else if (cipher
			 == eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_40)
	{
		*key_length = eapol_RSNA_key_header_c::eapol_RSNA_cipher_key_length_WEP_40;
	}
	else if (cipher
			 == eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_104)
	{
		*key_length = eapol_RSNA_key_header_c::eapol_RSNA_cipher_key_length_WEP_104;
	}
	else
	{
		*key_length = 0ul;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_4_way_handshake_message(
	const eap_am_network_id_c * const receive_network_id,
	eapol_RSNA_key_header_c * const eapol_key_message,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	

#if !defined(NO_EAPOL_KEY_STATE_SERVER)
	if (m_is_client == false
		&& eapol_key_message->get_key_information_request() == true
		&& eapol_key_message->get_key_information_key_MIC() == true
		&& eapol_key_message->get_key_information_key_ack() == false
		&& eapol_key_message->get_key_information_install() == false
		&& eapol_key_message->get_key_data_length() == 0ul)
	{
		// Message 0 to start 4-Way Handshake. Only server handles this.
		status = process_4_way_handshake_message_0(
			receive_network_id,
			eapol_key_message,
			packet_length);
	}
	else
#endif //#if !defined(NO_EAPOL_KEY_STATE_SERVER)
	if (m_is_client == true
		&& eapol_key_message->get_key_information_key_MIC() == false
		&& eapol_key_message->get_key_information_key_ack() == true
		&& eapol_key_message->get_key_information_install() == false)
	{
		// Message 1 of 4-Way Handshake. Only client handles this.
		status = process_4_way_handshake_message_1(
			receive_network_id,
			eapol_key_message,
			packet_length);
	}
	else
#if !defined(NO_EAPOL_KEY_STATE_SERVER)
	if (m_is_client == false
		&& eapol_key_message->get_key_information_key_MIC() == true
		&& eapol_key_message->get_key_information_key_ack() == false
		&& eapol_key_message->get_key_information_install() == false
		&& eapol_key_message->get_key_data_length() != 0ul)
	{
		// Message 2 of 4-Way Handshake. Only server handles this.
		status = process_4_way_handshake_message_2(
			receive_network_id,
			eapol_key_message,
			packet_length);
	}
	else
#endif //#if !defined(NO_EAPOL_KEY_STATE_SERVER)
	if (m_is_client == true
		&& eapol_key_message->get_key_information_key_MIC() == true
		&& eapol_key_message->get_key_information_key_ack() == true
		&& eapol_key_message->get_key_information_install() == true
		&& eapol_key_message->get_key_data_length() != 0ul)
	{
		// Message 3 of 4-Way Handshake. Only client handles this.
		status = process_4_way_handshake_message_3(
			receive_network_id,
			eapol_key_message,
			packet_length);
	}
	else
#if !defined(NO_EAPOL_KEY_STATE_SERVER)
	if (m_is_client == false
		&& eapol_key_message->get_key_information_key_MIC() == true
		&& eapol_key_message->get_key_information_key_ack() == false
		&& eapol_key_message->get_key_information_install() == false
		&& eapol_key_message->get_key_data_length() == 0ul)
	{
		// Message 4 of 4-Way Handshake. Only server handles this.
		status = process_4_way_handshake_message_4(
			receive_network_id,
			eapol_key_message,
			packet_length);
	}
	else
#endif //#if !defined(NO_EAPOL_KEY_STATE_SERVER)
	{
		// ERROR. Drop packet.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: Illegal EAPOL-Key 4-Way Handshake frame: ")
			 EAPL("IsClient: %d MIC %d, Key Ack %d, Install %d, Key Length %d\n"),
			m_is_client,
			eapol_key_message->get_key_information_key_MIC(),
			eapol_key_message->get_key_information_key_ack(),
			eapol_key_message->get_key_information_install(),
			eapol_key_message->get_key_data_length()));
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_group_key_handshake_message(
	const eap_am_network_id_c * const receive_network_id,
	eapol_RSNA_key_header_c * const eapol_key_message,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

#if !defined(NO_EAPOL_KEY_STATE_SERVER)
	if (m_is_client == false
		&& eapol_key_message->get_key_information_key_MIC() == true
		&& eapol_key_message->get_key_information_key_ack() == false
		&& eapol_key_message->get_key_information_request() == true)
	{
		// Message 0 of Group Key Handshake. Only server handles this.
		status = process_group_key_handshake_message_0(
			receive_network_id,
			eapol_key_message,
			packet_length);
	}
	else
#endif //#if !defined(NO_EAPOL_KEY_STATE_SERVER)
	if (m_is_client == true
		&& eapol_key_message->get_key_information_key_MIC() == true
		&& eapol_key_message->get_key_information_key_ack() == true
		&& eapol_key_message->get_key_information_request() == false)
	{
		// Message 1 of Group Key Handshake. Only client handles this.
		status = process_group_key_handshake_message_1(
			receive_network_id,
			eapol_key_message,
			packet_length);
	}
	else
#if !defined(NO_EAPOL_KEY_STATE_SERVER)
	if (m_is_client == false
		&& eapol_key_message->get_key_information_key_MIC() == true
		&& eapol_key_message->get_key_information_key_ack() == false
		&& eapol_key_message->get_key_information_request() == false)
	{
		// Message 2 of Group Key Handshake. Only server handles this.
		status = process_group_key_handshake_message_2(
			receive_network_id,
			eapol_key_message,
			packet_length);
	}
	else
#endif //#if !defined(NO_EAPOL_KEY_STATE_SERVER)
	{
		// ERROR. Drop packet.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("ERROR: EAPOL_KEY: Illegal EAPOL-Key Group Key Handshake frame: ")
			 EAPL("MIC %d, Key Ack %d, Request %d\n"),
			eapol_key_message->get_key_information_key_MIC(),
			eapol_key_message->get_key_information_key_ack(),
			eapol_key_message->get_key_information_request()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::process_RSNA_key_descriptor(
	const eap_am_network_id_c * const receive_network_id,
	eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	if (packet_length < eapol_RSNA_key_header_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	eapol_RSNA_key_header_c eapol_key_message(
		m_am_tools,
		get_is_RSNA(),
		get_is_WPXM(),
		packet_data->get_header_buffer(packet_data->get_header_buffer_length()),
		packet_data->get_header_buffer_length());
	if (eapol_key_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	status = eapol_key_message.check_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	TRACE_EAPOL_KEY_MESSAGE(
		"Received EAPOL Handshake Message",
		&eapol_key_message);

	u64_t packet_reply_counter = eapol_key_message.get_key_replay_counter();

	// compare_u64() function is used because in some platforms
	// unsigned 64-bit comparison is actually signed 64-bit comparison,
	// because unsigned 64-bit integer is implemented as a signed 64-bit integer.
	// This causes failures in test if broken AP sends Key Replay Counter with
	// highest bit set 1.
	i32_t comparison(m_am_tools->compare_u64(get_key_reply_counter(), packet_reply_counter));

	if (m_is_client == true)
	{
		// On client Key Reply Counter must be bigger
		// than on any other previous frame.
		//if (get_key_reply_counter() > packet_reply_counter)
		if (comparison > 0)
		{
			// ERROR. Drop packet.
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
				(EAPL("ERROR: EAPOL_KEY: Illegal EAPOL-Key frame Reply Counter\n")));
			EAP_TRACE_DATA_ERROR(
				m_am_tools,
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
				(EAPL("Local Reply Counter"),
				&m_key_reply_counter,
				sizeof(m_key_reply_counter)));
			EAP_TRACE_DATA_ERROR(
				m_am_tools,
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
				(EAPL("Packet Reply Counter"),
				&packet_reply_counter,
				sizeof(packet_reply_counter)));

			if (get_is_WPXM() == true)
			{
				// Here we must ignore the Reply Counter failure.
				// WPXM seems to work against RSN specification that says
				// every packet must be sent with new Reply Counter.
				// WPXM starts Group Key Handshake with Reply Counter 0 after successfull
				// 4-Way Handshake.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WARNING: EAPOL_KEY: Illegal EAPOL-Key frame Reply Counter in WPXM.\n")));
			}
			else
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
			}
		}
		else if (comparison == 0)
		{
			// This may be re-transmitted request.
			// Send the saved previous response
			// or process this message again.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: EAPOL_KEY: EAPOL-Key frame Reply Counter same as previous request.\n")));
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: Local Reply Counter"),
				&m_key_reply_counter,
				sizeof(m_key_reply_counter)));
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: Packet Reply Counter"),
				&packet_reply_counter,
				sizeof(packet_reply_counter)));
		}
	}
	else
	{
		if (eapol_key_message.get_key_information_request() == true)
		{
			// Reply Counter of request packets are not checked.
			comparison = 0;
		}

		// On server Key Reply Counter must be same
		// as the sent request frame.
		if (comparison != 0)
		{
			// ERROR. Drop packet.
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
				(EAPL("ERROR: EAPOL_KEY: Illegal EAPOL-Key frame Reply Counter\n")));
			EAP_TRACE_DATA_ERROR(
				m_am_tools,
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
				(EAPL("Local Reply Counter"),
				&m_key_reply_counter,
				sizeof(m_key_reply_counter)));
			EAP_TRACE_DATA_ERROR(
				m_am_tools,
				TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
				(EAPL("Packet Reply Counter"),
				&packet_reply_counter,
				sizeof(packet_reply_counter)));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
		}
	}


	if (eapol_key_message.get_key_information_key_type() == true)
	{
		// 4-Way Handshake message.
		status = process_4_way_handshake_message(
			receive_network_id,
			&eapol_key_message,
			packet_length);
	}
	else if (eapol_key_message.get_key_information_key_type() == false)
	{
		// Group Key Handshake message.
		status = process_group_key_handshake_message(
			receive_network_id,
			&eapol_key_message,
			packet_length);
	}
	else
	{
		// Unknown message received and dropped quietly.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_EAPOL_KEY_DATA_ERROR,
			(EAPL("WARNING: EAPOL_KEY: Handshake in NOT supported in m_eapol_key_handshake_type %s.\n"),
			eapol_key_state_string_c::get_eapol_key_handshake_type_string(m_eapol_key_handshake_type)));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// End.
