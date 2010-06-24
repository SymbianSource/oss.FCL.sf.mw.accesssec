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
* %version: 5.1.3 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 713 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_tools.h"
#include "eap_core.h"
#include "eap_type_tls_peap_types.h"
#include "tls_record_header.h"
#include "abs_tls_base_application.h"
#include "tls_application_eap_core.h"
#include "tls_peap_types.h"
#include "tls_peap_tlv_header.h"
#include "eap_diameter_avp_header.h"
#include "eap_state_notification.h"
#include "eap_crypto_api.h"
#include "eap_header_string.h"
#include "abs_eap_am_mutex.h"
#include "eap_config.h"
#include "eapol_header.h"
#include "eap_network_id_selector.h"
#include "eap_tlv_message_data.h"
#include "eap_array_algorithms.h"
#include "eap_automatic_variable.h"
#include "eap_base_type.h"

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	#include "eap_type_mschapv2_types.h"
	#include "eap_type_mschapv2_header.h"
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)


//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::check_ttls_plain_mschapv2_payloads(
	eap_diameter_payloads_c * const payloads,
	eap_ttls_tunneled_message_type_e * const message_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::check_ttls_plain_mschapv2_payloads()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::check_ttls_plain_mschapv2_payloads()");

	*message_type = eap_ttls_tunneled_message_type_none;

	eap_status_e status(eap_status_not_found);

	eap_array_c<eap_diameter_avp_code_c> needed_payloads(m_am_tools);

	if (m_is_client == false)
	{
		{
			// First check are there User-Name, MS-CHAP-Challenge and MS-CHAP2-Response AVPs.

			needed_payloads.reset();

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			eap_diameter_avp_code_c code_user_name(
				eap_diameter_avp_code_user_name);

			status = needed_payloads.add_object(&code_user_name, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			eap_diameter_avp_code_c code_ms_chap_challenge(
				eap_diameter_vendor_code_of_microsoft_ms_chap_challenge.get_code());

			status = needed_payloads.add_object(&code_ms_chap_challenge, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			eap_diameter_avp_code_c code_ms_chap2_response(
				eap_diameter_vendor_code_of_microsoft_ms_chap2_response.get_code());

			status = needed_payloads.add_object(&code_ms_chap2_response, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			// Test the required attribute.
			status = payloads->check_payloads_existense(
				&needed_payloads);
			if (status == eap_status_ok)
			{
				// This packet includes required AVPs.

				status = payloads->check_mandatory_payloads(
					&needed_payloads);
				if (status == eap_status_ok)
				{
					// All mandatory AVPs are included.

					*message_type = eap_ttls_tunneled_message_type_ms_chapv2_response;

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("Match User-Name, MS-CHAP-Challenge and MS-CHAP2-Response AVPs.\n")));

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}

		{
			// Second check are there MS-CHAP-NT-Enc-PW, MS-CHAP2-CPW, and MS-CHAP-Challenge AVPs.

			needed_payloads.reset();

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			eap_diameter_avp_code_c code_ms_chap_nt_enc_pw(
				eap_diameter_vendor_code_of_microsoft_ms_chap_nt_enc_pw.get_code());

			status = needed_payloads.add_object(&code_ms_chap_nt_enc_pw, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			eap_diameter_avp_code_c code_ms_chap2_cpw(
				eap_diameter_vendor_code_of_microsoft_ms_chap2_cpw.get_code());

			status = needed_payloads.add_object(&code_ms_chap2_cpw, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			eap_diameter_avp_code_c code_ms_chap_challenge(
				eap_diameter_vendor_code_of_microsoft_ms_chap_challenge.get_code());

			status = needed_payloads.add_object(&code_ms_chap_challenge, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			// Test the required attribute.
			status = payloads->check_payloads_existense(
				&needed_payloads);
			if (status == eap_status_ok)
			{
				// This packet includes required AVPs.

				status = payloads->check_mandatory_payloads(
					&needed_payloads);
				if (status == eap_status_ok)
				{
					// All mandatory AVPs are included.

					*message_type = eap_ttls_tunneled_message_type_ms_chapv2_change_password;

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("Match MS-CHAP-NT-Enc-PW, MS-CHAP2-CPW, and MS-CHAP-Challenge AVPs.\n")));

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
	}
	else //if (m_is_client == true)
	{
		{
			// First check are there MS-CHAP2-Success AVP.

			needed_payloads.reset();

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			eap_diameter_avp_code_c code_ms_chap2_success(
				eap_diameter_vendor_code_of_microsoft_ms_chap2_success.get_code());

			status = needed_payloads.add_object(&code_ms_chap2_success, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			// Test the required attribute.
			status = payloads->check_payloads_existense(
				&needed_payloads);
			if (status == eap_status_ok)
			{
				// This packet includes required AVPs.

				status = payloads->check_mandatory_payloads(
					&needed_payloads);
				if (status == eap_status_ok)
				{
					// All mandatory AVPs are included.

					*message_type = eap_ttls_tunneled_message_type_ms_chapv2_success;

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("Match MS-CHAP2-Success AVP.\n")));

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}

		{
			// Second check are there MS-CHAP2-Error AVP.

			needed_payloads.reset();

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			eap_diameter_avp_code_c code_ms_chap_error(
				eap_diameter_vendor_code_of_microsoft_ms_chap_error.get_code());

			status = needed_payloads.add_object(&code_ms_chap_error, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			// Test the required attribute.
			status = payloads->check_payloads_existense(
				&needed_payloads);
			if (status == eap_status_ok)
			{
				// This packet includes required AVPs.

				status = payloads->check_mandatory_payloads(
					&needed_payloads);
				if (status == eap_status_ok)
				{
					// All mandatory AVPs are included.

					*message_type = eap_ttls_tunneled_message_type_ms_chapv2_error;

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("Match MS-CHAP2-Error AVP.\n")));

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_server_handles_ms_chapv2_response(
	eap_diameter_payloads_c * const /* payloads */,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: function: tls_application_eap_core_c::ttls_server_handles_ms_chapv2_response(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_server_handles_ms_chapv2_response()");

	eap_status_e status(eap_status_not_found);

	eap_diameter_variable_data_c * const user_name_payload
		= m_ttls_received_payloads.get_payload(eap_diameter_avp_code_user_name);

	if (user_name_payload == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_variable_data_c * const user_name
		= user_name_payload->get_payload_buffer();

	if (user_name->get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}


	status = get_application_partner()->get_ttls_implicit_challenge(
		&m_ttls_implicit_challenge,
		EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_FULL_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const u8_t * const mschapv2_challenge = m_ttls_implicit_challenge.get_data_offset(
		EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_OFFSET,
		EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_LENGTH);
	if (mschapv2_challenge == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ttls_server_handles_ms_chapv2_response(): mschapv2_challenge"),
		 mschapv2_challenge,
		 EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_LENGTH));

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

		eap_network_id_selector_c state_selector(
			m_am_tools,
			&m_receive_network_id);

		status = memory_store_key.add_data(
			&state_selector);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_tlv_message_data_c tlv_data(m_am_tools);

		status = tlv_data.add_message_data(
			eap_type_mschapv2_implicit_challenge,
			EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_LENGTH,
			mschapv2_challenge);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_am_tools->memory_store_remove_data(&memory_store_key);
		if (status != eap_status_ok
			&& status != eap_status_not_found)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_am_tools->memory_store_add_data(
			&memory_store_key,
			&tlv_data,
			eap_type_default_credential_timeout);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ttls_server_handles_ms_chapv2_response(): cannot store credentials\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// We must create EAP-Response/Identity message and forward that message
	// to tunneled EAP-MsChapv2.

	u32_t eap_length = eap_header_wr_c::get_header_length() + 1ul + user_name->get_data_length();

	eap_buf_chain_wr_c eap_packet_buffer(
		eap_write_buffer,
		m_am_tools,
		eap_length);

	if (eap_packet_buffer.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_header_wr_c forwarded_eap_packet(
		m_am_tools,
		eap_packet_buffer.get_data(eap_length),
		eap_length);

	if (forwarded_eap_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	forwarded_eap_packet.reset_header(
		static_cast<u16_t>(eap_length),
		m_use_eap_expanded_type);
	forwarded_eap_packet.set_identifier(received_eap_identifier);
	forwarded_eap_packet.set_code(eap_code_response);
	forwarded_eap_packet.set_length(
		static_cast<u16_t>(eap_length),
		m_use_eap_expanded_type);
	forwarded_eap_packet.set_type(
		eap_type_identity,
		m_use_eap_expanded_type);

	u8_t * const eap_type_data = forwarded_eap_packet.get_type_data(user_name->get_data_length());
	if (eap_type_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_am_tools->memmove(eap_type_data, user_name->get_data(), user_name->get_data_length());

	set_ttls_tunneled_message_state(eap_ttls_tunneled_message_state_process_identity_response);

	status = packet_forward_to_tunnel(
		&m_receive_network_id,
		&forwarded_eap_packet,
		eap_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_server_handles_ms_chapv2_change_password(
	eap_diameter_payloads_c * const /* payloads */,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::ttls_server_handles_ms_chapv2_change_password()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_server_handles_ms_chapv2_change_password()");

	eap_status_e status(eap_status_not_found);

	const u32_t type_data_length = EAP_MSCHAPV2_HEADER_SIZE // OpCode, MS-CHAPv2-ID and MS-Length
		+ mschapv2_change_password_c::get_header_minimum_size();

	const u32_t eap_length = eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
		+ type_data_length;

	eap_buf_chain_wr_c eap_packet_buffer(
		eap_write_buffer,
		m_am_tools,
		eap_length);
	if (eap_packet_buffer.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_header_wr_c forwarded_eap_packet(
		m_am_tools,
		eap_packet_buffer.get_data(eap_length),
		eap_length);
	if (forwarded_eap_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	forwarded_eap_packet.set_code(eap_code_response);
	forwarded_eap_packet.set_identifier(received_eap_identifier);
	forwarded_eap_packet.set_length(
		static_cast<u16_t>(eap_length),
		m_use_eap_expanded_type);
	forwarded_eap_packet.set_type(
		eap_type_mschapv2,
		m_use_eap_expanded_type);

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		forwarded_eap_packet.get_type_data_offset(0, forwarded_eap_packet.get_type_data_length()),
		forwarded_eap_packet.get_type_data_length());
	mschapv2_header.set_opcode(mschapv2_opcode_change_password);

	const u8_t * const mschapv2ident = m_ttls_implicit_challenge.get_data_offset(
		EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_IDENT_OFFSET,
		sizeof(u8_t));
	if (mschapv2ident == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ttls_server_handles_ms_chapv2_change_password(): mschapv2ident"),
		 mschapv2ident,
		 sizeof(*mschapv2ident)));

	mschapv2_header.set_mschapv2_id(*mschapv2ident);
	mschapv2_header.set_ms_length(static_cast<u16_t>(type_data_length));

	mschapv2_change_password_c response(
		m_am_tools,
		mschapv2_header.get_data(),
		mschapv2_header.get_data_length());
	if (response.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = response.set_constants();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		eap_diameter_variable_data_c * const nt_enc_pw_payload
			= m_ttls_received_payloads.get_payload(
				eap_diameter_vendor_code_of_microsoft_ms_chap_nt_enc_pw.get_code());

		if (nt_enc_pw_payload == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		eap_variable_data_c * const nt_enc_pw
			= nt_enc_pw_payload->get_payload_buffer();

		if (nt_enc_pw == 0
			|| nt_enc_pw->get_is_valid_data() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		if (nt_enc_pw->get_data_length() != EAP_MSCHAPV2_CHANGE_PASSWORD_ENCRYPTED_PASSWORD_SIZE)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		response.set_encrypted_pw_block(nt_enc_pw->get_data());
	}

	{
		eap_diameter_variable_data_c * const cpw_payload
			= m_ttls_received_payloads.get_payload(
				eap_diameter_vendor_code_of_microsoft_ms_chap2_cpw.get_code());

		if (cpw_payload == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		eap_variable_data_c * const cpw
			= cpw_payload->get_payload_buffer();

		if (cpw == 0
			|| cpw->get_is_valid_data() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		if (cpw->get_data_length()
			!= (EAP_MSCHAPV2_CHANGE_PASSWORD_ENCRYPTED_HASH_SIZE
				+ EAP_MSCHAPV2_PEER_CHALLENGE_SIZE
				+ EAP_MSCHAPV2_NT_RESPONSE_SIZE))
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u32_t offset = 0ul;

		response.set_encrypted_hash(
			cpw->get_data_offset(offset, EAP_MSCHAPV2_CHANGE_PASSWORD_ENCRYPTED_HASH_SIZE));

		offset += EAP_MSCHAPV2_CHANGE_PASSWORD_ENCRYPTED_HASH_SIZE;

		response.set_peer_challenge(
			cpw->get_data_offset(offset, EAP_MSCHAPV2_PEER_CHALLENGE_SIZE));

		offset += EAP_MSCHAPV2_PEER_CHALLENGE_SIZE;

		response.set_nt_response(
			cpw->get_data_offset(offset, EAP_MSCHAPV2_NT_RESPONSE_SIZE));
	}

	status = packet_forward_to_tunnel(
		&m_receive_network_id,
		&forwarded_eap_packet,
		eap_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_ttls_tunneled_message_state(eap_ttls_tunneled_message_state_process_change_password_response);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_client_handles_ms_chapv2_success(
	eap_diameter_payloads_c * const /* payloads */,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::ttls_client_handles_ms_chapv2_success()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_client_handles_ms_chapv2_success()");

	eap_status_e status(eap_status_not_found);

	eap_diameter_variable_data_c * const success_data_payload
		= m_ttls_received_payloads.get_payload(
			eap_diameter_vendor_code_of_microsoft_ms_chap2_success.get_code());

	if (success_data_payload == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_variable_data_c * const success_data
		= success_data_payload->get_payload_buffer();

	if (success_data == 0
		|| success_data->get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	const u32_t type_data_length
		= EAP_MSCHAPV2_HEADER_SIZE // OpCode, MS-CHAPv2-ID and MS-Length
		+ (success_data->get_data_length() - 1ul);

	const u32_t eap_length
		= eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
		+ type_data_length;

	eap_buf_chain_wr_c eap_packet_buffer(
		eap_write_buffer,
		m_am_tools,
		eap_length);
	if (eap_packet_buffer.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_header_wr_c forwarded_eap_packet(
		m_am_tools,
		eap_packet_buffer.get_data(eap_length),
		eap_length);

	if (forwarded_eap_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	forwarded_eap_packet.reset_header(
		static_cast<u16_t>(eap_length),
		m_use_eap_expanded_type);
	forwarded_eap_packet.set_identifier(static_cast<u8_t>(received_eap_identifier+1ul));
	forwarded_eap_packet.set_code(eap_code_request);
	forwarded_eap_packet.set_length(
		static_cast<u16_t>(eap_length),
		m_use_eap_expanded_type);

	u8_t * const eap_data = forwarded_eap_packet.get_data(success_data->get_data_length());
	if (eap_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	forwarded_eap_packet.set_type(
		eap_type_mschapv2,
		m_use_eap_expanded_type);

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		forwarded_eap_packet.get_type_data_offset(
			0,
			forwarded_eap_packet.get_type_data_length()),
		forwarded_eap_packet.get_type_data_length());

	mschapv2_header.set_opcode(mschapv2_opcode_success);

	const u8_t * const mschapv2ident = m_ttls_implicit_challenge.get_data_offset(
		EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_IDENT_OFFSET,
		sizeof(u8_t));
	if (mschapv2ident == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ttls_client_handles_ms_chapv2_success(): mschapv2ident"),
		 mschapv2ident,
		 sizeof(*mschapv2ident)));

	mschapv2_header.set_mschapv2_id(*mschapv2ident);
	mschapv2_header.set_ms_length(static_cast<u16_t>(type_data_length));

	mschapv2_response_c response(
		m_am_tools,
		mschapv2_header.get_data(),
		mschapv2_header.get_data_length());
	if (response.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = response.set_constants();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u8_t * ms_success_data = mschapv2_header.get_data();
	if (ms_success_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (success_data->get_data_length() < 1ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// Copy auth string after headers
	m_am_tools->memmove(
		ms_success_data,
		success_data->get_data_offset(1ul, success_data->get_data_length() - 1ul),
		success_data->get_data_length() - 1ul);

	set_ttls_tunneled_message_state(eap_ttls_tunneled_message_state_process_success_request);

	status = packet_forward_to_tunnel(
		&m_receive_network_id,
		&forwarded_eap_packet,
		eap_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_complete_success_request)
	{
		eap_header_wr_c sent_eap_packet(
			m_am_tools,
			m_ttls_sent_eap_packet.get_data(),
			m_ttls_sent_eap_packet.get_data_length());

		status = ttls_tunneled_message_state_complete_success_request(&sent_eap_packet);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_client_handles_ms_chapv2_error(
	eap_diameter_payloads_c * const /* payloads */,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::ttls_client_handles_ms_chapv2_error()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_client_handles_ms_chapv2_error()");

	eap_status_e status(eap_status_not_found);

	eap_diameter_variable_data_c * const error_data_payload
		= m_ttls_received_payloads.get_payload(
			eap_diameter_vendor_code_of_microsoft_ms_chap_error.get_code());

	if (error_data_payload == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_variable_data_c * const error_data
		= error_data_payload->get_payload_buffer();

	if (error_data == 0
		|| error_data->get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	const u32_t type_data_length = EAP_MSCHAPV2_HEADER_SIZE // OpCode, MS-CHAPv2-ID and MS-Length
			+ mschapv2_challenge_c::get_header_minimum_size()
			+ error_data->get_data_length();

	const u32_t eap_length
		= eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
		+ type_data_length;

	eap_buf_chain_wr_c eap_packet_buffer(
		eap_write_buffer,
		m_am_tools,
		eap_length);
	if (eap_packet_buffer.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_header_wr_c forwarded_eap_packet(
		m_am_tools,
		eap_packet_buffer.get_data(eap_length),
		eap_length);

	if (forwarded_eap_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	forwarded_eap_packet.reset_header(
		static_cast<u16_t>(eap_length),
		m_use_eap_expanded_type);
	forwarded_eap_packet.set_identifier(static_cast<u8_t>(received_eap_identifier+1ul));
	forwarded_eap_packet.set_code(eap_code_request);
	forwarded_eap_packet.set_length(
		static_cast<u16_t>(eap_length),
		m_use_eap_expanded_type);

	u8_t * const eap_data = forwarded_eap_packet.get_data(error_data->get_data_length());
	if (eap_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	forwarded_eap_packet.set_type(
		eap_type_mschapv2,
		m_use_eap_expanded_type);

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		forwarded_eap_packet.get_type_data_offset(
			0,
			forwarded_eap_packet.get_type_data_length()),
		forwarded_eap_packet.get_type_data_length());

	mschapv2_header.set_opcode(mschapv2_opcode_failure);

	const u8_t * const mschapv2ident = m_ttls_implicit_challenge.get_data_offset(
		EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_IDENT_OFFSET,
		sizeof(u8_t));
	if (mschapv2ident == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ttls_client_handles_ms_chapv2_error(): mschapv2ident"),
		 mschapv2ident,
		 sizeof(*mschapv2ident)));

	mschapv2_header.set_mschapv2_id(*mschapv2ident);
	mschapv2_header.set_ms_length(static_cast<u16_t>(type_data_length));

	mschapv2_response_c response(
		m_am_tools,
		mschapv2_header.get_data(),
		mschapv2_header.get_data_length());
	if (response.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = response.set_constants();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u8_t * ms_error_data = mschapv2_header.get_data();
	if (ms_error_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// Copy auth string after headers
	m_am_tools->memmove(
		ms_error_data,
		error_data->get_data(),
		error_data->get_data_length());

	set_ttls_tunneled_message_state(eap_ttls_tunneled_message_state_process_error_request);

	status = packet_forward_to_tunnel(
		&m_receive_network_id,
		&forwarded_eap_packet,
		eap_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_complete_error_request)
	{
		eap_header_wr_c sent_eap_packet(
			m_am_tools,
			m_ttls_sent_eap_packet.get_data(),
			m_ttls_sent_eap_packet.get_data_length());

		status = ttls_tunneled_message_state_complete_error_request(&sent_eap_packet);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::handle_ttls_plain_mschapv2_payloads(
	eap_diameter_payloads_c * const payloads,
	const eap_ttls_tunneled_message_type_e message_type,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::handle_ttls_plain_mschapv2_payloads()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::handle_ttls_plain_mschapv2_payloads()");

	eap_status_e status(eap_status_not_found);

	switch(message_type)
	{
	case eap_ttls_tunneled_message_type_ms_chapv2_response:
		// Here are included User-Name, MS-CHAP-Challenge and MS-CHAP2-Response AVPs.
		status = ttls_server_handles_ms_chapv2_response(payloads, received_eap_identifier);
		break;
	case eap_ttls_tunneled_message_type_ms_chapv2_change_password:
		// Here are included MS-CHAP-NT-Enc-PW, MS-CHAP2-CPW, and MS-CHAP-Challenge AVPs.
		status = ttls_server_handles_ms_chapv2_change_password(payloads, received_eap_identifier);
		break;
	case eap_ttls_tunneled_message_type_ms_chapv2_success:
		// Here is included MS-CHAP2-Success AVP.
		status = ttls_client_handles_ms_chapv2_success(payloads, received_eap_identifier);
		break;
	case eap_ttls_tunneled_message_type_ms_chapv2_error:
		// Here is included MS-CHAP2-Error AVP.
		status = ttls_client_handles_ms_chapv2_error(payloads, received_eap_identifier);
		break;
	default:
		status = eap_status_unexpected_message;
		break;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::create_ttls_diameter_avp(
	eap_variable_data_c * const avp,
	const eap_variable_data_c * const data,
	eap_diameter_avp_code_c code,
	const bool include_vendor_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::create_ttls_diameter_avp()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::create_ttls_diameter_avp()");

	if (avp == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (data == 0
		|| data->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (code.get_vendor_code() == eap_diameter_avp_code_none)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = avp->reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	bool needs_vendor_id = include_vendor_id;
	if (code.get_vendor_id() != eap_diameter_vendor_id_of_ietf)
	{
		needs_vendor_id = true;
	}

	const u32_t padding_byte_data = 3ul;
	const u32_t avp_payload_length
		= eap_diameter_avp_header_c::get_header_length(needs_vendor_id) + data->get_data_length();

	status = avp->set_buffer_length(avp_payload_length + padding_byte_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (avp->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = avp->set_data_length(avp_payload_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_diameter_avp_header_c avp_header(
		m_am_tools,
		avp->get_data(),
		avp->get_data_length());
	if (avp_header.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// These packets are encapsulated to AVP.
	//  0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                           AVP Code                            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |V|M|r r r r r r|                  AVP Length                   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                      Vendor-ID (optional)                     |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                   Data ...
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	status = avp_header.reset_header(static_cast<u16_t>(avp_payload_length));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = avp_header.set_avp_code(code);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = avp_header.set_avp_flag_mandatory_avp(false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	{
		// Adds data as a payload to AVP.
		u16_t * const avp_payload = reinterpret_cast<u16_t *>(
			avp_header.get_data_offset(0ul, data->get_data_length()));
		if (avp_payload == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_am_tools->memmove(
			avp_payload,
			data->get_data(),
			data->get_data_length());
	}

	u32_t padding_length = avp_header.get_padding_length();
	if (padding_length != 0ul)
	{
		// Add padding.
		u8_t padding_byte = 0ul;

		for (u32_t ind = 0ul; ind < padding_length; ind++)
		{
			status = avp->add_data(
				&padding_byte,
				sizeof(padding_byte));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		} // for()
	}

	EAP_TLS_PEAP_TRACE_TTLS_PAYLOAD("Created TTLS AVP payload", &avp_header, m_is_client);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_tunneled_message_state_process_identity_response(
	eap_header_wr_c * const sent_eap_packet)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: function: tls_application_eap_core_c::ttls_tunneled_message_state_process_identity_response(): ")
		 EAPL("this = 0x%08x, m_ttls_tunneled_message_state=%d=%s, EAP-type=%d\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 get_ttls_tunneled_message_state(),
		 eap_tls_trace_string_c::get_ttls_state_string(get_ttls_tunneled_message_state()),
		 convert_eap_type_to_u32_t(sent_eap_packet->get_type())));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_tunneled_message_state_process_identity_response()");

	eap_status_e status(eap_status_process_general_error);

	// This message shoud include MS-CHAP-V2 Challenge.
	// We ignore this Challenge and instead we send Implicit Challenge from client.
	/**
	 * @{ This will require changes in EAP-MsChapv2 server.
	 * Implicit Challenge need to be used in authentication check. }
	 */

	const u8_t * const mschapv2ident = m_ttls_implicit_challenge.get_data_offset(
		EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_IDENT_OFFSET,
		sizeof(u8_t));
	if (mschapv2ident == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ttls_tunneled_message_state_process_identity_response(): mschapv2ident"),
		 mschapv2ident,
		 sizeof(*mschapv2ident)));

	eap_diameter_variable_data_c * const user_name_payload
		= m_ttls_received_payloads.get_payload(eap_diameter_avp_code_user_name);

	if (user_name_payload == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_variable_data_c * const user_name
		= user_name_payload->get_payload_buffer();

	if (user_name != 0
		&& user_name->get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	const u32_t type_data_length = EAP_MSCHAPV2_HEADER_SIZE // OpCode, MS-CHAPv2-ID and MS-Length
		+ mschapv2_response_c::get_header_minimum_size()
		+ user_name->get_data_length();

	const u32_t eap_length = eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
		+ type_data_length;

	eap_buf_chain_wr_c eap_packet_buffer(
		eap_write_buffer,
		m_am_tools,
		eap_length);
	if (eap_packet_buffer.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_header_wr_c forwarded_eap_packet(
		m_am_tools,
		eap_packet_buffer.get_data(eap_length),
		eap_length);

	if (forwarded_eap_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	forwarded_eap_packet.reset_header(
		static_cast<u16_t>(eap_length),
		m_use_eap_expanded_type);
	forwarded_eap_packet.set_identifier(sent_eap_packet->get_identifier());
	forwarded_eap_packet.set_code(eap_code_response);
	forwarded_eap_packet.set_length(
		static_cast<u16_t>(eap_length),
		m_use_eap_expanded_type);
	forwarded_eap_packet.set_type(
		eap_type_mschapv2,
		m_use_eap_expanded_type);

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		forwarded_eap_packet.get_type_data_offset(
			0,
			forwarded_eap_packet.get_type_data_length()),
		forwarded_eap_packet.get_type_data_length());

	mschapv2_header.set_opcode(mschapv2_opcode_response);
	mschapv2_header.set_mschapv2_id(*mschapv2ident);
	mschapv2_header.set_ms_length(static_cast<u16_t>(type_data_length));

	mschapv2_response_c response(
		m_am_tools,
		mschapv2_header.get_data(),
		mschapv2_header.get_data_length());
	if (response.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = response.set_constants();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_diameter_variable_data_c * const peer_challenge_payload
		= m_ttls_received_payloads.get_payload(
			eap_diameter_vendor_code_of_microsoft_ms_chap_challenge.get_code());

	if (peer_challenge_payload == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_variable_data_c * const peer_challenge
		= peer_challenge_payload->get_payload_buffer();

	if (peer_challenge != 0
		&& peer_challenge->get_is_valid_data() == false
		&& peer_challenge->get_data_length() == EAP_MSCHAPV2_PEER_CHALLENGE_SIZE)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	const u8_t * const mschapv2_challenge = m_ttls_implicit_challenge.get_data_offset(
		EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_OFFSET,
		EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_LENGTH);
	if (mschapv2_challenge == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_am_tools->memcmp(
		peer_challenge->get_data(),
		mschapv2_challenge,
		EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_LENGTH) != 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_diameter_variable_data_c * const response_data_payload
		= m_ttls_received_payloads.get_payload(
			eap_diameter_vendor_code_of_microsoft_ms_chap2_response.get_code());

	if (response_data_payload == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_variable_data_c * const response_data
		= response_data_payload->get_payload_buffer();

	if (response_data != 0
		&& response_data->get_is_valid_data() == false
		&& response_data->get_data_length() != EAP_MSCHAPV2_RESPONSE_MESSAGE_SIZE)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	response.set_peer_challenge(
		response_data->get_data_offset(
			EAP_MSCHAPV2_PEER_CHALLENGE_OFFSET,
			EAP_MSCHAPV2_PEER_CHALLENGE_SIZE));

	response.set_nt_response(
		response_data->get_data_offset(
			EAP_MSCHAPV2_NT_RESPONSE_OFFSET,
			EAP_MSCHAPV2_NT_RESPONSE_SIZE));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Copy username to end of response packet
	response.set_name(user_name->get_data());

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_ttls_tunneled_message_state(eap_ttls_tunneled_message_state_process_response);

	status = packet_forward_to_tunnel(
		&m_receive_network_id,
		&forwarded_eap_packet,
		eap_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_tunneled_message_state_process_response(
	eap_header_wr_c * const sent_eap_packet)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: function: tls_application_eap_core_c::ttls_tunneled_message_state_process_response(): ")
		 EAPL("this = 0x%08x, m_ttls_tunneled_message_state=%d=%s, EAP-type=%d\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 get_ttls_tunneled_message_state(),
		 eap_tls_trace_string_c::get_ttls_state_string(get_ttls_tunneled_message_state()),
		 convert_eap_type_to_u32_t(sent_eap_packet->get_type())));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_tunneled_message_state_process_response()");

	eap_status_e status(eap_status_process_general_error);

	// This message should include MS-CHAP-V2 Success or MS-CHAP-V2 Error.

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		sent_eap_packet->get_type_data_offset(0, sent_eap_packet->get_type_data_length()),
		sent_eap_packet->get_type_data_length());

	status = mschapv2_header.check_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (mschapv2_header.get_opcode() == mschapv2_opcode_success)
	{
		eap_variable_data_c avp_success(m_am_tools);

		{
			eap_variable_data_c success_data(m_am_tools);

			success_data.reset();

			u8_t ident = mschapv2_header.get_mschapv2_id();

			status = success_data.add_data(
				&ident,
				EAP_MSCHAPV2_IDENT_SIZE);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (mschapv2_header.get_ms_length() < EAP_MSCHAPV2_HEADER_SIZE)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ttls_tunneled_message_state_process_response(): mschapv2 data"),
				mschapv2_header.get_data(),
				mschapv2_header.get_ms_length()- EAP_MSCHAPV2_HEADER_SIZE));

			status = success_data.add_data(
				mschapv2_header.get_data(),
				mschapv2_header.get_ms_length() - EAP_MSCHAPV2_HEADER_SIZE);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = create_ttls_diameter_avp(
				&avp_success,
				&success_data,
				eap_diameter_vendor_code_of_microsoft_ms_chap2_success.get_code(),
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		eap_buf_chain_wr_c forwarded_packet(
			eap_write_buffer,
			m_am_tools,
			avp_success.get_data(),
			avp_success.get_data_length(),
			false,
			false,
			0ul);
		if (forwarded_packet.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = get_application_partner()->packet_send(
			&forwarded_packet,
			0ul,
			forwarded_packet.get_data_length(),
			forwarded_packet.get_buffer_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(
			m_am_tools,
			m_receive_network_id.get_destination_id(),
			m_receive_network_id.get_source_id(),
			m_receive_network_id.get_type());

		eap_state_notification_c notification(
			m_am_tools,
			&send_network_id,
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_internal_type,
			eap_type_ttls,
			eap_state_none,
			tls_peap_state_server_waits_ttls_plain_ms_chap_v2_empty_ack,
			sent_eap_packet->get_identifier(),
			false);
		get_application_partner()->state_notification(&notification);

		m_ttls_plain_ms_chap_v2_eap_identifier = sent_eap_packet->get_identifier();
	}
	else if (mschapv2_header.get_opcode() == mschapv2_opcode_failure)
	{
		eap_variable_data_c avp_error(m_am_tools);

		{
			eap_variable_data_c error_data(m_am_tools);
			status = error_data.set_buffer(
				mschapv2_header.get_data(),
				mschapv2_header.get_ms_length() - EAP_MSCHAPV2_HEADER_SIZE,
				false,
				false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = create_ttls_diameter_avp(
				&avp_error,
				&error_data,
				eap_diameter_vendor_code_of_microsoft_ms_chap_error.get_code(),
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		eap_buf_chain_wr_c forwarded_packet(
			eap_write_buffer,
			m_am_tools,
			avp_error.get_data(),
			avp_error.get_data_length(),
			false,
			false,
			0ul);
		if (forwarded_packet.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = get_application_partner()->packet_send(
			&forwarded_packet,
			0ul,
			forwarded_packet.get_data_length(),
			forwarded_packet.get_buffer_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_ttls_plain_ms_chap_v2_eap_identifier = sent_eap_packet->get_identifier();
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_tunneled_message_state_process_change_password_response(
	eap_header_wr_c * const sent_eap_packet)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: function: tls_application_eap_core_c::ttls_tunneled_message_state_process_change_password_response(): ")
		 EAPL("this = 0x%08x, m_ttls_tunneled_message_state=%d=%s, EAP-type=%d\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 get_ttls_tunneled_message_state(),
		 eap_tls_trace_string_c::get_ttls_state_string(get_ttls_tunneled_message_state()),
		 convert_eap_type_to_u32_t(sent_eap_packet->get_type())));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_tunneled_message_state_process_change_password_response()");

	eap_status_e status(eap_status_process_general_error);

	// This message should include MS-CHAP-V2 Success.

	status = ttls_tunneled_message_state_process_response(sent_eap_packet);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_tunneled_message_state_process_identity_request(
	eap_header_wr_c * const sent_eap_packet)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: function: tls_application_eap_core_c::ttls_tunneled_message_state_process_identity_request(): ")
		 EAPL("this = 0x%08x, m_ttls_tunneled_message_state=%d=%s, EAP-type=%d\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 get_ttls_tunneled_message_state(),
		 eap_tls_trace_string_c::get_ttls_state_string(get_ttls_tunneled_message_state()),
		 convert_eap_type_to_u32_t(sent_eap_packet->get_type())));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_tunneled_message_state_process_identity_request()");

	eap_status_e status(eap_status_process_general_error);

	// This message includes username.

	u32_t user_name_length = sent_eap_packet->get_type_data_length();

	status = m_ttls_user_name.set_copy_of_buffer(
		sent_eap_packet->get_type_data(user_name_length),
		user_name_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = get_application_partner()->get_ttls_implicit_challenge(
		&m_ttls_implicit_challenge,
		EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_FULL_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		const u32_t type_data_length = EAP_MSCHAPV2_HEADER_SIZE // OpCode, MS-CHAPv2-ID and MS-Length
			+ mschapv2_challenge_c::get_header_minimum_size()
			+ m_ttls_user_name.get_data_length();

		const u32_t eap_length = eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
			+ type_data_length;

		eap_buf_chain_wr_c eap_packet_buffer(
			eap_write_buffer,
			m_am_tools,
			eap_length);
		if (eap_packet_buffer.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_header_wr_c forwarded_eap_packet(
			m_am_tools,
			eap_packet_buffer.get_data(eap_length),
			eap_length);
		if (forwarded_eap_packet.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}
		forwarded_eap_packet.set_code(eap_code_request);
		forwarded_eap_packet.set_identifier(static_cast<u8_t>(sent_eap_packet->get_identifier()+1ul));
		forwarded_eap_packet.set_length(
			static_cast<u16_t>(eap_length),
			m_use_eap_expanded_type);
		forwarded_eap_packet.set_type(
			eap_type_mschapv2,
			m_use_eap_expanded_type);

		mschapv2_header_c mschapv2_header(
			m_am_tools,
			forwarded_eap_packet.get_type_data_offset(0, forwarded_eap_packet.get_type_data_length()),
			forwarded_eap_packet.get_type_data_length());
		mschapv2_header.set_opcode(mschapv2_opcode_challenge);

		const u8_t * const mschapv2ident = m_ttls_implicit_challenge.get_data_offset(
			EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_IDENT_OFFSET,
			sizeof(u8_t));
		if (mschapv2ident == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ttls_tunneled_message_state_process_identity_request(): mschapv2ident"),
			 mschapv2ident,
			 sizeof(*mschapv2ident)));

		mschapv2_header.set_mschapv2_id(*mschapv2ident);
		mschapv2_header.set_ms_length(static_cast<u16_t>(type_data_length));

		mschapv2_challenge_c challenge_packet(
			m_am_tools,
			mschapv2_header.get_data(),
			mschapv2_header.get_data_length());
		if (challenge_packet.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		const u8_t * const mschapv2_challenge = m_ttls_implicit_challenge.get_data_offset(
			EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_OFFSET,
			EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_LENGTH);
		if (mschapv2_challenge == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ttls_tunneled_message_state_process_identity_request(): mschapv2_challenge"),
			 mschapv2_challenge,
			 EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_LENGTH));


		challenge_packet.set_challenge(mschapv2_challenge);
		challenge_packet.set_value_size();
		challenge_packet.set_name(m_ttls_user_name.get_data(m_ttls_user_name.get_data_length()));

		set_ttls_tunneled_message_state(eap_ttls_tunneled_message_state_process_challenge_request);

		status = packet_forward_to_tunnel(
			&m_receive_network_id,
			&forwarded_eap_packet,
			eap_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_tunneled_message_state_process_challenge_request(
	eap_header_wr_c * const sent_eap_packet)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: function: tls_application_eap_core_c::ttls_tunneled_message_state_process_challenge_request(): ")
		 EAPL("this = 0x%08x, m_ttls_tunneled_message_state=%d=%s, EAP-type=%d\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 get_ttls_tunneled_message_state(),
		 eap_tls_trace_string_c::get_ttls_state_string(get_ttls_tunneled_message_state()),
		 convert_eap_type_to_u32_t(sent_eap_packet->get_type())));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_tunneled_message_state_process_challenge_request()");

	eap_status_e status(eap_status_process_general_error);

	// This message shoud include MS-CHAP-V2 Response.

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		sent_eap_packet->get_type_data_offset(0, sent_eap_packet->get_type_data_length()),
		sent_eap_packet->get_type_data_length());

	mschapv2_response_c response(
		m_am_tools,
		mschapv2_header.get_data(),
		mschapv2_header.get_data_length());
	if (response.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	eap_variable_data_c tunneled_data(m_am_tools);
	eap_variable_data_c avp(m_am_tools);

	{
		status = create_ttls_diameter_avp(
			&avp,
			&m_ttls_user_name,
			eap_diameter_avp_code_user_name,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = tunneled_data.add_data(&avp);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		const u8_t * const mschapv2_challenge = m_ttls_implicit_challenge.get_data_offset(
			EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_OFFSET,
			EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_LENGTH);
		if (mschapv2_challenge == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ttls_tunneled_message_state_process_challenge_request(): mschapv2_challenge"),
			 mschapv2_challenge,
			 EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_LENGTH));

		eap_variable_data_c peer_challenge(m_am_tools);
		status = peer_challenge.set_buffer(
			mschapv2_challenge,
			EAP_MSCHAPV2_PEER_CHALLENGE_SIZE,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = create_ttls_diameter_avp(
			&avp,
			&peer_challenge,
			eap_diameter_vendor_code_of_microsoft_ms_chap_challenge.get_code(),
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = tunneled_data.add_data(&avp);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		eap_variable_data_c response_data(m_am_tools);

		response_data.reset();

		const u8_t * const mschapv2ident = m_ttls_implicit_challenge.get_data_offset(
			EAP_TTLS_MS_CHAPV2_IMPLICIT_CHALLENGE_IDENT_OFFSET,
			EAP_MSCHAPV2_IDENT_SIZE);
		if (mschapv2ident == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = response_data.add_data(
			mschapv2ident,
			EAP_MSCHAPV2_IDENT_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u8_t flags = 0ul;

		status = response_data.add_data(
			&flags,
			EAP_MSCHAPV2_FLAGS_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = response_data.add_data(
			response.get_peer_challenge(),
			EAP_MSCHAPV2_PEER_CHALLENGE_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u8_t reserved_data[EAP_MSCHAPV2_RESERVED_RESPONSE_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };

		status = response_data.add_data(
			reserved_data,
			EAP_MSCHAPV2_RESERVED_RESPONSE_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = response_data.add_data(
			response.get_nt_response(),
			EAP_MSCHAPV2_NT_RESPONSE_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = create_ttls_diameter_avp(
			&avp,
			&response_data,
			eap_diameter_vendor_code_of_microsoft_ms_chap2_response.get_code(),
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = tunneled_data.add_data(&avp);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	eap_buf_chain_wr_c forwarded_packet(
		eap_write_buffer,
		m_am_tools,
		tunneled_data.get_data(),
		tunneled_data.get_data_length(),
		false,
		false,
		0ul);
	if (forwarded_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = get_application_partner()->packet_send(
		&forwarded_packet,
		0ul,
		forwarded_packet.get_data_length(),
		forwarded_packet.get_buffer_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_tunneled_message_state_process_success_request(
	eap_header_wr_c * const sent_eap_packet)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: function: tls_application_eap_core_c::ttls_tunneled_message_state_process_success_request(): ")
		 EAPL("this = 0x%08x, m_ttls_tunneled_message_state=%d=%s, EAP-type=%d\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 get_ttls_tunneled_message_state(),
		 eap_tls_trace_string_c::get_ttls_state_string(get_ttls_tunneled_message_state()),
		 convert_eap_type_to_u32_t(sent_eap_packet->get_type())));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_tunneled_message_state_process_success_request()");

	// Here should be no data.

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		sent_eap_packet->get_type_data(sent_eap_packet->get_type_data_length()),
		sent_eap_packet->get_type_data_length());

	if (mschapv2_header.get_opcode() != mschapv2_opcode_success)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	eap_status_e status = m_ttls_sent_eap_packet.set_copy_of_buffer(
		sent_eap_packet->get_header_buffer(sent_eap_packet->get_header_buffer_length()),
		sent_eap_packet->get_header_buffer_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// This will be completed after EAP-MSChapv2 returns. This is to reduce stack usage.
	set_ttls_tunneled_message_state(eap_ttls_tunneled_message_state_complete_success_request);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_tunneled_message_state_complete_success_request(
	eap_header_wr_c * const sent_eap_packet)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: function: tls_application_eap_core_c::ttls_tunneled_message_state_complete_success_request(): ")
		 EAPL("this = 0x%08x, m_ttls_tunneled_message_state=%d=%s\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 get_ttls_tunneled_message_state(),
		 eap_tls_trace_string_c::get_ttls_state_string(get_ttls_tunneled_message_state())
		 ));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_tunneled_message_state_complete_success_request()");

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(
		m_am_tools,
		m_receive_network_id.get_destination_id(),
		m_receive_network_id.get_source_id(),
		m_receive_network_id.get_type());

	eap_state_notification_c notification(
		m_am_tools,
		&send_network_id,
		m_is_client,
		eap_state_notification_eap,
		eap_protocol_layer_internal_type,
		eap_type_ttls,
		eap_state_none,
		tls_peap_state_client_send_ttls_plain_ms_chap_v2_empty_ack,
		sent_eap_packet->get_identifier(),
		false);
	get_application_partner()->state_notification(&notification);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_tunneled_message_state_process_error_request(
	eap_header_wr_c * const sent_eap_packet)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: function: tls_application_eap_core_c::ttls_tunneled_message_state_process_error_request(): ")
		 EAPL("this = 0x%08x, m_ttls_tunneled_message_state=%d=%s, EAP-type=%d\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 get_ttls_tunneled_message_state(),
		 eap_tls_trace_string_c::get_ttls_state_string(get_ttls_tunneled_message_state()),
		 convert_eap_type_to_u32_t(sent_eap_packet->get_type())));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_tunneled_message_state_process_error_request()");

	eap_status_e status(eap_status_process_general_error);

	// This message shoud include MS-CHAP-V2 Change-Password.

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		sent_eap_packet->get_type_data(sent_eap_packet->get_type_data_length()),
		sent_eap_packet->get_type_data_length());

	if (mschapv2_header.get_opcode() != mschapv2_opcode_change_password)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	status = m_ttls_sent_eap_packet.set_copy_of_buffer(
		sent_eap_packet->get_header_buffer(sent_eap_packet->get_header_buffer_length()),
		sent_eap_packet->get_header_buffer_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// This will be completed after EAP-MSChapv2 returns. This is to reduce stack usage.
	set_ttls_tunneled_message_state(eap_ttls_tunneled_message_state_complete_error_request);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_tunneled_message_state_complete_error_request(
	eap_header_wr_c * const sent_eap_packet)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: function: tls_application_eap_core_c::ttls_tunneled_message_state_process_error_request(): ")
		 EAPL("this = 0x%08x, m_ttls_tunneled_message_state=%d=%s, EAP-type=%d\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 get_ttls_tunneled_message_state(),
		 eap_tls_trace_string_c::get_ttls_state_string(get_ttls_tunneled_message_state()),
		 convert_eap_type_to_u32_t(sent_eap_packet->get_type())));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_tunneled_message_state_complete_error_request()");

	eap_status_e status(eap_status_process_general_error);

	// This message shoud include MS-CHAP-V2 Change-Password.

	mschapv2_header_c mschapv2_header(
		m_am_tools,
		sent_eap_packet->get_type_data(sent_eap_packet->get_type_data_length()),
		sent_eap_packet->get_type_data_length());

	if (mschapv2_header.get_opcode() != mschapv2_opcode_change_password)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}

	mschapv2_change_password_c response(
		m_am_tools,
		mschapv2_header.get_data(),
		mschapv2_header.get_data_length());
	if (response.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// We need to create MS-CHAP-NT-Enc-PW, MS-CHAP2-CPW, and MS-CHAP-Challenge AVPs.

	eap_variable_data_c tunneled_data(m_am_tools);
	eap_variable_data_c avp(m_am_tools);

	{
		eap_variable_data_c nt_enc_pw(m_am_tools);
		status = nt_enc_pw.set_buffer(
			response.get_encrypted_pw_block(),
			EAP_MSCHAPV2_CHANGE_PASSWORD_ENCRYPTED_PASSWORD_SIZE,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = create_ttls_diameter_avp(
			&avp,
			&nt_enc_pw,
			eap_diameter_vendor_code_of_microsoft_ms_chap_nt_enc_pw.get_code(),
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = tunneled_data.add_data(&avp);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		eap_variable_data_c cpw(m_am_tools);

		status = cpw.set_copy_of_buffer(
			response.get_encrypted_hash(),
			EAP_MSCHAPV2_CHANGE_PASSWORD_ENCRYPTED_HASH_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = cpw.add_data(
			response.get_peer_challenge(),
			EAP_MSCHAPV2_PEER_CHALLENGE_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = cpw.add_data(
			response.get_nt_response(),
			EAP_MSCHAPV2_NT_RESPONSE_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = create_ttls_diameter_avp(
			&avp,
			&cpw,
			eap_diameter_vendor_code_of_microsoft_ms_chap2_cpw.get_code(),
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = tunneled_data.add_data(&avp);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		eap_variable_data_c challenge_data(m_am_tools);
		status = challenge_data.set_buffer(
			response.get_peer_challenge(),
			EAP_MSCHAPV2_PEER_CHALLENGE_SIZE,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = create_ttls_diameter_avp(
			&avp,
			&challenge_data,
			eap_diameter_vendor_code_of_microsoft_ms_chap_challenge.get_code(),
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = tunneled_data.add_data(&avp);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	eap_buf_chain_wr_c forwarded_packet(
		eap_write_buffer,
		m_am_tools,
		tunneled_data.get_data(),
		tunneled_data.get_data_length(),
		false,
		false,
		0ul);
	if (forwarded_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = get_application_partner()->packet_send(
		&forwarded_packet,
		0ul,
		forwarded_packet.get_data_length(),
		forwarded_packet.get_buffer_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::send_ttls_ms_chapv2_packet(
	eap_header_wr_c * const sent_eap_packet)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: function: tls_application_eap_core_c::send_ttls_ms_chapv2_packet(): ")
		 EAPL("this = 0x%08x, m_ttls_tunneled_message_state=%d=%s, EAP-type=%d\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 get_ttls_tunneled_message_state(),
		 eap_tls_trace_string_c::get_ttls_state_string(get_ttls_tunneled_message_state()),
		 convert_eap_type_to_u32_t(sent_eap_packet->get_type())));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::send_ttls_ms_chapv2_packet()");

	eap_status_e status(eap_status_process_general_error);


	if (m_is_client == false)
	{
		// Server
		if (sent_eap_packet->get_code() == eap_code_request
			&& sent_eap_packet->get_type() == eap_type_mschapv2)
		{
			if (get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_process_identity_response)
			{
				status = ttls_tunneled_message_state_process_identity_response(sent_eap_packet);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else if (get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_process_response)
			{
				status = ttls_tunneled_message_state_process_response(sent_eap_packet);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else if (get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_process_change_password_response)
			{
				status = ttls_tunneled_message_state_process_change_password_response(sent_eap_packet);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
			}
		}
		else if (sent_eap_packet->get_code() == eap_code_success)
		{
			// EAP-Success is not needed in TTLS/MsChapv2.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
		}
	}
	else
	{
		// Client
		if (sent_eap_packet->get_type() == eap_type_identity)
		{
			// Client sends EAP-Response/Identity.
			if (get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_process_identity_request
				|| get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_process_identity_request_pending)
			{
				status = m_ttls_sent_eap_packet.set_copy_of_buffer(
					sent_eap_packet->get_header_buffer(sent_eap_packet->get_header_buffer_length()),
					sent_eap_packet->get_header_buffer_length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				if (get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_process_identity_request_pending)
				{
					// NOTE, here we process client send packets separately to 
					// reduce stack consumption.

					{
						eap_header_wr_c tmp_sent_eap_packet(
							m_am_tools,
							m_ttls_sent_eap_packet.get_data(),
							m_ttls_sent_eap_packet.get_data_length());

						if (tmp_sent_eap_packet.get_type() == eap_type_identity)
						{
							// Client sent EAP-Response/Identity.
							// This message should include username.

							status = ttls_tunneled_message_state_process_identity_request(&tmp_sent_eap_packet);
							if (status != eap_status_ok)
							{
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}
						}
						else
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
						}
					}

					// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

					{
						eap_header_wr_c tmp_sent_eap_packet(
							m_am_tools,
							m_ttls_sent_eap_packet.get_data(),
							m_ttls_sent_eap_packet.get_data_length());

						if (tmp_sent_eap_packet.get_type() == eap_type_mschapv2
							&& get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_process_challenge_request)
						{
							// This message should include MS-CHAP-V2 Response.
							status = ttls_tunneled_message_state_process_challenge_request(&tmp_sent_eap_packet);
							if (status != eap_status_ok)
							{
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}
						}
						else
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
						}
					}

					// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
				}
			}
			else
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
			}
		}
		else if (sent_eap_packet->get_type() == eap_type_mschapv2)
		{
			if (get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_process_challenge_request)
			{
				status = m_ttls_sent_eap_packet.set_copy_of_buffer(
					sent_eap_packet->get_header_buffer(sent_eap_packet->get_header_buffer_length()),
					sent_eap_packet->get_header_buffer_length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else if (get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_process_success_request)
			{
				// NOTE, here we process client send packets separately to 
				// reduce stack consumption.
				status = ttls_tunneled_message_state_process_success_request(sent_eap_packet);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else if (get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_process_error_request)
			{
				mschapv2_header_c mschapv2_header(
					m_am_tools,
					sent_eap_packet->get_type_data(sent_eap_packet->get_type_data_length()),
					sent_eap_packet->get_type_data_length());

				if (mschapv2_header.get_opcode() == mschapv2_opcode_change_password)
				{
					// This message shoud include MS-CHAP-V2 Change-Password.
					status = ttls_tunneled_message_state_process_error_request(sent_eap_packet);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
				else if (mschapv2_header.get_opcode() == mschapv2_opcode_response)
				{
					// This message shoud include MS-CHAP-V2 Response.

					status = ttls_tunneled_message_state_process_challenge_request(sent_eap_packet);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
				else
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
				}
			}
			else
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
			}
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

eap_ttls_tunneled_message_state_e tls_application_eap_core_c::get_ttls_tunneled_message_state()
{
	return m_ttls_tunneled_message_state;
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

void tls_application_eap_core_c::set_ttls_tunneled_message_state(eap_ttls_tunneled_message_state_e ttls_state)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: function: tls_application_eap_core_c::set_ttls_tunneled_message_state(): ")
		 EAPL("old m_ttls_tunneled_message_state=%d=%s, new m_ttls_tunneled_message_state=%d=%s\n"),
		 (m_is_client == true ? "client": "server"),
		 m_ttls_tunneled_message_state,
		 eap_tls_trace_string_c::get_ttls_state_string(m_ttls_tunneled_message_state),
		 ttls_state,
		 eap_tls_trace_string_c::get_ttls_state_string(ttls_state)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::set_ttls_tunneled_message_state()");

	m_ttls_tunneled_message_state = ttls_state;
}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

//--------------------------------------------------

// End.
