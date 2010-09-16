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
* %version: 14.1.3 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 114 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "eap_am_memory.h"
#include "eap_state_notification.h"
#include "eap_type_securid.h"
#include "eap_type_securid_types.h"
#include "eap_buffer.h"

const u8_t EAP_SECURID_PIN_STRING[] = "pin";
const u8_t EAP_SECURID_PASSCODE_STRING[] = "passcode";


EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::query_eap_identity(
	const bool /*must_be_synchronous*/,
	eap_variable_data_c * const identity,
	const eap_am_network_id_c * const receive_network_id,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());

	m_identifier = eap_identifier;

	eap_status_e status;

	if (m_identity.get_is_valid_data() == false
        || m_identity.get_data_length() == 0)
	{
		EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("eap_type_securid_c::query_eap_identity(): Identity (username) is empty or invalid\n")));
	
		// Ask identity
		if (m_is_pending == false)
		{
			m_is_pending = true;
			status = m_am_type_securid->show_identity_query_dialog(m_eap_type, &m_identity);

			EAP_TRACE_DEBUG(m_am_tools, 
				TRACE_FLAGS_DEFAULT, (
				EAPL("eap_type_securid_c::query_eap_identity(): show_identity_query_dialog returns %d\n"),
				status));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_pending_request);
		}
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("eap_type_securid_c::query_eap_identity(): m_identity (identity or username) is valid.\n")));

		status = identity->set_copy_of_buffer(&m_identity);

		m_state.set_state(eap_type_securid_state_identity_query);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::complete_eap_identity_query(
	const eap_variable_data_c * const identity_utf8)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_GTC: function: complete_eap_identity_query, m_identity:"),
		 m_identity.get_data(),
		 m_identity.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_GTC: function: complete_eap_identity_query, identity_utf8:"),
		 identity_utf8->get_data(),
		 identity_utf8->get_data_length()));

	eap_status_e status = get_type_partner()->complete_eap_identity_query(
		&m_send_network_id,
		identity_utf8,
		m_identifier);

	if (status == eap_status_ok)
	{
		m_state.set_state(eap_type_securid_state_identity_query);
	}

	m_identity_asked = true;
	m_is_pending = false;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_type_securid_c::client_packet_process(
	eap_header_wr_c * const received_eap,
	const u32_t eap_packet_length)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_drop_packet_quietly;

	m_identifier = received_eap->get_identifier();

	if (received_eap->get_type() == eap_type_identity)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	if (received_eap->get_code() == eap_code_failure)
	{
		if (m_state.is_valid_state(eap_type_securid_state_failure) == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}

		status = finish_unsuccessful_authentication(false);

		m_state.set_state(eap_type_securid_state_failure);
	}
	else if (received_eap->get_code() == eap_code_success)
	{
		if (m_state.is_valid_state(eap_type_securid_state_success) == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}

		status = finish_successful_authentication();

		m_state.set_state(eap_type_securid_state_success);
	}
	else if (received_eap->get_type() != m_eap_type)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else if (received_eap->get_code() == eap_code_request) // Request
	{
		// Securid
		if (m_eap_type == eap_type_securid)
		{
			status = client_securid_packet_process(
				received_eap,
				eap_packet_length);			    
		}
		// GTC
		else if (m_eap_type == eap_type_generic_token_card)
		{ 
			status = client_gtc_packet_process(
				received_eap,
				eap_packet_length);			    
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_type_securid_c::client_securid_packet_process(
	eap_header_wr_c * const eap,
	const u32_t eap_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_drop_packet_quietly;

	if (eap_packet_length < eap->get_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	u32_t type_data_length = eap->get_data_length();

	if (type_data_length == 0)
	{
		// Passcode query
		if (m_is_pending == false)
		{
			m_is_pending = true;
			m_am_type_securid->show_passcode_query_dialog(&m_passcode, true);
			if (status != eap_status_pending_request)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else
	{
		u8_t * data = eap->get_type_data(type_data_length);
		if (data == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		
		if (type_data_length < 4)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}
		else if (type_data_length >= 4)
		{
			if (m_am_tools->memcmp(data, EAP_SECURID_PIN_STRING, 3) == 0
				&& data[3] == 0x00)
			{
				// Pincode query
				if (m_is_pending == false)
				{
					m_is_pending = true;
					m_am_type_securid->show_pincode_query_dialog(&m_passcode, &m_pincode, true);
					if (status != eap_status_pending_request)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
			else if (type_data_length == 9
				&& m_am_tools->memcmp(data, EAP_SECURID_PASSCODE_STRING, 8) == 0
				&& data[8] == 0x00)
			{
				// Additional passcode query
				if (m_is_pending == false)
				{
					m_is_pending = true;
					m_am_type_securid->show_passcode_query_dialog(&m_passcode, false);
					if (status != eap_status_pending_request)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
			else
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
			}
		}
	}

			
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_type_securid_c::client_gtc_packet_process(
	eap_header_wr_c * const eap,
	const u32_t eap_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_drop_packet_quietly;

	if (eap_packet_length < eap->get_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	u32_t type_data_length = eap->get_type_data_length();
	if (type_data_length > 1020)
	{
		type_data_length = 1020; // Magic
	}

	// Passcode query
	if (m_is_pending == false)
	{
		m_is_pending = true;

#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)
		if (m_skip_user_interactions == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: EAP-GTC: eap_type_securid_c::client_gtc_packet_process(): skips user interactions\n")));

			status = client_gtc_complete_user_input_query(&m_identity, &m_passcode);
		}
		else
#endif //#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)
		{
			eap_variable_data_c message(m_am_tools);
			status = message.set_copy_of_buffer(eap->get_type_data(type_data_length), type_data_length);
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_am_type_securid->show_gtc_query_dialog(
				&m_passcode,
				message.get_data(),
				message.get_data_length(),
				true);
		}
	}
			
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::client_securid_complete_passcode_query(
	const eap_variable_data_c * const passcode_utf8)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Send passcode
	u32_t packet_length = eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
		+ passcode_utf8->get_data_length() + 2 + 1;

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
		m_eap_type,
		m_use_eap_expanded_type);

	u8_t * type_data = const_cast<u8_t *> (eap_header.get_type_data_offset(0, eap_header.get_type_data_length()));
	if (type_data == 0)
	{
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		m_am_tools->memset(type_data, 0x00, 2);
		type_data += 2;
		m_am_tools->memmove(
			type_data,
			passcode_utf8->get_data(passcode_utf8->get_data_length()),
			passcode_utf8->get_data_length());
		type_data += passcode_utf8->get_data_length();
		type_data[0] = 0x00;
	}

	eap_status_e status = packet_send(packet, packet_length);
	delete packet;

	m_is_pending = false;

	m_state.set_state(eap_type_securid_state_passcode_query);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::client_securid_complete_pincode_query(
	const eap_variable_data_c * const pincode,
	const eap_variable_data_c * const passcode)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_first_pincode_query = false;

	// Send pincode
	u32_t packet_length = eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
		+ passcode->get_data_length() + 2 + 1 + pincode->get_data_length() + 1;
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
		m_eap_type,
		m_use_eap_expanded_type);

	u8_t * type_data = const_cast<u8_t *> (eap_header.get_type_data_offset(0, eap_header.get_type_data_length()));
	if (type_data == 0)
	{
		delete packet;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_am_tools->memset(type_data, 0x00, 2);
	type_data += 2;
	// identity
	m_am_tools->memmove(
		type_data,
		passcode->get_data(passcode->get_data_length()),
		passcode->get_data_length());
	type_data += passcode->get_data_length();
	type_data[0] = 0x00;
	type_data++;
	m_am_tools->memmove(
		type_data,
		pincode->get_data(pincode->get_data_length()),
		pincode->get_data_length());
	type_data += pincode->get_data_length();
	type_data[0] = 0x00;

	eap_status_e status = packet_send(packet, packet_length);
	delete packet;

	m_is_pending = false;

	m_state.set_state(eap_type_securid_state_pincode_query);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_securid_c::client_gtc_complete_user_input_query(
	const eap_variable_data_c * const identity_utf8,
	const eap_variable_data_c * const response_utf8)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	if (identity_utf8->get_is_valid_data() == true)
	{
		status = m_identity.set_copy_of_buffer(identity_utf8);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// Send response
	u32_t packet_length = eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
		+ response_utf8->get_data_length();

#if defined(USE_FAST_EAP_TYPE)
	if (m_use_EAP_FAST_response == true)
	{
		packet_length += EAP_FAST_EAP_GTC_RESPONSE_PREFIX_LENGTH + m_identity.get_data_length() + EAP_FAST_EAP_GTC_RESPONSE_SEPARATOR_LENGTH;
	}
#endif //#if defined(USE_FAST_EAP_TYPE)

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
		m_eap_type,
		m_use_eap_expanded_type);

	if (response_utf8->get_data_length() > 0UL)
	{
		u8_t * type_data = const_cast<u8_t *> (eap_header.get_type_data_offset(0, eap_header.get_type_data_length()));
		if (type_data == 0)
		{
			delete packet;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

#if defined(USE_FAST_EAP_TYPE)
		if (m_use_EAP_FAST_response == true)
		{
			eap_variable_data_c eap_fast_response(m_am_tools);
			if (eap_fast_response.get_is_valid() == false)
			{
				delete packet;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = eap_fast_response.set_copy_of_buffer(EAP_FAST_EAP_GTC_RESPONSE_PREFIX, EAP_FAST_EAP_GTC_RESPONSE_PREFIX_LENGTH);
			if (status != eap_status_ok)
			{
				delete packet;
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_GTC: function: eap_type_securid_c::client_gtc_complete_user_input_query(): m_identity:"),
				 m_identity.get_data(),
				 m_identity.get_data_length()));

			status = eap_fast_response.add_data(&m_identity);
			if (status != eap_status_ok)
			{
				delete packet;
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = eap_fast_response.add_data(EAP_FAST_EAP_GTC_RESPONSE_SEPARATOR, EAP_FAST_EAP_GTC_RESPONSE_SEPARATOR_LENGTH);
			if (status != eap_status_ok)
			{
				delete packet;
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_GTC: function: eap_type_securid_c::client_gtc_complete_user_input_query(): response_utf8:"),
				 response_utf8->get_data(),
				 response_utf8->get_data_length()));

			status = eap_fast_response.add_data(response_utf8);
			if (status != eap_status_ok)
			{
				delete packet;
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			m_am_tools->memmove(
				type_data,
				eap_fast_response.get_data(),
				eap_fast_response.get_data_length());
		}
		else
#endif //#if defined(USE_FAST_EAP_TYPE)
		{
			m_am_tools->memmove(
				type_data,
				response_utf8->get_data(response_utf8->get_data_length()),
				response_utf8->get_data_length());
		}
	}

	status = packet_send(packet, packet_length);
	delete packet;

	m_is_pending = false;

	m_state.set_state(eap_type_securid_state_gtc_user_input_query);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------


// End.
