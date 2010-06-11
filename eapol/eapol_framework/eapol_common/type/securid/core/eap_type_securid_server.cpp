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
	#define EAP_FILE_NUMBER_ENUM 116 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "eap_am_memory.h"
#include "eap_state_notification.h"
#include "eap_type_securid.h"
#include "eap_type_securid_types.h"
#include "eap_buffer.h"

static const u8_t EAP_SECURID_PASSCODE_STRING[] = "passcode";


#ifdef EAP_SECURID_SERVER

eap_status_e eap_type_securid_c::server_packet_process(
	eap_header_wr_c * const received_eap,
	const u32_t eap_packet_length)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_header_corrupted;

	if (eap_packet_length < received_eap->get_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	if (received_eap->get_type() == eap_type_identity)
	{
		m_identifier = static_cast<u8_t> (received_eap->get_identifier() + 1);

		// Send request

		const u8_t * const message = EAP_SECURID_PASSCODE_STRING;
		u32_t message_length = m_am_tools->strlen(reinterpret_cast<eap_const_string>(message));

		u32_t packet_length = eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type)
			+ message_length; // Remove null termination

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
		eap_header.set_code(eap_code_request);
		eap_header.set_identifier(++m_identifier);
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

		m_am_tools->memmove(type_data, message, message_length);

		eap_status_e status = packet_send(packet, packet_length);
		delete packet;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (received_eap->get_type() == eap_type_securid)
	{
		// Verify passcode response.
		u8_t * type_data = const_cast<u8_t *>(received_eap->get_type_data(received_eap->get_type_data_length()));
		if (type_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (received_eap->get_type_data_length() != m_pincode.get_data_length()
			|| m_am_tools->memcmp(
				type_data,
				m_pincode.get_data(m_pincode.get_data_length()),
				m_pincode.get_data_length()) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
	}
	else if (received_eap->get_type() == eap_type_generic_token_card)
	{
		// Verify passcode response.
		u8_t * type_data = const_cast<u8_t *>(received_eap->get_type_data(received_eap->get_type_data_length()));
		if (type_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

#if defined(USE_FAST_EAP_TYPE)
		if (m_use_EAP_FAST_response == true)
		{
			const u32_t passcode_offset(EAP_FAST_EAP_GTC_RESPONSE_PREFIX_LENGTH + m_identity.get_data_length() + EAP_FAST_EAP_GTC_RESPONSE_SEPARATOR_LENGTH);

			if (received_eap->get_type_data_length() < passcode_offset+m_passcode.get_data_length())
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
			}

			type_data += passcode_offset;

			if (m_am_tools->memcmp(
					type_data,
					m_passcode.get_data(m_passcode.get_data_length()),
					m_passcode.get_data_length()) != 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
			}
		}
		else
#endif //#if defined(USE_FAST_EAP_TYPE)
		{
			if (received_eap->get_type_data_length() != m_passcode.get_data_length()
				|| m_am_tools->memcmp(
					type_data,
					m_passcode.get_data(m_passcode.get_data_length()),
					m_passcode.get_data_length()) != 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
			}
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	m_identifier++;

	status = finish_successful_authentication();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);

}

#endif //#ifdef EAP_SECURID_SERVER

//--------------------------------------------------


// End.
