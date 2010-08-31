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
	#define EAP_FILE_NUMBER_ENUM 104 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_radius.h"
#include "eap_radius_header.h"
#include "eap_radius_payloads.h"
#include "eap_radius_mac_attributes.h"
#include "abs_eap_am_radius.h"
#include "eap_crypto_api.h"
#include "eap_state_notification.h"
#include "abs_eap_am_mutex.h"
#include "eap_automatic_variable.h"
#include "eapol_header.h"
#include "eap_diameter_avp_code.h"


/// This is pseudo Ethernet and EAPOL header.
/// This is used in trace of tunneled EAP-packet.
const u8_t EAP_PSEUDO_ETHERNET_HEADER[] =
{
	0x50, 0x73, 0x65, 0x75, 0x64, 0x6f, 0x68, 0x65,
	0x61, 0x64, 0x65, 0x72, 0x88, 0x8e, 0x01, 0x00,
	0x00, 0x00
};

const u32_t EAP_PSEUDO_EAPOL_HEADER_OFFSET = 14ul;

//--------------------------------------------------

/** @file */

// 
EAP_FUNC_EXPORT eap_radius_c::~eap_radius_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_radius_c::~eap_radius_c(): this = 0x%08x => 0x%08x\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	EAP_ASSERT(m_shutdown_was_called == true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

// 
EAP_FUNC_EXPORT eap_radius_c::eap_radius_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_radius_c * const partner,
	eap_am_radius_c * const am_radius,
	const bool free_am_radius,
	const bool is_client_when_true)
	: m_am_tools(tools)
	, m_partner(partner)
	, m_session_map(tools, this)
	, m_pseudo_ethernet_header(tools)
	, m_radius_header_offset(0ul)
	, m_MTU(0ul)
	, m_trailer_length(0ul)
	, m_salt(0ul)
	, m_shutdown_was_called(false)
	, m_is_client(false)
	, m_is_valid(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_radius_c::eap_radius_c(): this = 0x%08x => 0x%08x, partner 0x%08x\n"),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		 partner));

	eap_status_e status = m_pseudo_ethernet_header.set_copy_of_buffer(
		EAP_PSEUDO_ETHERNET_HEADER,
		sizeof(EAP_PSEUDO_ETHERNET_HEADER));
	if (status != eap_status_ok)
	{
		// Do not care of this error.
		// User will check the validity of m_pseudo_ethernet_header.
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_radius_c::get_state_string(eap_radius_state_variable_e state)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_identity_request)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_pending_identity_query)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_start_request)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_imsi_waiting_for_start_request)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_pseydonym_waiting_for_start_request)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_analyse_start_request)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_challenge_request)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_analyses_challenge_request)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_pending_kc_sres_query)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_success)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_reauth_request)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_analyses_reauthentication_request)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_pending_pseudonym_decode_query)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_identity_response)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_start_response_with_at_permanent_identity)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_start_response_with_at_full_auth_identity)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_start_response_with_at_any_identity)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_start_response)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_challenge_response)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_pending_triplet_query)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_analyses_challenge_response)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_analyses_start_response)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_notification_request_success)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_notification_response_failure)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_notification_response_success)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_waiting_for_reauth_response)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_analyses_reauthentication_response)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_success)
	else EAP_IF_RETURN_STRING(state, eap_radius_state_failure)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown RADIUS state");
	}
}

//--------------------------------------------------

#if defined(USE_EAP_RADIUS_VERIFY_STATES)

/**
 * This function checks the valid states.
 */
bool eap_radius_c::verify_states(
	const eap_radius_state_variable_e * const valid_states,
	const u32_t count) const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	for (u32_t ind = 0ul; ind < count; ind++)
	{
		if (m_state == valid_states[ind])
		{
			return true;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return false;
}

#endif //#if defined(USE_EAP_RADIUS_VERIFY_STATES)

//--------------------------------------------------

static const u8_t DEFAULT_CALLED_STATION_ID[] = "000000";
static const u32_t DEFAULT_CALLED_STATION_ID_LENGTH = sizeof(DEFAULT_CALLED_STATION_ID);

static const u8_t DEFAULT_CALLING_STATION_ID[] = "111111";
static const u32_t DEFAULT_CALLING_STATION_ID_LENGTH = sizeof(DEFAULT_CALLING_STATION_ID);

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::analyse_radius_packet(
	const eap_am_network_id_c * const receive_network_id,
	eap_radius_header_base_c * const received_radius,
	const u32_t radius_packet_length,
	eap_radius_payloads_c * const p_radius_payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	if (m_is_client == true)
	{
		// Not supported yet. First priority is the server functionality.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}
	else
	{
		eap_variable_data_c called_station_id(m_am_tools);

		if (called_station_id.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (p_radius_payloads->get_payload(eap_diameter_avp_code_called_station_id) != 0)
		{
			status = called_station_id.add_data(p_radius_payloads->get_payload(eap_diameter_avp_code_called_station_id)->get_payload_buffer());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			status = called_station_id.add_data(DEFAULT_CALLED_STATION_ID, DEFAULT_CALLED_STATION_ID_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		eap_variable_data_c calling_station_id(m_am_tools);

		if (calling_station_id.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (p_radius_payloads->get_payload(eap_diameter_avp_code_calling_station_id) != 0)
		{
			status = calling_station_id.add_data(p_radius_payloads->get_payload(eap_diameter_avp_code_calling_station_id)->get_payload_buffer());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			status = called_station_id.add_data(DEFAULT_CALLING_STATION_ID, DEFAULT_CALLING_STATION_ID_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}


		// Test the required attributes.
		if (p_radius_payloads->get_payload(eap_diameter_avp_code_user_name) != 0
			&& p_radius_payloads->get_payload(eap_diameter_avp_code_nas_ip_address) != 0
			&& p_radius_payloads->get_payload(eap_diameter_avp_code_eap_message) != 0)
		{
			// Check the session.
			eap_variable_data_c selector(m_am_tools);

			if (selector.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = selector.add_data(
				p_radius_payloads->get_payload(
					eap_diameter_avp_code_user_name
					)->get_payload_buffer());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = selector.add_data(
				p_radius_payloads->get_payload(
					eap_diameter_avp_code_nas_ip_address
					)->get_payload_buffer());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = selector.add_data(&called_station_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = selector.add_data(
				p_radius_payloads->get_payload(
					eap_diameter_avp_code_calling_station_id
					)->get_payload_buffer());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("RADIUS session"),
				 selector.get_data(),
				 selector.get_data_length()));

			eap_radius_session_c * session = m_session_map.get_handler(&selector);

			if (session == 0)
			{
				// Create a new session.
				session = new eap_radius_session_c(
					m_am_tools,
					this,
					false,
					p_radius_payloads->get_payload(eap_diameter_avp_code_user_name),
					p_radius_payloads->get_payload(eap_diameter_avp_code_nas_ip_address));

				if (session == 0
					|| session->get_is_valid() == false)
				{
					delete session;
					session = 0;

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = session->configure();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = m_session_map.add_handler(&selector, session);
				if (status != eap_status_ok)
				{
					session->shutdown();
					delete session;
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			if (session != 0)
			{
				// Handle the received EAP-Response.

				status = session->save_request_data(
					received_radius->get_authenticator(),
					received_radius->get_authenticator_length(),
					received_radius->get_identifier());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				eap_variable_data_c * const eap_message
					= p_radius_payloads->get_payload(eap_diameter_avp_code_eap_message)
					->get_payload_buffer();

				eap_header_wr_c eap(
					m_am_tools,
					eap_message->get_data(),
					eap_message->get_data_length());
				
				trace_tunneled_packet(EAPL("-> TUNNELED packet server"), &eap);

				status = session->packet_process(
					receive_network_id,
					&eap,
					eap_message->get_data_length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::parse_radius_packet(
	eap_radius_header_base_c * const radius,
	const u32_t radius_packet_length,
	eap_radius_payloads_c * const p_radius_payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (radius->get_length() < radius->get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_RADIUS_ERROR,
			(EAPL("ERROR: eap_radius_payloads_c::parse_radius_packet(): ")
			 EAPL("RADIUS-header is corrupted. Buffer length and payload ")
			 EAPL("length does not match. RADIUS-header length %lu < minimum RADIUS-header length %lu.\n"),
			radius->get_length(),
			radius->get_header_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	if (radius->get_length() > radius_packet_length)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_RADIUS_ERROR, 
			(EAPL("ERROR: eap_radius_payloads_c::parse_radius_packet(): ")
			 EAPL("RADIUS-header is corrupted. Buffer length and payload ")
			 EAPL("length does not match. RADIUS-header length %lu > packet length %lu\n"),
			radius->get_length(),
			radius_packet_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	u32_t buffer_length = radius->get_length() - radius->get_header_length();

	if (buffer_length == 0u)
	{
		// No payload in this packet.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}


	eap_radius_attribute_header_c payload(
		m_am_tools,
		radius->get_data_offset(0ul, buffer_length),
		buffer_length);

	if (payload.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_RADIUS_ERROR, 
			(EAPL("ERROR: No eap_radius_attribute_header_c.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}


	eap_status_e status = p_radius_payloads->parse_radius_payload(
		&payload,
		&buffer_length);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (buffer_length != 0u)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_RADIUS_ERROR,
			(EAPL("ERROR: eap_radius_payloads_c::parse_radius_packet(): ")
			 EAPL("RADIUS-header is corrupted. Buffer length and payload ")
			 EAPL("length does not match. Illegal byte count %lu\n"),
			buffer_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::handle_radius_packet(
	const eap_am_network_id_c * const receive_network_id,
	eap_radius_header_base_c * const received_radius,
	const u32_t radius_length,
	eap_radius_payloads_c * const p_radius_payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_header_corrupted);

	status = parse_radius_packet(received_radius, radius_length, p_radius_payloads);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = analyse_radius_packet(
		receive_network_id,
		received_radius,
		radius_length,
		p_radius_payloads);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

#if defined(USE_EAP_TRACE)

// 
EAP_FUNC_EXPORT void eap_radius_c::packet_trace(
	eap_const_string prefix,
	const eap_am_network_id_c * const /* receive_network_id */,
	eap_radius_header_base_c * const eap_packet,
	const u32_t /* eap_packet_length */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(prefix);

	if (eap_packet->get_length() > eap_radius_header_base_c::get_header_length())
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("%s EAP_type_RADIUS: %s, (0x%08x), code=0x%02x=%s, ")
			 EAPL("identifier=0x%02x, length=0x%04x\n"),
			prefix,
			(m_is_client == true) ? "client": "server",
			this,
			eap_packet->get_code(),
			eap_packet->get_code_string(),
			eap_packet->get_identifier(),
			eap_packet->get_length()));

		EAP_TRACE_DEBUG(
			m_am_tools,
			eap_am_tools_c::eap_trace_mask_eap_messages,
			(EAPL("\n\t%s\n\tcode       = 0x%02x   = %s\n\tidentifier = ")
			 EAPL("0x%02x\n\tlength     = 0x%04x = %lu\n\n"),
			(m_is_client == true) ? "client": "server",
			eap_packet->get_code(),
			eap_packet->get_code_string(),
			eap_packet->get_identifier(),
			eap_packet->get_length(),
			eap_packet->get_length()));
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
			(EAPL("%s EAP_type_RADIUS: %s, (0x%08x), code=0x%02x=%s, ")
			 EAPL("identifier=0x%02x, length=0x%04x\n"),
			prefix,
			(m_is_client == true) ? "client": "server",
			this,
			eap_packet->get_code(),
			eap_packet->get_code_string(),
			eap_packet->get_identifier(),
			eap_packet->get_length()));

		EAP_TRACE_DEBUG(
			m_am_tools,
			eap_am_tools_c::eap_trace_mask_eap_messages,
			(EAPL("\n\t%s\n\tcode       = 0x%02x   = %s\n\tidentifier = ")
			 EAPL("0x%02x\n\tlength     = 0x%04x = %lu\n"),
			(m_is_client == true) ? "client": "server",
			eap_packet->get_code(),
			eap_packet->get_code_string(),
			eap_packet->get_identifier(),
			eap_packet->get_length(),
			eap_packet->get_length()));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

#endif //#if defined(USE_EAP_TRACE)

//--------------------------------------------------

#if defined(USE_EAP_TRACE)

EAP_FUNC_EXPORT void eap_radius_c::trace_tunneled_packet(
	eap_const_string prefix,
	const eap_header_base_c * const eap_packet)
{
	if (eap_packet == 0
		|| eap_packet->get_is_valid() == false)
	{
		// ERROR: Cannot trace invalid packet.
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: %s: %s: Cannot trace invalid packet.\n"),
			 prefix,
			 (m_is_client == true) ? "client": "server"));
		return;
	}

	if ((m_am_tools->get_trace_mask() & TRACE_FLAGS_DEFAULT)
		&& m_pseudo_ethernet_header.get_is_valid_data() == true
		&& m_pseudo_ethernet_header.get_data_length() >= sizeof(EAP_PSEUDO_ETHERNET_HEADER))
	{
		m_pseudo_ethernet_header.set_data_length(sizeof(EAP_PSEUDO_ETHERNET_HEADER));

		u32_t eap_packet_length = eap_packet->get_length();
		if (eap_packet->get_header_buffer_length() < eap_packet_length)
		{
			eap_packet_length = eap_packet->get_header_buffer_length();
		}

		eap_status_e status = m_pseudo_ethernet_header.add_data_to_offset(
			sizeof(EAP_PSEUDO_ETHERNET_HEADER),
			eap_packet->get_header_buffer(eap_packet_length),
			eap_packet_length);

		if (status == eap_status_ok)
		{
			m_pseudo_ethernet_header.set_data_length(
				sizeof(EAP_PSEUDO_ETHERNET_HEADER) + eap_packet_length);

			// Sets the EAPOL packet data length.
			eapol_header_wr_c eapol(
				m_am_tools,
				m_pseudo_ethernet_header.get_data_offset(
					EAP_PSEUDO_EAPOL_HEADER_OFFSET,
					m_pseudo_ethernet_header.get_data_length()-EAP_PSEUDO_EAPOL_HEADER_OFFSET),
				m_pseudo_ethernet_header.get_data_length()-EAP_PSEUDO_EAPOL_HEADER_OFFSET);

			if (eapol.get_is_valid() == true)
			{
				eapol.set_data_length(static_cast<u16_t>(eap_packet_length));

				EAP_TRACE_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("%s: %s: type=0x%08x, packet_length 0x%04x\n"),
					 prefix,
					 (m_is_client == true) ? "client": "server",
					 convert_eap_type_to_u32_t(eap_packet->get_type()),
					 eap_packet->get_length())); // NOTE, this will trace the values from the header of the EAP-packet.

				EAP_TRACE_DATA_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(prefix,
					m_pseudo_ethernet_header.get_data(m_pseudo_ethernet_header.get_data_length()),
					m_pseudo_ethernet_header.get_data_length()));
			}
		}
	}
}

#endif //#if defined(USE_EAP_TRACE)

//--------------------------------------------------

// 
EAP_FUNC_EXPORT bool eap_radius_c::get_is_client() 
{
	return m_is_client;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eap_radius_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT bool eap_radius_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_radius_c::packet_process(
	const eap_am_network_id_c * const receive_network_id,
	eap_radius_header_base_c * const received_eap,
	const u32_t eap_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_RADIUS_PACKET_TRACE(
		EAPL("->"),
		receive_network_id,
		received_eap,
		eap_packet_length);

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_RADIUS_ERROR, 
			(EAPL("ERROR: eap_radius_c::packet_process(): receive_network_id=0x%08x is invalid.\n"),
			receive_network_id));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (received_eap == 0
		|| received_eap->get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_RADIUS_ERROR, 
			(EAPL("ERROR: eap_radius_c::packet_process(): received_eap 0x%08x is invalid.\n"),
			received_eap));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (eap_packet_length < received_eap->get_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_RADIUS_ERROR, 
			(EAPL("ERROR: eap_radius_c::packet_process(): ")
			 EAPL("eap_packet_length=0x%04x < received_eap->get_length()=0x%04x.\n"),
			eap_packet_length, received_eap->get_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (received_eap->get_length() < eap_header_base_c::get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_RADIUS_ERROR, 
			(EAPL("ERROR: eap_radius_c::packet_process(): received_eap->get_length() ")
			 EAPL("< eap_header_base_c::get_header_length().\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}


	// NOTE: by disabling these calls throughput increases about 18%.
	// Disabling also decreases random seeds.
	m_am_tools->get_crypto()->add_rand_seed(
		received_eap->get_header_buffer(eap_packet_length),
		eap_packet_length);
	m_am_tools->get_crypto()->add_rand_seed_hw_ticks();


	eap_status_e status = eap_status_process_general_error;

	if ((m_is_client == true
		 && received_eap->get_code() == eap_radius_code_access_challenge)
		|| (m_is_client == false
			&& received_eap->get_code() == eap_radius_code_access_request))
	{
		eap_radius_header_base_c radius_header(
			m_am_tools,
			received_eap->get_header_buffer(received_eap->get_header_buffer_length()),
			received_eap->get_header_buffer_length());

		if (radius_header.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = radius_packet_process(
			receive_network_id,
			&radius_header,
			eap_packet_length,
			m_is_client);

		if (status == eap_status_ok)
		{
			EAP_GENERAL_HEADER_SET_ERROR_DETECTED(received_eap, false);
		}

		if (status != eap_status_ok
			&& status != eap_status_success
			&& status != eap_status_drop_packet_quietly
			&& status != eap_status_pending_request)
		{
			eap_status_string_c status_string;
			EAP_UNREFERENCED_PARAMETER(status_string);
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_RADIUS_ERROR, 
				(EAPL("ERROR: %s=%d eap_radius_c::radius_packet_process() failed\n"),
				 status_string.get_status_string(status), status));

			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else if (m_is_client == true
		&& (received_eap->get_code() == eap_radius_code_access_accept
		|| received_eap->get_code() == eap_radius_code_access_reject))
	{
		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(m_am_tools,
			receive_network_id->get_destination_id(),
			receive_network_id->get_source_id(),
			receive_network_id->get_type());

		if (received_eap->get_code() == eap_radius_code_access_accept)
		{
		}
		else if (received_eap->get_code() == eap_radius_code_access_reject)
		{
			// EAP is quite sloppy protocol.
			// Somebody just send a EAP-failure message and authentication is terminated.

			// Save received failure. We do not change our state yet.
			// The real correct EAP message could be received later if this failure was
			// send by nasty attacker.
			// We handle the EAP-Request/Failure message after a timeout.

			status = eap_status_ok;
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("dropped EAP code unknown: code=0x%02x, ")
				 EAPL("identifier=0x%02x, length=0x%04x, is client %d\n"),
				 received_eap->get_code(), received_eap->get_identifier(), 
				 received_eap->get_length(), (m_is_client == true)));
			status = eap_status_illegal_eap_code;
		}
	}
	else
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("dropped EAP code unknown: code=0x%02x, ")
			 EAPL("identifier=0x%02x, length=0x%04x, is client %d\n"),
			 received_eap->get_code(), received_eap->get_identifier(), 
			 received_eap->get_length(), (m_is_client == true)));
		status = eap_status_illegal_eap_code;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::radius_packet_process(
	const eap_am_network_id_c * const receive_network_id,
	eap_radius_header_base_c * const received_radius,
	const u32_t radius_packet_length,
	const bool is_client_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_RADIUS_ERROR, 
			(EAPL("ERROR: eap_radius_c::radius_packet_process(): ")
			 EAPL("receive_network_id=0x%08x is invalid.\n"),
			receive_network_id));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (received_radius == 0
		|| received_radius->get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_RADIUS_ERROR, 
			(EAPL("ERROR: eap_radius_c::radius_packet_process(): ")
			 EAPL("received_radius 0x%08x is invalid.\n"),
			received_radius));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (radius_packet_length < received_radius->get_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_RADIUS_ERROR, 
			(EAPL("ERROR: eap_radius_c::radius_packet_process(): ")
			 EAPL("radius_packet_length < received_radius->get_length().\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	eap_status_e status = eap_status_process_general_error;

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("received: RADIUS packet"),
		 received_radius->get_header_buffer(
			 received_radius->get_header_length()+received_radius->get_data_length()),
		 received_radius->get_header_length()+received_radius->get_data_length()));


	if (radius_packet_length < eap_radius_header_base_c::get_header_length())
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_RADIUS_ERROR,
			(EAPL("ERROR: eap_radius_c::radius_packet_process(): ")
			 EAPL("radius_packet_length < eap_radius_header_base_c::get_header_length().\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	status = received_radius->check_header();
	if (status != eap_status_ok)
	{
		eap_status_string_c status_string;
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_RADIUS_ERROR,
			(EAPL("ERROR: %s=%d eap_radius_c::radius_packet_process(): ")
			 EAPL("corrupted RADIUS-header.\n"),
			status_string.get_status_string(status), status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_radius_payloads_c * const l_radius_payloads = new eap_radius_payloads_c(m_am_tools);
	eap_automatic_variable_c<eap_radius_payloads_c> l_radius_payloads_automatic(
		m_am_tools,
		l_radius_payloads);

	if (l_radius_payloads == 0
		|| l_radius_payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = handle_radius_packet(
		receive_network_id,
		received_radius,
		radius_packet_length,
		l_radius_payloads);

	if (status != eap_status_ok
		&& status != eap_status_success
		&& status != eap_status_drop_packet_quietly
		&& status != eap_status_pending_request)
	{
		eap_status_string_c status_string;
		EAP_UNREFERENCED_PARAMETER(status_string);
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_RADIUS_ERROR, 
			(EAPL("ERROR: %s=%d eap_radius_c::radius_packet_process(): ")
			 EAPL("handle_radius_packet().\n"),
			status_string.get_status_string(status), status));
	}

	if (status == eap_status_ok)
	{
		// Do nothing special.
	}
	else if (status == eap_status_drop_packet_quietly)
	{
		// We will drop this message quietly.
	}
	else if (status != eap_status_ok)
	{
		// EAP-Failure will be sent from shutdown().
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t eap_radius_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	*MTU = 1020;
	*trailer_length = 0ul;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return 0ul;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->eap_radius_c::timer_expired(id 0x%02x, data 0x%08x).\n"),
		this, id, data));

	eap_status_e status = eap_status_process_general_error;

	if (id == EAP_TYPE_RADIUS_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: EAP_TYPE_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID elapsed.\n"),
			 (m_is_client == true) ? "client": "server"));
	}
	else if (id == EAP_TYPE_RADIUS_TIMER_DELAY_NOTIFICATION_MESSAGE_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: EAP_TYPE_TIMER_DELAY_NOTIFICATION_MESSAGE_ID elapsed.\n"),
			 (m_is_client == true) ? "client": "server"));
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_UNREFERENCED_PARAMETER(id);
	EAP_UNREFERENCED_PARAMETER(data);

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->eap_radius_c::timer_delete_data(id 0x%02x, data 0x%08x).\n"),
		this, id, data));

	if (id == EAP_TYPE_RADIUS_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: EAP_TYPE_TIMER_DELAY_FAILURE_MESSAGE_SENT_ID delete data.\n"),
			 (m_is_client == true) ? "client": "server"));
	}
	else if (id == EAP_TYPE_RADIUS_TIMER_DELAY_NOTIFICATION_MESSAGE_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: EAP_TYPE_TIMER_DELAY_NOTIFICATION_MESSAGE_ID delete data.\n"),
			 (m_is_client == true) ? "client": "server"));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::add_user_name_attribute(
	const eap_radius_variable_data_c * const user_name,
	eap_radius_header_base_c * const radius_header,
	u32_t * const radius_attribute_offset,
	crypto_hmac_c * const hmac_message_auth,
	crypto_md5_c * const md5_response_auth)
{
	const u32_t user_name_length
		= eap_radius_attribute_header_c::get_header_length()
		+ user_name->get_data_length();

	eap_radius_attribute_header_c user_name_attribute(
		m_am_tools,
		radius_header->get_data_offset(
			*radius_attribute_offset,
			user_name_length),
		user_name_length);
	if (user_name_attribute.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	user_name_attribute.reset_header(
		static_cast<u16_t>(user_name_length
			-eap_radius_attribute_header_c::get_header_length()));

	user_name_attribute.set_current_payload(eap_diameter_avp_code_user_name);

	u8_t * const data = user_name_attribute.get_data_offset(
		0ul,
		user_name->get_data_length());
	if (data == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_am_tools->memmove(
		data,
		user_name->get_data(user_name->get_data_length()),
		user_name->get_data_length());

	eap_status_e status = hmac_message_auth->hmac_update(
		user_name_attribute.get_header_buffer(
			user_name_attribute.get_header_buffer_length()),
		user_name_attribute.get_header_buffer_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = md5_response_auth->hash_update(
		user_name_attribute.get_header_buffer(
			user_name_attribute.get_header_buffer_length()),
		user_name_attribute.get_header_buffer_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("User-Name"),
		 user_name_attribute.get_header_buffer(
			 user_name_attribute.get_header_buffer_length()),
		 user_name_attribute.get_header_buffer_length()));

	*radius_attribute_offset += user_name_length;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_radius_c::xor_values(
	u8_t * const plaintext,
	const u32_t plaintext_length,
	const eap_variable_data_c * const intermediate_value)
{
	u8_t * const intermediate_value_data = intermediate_value->get_data(plaintext_length);

	if (intermediate_value_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	for (u32_t ind = 0ul; ind < plaintext_length; ind++)
	{
		plaintext[ind] = plaintext[ind] ^ intermediate_value_data[ind];
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::encrypt_ms_mppe_key_attribute(
	const eap_variable_data_c * const shared_secret,
	const eap_variable_data_c * const request_authenticator,
	const u8_t * salt,
	const u32_t salt_length,
	u8_t * const data,
	const u32_t data_length)
{
	crypto_md5_c md5(
		m_am_tools);

	eap_status_e status = md5.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = md5.hash_update(
		shared_secret->get_data(),
		shared_secret->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = md5.hash_update(
		request_authenticator->get_data(),
		request_authenticator->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = md5.hash_update(
		salt,
		salt_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	const u32_t block_size = md5.get_digest_length();
	const u32_t chunks_count = data_length/block_size;

	if ((data_length % block_size) != 0)
	{
		// ERROR
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	eap_variable_data_c intermediate_value(m_am_tools);

	status = intermediate_value.init(block_size);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = intermediate_value.set_data_length(block_size);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	for (u32_t ind = 0ul; ind < chunks_count; ind++)
	{
		status = md5.hash_final(
			intermediate_value.get_data(block_size),
			0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		xor_values(
			data+(ind*block_size),
			block_size,
			&intermediate_value);

		status = md5.hash_init();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = md5.hash_update(
			shared_secret->get_data(),
			shared_secret->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		status = md5.hash_update(
			data+(ind*block_size),
			block_size);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	} // for()

	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::add_one_ms_mppe_key_attribute(
	const eap_variable_data_c * const shared_secret,
	const eap_variable_data_c * const request_authenticator,
	eap_radius_header_base_c * const radius_header,
	u32_t * const radius_attribute_offset,
	const u8_t * const key,
	const u32_t key_length,
	const eap_diameter_avp_code_c mppe_key_type,
	crypto_hmac_c * const hmac_message_auth,
	crypto_md5_c * const md5_response_auth)
{
	const u32_t vendor_specific_length
		= eap_radius_attribute_header_c::get_header_length()
		+ EAP_RADIUS_VENDOR_ID_LENGTH;

	const u32_t mppe_key_length
		= eap_radius_attribute_header_c::get_header_length()
		+ EAP_RADIUS_MS_MPPE_KEY_DATA_LENGTH;

	const u32_t attribute_length
		= vendor_specific_length
		+ mppe_key_length;

	eap_radius_attribute_header_c vendor_specific(
		m_am_tools,
		radius_header->get_data_offset(
			*radius_attribute_offset,
			attribute_length),
		attribute_length);
	if (vendor_specific.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	vendor_specific.reset_header(
		static_cast<u16_t>(attribute_length
			-eap_radius_attribute_header_c::get_header_length()));

	vendor_specific.set_current_payload(eap_diameter_avp_code_vendor_specific);

	u8_t * const vendor_id = vendor_specific.get_data_offset(0ul, sizeof(u32_t));
	if (vendor_id == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t vendor_id_data_offset = 0ul;

	eap_write_u32_t_network_order(
		vendor_id,
		sizeof(u32_t),
		eap_diameter_vendor_id_of_microsoft);

	vendor_id_data_offset += sizeof(u32_t);

	*radius_attribute_offset += vendor_specific_length;


	eap_radius_attribute_header_c mppe_key(
		m_am_tools,
		vendor_specific.get_data_offset(
			vendor_id_data_offset,
			mppe_key_length),
		mppe_key_length);
	if (mppe_key.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	mppe_key.reset_header(
		static_cast<u16_t>(mppe_key_length
			-eap_radius_attribute_header_c::get_header_length()));
	mppe_key.set_current_payload(mppe_key_type);

	u8_t * const key_data = mppe_key.get_data_offset(0ul, EAP_RADIUS_MS_MPPE_KEY_DATA_LENGTH);
	if (key_data == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t key_offset = 0ul;

	u16_t salt_field = 0x8000 | m_salt++;

	eap_write_u16_t_network_order(
		key_data+key_offset,
		sizeof(u16_t),
		salt_field);
	key_offset += sizeof(u16_t);

	u8_t * const encrypted_data = key_data+key_offset;
	*(key_data+key_offset) = static_cast<u8_t>(key_length);
	key_offset += sizeof(u8_t);

	m_am_tools->memmove(key_data+key_offset, key, key_length);
	key_offset += key_length;

	u32_t encrypted_data_length = EAP_RADIUS_MS_MPPE_KEY_DATA_LENGTH-(sizeof(u16_t));

	m_am_tools->memset(key_data+key_offset, 0, EAP_RADIUS_MS_MPPE_KEY_DATA_LENGTH-key_length);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("Plain text MPPE key"),
		 vendor_specific.get_header_buffer(vendor_specific.get_header_buffer_length()),
		 vendor_specific.get_header_buffer_length()));

	eap_status_e status = encrypt_ms_mppe_key_attribute(
		shared_secret,
		request_authenticator,
		key_data, //salt
		sizeof(u16_t), // salt_length,
		encrypted_data,
		encrypted_data_length);

	*radius_attribute_offset += mppe_key_length;

	status = hmac_message_auth->hmac_update(
		vendor_specific.get_header_buffer(
			vendor_specific.get_header_buffer_length()),
		vendor_specific.get_header_buffer_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = md5_response_auth->hash_update(
		vendor_specific.get_header_buffer(
			vendor_specific.get_header_buffer_length()),
		vendor_specific.get_header_buffer_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
		(EAPL("Encrypted MPPE key"),
		 vendor_specific.get_header_buffer(vendor_specific.get_header_buffer_length()),
		 vendor_specific.get_header_buffer_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::add_ms_mppe_key_attributes(
	const eap_variable_data_c * const shared_secret,
	const eap_variable_data_c * const master_session_key,
	const eap_variable_data_c * const request_authenticator,
	eap_radius_header_base_c * const radius_header,
	u32_t * const radius_attribute_offset,
	crypto_hmac_c * const hmac_message_auth,
	crypto_md5_c * const md5_response_auth)
{
	eap_status_e status = add_one_ms_mppe_key_attribute(
		shared_secret,
		request_authenticator,
		radius_header,
		radius_attribute_offset,
		master_session_key->get_data(EAP_RADIUS_MS_MPPE_KEY_LENGTH),
		EAP_RADIUS_MS_MPPE_KEY_LENGTH,
		eap_diameter_vendor_code_of_microsoft_ms_mppe_recv_key.get_code(),
		hmac_message_auth,
		md5_response_auth);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_one_ms_mppe_key_attribute(
		shared_secret,
		request_authenticator,
		radius_header,
		radius_attribute_offset,
		master_session_key->get_data_offset(
			EAP_RADIUS_MS_MPPE_KEY_LENGTH,
			EAP_RADIUS_MS_MPPE_KEY_LENGTH),
		EAP_RADIUS_MS_MPPE_KEY_LENGTH,
		eap_diameter_vendor_code_of_microsoft_ms_mppe_send_key.get_code(),
		hmac_message_auth,
		md5_response_auth);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::packet_send(
	const eap_am_network_id_c * const network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length,
	eap_radius_session_c * const session)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_radius_c::packet_send().\n")));

	eap_header_rd_c eap(
		m_am_tools,
		sent_packet->get_data_offset(
			header_offset, data_length),
		data_length);
	if (eap.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	trace_tunneled_packet(EAPL("<- TUNNELED packet server"), &eap);

	crypto_md5_c md5_message_auth(
		m_am_tools);

	crypto_hmac_c hmac_message_auth(
		m_am_tools,
		&md5_message_auth,
		false);
	if (hmac_message_auth.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = hmac_message_auth.hmac_set_key(session->get_shared_secret());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	crypto_md5_c md5_response_auth(
		m_am_tools);

	status = md5_response_auth.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	u32_t fragment_count
		= (1ul
		   + eap.get_length()
		   / eap_radius_attribute_header_c::get_max_attribute_data_length());

	u32_t eap_payload_length
		= eap.get_length()
		+ eap_radius_attribute_header_c::get_header_length() * fragment_count;

	u32_t packet_data_length
		= eap_radius_header_base_c::get_header_length()
		+ eap_payload_length
		+ eap_radius_attribute_header_c::get_header_length()
		+ hmac_message_auth.get_digest_length();

	if (session->get_state() == eap_state_authentication_finished_successfully)
	{
		// Successfully finished authentication.
		// The keys must be added.
		packet_data_length
			+= 2ul * (2ul * eap_radius_attribute_header_c::get_header_length()
					  + EAP_RADIUS_VENDOR_ID_LENGTH
					  + EAP_RADIUS_MS_MPPE_KEY_DATA_LENGTH)
			+ eap_radius_attribute_header_c::get_header_length()
			+ session->get_user_name()->get_data_length();
	}

	eap_buf_chain_wr_c challenge(
		eap_write_buffer, 
		m_am_tools, 
		packet_data_length);

	if (challenge.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	eap_radius_header_base_c radius_header(
		m_am_tools,
		reinterpret_cast<eap_radius_header_base_c *>(
			challenge.get_data_offset(0ul, packet_data_length)),
		packet_data_length);
	if (radius_header.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	radius_header.reset_header(static_cast<u16_t>(packet_data_length));

	radius_header.set_identifier(session->get_identifier());

	if (session->get_state() == eap_state_authentication_finished_successfully
		/* && eap.get_code() == eap_code_success */)
	{
		// Successfully finished authentication.
		radius_header.set_code(eap_radius_code_access_accept);
	}
	else if (session->get_state() == eap_state_authentication_terminated_unsuccessfully
		&& eap.get_code() == eap_code_failure)
	{
		// Failed authentication.
		radius_header.set_code(eap_radius_code_access_reject);
	}
	else if (eap.get_code() == eap_code_request
			 || eap.get_code() == eap_code_response
			 || eap.get_code() == eap_code_success)
	{
		radius_header.set_code(eap_radius_code_access_challenge);
	}
	else
	{
		// Illegal combination.
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Illegal combination eap.code %d, session.state %d.\n"),
			 eap.get_code(),
			 session->get_state()));
		EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_code);
	}


	{
		// Type, Identifier and Length fields.
		const u32_t hmac_fields_length = 4ul;

		{
			status = hmac_message_auth.hmac_update(
				radius_header.get_header_buffer(hmac_fields_length),
				hmac_fields_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			status = hmac_message_auth.hmac_update(
				session->get_request_authenticator()->get_data(),
				session->get_request_authenticator()->get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

		}

		{
			status = md5_response_auth.hash_update(
				radius_header.get_header_buffer(hmac_fields_length),
				hmac_fields_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			status = md5_response_auth.hash_update(
				session->get_request_authenticator()->get_data(),
				session->get_request_authenticator()->get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	u32_t radius_attribute_offset(0ul);

	if (session->get_state() == eap_state_authentication_finished_successfully)
	{
		// Successfully finished authentication.
		// The MPPE keys and User-Name must be added.
		status = add_ms_mppe_key_attributes(
			session->get_shared_secret(),
			session->get_master_session_key(),
			session->get_request_authenticator(),
			&radius_header,
			&radius_attribute_offset,
			&hmac_message_auth,
			&md5_response_auth);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = add_user_name_attribute(
			session->get_user_name(),
			&radius_header,
			&radius_attribute_offset,
			&hmac_message_auth,
			&md5_response_auth);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	u32_t remaining_eap_data_length = eap.get_length();
	u8_t * eap_data = eap.get_header_buffer(remaining_eap_data_length);
	if (eap_data == 0)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t max_data_length
		= eap_radius_attribute_header_c::get_max_attribute_data_length()
		- eap_radius_attribute_header_c::get_header_length();

	for (u32_t ind = 0ul; ind < fragment_count; ind++)
	{
		u32_t fragment_length = remaining_eap_data_length;
		if (fragment_length > max_data_length)
		{
			fragment_length = max_data_length;
		}

		eap_radius_attribute_header_c fragment(
			m_am_tools,
			radius_header.get_data_offset(
				radius_attribute_offset
				+ ind * eap_radius_attribute_header_c::get_max_attribute_data_length(),
				fragment_length),
			eap_radius_attribute_header_c::get_header_length()+fragment_length);
		if (fragment.get_is_valid() == false)
		{
			EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		fragment.reset_header(static_cast<u16_t>(fragment_length));
		fragment.set_current_payload(eap_diameter_avp_code_eap_message);

		u8_t * const data = fragment.get_data_offset(0ul, fragment_length);
		if (data == 0)
		{
			EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_am_tools->memmove(data, eap_data, fragment_length);

		status = hmac_message_auth.hmac_update(
			fragment.get_header_buffer(fragment.get_length()),
			fragment.get_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = md5_response_auth.hash_update(
			fragment.get_header_buffer(fragment.get_length()),
			fragment.get_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		remaining_eap_data_length -= fragment_length;
		eap_data += fragment_length;

	} // for()


	radius_attribute_offset += eap_payload_length;

	u32_t authenticator_length
		= eap_radius_attribute_header_c::get_header_length()
		+ hmac_message_auth.get_digest_length();

	eap_radius_attribute_header_c authenticator(
		m_am_tools,
		radius_header.get_data_offset(
			radius_attribute_offset,
			authenticator_length),
		authenticator_length);
	if (authenticator.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	authenticator.reset_header(static_cast<u16_t>(hmac_message_auth.get_digest_length()));
	authenticator.set_current_payload(eap_diameter_avp_code_message_authenticator);

	{
		u8_t * const signature
			= authenticator.get_data_offset(
				0ul,
				authenticator.get_data_length());

		m_am_tools->memset(signature, 0, authenticator.get_data_length());

		status = hmac_message_auth.hmac_update(
			authenticator.get_header_buffer(authenticator.get_length()),
			authenticator.get_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = hmac_message_auth.hmac_final(
			signature,
			0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = md5_response_auth.hash_update(
			authenticator.get_header_buffer(authenticator.get_length()),
			authenticator.get_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		status = md5_response_auth.hash_update(
			session->get_shared_secret()->get_data(),
			session->get_shared_secret()->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
				
		status = md5_response_auth.hash_final(
			radius_header.get_authenticator(),
			0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	challenge.set_data_length(packet_data_length);

	EAP_RADIUS_PACKET_TRACE(
		EAPL("<-"),
		network_id,
		&radius_header,
		packet_data_length);

	status = m_partner->packet_send(
		network_id, 
		&challenge, 
		header_offset, 
		packet_data_length,
		challenge.get_buffer_length()
		);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_radius_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (cf_str_EAP_CORE_send_eap_success_after_notification.get_field()->compare(
			m_am_tools,
			field) == true)
	{
		// In Radius server EAP-Success must be send after state notification.
		u32_t send_eap_success_after_notification(true);
		
		const eap_status_e status = data->set_copy_of_buffer(
			&send_eap_success_after_notification,
			sizeof(send_eap_success_after_notification));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const eap_status_e status = m_partner->read_configure(field, data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_radius_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = m_partner->write_configure(field, data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is commented in eap_base_type_c::configure().
EAP_FUNC_EXPORT eap_status_e eap_radius_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_radius_c::configure(): this = 0x%08x => 0x%08x\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	m_radius_header_offset = m_partner->get_header_offset(
		&m_MTU, &m_trailer_length);

	if (m_radius_header_offset+m_MTU+m_trailer_length
		> EAP_TYPE_RADIUS_LOCAL_PACKET_BUFFER_LENGTH)
	{
		EAP_ASSERT_ALWAYS(EAP_TYPE_RADIUS_LOCAL_PACKET_BUFFER_LENGTH
						  >= (m_radius_header_offset+m_trailer_length));

		m_MTU = EAP_TYPE_RADIUS_LOCAL_PACKET_BUFFER_LENGTH
			- (m_radius_header_offset+m_trailer_length);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::shutdown_operation(
	eap_radius_session_c * const session,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = session->shutdown();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is commented in eap_base_type_c::shutdown().
EAP_FUNC_EXPORT eap_status_e eap_radius_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_radius_c::shutdown(): this = 0x%08x => 0x%08x\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	eap_status_e status = m_session_map.for_each(shutdown_operation, true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This function is to allow reuse of this object.
// The whole object state must be reset.
EAP_FUNC_EXPORT eap_status_e eap_radius_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("RADIUS: %s: function: eap_radius_c::reset(): this = 0x%08x\n"),
		(m_is_client == true ? "client": "server"),
		this));

	eap_status_e status = eap_status_not_supported;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::load_module(
	const eap_type_value_e type,
	const eap_type_value_e tunneling_type,
	abs_eap_base_type_c * const partner,
	eap_base_type_c ** const eap_type,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = m_partner->load_module(
		type,
		tunneling_type,
		partner,
		eap_type,
		is_client_when_true,
		receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::unload_module(const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->unload_module(type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::restart_authentication(
	const eap_am_network_id_c * const send_network_id,
	const bool is_client_when_true,
		const bool force_clean_restart,
		const bool from_timer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eap_radius_c::asynchronous_init_remove_eap_session(
	const eap_am_network_id_c * const send_network_id)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_session_core_c::asynchronous_init_remove_eap_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	eap_status_e status = eap_status_process_general_error;

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_radius_c::check_is_valid_eap_type(
	const eap_type_value_e eap_type)
{
	eap_status_e status = m_partner->check_is_valid_eap_type(eap_type);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_radius_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	eap_status_e status = m_partner->get_eap_type_list(eap_type_list);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_radius_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = m_partner->add_rogue_ap(rogue_ap_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::set_session_timeout(
	const u32_t /* session_timeout_ms */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::set_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id, 
	void * const p_data,
	const u32_t p_time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->set_timer(
		p_initializer, 
		p_id, 
		p_data,
		p_time_ms);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::cancel_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->cancel_timer(
		p_initializer, 
		p_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_c::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->cancel_all_timers();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------



// End.
