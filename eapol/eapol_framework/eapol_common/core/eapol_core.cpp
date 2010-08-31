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
* %version: 100 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 747 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eapol_core.h"
#include "eap_crypto_api.h"
#include "eapol_key_header.h"
#include "eapol_rc4_key_header.h"
#include "eap_state_notification.h"
#include "eap_automatic_variable.h"
#include "eap_network_id_selector.h"
#include "eap_config.h"
#include "eap_buffer.h"
#include "eapol_session_key.h"
#include "eap_master_session_key.h"

#define MPPE_KEY_LENGTH 32

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_core_c::~eapol_core_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_core_c::~eapol_core_c(): this = 0x%08x\n"),
		this));

	EAP_ASSERT(m_shutdown_was_called == true);

	delete m_eap_core;
	m_eap_core = 0;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

// 
EAP_FUNC_EXPORT eapol_core_c::eapol_core_c(
	abs_eap_am_tools_c * const tools,
	abs_eapol_core_c * const partner,
	const bool is_client_when_true)
	: m_partner(partner)
	, m_eap_core(0)
	  , m_eapol_key_state_map(tools, this)
	  , m_am_tools(tools)
	  , m_master_session_key(m_am_tools)
	  , m_authentication_type(eapol_key_authentication_type_none)
	  , m_eapol_header_offset(0u)
	  , m_MTU(0u)
	  , m_trailer_length(0u)
	  , m_max_eapol_starts(0u)
	  , m_eapol_start_interval(0u)
	  , m_eapol_starts_sent(0u)
	  , m_is_client(is_client_when_true)
	  , m_is_valid(false)
	  , m_shutdown_was_called(false)
	  , m_block_state_notifications(false)
	  , m_skip_start_4_way_handshake(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_core_c::eapol_core_c(): %s, this = 0x%08x => 0x%08x, compiled %s %s.\n"),
		(m_is_client == true) ? "client": "server",
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this),
		__DATE__,
		__TIME__));

#if defined(EAP_USE_WPXM)
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_core_c::eapol_core_c(): WPX enabled.")));
#else
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_core_c::eapol_core_c(): WPX disabled.")));
#endif //#if defined(EAP_USE_WPXM)

	if (m_partner != 0)
	{
		set_is_valid();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::configure()
{
	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eapol_core_c::configure()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::configure()");

	eap_status_e status(eap_status_process_general_error);

	m_eapol_header_offset = m_partner->get_header_offset(
		&m_MTU, &m_trailer_length);

#if defined(NO_EAP_CORE_CLIENT_MESSAGE_IF)
	m_eap_core = eap_session_core_base_c::new_eap_session_core_c(
		m_am_tools,
		this,
		m_is_client,
		m_MTU-eapol_header_wr_c::get_header_length());
#else
	m_eap_core = new_eap_core_client_message_if_c(
		m_am_tools,
		this,
		m_is_client,
		m_MTU-eapol_header_wr_c::get_header_length());
#endif

	if (m_eap_core == 0
		|| m_eap_core->get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		eap_variable_data_c max_eapol_starts(m_am_tools);

		status = read_configure(
			cf_str_EAPOL_CORE_starts_max_count.get_field(),
			&max_eapol_starts);
		if (status != eap_status_ok 
			|| max_eapol_starts.get_is_valid_data() == false
			|| max_eapol_starts.get_data_length() < sizeof(u32_t))
		{
			// Probably not found from db. Use the default value.
			m_max_eapol_starts = EAPOL_CORE_MAX_EAPOL_START_SENDINGS;						
		} 
		else 
		{
			m_max_eapol_starts = *reinterpret_cast<u32_t *>(
				max_eapol_starts.get_data(sizeof(u32_t)));
		}
	}

	{
		eap_variable_data_c eapol_start_interval(m_am_tools);

		status = read_configure(
			cf_str_EAPOL_CORE_send_start_interval.get_field(),
			&eapol_start_interval);
		if (status != eap_status_ok 
			|| eapol_start_interval.get_is_valid_data() == false
			|| eapol_start_interval.get_data_length() < sizeof(u32_t))
		{
			// Probably not found from db. Use the default value.
			m_eapol_start_interval = EAPOL_CORE_TIMER_SEND_START_AGAIN_TIMEOUT;						
		} 
		else 
		{
			m_eapol_start_interval = *reinterpret_cast<u32_t *>(
				eapol_start_interval.get_data(sizeof(u32_t)));
		}
	}

#if defined(USE_EAP_CORE_SERVER)
	if (m_is_client == false)
	{
		eap_variable_data_c data(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAPOL_CORE_skip_start_4_way_handshake.get_field(),
			&data);
		if (status == eap_status_ok
			&& data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			u32_t *flag = reinterpret_cast<u32_t *>(data.get_data(data.get_data_length()));

			if (flag != 0)
			{
				if ((*flag) != 0ul)
				{
					m_skip_start_4_way_handshake = true;
				}
				else
				{
					m_skip_start_4_way_handshake = false;
				}
			}
		}
	}
#endif //#if defined(USE_EAP_CORE_SERVER)

	return EAP_STATUS_RETURN(m_am_tools, m_eap_core->configure());
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::packet_process(
	const eap_am_network_id_c * const receive_network_id,
	eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (packet_data == 0
		|| packet_length < eap_header_base_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	eapol_header_wr_c eapol(
		m_am_tools,
		packet_data->get_header_buffer(packet_data->get_header_buffer_length()),
		packet_data->get_header_buffer_length());

	if (eapol.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (packet_length < eapol.get_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (m_eap_core == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (packet_length < eapol_header_rd_c::get_header_length() // First we need atleast header to check the data length.
		|| packet_length < eapol_header_rd_c::get_header_length()+eapol.get_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("-> EAPOL: %s, version=0x%02x, packet_type=0x%02x=%s, data_length=0x%04x, packet_length 0x%04x\n"),
		(m_is_client == true) ? "client": "server",
		eapol.get_version(),
		eapol.get_packet_type(),
		eapol.get_type_string(),
		eapol.get_data_length(),
		packet_length));

	status = eapol.check_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (receive_network_id->get_type() == eapol_ethernet_type_preauthentication
		&& eapol.get_packet_type() != eapol_packet_type_eap
		&& eapol.get_packet_type() != eapol_packet_type_start)
	{
		// Only EAP-Packet and EAPOL-Start are valid for preauthentication.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eapol_type);
	}


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eapol_key_state_c *eapol_key_state = 0;

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

		eap_network_id_selector_c state_selector(
			m_am_tools,
			&send_network_id);

		if (state_selector.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_process(): EAPOL-Key session"),
			state_selector.get_data(state_selector.get_data_length()),
			state_selector.get_data_length()));


		// Check do we have handler for this packet. This applies to EAP-packets too.
		eapol_key_state = m_eapol_key_state_map.get_handler(&state_selector);

		if (eapol_key_state == 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: eapol_core_c::packet_process() failed, no eapol_key_state_c object for this packet. Drop packet.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


	if (eapol.get_packet_type() == eapol_packet_type_eap
		&& eapol.get_data_length() >= eap_header_base_c::get_header_length())
	{
		if (m_authentication_type != eapol_key_authentication_type_RSNA_EAP
			&& m_authentication_type != eapol_key_authentication_type_WPA_EAP
			&& m_authentication_type != eapol_key_authentication_type_dynamic_WEP
#if defined(EAP_USE_WPXM)
			&& m_authentication_type != eapol_key_authentication_type_WPXM
#endif //#if defined(EAP_USE_WPXM)
			&& m_authentication_type != eapol_key_authentication_type_WPS
			&& m_authentication_type != eapol_key_authentication_type_EAP_authentication_no_encryption
			)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: eapol_core_c::packet_process(): Illegal authentication type 0x%08x\n"),
				 m_authentication_type));
			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eapol_type);
		}

		// Test first we are connected.
		if (eapol_key_state->get_is_associated() == true)
		{
			eap_header_wr_c eap(
				m_am_tools,
				eapol.get_eap_header(),
				eapol.get_data_length());

			status = m_eap_core->packet_process(
				receive_network_id,
				&eap,
				eapol.get_data_length());

			EAP_GENERAL_HEADER_COPY_ERROR_PARAMETERS(packet_data, &eap);
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}
	}
	else if (m_is_client == false
		&& eapol.get_packet_type() == eapol_packet_type_logoff)
	{
		status = eap_status_ok;
	}
	else if (m_is_client == false
		&& eapol.get_packet_type() == eapol_packet_type_start)
	{
		if (m_authentication_type != eapol_key_authentication_type_RSNA_EAP
			&& m_authentication_type != eapol_key_authentication_type_WPA_EAP
			&& m_authentication_type != eapol_key_authentication_type_dynamic_WEP
			&& m_authentication_type != eapol_key_authentication_type_WPS
#if defined(EAP_USE_WPXM)
			&& m_authentication_type != eapol_key_authentication_type_WPXM
#endif //#if defined(EAP_USE_WPXM)
			&& m_authentication_type != eapol_key_authentication_type_EAP_authentication_no_encryption
			)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: eapol_core_c::packet_process(): Illegal authentication type 0x%08x\n"),
				 m_authentication_type));
			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eapol_type);
		}

		// This call does not cause clean restart. On-going authentication is not terminated.
		status = restart_authentication(
			receive_network_id,
			m_is_client,
			false);
	}
	else if (eapol.get_packet_type() == eapol_packet_type_key)
	{
		if (m_authentication_type != eapol_key_authentication_type_RSNA_EAP
			&& m_authentication_type != eapol_key_authentication_type_RSNA_PSK
			&& m_authentication_type != eapol_key_authentication_type_WPA_EAP
			&& m_authentication_type != eapol_key_authentication_type_WPA_PSK
			&& m_authentication_type != eapol_key_authentication_type_dynamic_WEP
#if defined(EAP_USE_WPXM)
			&& m_authentication_type != eapol_key_authentication_type_WPXM
#endif //#if defined(EAP_USE_WPXM)
			&& m_authentication_type != eapol_key_authentication_type_EAP_authentication_no_encryption
			)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: eapol_core_c::packet_process(): Illegal authentication type 0x%08x\n"),
				 m_authentication_type));
			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eapol_type);
		}

		// Indicates EAP-Core of received EAPOL-Key message.
		// This is indication of finished EAP-authentication.
		// NOTE, we do not care of the status.
		// Some EAP-types does not implement this function.
		(void) eap_acknowledge(receive_network_id);

		if (eapol_key_state != 0)
		{
			status = eapol_key_state->process_eapol_key_frame(
				receive_network_id,
				packet_data,
				packet_length);
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: process_eapol_key_frame() failed, no eapol_key_state_c object\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
		}
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: %s, packet_type=0x%02x=%s not handled, data length 0x%04x.\n"),
			(m_is_client == true) ? "client": "server",
			eapol.get_packet_type(),
			eapol.get_type_string(),
			eapol.get_data_length()));
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("     source"), receive_network_id->get_source(), receive_network_id->get_source_length()));
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("destination"), receive_network_id->get_destination(), receive_network_id->get_destination_length()));

		status = eap_status_wrong_eapol_type;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::packet_send(
	const eap_am_network_id_c * const send_network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);
	EAP_ASSERT(header_offset < sent_packet->get_data_length());
	EAP_ASSERT(data_length <= sent_packet->get_data_length());
	EAP_ASSERT(sent_packet->get_data_length() <= buffer_length);

	if (header_offset < m_eapol_header_offset+eapol_header_wr_c::get_header_length())
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet_send: packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eapol_header_wr_c eapol(
		m_am_tools,
		sent_packet->get_data_offset(
			header_offset-eapol_header_wr_c::get_header_length(), data_length),
		data_length);

	if (eapol.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet_send: packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eapol.set_version(eapol_protocol_version_1);
	eapol.set_packet_type(eapol_packet_type_eap);
	eapol.set_data_length(static_cast<u16_t>(data_length));

	{
		eap_network_id_selector_c state_selector(
			m_am_tools,
			send_network_id);
		if (state_selector.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send(): EAPOL-Key session"),
			state_selector.get_data(state_selector.get_data_length()),
			state_selector.get_data_length()));

		eapol_key_state_c *session = m_eapol_key_state_map.get_handler(&state_selector);

		bool encryption_on(false);

		if (session != 0
			&& session->get_is_valid() == true)
		{
			encryption_on = session->get_is_encryption_on();
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Read EAPOL-Key session: encryption is %s\n"),
			((encryption_on == true) ? "on" : "off")));
		
		sent_packet->set_encrypt(encryption_on);
	}

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("<- EAPOL: %s, version=0x%02x, packet_type=0x%02x=%s, data_length=0x%04x, packet_length 0x%04x\n"),
		(m_is_client == true) ? "client": "server",
		eapol.get_version(),
		eapol.get_packet_type(),
		eapol.get_type_string(),
		eapol.get_data_length(),
		data_length));

	if (m_shutdown_was_called == true
		&& m_is_client == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: EAP_Core: %s, eapol_core_c::packet_send(): %s packet dropped quietly because shutdown was already called.\n"),
			 (m_is_client == true) ? "client": "server",
			 eapol.get_type_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	eap_status_e status = m_partner->packet_send(
		send_network_id,
		sent_packet,
		header_offset-eapol_header_wr_c::get_header_length(),
		data_length+eapol_header_wr_c::get_header_length(),
		buffer_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t eapol_core_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const u32_t offset = m_partner->get_header_offset(MTU, trailer_length);
	(*MTU) -= eapol_header_wr_c::get_header_length();
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return offset+eapol_header_wr_c::get_header_length();
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::eap_acknowledge(
	const eap_am_network_id_c * const receive_network_id)
{
	// Any Network Protocol packet is accepted as a success indication.
	// This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (m_eap_core == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = m_eap_core->eap_acknowledge(receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::load_module(
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
EAP_FUNC_EXPORT eap_status_e eapol_core_c::unload_module(const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->unload_module(type);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::restart_authentication(
	const eap_am_network_id_c * const receive_network_id,
	const bool is_client_when_true,
	const bool force_clean_restart,
	const bool from_timer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_core_c::restart_authentication(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::restart_authentication()");

	eap_status_e status = eap_status_process_general_error;

	if (receive_network_id->get_type() != eapol_ethernet_type_pae
		&& receive_network_id->get_type() != eapol_ethernet_type_preauthentication)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eapol_core_c::restart_authentication(): Illegal Ethernet type %d\n"),
			receive_network_id->get_type()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ethernet_type_not_supported);
	}

	if (is_client_when_true == true)
	{
		// Client sends a EAPOL-Start message.
		(void) m_partner->cancel_timer(
			this,
			EAPOL_CORE_TIMER_SEND_START_AGAIN_ID);

		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(m_am_tools,
			receive_network_id->get_destination_id(),
			receive_network_id->get_source_id(),
			receive_network_id->get_type());
		if (send_network_id.get_is_valid_data() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_buf_chain_wr_c start_packet(
			eap_write_buffer, 
			m_am_tools, 
			EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

		if (start_packet.get_is_valid() == false)
		{
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t buffer_size = EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH;
		EAP_ASSERT_ALWAYS(m_MTU > m_trailer_length);
		if (m_MTU-m_trailer_length < buffer_size)
		{
			buffer_size = m_MTU-m_trailer_length;
		}

		EAP_ASSERT_ALWAYS(buffer_size >= m_eapol_header_offset);
		eapol_header_wr_c eapol(
			m_am_tools,
			start_packet.get_data_offset(
				m_eapol_header_offset,
				(buffer_size-m_eapol_header_offset)),
			(buffer_size-m_eapol_header_offset));

		if (eapol.get_is_valid() == false)
		{
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet_send: packet buffer corrupted.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		eapol.set_version(eapol_protocol_version_1);
		eapol.set_packet_type(eapol_packet_type_start);
		eapol.set_data_length(0);

		start_packet.set_data_length(
			m_eapol_header_offset
			+eapol_header_wr_c::get_header_length()
			+eapol.get_data_length());

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("<- EAPOL: %s, version=0x%02x, packet_type=0x%02x=%s, data_length=0x%04x, packet length 0x%04x\n"),
			(m_is_client == true) ? "client": "server",
			eapol.get_version(),
			eapol.get_packet_type(),
			eapol.get_type_string(),
			eapol.get_data_length(),
			eapol_header_wr_c::get_header_length()+eapol.get_data_length()));

		status = m_partner->packet_send(
			&send_network_id,
			&start_packet,
			m_eapol_header_offset,
			eapol_header_wr_c::get_header_length()+eapol.get_data_length(),
			buffer_size);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (m_authentication_type == eapol_key_authentication_type_EAP_authentication_no_encryption)
		{
			// Some APs need broadcast EAPOL-Start-message.

			const u8_t BROADCAST_ADDRESS[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

			eap_variable_data_c broadcast_destination(
				m_am_tools,
				BROADCAST_ADDRESS,
				sizeof(BROADCAST_ADDRESS),
				false,
				false);
		
			if (broadcast_destination.get_is_valid_data() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// Here we swap the addresses.
			eap_am_network_id_c broadcast_send_network_id(m_am_tools,
				receive_network_id->get_destination_id(),
				&broadcast_destination,
				receive_network_id->get_type());
			if (send_network_id.get_is_valid_data() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = m_partner->packet_send(
				&broadcast_send_network_id,
				&start_packet,
				m_eapol_header_offset,
				eapol_header_wr_c::get_header_length()+eapol.get_data_length(),
				buffer_size);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (from_timer == false)
		{
			// Reset EAPOL-Start counter because this is not a resending.
			m_eapol_starts_sent = 1;
			// Send notification
			eap_state_notification_c notification(
				m_am_tools,
				&send_network_id,
				true, // m_is_client
				eap_state_notification_generic,
				eap_protocol_layer_eapol,
				eap_type_none,
				eapol_state_none,
				eapol_state_start_sent,
				0 /* EAP identifier not valid here */,
				false);
			state_notification(&notification);
		}

		// This copy is important because timer needs data that is allocated from heap.
		eap_am_network_id_c * const copy_receive_network_id = receive_network_id->copy();
		eap_automatic_variable_c<eap_am_network_id_c> automatic_copy_receive_network_id(
			m_am_tools,
			copy_receive_network_id);

		if (copy_receive_network_id == 0
			|| copy_receive_network_id->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Timer will hold copy_send_network_id data.
		automatic_copy_receive_network_id.do_not_free_variable();

		status = m_partner->set_timer(
			this,
			EAPOL_CORE_TIMER_SEND_START_AGAIN_ID, 
			copy_receive_network_id,
			m_eapol_start_interval);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TIMER: %s: EAPOL_CORE_TIMER_SEND_START_AGAIN_ID set %d ms.\n"),
			 (m_is_client == true ? "client": "server"),
			 m_eapol_start_interval));
		
	}
#if defined(USE_EAP_CORE_SERVER)
	else 
	{
		// Server.

		if (m_eap_core == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (force_clean_restart == true)
		{
			// It is bad idea to terminate on-going authentication
			// when EAPOL-Start is received.
			// Because of that remove_eap_session() is called
			// only when force_clean_restart is true.
			bool previous_block = m_block_state_notifications;
			m_block_state_notifications = true;
			(void) m_eap_core->remove_eap_session(false, receive_network_id);
			m_block_state_notifications = previous_block;
		}

		if (m_authentication_type == eapol_key_authentication_type_RSNA_EAP
			|| m_authentication_type == eapol_key_authentication_type_WPA_EAP
			|| m_authentication_type == eapol_key_authentication_type_dynamic_WEP
#if defined(EAP_USE_WPXM)
			|| m_authentication_type == eapol_key_authentication_type_WPXM
#endif //#if defined(EAP_USE_WPXM)
			|| m_authentication_type == eapol_key_authentication_type_WPS
			|| m_authentication_type == eapol_key_authentication_type_EAP_authentication_no_encryption
			)
		{
			status = m_eap_core->send_eap_identity_request(receive_network_id);
		}
		else
		{
			status = eap_status_ok;
		}
	}

#else

	EAP_UNREFERENCED_PARAMETER(force_clean_restart); // Only server version uses this.

#endif //#if defined(USE_EAP_CORE_SERVER)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::check_pmksa_cache(
	eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids,
	const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_core_c::check_pmksa_cache(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::check_pmksa_cache()");

	eap_status_e status = eap_status_ok;

	for (u32_t ind = 0ul; ind < bssid_sta_receive_network_ids->get_object_count();)
	{
		eap_am_network_id_c * const receive_network_id = bssid_sta_receive_network_ids->get_object(ind);
		if (receive_network_id == 0)
		{
			bssid_sta_receive_network_ids->reset();
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(
			m_am_tools,
			receive_network_id->get_destination_id(),
			receive_network_id->get_source_id(),
			receive_network_id->get_type());
		if (send_network_id.get_is_valid_data() == false)
		{
			bssid_sta_receive_network_ids->reset();
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_network_id_selector_c state_selector(
			m_am_tools,
			&send_network_id);
		if (state_selector.get_is_valid() == false)
		{
			bssid_sta_receive_network_ids->reset();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("check_pmksa_cache(): checks PMKSA EAPOL-Key session"),
			 state_selector.get_data(state_selector.get_data_length()),
			 state_selector.get_data_length()));
		
		eapol_key_state_c *session = m_eapol_key_state_map.get_handler(&state_selector);
		
		if (session == 0
			|| selected_eapol_key_authentication_type == eapol_key_authentication_type_RSNA_PSK
			|| selected_eapol_key_authentication_type == eapol_key_authentication_type_WPA_PSK
			|| session->check_pmksa_cache(
				selected_eapol_key_authentication_type,
				pairwise_key_cipher_suite,
				group_key_cipher_suite) != eap_status_ok)
		{
			// No cached PMKID for this address and security suite.
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("No cached PMKID for this address"),
				 state_selector.get_data(state_selector.get_data_length()),
				 state_selector.get_data_length()));

			status = bssid_sta_receive_network_ids->remove_object(ind);
			if (status != eap_status_ok)
			{
				bssid_sta_receive_network_ids->reset();
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Note here we do not increase index because we removed the current object.
		}
		else
		{
			// Check the next index.
			++ind;
		}
	} // for()

#if 1

	status = m_partner->complete_check_pmksa_cache(bssid_sta_receive_network_ids);
	return EAP_STATUS_RETURN(m_am_tools, status);

#else

	if (bssid_sta_receive_network_ids->get_object_count() > 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_found);
	}

#endif

}

//--------------------------------------------------

/**
 * This function removes PMKSA from cache.
 * @param receive_network_id carries the MAC addresses.
 * MAC address of Authenticator should be in source address.
 * MAC address of Supplicant should be in destination address.
 */
EAP_FUNC_EXPORT eap_status_e eapol_core_c::remove_pmksa_from_cache(
	const eap_am_network_id_c * const receive_network_id
	)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::remove_pmksa_from_cache().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::remove_pmksa_from_cache()");

	if (receive_network_id == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

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

	status = remove_eapol_key_state(
		&send_network_id,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eapol_core_c::remove_pmksa_from_cache(): ")
			 EAPL("remove_eapol_key_state(), eap_status_e %d\n"),
			status));
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::start_preauthentication(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::start_preauthentication().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::start_preauthentication()");

	if (receive_network_id->get_type() != eapol_ethernet_type_preauthentication)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eapol_core_c::start_preauthentication(): Illegal Ethernet type 0x%04x\n"),
			receive_network_id->get_type()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ethernet_type_not_supported);
	}


	if (m_authentication_type != authentication_type)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eapol_core_c::start_preauthentication(): Illegal authentication type 0x%08x, ")
			 EAPL("it should be 0x%08x\n"),
			 authentication_type,
			 m_authentication_type));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_authentication_type);
	}


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

	eap_network_id_selector_c state_selector(
		m_am_tools,
		&send_network_id);

	if (state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("start_preauthentication(): EAPOL-Key session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));


	eapol_key_state_c *eapol_key_state = m_eapol_key_state_map.get_handler(&state_selector);

	if (eapol_key_state != 0)
	{
		// Reuse the session.
		eapol_key_state->unset_marked_removed();

		status = eapol_key_state->reset();
		if (status != eap_status_ok)
		{
			// We cannot reuse the session.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_ERROR, 
				(EAPL("start_preauthentication(): eapol_key_state NOT reused.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	if (eapol_key_state == 0)
	{
		eapol_key_state = new eapol_key_state_c(
			m_am_tools,
			this,
			m_partner,
			m_is_client,
			receive_network_id,
			authentication_type);
		if (eapol_key_state == 0
			|| eapol_key_state->get_is_valid() == false)
		{
			if (eapol_key_state != 0)
			{
				eapol_key_state->shutdown();
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("WARNING: eapol_core_c::start_preauthentication(): Cannot run eapol_key_state->shutdown() 0x%08x\n"),
					eapol_key_state));
			}
			delete eapol_key_state;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = eapol_key_state->initialize_preauthentication(
			receive_network_id,
			authentication_type);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_eapol_key_state_map.add_handler(&state_selector, eapol_key_state);
		if (status != eap_status_ok)
		{
			eapol_key_state->shutdown();
			delete eapol_key_state;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = eapol_key_state->initialize_preauthentication(
			receive_network_id,
			authentication_type);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	status = eapol_key_state->configure();
	if (status != eap_status_ok)
	{
		status = remove_eapol_key_state(
			&send_network_id,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: eapol_core_c::start_preauthentication(): remove_eapol_key_state(), eap_status_e %d\n"),
				status));
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	// This call does cause clean restart. On-going authentication is terminated.
	status = restart_authentication(
		receive_network_id,
		m_is_client,
		true,
		false);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eapol_core_c::copy_eapol_key_state(
	const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
	const eap_am_network_id_c * const new_receive_network_id ///< source includes remote address, destination includes local address.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eapol_core_c::copy_eapol_key_state()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::copy_eapol_key_state()");

	eap_status_e status(eap_status_process_general_error);

	if (old_receive_network_id == 0
		|| old_receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (new_receive_network_id == 0
		|| new_receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// Here we swap the addresses.
	eap_am_network_id_c old_send_network_id(
		m_am_tools,
		old_receive_network_id->get_destination_id(),
		old_receive_network_id->get_source_id(),
		old_receive_network_id->get_type());
	if (old_send_network_id.get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_network_id_selector_c old_state_selector(
		m_am_tools,
		&old_send_network_id);

	if (old_state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("copy_eapol_key_state(): old EAPOL-Key session"),
		old_state_selector.get_data(),
		old_state_selector.get_data_length()));

	eapol_key_state_c *old_eapol_key_state = m_eapol_key_state_map.get_handler(&old_state_selector);

	if (old_eapol_key_state != 0)
	{
		{
			// Here we remove the old state from map. Note the old state is not deleted.
			// Later we add the modified old map to new location in the map.
			status = m_eapol_key_state_map.remove_handler(&old_state_selector, false);
			if (status != eap_status_ok)
			{
				old_eapol_key_state->shutdown();
				delete old_eapol_key_state;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Set up the old state and add it to m_eapol_key_state_map.

			// Here we swap the addresses.
			eap_am_network_id_c new_send_network_id(
				m_am_tools,
				new_receive_network_id->get_destination_id(),
				new_receive_network_id->get_source_id(),
				new_receive_network_id->get_type());
			if (new_send_network_id.get_is_valid_data() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

#if defined(EAP_USE_WPXM)
			status = old_eapol_key_state->set_WPXM_parameters(new_receive_network_id);
			if (status != eap_status_ok)
			{
				old_eapol_key_state->shutdown();
				delete old_eapol_key_state;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
#endif //#if defined(EAP_USE_WPXM)

			eap_network_id_selector_c new_state_selector(
				m_am_tools,
				&new_send_network_id);

			if (new_state_selector.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("copy_eapol_key_state(): new EAPOL-Key session"),
				new_state_selector.get_data(),
				new_state_selector.get_data_length()));

			status = m_eapol_key_state_map.add_handler(&new_state_selector, old_eapol_key_state);
			if (status != eap_status_ok)
			{
				old_eapol_key_state->shutdown();
				delete old_eapol_key_state;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eapol_core_c::generate_new_pmksa(
	eapol_key_state_c * * const new_eapol_key_state,
	const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
	const eap_am_network_id_c * const new_receive_network_id ///< source includes remote address, destination includes local address.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eapol_core_c::generate_new_pmksa()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::generate_new_pmksa()");

	eap_status_e status(eap_status_process_general_error);

	if (new_eapol_key_state == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (old_receive_network_id == 0
		|| old_receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (new_receive_network_id == 0
		|| new_receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// Here we swap the addresses.
	eap_am_network_id_c old_send_network_id(
		m_am_tools,
		old_receive_network_id->get_destination_id(),
		old_receive_network_id->get_source_id(),
		old_receive_network_id->get_type());
	if (old_send_network_id.get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_network_id_selector_c old_state_selector(
		m_am_tools,
		&old_send_network_id);

	if (old_state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("generate_new_pmksa(): old EAPOL-Key session"),
		old_state_selector.get_data(),
		old_state_selector.get_data_length()));

	eapol_key_state_c *old_eapol_key_state = m_eapol_key_state_map.get_handler(&old_state_selector);

	if (old_eapol_key_state != 0)
	{
		*new_eapol_key_state = old_eapol_key_state->copy(new_receive_network_id);

		if (*new_eapol_key_state == 0
			|| (*new_eapol_key_state)->get_is_valid() == false)
		{
			if (*new_eapol_key_state != 0)
			{
				(*new_eapol_key_state)->shutdown();
				delete *new_eapol_key_state;
				*new_eapol_key_state = 0;
			}
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (*new_eapol_key_state != 0)
		{
			// Here we swap the addresses.
			eap_am_network_id_c new_send_network_id(
				m_am_tools,
				new_receive_network_id->get_destination_id(),
				new_receive_network_id->get_source_id(),
				new_receive_network_id->get_type());
			if (new_send_network_id.get_is_valid_data() == false)
			{
				(*new_eapol_key_state)->shutdown();
				delete *new_eapol_key_state;
				*new_eapol_key_state = 0;
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_network_id_selector_c new_state_selector(
				m_am_tools,
				&new_send_network_id);

			if (new_state_selector.get_is_valid() == false)
			{
				(*new_eapol_key_state)->shutdown();
				delete *new_eapol_key_state;
				*new_eapol_key_state = 0;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("generate_new_pmksa(): new EAPOL-Key session"),
				new_state_selector.get_data(),
				new_state_selector.get_data_length()));

			status = m_eapol_key_state_map.add_handler(&new_state_selector, *new_eapol_key_state);
			if (status != eap_status_ok)
			{
				(*new_eapol_key_state)->shutdown();
				delete *new_eapol_key_state;
				*new_eapol_key_state = 0;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else
	{
		status = eap_status_not_found;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::read_reassociation_parameters(
	const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
	const eap_am_network_id_c * const new_receive_network_id, ///< source includes remote address, destination includes local address.
	const eapol_key_authentication_type_e authentication_type,
	eap_variable_data_c * const PMKID,
	const eap_variable_data_c * const received_WPA_ie,
	const eap_variable_data_c * const sent_WPA_ie)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eapol_core_c::read_reassociation_parameters()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::read_reassociation_parameters()");

	eap_status_e status(eap_status_process_general_error);

	// No need to check authentication type anymore. It can be changed in reassociation.

#if defined(EAP_USE_WPXM)
	if (authentication_type == eapol_key_authentication_type_WPXM)
	{
		status = copy_eapol_key_state(old_receive_network_id, new_receive_network_id);
		if (status != eap_status_ok)
		{
			// We cannot copy the session.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_ERROR, 
				(EAPL("eapol_core_c::read_reassociation_parameters(): cannot copy eapol_key_state.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#else
	EAP_UNREFERENCED_PARAMETER(old_receive_network_id);
#endif //#if defined(EAP_USE_WPXM)

	// Here we swap the addresses.
	eap_am_network_id_c new_send_network_id(
		m_am_tools,
		new_receive_network_id->get_destination_id(),
		new_receive_network_id->get_source_id(),
		new_receive_network_id->get_type());
	if (new_send_network_id.get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_network_id_selector_c state_selector(
		m_am_tools,
		&new_send_network_id);

	if (state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("read_reassociation_parameters(): EAPOL-Key session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));

	eapol_key_state_c *eapol_key_state = m_eapol_key_state_map.get_handler(&state_selector);

	if (eapol_key_state == 0
		&& authentication_type == eapol_key_authentication_type_RSNA_EAP)
	{
		// Creates a new PMKSA based on old PMKSA and the new MAC address of new access point.
		status = generate_new_pmksa(&eapol_key_state, old_receive_network_id, new_receive_network_id);
		if (status != eap_status_ok)
		{
			// We cannot generate a new PMKSA.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eapol_core_c::read_reassociation_parameters(): new eapol_key_state NOT generated.\n")));
			status = eap_status_not_found;
		}
	}

	if (eapol_key_state != 0)
	{
		status = eapol_key_state->reset_cached_pmksa();
		if (status != eap_status_ok)
		{
			// We cannot reuse the session.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_ERROR, 
				(EAPL("eapol_core_c::read_reassociation_parameters(): eapol_key_state NOT reused.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// We have state for this connection.
		status = eapol_key_state->read_reassociation_parameters(
			new_receive_network_id, ///< source includes remote address, destination includes local address.
			authentication_type,
			PMKID,
			received_WPA_ie,
			sent_WPA_ie);
		if (status != eap_status_ok)
		{
			// ERROR, Cannot reassociate.

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: eapol_core_c::read_reassociation_parameters(): Cannot reassociate.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = eap_status_not_found;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::start_reassociation(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const /*PMKID*/)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eapol_core_c::start_reassociation()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::start_reassociation()");

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

	eap_network_id_selector_c state_selector(
		m_am_tools,
		&send_network_id);

	if (state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("start_reassociation(): EAPOL-Key session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));

	eap_status_e status(eap_status_process_general_error);

	eapol_key_state_c *eapol_key_state = m_eapol_key_state_map.get_handler(&state_selector);

	if (eapol_key_state != 0)
	{
		status = eapol_key_state->reset_cached_pmksa();
		if (status != eap_status_ok)
		{
			// We cannot reuse the session.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_ERROR, 
				(EAPL("eapol_core_c::start_reassociation(): eapol_key_state NOT reused.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (m_skip_start_4_way_handshake == true
			&& (authentication_type == eapol_key_authentication_type_RSNA_EAP
				|| authentication_type == eapol_key_authentication_type_RSNA_PSK
				|| authentication_type == eapol_key_authentication_type_WPA_EAP
				|| authentication_type == eapol_key_authentication_type_WPA_PSK))
		{
			// This is test to skip 4-Way Handshake start.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: eapol_core_c::start_reassociation(): ")
				 EAPL("skips start_4_way_handshake()\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
		else
		{
#if !defined(NO_EAPOL_KEY_STATE_SERVER)
			status = eapol_key_state->start_4_way_handshake(
				receive_network_id);
#endif //#if !defined(NO_EAPOL_KEY_STATE_SERVER)
		}

#if !defined(NO_EAPOL_KEY_STATE_SERVER)
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: eapol_core_c::start_reassociation(): ")
				 EAPL("start_4_way_handshake() failed, eap_status_e %d\n"),
				 status));
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eapol_core_c::start_reassociation(): ")
				 EAPL("start_4_way_handshake(), eap_status_e %d\n"),
				 status));
		}
#endif //#if !defined(NO_EAPOL_KEY_STATE_SERVER)

	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::complete_reassociation(
	const eapol_wlan_authentication_state_e reassociation_result,
	const eap_am_network_id_c * const receive_network_id,
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
		(EAPL("%s: eapol_core_c::complete_reassociation()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::complete_reassociation()");

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


	// No need to check previous authentication type. It can be changed in reassociation.
	m_authentication_type = authentication_type;


	eap_network_id_selector_c state_selector(
		m_am_tools,
		&send_network_id);

	if (state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("complete_reassociation(): EAPOL-Key session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));

	eapol_key_state_c *eapol_key_state = m_eapol_key_state_map.get_handler(&state_selector);

	if (eapol_key_state != 0)
	{
		// We have state for this connection.
		eap_status_e status = eapol_key_state->complete_reassociation(
			reassociation_result,
			receive_network_id,
			authentication_type,
			received_WPA_IE,
			sent_WPA_IE,
			pairwise_key_cipher_suite,
			group_key_cipher_suite
			);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::send_logoff(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eapol_core_c::send_logoff()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::send_logoff()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_not_supported);

	if (m_eap_core == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (receive_network_id == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());
	if (send_network_id.get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_buf_chain_wr_c logoff_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (logoff_packet.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t data_length = EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH;

	if (data_length > 0)
	{
		data_length = 0;
	}

	eapol_header_wr_c eapol(
		m_am_tools,
		logoff_packet.get_data_offset(
			m_eapol_header_offset, m_eapol_header_offset+data_length),
		m_eapol_header_offset+data_length);

	if (eapol.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet_send: packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eapol.set_version(eapol_protocol_version_1);
	eapol.set_packet_type(eapol_packet_type_logoff);
	eapol.set_data_length(static_cast<u16_t>(data_length));

	logoff_packet.set_data_length(m_eapol_header_offset+eapol_header_wr_c::get_header_length()+data_length);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("<- EAPOL: %s, version=0x%02x, packet_type=0x%02x=%s, data_length=0x%04x, packet length 0x%04x\n"),
		(m_is_client == true) ? "client": "server",
		eapol.get_version(),
		eapol.get_packet_type(),
		eapol.get_type_string(),
		eapol.get_data_length(),
		eapol.get_header_length()+eapol.get_data_length()));

	status = m_partner->packet_send(
		&send_network_id, &logoff_packet, m_eapol_header_offset,
		eapol.get_header_length()+eapol.get_data_length(), EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::packet_data_crypto_keys(
	const eap_am_network_id_c * const send_network_id,
	const eap_master_session_key_c * const master_session_key
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eapol_core_c::packet_data_crypto_keys()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::packet_data_crypto_keys()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	if (master_session_key->get_is_valid() == true)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("master session key"),
			 master_session_key->get_data(master_session_key->get_data_length()),
			 master_session_key->get_data_length()));
	}

	eap_network_id_selector_c state_selector(
		m_am_tools,
		send_network_id);

	if (state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("packet_data_crypto_keys(): EAPOL-Key session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));

	eapol_key_state_c *eapol_key_state = m_eapol_key_state_map.get_handler(&state_selector);

	if (eapol_key_state != 0)
	{
		status = eapol_key_state->set_pairwise_PMK(
			master_session_key,
			send_network_id);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: packet_data_crypto_keys() failed, no eapol_key_state_c object\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::packet_data_session_key(
	const eap_am_network_id_c * const send_network_id,
	const eapol_session_key_c * const key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eapol_core_c::packet_data_session_key()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::packet_data_session_key()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	if (key->get_is_valid() == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eapol session key: type 0x%02x, index 0x%02x, tx %d\n"),
			 key->get_key_type(),
			 key->get_key_index(),
			 key->get_key_tx_bit()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eapol session key"),
			 key->get_key()->get_data(key->get_key()->get_data_length()),
			 key->get_key()->get_data_length()));
	}

	// Forward the keys to lower layers
	status = m_partner->packet_data_session_key(
			send_network_id,
			key);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::shutdown_operation(
	eapol_key_state_c * const handler,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	eap_status_e status = handler->shutdown();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eapol_core_c::shutdown(), m_shutdown_was_called=%d\n"),
		(m_is_client == true) ? "client": "server",
		m_shutdown_was_called));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::shutdown()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	eap_status_e status = m_eapol_key_state_map.for_each(shutdown_operation, true);

	if (m_eap_core != 0)
	{
		status = m_eap_core->shutdown();
	}

	// This will cancel all timers of this object.
	m_partner->cancel_timer(this, EAPOL_CORE_TIMER_SEND_START_AGAIN_ID);
	m_partner->cancel_timer(this, EAPOL_REMOVE_EAPOL_KEY_HANDSHAKE_ID);
	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->read_configure(field, data);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_core_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->write_configure(field, data);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eapol_core_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eapol_core_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: %s: [0x%08x]->eapol_core_c::timer_expired(id 0x%02x, data 0x%08x).\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 id,
		 data));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::timer_expired()");

	if (id == EAPOL_CORE_TIMER_SEND_START_AGAIN_ID)
	{
		const eap_am_network_id_c * const receive_network_id
			= reinterpret_cast<const eap_am_network_id_c *>(data);
		if (m_eapol_starts_sent < m_max_eapol_starts)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TIMER: %s: EAPOL_CORE_TIMER_SEND_START_AGAIN_ID expired, re-start authentication.\n"),
				 (m_is_client == true ? "client": "server"),
				 m_eapol_start_interval));

			m_eapol_starts_sent++;			
			restart_authentication(receive_network_id , m_is_client, true, true);
		}
		else 
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: TIMER: %s: EAPOL_CORE_TIMER_SEND_START_AGAIN_ID expired, too many re-starts, notifies lower layers.\n"),
				 (m_is_client == true ? "client": "server"),
				 m_eapol_start_interval));

			// Here we swap the addresses.
			eap_am_network_id_c send_network_id(m_am_tools,
				receive_network_id->get_destination_id(),
				receive_network_id->get_source_id(),
				receive_network_id->get_type());
			if (send_network_id.get_is_valid_data() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// EAPOL-Start has been sent enough times. Send notification to lower layers.
			// After this EAPOL stays quiet and waits for incoming
			// packets or authentication restarting.
			eap_state_notification_c notification(
				m_am_tools,
				&send_network_id,
				true, // m_is_client
				eap_state_notification_generic,
				eap_protocol_layer_eapol,
				eap_type_none,
				eapol_state_start_sent,
				eapol_state_no_start_response,
				0 /* EAP identifier not valid here */,
				false);

			notification.set_authentication_error(eap_status_authentication_failure);

			state_notification(&notification);
		}
	}
	else if (id == EAPOL_REMOVE_EAPOL_KEY_HANDSHAKE_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: EAPOL_REMOVE_EAPOL_KEY_HANDSHAKE_ID elapsed, %s.\n"),
			 (m_is_client == true) ? "client": "server"));

		const eap_am_network_id_c * const send_network_id 
			= reinterpret_cast<const eap_am_network_id_c *>(data);
		if (send_network_id->get_is_valid_data() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		(void) remove_eapol_key_state(send_network_id, false);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: %s: [0x%08x]->eapol_core_c::timer_delete_data(id 0x%02x, data 0x%08x).\n"),
		(m_is_client == true) ? "client": "server",
		this, id, data));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::timer_delete_data()");

	if (id == EAPOL_CORE_TIMER_SEND_START_AGAIN_ID)
	{
		const eap_am_network_id_c * const send_network_id
			= reinterpret_cast<const eap_am_network_id_c *>(data);
		delete send_network_id;
	}
	else if (id == EAPOL_REMOVE_EAPOL_KEY_HANDSHAKE_ID)

	{
		const eap_am_network_id_c * const send_network_id 
			= reinterpret_cast<const eap_am_network_id_c *>(data);
		delete send_network_id;
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::init_eapol_key_pmksa_caching_timeout(
	const eap_am_network_id_c * const send_network_id)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::init_eapol_key_pmksa_caching_timeout().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::init_eapol_key_pmksa_caching_timeout()");

	// Initialize PMK caching timeout of EAPOL Key state.
	eap_network_id_selector_c state_selector(
		m_am_tools,
		send_network_id);

	if (state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("init_eapol_key_pmksa_caching_timeout(): EAPOL-Key session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));

	eapol_key_state_c *eapol_key_state = m_eapol_key_state_map.get_handler(&state_selector);

	if (eapol_key_state == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("session not found.\n"),
			 (m_is_client == true) ? "client": "server"));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	eap_status_e status = eapol_key_state->init_pmksa_caching_timeout();
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eapol_core_c::init_eapol_key_pmksa_caching_timeout(): ")
			 EAPL("eapol_key_state->init_pmksa_caching_timeout(), eap_status_e %d\n"),
			 status));
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::indicate_eapol_key_state_started_eap_authentication(
	const eap_am_network_id_c * const send_network_id)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::indicate_eapol_key_state_started_eap_authentication().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::indicate_eapol_key_state_started_eap_authentication()");

	// Remove possible EAPOL Key state.
	eap_network_id_selector_c state_selector(
		m_am_tools,
		send_network_id);

	if (state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("indicate_eapol_key_state_started_eap_authentication(): EAPOL-Key session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));

	eapol_key_state_c *eapol_key_state = m_eapol_key_state_map.get_handler(&state_selector);

	eap_status_e status(eap_status_handler_does_not_exists_error);

	if (eapol_key_state != 0)
	{
		status = eapol_key_state->started_eap_authentication();
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eapol_core_c::indicate_eapol_key_state_started_eap_authentication(): Cannot run eapol_key_state->started_eap_authentication() 0x%08x\n"),
			eapol_key_state));
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::remove_eapol_key_state(
	const eap_am_network_id_c * const send_network_id,
	const bool force_remove)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::remove_eapol_key_state().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::remove_eapol_key_state()");

	// Remove possible EAPOL Key state.
	eap_network_id_selector_c state_selector(
		m_am_tools,
		send_network_id);

	if (state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("remove_eapol_key_state(): EAPOL-Key session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));

	eapol_key_state_c *eapol_key_state = m_eapol_key_state_map.get_handler(&state_selector);

	if (eapol_key_state != 0)
	{
		if (force_remove == false
			&& eapol_key_state->get_marked_removed() == false)
		{
			// Do not remove object in use.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: eapol_core_c::remove_eapol_key_state(): Cannot removed used object 0x%08x\n"),
				eapol_key_state));
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}

		eapol_key_state->shutdown();
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eapol_core_c::remove_eapol_key_state(): Cannot run eapol_key_state->shutdown() 0x%08x\n"),
			eapol_key_state));
	}

	eap_status_e status = m_eapol_key_state_map.remove_handler(&state_selector, true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eapol_core_c::remove_eapol_key_state(): ")
			 EAPL("eapol_key_state->remove_handler(), eap_status_e %d\n"),
			 status));
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::asynchronous_init_remove_eapol_key_state(
	const eap_am_network_id_c * const send_network_id)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::asynchronous_init_remove_eapol_key_state().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::asynchronous_init_remove_eapol_key_state()");

	// NOTE: we cannot delete the eapol_key_state_c object directly, because we will
	// return from here to removed object.

	eap_status_e status = eap_status_process_general_error;

	eap_network_id_selector_c state_selector(
		m_am_tools,
		send_network_id);

	if (state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("asynchronous_init_remove_eapol_key_state(): EAPOL-Key session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));

	eapol_key_state_c *session = m_eapol_key_state_map.get_handler(&state_selector);

	if (session != 0)
	{
		session->set_marked_removed();

		// So we initiate a timer to remove session identified by state_selector.
		eap_am_network_id_c * const copy_send_network_id = send_network_id->copy();
		if (copy_send_network_id == 0
			|| copy_send_network_id->get_is_valid_data() == false)
		{
			delete copy_send_network_id;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = m_partner->set_timer(
			this,
			EAPOL_REMOVE_EAPOL_KEY_HANDSHAKE_ID, 
			copy_send_network_id,
			EAPOL_REMOVE_EAPOL_KEY_HANDSHAKE_TIMEOUT);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eapol_core_c::asynchronous_init_remove_eapol_key_state()")
			 EAPL(": %s: EAPOL_REMOVE_EAPOL_KEY_HANDSHAKE_ID timer set %d ms.\n"),
			 (m_is_client == true) ? "client": "server",
			 EAPOL_REMOVE_EAPOL_KEY_HANDSHAKE_TIMEOUT));
	}
	else
	{
		// Not found, cannot remove.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: eapol_core_c::asynchronous_init_remove_eapol_key_state()")
			 EAPL(": %s: failed session not found.\n"),
			 (m_is_client == true) ? "client": "server"));

		status = eap_status_ok;
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eapol_core_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::state_notification(): m_block_state_notifications=%d.\n"),
		 (m_is_client == true) ? "client": "server",
		 m_block_state_notifications));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::state_notification()");

	if (m_block_state_notifications == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: eapol_core_c::state_notification(): Blocks state notification")
			 EAPL("Protocol layer %d, Protocol %d, State transition ")
			 EAPL("from %d=%s to %d=%s, client %d\n"),
			state->get_protocol_layer(), 
			state->get_protocol(), 
			state->get_previous_state(), 
			state->get_previous_state_string(), 
			state->get_current_state(), 
			state->get_current_state_string(),
			state->get_is_client()));

		return;
	}

	if (state->get_protocol_layer() == eap_protocol_layer_eap)
	{
		if (state->get_current_state() == eap_state_identity_request_received
			|| state->get_current_state() == eap_state_eap_response_sent)
		{
			if (state->get_current_state() == eap_state_identity_request_received)
			{
				(void) m_partner->cancel_timer(
					this,
					EAPOL_CORE_TIMER_SEND_START_AGAIN_ID);
			}

			if (state->get_current_state() == eap_state_identity_request_received
				|| state->get_current_state() == eap_state_eap_response_sent)
			{
				// Indicate EAPOL Key state the started EAP-authentication.
				status = indicate_eapol_key_state_started_eap_authentication(
					state->get_send_network_id());
				if (status != eap_status_ok)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("WARNING: eapol_core_c::state_notification(): ")
						 EAPL("indicate_eapol_key_state_started_eap_authentication(), eap_status_e %d\n"),
						status));
				}
			}

		}
		else if (state->get_current_state() == eap_state_authentication_terminated_unsuccessfully)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: eapol_core_c::state_notification(): %s: EAP-authentication FAILED\n"),
				 (state->get_is_client() == true ? "client": "server")));

			// Remove possible EAPOL Key state.
			status = remove_eapol_key_state(
				state->get_send_network_id(),
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("WARNING: eapol_core_c::state_notification(): ")
					 EAPL("remove_eapol_key_state(), eap_status_e %d\n"),
					status));
			}

		}
		else if (state->get_current_state() == eap_state_authentication_finished_successfully)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eapol_core_c::state_notification(): %s: EAP authentication SUCCESS\n"),
				(state->get_is_client() == true ? "client": "server")));

			eap_network_id_selector_c state_selector(
				m_am_tools,
				state->get_send_network_id());

			if (state_selector.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return;
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("state_notification(): EAPOL-Key session"),
				 state_selector.get_data(state_selector.get_data_length()),
				 state_selector.get_data_length()));

			eapol_key_state_c *eapol_key_state
				= m_eapol_key_state_map.get_handler(&state_selector);

#if !defined(NO_EAPOL_KEY_STATE_SERVER)
			if (m_is_client == false)
			{
				// server
				if (eapol_key_state != 0)
				{
					// Here we swap the addresses.
					eap_am_network_id_c receive_network_id(
						m_am_tools,
						state->get_send_network_id()->get_destination_id(),
						state->get_send_network_id()->get_source_id(),
						state->get_send_network_id()->get_type());
					if (receive_network_id.get_is_valid_data() == false)
					{
						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("ERROR: eapol_core_c::state_notification(): ")
							 EAPL("start_4_way_handshake() failed, allocation error\n"),
							status));
						return;
					}

					if (m_skip_start_4_way_handshake == true
						&& (m_authentication_type == eapol_key_authentication_type_RSNA_EAP
							|| m_authentication_type == eapol_key_authentication_type_RSNA_PSK
							|| m_authentication_type == eapol_key_authentication_type_WPA_EAP
							|| m_authentication_type == eapol_key_authentication_type_WPA_PSK
							|| m_authentication_type == eapol_key_authentication_type_WPXM))
					{
						// This is test to skip 4-Way Handshake start.
						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("WARNING: eapol_core_c::state_notification(): ")
							 EAPL("skips start_4_way_handshake()\n")));
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return;
					}
					else
					{
						status = eapol_key_state->start_4_way_handshake(
							&receive_network_id);
					}

					if (status != eap_status_ok)
					{
						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("ERROR: eapol_core_c::state_notification(): ")
							 EAPL("start_4_way_handshake() failed, eap_status_e %d\n"),
							status));
					}
					else
					{
						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("eapol_core_c::state_notification(): ")
							 EAPL("start_4_way_handshake(), eap_status_e %d\n"),
							status));
					}
				}
				else
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("ERROR: eapol_core_c::state_notification(): ")
						 EAPL("start_4_way_handshake() failed, no eapol_key_state_c object\n")));
				}
			}
			else
#endif //#if !defined(NO_EAPOL_KEY_STATE_SERVER)
			{
				if (eapol_key_state != 0)
				{
					eap_status_e status = eapol_key_state->allow_4_way_handshake();
					if (status != eap_status_ok)
					{
						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("ERROR: eapol_core_c::state_notification(): ")
							 EAPL("allow_4_way_handshake() failed, eap_status_e %d\n"),
							status));
					}
					else
					{
						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("eapol_core_c::state_notification(): ")
							 EAPL("allow_4_way_handshake(), eap_status_e %d\n"),
							status));
					}
				}
				else
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("ERROR: eapol_core_c::state_notification(): ")
						 EAPL("allow_4_way_handshake() failed, no eapol_key_state_c object\n")));
				}
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eapol_core_c::state_notification(): Unknown notification: ")
				 EAPL("Protocol layer %d, Protocol %d, State transition ")
				 EAPL("from %d=%s to %d=%s, client %d\n"),
				state->get_protocol_layer(), 
				state->get_protocol(), 
				state->get_previous_state(), 
				state->get_previous_state_string(), 
				state->get_current_state(), 
				state->get_current_state_string(),
				state->get_is_client()));
		}
	}
	else if (state->get_protocol_layer() == eap_protocol_layer_eapol_key)
	{
		// This nofifation is from eapol_key_state_c object.
		if (state->get_current_state()
			== eapol_key_state_802_11i_authentication_terminated_unsuccessfull)
		{
			if (state->get_protocol() == eapol_key_handshake_type_4_way_handshake)
			{
				// 4-Way Handshake failed.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: eapol_core_c::state_notification(): ")
					 EAPL("%s: 4-Way Handshake FAILED\n"),
					 (state->get_is_client() == true ? "client": "server")));
			}
			else if (state->get_protocol() == eapol_key_handshake_type_group_key_handshake)
			{
				// Group Key Handshake failed.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: eapol_core_c::state_notification(): ")
					 EAPL("%s: Group Key Handshake FAILED\n"),
					 (state->get_is_client() == true ? "client": "server")));
			}
		}
		else if (state->get_current_state()
				 == eapol_key_state_802_11i_authentication_finished_successfull)
		{
			if (state->get_protocol() == eapol_key_handshake_type_4_way_handshake)
			{
				// 4-Way Handshake succesfull.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eapol_core_c::state_notification(): %s: 4-Way Handshake SUCCESS.\n"),
					 (state->get_is_client() == true ? "client": "server")));
			}
			else if (state->get_protocol() == eapol_key_handshake_type_group_key_handshake)
			{
				// Group Key Handshake succesfull.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eapol_core_c::state_notification(): %s: Group Key Handshake SUCCESS.\n"),
					 (state->get_is_client() == true ? "client": "server")));
			}
			else if (state->get_protocol() == eapol_key_handshake_type_802_11i_handshake)
			{
				// Full 802.11i authentication succesfull.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eapol_core_c::state_notification(): %s: ")
					 EAPL("Full 802.11i authentication SUCCESS.\n"),
					 (state->get_is_client() == true ? "client": "server")));
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eapol_core_c::state_notification(): Unknown notification: ")
					 EAPL("Protocol layer %d, Protocol %d, State transition ")
					 EAPL("from %d=%s to %d=%s, client %d\n"),
					state->get_protocol_layer(), 
					state->get_protocol(), 
					state->get_previous_state(), 
					state->get_previous_state_string(), 
					state->get_current_state(), 
					state->get_current_state_string(),
					state->get_is_client()));
			}
		}
#if defined(EAP_USE_WPXM)
		else if (state->get_current_state()
				 == eapol_key_state_wpxm_reassociation_finished_successfull)
		{
			if (state->get_protocol() == eapol_key_handshake_type_WPXM_reassociation)
			{
				// WPXM reassociation succesfull.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eapol_core_c::state_notification(): %s: ")
					 EAPL("WPXM reassociation SUCCESS.\n"),
					 (state->get_is_client() == true ? "client": "server")));
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eapol_core_c::state_notification(): Unknown notification: ")
					 EAPL("Protocol layer %d, Protocol %d, State transition ")
					 EAPL("from %d=%s to %d=%s, client %d\n"),
					state->get_protocol_layer(), 
					state->get_protocol(), 
					state->get_previous_state(), 
					state->get_previous_state_string(), 
					state->get_current_state(), 
					state->get_current_state_string(),
					state->get_is_client()));
			}
		}
#endif //#if defined(EAP_USE_WPXM)
		else if (state->get_current_state()
				 == eapol_key_state_group_key_handshake_successfull)
		{
			if (state->get_protocol() == eapol_key_handshake_type_group_key_handshake)
			{
				// Group Key Handshake succesfull.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eapol_core_c::state_notification(): %s: Group Key Handshake SUCCESS.\n"),
					 (state->get_is_client() == true ? "client": "server")));
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eapol_core_c::state_notification(): Unknown notification: ")
					 EAPL("Protocol layer %d, Protocol %d, State transition ")
					 EAPL("from %d=%s to %d=%s, client %d\n"),
					state->get_protocol_layer(), 
					state->get_protocol(), 
					state->get_previous_state(), 
					state->get_previous_state_string(), 
					state->get_current_state(), 
					state->get_current_state_string(),
					state->get_is_client()));
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eapol_core_c::state_notification(): Unknown notification: ")
				 EAPL("Protocol layer %d, Protocol %d, State transition ")
				 EAPL("from %d=%s to %d=%s, client %d\n"),
				state->get_protocol_layer(), 
				state->get_protocol(), 
				state->get_previous_state(), 
				state->get_previous_state_string(), 
				state->get_current_state(), 
				state->get_current_state_string(),
				state->get_is_client()));
		}
	}

	m_partner->state_notification(state);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::asynchronous_init_remove_eap_session(
	const eap_am_network_id_c * const /* send_network_id */)
{
	// eapol_core_c object does not support asynchronous_init_remove_eap_session().
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::asynchronous_start_authentication(
	const eap_am_network_id_c * const /* receive_network_id */,
	const bool /* is_client_when_true */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::set_timer(
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
EAP_FUNC_EXPORT eap_status_e eapol_core_c::cancel_timer(
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

EAP_FUNC_EXPORT eap_status_e eapol_core_c::check_is_valid_eap_type(
	const eap_type_value_e eap_type)
{
	eap_status_e status = m_partner->check_is_valid_eap_type(eap_type);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_core_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	eap_status_e status = m_partner->get_eap_type_list(eap_type_list);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::cancel_authentication_session(
	eapol_key_state_c * const handler,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_core_c::cancel_authentication_session(): this = 0x%08x => 0x%08x.\n"),
		handler,
		dynamic_cast<abs_eap_base_timer_c *>(handler)));

	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	eap_status_e status = handler->cancel_authentication_session();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_core_c::cancel_all_authentication_sessions()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_core_c::cancel_all_authentication_sessions(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::cancel_all_authentication_sessions()");

	eap_status_e status(eap_status_ok);


	bool previous_block = m_block_state_notifications;
	m_block_state_notifications = true;

	if (m_eap_core != 0)
	{
		status = m_eap_core->cancel_all_eap_sessions();
	}

	status = m_eapol_key_state_map.for_each(cancel_authentication_session, true);

	m_block_state_notifications = previous_block;


	// This will cancel all timers of this object.
	m_partner->cancel_timer(this, EAPOL_CORE_TIMER_SEND_START_AGAIN_ID);
	m_partner->cancel_timer(this, EAPOL_REMOVE_EAPOL_KEY_HANDSHAKE_ID);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_core_c::get_and_increment_global_key_counter(
	eap_variable_data_c * const key_counter)
{
	key_counter->reset();
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

/**
 * Function creates a state for later use. This is for optimazing 4-Way Handshake.
 * @param receive_network_id carries the MAC addresses.
 * MAC address of Authenticator should be in source address. MAC address of 
 * Supplicant should be in destination address.
 * @param authentication_type is the selected authentication type.
 */
EAP_FUNC_EXPORT eap_status_e eapol_core_c::create_state(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type
	)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::create_state().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::create_state()");

	if (receive_network_id->get_type() != eapol_ethernet_type_pae)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eapol_core_c::create_state(): Illegal Ethernet type %d\n"),
			receive_network_id->get_type()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ethernet_type_not_supported);
	}

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

	eap_network_id_selector_c state_selector(
		m_am_tools,
		&send_network_id);

	if (state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_authentication_type = authentication_type;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("create_state(): EAPOL-Key session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));


	eapol_key_state_c *eapol_key_state = m_eapol_key_state_map.get_handler(&state_selector);

	if (eapol_key_state != 0)
	{
		// Reuse the session.
		eapol_key_state->unset_marked_removed();

		if (m_is_client == false)
		{
			// In test version do not reset server.
		}
		else
		{
			status = eapol_key_state->reset();
			if (status != eap_status_ok)
			{
				// We cannot reuse the session.
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_ERROR,
					(EAPL("eapol_core_c::create_state(): eapol_key_state NOT reused.\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}


	if (eapol_key_state == 0)
	{
		eapol_key_state = new eapol_key_state_c(
			m_am_tools,
			this,
			m_partner,
			m_is_client,
			receive_network_id,
			authentication_type);
		if (eapol_key_state == 0
			|| eapol_key_state->get_is_valid() == false)
		{
			if (eapol_key_state != 0)
			{
				eapol_key_state->shutdown();
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("WARNING: eapol_core_c::create_state(): Cannot run eapol_key_state->shutdown() 0x%08x\n"),
					eapol_key_state));
			}
			delete eapol_key_state;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = eapol_key_state->initialize(
			receive_network_id,
			authentication_type);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_eapol_key_state_map.add_handler(&state_selector, eapol_key_state);
		if (status != eap_status_ok)
		{
			if (eapol_key_state != 0)
			{
				eapol_key_state->shutdown();
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("WARNING: eapol_core_c::create_state(): Cannot run eapol_key_state->shutdown() 0x%08x\n"),
					eapol_key_state));
			}
			delete eapol_key_state;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = eapol_key_state->initialize(
			receive_network_id,
			authentication_type);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = eapol_key_state->configure();
	if (status != eap_status_ok)
	{
		status = remove_eapol_key_state(
			&send_network_id,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: eapol_core_c::create_state(): ")
				 EAPL("remove_eapol_key_state(), eap_status_e %d\n"),
				status));
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * @param receive_network_id carries the MAC addresses.
 * MAC address of Authenticator should be in source address. MAC address of 
 * Supplicant should be in destination address.
 * @param authenticator_RSNA_IE is RSN IE of authenticator. Authenticator 
 * sends this in Beacon or Probe message.
 * @param supplicant_RSNA_IE is RSN IE of supplicant. Supplicant sends 
 * this in (re)association request message.
 * @param eapol_pairwise_cipher is the selected pairwise cipher.
 * @param eapol_group_cipher is the selected group cipher.
 */
EAP_FUNC_EXPORT eap_status_e eapol_core_c::association(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const authenticator_RSNA_IE,
	const eap_variable_data_c * const supplicant_RSNA_IE,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_pairwise_cipher,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_group_cipher,
	const eap_variable_data_c * const pre_shared_key_PSK
	)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::association().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::association()");

	if (receive_network_id->get_type() != eapol_ethernet_type_pae)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eapol_core_c::association(): Illegal Ethernet type %d\n"),
			receive_network_id->get_type()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ethernet_type_not_supported);
	}

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

	eap_network_id_selector_c state_selector(
		m_am_tools,
		&send_network_id);

	if (state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_authentication_type = authentication_type;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("association(): EAPOL-Key session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));


	eapol_key_state_c *eapol_key_state = m_eapol_key_state_map.get_handler(&state_selector);

	if (eapol_key_state == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
	}
	else
	{
		status = eapol_key_state->initialize(
			receive_network_id,
			authentication_type,
			authenticator_RSNA_IE,
			supplicant_RSNA_IE,
			eapol_pairwise_cipher,
			eapol_group_cipher,
			pre_shared_key_PSK);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (authentication_type == eapol_key_authentication_type_RSNA_PSK
		|| authentication_type == eapol_key_authentication_type_WPA_PSK)
	{

#if !defined(NO_EAPOL_KEY_STATE_SERVER)
		if (m_is_client == false)
		{
			if (m_skip_start_4_way_handshake == true)
			{
				// This is test to skip 4-Way Handshake start.
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("WARNING: eapol_core_c::association(): ")
					 EAPL("skips start_4_way_handshake()\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
			else
			{
				status = eapol_key_state->start_4_way_handshake(
					receive_network_id);
			}

			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
#endif //#if !defined(NO_EAPOL_KEY_STATE_SERVER)
		{
			eapol_key_state->allow_4_way_handshake();
		}
	}
	else if (authentication_type == eapol_key_authentication_type_RSNA_EAP
		|| authentication_type == eapol_key_authentication_type_WPA_EAP
		|| authentication_type == eapol_key_authentication_type_dynamic_WEP
		|| authentication_type == eapol_key_authentication_type_WPXM
		|| authentication_type == eapol_key_authentication_type_WPS
		|| authentication_type == eapol_key_authentication_type_EAP_authentication_no_encryption
		)
	{
		// Creates a EAP-session.
		status = m_eap_core->create_eap_session(receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * @param receive_network_id carries the MAC addresses.
 * MAC address of Authenticator should be in source address.
 * MAC address of Supplicant should be in destination address.
 */
EAP_FUNC_EXPORT eap_status_e eapol_core_c::disassociation(
	const bool complete_to_lower_layer,
	const eap_am_network_id_c * const receive_network_id
	)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::disassociation().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::disassociation()");

	if (receive_network_id == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

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


	(void) m_partner->cancel_timer(this, EAPOL_CORE_TIMER_SEND_START_AGAIN_ID);

	// First we remove possible EAP session.
	(void) m_eap_core->remove_eap_session(
		complete_to_lower_layer,
		receive_network_id);

	status = init_eapol_key_pmksa_caching_timeout(
		&send_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eapol_core_c::disassociation(): ")
			 EAPL("init_eapol_key_pmksa_caching_timeout(), eap_status_e %d\n"),
			status));
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/// @see abs_eap_core_c::add_rogue_ap().
EAP_FUNC_EXPORT eap_status_e eapol_core_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::add_rogue_ap().\n"),
		 (m_is_client == true) ? "client": "server"));

	const eap_status_e status = m_partner->add_rogue_ap(rogue_ap_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_core_c::tkip_mic_failure(
	const eap_am_network_id_c * const receive_network_id,
	const bool fatal_failure_when_true,
	const eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e tkip_mic_failure_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::tkip_mic_failure().\n"),
		 (m_is_client == true) ? "client": "server"));

	eap_status_e status = eap_status_process_general_error;

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

	eap_network_id_selector_c state_selector(
		m_am_tools,
		&send_network_id);

	if (state_selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("tkip_mic_failure(): EAPOL-Key session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));


	eapol_key_state_c *eapol_key_state = m_eapol_key_state_map.get_handler(&state_selector);

	if (eapol_key_state != 0)
	{
		status = eapol_key_state->tkip_mic_failure(
			fatal_failure_when_true,
			tkip_mic_failure_type);
	}
	else
	{
		status = eap_status_handler_does_not_exists_error;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::set_session_timeout(
	const u32_t /* session_timeout_ms */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eapol_core_c::save_simple_config_session(
	const simple_config_state_e state,
	EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
	const eap_variable_data_c * const new_password,
	const simple_config_Device_Password_ID_e Device_Password_ID,
	const simple_config_payloads_c * const other_configuration)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::save_simple_config_session().\n"),
		 (m_is_client == true) ? "client": "server"));

	const eap_status_e status = m_partner->save_simple_config_session(
		state,
		credential_array,
		new_password,
		Device_Password_ID,
		other_configuration);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::set_eap_database_reference_values(
	const eap_variable_data_c * const reference)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_core_c::set_eap_database_reference_values()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::set_eap_database_reference_values()");

	eap_status_e status(eap_status_ok);

	if (m_eap_core != 0)
	{
		status = m_eap_core->set_eap_database_reference_values(reference);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::get_802_11_authentication_mode(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const SSID,
	const eap_variable_data_c * const preshared_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_core_c::get_802_11_authentication_mode()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::get_802_11_authentication_mode()");

	eap_status_e status(eap_status_ok);

	if (m_eap_core != 0)
	{
		status = m_eap_core->get_802_11_authentication_mode(
			receive_network_id,
			authentication_type,
			SSID,
			preshared_key);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::complete_get_802_11_authentication_mode(
		const eap_status_e completion_status,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_802_11_authentication_mode_e mode)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_core_c::complete_get_802_11_authentication_mode()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::complete_get_802_11_authentication_mode()");

	eap_status_e status(eap_status_ok);

	if (m_partner != 0)
	{
		status = m_partner->complete_get_802_11_authentication_mode(
			completion_status,
			receive_network_id,
			mode);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_core_c::complete_remove_eap_session(
	const bool complete_to_lower_layer,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_core_c::complete_remove_eap_session()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_core_c::complete_remove_eap_session()");

	eap_status_e status(eap_status_ok);

	if (m_partner != 0)
	{
		status = m_partner->complete_disassociation(
			complete_to_lower_layer,
			receive_network_id);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
// End.
