/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wapi_session_core.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 16.1.1 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.1.1
*/

// This is enumeration of WAPI source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 20004
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "wapi_session_core.h"
#include "eap_state_notification.h"
#include "eap_network_id_selector.h"
#include "abs_eap_am_mutex.h"
#include "eap_config.h"
#include "wapi_core.h"
#include "eap_buffer.h"
#include "eap_automatic_variable.h"
#include "wai_protocol_packet_header.h"
#include "wapi_strings.h"
#include "eapol_session_key.h"


//--------------------------------------------------

// 
EAP_FUNC_EXPORT wapi_session_core_c::~wapi_session_core_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_session_core_c::~wapi_session_core_c(): this = 0x%08x => 0x%08x.\n"),
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
EAP_FUNC_EXPORT wapi_session_core_c::wapi_session_core_c(
	abs_eap_am_tools_c * const tools,
	abs_wapi_core_c * const partner,
	const bool is_client_when_true)
: m_partner(partner)
, m_am_tools(tools)
, m_session_map(tools, this)
, m_remove_session_timeout(WAPI_SESSION_CORE_REMOVE_SESSION_TIMEOUT)
, m_is_client(is_client_when_true)
, m_is_valid(false)
, m_use_wapi_session_core_reset_session(true)
, m_shutdown_was_called(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_session_core_c::wapi_session_core_c(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT abs_wapi_core_c * wapi_session_core_c::get_partner()
{
	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	return m_partner;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void wapi_session_core_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool wapi_session_core_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_session_core_c::reset(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	eap_status_e status = m_session_map.for_each(shutdown_operation, true);
	(void)EAP_STATUS_RETURN(m_am_tools, status);

	status = m_session_map.reset();
	(void)EAP_STATUS_RETURN(m_am_tools, status);

	m_partner->cancel_timer(this, WAPI_SESSION_CORE_REMOVE_SESSION_ID);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: WAPI_SESSION_CORE_REMOVE_SESSION_ID cancelled, %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT wapi_core_c * wapi_session_core_c::create_new_session(
	const eap_am_network_id_c * const receive_network_id)
{
	eap_status_e status = eap_status_process_general_error;

	// Create a new session.
	wapi_core_c * const session = new wapi_core_c(
		m_am_tools,
		this,
		m_is_client,
		receive_network_id);

	if (session == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return 0;
	}

	if (session->get_is_valid() == false)
	{
		session->shutdown();
		delete session;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return 0;
	}

	status = session->configure();
	if (status != eap_status_ok)
	{
		session->shutdown();
		delete session;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void)EAP_STATUS_RETURN(m_am_tools, status);
		return 0;
	}

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());
	if (send_network_id.get_is_valid_data() == false)
	{
		session->shutdown();
		delete session;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return 0;
	}

	eap_network_id_selector_c selector(
		m_am_tools,
		&send_network_id);
	if (selector.get_is_valid() == false)
	{
		session->shutdown();
		delete session;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return 0;
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("create_new_session() WAPI session"),
		 selector.get_data(selector.get_data_length()),
		 selector.get_data_length()));

	status = m_session_map.add_handler(&selector, session);
	if (status != eap_status_ok)
	{
		session->shutdown();
		delete session;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void)EAP_STATUS_RETURN(m_am_tools, status);
		return 0;
	}

	return session;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::reset_or_remove_session(
	wapi_core_c ** const session,
	const eap_network_id_selector_c * const selector,
	const bool reset_immediately)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	if (session == 0
		|| *session == 0
		|| selector == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	if (m_use_wapi_session_core_reset_session == true)
	{
		// This will reuse session.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_session_core_c::reset_or_remove_session(): resets session, session 0x%08x.\n"),
			(*session)));

		// NOTE, this delayed reset of session is used bacause the device is so slow in some cases
		// (e.g. it cannot respond to WPA 4-Way Handshake message fast enough)

		if (reset_immediately == true)
		{
			(*session)->unset_marked_removed();

			status = (*session)->reset();
		}
		else
		{
			// This will delay reset to wapi_core_c::packet_process().
			status = eap_status_ok;
		}
	}
	else
	{
		//  This will cause shutdown of the session.
		status = eap_status_process_general_error;
	}

	if (status != eap_status_ok)
	{
		// We cannot reuse the session.

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_session_core_c::reset_or_remove_session(): shutdown session, session 0x%08x.\n"),
			(*session)));

		(*session)->shutdown();
		(*session) = 0;

		status = m_session_map.remove_handler(selector, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: wapi_session_core_c::reset_or_remove_session(): m_session_map.remove_type(), eap_status_e %d\n"),
				status));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_session_core_c::reset_or_remove_session(): session NOT reused.\n")));
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_session_core_c::reset_or_remove_session(): session reused, session 0x%08x.\n"),
			(*session)));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::packet_process(
	const eap_am_network_id_c * const receive_network_id,
	eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	// Each WAPI authentication session includes its own wapi_core_c object.
	// WAPI authentication sessions are separated by eap_am_network_id_c object.

	if (packet_data == 0
		|| packet_length < eap_header_base_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	wai_protocol_packet_header_c wai(
		m_am_tools,
		packet_data->get_header_buffer(packet_length),
		packet_length);

	if (wai.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_session_core_c::packet_process(): %s, packet buffer corrupted.\n"),
			 (m_is_client == true) ? "client": "server"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA|TRACE_TEST_VECTORS, 
		(EAPL("WAI-packet"),
		 wai.get_header_buffer(packet_length),
		 packet_length));

	WAI_PROTOCOL_PACKET_TRACE_HEADER("->", &wai, m_is_client);

	status = wai.check_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());
	if (send_network_id.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_network_id_selector_c selector(
		m_am_tools,
		&send_network_id);
	if (selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("packet_process() WAPI-session"),
		 selector.get_data(selector.get_data_length()),
		 selector.get_data_length()));

	wapi_core_c *session = m_session_map.get_handler(&selector);

	if (session == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
	}

	if (session != 0)
	{
		status = session->packet_process(
			receive_network_id,
			&wai,
			packet_length);
	}
	else
	{
		status = eap_status_illegal_eap_type;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::packet_send(
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

	wai_protocol_packet_header_c wai(
		m_am_tools,
		sent_packet->get_data_offset(header_offset, data_length),
		data_length);

	if (wai.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_session_core_c::packet_process(): %s, packet buffer corrupted.\n"),
			 (m_is_client == true) ? "client": "server"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA|TRACE_TEST_VECTORS, 
		(EAPL("WAI-packet"),
		 wai.get_header_buffer(data_length),
		 data_length));

	WAI_PROTOCOL_PACKET_TRACE_HEADER("<-", &wai, m_is_client);

	eap_status_e status = m_partner->packet_send(
		send_network_id, sent_packet, header_offset, data_length, buffer_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t wapi_session_core_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const u32_t offset = m_partner->get_header_offset(MTU, trailer_length);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return offset;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);


	{
		// This is optional.
		eap_variable_data_c data(m_am_tools);

		eap_status_e status = m_partner->read_configure(
			cf_str_EAP_SESSION_use_reset_session.get_field(),
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
					m_use_wapi_session_core_reset_session = true;
				}
				else
				{
					m_use_wapi_session_core_reset_session = false;
				}
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::shutdown_operation(
	wapi_core_c * const core,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	eap_status_e status = core->shutdown();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_session_core_c::shutdown(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	eap_status_e status = reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::restart_authentication(
	const eap_am_network_id_c * const send_network_id,
	const bool is_client_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);
	EAP_ASSERT(is_client_when_true == m_is_client);

	eap_status_e status = eap_status_process_general_error;

	eap_network_id_selector_c selector(
		m_am_tools,
		send_network_id);
	if (selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("restart_authentication() WAPI session"),
		 selector.get_data(selector.get_data_length()),
		 selector.get_data_length()));

	wapi_core_c *session = m_session_map.get_handler(&selector);

	if (session != 0)
	{
		status = session->restart_authentication(
			send_network_id,
			is_client_when_true);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::restart_authentication(
	const eap_am_network_id_c * const receive_network_id,
	const bool is_client_when_true,
	const bool force_clean_restart,
	const bool from_timer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);
	EAP_ASSERT(is_client_when_true == m_is_client);

	eap_status_e status = eap_status_process_general_error;

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());
	if (send_network_id.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_network_id_selector_c selector(
		m_am_tools,
		&send_network_id);
	if (selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("restart_authentication() WAPI session"),
		 selector.get_data(selector.get_data_length()),
		 selector.get_data_length()));

	wapi_core_c *session = m_session_map.get_handler(&selector);

	if (session == 0)
	{
		// Create a new session.
		session = create_new_session(receive_network_id);
	}

	if (session != 0)
	{
		status = session->restart_authentication(
			receive_network_id,
			is_client_when_true);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::packet_data_session_key(
	const eap_am_network_id_c * const send_network_id,
	const eapol_session_key_c * const key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: wapi_session_core_c::packet_data_session_key()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_session_core_c::packet_data_session_key()");

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

EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::read_configure(
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

EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::write_configure(
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
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->wapi_session_core_c::")
		 EAPL("timer_expired(id 0x%02x, data 0x%08x), %s.\n"),
		 this,
		 id,
		 data,
		 (m_is_client == true) ? "client": "server"));

	if (id == WAPI_SESSION_CORE_REMOVE_SESSION_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: WAPI_SESSION_CORE_REMOVE_SESSION_ID elapsed, %s.\n"),
			 (m_is_client == true) ? "client": "server"));

		const eap_network_id_selector_c * const selector 
			= reinterpret_cast<const eap_network_id_selector_c *>(data);
		if (selector == 0
			|| selector->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("timer_expired() WAPI-session"),
			 selector->get_data(selector->get_data_length()),
			 selector->get_data_length()));

		wapi_core_c *session = m_session_map.get_handler(selector);

		if (session != 0
			&& session->get_marked_removed() == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("TIMER: unused session found, it is deleted, session 0x%08x.\n"),
				session));

			// Session must be deleted here.
			session->shutdown();
			session = 0;

			// This will delete session.
			eap_status_e status = m_session_map.remove_handler(selector, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("ERROR: m_session_map.remove_type(), eap_status_e %d\n"),
					 status));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (session != 0
			&& session->get_marked_removed() == false)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("TIMER: session found, it is in use, session 0x%08x.\n"),
				session));
		}
		else
		{
			// Not found, no need to remove.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("TIMER: session not found.\n")));
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->wapi_session_core_c::")
		 EAPL("timer_delete_data(id 0x%02x, data 0x%08x).\n"),
		this, id, data));

	if (id == WAPI_SESSION_CORE_REMOVE_SESSION_ID)

	{
		const eap_network_id_selector_c * const selector 
			= reinterpret_cast<const eap_network_id_selector_c *>(data);
		delete selector;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::synchronous_cancel_all_wapi_sessions()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_session_core_c::synchronous_cancel_all_wapi_sessions(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	eap_status_e status = reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::synchronous_create_wapi_session(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_session_core_c::synchronous_create_wapi_session(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	eap_status_e status = eap_status_process_general_error;

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(
		m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());
	if (send_network_id.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_network_id_selector_c selector(
		m_am_tools,
		&send_network_id);
	if (selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("synchronous_create_eap_session() WAPI-session"),
		 selector.get_data(selector.get_data_length()),
		 selector.get_data_length()));

	wapi_core_c *session = m_session_map.get_handler(&selector);

	if (session == 0)
	{
		session = create_new_session(receive_network_id);

		if (session == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		else
		{
			status = eap_status_ok;
		}
	}
	else
	{
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::synchronous_remove_wapi_session(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_session_core_c::synchronous_remove_eap_session(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	eap_status_e status = eap_status_process_general_error;

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(
		m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());
	if (send_network_id.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_network_id_selector_c selector(
		m_am_tools,
		&send_network_id);
	if (selector.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("synchronous_remove_eap_session() WAPI-session"),
		 selector.get_data(selector.get_data_length()),
		 selector.get_data_length()));

	wapi_core_c *session = m_session_map.get_handler(&selector);

	if (session != 0)
	{
		// This reset is immediaete.
		status = reset_or_remove_session(
			&session,
			&selector,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		// Not found, no need to remove.
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e wapi_session_core_c::asynchronous_init_remove_wapi_session(
	const eap_am_network_id_c * const send_network_id)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_session_core_c::asynchronous_init_remove_wapi_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

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
		(EAPL("asynchronous_init_remove_wapi_session() WAPI session"),
		 state_selector.get_data(state_selector.get_data_length()),
		 state_selector.get_data_length()));

	eap_status_e status = asynchronous_init_remove_wapi_session(
		&state_selector);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e wapi_session_core_c::asynchronous_init_remove_wapi_session(
	const eap_network_id_selector_c * const state_selector)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_session_core_c::asynchronous_init_remove_wapi_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	// NOTE: we cannot call directly synchronous_remove_wapi_session(), because we will
	// return from here to removed object.

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("asynchronous_init_remove_wapi_session() WAPI session"),
		 state_selector->get_data(state_selector->get_data_length()),
		 state_selector->get_data_length()));

	wapi_core_c *session = m_session_map.get_handler(state_selector);

	if (session != 0)
	{
		session->set_marked_removed();

		// So we initiate a timer to remove session identified by state_selector.
		eap_network_id_selector_c * const copy_selector = state_selector->copy();
		if (copy_selector == 0
			|| copy_selector->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = m_partner->set_timer(
			this,
			WAPI_SESSION_CORE_REMOVE_SESSION_ID, 
			copy_selector,
			m_remove_session_timeout);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("wapi_session_core_c::asynchronous_init_remove_wapi_session()")
			 EAPL(": %s: WAPI_SESSION_CORE_REMOVE_SESSION_ID timer set %d ms.\n"),
			 (m_is_client == true) ? "client": "server",
			 m_remove_session_timeout));
	}
	else
	{
		// Not found, cannot remove.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: wapi_session_core_c::asynchronous_init_remove_wapi_session()")
			 EAPL(": %s: failed session not found.\n"),
			 (m_is_client == true) ? "client": "server"));

		status = eap_status_ok;
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void wapi_session_core_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	m_partner->state_notification(state);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::set_timer(
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
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::cancel_timer(
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
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->cancel_all_timers();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::set_session_timeout(
	const u32_t /* session_timeout_ms */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::cancel_authentication_session(
	wapi_core_c * const handler,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_session_core_c::cancel_authentication_session(): this = 0x%08x => 0x%08x.\n"),
		handler,
		dynamic_cast<abs_eap_base_timer_c *>(handler)));

	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	eap_status_e status = handler->cancel_authentication_session();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::cancel_all_authentication_sessions()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_ethernet_core_c::cancel_all_authentication_sessions()\n")));

	eap_status_e status = m_session_map.for_each(cancel_authentication_session, true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::check_bksa_cache(
	eap_array_c<eap_am_network_id_c> * const bssid_sta_receive_network_ids,
	// ****
	// TODO: This needs to be updated for WAPI
	const eapol_key_authentication_type_e selected_eapol_key_authentication_type,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e pairwise_key_cipher_suite,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e group_key_cipher_suite
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

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
			(EAPL("check_pmksa_cache(): checks WAPI-session"),
			 state_selector.get_data(state_selector.get_data_length()),
			 state_selector.get_data_length()));
		
		wapi_core_c *session = m_session_map.get_handler(&state_selector);
		
		if (session == 0
			|| selected_eapol_key_authentication_type == eapol_key_authentication_type_RSNA_PSK
			|| selected_eapol_key_authentication_type == eapol_key_authentication_type_WPA_PSK
			|| session->check_bksa_cache(
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
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::association(
	const eap_am_network_id_c * const receive_network_id,
	// ****
	// TODO: This needs to be updated for WAPI
	const eapol_key_authentication_type_e authentication_type,
	const eap_variable_data_c * const wapi_ie_ae,
	const eap_variable_data_c * const wapi_ie_asue,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_pairwise_cipher,
	const eapol_RSNA_key_header_c::eapol_RSNA_cipher_e eapol_group_cipher,
	const eap_variable_data_c * const /* pre_shared_key_PSK */
	)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: wapi_session_core_c::association().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_session_core_c::association()");

	if (receive_network_id->get_type() != eapol_ethernet_type_wapi)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: wapi_session_core_c::association(): Illegal Ethernet type %d\n"),
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

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("association(): WAPI-session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));


	wapi_core_c *session = m_session_map.get_handler(&state_selector);

	if (session != 0)
	{
		// Reuse the session.
		session->unset_marked_removed();

		if (m_is_client == false)
		{
			// In test version do not reset server.
		}
		else
		{
			status = session->reset();
			if (status != eap_status_ok)
			{
				// We cannot reuse the session.
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_ERROR,
					(EAPL("wapi_session_core_c::association(): session NOT reused.\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	if (session == 0)
	{
		session = new wapi_core_c(
			m_am_tools,
			this,
			m_is_client,
			receive_network_id);
		if (session == 0
			|| session->get_is_valid() == false)
		{
			if (session != 0)
			{
				session->shutdown();
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("WARNING: wapi_session_core_c::association(): Cannot run session->shutdown() 0x%08x\n"),
					session));
			}
			delete session;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = session->configure();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = session->initialize(
			receive_network_id,
			authentication_type,
			wapi_ie_ae,
			wapi_ie_asue,
			eapol_pairwise_cipher,
			eapol_group_cipher);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_session_map.add_handler(&state_selector, session);
		if (status != eap_status_ok)
		{
			if (session != 0)
			{
				session->shutdown();
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("WARNING: wapi_session_core_c::association(): Cannot run session->shutdown() 0x%08x\n"),
					session));
			}
			delete session;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}
	else
	{
		status = session->initialize(
			receive_network_id,
			authentication_type,
			wapi_ie_ae,
			wapi_ie_asue,
			eapol_pairwise_cipher,
			eapol_group_cipher);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


#if 0
#if defined(USE_WAPI_CORE_SERVER)
	if (m_is_client == false)
	{
		status = session->start_authentication();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
#endif //#if defined(USE_WAPI_CORE_SERVER)
#endif
	if (m_is_client == true)
	{
		status = session->allow_authentication();
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
eap_status_e wapi_session_core_c::init_eapol_key_bksa_caching_timeout(
	const eap_am_network_id_c * const send_network_id)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: wapi_session_core_c::init_eapol_key_pmksa_caching_timeout().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_session_core_c::init_eapol_key_bksa_caching_timeout()");

	// Initialize BKSA caching timeout of WAPI-session.
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
		(EAPL("init_eapol_key_bksa_caching_timeout(): WAPI session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));

	wapi_core_c *session = m_session_map.get_handler(&state_selector);

	if (session == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("session not found.\n"),
			 (m_is_client == true) ? "client": "server"));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	eap_status_e status = session->init_bksa_caching_timeout();
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: wapi_session_core_c::init_eapol_key_bksa_caching_timeout(): ")
			 EAPL("session->init_pmksa_caching_timeout(), eap_status_e %d\n"),
			 status));
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::disassociation(
	const eap_am_network_id_c * const receive_network_id
	)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: wapi_session_core_c::disassociation().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_session_core_c::disassociation()");

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

	status = init_eapol_key_bksa_caching_timeout(
		&send_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: wapi_session_core_c::disassociation(): ")
			 EAPL("init_eapol_key_pmksa_caching_timeout(), eap_status_e %d\n"),
			status));
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::create_state(
	const eap_am_network_id_c * const receive_network_id,
	// ****
	// TODO: This needs to be updated for WAPI
	const eapol_key_authentication_type_e authentication_type
	)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: eapol_core_c::create_state().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_session_core_c::create_state()");

	if (receive_network_id->get_type() != eapol_ethernet_type_wapi)
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

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_session_core_c::create_state(): WAPI-session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));


	wapi_core_c *session = m_session_map.get_handler(&state_selector);

	if (session != 0)
	{
		// Reuse the session.
		session->unset_marked_removed();

		if (m_is_client == false)
		{
			// In test version do not reset server.
		}
		else
		{
			status = session->reset();
			if (status != eap_status_ok)
			{
				// We cannot reuse the session.
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_ERROR,
					(EAPL("wapi_session_core_c::create_state(): session NOT reused.\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}


	if (session == 0)
	{
		session = new wapi_core_c(
			m_am_tools,
			this,
			m_is_client,
			receive_network_id);
		if (session == 0
			|| session->get_is_valid() == false)
		{
			if (session != 0)
			{
				session->shutdown();
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("WARNING: wapi_session_core_c::create_state(): Cannot run session->shutdown() 0x%08x\n"),
					session));
			}
			delete session;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = session->initialize(
			receive_network_id,
			authentication_type);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_session_map.add_handler(&state_selector, session);
		if (status != eap_status_ok)
		{
			if (session != 0)
			{
				session->shutdown();
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("WARNING: wapi_session_core_c::create_state(): Cannot run session->shutdown() 0x%08x\n"),
					session));
			}
			delete session;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = session->initialize(
			receive_network_id,
			authentication_type);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = session->configure();
	if (status != eap_status_ok)
	{
		status = remove_wapi_state(
			&send_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: wapi_session_core_c::create_state(): ")
				 EAPL("remove_eapol_key_state(), eap_status_e %d\n"),
				status));
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e wapi_session_core_c::remove_wapi_state(
	const eap_am_network_id_c * const send_network_id)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: wapi_session_core_c::remove_wapi_state().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_session_core_c::remove_wapi_state()");

	// Remove possible WAPI state.
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
		(EAPL("remove_eapol_key_state(): WAPI-session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));

	wapi_core_c * const session = m_session_map.get_handler(&state_selector);

	if (session != 0)
	{
		if (session->get_marked_removed() == false)
		{
			// Do not remove object in use.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: wapi_session_core_c::remove_eapol_key_state(): Cannot removed used object 0x%08x\n"),
				session));
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}

		session->shutdown();
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: wapi_session_core_c::remove_eapol_key_state(): Cannot run session->shutdown() 0x%08x\n"),
			session));
	}

	eap_status_e status = m_session_map.remove_handler(&state_selector, true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: wapi_session_core_c::remove_eapol_key_state(): ")
			 EAPL("session->remove_handler(), eap_status_e %d\n"),
			 status));
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::remove_bksa_from_cache(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("%s: wapi_session_core_c::remove_bksa_from_cache().\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_session_core_c::remove_bksa_from_cache()");

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

	status = remove_wapi_state(
		&send_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: ewapi_session_core_c::remove_bksa_from_cache(): ")
			 EAPL("remove_eapol_key_state(), eap_status_e %d\n"),
			status));
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_session_core_c::read_reassociation_parameters(
	const eap_am_network_id_c * const old_receive_network_id, ///< source includes remote address, destination includes local address.
	const eap_am_network_id_c * const new_receive_network_id, ///< source includes remote address, destination includes local address.
	const eapol_key_authentication_type_e authentication_type,
	eap_variable_data_c * const BKID,
	const eap_variable_data_c * const received_WAPI_ie,
	const eap_variable_data_c * const sent_WAPI_ie)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: wapi_session_core_c::read_reassociation_parameters()\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: wapi_session_core_c::read_reassociation_parameters()");

	eap_status_e status(eap_status_process_general_error);

	// No need to check authentication type anymore. It can be changed in reassociation.

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
		(EAPL("read_reassociation_parameters(): WAPI-session"),
		state_selector.get_data(state_selector.get_data_length()),
		state_selector.get_data_length()));

	wapi_core_c * const session = m_session_map.get_handler(&state_selector);

	if (session != 0)
	{
		status = session->reset_cached_bksa();
		if (status != eap_status_ok)
		{
			// We cannot reuse the session.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_ERROR, 
				(EAPL("wapi_session_core_c::read_reassociation_parameters(): session NOT reused.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// We have state for this connection.
		status = session->read_reassociation_parameters(
			new_receive_network_id, ///< source includes remote address, destination includes local address.
			authentication_type,
			BKID,
			received_WAPI_ie,
			sent_WAPI_ie);
		if (status != eap_status_ok)
		{
			// ERROR, Cannot reassociate.

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: wapi_session_core_c::read_reassociation_parameters(): Cannot reassociate.\n")));
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

// End.
