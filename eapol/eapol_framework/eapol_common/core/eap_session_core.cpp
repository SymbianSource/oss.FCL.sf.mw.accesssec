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
* %version: 37 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 731 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_session_core.h"
#include "eap_state_notification.h"
#include "eap_network_id_selector.h"
#include "abs_eap_am_mutex.h"
#include "eap_config.h"
#include "eap_core.h"
#include "eap_buffer.h"
#include "eap_base_type.h"
#include "eap_automatic_variable.h"


//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_session_core_c::~eap_session_core_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_session_core_c::~eap_session_core_c(): this = 0x%08x => 0x%08x.\n"),
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
EAP_FUNC_EXPORT eap_session_core_c::eap_session_core_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_session_core_c * const partner,
	const bool is_client_when_true)
: m_partner(partner)
, m_am_tools(tools)
, m_session_map(tools, this)
, m_remove_session_timeout(EAP_SESSION_CORE_REMOVE_SESSION_TIMEOUT)
, m_is_client(is_client_when_true)
, m_is_valid(false)
, m_use_eap_session_core_reset_session(true)
, m_shutdown_was_called(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_session_core_c::eap_session_core_c(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT abs_eap_session_core_c * eap_session_core_c::get_partner()
{
	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	return m_partner;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_session_core_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_session_core_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_session_core_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_session_core_c::reset(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	eap_status_e status = m_session_map.for_each(shutdown_operation, true);
	(void)EAP_STATUS_RETURN(m_am_tools, status);

	status = m_session_map.reset();
	(void)EAP_STATUS_RETURN(m_am_tools, status);

	m_partner->cancel_timer(this, EAP_SESSION_CORE_REMOVE_SESSION_ID);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: EAP_SESSION_CORE_REMOVE_SESSION_ID cancelled, %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::load_module(
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
EAP_FUNC_EXPORT eap_core_c * eap_session_core_c::create_new_session(
	const eap_am_network_id_c * const receive_network_id)
{
	eap_status_e status = eap_status_process_general_error;

	// Create a new session.
	eap_core_c *session = new eap_core_c(
		m_am_tools,
		this,
		m_is_client,
		receive_network_id,
		false);

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
		(EAPL("eap_session_core_c::create_new_session() EAP-session"),
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
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::reset_or_remove_session(
	eap_core_c ** const session,
	const eap_network_id_selector_c * const selector,
	const bool reset_immediately)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_session_core_c::reset_or_remove_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_session_core_c::reset_or_remove_session()");

	eap_status_e status(eap_status_process_general_error);

	if (session == 0
		|| *session == 0
		|| selector == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	if (m_use_eap_session_core_reset_session == true)
	{
		// This will reuse session.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_session_core_c::reset_or_remove_session(): resets session, session 0x%08x.\n"),
			(*session)));

		// NOTE, this delayed reset of session is used bacause the device is so slow it cannot respond to
		// 4-Way Handshake message fast enough.

		if (reset_immediately == true)
		{
			(*session)->unset_marked_removed();

			status = (*session)->reset();
		}
		else
		{
			// This will delay reset to eap_core_c::packet_process().
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
			(EAPL("eap_session_core_c::reset_or_remove_session(): shutdown session, session 0x%08x.\n"),
			(*session)));

		(*session)->shutdown();
		(*session) = 0;

		status = m_session_map.remove_handler(selector, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: eap_session_core_c::reset_or_remove_session(): m_session_map.remove_type(), eap_status_e %d\n"),
				status));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_session_core_c::reset_or_remove_session(): session NOT reused.\n")));
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_session_core_c::reset_or_remove_session(): session reused, session 0x%08x.\n"),
			(*session)));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::packet_process(
	const eap_am_network_id_c * const receive_network_id,
	eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	// Each EAP authentication session includes own eap_core_c object.
	// EAP authentication sessions are separated by eap_am_network_id_c object.

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

	eap_header_wr_c eap(
		m_am_tools,
		packet_data->get_header_buffer(packet_data->get_header_buffer_length()),
		packet_data->get_header_buffer_length());

	if (eap.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (packet_length < eap.get_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (eap.get_code() == eap_code_none)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("-> EAP_session: %s, code=0x%02x=%s, identifier=0x%02x, ")
		 EAPL("length=0x%04x, type=0x%08x=%s, packet length 0x%04x\n"),
		(m_is_client == true) ? "client": "server",
		eap.get_code(),
		eap.get_code_string(),
		eap.get_identifier(),
		eap.get_length(),
		convert_eap_type_to_u32_t(eap.get_type()),
		eap.get_type_string(),
		packet_length));

	status = eap.check_header();
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
		(EAPL("eap_session_core_c::packet_process() EAP-session"),
		 selector.get_data(selector.get_data_length()),
		 selector.get_data_length()));

	eap_core_c *session = m_session_map.get_handler(&selector);

	if (session == 0)
	{
		// Create a new session.
		session = create_new_session(receive_network_id);
	}

	if (session != 0)
	{
		status = session->packet_process(
			receive_network_id,
			&eap,
			packet_length);

		EAP_GENERAL_HEADER_COPY_ERROR_PARAMETERS(packet_data, &eap);
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
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::packet_send(
	const eap_am_network_id_c * const send_network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_header_wr_c eap(
		m_am_tools,
		sent_packet->get_data_offset(header_offset, data_length),
		data_length);

	if (eap.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_send: packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_ASSERT(header_offset < sent_packet->get_data_length());
	EAP_ASSERT(data_length <= sent_packet->get_data_length());
	EAP_ASSERT(sent_packet->get_data_length() <= buffer_length);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("<- EAP_session: %s, code=0x%02x=%s, identifier=0x%02x, ")
		 EAPL("length=0x%04x, type=0x%08x=%s, packet length 0x%04x\n"),
		(m_is_client == true) ? "client": "server",
		eap.get_code(),
		eap.get_code_string(),
		eap.get_identifier(),
		eap.get_length(),
		convert_eap_type_to_u32_t(eap.get_type()),
		eap.get_type_string(),
		data_length));

	eap_status_e status = m_partner->packet_send(
		send_network_id, sent_packet, header_offset, data_length, buffer_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t eap_session_core_c::get_header_offset(
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
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::configure()
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
					m_use_eap_session_core_reset_session = true;
				}
				else
				{
					m_use_eap_session_core_reset_session = false;
				}
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::shutdown_operation(
	eap_core_c * const core,
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
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_session_core_c::shutdown(): this = 0x%08x => 0x%08x.\n"),
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
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::unload_module(const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->unload_module(type);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::eap_acknowledge(
	const eap_am_network_id_c * const receive_network_id)
{
	// Any Network Protocol packet is accepted as a success indication.
	// This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	if (receive_network_id == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
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
		(EAPL("eap_session_core_c::eap_acknowledge() EAP-session"),
		 selector.get_data(selector.get_data_length()),
		 selector.get_data_length()));

	eap_core_c *session = m_session_map.get_handler(&selector);

	if (session != 0)
	{
		status = session->eap_acknowledge(
			receive_network_id);
	}
	else
	{
		// Here we do not care of missing session.
		// Acknowledge is meaningfull only for existing session.
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::restart_authentication(
	const eap_am_network_id_c * const send_network_id,
	const bool is_client_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

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
		(EAPL("eap_session_core_c::restart_authentication() EAP-session"),
		 selector.get_data(selector.get_data_length()),
		 selector.get_data_length()));

	eap_core_c *session = m_session_map.get_handler(&selector);

	if (session != 0)
	{
		status = session->restart_authentication(send_network_id, is_client_when_true);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::restart_authentication(
	const eap_am_network_id_c * const receive_network_id,
	const bool /* is_client_when_true */,
	const bool force_clean_restart,
	const bool /* from_timer */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

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
		(EAPL("eap_session_core_c::restart_authentication() EAP-session"),
		 selector.get_data(selector.get_data_length()),
		 selector.get_data_length()));

	eap_core_c *session = m_session_map.get_handler(&selector);

	if (session == 0)
	{
		// Create a new session.
		session = create_new_session(receive_network_id);
	}

	if (session != 0)
	{
		status = m_partner->restart_authentication(
			receive_network_id,
			m_is_client,
			force_clean_restart);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_CORE_SERVER)

//
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::send_eap_identity_request(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_session_core_c::send_eap_identity_request()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_session_core_c::send_eap_identity_request()");

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
		(EAPL("eap_session_core_c::send_eap_identity_request() EAP-session"),
		 selector.get_data(selector.get_data_length()),
		 selector.get_data_length()));

	eap_core_c *session = m_session_map.get_handler(&selector);

	if (session == 0)
	{
		// Create a new session.
		session = create_new_session(receive_network_id);
	}

	if (session != 0)
	{
		status = session->send_eap_identity_request(receive_network_id);
		(void)EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_SERVER)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_session_core_c::packet_data_crypto_keys(
	const eap_am_network_id_c * const send_network_id,
	const eap_master_session_key_c * const master_session_key
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->packet_data_crypto_keys(
		send_network_id,
		master_session_key);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_session_core_c::read_configure(
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

EAP_FUNC_EXPORT eap_status_e eap_session_core_c::write_configure(
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
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->eap_session_core_c::")
		 EAPL("timer_expired(id 0x%02x, data 0x%08x), %s.\n"),
		 this,
		 id,
		 data,
		 (m_is_client == true) ? "client": "server"));

	if (id == EAP_SESSION_CORE_REMOVE_SESSION_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: EAP_SESSION_CORE_REMOVE_SESSION_ID elapsed, %s.\n"),
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
			(EAPL("eap_session_core_c::timer_expired() EAP-session"),
			 selector->get_data(selector->get_data_length()),
			 selector->get_data_length()));

		eap_core_c *session = m_session_map.get_handler(selector);

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
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->eap_session_core_c::")
		 EAPL("timer_delete_data(id 0x%02x, data 0x%08x).\n"),
		this, id, data));

	if (id == EAP_SESSION_CORE_REMOVE_SESSION_ID)

	{
		const eap_network_id_selector_c * const selector 
			= reinterpret_cast<const eap_network_id_selector_c *>(data);
		delete selector;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_session_core_c::cancel_all_eap_sessions()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_session_core_c::cancel_all_eap_sessions(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	eap_status_e status = reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_session_core_c::create_eap_session(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_session_core_c::create_eap_session(): this = 0x%08x => 0x%08x.\n"),
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
		(EAPL("eap_session_core_c::create_eap_session() EAP-session"),
		 selector.get_data(selector.get_data_length()),
		 selector.get_data_length()));

	eap_core_c *session = m_session_map.get_handler(&selector);

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

EAP_FUNC_EXPORT eap_status_e eap_session_core_c::remove_eap_session(
	const bool /* complete_to_lower_layer */,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_session_core_c::remove_eap_session(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eap_session_core_c::remove_eap_session()");

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
		(EAPL("eap_session_core_c::remove_eap_session() EAP-session"),
		 selector.get_data(selector.get_data_length()),
		 selector.get_data_length()));

	eap_core_c *session = m_session_map.get_handler(&selector);

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
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_session_core_c::remove_eap_session(): session not found.\n")));

		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eap_session_core_c::asynchronous_init_remove_eap_session(
	const eap_am_network_id_c * const send_network_id)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_session_core_c::asynchronous_init_remove_eap_session(): %s.\n"),
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
		(EAPL("eap_session_core_c::asynchronous_init_remove_eap_session() EAP-session"),
		 state_selector.get_data(state_selector.get_data_length()),
		 state_selector.get_data_length()));

	eap_status_e status = asynchronous_init_remove_eap_session(
		&state_selector);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::asynchronous_init_remove_eap_session(
	const eap_network_id_selector_c * const state_selector)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_session_core_c::asynchronous_init_remove_eap_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	// NOTE: we cannot call directly remove_eap_session(), because we will
	// return from here to removed object.

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_session_core_c::asynchronous_init_remove_eap_session() EAP-session"),
		 state_selector->get_data(state_selector->get_data_length()),
		 state_selector->get_data_length()));

	eap_core_c *session = m_session_map.get_handler(state_selector);

	if (session != 0)
	{
		session->set_marked_removed();

		// So we initiate a timer to remove session identified by state_selector.
		eap_network_id_selector_c * const copy_selector = state_selector->copy();
		if (copy_selector == 0
			|| copy_selector->get_is_valid() == false)
		{
			delete copy_selector;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = m_partner->set_timer(
			this,
			EAP_SESSION_CORE_REMOVE_SESSION_ID, 
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
			(EAPL("eap_session_core_c::asynchronous_init_remove_eap_session()")
			 EAPL(": %s: EAP_SESSION_CORE_REMOVE_SESSION_ID timer set %d ms.\n"),
			 (m_is_client == true) ? "client": "server",
			 m_remove_session_timeout));
	}
	else
	{
		// Not found, cannot remove.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: eap_session_core_c::asynchronous_init_remove_eap_session()")
			 EAPL(": %s: failed session not found.\n"),
			 (m_is_client == true) ? "client": "server"));

		status = eap_status_ok;
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_session_core_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_session_core_c::state_notification(), %s.\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_session_core_c::state_notification()");

	m_partner->state_notification(state);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::set_timer(
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
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::cancel_timer(
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

EAP_FUNC_EXPORT eap_status_e eap_session_core_c::check_is_valid_eap_type(
	const eap_type_value_e eap_type)
{
	eap_status_e status = m_partner->check_is_valid_eap_type(eap_type);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_session_core_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	eap_status_e status = m_partner->get_eap_type_list(eap_type_list);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_session_core_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = m_partner->add_rogue_ap(rogue_ap_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_session_core_c::set_session_timeout(
	const u32_t /* session_timeout_ms */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_session_core_c::set_eap_database_reference_values(
	const eap_variable_data_c * const /* reference */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_session_core_c::get_802_11_authentication_mode(
	const eap_am_network_id_c * const /* receive_network_id */,
	const eapol_key_authentication_type_e /* authentication_type */,
	const eap_variable_data_c * const /* SSID */,
	const eap_variable_data_c * const /* preshared_key */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------
// End.
