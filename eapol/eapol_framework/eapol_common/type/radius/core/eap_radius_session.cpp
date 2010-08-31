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
	#define EAP_FILE_NUMBER_ENUM 111 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_radius_session.h"
#include "eap_state_notification.h"
#include "eap_network_id_selector.h"
#include "abs_eap_am_mutex.h"
#include "eap_config.h"
#include "eap_core.h"
#include "eap_buffer.h"
#include "eap_automatic_variable.h"


//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_radius_session_c::~eap_radius_session_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_radius_session_c::~eap_radius_session_c(): this = 0x%08x => 0x%08x.\n"),
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
EAP_FUNC_EXPORT eap_radius_session_c::eap_radius_session_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_radius_session_c * const partner,
	const bool is_client_when_true,
	const eap_radius_variable_data_c * const user_name,
	const eap_radius_variable_data_c * const nas_ip_address)
	: m_partner(partner)
	, m_am_tools(tools)
	, m_eap_core(0)
	, m_master_session_key(tools, eap_type_none)
	, m_request_authenticator(tools)
	, m_shared_secret(tools)
	, m_identifier(0ul)
	, m_user_name(0)
	, m_nas_ip_address(0)
	, m_state(eap_state_none)
	, m_remove_session_timeout(EAP_RADIUS_SESSION_REMOVE_SESSION_TIMEOUT)
	, m_is_client(is_client_when_true)
	, m_is_valid(false)
	, m_shutdown_was_called(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_radius_session_c::eap_radius_session_c(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	if (user_name == 0
		|| nas_ip_address == 0)
	{
		return;
	}

	m_user_name = user_name->copy();
	m_nas_ip_address = nas_ip_address->copy();

	if (m_user_name == 0
		|| m_nas_ip_address == 0)
	{
		return;
	}


	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::save_request_data(
	const void * const data,
	const u32_t data_length,
	const u8_t identifier)
{
	m_identifier = identifier;

	eap_status_e status = m_request_authenticator.set_copy_of_buffer(
		data,
		data_length);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u8_t eap_radius_session_c::get_identifier()
{
	return m_identifier;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT const eap_variable_data_c * eap_radius_session_c::get_shared_secret() const
{
	return &m_shared_secret;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT const eap_variable_data_c * eap_radius_session_c::get_request_authenticator()
{
	return &m_request_authenticator;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT const eap_radius_variable_data_c * eap_radius_session_c::get_user_name()
{
	return m_user_name;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_state_variable_e eap_radius_session_c::get_state()
{
	return m_state;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_variable_data_c * eap_radius_session_c::get_master_session_key()
{
	return &m_master_session_key;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_radius_session_c::object_increase_reference_count()
{
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t eap_radius_session_c::object_decrease_reference_count()
{
	return 0u;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT abs_eap_radius_session_c * eap_radius_session_c::get_partner()
{
	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	return m_partner;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_radius_session_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_radius_session_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::load_module(
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
EAP_FUNC_EXPORT eap_core_c * eap_radius_session_c::create_new_session(
	const eap_am_network_id_c * const receive_network_id)
{
	eap_status_e status = eap_status_process_general_error;

	if (m_eap_core != 0)
	{
		m_eap_core->shutdown();
	}
	delete m_eap_core;
	m_eap_core = 0;

	// Create a new session.
	m_eap_core = new eap_core_c(
		m_am_tools,
		this,
		m_is_client,
		receive_network_id,
		false);

	if (m_eap_core == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return 0;
	}

	if (m_eap_core->get_is_valid() == false)
	{
		m_eap_core->shutdown();
		delete m_eap_core;
		m_eap_core = 0;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return 0;
	}

	status = m_eap_core->configure();
	if (status != eap_status_ok)
	{
		m_eap_core->shutdown();
		delete m_eap_core;
		m_eap_core = 0;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, status);
		return 0;
	}

	return m_eap_core;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::reset()
{
	if (m_eap_core != 0)
	{
		m_eap_core->shutdown();
	}
	delete m_eap_core;
	m_eap_core = 0;

	m_master_session_key.reset();

	m_request_authenticator.reset();

	m_identifier = 0ul;

	m_state = eap_state_none;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::packet_process(
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

	if (m_eap_core != 0
		&& m_eap_core->get_marked_removed() == true)
	{
		if (eap.get_code() == eap_code_request
			|| eap.get_code() == eap_code_response)
		{
			// Only EAP-Request or EAP-Response resets the session.
			// This reset is delayed.
			reset();
		}
	}

	if (m_eap_core == 0)
	{
		// Create a new session.
		m_eap_core = create_new_session(receive_network_id);
	}

	if (m_eap_core != 0)
	{
		status = m_eap_core->packet_process(
			receive_network_id,
			&eap,
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
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::packet_send(
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
		send_network_id,
		sent_packet,
		header_offset,
		data_length,
		buffer_length,
		this);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t eap_radius_session_c::get_header_offset(
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
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);


	{
		eap_configuration_field_c * const field
			=  cf_str_EAP_RADIUS_SERVER_shared_secret.get_field()->copy(
				m_am_tools,
				cf_str_EAP_RADIUS_SERVER_client.get_field(),
				m_nas_ip_address->get_payload_buffer());

		eap_automatic_variable_c<eap_configuration_field_c>
			automatic_field(m_am_tools, field);

		eap_status_e status = read_configure(
			field,
			&m_shared_secret);
		if (status == eap_status_ok
			&& m_shared_secret.get_is_valid_data() == true)
		{
			// OK shared secret is configured.
		}
		else
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: unknown radius client (IP)"), 
				 m_nas_ip_address->get_payload_buffer()->get_data(), 
				 m_nas_ip_address->get_payload_buffer()->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::shutdown_operation(
	eap_core_c * const core,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = core->shutdown();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_radius_session_c::shutdown(): this = 0x%08x => 0x%08x.\n"),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this)));

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	eap_status_e status = m_eap_core->shutdown();
	delete m_eap_core;
	m_eap_core = 0;

	delete m_user_name;
	m_user_name = 0;

	delete m_nas_ip_address;
	m_nas_ip_address = 0;

	m_partner->cancel_timer(this, EAP_RADIUS_SESSION_REMOVE_SESSION_ID);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: EAP_RADIUS_SESSION_REMOVE_SESSION_ID cancelled, %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::unload_module(const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->unload_module(type);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::eap_acknowledge(
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

	if (m_eap_core != 0)
	{
		status = m_eap_core->eap_acknowledge(
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
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::restart_authentication(
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

	if (m_eap_core != 0)
	{
		status = m_eap_core->restart_authentication(send_network_id, is_client_when_true);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::restart_authentication(
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

	if (m_eap_core == 0)
	{
		// Create a new session.
		m_eap_core = create_new_session(receive_network_id);
	}

	if (m_eap_core != 0)
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
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::send_eap_identity_request(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_radius_session_c::send_eap_identity_request()\n")));

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

	if (m_eap_core == 0)
	{
		// Create a new session.
		m_eap_core = create_new_session(receive_network_id);
	}

	if (m_eap_core != 0)
	{
		status = m_eap_core->send_eap_identity_request(receive_network_id);
		(void) EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_SERVER)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::packet_data_crypto_keys(
	const eap_am_network_id_c * const send_network_id,
	const eap_master_session_key_c * const master_session_key
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_master_session_key.set_copy(
		master_session_key);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::read_configure(
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

EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::write_configure(
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
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->eap_radius_session_c::")
		 EAPL("timer_expired(id 0x%02x, data 0x%08x), %s.\n"),
		 this,
		 id,
		 data,
		 (m_is_client == true) ? "client": "server"));

	if (id == EAP_RADIUS_SESSION_REMOVE_SESSION_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: EAP_RADIUS_SESSION_REMOVE_SESSION_ID elapsed, %s.\n"),
			 (m_is_client == true) ? "client": "server"));

		reset();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->eap_radius_session_c::")
		 EAPL("timer_delete_data(id 0x%02x, data 0x%08x).\n"),
		this, id, data));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::remove_eap_session(
	const bool complete_to_lower_layer,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

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

	reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
eap_status_e eap_radius_session_c::asynchronous_init_remove_eap_session(
	const eap_am_network_id_c * const send_network_id)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_radius_session_c::asynchronous_init_remove_eap_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

		eap_network_id_selector_c state_selector(
			m_am_tools,
			send_network_id);
		if (state_selector.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_status_e status = asynchronous_init_remove_eap_session(
			&state_selector);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eap_radius_session_c::asynchronous_init_remove_eap_session(
	const eap_network_id_selector_c * const state_selector)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_radius_session_c::asynchronous_init_remove_eap_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	// NOTE: we cannot call directly remove_eap_session(), because we will
	// return from here to removed object.

	eap_status_e status = eap_status_process_general_error;

	if (m_eap_core != 0)
	{
		m_eap_core->set_marked_removed();

		status = m_partner->set_timer(
			this,
			EAP_RADIUS_SESSION_REMOVE_SESSION_ID, 
			0,
			m_remove_session_timeout);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_radius_session_c::asynchronous_init_remove_eap_session()")
			 EAPL(": %s: EAP_RADIUS_SESSION_REMOVE_SESSION_ID timer set.\n"),
			 (m_is_client == true) ? "client": "server"));
	}
	else
	{
		// Not found, cannot remove.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: eap_radius_session_c::asynchronous_init_remove_eap_session()")
			 EAPL(": %s: failed session not found.\n"),
			 (m_is_client == true) ? "client": "server"));

		status = eap_status_ok;
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_radius_session_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	if (state->get_protocol_layer() == eap_protocol_layer_eap)
	{
		if (m_state == eap_state_authentication_terminated_unsuccessfully)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: session already failed.\n")));
			return;
		}

		m_state = static_cast<eap_state_variable_e>(state->get_current_state());

		if (state->get_current_state() == eap_state_identity_response_received)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("EAP-Response/Identity received:\n")));
		}
		else if (state->get_current_state() == eap_state_identity_request_received)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("EAP-Request/Identity received:\n")));
		}
		else if (state->get_current_state() == eap_state_authentication_terminated_unsuccessfully)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("radius_server_c::state_notification(): ")
				 EAPL("Protocol layer %d, EAP type 0x%02x, State transition from ")
				 EAPL("%d=%s to %d=%s, client %d when shutdown was called.\n"),
				 state->get_protocol_layer(), 
				 state->get_protocol(), 
				 state->get_previous_state(), 
				 state->get_previous_state_string(), 
				 state->get_current_state(), 
				 state->get_current_state_string(),
				 state->get_is_client()));
		}
		else if (state->get_current_state() == eap_state_authentication_finished_successfully)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("radius_server_c::state_notification(): ")
				 EAPL("Protocol layer %d, EAP type 0x%02x, State transition from ")
				 EAPL("%d=%s to %d=%s, client %d when shutdown was called.\n"),
				 state->get_protocol_layer(), 
				 state->get_protocol(), 
				 state->get_previous_state(), 
				 state->get_previous_state_string(), 
				 state->get_current_state(), 
				 state->get_current_state_string(),
				 state->get_is_client()));
		}
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::set_timer(
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
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::cancel_timer(
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
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->cancel_all_timers();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::check_is_valid_eap_type(
	const eap_type_value_e eap_type)
{
	eap_status_e status = m_partner->check_is_valid_eap_type(eap_type);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	eap_status_e status = m_partner->get_eap_type_list(eap_type_list);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = m_partner->add_rogue_ap(rogue_ap_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_radius_session_c::set_session_timeout(
	const u32_t /* session_timeout_ms */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------



// End.
