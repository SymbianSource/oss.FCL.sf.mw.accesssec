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
* %version: 58.1.15 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 44 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_core.h"
#include "eap_core_nak_info.h"
#include "eap_state_notification.h"
#include "eap_network_id_selector.h"
#include "eap_buffer.h"
#include "eap_header_string.h"
#include "eap_automatic_variable.h"


/**
 * This is the character that separates routing realms.
 */
const u8_t EAP_NAI_ROUTING_REALM_SEPARATOR[] = "!";

/**
 * This is the at character of NAI.
 */
const u8_t EAP_NAI_AT_CHARACTER[] = "@";


//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_core_c::~eap_core_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::~eap_core_c(): %s, %s, this = 0x%08x => 0x%08x.\n"),
		(m_is_client == true) ? "client": "server",
		(m_is_tunneled_eap == true) ? "tunneled": "outer most",
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
EAP_FUNC_EXPORT eap_core_c::eap_core_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_core_c * const partner,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id,
	const bool is_tunneled_eap)
	: m_partner(partner)
	, m_am_tools(tools)
	, m_type_map(tools, this)
	, m_current_eap_type(eap_type_none)
	, m_default_eap_type(eap_type_none)
	, m_eap_identity(tools)
	, m_eap_header_offset(0u)
	, m_MTU(0u)
	, m_trailer_length(0u)
	, m_receive_network_id(tools)
	, m_retransmission(0)
	, m_retransmission_time(EAP_CORE_RETRANSMISSION_TIME)
	, m_retransmission_counter(EAP_CORE_RETRANSMISSION_COUNTER)
	, m_session_timeout(EAP_CORE_SESSION_TIMEOUT)
	, m_eap_core_failure_received_timeout(EAP_CORE_FAILURE_RECEIVED_TIMEOUT)
	, m_remove_session_timeout(EAP_CORE_REMOVE_SESSION_TIMEOUT)
#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)
	, m_wait_eap_request_type_timeout(EAP_CORE_WAIT_EAP_REQUEST_TYPE_TIMEOUT)
	, m_wait_eap_request_type_timeout_set(false)
#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)
	, m_eap_identity_request_identifier_client(0)
	, m_is_client(is_client_when_true)
	, m_is_client_role(is_client_when_true)
	, m_is_valid(false)
	, m_client_restart_authentication_initiated(false)
	, m_marked_removed(false)
	, m_eap_identity_response_accepted(false)
	, m_shutdown_was_called(false)
	, m_eap_type_response_sent(false)
	, m_is_tunneled_eap(is_tunneled_eap)
#if defined(USE_EAP_CORE_SERVER)
	, m_process_eap_nak_immediately(EAP_CORE_PROCESS_EAP_NAK_IMMEDIATELY)
	, m_nak_process_timer_active(false)
	, m_eap_identity_request_send(false)
	, m_eap_identity_response_received(false)
	, m_eap_failure_sent(false)
	, m_send_eap_success_after_notification(false)
#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)
	, m_skip_eap_request_identity(false)
#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)
#endif //#if defined(USE_EAP_CORE_SERVER)
	, m_use_eap_expanded_type(false)
	, m_ignore_eap_failure(false)
	, m_ignore_notifications(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::eap_core_c(): %s, %s, this = 0x%08x => 0x%08x, compiled %s %s.\n"),
		(m_is_client == true) ? "client": "server",
		(m_is_tunneled_eap == true) ? "tunneled": "outer most",
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this),
		__DATE__,
		__TIME__));

	eap_status_e status = m_receive_network_id.set_copy_of_network_id(receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT abs_eap_core_c * eap_core_c::get_partner()
{
	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	return m_partner;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_core_c::set_partner(abs_eap_core_c * const partner)
{
	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	m_partner = partner;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_core_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_core_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_core_c::object_increase_reference_count()
{
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t eap_core_c::object_decrease_reference_count()
{
	return 0u;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_core_c::get_marked_removed()
{
	return m_marked_removed;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_core_c::set_marked_removed()
{
	m_marked_removed = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_core_c::unset_marked_removed()
{
	m_marked_removed = false;
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_core_c::ignore_notifications()
{
	m_ignore_notifications = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::initialize_asynchronous_init_remove_eap_session(
	const u32_t remove_session_timeout)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::initialize_asynchronous_init_remove_eap_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	eap_status_e status = eap_status_process_general_error;


	if (m_is_client_role == false)
	{
		// Server stops re-transmissions.
		// Client can re-transmit until session is removed.
		cancel_retransmission();
	}

	cancel_eap_failure_timeout();

	cancel_session_timeout();

#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)
	if (m_is_tunneled_eap == false
		&& m_is_client_role == true)
	{
		cancel_wait_eap_request_type_timeout();
	}
#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

	set_marked_removed();


	if (remove_session_timeout == 0ul)
	{
		status = asynchronous_init_remove_eap_session();
	}
	else
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		cancel_asynchronous_init_remove_eap_session();

		status = m_partner->set_timer(
			this,
			EAP_CORE_REMOVE_SESSION_TIMEOUT_ID,
			0,
			remove_session_timeout);

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_REMOVE_SESSION_TIMEOUT_ID set %d ms, this = 0x%08x.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
			 remove_session_timeout,
			 this));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_c::cancel_asynchronous_init_remove_eap_session()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_partner != 0)
	{
		eap_status_e status = m_partner->cancel_timer(
			this,
			EAP_CORE_REMOVE_SESSION_TIMEOUT_ID);

		EAP_UNREFERENCED_PARAMETER(status); // in release
		
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_REMOVE_SESSION_TIMEOUT_ID cancelled status %d, this = 0x%08x.\n"),
			 (m_is_client == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
			 status,
			 this));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::asynchronous_init_remove_eap_session()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::asynchronous_init_remove_eap_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

		eap_am_network_id_c send_network_id(
			m_am_tools,
			m_receive_network_id.get_destination_id(),
			m_receive_network_id.get_source_id(),
			m_receive_network_id.get_type());

		eap_status_e status = m_partner->asynchronous_init_remove_eap_session(
			&send_network_id);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eap_core_c::init_end_of_session(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::init_end_of_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	eap_status_e status(eap_status_process_general_error);

	// Normally we will remove session after authentication ends.
	// Remove session only if the stack is not already being deleted
	if (m_shutdown_was_called == false)
	{
		#if defined(USE_EAP_CORE_SIMULATOR_VERSION)

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_core_c::init_end_of_session(): %s, %s, Ignored notification: ")
				 EAPL("Protocol layer %d, EAP-type 0x%02x, State transition from ")
				 EAPL("%d=%s to %d=%s, client %d.\n"),
				 (m_is_client == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
				 state->get_protocol_layer(), 
				 state->get_protocol(), 
				 state->get_previous_state(), 
				 state->get_previous_state_string(), 
				 state->get_current_state(), 
				 state->get_current_state_string(),
				 state->get_is_client()));

		#endif //#if defined(USE_EAP_CORE_SIMULATOR_VERSION)

		status = initialize_asynchronous_init_remove_eap_session(m_remove_session_timeout);
		if (status != eap_status_ok)
		{
			EAP_UNREFERENCED_PARAMETER(state);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_core_c::init_end_of_session(): %s, %s, Ignored notification: ")
			 EAPL("Protocol layer %d, EAP-type 0x%02x, State transition from ")
			 EAPL("%d=%s to %d=%s, client %d when shutdown was called.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
			 state->get_protocol_layer(), 
			 state->get_protocol(), 
			 state->get_previous_state(), 
			 state->get_previous_state_string(), 
			 state->get_current_state(), 
			 state->get_current_state_string(),
			 state->get_is_client()));

		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_core_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_string_c status_string;
	EAP_UNREFERENCED_PARAMETER(status_string); // in release

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::state_notification(), %s, %s, protocol_layer %d=%s, protocol %d=%s, EAP-type 0xfe%06x%08x=%s.\n"),
		(m_is_client == true) ? "client": "server",
		(m_is_tunneled_eap == true) ? "tunneled": "outer most",
		state->get_protocol_layer(),
		state->get_protocol_layer_string(),
		state->get_protocol(),
		state->get_protocol_string(),
		state->get_eap_type().get_vendor_id(),
		state->get_eap_type().get_vendor_type(),
		eap_header_string_c::get_eap_type_string(state->get_eap_type())));

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::state_notification(), %s, %s, current_state %d=%s, error %d=%s.\n"),
		(m_is_client == true) ? "client": "server",
		(m_is_tunneled_eap == true) ? "tunneled": "outer most",
		state->get_current_state(),
		state->get_current_state_string(),
		state->get_authentication_error(),
		status_string.get_status_string(state->get_authentication_error())));

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::state_notification(), %s, %s, m_eap_identity_request_send=%d, m_eap_identity_response_received=%d.\n"),
		(m_is_client == true) ? "client": "server",
		(m_is_tunneled_eap == true) ? "tunneled": "outer most",
		m_eap_identity_request_send,
		m_eap_identity_response_received));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_core_c::state_notification()");

	if (m_ignore_notifications == true
		|| m_partner == 0)
	{
		return;
	}

	// Check if the notification is from the current active type
	if (state->get_protocol_layer() == eap_protocol_layer_general)
	{
		 // These notications are allowed always.
	}
	else if (state->get_protocol_layer() == eap_protocol_layer_eap
		&& state->get_eap_type() != m_current_eap_type
		&& m_is_client == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_core_c::state_notification(): %s, %s, Ignored notification: ")
			 EAPL("Protocol layer %d, non-active EAP-type 0x%02x, current EAP type 0x%08x, State transition from ")
			 EAPL("%d=%s to %d=%s, client %d\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
			state->get_protocol_layer(),
			state->get_protocol(),
			convert_eap_type_to_u32_t(m_current_eap_type),
			state->get_previous_state(),
			state->get_previous_state_string(),
			state->get_current_state(),
			state->get_current_state_string(),
			state->get_is_client()));
		return;
	}

	if (state->get_protocol_layer() == eap_protocol_layer_eap)
	{
		if (state->get_current_state() == eap_state_identity_response_received)
		{
			m_eap_identity_response_accepted = true;

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("EAP-Response/Identity received: %s, %s\n"),
				 (m_is_client == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
				 ));
		}
		else if (state->get_current_state() == eap_state_identity_request_received)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("EAP-Request/Identity received: %s, %s\n"),
				 (m_is_client == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
				 ));
		}
		else if (state->get_current_state() == eap_state_authentication_terminated_unsuccessfully)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: eap_core_c::state_notification(): %s, %s: EAP-authentication terminated unsuccessfully.\n"),
				 (m_is_client == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
				 ));

#if defined(USE_EAP_CORE_SERVER)
			if (m_is_client == false
				&& (m_eap_type_response_sent == true
					|| m_eap_identity_response_received == true)
				&& m_send_eap_success_after_notification == false)
			{
				/**
				 * 2003-10-01 draft-ietf-eap-rfc2284bis-06.txt chapter 2.
				 * Extensible Authentication Protocol (EAP):
				 * The authenticator MUST NOT send a Success or Failure packet when retransmitting
				 * or when it fails to get a response from the peer.
				 * In the case eap_state_authentication_terminated_unsuccessfully we will need a flag
				 * that indicates whether there was a response from client or not.
				 * If there was a response server must send EAP-Failure.
				 * If there was NO response from client server
				 * does NOT send EAP-Failure.
				 */
				send_eap_failure(
					state->get_send_network_id(),
					state->get_eap_identifier());
			}
#endif //#if defined(USE_EAP_CORE_SERVER)

			(void) init_end_of_session(state);
		}
		else if (state->get_current_state() == eap_state_authentication_finished_successfully)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_core_c::state_notification(): %s, %s: EAP-authentication finished successfully.\n"),
				 (m_is_client == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
				 ));


#if defined(USE_EAP_CORE_SERVER)
			if (m_is_client == false
				&& m_eap_type_response_sent == true
				&& m_send_eap_success_after_notification == false)
			{
				// Here we test whether the EAP-type allow send EAP-Success.
				// For example PEAP v1 does not allow send EAP-Success.
				if (state->get_allow_send_eap_success() == true)
				{
					send_eap_success(
						state->get_send_network_id(),
						state->get_eap_identifier());
				}

				// Now we can send a new EAP-Request/Identity.
				m_eap_identity_request_send = false;
			}
#endif //#if defined(USE_EAP_CORE_SERVER)

			(void) init_end_of_session(state);
		}
		else if (m_is_client == true
			&& state->get_current_state() == eap_state_use_eap_failure_in_termination)
		{
			// Client should accept EAP-Failure quietly.
			m_ignore_eap_failure = true;

			(void) init_end_of_session(state);
		}
#if defined(USE_EAP_CORE_SERVER)
		else if (m_is_client == false
			&& state->get_current_state() == eap_state_use_eap_failure_in_termination)
		{
			send_eap_failure(
				state->get_send_network_id(),
				state->get_eap_identifier());

			(void) init_end_of_session(state);
		}
		else if (m_current_eap_type == eap_type_peap
			&& state->get_current_state() == eap_state_authentication_wait_tppd_peapv1_empty_acknowledge)
		{
			send_eap_success(
				state->get_send_network_id(),
				state->get_eap_identifier());

			return;
		}
#endif //#if defined(USE_EAP_CORE_SERVER)
	}


	m_partner->state_notification(state);


#if defined(USE_EAP_CORE_SERVER)
	// EAP-Success is send after the success notification is forwarded to lower layer.
	// This allows to combine success notification and sent EAP-success packet.
	if (state->get_current_state() == eap_state_authentication_finished_successfully)
	{
		if (m_is_client == false
			&& m_eap_type_response_sent == true
			&& m_send_eap_success_after_notification == true)
		{
			// Here we test whether the EAP-type allow send EAP-Success.
			// For example PEAP v1 does not allow send EAP-Success.
			if (state->get_allow_send_eap_success() == true)
			{
				send_eap_success(
					state->get_send_network_id(),
					state->get_eap_identifier());
			}
			
			// Now we can send a new EAP-Request/Identity.
			m_eap_identity_request_send = false;
		}
	}
	else if (state->get_current_state() == eap_state_authentication_terminated_unsuccessfully)
	{
		if (m_is_client == false
			&& (m_eap_type_response_sent == true
				|| m_eap_identity_response_received == true)
			&& m_send_eap_success_after_notification == true)
		{
			/**
			 * 2003-10-01 draft-ietf-eap-rfc2284bis-06.txt chapter 2.
			 * Extensible Authentication Protocol (EAP):
			 * The authenticator MUST NOT send a Success or Failure packet when retransmitting
			 * or when it fails to get a response from the peer.
			 * In the case eap_state_authentication_terminated_unsuccessfully we will need a flag
			 * that indicates whether there was a response from client or not.
			 * If there was a response server must send EAP-Failure.
			 * If there was NO response from client server
			 * does NOT send EAP-Failure.
			 */
			send_eap_failure(
				state->get_send_network_id(),
				state->get_eap_identifier());
		}
	}
#endif //#if defined(USE_EAP_CORE_SERVER)


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_base_type_c * eap_core_c::load_type(
	const eap_type_value_e type,
	const eap_type_value_e tunneling_type,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_base_type_c *handler = 0;

	eap_status_e status = m_partner->load_module(
		type,
		tunneling_type,
		this,
		&handler,
		m_is_client,
		receive_network_id);
	if (status != eap_status_ok)
	{
		if (handler != 0)
		{
			handler->shutdown();
			delete handler;
		}
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return 0;
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return handler;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_c::check_is_valid_eap_type(const eap_type_value_e eap_type)
{
	eap_status_e status = m_partner->check_is_valid_eap_type(eap_type);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	eap_status_e status = m_partner->get_eap_type_list(eap_type_list);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::initialize_session_timeout(const u32_t session_timeout_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	cancel_session_timeout();

	eap_status_e status = m_partner->set_timer(
		this,
		EAP_CORE_SESSION_TIMEOUT_ID,
		0,
		session_timeout_ms);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s: %s, EAP_CORE_SESSION_TIMEOUT_ID set %d ms, this = 0x%08x.\n"),
		 (m_is_client == true) ? "client": "server",
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
		 session_timeout_ms,
		 this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_c::cancel_session_timeout()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	if (m_am_tools != 0)
	{
		status = m_partner->cancel_timer(
			this,
			EAP_CORE_SESSION_TIMEOUT_ID);
	}
	
	EAP_UNREFERENCED_PARAMETER(status); // in release
	
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s: %s, EAP_CORE_SESSION_TIMEOUT_ID cancelled status %d, this = 0x%08x.\n"),
		 (m_is_client == true ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
		 status,
		 this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_core_c::trace_eap_packet(
	eap_const_string prefix,
	const eap_header_wr_c * const eap_header)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Get rid of warnings in release version
	EAP_UNREFERENCED_PARAMETER(eap_header);
	EAP_UNREFERENCED_PARAMETER(prefix);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
		(EAPL("%s EAP_Core: %s, %s, code=0x%02x=%s, identifier=0x%02x, length=0x%04x, type=0x%08x=%s, packet length 0x%04x\n"),
		prefix,
		(m_is_client == true) ? "client": "server",
		(m_is_tunneled_eap == true) ? "tunneled": "outer most",
		eap_header->get_code(),
		eap_header->get_code_string(),
		eap_header->get_identifier(),
		eap_header->get_length(),
		convert_eap_type_to_u32_t(eap_header->get_type()),
		eap_header->get_type_string(),
		eap_header->get_length()));
}


//--------------------------------------------------

#if defined(USE_EAP_CORE_SERVER)

EAP_FUNC_EXPORT eap_status_e eap_core_c::restart_with_new_type(
	const eap_type_value_e used_eap_type,
	const eap_am_network_id_c * const receive_network_id,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::restart_with_new_type(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_core_c::restart_with_new_type()");

	// Here we need to re-create the received EAP-Response/Identity message.

	if (m_eap_identity.get_is_valid_data() == false)
	{
		// No saved EAP-Identity. Cannot continue.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
	}

	eap_status_e status = eap_status_process_general_error;

	eap_buf_chain_wr_c response_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_CORE_PACKET_BUFFER_LENGTH);

	if (response_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet buffer corrupted: %s, %s\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = create_eap_identity_response(
		&response_packet,
		&m_eap_identity,
		eap_identifier);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	eap_header_wr_c eap(
		m_am_tools,
		response_packet.get_data_offset(m_eap_header_offset, response_packet.get_data_length()),
		response_packet.get_data_length());
	if (eap.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	// Bacause we start with a new EAP-type EAP-Response/Identity is prosessed again.
	m_eap_identity_response_accepted = false;

	m_ignore_eap_failure = false;

	status = packet_process_type(
		used_eap_type,
		receive_network_id,
		&eap,
		eap.get_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_SERVER)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_c::client_proposes_eap_types(
	const eap_am_network_id_c * const receive_network_id,
	const u8_t eap_identifier)
{
	eap_array_c<eap_type_value_e> eap_type_list(m_am_tools);

	/**
	 * @{ 2005-04-19 complete Expanded Nak Type to client_proposes_eap_types(). }
	 */
	eap_status_e status = get_eap_type_list(&eap_type_list);
	if (status != eap_status_ok)
	{
		eap_type_list.reset();

		eap_type_value_e * default_eap_type = new eap_type_value_e(m_default_eap_type);
		if (default_eap_type == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_type_list.add_object(default_eap_type, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = send_eap_nak_response(
		receive_network_id,
		eap_identifier,
		&eap_type_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_c::packet_process_type(
	const eap_type_value_e used_eap_type,
	const eap_am_network_id_c * const receive_network_id,
	eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::packet_process_type(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_core_c::packet_process_type()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (packet_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_illegal_packet_error);
	}

	if (packet_length < eap_header_base_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
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
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	if (eap.get_code() == eap_code_none)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_code);
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_TEST_VECTORS, 
		(EAPL("--------------------------------------------------------\n")));

	eap_status_e status = eap.check_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}



	status = eap_status_process_general_error;

	if (m_eap_type_response_sent == false
		&& m_current_eap_type != used_eap_type)
	{
		status = check_is_valid_eap_type(used_eap_type);
		if (status != eap_status_ok)
		{
			if (m_is_client_role == true)
			{
				// Client does not accept proposed EAP type.
				// We must send EAP-Response/Nak message with list of our own preferred EAP-Types.
				status = client_proposes_eap_types(
					receive_network_id,
					eap.get_identifier());

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			} 
			else 
			{
				// Not acceptable EAP-type in the server.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// Now the current EAP-type is used_eap_type.

		// First remove current EAP-type.
		eap_variable_data_c selector(m_am_tools);
		status = selector.set_copy_of_buffer(&m_current_eap_type, sizeof(m_current_eap_type));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		eap_base_type_c *handler = m_type_map.get_handler(&selector);

		// Change the current EAP-type here because shutdown could cause state notifications from old EAP-type.
		m_current_eap_type = used_eap_type;

		if (handler != 0)
		{
			status = handler->shutdown();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_type_map.remove_handler(&selector, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	// Here we query the desired EAP-type.
	eap_variable_data_c selector(m_am_tools);
	u64_t selector_eap_type = convert_eap_type_to_u64_t(used_eap_type);
	status = selector.set_buffer(&selector_eap_type, sizeof(selector_eap_type), false, false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	eap_base_type_c *handler = m_type_map.get_handler(&selector);
	
	// Check if we already have this type loaded.
	if (handler == 0)
	{
		// No. Load it.
		if (m_eap_type_response_sent == false
			&& eap.get_type() != eap_type_identity
			&& (eap.get_code() == eap_code_request
				|| eap.get_code() == eap_code_response))
		{
			// Here we need a check that proposed EAP type is valid for us.
			status = check_is_valid_eap_type(used_eap_type);
			if (status != eap_status_ok)
			{
				if (m_is_client_role == true)
				{
					// Client does not accept proposed EAP type.
					// We must send EAP-Response/Nak message with list of our own preferred EAP-Types.
					status = client_proposes_eap_types(
						receive_network_id,
						eap.get_identifier());

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				} 
				else 
				{
					// Not acceptable EAP-type in the server.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			// Change the current eap type.
			m_current_eap_type = used_eap_type;
		}
		else if (eap.get_code() == eap_code_success
				|| eap.get_code() == eap_code_failure)
		{
			// EAP-Success or EAP-Failure is not allowed at this state.
			// This packet is dropped quietly.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: eap_core_c::packet_process_type(): %s, %s, drops %s quietly.\n"),
				 (m_is_client_role == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
				 eap.get_code_string()
				 ));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
		else if (m_eap_type_response_sent == false
			&& eap.get_type() == eap_type_identity
			&& (eap.get_code() == eap_code_request
				|| eap.get_code() == eap_code_response))
		{
			// EAP-Request/Identity is allowed at this state.
			EAP_ASSERT(used_eap_type != eap_type_none);
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_code);
		}

		// A new EAP-type is needed. The load_type() allocates new object.
		handler = load_type(
			used_eap_type,
			eap_type_none,
			receive_network_id);
		if (handler != 0
			&& handler->get_is_valid() == true)
		{
			status = handler->configure();
			if (status != eap_status_ok)
			{
				handler->shutdown();
				delete handler;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_type_map.add_handler(&selector, handler);
			if (status != eap_status_ok)
			{
				handler->shutdown();
				delete handler;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			if (handler != 0)
			{
				// Handler not constructed successfully.
				handler->shutdown();
				delete handler;
				status = eap_status_allocation_error;
			}
			else
			{
				status = eap_status_type_does_not_exists_error;
			}

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	} 

#if defined(USE_EAP_CORE_SERVER)
	// We now have handler. Process packet
	if (m_nak_process_timer_active == true)
	{
		m_partner->cancel_timer(
			this,
			EAP_CORE_DELAYED_EAP_NAK_PROCESS_ID);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_DELAYED_EAP_NAK_PROCESS_ID cancelled, this = 0x%08x.\n"),
			 (m_is_client_role == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
			 this));

		m_nak_process_timer_active = false;
	}
#endif //#if defined(USE_EAP_CORE_SERVER)


	if (m_is_client_role == true
		&& eap.get_code() == eap_code_request
		&& (eap.get_type() == eap_type_identity
			|| eap.get_type() == eap_type_notification))
	{
		// Client handles this packet, which is EAP-Request/Identity or EAP-Request/Notification.

		if (eap.get_type() == eap_type_identity)
		{
			status = handle_eap_identity_request(
				used_eap_type,
				eap.get_identifier(),
				receive_network_id);
		}
		else if (eap.get_type() == eap_type_notification)
		{
			// Here we swap the addresses.
			eap_am_network_id_c send_network_id(m_am_tools,
				receive_network_id->get_destination_id(),
				receive_network_id->get_source_id(),
				receive_network_id->get_type());

			/**
			 * @{ 2003-10-02 draft-ietf-eap-rfc2284bis-06.txt chapter 5.2 Notification:
			 * The peer SHOULD display this message to the user or log it if it
			 * cannot be displayed.  The Notification Type is intended to provide
			 * an acknowledged notification of some imperative nature, but it is
			 * not an error indication, and therefore does not change the state
			 * of the peer.  Examples include a password with an expiration time
			 * that is about to expire, an OTP sequence integer which is nearing
			 * 0, an authentication failure warning, etc.  In most circumstances,
			 * Notification should not be required.
			 * }
			 */
			status = send_eap_notification_response(
				&send_network_id,
				eap.get_identifier());
		}
	}
#if defined(USE_EAP_CORE_SERVER)
	else if (m_is_client_role == false
		&& eap.get_code() == eap_code_response
		&& eap.get_type() == eap_type_identity)
	{
		// Server handles this EAP-Response/Identity packet.

		if (m_eap_identity_response_accepted == false)
		{
			m_eap_identity_response_received = true;

			status = handle_eap_identity_response(
				handler,
				used_eap_type,
				receive_network_id,
				&eap,
				packet_length);

			EAP_GENERAL_HEADER_COPY_ERROR_PARAMETERS(packet_data, &eap);
		}
		else
		{
			// Do not accept multiple EAP-Response/Identity messages.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: EAP_Core: %s,%s, packet dropped quietly. m_eap_type_response_sent %d, ")
				 EAPL("EAP-Type 0x%08x, m_current_eap_type 0x%08x\n"),
				 (m_is_client_role == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
				 m_eap_type_response_sent,
				 convert_eap_type_to_u32_t(eap.get_type()),
				 convert_eap_type_to_u32_t(m_current_eap_type)));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}
	}
#endif //#if defined(USE_EAP_CORE_SERVER)
	else if (((eap.get_code() == eap_code_request
				|| eap.get_code() == eap_code_response)
			  && eap.get_type() == used_eap_type)
		|| eap.get_code() == eap_code_success
		|| eap.get_code() == eap_code_failure)
	{
		// Client and server handles this packet.
		// Packet is EAP-Request, EAP-Response, EAP-Success or EAP-Failure.
		// EAP-Request and EAP-Response must be of the used EAP-type.

		if (m_is_client_role == false)
		{
			// Server received EAP-Response from client.
			// Now server could send EAP-Failure or EAP-success to client.
			// See draft-ietf-eap-rfc2284bis-06.txt chapter 2. Extensible Authentication Protocol (EAP).
			if (m_eap_type_response_sent == false)
			{
				// Here we swap the addresses.
				eap_am_network_id_c send_network_id(m_am_tools,
					receive_network_id->get_destination_id(),
					receive_network_id->get_source_id(),
					receive_network_id->get_type());

				// Send state change notification
				eap_state_notification_c notification(
					m_am_tools,
					&send_network_id,
					m_is_client,
					eap_state_notification_eap,
					eap_protocol_layer_eap,
					m_current_eap_type,
					eap_state_none,
					eap_state_eap_response_sent,
					eap.get_identifier(),
					false);
				state_notification(&notification);
			}
			m_eap_type_response_sent = true;
		}
#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)
		else
		{
			if (eap.get_code() == eap_code_request
				&& m_is_tunneled_eap == false
				&& m_is_client_role == true)
			{
				// We got the response. Now we let the session timer handle rest of timeout cases.
				cancel_wait_eap_request_type_timeout();
			}
		}
#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

		if (m_ignore_eap_failure == false
			&& eap.get_code() == eap_code_failure)
		{
			// Set timer to delay EAP-Failure handling.
			// If no other packet is received session will be
			// terminated after timeout.
			set_eap_failure_timeout();
		}
		else
		{
			cancel_eap_failure_timeout();
		}

		status = handler->packet_process(
			receive_network_id,
			&eap,
			packet_length);

		EAP_GENERAL_HEADER_COPY_ERROR_PARAMETERS(packet_data, &eap);

		if (status == eap_status_success)
		{
			// NOTE state_notification() will send EAP-Success message.
		}
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: %s, %s, Illegal EAP-Code %d=0x%02x=%s, EAP-Type 0x%08x=%s\n"),
			 (m_is_client_role == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
			 eap.get_code(),
			 eap.get_code(),
			 eap.get_code_string(),
			 convert_eap_type_to_u32_t(eap.get_type()),
			 eap.get_type_string()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_code);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * @{ 2003-10-01 draft-ietf-eap-rfc2284bis-06.txt chapter 2.1 Support for sequences:
 * An EAP conversation MAY utilize a sequence of methods.  A common
 * example of this is an Identity request followed by a single EAP
 * authentication method such as an MD5-Challenge.  However the peer and
 * authenticator MUST utilize only one authentication method (Type 4 or
 * greater) within an EAP conversation, after which the authenticator
 * MUST send a Success or Failure packet.
 * Once a peer has sent a Response of the same Type as the initial
 * Request, an authenticator MUST NOT send a Request of a different Type
 * prior to completion of the final round of a given method (with the
 * exception of a Notification-Request) and MUST NOT send a Request for
 * an additional method of any Type after completion of the initial
 * authentication method; a peer receiving such Requests MUST treat them
 * as invalid, and silently discard them. As a result, Identity Requery
 * is not supported.
 * A peer MUST NOT send a Nak (legacy or expanded) in reply to a
 * Request, after an initial non-Nak Response has been sent.  Since
 * spoofed EAP Request packets may be sent by an attacker, an
 * authenticator receiving an unexpected Nak SHOULD discard it and log
 * the event.
 * Multiple authentication methods within an EAP conversation are not
 * supported due to their vulnerability to man-in-the-middle attacks
 * (see Section 7.4) and incompatibility with existing implementations.
 * }
 */
EAP_FUNC_EXPORT eap_status_e eap_core_c::packet_process(
	const eap_am_network_id_c * const receive_network_id,
	eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::packet_process(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_core_c::packet_process()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (packet_data == 0
		|| packet_data->get_is_valid() == false)
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

	if (packet_length < eap_header_base_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
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
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	if (eap.get_code() == eap_code_none)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_code);
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_TEST_VECTORS, 
		(EAPL("--------------------------------------------------------\n")));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA|TRACE_TEST_VECTORS, 
		(EAPL("EAP-packet"),
		 eap.get_header_buffer(packet_length),
		 packet_length));

	trace_eap_packet("->", &eap);

	eap_status_e status = eap.check_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


#if defined (_DEBUG)
	if (m_retransmission != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAP_Core: eap_core_c::packet_process(): %s, retransmission counter %d, retrans EAP-type %s, retrans EAP-Id %d, current EAP-type %s, current EAP-Id %d, session 0x%08x.\n"),
			 (m_is_client_role == true) ? "client": "server",
			 m_retransmission->get_retransmission_counter(),
			 eap_header_string_c::get_eap_type_string(m_retransmission->get_eap_type()),
			 m_retransmission->get_eap_identifier(),
			 eap_header_string_c::get_eap_type_string(eap.get_type()),
			 eap.get_identifier(),
			 this));
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAP_Core: eap_core_c::packet_process(): %s, retransmission NULL, session 0x%08x.\n"),
			 (m_is_client_role == true) ? "client": "server",
			 this));
	}
#endif //#if defined (_DEBUG)


	if (m_is_client_role == true
		&& m_retransmission != 0
		&& m_retransmission->get_eap_type() == eap.get_type()
		&& m_retransmission->get_eap_identifier() == eap.get_identifier())
	{
		if (m_retransmission->get_retransmission_counter() > 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("EAP_Core: eap_core_c::packet_process(): %s, retransmits previous packet, counter %d, session 0x%08x.\n"),
				 (m_is_client_role == true) ? "client": "server",
				 m_retransmission->get_retransmission_counter(),
				 this));

			// We have the previous send EAP-packet stored.
			// It does match to the current query.
			// We could send the previous EAP-packet again.
			status = resend_packet(
				m_retransmission->get_send_network_id(),
				m_retransmission->get_sent_packet(),
				m_retransmission->get_header_offset(),
				m_retransmission->get_data_length(),
				m_retransmission->get_buffer_size(),
				m_retransmission->get_retransmission_counter()
				);

			m_retransmission->get_next_retransmission_counter(); // This decrements the counter.
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("EAP_Core: eap_core_c::packet_process(): %s, Does not retransmit previous packet, counter %d, session 0x%08x.\n"),
				 (m_is_client_role == true) ? "client": "server",
				 m_retransmission->get_retransmission_counter(),
				 this));

			status = eap_status_unexpected_message;
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
#if defined(USE_EAP_CORE_SERVER)
	else if (m_is_client_role == false
		&& m_retransmission != 0
		&& m_retransmission->get_eap_type() == eap.get_type()
		&& m_retransmission->get_eap_identifier() > eap.get_identifier())
	{
		// Here we assume the EAP-Identifier increases. This is for testing purposes.
		// This packet is old response, drop it.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("EAP_Core: eap_core_c::packet_process(): %s, Does not process old packet, EAP-Identifier of last received response %d, EAP-Identifier of the packet %d, session 0x%08x.\n"),
			 (m_is_client_role == true) ? "client": "server",
			 m_retransmission->get_eap_identifier(),
			 eap.get_identifier(),
			 this));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	}
#endif //#if defined(USE_EAP_CORE_SERVER)
	else if (get_marked_removed() == true
			 && eap.get_code() != eap_code_success
			 && eap.get_code() != eap_code_failure)
	{
		// NOTE, this delayed reset of session is used bacause in some cases cannot be responsed
		// 4-Way Handshake message fast enough.

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_core_c::packet_process(): %s, resets session, session 0x%08x.\n"),
			 (m_is_client_role == true) ? "client": "server",
			this));

		unset_marked_removed();

		reset();
	}


	eap_type_value_e used_eap_type = eap_type_none;

	if (eap.get_code() == eap_code_request
		&& m_is_client_role == true)
	{
		// Send ID using default EAP type, this is our best quess of other peer's EAP type.
		// Other peer will sent the real EAP type later and we can NAK it then
		// and send our own EAP type.
		if (m_current_eap_type == eap_type_none)
		{
			// In Symbian implementation the default type is the highest priority EAP type. 
			// At the moment it is always used to reply to the identity request.
			m_current_eap_type = m_default_eap_type;
			used_eap_type = m_current_eap_type;
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		if (eap.get_length() > eap_header_base_c::get_header_length())
		{
			if (m_eap_type_response_sent == true
				&& eap.get_type() != m_current_eap_type)
			{
				if (eap.get_type() == eap_type_tlv_extensions)
				{
					// Send EAP-Response/Nak to show this is not supported.

					eap_array_c<eap_type_value_e> eap_type_list(m_am_tools);

					status = send_eap_nak_response(
						receive_network_id,
						eap.get_identifier(),
						&eap_type_list);

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else
				{
					/*
					 * 2003-10-01 draft-ietf-eap-rfc2284bis-06.txt chapter 2.1 Support for sequences:
					 * An EAP conversation MAY utilize a sequence of methods.  A common
					 * example of this is an Identity request followed by a single EAP
					 * authentication method such as an MD5-Challenge.  However the peer and
					 * authenticator MUST utilize only one authentication method (Type 4 or
					 * greater) within an EAP conversation, after which the authenticator
					 * MUST send a Success or Failure packet.
					 * Once a peer has sent a Response of the same Type as the initial
					 * Request, an authenticator MUST NOT send a Request of a different Type
					 * prior to completion of the final round of a given method (with the
					 * exception of a Notification-Request) and MUST NOT send a Request for
					 * an additional method of any Type after completion of the initial
					 * authentication method; a peer receiving such Requests MUST treat them
					 * as invalid, and silently discard them. As a result, Identity Requery
					 * is not supported.
					 */
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("WARNING: EAP_Core: %s, %s, packet dropped quietly. m_eap_type_response_sent %d, ")
						 EAPL("EAP-Type 0x%08x, m_current_eap_type 0x%08x\n"),
						 (m_is_client_role == true) ? "client": "server",
						 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
						 m_eap_type_response_sent,
						 convert_eap_type_to_u32_t(eap.get_type()),
						 convert_eap_type_to_u32_t(m_current_eap_type)));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
				}
			}
			else if (eap.get_type() == eap_type_identity)
			{
				// Should we respond here with another type?
				/**
				 * @{ Check if this is a re-transmission or a new request.
				 * If this is re-transmission respond using the same type as previously. 
				 * Otherwise assume that peer did not like our previous identity and 
				 * try another configured type.
				 * At the moment just try the last type that was used.
				 * }
				 */
				used_eap_type = m_current_eap_type;
			}
			else if (eap.get_type() == eap_type_notification)
			{
				// Here we are again on thin ice.
				// Best ques is the las used EAP type.
				used_eap_type = m_current_eap_type;
			}
			else
			{
				// Here we know what the server really wants
				// use this EAP-Type.
				used_eap_type = eap.get_type();
			}
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_code);
		}
	}
#if defined(USE_EAP_CORE_SERVER)
	else if (eap.get_code() == eap_code_response
		&& m_is_client_role == false)
	{
		// Received ID using some EAP type, this may be other than our current type.

		if (m_current_eap_type == eap_type_none)
		{
			m_current_eap_type = m_default_eap_type;
			used_eap_type = m_default_eap_type;
		}
		else if (eap.get_length() > eap_header_base_c::get_header_length())
		{
			if (eap.get_type() == eap_type_identity)
			{
				used_eap_type = m_default_eap_type;
			}
			else
			{
				used_eap_type = eap.get_type();

				if (used_eap_type == eap_type_nak
					|| eap_expanded_type_nak.get_type() == used_eap_type
					)
				{
					// Server received EAP-Response from client.
					// Now server could send EAP-Failure or EAP-success to client.
					// See draft-ietf-eap-rfc2284bis-06.txt chapter 2. Extensible Authentication Protocol (EAP).

					/**
					 * @{ 2003-10-02 draft-ietf-eap-rfc2284bis-06.txt chapter 5.3.1 Legacy Nak:
					 * The legacy Nak Type is valid only in Response messages.  It is
					 * sent in reply to a Request where the desired authentication Type
					 * is unacceptable.  Authentication Types are numbered 4 and above.
					 * The Response contains one or more authentication Types desired by
					 * the Peer.  Type zero (0) is used to indicate that the sender has
					 * no viable alternatives, and therefore the authenticator SHOULD NOT
					 * send another Request after receiving a Nak Response containing a
					 * zero value.
					 * Since the legacy Nak Type is valid only in Responses and has very
					 * limited functionality, it MUST NOT be used as a general purpose
					 * error indication, such as for communication of error messages, or
					 * negotiation of parameters specific to a particular EAP method.
					 * }
					 */

					/**
					 * @{ 2003-10-02 draft-ietf-eap-rfc2284bis-06.txt chapter 5.3.2 Expanded Nak:
					 * The Expanded Nak Type is valid only in Response messages.  It MUST
					 * be sent only in reply to a Request of Type 254 (Expanded Type)
					 * where the authentication Type is unacceptable.  The Expanded Nak
					 * Type uses the Expanded Type format itself, and the Response
					 * contains one or more authentication Types desired by the peer, all
					 * in Expanded Type format.  Type zero (0) is used to indicate that
					 * the sender has no viable alternatives.  The general format of the
					 * Expanded Type is described in Section 5.7.
					 * Since the Expanded Nak Type is valid only in Responses and has
					 * very limited functionality, it MUST NOT be used as a general
					 * purpose error indication, such as for communication of error
					 * messages, or negotiation of parameters specific to a particular
					 * EAP method.
					 * }
					 */

					// Only server should receive this packet.
					if (eap.get_type_data_length() >= sizeof(u8_t))
					{
						// EAP-Response/Nak includes list of new proposal for EAP type.
						// Now we need to know does the proposed EAP type need separate identity.
						// In that case we must restart the authentication.
						// If the same identity is valid, we could continue.

						u32_t proposal_length = eap.get_type_data_length();
						for (u32_t ind = 0ul; ind < proposal_length; ind++)
						{
							/**
							 * @{ 2005-04-19 complete Expanded Nak Type to packet_process(). }
							 */
							status = eap_expanded_type_c::read_type(
								m_am_tools,
								ind,
								eap.get_type_data(eap.get_type_data_length()),
								eap.get_type_data_length(),
								&used_eap_type);
							if (status != eap_status_ok)
							{
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}

							// Here we need a check that proposed EAP type is valid for us.
							status = check_is_valid_eap_type(used_eap_type);
							if (status == eap_status_ok)
							{
								// Let's use this EAP-type.
								break;
							}
							else
							{
								used_eap_type = eap_type_none;
							}
						} // for()

						if (used_eap_type == eap_type_none)
						{
							EAP_TRACE_DEBUG(
								m_am_tools,
								TRACE_FLAGS_DEFAULT,
								(EAPL("TIMER: %s: %s, EAP-Reponse/Nak did not include any valid EAp-type.\n"),
								 (m_is_client_role == true ? "client": "server"),
								 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
								 ));
						}

						// Here we swap the addresses.
						eap_am_network_id_c send_network_id(m_am_tools,
							receive_network_id->get_destination_id(),
							receive_network_id->get_source_id(),
							receive_network_id->get_type());

						if (m_process_eap_nak_immediately == true)
						{
							if (used_eap_type == eap_type_none)
							{
								// No acceptable EAP-type.
								// Send a EAP-Failure.
								status = send_eap_failure(
									&send_network_id,
									static_cast<u8_t>(eap.get_identifier()+1ul));

								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_type);
							}
							else
							{
								// First remove current EAP-type.
								eap_variable_data_c selector(m_am_tools);
								status = selector.set_copy_of_buffer(
									&m_current_eap_type,
									sizeof(m_current_eap_type));
								if (status != eap_status_ok)
								{
									EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
									return EAP_STATUS_RETURN(m_am_tools, status);
								}
								eap_base_type_c *handler = m_type_map.get_handler(&selector);

								// Change the current EAP-type here because shutdown could
								// cause state notifications from old EAP-type.
								m_current_eap_type = used_eap_type;

								if (handler != 0)
								{
									status = handler->shutdown();
									if (status != eap_status_ok)
									{
										EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
										return EAP_STATUS_RETURN(m_am_tools, status);
									}

									status = m_type_map.remove_handler(&selector, true);
									if (status != eap_status_ok)
									{
										EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
										return EAP_STATUS_RETURN(m_am_tools, status);
									}
								}

								// Now restart authentication with proposed EAP type.
								status = restart_with_new_type(
									used_eap_type,
									receive_network_id,
									eap.get_identifier());

								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}
						}
						else //if (m_process_eap_nak_immediately == false)
						{
							status = eap_status_illegal_eap_type;

							if (m_nak_process_timer_active == false)
							{
								eap_core_nak_info_c * const nak_info
									= new eap_core_nak_info_c(
										m_am_tools,
										receive_network_id,
										used_eap_type,
										eap.get_identifier());

								status = m_partner->set_timer(
									this,
									EAP_CORE_DELAYED_EAP_NAK_PROCESS_ID, 
									nak_info,
									EAP_CORE_DELAYED_EAP_NAK_PROCESS_TIMEOUT);
								if (status == eap_status_ok)
								{
									m_nak_process_timer_active = true;
								}
								else
								{
									// ERROR.
									// NOTE: timer queue did call timer_delete_data() function to free nak_info.
								}

								EAP_TRACE_DEBUG(
									m_am_tools,
									TRACE_FLAGS_DEFAULT,
									(EAPL("TIMER: %s: %s, EAP_CORE_DELAYED_EAP_NAK_PROCESS_ID set %d ms.\n"),
									 (m_is_client_role == true ? "client": "server"),
									 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
									 EAP_CORE_DELAYED_EAP_NAK_PROCESS_TIMEOUT
									 ));
							}
						}

						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);						

					} // if (eap.get_type_data_length() >= sizeof(u8_t))
					else
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_type);
					}
				}
			}
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_code);
		}
	}
#endif //#if defined(USE_EAP_CORE_SERVER)
	else if (eap.get_code() == eap_code_success
		|| eap.get_code() == eap_code_failure)
	{
		if (m_current_eap_type != eap_type_none)
		{
			// Here we are again on thin ice.
			// Use saved EAP type, this is our best quess of other peer's EAP type.
			// Other peer just informs status of authentication.
			used_eap_type = m_current_eap_type;
		}
		else
		{
			// No EAP-type loaded, drop message quietly.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("WARNING: EAP_Core: %s,%s, %s packet dropped quietly. m_eap_type_response_sent %d, ")
				 EAPL("m_current_eap_type 0x%08x\n"),
				 (m_is_client_role == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
				 eap.get_code_string(),
				 m_eap_type_response_sent,
				 convert_eap_type_to_u32_t(m_current_eap_type)));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_code);
	}


	status = packet_process_type(
		used_eap_type,
		receive_network_id,
		packet_data,
		packet_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::packet_send(
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
		sent_packet->get_data_offset(
			header_offset, data_length),
		data_length);

	if (eap.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_send: %s, %s, packet buffer corrupted.\n"),
			 (m_is_client_role == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_ASSERT(header_offset < sent_packet->get_data_length());
	EAP_ASSERT(data_length <= sent_packet->get_data_length());
	EAP_ASSERT(sent_packet->get_data_length() <= buffer_length);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		EAP_TRACE_FLAGS_MESSAGE_DATA|TRACE_TEST_VECTORS, 
		(EAPL("EAP-packet"),
		 eap.get_header_buffer(data_length),
		 data_length));

	trace_eap_packet("<-", &eap);

	if (m_shutdown_was_called == true
		&& m_is_client_role == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: EAP_Core: %s,%s, eap_core_c::packet_send(): %s packet dropped quietly because shutdown was already called. m_eap_type_response_sent %d, ")
			 EAPL("m_current_eap_type 0x%08x\n"),
			 (m_is_client_role == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
			 eap.get_code_string(),
			 m_eap_type_response_sent,
			 convert_eap_type_to_u32_t(m_current_eap_type)));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_TEST_VECTORS, 
		(EAPL("--------------------------------------------------------\n")));


	cancel_retransmission();

	if (sent_packet->get_do_packet_retransmission() == true)
	{
		// Both EAP-client and EAP-server initializes re-transmission.
		// EAP-client will respond to re-transmitted EAP-request with the matching packet.
		// EAP-server will re-transmit the packet when timer elapses and no response is received.
		// Note the EAP-type could do re-transmission itself too. When EAP-type do re-transmission
		// itself EAP-type should set flag of re-transmission in the packet to true with the
		// set_do_packet_retransmission(true) function.
		init_retransmission(
			send_network_id,
			sent_packet,
			header_offset,
			data_length,
			eap.get_code(),
			eap.get_identifier(),
			eap.get_type());
	}


	eap_status_e status = m_partner->packet_send(
		send_network_id, sent_packet, header_offset, data_length, buffer_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_is_client_role == true
		&& eap.get_type() == m_current_eap_type
		&& m_current_eap_type != eap_type_none)
	{
		/*
		 * Once a peer has sent a Response of the same Type as the initial
		 * Request, an authenticator MUST NOT send a Request of a different Type
		 * prior to completion of the final round of a given method (with the
		 * exception of a Notification-Request) and MUST NOT send a Request for
		 * an additional method of any Type after completion of the initial
		 * authentication method; a peer receiving such Requests MUST treat them
		 * as invalid, and silently discard them. As a result, Identity Requery
		 * is not supported.
		 */
		if (m_eap_type_response_sent == false)
		{
			// Send state change notification
			eap_state_notification_c notification(
				m_am_tools,
				send_network_id,
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_eap,
				m_current_eap_type,
				eap_state_none,
				eap_state_eap_response_sent,
				eap.get_identifier(),
				false);
			state_notification(&notification);
		}
		m_eap_type_response_sent = true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_c::resend_packet(
	const eap_am_network_id_c * const send_network_id,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length,
	const u32_t retransmission_counter)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(retransmission_counter); // Only trace uses this.

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("<- EAP_Core: %s: %s, eap_core_c::resend_packet(), counter %d.\n"),
		 (m_is_client_role == true) ? "client": "server",
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
		 retransmission_counter
		 ));

	// We make a copy because random error test may corrupt the data.
	eap_buf_chain_wr_c * const copy_packet = sent_packet->copy();

	if (copy_packet == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT(m_eap_header_offset < sent_packet->get_data_length());
	EAP_ASSERT(data_length <= sent_packet->get_data_length());
	EAP_ASSERT(sent_packet->get_data_length() <= buffer_length);

	// NOTE: send packet directly to partner object.
	// This will skip initialization of re-transmission tfor re-transmitted packet.
	eap_status_e status = m_partner->packet_send(
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

EAP_FUNC_EXPORT eap_status_e eap_core_c::cancel_retransmission()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	//if (m_retransmission != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_TIMER_RETRANSMISSION_ID cancelled.\n"),
			 (m_is_client_role == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));

		if (m_is_client_role == false
			&& m_partner != 0)
		{
			// Only EAP-server uses timer to re-transmits EAP-packets.
			m_partner->cancel_timer(this, EAP_CORE_TIMER_RETRANSMISSION_ID);
		}

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

EAP_FUNC_EXPORT eap_status_e eap_core_c::init_retransmission(
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

	if (m_is_client_role == false)
	{
		if (m_retransmission_time == 0u
			|| m_retransmission_counter == 0u)
		{
			// No retransmission.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
	}

	EAP_ASSERT(send_network_id->get_source() != 0);
	EAP_ASSERT(send_network_id->get_destination() != 0);

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

	if (m_is_client_role == false)
	{
		// Only EAP-server uses timer to re-transmits EAP-packets.
		m_partner->cancel_timer(this, EAP_CORE_TIMER_RETRANSMISSION_ID);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_TIMER_RETRANSMISSION_ID cancelled.\n"),
			 (m_is_client_role == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
	}

	if (m_retransmission == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_retransmission->get_is_valid() == true)
	{
		// Because this object do re-transmission other layers must not do re-transmission of this packet.
		sent_packet->set_do_packet_retransmission(false);

		if (m_is_client_role == false)
		{
			// Only EAP-server uses timer to re-transmits EAP-packets.
			u32_t next_retransmission_time = m_retransmission->get_next_retransmission_time();

			eap_status_e status = m_partner->set_timer(this, EAP_CORE_TIMER_RETRANSMISSION_ID, 0,
				next_retransmission_time);
			if (status != eap_status_ok)
			{
				delete m_retransmission;
				m_retransmission = 0;
			}

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("TIMER: %s: %s, EAP_CORE_TIMER_RETRANSMISSION_ID set %d ms.\n"),
				 (m_is_client_role == true ? "client": "server"),
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
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

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::set_eap_failure_timeout()
{
	eap_status_e status = m_partner->set_timer(
		this,
		EAP_CORE_FAILURE_RECEIVED_ID,
		0,
		m_eap_core_failure_received_timeout);
	if (status != eap_status_ok)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: TIMER: %s: %s, EAP_CORE_FAILURE_RECEIVED_ID failed.\n"),
			 (m_is_client_role == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_FAILURE_RECEIVED_ID set %d ms.\n"),
			 (m_is_client_role == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
			 m_eap_core_failure_received_timeout
			 ));
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::cancel_eap_failure_timeout()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s: %s, EAP_CORE_FAILURE_RECEIVED_ID cancelled.\n"),
		 (m_is_client_role == true ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
		 ));

	eap_status_e status(eap_status_ok);

	if (m_am_tools != 0)
	{
		status = m_partner->cancel_timer(
			this,
			EAP_CORE_FAILURE_RECEIVED_ID);
	}
	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

//
eap_status_e eap_core_c::set_wait_eap_request_type_timeout()
{
	EAP_ASSERT_TOOLS(m_am_tools, (m_wait_eap_request_type_timeout_set == false));

	eap_status_e status = m_partner->set_timer(
		this,
		EAP_CORE_WAIT_EAP_REQUEST_TYPE_ID,
		0,
		m_wait_eap_request_type_timeout);
	if (status != eap_status_ok)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: TIMER: %s: %s, EAP_CORE_WAIT_EAP_REQUEST_TYPE_ID failed.\n"),
			 (m_is_client_role == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_WAIT_EAP_REQUEST_TYPE_ID set %d ms.\n"),
			 (m_is_client_role == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
			 m_wait_eap_request_type_timeout
			 ));

		m_wait_eap_request_type_timeout_set = true;
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

//--------------------------------------------------

#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

//
eap_status_e eap_core_c::cancel_wait_eap_request_type_timeout()
{
	if (m_wait_eap_request_type_timeout_set == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_WAIT_EAP_REQUEST_TYPE_ID cancelled.\n"),
			 (m_is_client_role == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));

		m_wait_eap_request_type_timeout_set = false;

		eap_status_e status(eap_status_ok);

		if (m_am_tools != 0)
		{
			m_partner->cancel_timer(
				this,
				EAP_CORE_WAIT_EAP_REQUEST_TYPE_ID);
		}

		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
}

#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t eap_core_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const u32_t offset = m_partner->get_header_offset(MTU, trailer_length);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_core_c::get_header_offset(): offset=%d, MTU=%d, trailer_length=%d\n"),
		offset,
		*MTU,
		*trailer_length));

	return offset;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::load_module(
	const eap_type_value_e type,
	const eap_type_value_e tunneling_type,
	abs_eap_base_type_c * const partner,
	eap_base_type_c ** const handler,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->load_module(
		type,
		tunneling_type,
		partner,
		handler,
		is_client_when_true,
		receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

#if !defined(USE_EAP_DEBUG_TRACE)
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::configure(): %s: %s.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most"));
#else
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::configure(): %s: %s, this = 0x%08x => 0x%08x.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
#endif

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_core_c::configure()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		eap_variable_data_c data(m_am_tools);

		status = m_partner->read_configure(
			cf_str_EAP_default_type_hex_data.get_field(),
			&data);
		if (status == eap_status_illegal_configure_type)
		{
			status = m_partner->read_configure(
				cf_str_EAP_default_type_u32_t.get_field(),
				&data);
		}

#if defined(USE_EAP_CORE_SERVER)
		if (m_is_client == false)
		{
			// This option is only applicable in server.

			eap_variable_data_c server_data(m_am_tools);

			eap_status_e server_status = m_partner->read_configure(
				cf_str_EAP_server_default_type_hex_data.get_field(),
				&server_data);
			if (server_status == eap_status_illegal_configure_type)
			{
				server_status = m_partner->read_configure(
					cf_str_EAP_server_default_type_u32_t.get_field(),
					&server_data);
			}

			if (server_status == eap_status_ok
				&& server_data.get_is_valid_data() == true)
			{
				status = data.set_copy_of_buffer(&server_data);
			}
		}
#endif //#if defined(USE_EAP_CORE_SERVER)

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			m_default_eap_type
				= *(reinterpret_cast<eap_type_ietf_values_e *>(
						data.get_data(data.get_data_length())));
		}
		else if (data.get_data_length() == eap_expanded_type_c::get_eap_expanded_type_size()
			&& data.get_data(data.get_data_length()) != 0)
		{
			eap_expanded_type_c eap_type(eap_type_none);

			status = eap_type.set_expanded_type_data(
				m_am_tools,
				&data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = eap_type.get_type_data(
				m_am_tools,
				&m_default_eap_type);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: %s: %s, No EAP-type configured, %s.\n"),
				 (m_is_client == true ? "client": "server"),
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
				 cf_str_EAP_default_type_hex_data.get_field()->get_field()));
			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_TEST_VECTORS)

	{
		eap_variable_data_c data(m_am_tools);

		status = m_partner->read_configure(
			cf_str_EAP_TRACE_only_trace_messages.get_field(),
			&data);
		if (status == eap_status_ok
			&& data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			if (*(reinterpret_cast<u32_t *>(data.get_data(data.get_data_length()))) != 0u)
			{
				// Activate only EAP message traces.
				m_am_tools->set_trace_mask(
					eap_am_tools_c::eap_trace_mask_always
					| eap_am_tools_c::eap_trace_mask_eap_messages);
			}
			else
			{
				// Disable only EAP message traces.
				m_am_tools->set_trace_mask(
					m_am_tools->get_trace_mask() & (~eap_am_tools_c::eap_trace_mask_eap_messages));
			}
		}
		else
		{
			// Disable only EAP message traces.
			m_am_tools->set_trace_mask(
				m_am_tools->get_trace_mask() & (~eap_am_tools_c::eap_trace_mask_eap_messages));
		}
	}


	{
		eap_variable_data_c data(m_am_tools);

		status = m_partner->read_configure(
			cf_str_EAP_TRACE_only_test_vectors.get_field(),
			&data);
		if (status == eap_status_ok
			&& data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			if (*(reinterpret_cast<u32_t *>(data.get_data(data.get_data_length()))) != 0u)
			{
				// Activates only EAP test vector traces.
				m_am_tools->set_trace_mask(eap_am_tools_c::eap_trace_mask_test_vectors);
			}
		}
	}


	{
		eap_variable_data_c data(m_am_tools);

		status = m_partner->read_configure(
			cf_str_EAP_TRACE_crypto_test_vectors_sha1.get_field(),
			&data);
		if (status == eap_status_ok
			&& data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			if (*(reinterpret_cast<u32_t *>(data.get_data(data.get_data_length()))) != 0u)
			{
				// Activates SHA1 EAP test vector traces.
				m_am_tools->set_trace_mask(m_am_tools->get_trace_mask()
					| eap_am_tools_c::eap_trace_mask_crypto_sha1);
			}
		}
	}


	{
		eap_variable_data_c data(m_am_tools);

		status = m_partner->read_configure(
			cf_str_EAP_TRACE_crypto_test_vectors_rc4.get_field(),
			&data);
		if (status == eap_status_ok
			&& data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			if (*(reinterpret_cast<u32_t *>(data.get_data(data.get_data_length()))) != 0u)
			{
				// Activates RC4 EAP test vector traces.
				m_am_tools->set_trace_mask(m_am_tools->get_trace_mask()
					| eap_am_tools_c::eap_trace_mask_crypto_rc4);
			}
		}
	}


	{
		eap_variable_data_c data(m_am_tools);

		status = m_partner->read_configure(
			cf_str_EAP_TRACE_crypto_test_vectors_md4.get_field(),
			&data);
		if (status == eap_status_ok
			&& data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			if (*(reinterpret_cast<u32_t *>(data.get_data(data.get_data_length()))) != 0u)
			{
				// Activates MD4 EAP test vector traces.
				m_am_tools->set_trace_mask(m_am_tools->get_trace_mask()
					| eap_am_tools_c::eap_trace_mask_crypto_md4);
			}
		}
	}


	{
		eap_variable_data_c data(m_am_tools);

		status = m_partner->read_configure(
			cf_str_EAP_TRACE_crypto_test_vectors_test_random.get_field(),
			&data);
		if (status == eap_status_ok
			&& data.get_data_length() == sizeof(u32_t)
			&& data.get_data(data.get_data_length()) != 0)
		{
			if (*(reinterpret_cast<u32_t *>(data.get_data(data.get_data_length()))) != 0u)
			{
				// Activates test random generator EAP test vector traces.
				m_am_tools->set_trace_mask(m_am_tools->get_trace_mask()
					| eap_am_tools_c::eap_trace_mask_crypto_test_random
					| eap_am_tools_c::eap_trace_mask_crypto_sha1);
			}
		}
	}

#endif //#if defined(USE_EAP_TEST_VECTORS)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_CORE_SERVER)
	if (m_is_client == false)
	{
		eap_variable_data_c data(m_am_tools);

		status = m_partner->read_configure(
			cf_str_EAP_CORE_process_EAP_Nak_immediately.get_field(),
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
					m_process_eap_nak_immediately = true;
				}
				else
				{
					m_process_eap_nak_immediately = false;
				}
			}
		}
	}
#endif //#if defined(USE_EAP_CORE_SERVER)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_CORE_SERVER)
	if (m_is_client == false)
	{
		eap_variable_data_c retransmission_time(m_am_tools);

		status = read_configure(
			cf_str_EAP_CORE_retransmission_time.get_field(),
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
				m_retransmission_time = EAP_CORE_RETRANSMISSION_TIME;
			}
		}
		else
		{
			m_retransmission_time = EAP_CORE_RETRANSMISSION_TIME;
		}
	}
#endif //#if defined(USE_EAP_CORE_SERVER)

	//if (m_is_client == false)
	{
		eap_variable_data_c retransmission_counter(m_am_tools);

		status = read_configure(
			cf_str_EAP_CORE_retransmission_counter.get_field(),
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
			else
			{
				m_retransmission_counter = EAP_CORE_RETRANSMISSION_COUNTER;
			}
		}
		else
		{
			m_retransmission_counter = EAP_CORE_RETRANSMISSION_COUNTER;
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c session_timeout(m_am_tools);

		status = read_configure(
			cf_str_EAP_CORE_session_timeout.get_field(),
			&session_timeout);
		if (status == eap_status_ok
			&& session_timeout.get_is_valid_data() == true)
		{
			u32_t *handler_timeout = reinterpret_cast<u32_t *>(
				session_timeout.get_data(sizeof(u32_t)));
			if (handler_timeout != 0)
			{
				m_session_timeout = *handler_timeout;
			}
			else
			{
				m_session_timeout = EAP_CORE_SESSION_TIMEOUT;
			}
		}
		else
		{
			m_session_timeout = EAP_CORE_SESSION_TIMEOUT;
		}
	}


#if defined(USE_EAP_CORE_SERVER)

	if (m_is_client == false)
	{
		eap_variable_data_c session_timeout(m_am_tools);

		status = read_configure(
			cf_str_EAP_CORE_server_session_timeout.get_field(),
			&session_timeout);
		if (status == eap_status_ok
			&& session_timeout.get_is_valid_data() == true)
		{
			u32_t *handler_timeout = reinterpret_cast<u32_t *>(
				session_timeout.get_data(sizeof(u32_t)));
			if (handler_timeout != 0)
			{
				// This is optional.
				m_session_timeout = *handler_timeout;
			}
		}
	}

	if (m_is_client == false)
	{
		eap_variable_data_c data(m_am_tools);

		status = m_partner->read_configure(
			cf_str_EAP_CORE_send_eap_success_after_notification.get_field(),
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
					m_send_eap_success_after_notification = true;
				}
				else
				{
					m_send_eap_success_after_notification = false;
				}
			}
		}
	}

#endif //#if defined(USE_EAP_CORE_SERVER)

	//----------------------------------------------------------

	{
		eap_variable_data_c failure_received_timeout(m_am_tools);

		status = read_configure(
			cf_str_EAP_CORE_failure_received_timeout.get_field(),
			&failure_received_timeout);
		if (status == eap_status_ok
			&& failure_received_timeout.get_is_valid_data() == true)
		{
			u32_t *timeout = reinterpret_cast<u32_t *>(
				failure_received_timeout.get_data(sizeof(u32_t)));
			if (timeout != 0)
			{
				m_eap_core_failure_received_timeout = *timeout;
			}
		}
	}

	//----------------------------------------------------------

	if (m_is_tunneled_eap == false)
	{
		eap_variable_data_c remove_session_timeout(m_am_tools);

		status = read_configure(
			cf_str_EAP_CORE_remove_session_timeout.get_field(),
			&remove_session_timeout);
		if (status == eap_status_ok
			&& remove_session_timeout.get_is_valid_data() == true)
		{
			u32_t *remove_session_timeout_value = reinterpret_cast<u32_t *>(
				remove_session_timeout.get_data(sizeof(u32_t)));
			if (remove_session_timeout_value != 0)
			{
				m_remove_session_timeout = *remove_session_timeout_value;
			}
		}
	}
	else
	{
		// Inside the tunnel we do not need any timeout.
		m_remove_session_timeout = 0ul;
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c use_eap_expanded_type(m_am_tools);

		status = m_partner->read_configure(
			cf_str_EAP_CORE_use_eap_expanded_type.get_field(),
			&use_eap_expanded_type);
		if (status == eap_status_ok
			&& use_eap_expanded_type.get_data_length() == sizeof(u32_t)
			&& use_eap_expanded_type.get_data() != 0)
		{
			u32_t *flag = reinterpret_cast<u32_t *>(use_eap_expanded_type.get_data(use_eap_expanded_type.get_data_length()));

			if (flag != 0)
			{
				if ((*flag) != 0ul)
				{
					m_use_eap_expanded_type = true;
				}
				else
				{
					m_use_eap_expanded_type = false;
				}
			}
		}
	}

	//----------------------------------------------------------

#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)
	{
		eap_variable_data_c wait_eap_request_type_timeout(m_am_tools);

		status = read_configure(
			cf_str_EAP_CORE_wait_eap_request_type_timeout.get_field(),
			&wait_eap_request_type_timeout);
		if (status == eap_status_ok
			&& wait_eap_request_type_timeout.get_is_valid_data() == true)
		{
			u32_t *timeout = reinterpret_cast<u32_t *>(
				wait_eap_request_type_timeout.get_data(sizeof(u32_t)));
			if (timeout != 0)
			{
				m_wait_eap_request_type_timeout = *timeout;
			}
		}
	}

#if defined(USE_EAP_CORE_SERVER)
	if (m_is_tunneled_eap == false)
	{
		
		eap_variable_data_c skip_eap_request_identity(m_am_tools);

		status = m_partner->read_configure(
			cf_str_EAP_CORE_skip_eap_request_identity.get_field(),
			&skip_eap_request_identity);
		if (status == eap_status_ok
			&& skip_eap_request_identity.get_data_length() == sizeof(u32_t)
			&& skip_eap_request_identity.get_data() != 0)
		{
			u32_t *flag = reinterpret_cast<u32_t *>(skip_eap_request_identity.get_data(skip_eap_request_identity.get_data_length()));

			if (flag != 0)
			{
				if ((*flag) != 0ul)
				{
					m_skip_eap_request_identity = true;
				}
				else
				{
					m_skip_eap_request_identity = false;
				}
			}
		}
	}
#endif //#if defined(USE_EAP_CORE_SERVER)

#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

	//----------------------------------------------------------

	m_eap_header_offset = m_partner->get_header_offset(&m_MTU, &m_trailer_length);


	// Add session timeout.
	status = initialize_session_timeout(m_session_timeout);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

	if (m_is_tunneled_eap == false
		&& m_is_client_role == true)
	{
		status = cancel_wait_eap_request_type_timeout();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = set_wait_eap_request_type_timeout();
	}

#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::shutdown_operation(
	eap_base_type_c * const handler,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::shutdown_operation(): handler=0x%08x.\n"),
		 handler));

	eap_status_e status = handler->shutdown();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

#if !defined(USE_EAP_DEBUG_TRACE)
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::shutdown(): %s: %s, m_shutdown_was_called=%d.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
		 m_shutdown_was_called));
#else
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::shutdown(): %s: %s, this = 0x%08x => 0x%08x, ")
		 EAPL("m_shutdown_was_called=%d.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		 m_shutdown_was_called));
#endif

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_core_c::shutdown()");

	if (m_shutdown_was_called == true)
	{
		// Shutdown was already called once.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	if (m_partner == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_core_c::shutdown(): m_is_tunneled_eap=%d, m_eap_type_response_sent=%d\n"),
		m_is_tunneled_eap,
		m_eap_type_response_sent));

	if (m_is_client == true
		&& m_is_tunneled_eap == false
		&& m_eap_type_response_sent == false)
	{
		// EAP-authentication failed before any EAP-messages.

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_core_c::shutdown(): EAP-authentication failed before any EAP-messages.\n")));

		eap_am_network_id_c send_network_id(m_am_tools,
			m_receive_network_id.get_destination_id(),
			m_receive_network_id.get_source_id(),
			m_receive_network_id.get_type());

		eap_state_notification_c notification(
			m_am_tools,
			&send_network_id,
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_eap,
			m_current_eap_type,
			eap_state_none,
			eap_state_authentication_terminated_unsuccessfully,
			m_eap_identity_request_identifier_client,
			false);

		notification.set_authentication_error(eap_status_authentication_failure);

		state_notification(&notification);
	}

	eap_status_e status = m_type_map.for_each(shutdown_operation, true);

	m_type_map.reset();

	cancel_retransmission();

	cancel_session_timeout();

	cancel_eap_failure_timeout();

	cancel_asynchronous_init_remove_eap_session();

#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)
	if (m_is_tunneled_eap == false
		&& m_is_client_role == true)
	{
		cancel_wait_eap_request_type_timeout();
	}
#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)


	if (m_partner != 0)
	{

#if defined(USE_EAP_CORE_SERVER)
		m_partner->cancel_timer(this, EAP_CORE_DELAYED_EAP_NAK_PROCESS_ID);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_DELAYED_EAP_NAK_PROCESS_ID ")
			 EAPL("cancelled, this = 0x%08x.\n"),
			 (m_is_client == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
			 this));
#endif //#if defined(USE_EAP_CORE_SERVER)

		m_partner->cancel_timer(this, EAP_CORE_SESSION_TIMEOUT_ID);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_SESSION_TIMEOUT_ID cancelled, this = 0x%08x.\n"),
			 (m_is_client == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
			 this));
	}

#if !defined(USE_EAP_DEBUG_TRACE)
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::shutdown(): %s: %s, m_shutdown_was_called=%d, status=%d returns.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
		 m_shutdown_was_called,
		 status));
#else
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::shutdown(): %s: %s, this = 0x%08x => 0x%08x, ")
		 EAPL("m_shutdown_was_called=%d, status=%d returns.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		 m_shutdown_was_called,
		 status));
#endif

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::unload_module(const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_partner->unload_module(type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_c::eap_acknowledge(
	const eap_am_network_id_c * const receive_network_id)
{
	// Any Network Protocol packet is accepted as a success indication.
	// This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status(eap_status_process_general_error);

	/**
	 * @{ 2003-10-01 draft-ietf-eap-rfc2284bis-06.txt chapter 3.4 Lower layer indications:
	 * To improve reliability, if a peer receives a lower layer success
	 * indication as defined in Section 7.2, it MAY conclude that a Success
	 * packet has been lost, and behave as if it had actually received a
	 * Success packet.  This includes choosing to ignore the Success in some
	 * circumstances as described in Section 4.2.
	 * Add call to current EAP-type. Maybe the EAP-Success packet could
	 * be created here and send to EAP-type.
	 * }
	 */

	if (m_current_eap_type != eap_type_none)
	{
		// Here we query the current EAP-type.
		eap_variable_data_c selector(m_am_tools);
		u64_t selector_eap_type = convert_eap_type_to_u64_t(m_current_eap_type);
		status = selector.set_buffer(&selector_eap_type, sizeof(selector_eap_type), false, false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		eap_base_type_c *handler = m_type_map.get_handler(&selector);
		
		// Check if we already have this type loaded.
		if (handler != 0)
		{
			status = handler->eap_acknowledge(receive_network_id);

			if (status == eap_status_not_supported)
			{
				// This is too noisy.
				/**
				 * @{ 2004-09-02 Fix all eap_acknowledge() functions. }
				 */
				status = eap_status_ok;
			}
		}
		else
		{
			// Here we do not care of missing handler.
			// Acknowledge is meaningfull only for existing handler.
			status = eap_status_ok;
		}
	}
	else
	{
		// Here we do not care of missing handler.
		// Acknowledge is meaningfull only for existing handler.
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::restart_authentication(
	const eap_am_network_id_c * const send_network_id,
	const bool is_client_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	// Here we swap the addresses.
	eap_am_network_id_c receive_network_id(m_am_tools,
		send_network_id->get_destination_id(),
		send_network_id->get_source_id(),
		send_network_id->get_type());

	eap_status_e status = eap_status_process_general_error;

	initialize_session_timeout(m_session_timeout);

	if (is_client_when_true == false)
	{
		// This is much faster.
		status = m_partner->restart_authentication(
			&receive_network_id,
			is_client_when_true,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_client_restart_authentication_initiated = true;
	}
	else
	{
		if (m_client_restart_authentication_initiated == true)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}

		// This is much faster.
		status = m_partner->restart_authentication(
			&receive_network_id,
			is_client_when_true,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_client_restart_authentication_initiated = true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_CORE_SERVER)

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::send_eap_identity_request(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_ASSERT(m_is_client == false);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::send_eap_identity_request(): %s, %s\n"),
		 (m_is_client == true) ? "client": "server",
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
		 ));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_core_c::send_eap_identity_request()");

	if (receive_network_id->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
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

#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::send_eap_identity_request(): %s, %s, m_skip_eap_request_identity=%d, m_eap_identity_request_send=%d, m_eap_identity_response_accepted=%d\n"),
		 (m_is_client == true) ? "client": "server",
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
		 m_skip_eap_request_identity,
		 m_eap_identity_request_send,
		 m_eap_identity_response_accepted
		 ));

	if (m_skip_eap_request_identity == true)
	{
		if (m_eap_identity_request_send == true)
		{
			// Do nothing, this have been done already.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}

		if (m_eap_identity.get_is_valid_data() == false)
		{
			// No saved EAP-Identity. Set an empty EAP-Identity.
			status = m_eap_identity.init(0ul);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// We will skip EAP-Request/Identity and EAP-Response/Identity for testing purposes.
		// Now restart authentication with proposed EAP type.
		status = restart_with_new_type(
			m_default_eap_type,
			receive_network_id,
			0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_eap_identity_request_send = true;
		m_eap_identity_response_accepted = true;
	}
	else
#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)
	{
		// Creates a identity request message.
		eap_buf_chain_wr_c request_packet(
			eap_write_buffer, 
			m_am_tools, 
			EAP_CORE_PACKET_BUFFER_LENGTH);

		if (request_packet.get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("send_eap_identity_request(): %s, %s, packet buffer corrupted.\n"),
				 (m_is_client == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
				 ));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t buffer_size = EAP_CORE_PACKET_BUFFER_LENGTH;
		EAP_ASSERT_ALWAYS(m_MTU > m_trailer_length);
		if (m_MTU-m_trailer_length < buffer_size)
		{
			buffer_size = m_MTU-m_trailer_length;
		}

		EAP_ASSERT_ALWAYS(buffer_size >= m_eap_header_offset);
		eap_header_wr_c eap_request(
			m_am_tools,
			request_packet.get_data_offset(
				m_eap_header_offset,
				(buffer_size-m_eap_header_offset)),
			(buffer_size-m_eap_header_offset));

		if (eap_request.get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("send_eap_identity_request(): %s, %s, packet buffer corrupted.\n"),
				 (m_is_client == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
				 ));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		eap_request.set_length(
			static_cast<u16_t>((EAP_CORE_PACKET_BUFFER_LENGTH-m_eap_header_offset)),
			m_use_eap_expanded_type);
		eap_request.set_code(eap_code_request);
		eap_request.set_identifier(0);
		eap_request.set_type_data_length(0ul, m_use_eap_expanded_type);
		eap_request.set_type(eap_type_identity, m_use_eap_expanded_type);

		request_packet.set_data_length(m_eap_header_offset+eap_request.get_length());
		request_packet.set_do_packet_retransmission(true);

		EAP_ASSERT(m_eap_header_offset < request_packet.get_data_length());
		EAP_ASSERT(eap_request.get_length() <= request_packet.get_data_length());
		EAP_ASSERT(request_packet.get_data_length() <= EAP_CORE_PACKET_BUFFER_LENGTH);

		status = packet_send(
			&send_network_id, &request_packet, m_eap_header_offset,
			eap_request.get_length(),
			EAP_CORE_PACKET_BUFFER_LENGTH);

		if (status == eap_status_ok)
		{
			eap_state_notification_c notification(
				m_am_tools,
				&send_network_id,
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_eap,
				m_current_eap_type,
				eap_state_none,
				eap_state_identity_request_sent,
				eap_request.get_identifier(),
				false);
			state_notification(&notification);
		}

		m_eap_identity_request_send = true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_SERVER)

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::send_eap_nak_response(
	const eap_am_network_id_c * const receive_network_id,
	const u8_t eap_identifier,
	const eap_array_c<eap_type_value_e> * const eap_type_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::send_eap_nak_response(): %s, %s\n"),
		 (m_is_client == true) ? "client": "server",
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
		 ));

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());

	// Creates a identity request message.
	eap_buf_chain_wr_c nak_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_CORE_PACKET_BUFFER_LENGTH);

	if (nak_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_core_c::send_eap_nak_response(): %s, %s, packet buffer corrupted.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t buffer_size = EAP_CORE_PACKET_BUFFER_LENGTH;
	EAP_ASSERT_ALWAYS(m_MTU > m_trailer_length);
	if (m_MTU-m_trailer_length < buffer_size)
	{
		buffer_size = m_MTU-m_trailer_length;
	}

	EAP_ASSERT_ALWAYS(buffer_size >= m_eap_header_offset);
	eap_header_wr_c eap_nak_hdr(
		m_am_tools,
		nak_packet.get_data_offset(
			m_eap_header_offset,
			(buffer_size-m_eap_header_offset)),
		(buffer_size-m_eap_header_offset)
		);

	if (eap_nak_hdr.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_core_c::send_eap_nak_response(): %s, %s, packet buffer corrupted.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	bool write_expanded_type(false);
	u32_t ind = 0ul;
	u32_t count_of_eap_types = eap_type_list->get_object_count();

	for (ind = 0ul; ind < count_of_eap_types; ind++)
	{
		const eap_type_value_e * const type = eap_type_list->get_object(ind);
		if (type != 0
			&& eap_expanded_type_c::is_ietf_type(*type) == false)
		{
			write_expanded_type = true;
			break;
		}
	}

	eap_nak_hdr.set_length(
		static_cast<u16_t>((EAP_CORE_PACKET_BUFFER_LENGTH-m_eap_header_offset)),
		write_expanded_type);
	eap_nak_hdr.set_code(eap_code_response);
	eap_nak_hdr.set_identifier(eap_identifier);
	eap_nak_hdr.set_type_data_length(eap_nak_hdr.get_length(), write_expanded_type);
	eap_nak_hdr.set_type(eap_type_nak, write_expanded_type);

	u32_t required_data_length = count_of_eap_types
		*eap_expanded_type_c::get_eap_expanded_type_size();

	if (eap_nak_hdr.get_length() < required_data_length)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t type_length = eap_expanded_type_c::m_ietf_type_size;
	if (write_expanded_type == true)
	{
		type_length = eap_expanded_type_c::m_eap_expanded_type_size;
	}

	u8_t * const type_data = eap_nak_hdr.get_data_offset(type_length, required_data_length);

	if (type_data == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_core_c::send_eap_nak_response(): %s, %s, packet buffer corrupted.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	u8_t * const data = type_data;

	for (ind = 0ul; ind < count_of_eap_types; ind++)
	{
		const eap_type_value_e * const type = eap_type_list->get_object(ind);

		if (type != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("%s: eap_core_c::send_eap_nak_response(): allowed EAP-type %d.\n"),
				 (m_is_client == true ? "client": "server"),
				 convert_eap_type_to_u32_t(*type)));

			status = eap_expanded_type_c::write_type(
				m_am_tools,
				ind,
				data,
				eap_nak_hdr.get_type_data_length()
				-eap_expanded_type_c::get_eap_expanded_type_size()*ind,
				write_expanded_type,
				*type);
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_core_c::send_eap_nak_response(): %s, %s, ")
				 EAPL("No EAP-type supported.\n"),
				 (m_is_client == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most"));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
		}
	} // for()

	eap_nak_hdr.set_type_data_length(
		static_cast<u16_t>(count_of_eap_types*type_length),
		write_expanded_type);
	nak_packet.set_data_length(m_eap_header_offset+eap_nak_hdr.get_length());

	EAP_ASSERT(m_eap_header_offset < nak_packet.get_data_length());
	EAP_ASSERT(eap_nak_hdr.get_length() <= nak_packet.get_data_length());
	EAP_ASSERT(nak_packet.get_data_length() <= EAP_CORE_PACKET_BUFFER_LENGTH);

	status = packet_send(
		&send_network_id, &nak_packet, m_eap_header_offset,
		eap_nak_hdr.get_length(),
		EAP_CORE_PACKET_BUFFER_LENGTH);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_c::packet_data_crypto_keys(
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

EAP_FUNC_EXPORT eap_status_e eap_core_c::read_configure(
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

EAP_FUNC_EXPORT eap_status_e eap_core_c::write_configure(
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
EAP_FUNC_EXPORT eap_status_e eap_core_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(data); // Only trace uses this.
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: [0x%08x]->eap_core_c::timer_expired(id 0x%02x, data 0x%08x), %s, %s.\n"),
		 this,
		 id,
		 data,
		 (m_is_client == true) ? "client": "server",
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most"));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	if (id == EAP_CORE_FAILURE_RECEIVED_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_FAILURE_RECEIVED_ID elapsed.\n"),
			 (m_is_client == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));

		{
			eap_am_network_id_c send_network_id(m_am_tools,
				m_receive_network_id.get_destination_id(),
				m_receive_network_id.get_source_id(),
				m_receive_network_id.get_type());

			eap_state_notification_c notification(
				m_am_tools,
				&send_network_id,
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_eap,
				m_current_eap_type,
				eap_state_none,
				eap_state_authentication_terminated_unsuccessfully,
				m_eap_identity_request_identifier_client,
				false);

			notification.set_authentication_error(eap_status_authentication_failure);

			state_notification(&notification);
		}

		status = eap_status_ok;
	}
	else if (id == EAP_CORE_TIMER_RETRANSMISSION_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_TIMER_RETRANSMISSION_ID elapsed.\n"),
			 (m_is_client == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));

		if (m_retransmission != 0
			&& m_retransmission->get_is_valid() == true
			&& m_retransmission->get_retransmission_counter() > 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TIMER: %s, %s, new retransmission, m_retransmission->get_is_valid()=%d, ")
				 EAPL("m_retransmission->get_retransmission_counter()=%d.\n"),
				 (m_is_client == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
				 m_retransmission->get_is_valid(),
				 m_retransmission->get_retransmission_counter()));

			// This packet send is initialized by timer event.

			status = resend_packet(
				m_retransmission->get_send_network_id(),
				m_retransmission->get_sent_packet(),
				m_retransmission->get_header_offset(),
				m_retransmission->get_data_length(),
				m_retransmission->get_buffer_size(),
				m_retransmission->get_retransmission_counter()
				);

			if (status == eap_status_ok)
			{
				if (m_retransmission->get_retransmission_counter() > 0u)
				{
					// OK, initialize the next time to retransmit.
					u32_t next_retransmission_time
						= m_retransmission->get_next_retransmission_time();

					status = m_partner->set_timer(
						this,
						EAP_CORE_TIMER_RETRANSMISSION_ID,
						0,
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
							(EAPL("TIMER: %s: %s, EAP_CORE_TIMER_RETRANSMISSION_ID ")
							 EAPL("set %d ms, retransmission_counter %d.\n"),
							 (m_is_client == true ? "client": "server"),
							 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
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
				(EAPL("TIMER: %s, %s, no retransmission, m_retransmission=0x%08x.\n"),
				 (m_is_client == true) ? "client": "server",
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
				 m_retransmission));
			if (m_retransmission != 0)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("TIMER: %s, %s, no retransmission, m_retransmission->get_is_valid()=%d, ")
					 EAPL("m_retransmission->get_retransmission_counter()=%d.\n"),
					 (m_is_client == true) ? "client": "server",
					 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
					 m_retransmission->get_is_valid(),
					 m_retransmission->get_retransmission_counter()));
			}

			// No good EAP-Response received to EAP-Requests.
			// Terminate the session.

			{
				eap_am_network_id_c send_network_id(m_am_tools,
					m_receive_network_id.get_destination_id(),
					m_receive_network_id.get_source_id(),
					m_receive_network_id.get_type());

				eap_state_notification_c notification(
					m_am_tools,
					&send_network_id,
					m_is_client,
					eap_state_notification_eap,
					eap_protocol_layer_eap,
					m_current_eap_type,
					eap_state_none,
					eap_state_authentication_terminated_unsuccessfully,
					m_eap_identity_request_identifier_client,
					false);

				notification.set_authentication_error(eap_status_authentication_failure);

				state_notification(&notification);
			}

			status = eap_status_ok;
		}
	}
#if defined(USE_EAP_CORE_SERVER)
	else if (id == EAP_CORE_DELAYED_EAP_NAK_PROCESS_ID)
	{
		// Now restart authentication with proposed EAP type.
		const eap_core_nak_info_c * const nak_info
			= reinterpret_cast<const eap_core_nak_info_c *>(data);
		
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_DELAYED_EAP_NAK_PROCESS_ID elapsed.\n"),
			 (m_is_client == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));

		eap_type_value_e used_eap_type = nak_info->get_proposed_eap_type();

		m_nak_process_timer_active = false;

		{
			// First remove current EAP-type.
			eap_variable_data_c selector(m_am_tools);
			status = selector.set_copy_of_buffer(
				&m_current_eap_type,
				sizeof(m_current_eap_type));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			eap_base_type_c *handler = m_type_map.get_handler(&selector);

			// Change the current EAP-type here because shutdown could
			// cause state notifications from old EAP-type.
			m_current_eap_type = used_eap_type;

			if (handler != 0)
			{
				status = handler->shutdown();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = m_type_map.remove_handler(&selector, true);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			// Now restart authentication with proposed EAP type.
			status = restart_with_new_type(
				used_eap_type,
				nak_info->get_network_id(),
				nak_info->get_eap_identifier());

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#endif //#if defined(USE_EAP_CORE_SERVER)
	else if (id == EAP_CORE_SESSION_TIMEOUT_ID
#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)
				|| id == EAP_CORE_WAIT_EAP_REQUEST_TYPE_ID
#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)
		)
	{
#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)
		if (id == EAP_CORE_WAIT_EAP_REQUEST_TYPE_ID)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("TIMER: %s: %s, EAP_CORE_WAIT_EAP_REQUEST_TYPE_ID elapsed.\n"),
				 (m_is_client == true ? "client": "server"),
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
				 ));
		}
		else
#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("TIMER: %s: %s, EAP_CORE_SESSION_TIMEOUT_ID elapsed.\n"),
				 (m_is_client == true ? "client": "server"),
				 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
				 ));
		}

		// we will remove this session immediately.
		status = initialize_asynchronous_init_remove_eap_session(0ul);

		eap_am_network_id_c send_network_id(m_am_tools,
				m_receive_network_id.get_destination_id(),
				m_receive_network_id.get_source_id(),
				m_receive_network_id.get_type());

		eap_state_notification_c notification(
			m_am_tools,
			&send_network_id,
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_eap,
			m_current_eap_type,
			eap_state_none,
			eap_state_authentication_terminated_unsuccessfully,
			m_eap_identity_request_identifier_client,
			false);

		notification.set_authentication_error(eap_status_authentication_failure);

		state_notification(&notification);

		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (id == EAP_CORE_REMOVE_SESSION_TIMEOUT_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_REMOVE_SESSION_TIMEOUT_ID elapsed.\n"),
			 (m_is_client == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));

		status = asynchronous_init_remove_eap_session();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(data); // Only trace uses this.

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: [0x%08x]->eap_core_c::timer_delete_data(id 0x%02x, data 0x%08x): %s, %s.\n"),
		 this,
		 id,
		 data,
		 (m_is_client == true) ? "client": "server",
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
		 ));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (id == EAP_CORE_TIMER_RETRANSMISSION_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: %s, EAP_CORE_TIMER_RETRANSMISSION_ID delete data.\n"),
			 (m_is_client == true ? "client": "server"),
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));

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
#if defined(USE_EAP_CORE_SERVER)
	else if (id == EAP_CORE_DELAYED_EAP_NAK_PROCESS_ID)
	{
		const eap_core_nak_info_c * const nak_info
			= reinterpret_cast<const eap_core_nak_info_c *>(data);
		delete nak_info;
	}
#endif //#if defined(USE_EAP_CORE_SERVER)
	else if (id == EAP_CORE_REMOVE_SESSION_TIMEOUT_ID)
	{
		// Nothing to do.
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::reset_operation(
	eap_base_type_c * const handler,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::reset_operation(): handler=0x%08x.\n"),
		 handler));

	eap_status_e status = handler->reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

#if !defined(USE_EAP_DEBUG_TRACE)
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::reset(): %s: %s.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most"));
#else
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_core_c::reset(): %s: %s, this = 0x%08x => 0x%08x.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
#endif

	eap_status_e status = eap_status_ok;

	eap_variable_data_c selector(m_am_tools);
	u64_t tmp_eap_type = convert_eap_type_to_u64_t(m_current_eap_type);
	status = selector.set_buffer(&tmp_eap_type, sizeof(tmp_eap_type), false, false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	cancel_retransmission();

	cancel_session_timeout();

	cancel_eap_failure_timeout();

	cancel_asynchronous_init_remove_eap_session();

#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

	if (m_is_tunneled_eap == false
		&& m_is_client_role == true)
	{
		status = cancel_wait_eap_request_type_timeout();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = set_wait_eap_request_type_timeout();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

	m_eap_identity_response_accepted = false;
	m_eap_type_response_sent = false;

#if defined(USE_EAP_CORE_SERVER)
	m_eap_identity_request_send = false;
	m_eap_identity_response_received = false;
	m_eap_failure_sent = false;
#endif //#if defined(USE_EAP_CORE_SERVER)

	m_ignore_eap_failure = false;

	status = m_type_map.for_each(reset_operation, true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_current_eap_type = eap_type_none;
	m_eap_identity.reset();

	// Add session timeout.
	initialize_session_timeout(m_session_timeout);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_core_c::handle_eap_identity_request(
	const eap_type_value_e used_eap_type,
	const u8_t eap_identifier,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

	if (m_is_tunneled_eap == false
		&& m_is_client_role == true)
	{
		status = cancel_wait_eap_request_type_timeout();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

	// Here we query the desired EAP-type.
	eap_variable_data_c selector(m_am_tools);
	u64_t tmp_used_eap_type = convert_eap_type_to_u64_t(used_eap_type);
	status = selector.set_buffer(&tmp_used_eap_type, sizeof(tmp_used_eap_type), false, false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_base_type_c *handler = m_type_map.get_handler(&selector);

	if (handler == 0
		|| handler->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_type_does_not_exists_error);
	}

	m_client_restart_authentication_initiated = false;

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());


	// Send state change notification
	eap_state_notification_c notification(
		m_am_tools,
		&send_network_id,
		m_is_client,
		eap_state_notification_eap,
		eap_protocol_layer_eap,
		m_current_eap_type,
		eap_state_none,
		eap_state_identity_request_received,
		eap_identifier,
		false);
	state_notification(&notification);

	// Save EAP-identifier
	m_eap_identity_request_identifier_client = eap_identifier;

	status = handler->query_eap_identity(
		false,
		&m_eap_identity,
		receive_network_id,
		eap_identifier);
	if (status == eap_status_drop_packet_quietly)
	{
		// This packet was dropped.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status == eap_status_pending_request)
	{
		// This is pending query, that will be completed by complete_eap_identity_query() call.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status == eap_status_completed_request)
	{
		// This is already completed by complete_eap_identity_query() call.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else if (status != eap_status_ok)
	{
		// Send failure notification
		eap_state_notification_c notification(
			m_am_tools,
			&send_network_id,
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_eap,
			m_current_eap_type,
			eap_state_none,
			eap_state_authentication_terminated_unsuccessfully,
			eap_identifier,
			false);

		notification.set_authentication_error(eap_status_authentication_failure);

		state_notification(&notification);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else // status == eap_status_ok
	{
		// The query_eap_identity() function call is synchronous.
		// We must call send_eap_identity_response().

		status = send_eap_identity_response(
			&send_network_id,
			&m_eap_identity,
			m_eap_identity_request_identifier_client); // Uses the EAP-Identifier from the latest EAP-Request/Identity.
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_CORE_SERVER)

// 
EAP_FUNC_EXPORT eap_status_e eap_core_c::handle_eap_identity_response(
	eap_base_type_c * const handler,
	const eap_type_value_e used_eap_type,
	const eap_am_network_id_c * const receive_network_id,
	eap_header_wr_c * const eap,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(used_eap_type); 

	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_ASSERT(m_is_client == false);

	if (handler == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_type_does_not_exists_error);
	}

	status = handler->packet_process(
		receive_network_id,
		eap,
		packet_length);

	if (status == eap_status_ok)
	{
		// We need to copy EAP-Identity for later use.

		const u8_t * identity = eap->get_type_data(eap->get_type_data_length());
		const u32_t identity_length = eap->get_type_data_length();
		const u8_t empty_identity[] = "";

		if (identity == 0
			|| identity_length == 0ul)
		{
			identity = empty_identity;
		}

		status = m_eap_identity.set_copy_of_buffer(
			identity,
			identity_length);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_SERVER)

//--------------------------------------------------

#if defined(USE_EAP_CORE_SERVER)

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::send_eap_success(
	const eap_am_network_id_c * const send_network_id,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_buf_chain_wr_c eap_success_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_CORE_PACKET_BUFFER_LENGTH);

	if (eap_success_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_core_c::send_eap_success(): packet buffer corrupted: %s, %s\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT_ALWAYS(EAP_CORE_PACKET_BUFFER_LENGTH >= (m_eap_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_CORE_PACKET_BUFFER_LENGTH-m_trailer_length;

	if (m_eap_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_eap_header_offset+m_MTU;
	}

	eap_header_wr_c eap_response(
		m_am_tools,
		eap_success_packet.get_data_offset(
			m_eap_header_offset,
			(packet_buffer_free-m_eap_header_offset)),
		(packet_buffer_free-m_eap_header_offset));

	if (eap_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_core_c::send_eap_success(): %s, %s, packet buffer corrupted.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_response.reset_header(
		static_cast<u16_t>((packet_buffer_free-m_eap_header_offset)),
		m_use_eap_expanded_type);
	eap_response.set_length(
		static_cast<u16_t>((eap_header_wr_c::get_header_length())),
		m_use_eap_expanded_type);
	eap_response.set_code(eap_code_success);
	eap_response.set_identifier(eap_identifier);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_success_packet.set_data_length(m_eap_header_offset+eap_response.get_header_length());

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("    send: EAP-success packet"),
		eap_response.get_header_buffer(eap_response.get_length()),
		eap_response.get_length()));

	status = packet_send(
		send_network_id,
		&eap_success_packet,
		m_eap_header_offset,
		eap_response.get_length(),
		EAP_CORE_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		// After EAP-Success is sent no re-transmissions must occur.
		cancel_retransmission();
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_SERVER)

//--------------------------------------------------

#if defined(USE_EAP_CORE_SERVER)

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::send_eap_failure(
	const eap_am_network_id_c * const send_network_id,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_eap_failure_sent == true)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_core_c::send_eap_failure(): %s, %s, EAP-Failure already sent.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	eap_buf_chain_wr_c eap_failure_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_CORE_PACKET_BUFFER_LENGTH);

	if (eap_failure_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_core_c::send_eap_failure(): %s, %s, packet buffer corrupted.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT_ALWAYS(EAP_CORE_PACKET_BUFFER_LENGTH >= (m_eap_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_CORE_PACKET_BUFFER_LENGTH-m_trailer_length;

	if (m_eap_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_eap_header_offset+m_MTU;
	}

	eap_header_wr_c eap_response(
		m_am_tools,
		eap_failure_packet.get_data_offset(
			m_eap_header_offset,
			(packet_buffer_free-m_eap_header_offset)),
		(packet_buffer_free-m_eap_header_offset));

	if (eap_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_core_c::send_eap_failure(): %s, %s, packet buffer corrupted.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_response.reset_header(
		static_cast<u16_t>((packet_buffer_free-m_eap_header_offset)),
		m_use_eap_expanded_type);
	eap_response.set_length(
		static_cast<u16_t>((eap_header_wr_c::get_header_length())),
		m_use_eap_expanded_type);
	eap_response.set_code(eap_code_failure);
	eap_response.set_identifier(eap_identifier);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_failure_packet.set_data_length(m_eap_header_offset+eap_response.get_header_length());

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("    send: EAP-failure packet"),
		eap_response.get_header_buffer(eap_response.get_length()),
		eap_response.get_length()));

	status = packet_send(
		send_network_id,
		&eap_failure_packet,
		m_eap_header_offset,
		eap_response.get_length(),
		EAP_CORE_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		m_eap_failure_sent = true;

		// After EAP-Failure is sent no re-transmissions must occur.
		cancel_retransmission();
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_SERVER)

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::send_eap_notification_response(
	const eap_am_network_id_c * const send_network_id,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_buf_chain_wr_c eap_notification_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_CORE_PACKET_BUFFER_LENGTH);

	if (eap_notification_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_core_c::send_eap_notification_response(): ")
			 EAPL("%s, %s, packet buffer corrupted.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT_ALWAYS(EAP_CORE_PACKET_BUFFER_LENGTH >= (m_eap_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_CORE_PACKET_BUFFER_LENGTH-m_trailer_length;

	if (m_eap_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_eap_header_offset+m_MTU;
	}

	eap_header_wr_c eap_response(
		m_am_tools,
		eap_notification_packet.get_data_offset(
			m_eap_header_offset,
			(packet_buffer_free-m_eap_header_offset)),
		(packet_buffer_free-m_eap_header_offset));

	if (eap_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_core_c::send_eap_notification_response(): ")
			 EAPL("%s, %s, packet buffer corrupted.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_response.reset_header(
		static_cast<u16_t>((packet_buffer_free-m_eap_header_offset)),
		m_use_eap_expanded_type);
	eap_response.set_length(
		static_cast<u16_t>((eap_header_base_c::get_header_length()+1u)),
		m_use_eap_expanded_type);
	eap_response.set_code(eap_code_response);
	eap_response.set_identifier(eap_identifier);
	eap_response.set_type(eap_type_notification, m_use_eap_expanded_type);
	

	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_notification_packet.set_data_length(
		m_eap_header_offset+eap_response.get_header_length()+1u);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("    send: EAP-Response/Notification packet"),
		 eap_response.get_header_buffer(eap_response.get_length()),
		 eap_response.get_length()));
	
	status = packet_send(
		send_network_id,
		&eap_notification_packet,
		m_eap_header_offset,
		eap_response.get_length(),
		EAP_CORE_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		// After EAP-Notification is sent no re-transmissions must occur.
		cancel_retransmission();
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::create_eap_identity_response(
	eap_buf_chain_wr_c * const response_packet,
	const eap_variable_data_c * const identity,
	const u8_t eap_identifier
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (identity == 0
		|| identity->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	if (response_packet == 0
		|| response_packet->get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet buffer corrupted: %s, %s\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_ASSERT_ALWAYS(EAP_CORE_PACKET_BUFFER_LENGTH >= (m_eap_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_CORE_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_eap_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_eap_header_offset+m_MTU;
	}

	eap_header_wr_c eap_response(
		m_am_tools,
		response_packet->get_data_offset(
			m_eap_header_offset,
			(EAP_CORE_PACKET_BUFFER_LENGTH-(m_eap_header_offset+m_trailer_length))),
		EAP_CORE_PACKET_BUFFER_LENGTH-(m_eap_header_offset+m_trailer_length));

	if (eap_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("send_eap_identity_response: %s, %s, packet buffer corrupted.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_response.reset_header(
		static_cast<u16_t>((packet_buffer_free-m_eap_header_offset)),
		m_use_eap_expanded_type);

	eap_response.set_length(
		static_cast<u16_t>((packet_buffer_free-m_eap_header_offset)),
		m_use_eap_expanded_type);
	eap_response.set_code(eap_code_response);
	eap_response.set_identifier(eap_identifier);
	eap_response.set_type(eap_type_identity, m_use_eap_expanded_type);

	packet_buffer_offset += eap_response.get_header_length();

	u8_t * const target_nai = eap_response.get_type_data(
		identity->get_data_length());
	if (target_nai == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("send_eap_identity_response: %s, %s, too long EAP-Identity.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Identity"),
			 identity->get_data(identity->get_data_length()),
			 identity->get_data_length()));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_am_tools->memmove(
		target_nai,
		identity->get_data(identity->get_data_length()), 
		identity->get_data_length());

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_response.set_type_data_length(
		static_cast<u16_t>(identity->get_data_length()),
		m_use_eap_expanded_type);

	response_packet->set_data_length(m_eap_header_offset+eap_response.get_length());

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send EAP-identity NAI"),
		 eap_response.get_type_data(eap_response.get_type_data_length()),
		 eap_response.get_type_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::send_eap_identity_response(
	const eap_am_network_id_c * const send_network_id,
	const eap_variable_data_c * const identity,
	const u8_t eap_identifier
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	if (send_network_id == 0
		|| identity == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_buf_chain_wr_c response_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_CORE_PACKET_BUFFER_LENGTH);

	if (response_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet buffer corrupted: %s, %s.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	// Get add possible NAI decoration and 
	// extra routing info to identity

	eap_variable_data_c local_identity(m_am_tools);
	status = local_identity.set_copy_of_buffer(identity);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_eap_identity_routing_info_and_nai_decoration(&local_identity);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = create_eap_identity_response(
		&response_packet,
		&local_identity,
		eap_identifier);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_header_wr_c eap_response(
		m_am_tools,
		response_packet.get_data_offset(
			m_eap_header_offset,
			(response_packet.get_buffer_length()-(m_eap_header_offset+m_trailer_length))),
		response_packet.get_buffer_length()-(m_eap_header_offset+m_trailer_length));
	if (eap_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("send_eap_identity_response: %s, %s, packet buffer corrupted.\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
			 ));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	status = packet_send(
		send_network_id,
		&response_packet,
		m_eap_header_offset,
		eap_response.get_length(),
		response_packet.get_buffer_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

	if (m_is_tunneled_eap == false
		&& m_is_client_role == true)
	{
		status = cancel_wait_eap_request_type_timeout();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = set_wait_eap_request_type_timeout();
	}

#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eap_core_c::set_eap_identity_routing_info_and_nai_decoration(
	eap_variable_data_c * const identity)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (identity == 0
		|| identity->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	bool routing_info_available(true);
	bool nai_decoration_available(true);

	eap_status_e status(eap_status_process_general_error);

	// read routing info from AM
	eap_variable_data_c routing_info(m_am_tools);
	status = read_configure(
		cf_str_EAP_outer_identity_routing.get_field(),
		&routing_info);
	if (status != eap_status_ok 
		|| routing_info.get_is_valid_data() == false 
		|| routing_info.get_data_length() == 0)
	{
		routing_info_available = false;
	}

	// read NAI decoration from AM
	eap_variable_data_c nai_decoration(m_am_tools);
	status = read_configure(
		cf_str_EAP_outer_identity_decoration.get_field(),
		&nai_decoration);
	if (status != eap_status_ok 
		|| nai_decoration.get_is_valid_data() == false 
		|| nai_decoration.get_data_length() == 0)
	{
		nai_decoration_available = false;
	}

	// nothing to be added (which is ok)
	if(routing_info_available == false 
		&& nai_decoration_available == false) 
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	eap_variable_data_c username(m_am_tools);
	eap_variable_data_c home_realm(m_am_tools);

	// get username and home realm from the current NAI
	status = m_am_tools->parse_nai(
		identity,
		&username,
		&home_realm);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// username must be present
	if (username.get_is_valid_data() == false
		/* || home_realm.get_is_valid_data() == false */)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// original NAI can be cleared,
	// the new one is constructed to the same place
	identity->reset();

	// routing_info contains a string in format 
	// "RoutingRealm1!RoutingRealm2!RoutingRealm3"
	// in which RoutingRealm3 is replaced with the home
	// realm and RoutingRealm1 is appended after @-sign in NAI
	if(routing_info_available == true) 
	{
		// this points to the last byte of routing_info
		const u8_t* const p_last = 
			routing_info.get_data() + 
			(routing_info.get_data_length() - 1);

		// first and last characters cannot be !-signs
		if(*p_last == EAP_NAI_ROUTING_REALM_SEPARATOR[0]
			|| *(routing_info.get_data()) == EAP_NAI_ROUTING_REALM_SEPARATOR[0])
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		// find first !-sign
		const u8_t *separator = reinterpret_cast<const u8_t *>(
			m_am_tools->memchr(
				routing_info.get_data(),
				EAP_NAI_ROUTING_REALM_SEPARATOR[0],
				routing_info.get_data_length())
			);

		// !-sign found, more than one realm present
		// (the sign is not first or last character)
		if (separator != 0)
		{
			// others except the first realm are put in front
			status = identity->add_data(
				separator + 1, 
				p_last - separator);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// add !-sign
			status = identity->add_data(EAP_NAI_ROUTING_REALM_SEPARATOR, 1);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

		}

		// add home realm if it existed
		if(home_realm.get_is_valid_data() == true)
		{
			status = identity->add_data(
				home_realm.get_data(), 
				home_realm.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// add !-sign
			status = identity->add_data(EAP_NAI_ROUTING_REALM_SEPARATOR, 1);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// store the first realm of routing info here
		home_realm.reset();

		// more than one realm in routing info
		if (separator != 0) 
		{
			status = home_realm.add_data(
				routing_info.get_data(), 
				separator - routing_info.get_data()
				);
		}
		// only one realm in routing info
		else
		{
			status = home_realm.add_data(
				routing_info.get_data(), 
				routing_info.get_data_length());
		}

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// nai_decoration contains a string which is placed 
	// in front of the username in NAI
	if(nai_decoration_available == true) 
	{
		status = identity->add_data(nai_decoration.get_data(), nai_decoration.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = identity->add_data(username.get_data(), username.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	// add realm if it exists
        if (home_realm.get_is_valid_data() == true) {
	  // add @-sign
	  status = identity->add_data(EAP_NAI_AT_CHARACTER, 1);
	  if (status != eap_status_ok)
	    {
	      EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	      return EAP_STATUS_RETURN(m_am_tools, status);
	    }
	  
	  status = identity->add_data(home_realm.get_data(), home_realm.get_data_length());
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);

}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::complete_eap_identity_query(
	const eap_am_network_id_c * const send_network_id,
	const eap_variable_data_c * const identity,
	const u8_t /*eap_identifier*/) // Remove eap_identifier parameter.
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_illegal_eap_identity);

	if (identity != 0)
	{
		status = m_eap_identity.set_copy_of_buffer(identity);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
			
		status = send_eap_identity_response(
			send_network_id,
			identity,
			m_eap_identity_request_identifier_client); // Uses the EAP-Identifier from the latest EAP-Request/Identity.
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::get_saved_eap_identity(
	eap_variable_data_c * const identity)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_illegal_eap_identity;

	if (m_eap_identity.get_is_valid_data() == true)
	{
		status = identity->set_copy_of_buffer(&m_eap_identity);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: %s, %s, EAP-identity is unknown: current EAP-type 0xfe%06x%08x=%s\n"),
			 (m_is_client == true) ? "client": "server",
			 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
			 m_current_eap_type.get_vendor_id(),
			 m_current_eap_type.get_vendor_type(),
			 eap_header_string_c::get_eap_type_string(m_current_eap_type)));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN_WARNING(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_core_c::set_session_timeout(
	const u32_t session_timeout_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = initialize_session_timeout(session_timeout_ms);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_is_tunneled_eap == true)
	{
		status = m_partner->set_session_timeout(session_timeout_ms);
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
EAP_FUNC_EXPORT eap_status_e eap_core_c::set_timer(
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
EAP_FUNC_EXPORT eap_status_e eap_core_c::cancel_timer(
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

EAP_FUNC_EXPORT eap_status_e eap_core_c::set_authentication_role(const bool when_true_set_client)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	cancel_retransmission();

	cancel_eap_failure_timeout();

	m_is_client_role = when_true_set_client;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_core_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = m_partner->add_rogue_ap(rogue_ap_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_core_c::get_is_tunneled_eap() const
{
	return m_is_tunneled_eap;
}

//--------------------------------------------------
//--------------------------------------------------



// End.
