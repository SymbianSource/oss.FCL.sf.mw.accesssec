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
* %version: 8 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 716 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "dummy_eap_core.h"
#include "eap_core_nak_info.h"
#include "eap_state_notification.h"
#include "eap_network_id_selector.h"
#include "eap_buffer.h"
#include "eap_header_string.h"
#include "eap_automatic_variable.h"


//--------------------------------------------------

// 
EAP_FUNC_EXPORT dummy_eap_core_c::~dummy_eap_core_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("dummy_eap_core_c::~dummy_eap_core_c: ")
		 EAPL("this = 0x%08x\n"),
		 this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

// 
EAP_FUNC_EXPORT dummy_eap_core_c::dummy_eap_core_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_core_c * const partner,
	const bool is_client_when_true,
	const eap_am_network_id_c * const /* receive_network_id */,
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
		(EAPL("dummy_eap_core_c::dummy_eap_core_c: ")
		 EAPL("this = 0x%08x\n"),
		 this));

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT abs_eap_core_c * dummy_eap_core_c::get_partner()
{

	return m_partner;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void dummy_eap_core_c::set_partner(abs_eap_core_c * const partner)
{

	m_partner = partner;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void dummy_eap_core_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool dummy_eap_core_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void dummy_eap_core_c::object_increase_reference_count()
{
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t dummy_eap_core_c::object_decrease_reference_count()
{
	return 0u;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool dummy_eap_core_c::get_marked_removed()
{
	return false;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void dummy_eap_core_c::set_marked_removed()
{
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void dummy_eap_core_c::unset_marked_removed()
{
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT void dummy_eap_core_c::ignore_notifications()
{
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::initialize_asynchronous_init_remove_eap_session(
	const u32_t /* remove_session_timeout */)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("dummy_eap_core_c::initialize_asynchronous_init_remove_eap_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::cancel_asynchronous_init_remove_eap_session()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::asynchronous_init_remove_eap_session()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("dummy_eap_core_c::asynchronous_init_remove_eap_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

		eap_status_e status = eap_status_process_general_error;

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e dummy_eap_core_c::init_end_of_session(
	const abs_eap_state_notification_c * const /* state */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("dummy_eap_core_c::init_end_of_session(): %s.\n"),
		 (m_is_client == true) ? "client": "server"));

	eap_status_e status(eap_status_process_general_error);


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void dummy_eap_core_c::state_notification(
	const abs_eap_state_notification_c * const /* state */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);



	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_base_type_c * dummy_eap_core_c::load_type(
	const eap_type_value_e /* type */,
	const eap_type_value_e /* tunneling_type */,
	const eap_am_network_id_c * /* const receive_network_id */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_base_type_c *handler = 0;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return handler;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::check_is_valid_eap_type(const eap_type_value_e /* eap_type */)
{
		eap_status_e status = eap_status_process_general_error;

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const /* eap_type_list */)
{
		eap_status_e status = eap_status_process_general_error;

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::initialize_session_timeout(const u32_t /* session_timeout_ms */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::cancel_session_timeout()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void dummy_eap_core_c::trace_eap_packet(
	eap_const_string /* prefix */,
	const eap_header_wr_c * /* const eap_header */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

}


//--------------------------------------------------

#if defined(USE_EAP_CORE_SERVER)

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::restart_with_new_type(
	const eap_type_value_e /* used_eap_type */,
	const eap_am_network_id_c * /* const receive_network_id */,
	const u8_t /* eap_identifier */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		eap_status_e status = eap_status_process_general_error;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_SERVER)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::client_proposes_eap_types(
	const eap_am_network_id_c * const /* receive_network_id */,
	const u8_t /* eap_identifier */)
{

	/**
	 * @{ 2005-04-19 complete Expanded Nak Type to client_proposes_eap_types(). }
	 */
		eap_status_e status = eap_status_process_general_error;


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::packet_process_type(
	const eap_type_value_e /* used_eap_type */,
	const eap_am_network_id_c * /* const receive_network_id */,
	eap_general_header_base_c * /* const packet_data */,
	const u32_t /* packet_length */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("dummy_eap_core_c::packet_process_type(): %s\n"),
		(m_is_client == true) ? "client": "server"));


	eap_status_e status = eap_status_process_general_error;


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
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::packet_process(
	const eap_am_network_id_c * /* const receive_network_id */,
	eap_general_header_base_c * /* const packet_data */,
	const u32_t /* packet_length */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("dummy_eap_core_c::packet_process(): %s\n"),
		(m_is_client == true) ? "client": "server"));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: dummy_eap_core_c::packet_process()");

	eap_status_e status = eap_status_process_general_error;


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::packet_send(
	const eap_am_network_id_c * const /* send_network_id */,
	eap_buf_chain_wr_c * const /* sent_packet */,
	const u32_t /* header_offset */,
	const u32_t /* data_length */,
	const u32_t /* buffer_length */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::resend_packet(
	const eap_am_network_id_c * const /* send_network_id */,
	eap_buf_chain_wr_c * const /* sent_packet */,
	const u32_t /* header_offset */,
	const u32_t /* data_length */,
	const u32_t /* buffer_length */,
	const u32_t /* retransmission_counter */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::cancel_retransmission()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::init_retransmission(
	const eap_am_network_id_c * const /* send_network_id */,
	eap_buf_chain_wr_c * const /* sent_packet */,
	const u32_t /* header_offset */,
	const u32_t /* data_length */,
	const eap_code_value_e /* eap_code */,
	const u8_t /* eap_identifier */,
	const eap_type_value_e /* eap_type */
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);

}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::set_eap_failure_timeout()
{
	eap_status_e status = eap_status_process_general_error;

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::cancel_eap_failure_timeout()
{
	eap_status_e status = eap_status_process_general_error;

	return EAP_STATUS_RETURN(m_am_tools, status);

}

//--------------------------------------------------

#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

//
eap_status_e dummy_eap_core_c::set_wait_eap_request_type_timeout()
{

	eap_status_e status = eap_status_process_general_error;

	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

//--------------------------------------------------

#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

//
eap_status_e dummy_eap_core_c::cancel_wait_eap_request_type_timeout()
{
	eap_status_e status = eap_status_process_general_error;

	return EAP_STATUS_RETURN(m_am_tools, status);

}

#endif //#if defined(USE_EAP_CORE_WAIT_REQUEST_TYPE_TIMER)

//--------------------------------------------------

//
EAP_FUNC_EXPORT u32_t dummy_eap_core_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_UNREFERENCED_PARAMETER(MTU);
	EAP_UNREFERENCED_PARAMETER(trailer_length);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const u32_t offset = 0;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("dummy_eap_core_c::get_header_offset(): offset=%d, MTU=%d, trailer_length=%d\n"),
		offset,
		*MTU,
		*trailer_length));

	return offset;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::load_module(
	const eap_type_value_e /* type */,
	const eap_type_value_e /* tunneling_type */,
	abs_eap_base_type_c * /* const partner */,
	eap_base_type_c ** const /* handler */,
	const bool /* is_client_when_true */,
	const eap_am_network_id_c * const /* receive_network_id */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::configure()
	{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

#if !defined(USE_EAP_DEBUG_TRACE)
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("dummy_eap_core_c::configure(): %s: %s.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most"));
#else
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("dummy_eap_core_c::configure(): %s: %s, this = 0x%08x => 0x%08x.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
#endif

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: dummy_eap_core_c::configure()");

	eap_status_e status(eap_status_ok);


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
	}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::shutdown_operation(
	eap_base_type_c * const handler,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_UNREFERENCED_PARAMETER(handler);

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("dummy_eap_core_c::shutdown_operation(): handler=0x%08x.\n"),
		 handler));

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	eap_status_e status(eap_status_ok);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::unload_module(const eap_type_value_e /* type */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::eap_acknowledge(
	const eap_am_network_id_c * const /* receive_network_id */)
{
	// Any Network Protocol packet is accepted as a success indication.
	// This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::restart_authentication(
	const eap_am_network_id_c * const /* send_network_id */,
	const bool /* is_client_when_true */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_CORE_SERVER)

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::send_eap_identity_request(
	const eap_am_network_id_c * const /* receive_network_id */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("dummy_eap_core_c::send_eap_identity_request(): %s, %s\n"),
		 (m_is_client == true) ? "client": "server",
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
		 ));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: dummy_eap_core_c::send_eap_identity_request()");

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_SERVER)

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::send_eap_nak_response(
	const eap_am_network_id_c * const /* receive_network_id */,
	const u8_t /* eap_identifier */,
	const eap_array_c<eap_type_value_e> * const /* eap_type_list */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("dummy_eap_core_c::send_eap_nak_response(): %s, %s\n"),
		 (m_is_client == true) ? "client": "server",
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most"
		 ));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::packet_data_crypto_keys(
	const eap_am_network_id_c * const /* send_network_id */,
	const eap_master_session_key_c * const /* master_session_key */
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::read_configure(
	const eap_configuration_field_c * const /* field */,
	eap_variable_data_c * const /* data */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_illegal_configure_field;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::write_configure(
	const eap_configuration_field_c * const /* field */,
	eap_variable_data_c * const /* data */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::timer_expired(
	const u32_t /* id */, void * /* data */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::timer_delete_data(
	const u32_t /* id */, void * /* data */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::reset_operation(
	eap_base_type_c * const handler,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_UNREFERENCED_PARAMETER(handler);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("dummy_eap_core_c::reset_operation(): handler=0x%08x.\n"),
		 handler));

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

#if !defined(USE_EAP_DEBUG_TRACE)
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("dummy_eap_core_c::reset(): %s: %s.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most"));
#else
	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("dummy_eap_core_c::reset(): %s: %s, this = 0x%08x => 0x%08x.\n"),
		 ((m_is_client == true) ? "client": "server"),
		 (m_is_tunneled_eap == true) ? "tunneled": "outer most",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
#endif

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::handle_eap_identity_request(
	const eap_type_value_e /* used_eap_type */,
	const u8_t /* eap_identifier */,
	const eap_am_network_id_c * const /* receive_network_id */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_CORE_SERVER)

// 
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::handle_eap_identity_response(
	eap_base_type_c * const /* handler */,
	const eap_type_value_e used_eap_type,
	const eap_am_network_id_c * const /* receive_network_id */,
	eap_header_wr_c * const /* eap */,
	const u32_t /* packet_length */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(used_eap_type); 

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_SERVER)

//--------------------------------------------------

#if defined(USE_EAP_CORE_SERVER)

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::send_eap_success(
	const eap_am_network_id_c * const /* send_network_id */,
	const u8_t /* eap_identifier */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_SERVER)

//--------------------------------------------------

#if defined(USE_EAP_CORE_SERVER)

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::send_eap_failure(
	const eap_am_network_id_c * const /* send_network_id */,
	const u8_t /* eap_identifier */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_CORE_SERVER)

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::send_eap_notification_response(
	const eap_am_network_id_c * const /* send_network_id */,
	const u8_t /* eap_identifier */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::create_eap_identity_response(
	eap_buf_chain_wr_c * const /* response_packet */,
	const eap_variable_data_c * const /* identity */,
	const u8_t /* eap_identifier */
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::send_eap_identity_response(
	const eap_am_network_id_c * const /* send_network_id */,
	const eap_variable_data_c * const /* identity */,
	const u8_t /* eap_identifier */
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e dummy_eap_core_c::set_eap_identity_routing_info_and_nai_decoration(
	eap_variable_data_c * const /* identity */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);

}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::complete_eap_identity_query(
	const eap_am_network_id_c * const /* send_network_id */,
	const eap_variable_data_c * const /* identity */,
	const u8_t /*eap_identifier*/) // Remove eap_identifier parameter.
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		eap_status_e status = eap_status_process_general_error;

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::get_saved_eap_identity(
	eap_variable_data_c * const /* identity */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN_WARNING(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::set_session_timeout(
	const u32_t /* session_timeout_ms */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::set_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id, 
	void * const p_data,
	const u32_t p_time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_am_tools->am_set_timer(
		p_initializer, 
		p_id, 
		p_data,
		p_time_ms);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::cancel_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	const eap_status_e status = m_am_tools->am_cancel_timer(
		p_initializer, 
		p_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::set_authentication_role(const bool /* when_true_set_client */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e dummy_eap_core_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & /* rogue_ap_list */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool dummy_eap_core_c::get_is_tunneled_eap() const
{
	return m_is_tunneled_eap;
}

//--------------------------------------------------
//--------------------------------------------------



// End.
