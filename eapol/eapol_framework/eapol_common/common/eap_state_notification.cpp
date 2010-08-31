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
	#define EAP_FILE_NUMBER_ENUM 37 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_state_notification.h"
#include "eap_am_tools.h"
#include "eap_tools.h"
#include "eapol_key_types.h"
#include "eap_am_network_id.h"


EAP_FUNC_EXPORT eap_state_notification_c::~eap_state_notification_c()
{
	delete m_send_network_id;
	m_send_network_id = 0;
}

EAP_FUNC_EXPORT eap_state_notification_c::eap_state_notification_c(
	abs_eap_am_tools_c * const tools,
	const eap_am_network_id_c * const send_network_id,
	bool is_client,
	eap_state_notification_generic_e,
	eap_protocol_layer_e layer,
	u32_t protocol,
	u32_t previous_state,
	u32_t current_state,
	u8_t eap_identifier,
	bool allow_send_eap_success)
	: m_am_tools(tools)
	, m_layer(layer)
	, m_notification_string(tools)
	, m_needs_confirmation_from_user(false)
	, m_protocol(protocol)
	, m_eap_type(eap_type_none)
	, m_previous_state(previous_state)
	, m_current_state(current_state)
	, m_send_network_id(0)
	, m_is_client(is_client)
	, m_eap_identifier(eap_identifier)
	, m_allow_send_eap_success(allow_send_eap_success)
	, m_authentication_error(eap_status_ok)
{
	if (send_network_id == 0
		|| send_network_id->get_is_valid() == false)
	{
		(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return;
	}

	m_send_network_id = send_network_id->copy();

	if (m_send_network_id == 0
		|| m_send_network_id->get_is_valid() == false)
	{
		delete m_send_network_id;
		m_send_network_id = 0;
		(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return;
	}
}

EAP_FUNC_EXPORT eap_state_notification_c::eap_state_notification_c(
	abs_eap_am_tools_c * const tools,
	const eap_am_network_id_c * const send_network_id,
	bool is_client,
	eap_state_notification_eap_e,
	eap_protocol_layer_e layer,
	eap_type_value_e eap_type,
	u32_t previous_state,
	u32_t current_state,
	u8_t eap_identifier,
	bool allow_send_eap_success)
	: m_am_tools(tools)
	, m_layer(layer)
	, m_notification_string(tools)
	, m_needs_confirmation_from_user(false)
	, m_protocol(0ul)
	, m_eap_type(eap_type)
	, m_previous_state(previous_state)
	, m_current_state(current_state)
	, m_send_network_id(0)
	, m_is_client(is_client)
	, m_eap_identifier(eap_identifier)
	, m_allow_send_eap_success(allow_send_eap_success)
	, m_authentication_error(eap_status_ok)
{
	if (send_network_id == 0
		|| send_network_id->get_is_valid() == false)
	{
		(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return;
	}

	m_send_network_id = send_network_id->copy();

	if (m_send_network_id == 0
		|| m_send_network_id->get_is_valid() == false)
	{
		delete m_send_network_id;
		m_send_network_id = 0;
		(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return;
	}
}


EAP_FUNC_EXPORT eap_state_notification_c::eap_state_notification_c(
	abs_eap_am_tools_c * const tools,
	const eap_am_network_id_c * const send_network_id,
	bool is_client,
	eap_state_notification_eap_e,
	eap_protocol_layer_e layer,
	eap_type_ietf_values_e eap_type,
	u32_t previous_state,
	u32_t current_state,
	u8_t eap_identifier,
	bool allow_send_eap_success)
	: m_am_tools(tools)
	, m_layer(layer)
	, m_notification_string(tools)
	, m_needs_confirmation_from_user(false)
	, m_protocol(0ul)
	, m_eap_type(eap_type)
	, m_previous_state(previous_state)
	, m_current_state(current_state)
	, m_send_network_id(0)
	, m_is_client(is_client)
	, m_eap_identifier(eap_identifier)
	, m_allow_send_eap_success(allow_send_eap_success)
	, m_authentication_error(eap_status_ok)
{
	if (send_network_id == 0
		|| send_network_id->get_is_valid() == false)
	{
		(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return;
	}

	m_send_network_id = send_network_id->copy();

	if (m_send_network_id == 0
		|| m_send_network_id->get_is_valid() == false)
	{
		delete m_send_network_id;
		m_send_network_id = 0;
		(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return;
	}
}

EAP_FUNC_EXPORT const eap_am_network_id_c * eap_state_notification_c::get_send_network_id() const
{
	return m_send_network_id;
}

EAP_FUNC_EXPORT eap_protocol_layer_e eap_state_notification_c::get_protocol_layer() const
{
	return m_layer;
}

EAP_FUNC_EXPORT u32_t eap_state_notification_c::get_protocol() const
{
	return m_protocol;
}

EAP_FUNC_EXPORT eap_type_value_e eap_state_notification_c::get_eap_type() const
{
	return m_eap_type;
}

EAP_FUNC_EXPORT u32_t eap_state_notification_c::get_previous_state() const
{
	return m_previous_state;
}

EAP_FUNC_EXPORT u32_t eap_state_notification_c::get_current_state() const
{
	return m_current_state;
}

EAP_FUNC_EXPORT eap_const_string eap_state_notification_c::get_state_string(const u32_t protocol_layer, const u32_t state)
{

#if defined(USE_EAP_TRACE_STRINGS)

	if (protocol_layer == eap_protocol_layer_general)
	{
		EAP_IF_RETURN_STRING(state, eap_general_state_none)
		else EAP_IF_RETURN_STRING(state, eap_general_state_show_notification_string)
		else EAP_IF_RETURN_STRING(state, eap_general_state_configuration_error)
		else EAP_IF_RETURN_STRING(state, eap_general_state_authentication_cancelled)
		else EAP_IF_RETURN_STRING(state, eap_general_state_authentication_error)
		else EAP_IF_RETURN_STRING(state, eap_general_state_immediate_reconnect)
		else EAP_IF_RETURN_STRING(state, eap_general_state_last_mark)
		else
		{
			return EAPL("Unknown general state");
		}
	}
	else if (protocol_layer == eap_protocol_layer_internal_type
		|| protocol_layer == eap_protocol_layer_am_eap_type
		|| protocol_layer == eap_protocol_layer_eap_type
		|| protocol_layer == eap_protocol_layer_eap)
	{
		EAP_IF_RETURN_STRING(state, eap_state_none)
		else EAP_IF_RETURN_STRING(state, eap_state_identity_request_sent)
		else EAP_IF_RETURN_STRING(state, eap_state_identity_request_received)
		else EAP_IF_RETURN_STRING(state, eap_state_identity_response_received)
		else EAP_IF_RETURN_STRING(state, eap_state_eap_response_sent)
		else EAP_IF_RETURN_STRING(state, eap_state_tppd_peapv1_authentication_finished_successfully_with_tunneled_eap_success)
		else EAP_IF_RETURN_STRING(state, eap_state_authentication_finished_successfully)
		else EAP_IF_RETURN_STRING(state, eap_state_authentication_terminated_unsuccessfully)
		else EAP_IF_RETURN_STRING(state, eap_state_authentication_wait_tppd_peapv1_empty_acknowledge)
		else EAP_IF_RETURN_STRING(state, eap_state_use_eap_failure_in_termination)
		else EAP_IF_RETURN_STRING(state, eap_state_inner_eap_method_skipped)
		else EAP_IF_RETURN_STRING(state, eap_state_authentication_wait_eap_fast_empty_acknowledge)
		else EAP_IF_RETURN_STRING(state, eap_state_wait_plain_eap_success)
		else
		{
			return EAPL("Unknown EAP state");
		}
	}
	else if (protocol_layer == eap_protocol_layer_eapol)
	{
		EAP_IF_RETURN_STRING(state, eapol_state_none)
		else EAP_IF_RETURN_STRING(state, eapol_state_start_sent)
		else EAP_IF_RETURN_STRING(state, eapol_state_no_start_response)
		else
		{
			return EAPL("Unknown EAPOL state");
		}
	}
	else if (protocol_layer == eap_protocol_layer_eapol_key)
	{
		EAP_IF_RETURN_STRING(state, eapol_key_state_none)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_preauthenticated)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_eap_authentication_running)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_4_way_handshake_start)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_4_way_handshake_message_1)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_4_way_handshake_message_2)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_4_way_handshake_message_3)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_4_way_handshake_message_4)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_4_way_handshake_running)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_4_way_handshake_failed)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_4_way_handshake_successfull)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_group_key_handshake_message_1)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_group_key_handshake_message_2)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_group_key_handshake_failed)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_group_key_handshake_successfull)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_rc4_key_message)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_802_11i_authentication_terminated_unsuccessfull)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_802_11i_authentication_finished_successfull)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_reassociation_failed)
#if defined(EAP_USE_WPXM)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_wpxm_reassociation_finished_successfull)
#endif //#if defined(EAP_USE_WPXM)
		else
		{
			return EAPL("Unknown EAPOL state");
		}
	}
#if defined(USE_WAPI_CORE)
	else if (protocol_layer == eap_protocol_layer_wapi)
	{
		EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_none)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_this_ap_failed)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_authentication_successfull)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_wapi_authentication_running)
		else
		{
			return EAPL("Unknown WAPI state");
		}
	}
	else if (protocol_layer == eap_protocol_layer_wai)
	{
		EAP_IF_RETURN_STRING(state, eapol_key_state_none)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_wapi_authentication_terminated_unsuccessfull)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_wapi_authentication_finished_successfull)
		else EAP_IF_RETURN_STRING(state, eapol_key_state_wapi_authentication_running)
		else
		{
			return EAPL("Unknown WAI state");
		}
	}
#endif //#if defined(USE_WAPI_CORE)
	else if (protocol_layer == eap_protocol_layer_ethernet)
	{
		return EAPL("Unknown ethernet state");
	}
	else if (protocol_layer == eap_protocol_layer_wlan_authentication)
	{
		EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_none)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_association_ok)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_this_ap_failed)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_failed_completely)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_802_11_auth_algorithm_not_supported)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_authenticating)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_eap_authentication_running)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_no_response)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_4_way_handshake_running)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_authentication_successfull)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_authentication_cancelled)
		else EAP_IF_RETURN_STRING(state, eapol_wlan_authentication_state_immediate_reconnect)
		else
		{
			return EAPL("Unknown wauth state");
		}
	}
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(protocol_layer);
		EAP_UNREFERENCED_PARAMETER(state);

		return EAPL("Unknown state");
	}
}

EAP_FUNC_EXPORT eap_const_string eap_state_notification_c::get_current_state_string() const
{
	return get_state_string(m_layer, m_current_state);
}

EAP_FUNC_EXPORT eap_const_string eap_state_notification_c::get_previous_state_string() const
{
	return get_state_string(m_layer, m_previous_state);
}

EAP_FUNC_EXPORT eap_const_string eap_state_notification_c::get_protocol_layer_string(const u32_t protocol_layer)
{

#if defined(USE_EAP_TRACE_STRINGS)

	EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_none)
	else EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_general)
	else EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_internal_type)
	else EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_am_eap_type)
	else EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_radius)
	else EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_eap_type)
	else EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_eap)
	else EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_eapol)
	else EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_eapol_key)
	else EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_ethernet)
	else EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_wlan_authentication)
	else EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_authentication_server)
#if defined(USE_WAPI_CORE)
	else EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_wapi)
	else EAP_IF_RETURN_STRING(protocol_layer, eap_protocol_layer_wai)
#endif //#if defined(USE_WAPI_CORE)

#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(protocol_layer);

		return EAPL("Unknown protocol layer");
	}
}

EAP_FUNC_EXPORT eap_const_string eap_state_notification_c::get_protocol_layer_string() const
{
	return get_protocol_layer_string(m_layer);
}

EAP_FUNC_EXPORT eap_const_string eap_state_notification_c::get_protocol_string(const u32_t protocol_layer, const u32_t protocol)
{

#if defined(USE_EAP_TRACE_STRINGS)

	if (protocol_layer == eap_protocol_layer_general)
	{
		return EAPL("No general protocol");
	}
	else if (protocol_layer == eap_protocol_layer_internal_type
		|| protocol_layer == eap_protocol_layer_am_eap_type
		|| protocol_layer == eap_protocol_layer_eap_type
		|| protocol_layer == eap_protocol_layer_eap)
	{
		return EAPL("No EAP protocol");
	}
	else if (protocol_layer == eap_protocol_layer_eapol)
	{
		return EAPL("No EAPOL protocol");
	}
	else if (protocol_layer == eap_protocol_layer_eapol_key)
	{
		EAP_IF_RETURN_STRING(protocol, eapol_key_handshake_type_none)
		else EAP_IF_RETURN_STRING(protocol, eapol_key_handshake_type_4_way_handshake)
		else EAP_IF_RETURN_STRING(protocol, eapol_key_handshake_type_group_key_handshake)
		else EAP_IF_RETURN_STRING(protocol, eapol_key_handshake_type_STAKey_handshake)
		else EAP_IF_RETURN_STRING(protocol, eapol_key_handshake_type_802_11i_handshake)
		else EAP_IF_RETURN_STRING(protocol, eapol_key_handshake_type_dynamic_WEP)
#if defined(EAP_USE_WPXM)
		else EAP_IF_RETURN_STRING(protocol, eapol_key_handshake_type_WPXM_reassociation)
#endif //#if defined(EAP_USE_WPXM)
#if defined(USE_WAPI_CORE)
		else EAP_IF_RETURN_STRING(protocol, eapol_key_handshake_type_wai_handshake)
#endif //#if defined(USE_WAPI_CORE)
		else EAP_IF_RETURN_STRING(protocol, eapol_key_handshake_type_authenticated)
		else
		{
			return EAPL("Unknown EAPOL protocol");
		}
	}
	else if (protocol_layer == eap_protocol_layer_ethernet)
	{
		return EAPL("No ethernet protocol");
	}
	else if (protocol_layer == eap_protocol_layer_wlan_authentication)
	{
		{
			return EAPL("No wauth protocol");
		}
	}
#if defined(USE_WAPI_CORE)
	else if (protocol_layer == eap_protocol_layer_wapi)
	{
		EAP_IF_RETURN_STRING(protocol, eapol_key_handshake_type_none)
		else EAP_IF_RETURN_STRING(protocol, eapol_key_handshake_type_wai_handshake)
		else
		{
			return EAPL("Unknown WAPI protocol");
		}
	}
	else if (protocol_layer == eap_protocol_layer_wai)
	{
		EAP_IF_RETURN_STRING(protocol, eapol_key_handshake_type_none)
		else EAP_IF_RETURN_STRING(protocol, eapol_key_handshake_type_wai_handshake)
		else
		{
			return EAPL("Unknown WAI protocol");
		}
	}
#endif //#if defined(USE_WAPI_CORE)
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(protocol_layer);
		EAP_UNREFERENCED_PARAMETER(protocol);

		return EAPL("Unknown protocol");
	}
}

EAP_FUNC_EXPORT eap_const_string eap_state_notification_c::get_protocol_string() const
{
	return get_protocol_string(m_layer, m_protocol);
}

EAP_FUNC_EXPORT bool eap_state_notification_c::get_is_client() const
{
	return m_is_client;
}

EAP_FUNC_EXPORT u8_t eap_state_notification_c::get_eap_identifier() const
{
	return m_eap_identifier;
}

EAP_FUNC_EXPORT bool eap_state_notification_c::get_allow_send_eap_success() const
{
	return m_allow_send_eap_success;
}

EAP_FUNC_EXPORT eap_status_e eap_state_notification_c::set_notification_string(
	const eap_variable_data_c * const notification_string,
	const bool needs_confirmation_from_user)
{
	eap_status_e status = m_notification_string.set_copy_of_buffer(notification_string);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_needs_confirmation_from_user = needs_confirmation_from_user;

	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT const eap_variable_data_c * eap_state_notification_c::get_notification_string() const
{
	return &m_notification_string;
}

EAP_FUNC_EXPORT bool eap_state_notification_c::get_needs_confirmation_from_user() const
{
	return m_needs_confirmation_from_user;
}


EAP_FUNC_EXPORT void eap_state_notification_c::set_authentication_error(const eap_status_e error)
{
	m_authentication_error = error;
}

EAP_FUNC_EXPORT eap_status_e eap_state_notification_c::get_authentication_error() const
{
	return m_authentication_error;
}

//--------------------------------------------------



// End.
