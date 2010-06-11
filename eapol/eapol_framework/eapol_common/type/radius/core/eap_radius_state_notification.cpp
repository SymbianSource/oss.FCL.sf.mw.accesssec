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
	#define EAP_FILE_NUMBER_ENUM 113 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_radius_state_notification.h"
#include "eap_radius_types.h"
#include "eap_tools.h"
#include "eap_radius.h"


EAP_FUNC_EXPORT eap_radius_state_notification_c::~eap_radius_state_notification_c()
{
}

EAP_FUNC_EXPORT eap_radius_state_notification_c::eap_radius_state_notification_c(
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
	, m_send_network_id(send_network_id)
	, m_is_client(is_client)
	, m_eap_identifier(eap_identifier)
	, m_allow_send_eap_success(allow_send_eap_success)
{
}


EAP_FUNC_EXPORT eap_radius_state_notification_c::eap_radius_state_notification_c(
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
	, m_send_network_id(send_network_id)
	, m_is_client(is_client)
	, m_eap_identifier(eap_identifier)
	, m_allow_send_eap_success(allow_send_eap_success)
{
}


EAP_FUNC_EXPORT eap_radius_state_notification_c::eap_radius_state_notification_c(
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
	, m_send_network_id(send_network_id)
	, m_is_client(is_client)
	, m_eap_identifier(eap_identifier)
	, m_allow_send_eap_success(allow_send_eap_success)
{
}

EAP_FUNC_EXPORT const eap_am_network_id_c * eap_radius_state_notification_c::get_send_network_id() const
{
	return m_send_network_id;
}

EAP_FUNC_EXPORT eap_protocol_layer_e eap_radius_state_notification_c::get_protocol_layer() const
{
	return m_layer;
}

EAP_FUNC_EXPORT u32_t eap_radius_state_notification_c::get_protocol() const
{
	return m_protocol;
}

EAP_FUNC_EXPORT eap_type_value_e eap_radius_state_notification_c::get_eap_type() const
{
	return m_eap_type;
}

EAP_FUNC_EXPORT u32_t eap_radius_state_notification_c::get_previous_state() const
{
	return m_previous_state;
}

EAP_FUNC_EXPORT u32_t eap_radius_state_notification_c::get_current_state() const
{
	return m_current_state;
}

EAP_FUNC_EXPORT eap_const_string eap_radius_state_notification_c::get_current_state_string() const
{
	// NOTE this is static function.
	return eap_radius_c::get_state_string(static_cast<eap_radius_state_variable_e>(m_current_state));
}

EAP_FUNC_EXPORT eap_const_string eap_radius_state_notification_c::get_previous_state_string() const
{
	// NOTE this is static function.
	return eap_radius_c::get_state_string(static_cast<eap_radius_state_variable_e>(m_previous_state));
}

EAP_FUNC_EXPORT bool eap_radius_state_notification_c::get_is_client() const
{
	return m_is_client;
}

EAP_FUNC_EXPORT u8_t eap_radius_state_notification_c::get_eap_identifier() const
{
	return m_eap_identifier;
}

EAP_FUNC_EXPORT bool eap_radius_state_notification_c::get_allow_send_eap_success() const
{
	return m_allow_send_eap_success;
}

EAP_FUNC_EXPORT eap_status_e eap_radius_state_notification_c::set_notification_string(
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

EAP_FUNC_EXPORT const eap_variable_data_c * eap_radius_state_notification_c::get_notification_string() const
{
	return &m_notification_string;
}

EAP_FUNC_EXPORT bool eap_radius_state_notification_c::get_needs_confirmation_from_user() const
{
	return m_needs_confirmation_from_user;
}

//--------------------------------------------------



// End.
