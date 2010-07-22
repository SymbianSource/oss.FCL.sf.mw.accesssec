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
	#define EAP_FILE_NUMBER_ENUM 118 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_tls_peap_state_notification.h"
#include "eap_type_tls_peap.h"
#include "eap_tools.h"


EAP_FUNC_EXPORT eap_tls_peap_state_notification_c::~eap_tls_peap_state_notification_c()
{
}

EAP_FUNC_EXPORT eap_tls_peap_state_notification_c::eap_tls_peap_state_notification_c(
	const eap_am_network_id_c * const send_network_id,
	eap_boolean_e is_client,
	eap_protocol_layer_e layer,
	u32_t protocol,
	u32_t previous_state,
	u32_t current_state,
	u8_t eap_identifier,
	eap_boolean_e allow_send_eap_success)
	: m_layer(layer)
	, m_protocol(protocol)
	, m_previous_state(previous_state)
	, m_current_state(current_state)
	, m_send_network_id(send_network_id)
	, m_is_client(is_client)
	, m_eap_identifier(eap_identifier)
	, m_allow_send_eap_success(allow_send_eap_success)
{
}

EAP_FUNC_EXPORT const eap_am_network_id_c * const eap_tls_peap_state_notification_c::get_send_network_id() const
{
	return m_send_network_id;
}

EAP_FUNC_EXPORT const eap_protocol_layer_e eap_tls_peap_state_notification_c::get_protocol_layer() const
{
	return m_layer;
}

EAP_FUNC_EXPORT const u32_t eap_tls_peap_state_notification_c::get_protocol() const
{
	return m_protocol;
}

EAP_FUNC_EXPORT const u32_t eap_tls_peap_state_notification_c::get_previous_state() const
{
	return m_previous_state;
}

EAP_FUNC_EXPORT const u32_t eap_tls_peap_state_notification_c::get_current_state() const
{
	return m_current_state;
}

EAP_FUNC_EXPORT eap_const_string eap_tls_peap_state_notification_c::get_current_state_string() const
{
	// NOTE this is static function.
	return eap_type_tls_peap_c::get_state_string((eap_type_tls_peap_state_variable_e)m_current_state);
}

EAP_FUNC_EXPORT eap_const_string eap_tls_peap_state_notification_c::get_previous_state_string() const
{
	// NOTE this is static function.
	return eap_type_tls_peap_c::get_state_string((eap_type_tls_peap_state_variable_e)m_previous_state);
}

EAP_FUNC_EXPORT const eap_boolean_e eap_tls_peap_state_notification_c::get_is_client() const
{
	return m_is_client;
}

EAP_FUNC_EXPORT const u8_t eap_tls_peap_state_notification_c::get_eap_identifier() const
{
	return m_eap_identifier;
}

EAP_FUNC_EXPORT eap_boolean_e eap_tls_peap_state_notification_c::get_allow_send_eap_success() const
{
	return m_allow_send_eap_success;
}

//--------------------------------------------------



// End.
