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
	#define EAP_FILE_NUMBER_ENUM 84 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_type_gsmsim_state_notification.h"
#include "eap_type_gsmsim_types.h"
#include "eap_tools.h"
#include "eap_type_gsmsim.h"


EAP_FUNC_EXPORT eap_type_gsmsim_state_notification_c::~eap_type_gsmsim_state_notification_c()
{
}

EAP_FUNC_EXPORT eap_type_gsmsim_state_notification_c::eap_type_gsmsim_state_notification_c(
	abs_eap_am_tools_c * const tools,
	const eap_am_network_id_c * const send_network_id,
	bool is_client,
	eap_state_notification_generic_e type,
	eap_protocol_layer_e layer,
	u32_t protocol,
	u32_t previous_state,
	u32_t current_state,
	u8_t eap_identifier,
	bool allow_send_eap_success)
	: eap_state_notification_c(
		tools,
		send_network_id,
		is_client,
		type,
		layer,
		protocol,
		previous_state,
		current_state,
		eap_identifier,
		allow_send_eap_success)
{
}


EAP_FUNC_EXPORT eap_type_gsmsim_state_notification_c::eap_type_gsmsim_state_notification_c(
	abs_eap_am_tools_c * const tools,
	const eap_am_network_id_c * const send_network_id,
	bool is_client,
	eap_state_notification_eap_e type,
	eap_protocol_layer_e layer,
	eap_type_value_e eap_type,
	u32_t previous_state,
	u32_t current_state,
	u8_t eap_identifier,
	bool allow_send_eap_success)
	: eap_state_notification_c(
		tools,
		send_network_id,
		is_client,
		type,
		layer,
		eap_type,
		previous_state,
		current_state,
		eap_identifier,
		allow_send_eap_success)
{
}


EAP_FUNC_EXPORT eap_type_gsmsim_state_notification_c::eap_type_gsmsim_state_notification_c(
	abs_eap_am_tools_c * const tools,
	const eap_am_network_id_c * const send_network_id,
	bool is_client,
	eap_state_notification_eap_e type,
	eap_protocol_layer_e layer,
	eap_type_ietf_values_e eap_type,
	u32_t previous_state,
	u32_t current_state,
	u8_t eap_identifier,
	bool allow_send_eap_success)
	: eap_state_notification_c(
		tools,
		send_network_id,
		is_client,
		type,
		layer,
		eap_type,
		previous_state,
		current_state,
		eap_identifier,
		allow_send_eap_success)
{
}

//--------------------------------------------------

// End.
