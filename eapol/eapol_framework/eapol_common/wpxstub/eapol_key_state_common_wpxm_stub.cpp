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
	#define EAP_FILE_NUMBER_ENUM 583 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eapol_key_state.h"
#include "eapol_key_header.h"
#include "eap_crypto_api.h"
#include "abs_eap_am_mutex.h"
#include "eap_state_notification.h"
#include "eap_automatic_variable.h"
#include "eapol_rsna_key_data_gtk_header.h"
#include "abs_eapol_core.h"
#include "abs_eapol_key_state.h"
#include "eap_core_retransmission.h"
#include "eapol_rsna_key_data_payloads.h"
#include "eap_buffer.h"
#include "eapol_session_key.h"

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::set_WPXM_parameters(
	const eap_am_network_id_c * const /* receive_network_id */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::start_WPXM_reassociation(
	const eap_am_network_id_c * const /*receive_network_id*/,
	const eapol_key_authentication_type_e /*authentication_type*/,
	eap_variable_data_c * const /* send_reassociation_request_ie */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_key_state_c::complete_WPXM_reassociation(
	const eapol_wlan_authentication_state_e /*reassociation_result*/,
	const eap_am_network_id_c * const /*receive_network_id*/,
	const eapol_key_authentication_type_e /*authentication_type*/,
	const eap_variable_data_c * const /* received_reassociation_ie */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eapol_key_state_c::get_is_WPXM()
{
	return false;
}

//--------------------------------------------------

//
eap_status_e eapol_key_state_c::derive_WPXM_WPXK1_WPXK2()
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
eap_status_e eapol_key_state_c::save_keys_for_test_use(
	const eap_variable_data_c * const /* confirmation_KCK */,
	const eap_variable_data_c * const /* encryption_KEK */,
	const eap_variable_data_c * const /* temporal_TK */,
	const u32_t /* WPXM_WPXC */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
eap_status_e eapol_key_state_c::derive_WPXM_PTK(const u32_t /* WPXM_WPXC */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

// End.
