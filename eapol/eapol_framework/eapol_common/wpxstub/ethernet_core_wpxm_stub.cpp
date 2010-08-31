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
	#define EAP_FILE_NUMBER_ENUM 587 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_variable_data.h"
#include "eap_tools.h"
#include "ethernet_core.h"
#include "eapol_ethernet_header.h"
#include "eap_buffer.h"
#include "eapol_session_key.h"


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::start_WPXM_reassociation(
	const eap_am_network_id_c * const /* receive_network_id */,
	const eapol_key_authentication_type_e /* authentication_type */,
	eap_variable_data_c * const /* send_reassociation_request_ie */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ethernet_core_c::complete_WPXM_reassociation(
	const eapol_wlan_authentication_state_e /* reassociation_result */,
	const eap_am_network_id_c * const /* receive_network_id */,
	const eapol_key_authentication_type_e /* authentication_type */,
	const eap_variable_data_c * const /* received_reassociation_ie */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

// End.
