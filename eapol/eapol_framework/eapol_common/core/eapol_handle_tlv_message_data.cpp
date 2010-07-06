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
* %version: 36 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 715 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_automatic_variable.h"
#include "eapol_handle_tlv_message_data.h"
#include "eap_variable_data.h"
#include "eap_am_network_id.h"
#include "eap_buffer.h"
#include "eapol_session_key.h"
#include "abs_eap_state_notification.h"
#include "eap_state_notification.h"

#if defined(USE_EAP_SIMPLE_CONFIG)
#include "simple_config_types.h"
#include "simple_config_credential.h"
#include "simple_config_payloads.h"
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)


/** @file */


//--------------------------------------------------

EAP_FUNC_EXPORT eapol_handle_tlv_message_data_c::~eapol_handle_tlv_message_data_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eapol_handle_tlv_message_data_c::eapol_handle_tlv_message_data_c(
	abs_eap_am_tools_c * const tools)
	: eap_process_tlv_message_data_c(tools)
	, m_am_tools(tools)
	, m_is_valid(true)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eapol_handle_tlv_message_data_c::get_is_valid()
{
	return m_is_valid && eap_process_tlv_message_data_c::get_is_valid();
}

//--------------------------------------------------
// End.
