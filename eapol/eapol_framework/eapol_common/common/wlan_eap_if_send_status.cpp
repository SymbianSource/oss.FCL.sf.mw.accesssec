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
* %version: 7.1.3 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 760 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "eap_am_export.h"
#include "eap_am_types.h"
#include "eap_status.h"
#include "wlan_eap_if_send_status.h"

/** @file */

EAP_FUNC_EXPORT wlan_eap_if_send_status_e wlan_eap_if_send_status_conversion_c::convert(const eap_status_e status)
{
	switch(status)
	{
	case eap_status_ok:
		return wlan_eap_if_send_status_ok;
	case eap_status_pending_request:
	    return wlan_eap_if_send_status_pending_request;
	case eap_status_allocation_error:
	    return wlan_eap_if_send_status_allocation_error;
	case eap_status_illegal_parameter:
	    return wlan_eap_if_send_status_illegal_parameter;
	case eap_status_not_found:
	    return wlan_eap_if_send_status_not_found;
	case eap_status_success:
	    return wlan_eap_if_send_status_success;
	case eap_status_drop_packet_quietly:
	    return wlan_eap_if_send_status_drop_packet_quietly;
	default:
	    return wlan_eap_if_send_status_process_general_error;
	}
}

EAP_FUNC_EXPORT eap_status_e wlan_eap_if_send_status_conversion_c::convert(const wlan_eap_if_send_status_e status)
{
	switch(status)
	{
	case wlan_eap_if_send_status_ok:
		return eap_status_ok;
	case wlan_eap_if_send_status_pending_request:
		return eap_status_pending_request;
	case wlan_eap_if_send_status_allocation_error:
		return eap_status_allocation_error;
	case wlan_eap_if_send_status_illegal_parameter:
		return eap_status_illegal_parameter;
	case wlan_eap_if_send_status_not_found:
		return eap_status_not_found;
	case wlan_eap_if_send_status_success:
		return eap_status_success;
	case wlan_eap_if_send_status_drop_packet_quietly:
		return eap_status_drop_packet_quietly;
	default:
	    return eap_status_process_general_error;
	}
}

//--------------------------------------------------


// End.
