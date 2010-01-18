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
* %version: 9 %
*/

#if !defined(_WLAN_EAP_IF_SEND_STATUS_H_)
#define _WLAN_EAP_IF_SEND_STATUS_H_

//--------------------------------------------------

#include "eap_am_export.h"
#include "eap_am_types.h"
#include "eap_status.h"

/** @file */

/**
 * This enumeration defines the return values of abs_eapol_message_wlan_authentication_c::send_data() function.
 */
enum wlan_eap_if_send_status_e
{
    wlan_eap_if_send_status_ok,
    wlan_eap_if_send_status_pending_request,
    wlan_eap_if_send_status_allocation_error,
    wlan_eap_if_send_status_illegal_parameter,
    wlan_eap_if_send_status_process_general_error,
    wlan_eap_if_send_status_not_found,
    wlan_eap_if_send_status_success,
	wlan_eap_if_send_status_drop_packet_quietly,
};


/// This class is converts the status values between wlan_eap_if_send_status_e and eap_status_e.
class EAP_EXPORT_INTERFACE wlan_eap_if_send_status_conversion_c
{

public:

	EAP_FUNC_IMPORT_INTERFACE static wlan_eap_if_send_status_e convert(const eap_status_e status);

	EAP_FUNC_IMPORT_INTERFACE static eap_status_e convert(const wlan_eap_if_send_status_e status);

}; // class abs_eapol_message_wlan_authentication_c


#endif //#if !defined(_WLAN_EAP_IF_SEND_STATUS_H_)

//--------------------------------------------------


// End.
