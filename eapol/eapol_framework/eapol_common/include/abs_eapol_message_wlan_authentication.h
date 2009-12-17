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



#if !defined(_ABS_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H_)
#define _ABS_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H_

//--------------------------------------------------

#include "eap_am_export.h"
#include "eap_am_types.h"
#include "eap_status.h"
#include "wlan_eap_if_send_status.h"

/** @file */

/// This class is abstract interface to send data messages through abstract interface.
class EAP_EXPORT abs_eapol_message_wlan_authentication_c
{

private:
	//--------------------------------------------------

	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~abs_eapol_message_wlan_authentication_c()
	{
	}

	/// Function sends the data message to lower layer.
	/// Data is formatted to Attribute-Value Pairs.
	/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
	virtual wlan_eap_if_send_status_e send_data(const void * const data, const u32_t length) = 0;

}; // class abs_eapol_message_wlan_authentication_c


#endif //#if !defined(_ABS_EAPOL_MESSAGE_WLAN_AUTHENTICATION_H_)

//--------------------------------------------------


// End.
