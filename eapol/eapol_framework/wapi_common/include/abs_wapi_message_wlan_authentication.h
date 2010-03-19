/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/abs_wapi_message_wlan_authentication.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 4 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.2
*/


#if !defined(_ABS_WAPI_MESSAGE_WLAN_AUTHENTICATION_H_)
#define _ABS_WAPI_MESSAGE_WLAN_AUTHENTICATION_H_

//--------------------------------------------------

#include "eap_am_export.h"
#include "eap_am_types.h"
#include "eap_status.h"
#include "wlan_eap_if_send_status.h"

/** @file */

/// This class is abstract interface to send data messages through abstract interface.
class EAP_EXPORT abs_wapi_message_wlan_authentication_c
{

private:
	//--------------------------------------------------

	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~abs_wapi_message_wlan_authentication_c()
	{
	}

	/// Function sends the data message to lower layer.
	/// Data is formatted to Attribute-Value Pairs.
	/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
	virtual wlan_eap_if_send_status_e send_data(const void * const data, const u32_t length) = 0;

}; // class abs_wapi_message_wlan_authentication_c


#endif //#if !defined(_ABS_WAPI_MESSAGE_WLAN_AUTHENTICATION_H_)

//--------------------------------------------------


// End.
