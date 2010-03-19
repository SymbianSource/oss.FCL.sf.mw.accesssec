/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/abs_wapi_am_wlan_authentication.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 5 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_ABS_WAPI_AM_WLAN_AUTHENTICATION_H_)
#define _ABS_WAPI_AM_WLAN_AUTHENTICATION_H_

#include "eap_am_export.h"
#include "eapol_key_types.h"

/// This class declares the functions the adaptation module of WAPI
/// requires from wapi_wlan_authentication_c
class EAP_EXPORT abs_wapi_am_wlan_authentication_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~abs_wapi_am_wlan_authentication_c()
	{
	}

	// 
	abs_wapi_am_wlan_authentication_c()
	{
	}

	/**
	 *	This function disassociates the connection.
	 */
	virtual eap_status_e disassociation(
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		) = 0;


	/**
	 *	This function indicates the state of WLAN authentication.
	 */
	virtual eap_status_e wapi_indication(
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		const eapol_wlan_authentication_state_e wlan_authentication_state) = 0;

	/**
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully. WAPI MUST send these
	 * two notifications to lower layer.
	 * These two notifications are sent using WAPI-protocol layer (eap_protocol_layer_e::eap_protocol_layer_wapi).
	 * See also eap_state_notification_c.
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

	//--------------------------------------------------
}; // class abs_wapi_am_wlan_authentication_c

#endif //#if !defined(_ABS_WAPI_AM_WLAN_AUTHENTICATION_H_)

//--------------------------------------------------



// End.
