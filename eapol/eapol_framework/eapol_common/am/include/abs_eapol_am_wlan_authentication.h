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

#if !defined(_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H_)
#define _ABS_EAPOL_AM_WLAN_AUTHENTICATION_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H 
#elif defined(EAP_EXPORT_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H 
#endif
// End: added by script change_export_macros.sh.
#include "eapol_key_types.h"

/// This class declares the functions adaptation module of GSMSIM EAP type
/// requires from the GSMSIM EAP type.
class EAP_CLASS_VISIBILITY_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H abs_eapol_am_wlan_authentication_c
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
	virtual ~abs_eapol_am_wlan_authentication_c()
	{
	}

	// 
	abs_eapol_am_wlan_authentication_c()
	{
	}

	/**
	 *	This function disassociates the connection.
	 */
	virtual eap_status_e disassociation(
		const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
		) = 0;

	/**
	 *	This function gets the current active eap index.
	 */
	virtual u32_t get_current_eap_index() = 0;

	/**
	 *	This function sets the current active eap index.
	 */
	virtual void set_current_eap_index(u32_t eap_index) = 0;

	/**
	 *	This function indicates the state of WLAN authentication.
	 */
	virtual eap_status_e eapol_indication(
		const eap_am_network_id_c * const receive_network_id, ///< source includes remote address, destination includes local address.
		const eapol_wlan_authentication_state_e wlan_authentication_state) = 0;

	/**
	 * This is notification of internal state transition.
	 * This is used for notifications, debugging and protocol testing.
	 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
	 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully. EAP-type MUST send these
	 * two notifications to lower layer.
	 * These two notifications are sent using EAP-protocol layer (eap_protocol_layer_e::eap_protocol_layer_eap).
	 * See also eap_state_notification_c.
	 */
	virtual void state_notification(
		const abs_eap_state_notification_c * const state) = 0;

	//--------------------------------------------------
}; // class abs_eapol_am_wlan_authentication_c

#endif //#if !defined(_ABS_EAPOL_AM_WLAN_AUTHENTICATION_H_)

//--------------------------------------------------



// End.
