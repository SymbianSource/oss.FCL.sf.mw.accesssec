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

#if !defined(_EAPOL_WLAN_STATE_H_)
#define _EAPOL_WLAN_STATE_H_

#include "eap_type_selection.h"
#include "eap_array.h"
#include "eapol_key_state.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_WLAN_STATE_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_WLAN_STATE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_WLAN_STATE_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_WLAN_STATE_H 
	#define EAP_FUNC_EXPORT_EAPOL_WLAN_STATE_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_WLAN_STATE_H 
#elif defined(EAP_EXPORT_EAPOL_WLAN_STATE_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_WLAN_STATE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_WLAN_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_WLAN_STATE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_WLAN_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_WLAN_STATE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_WLAN_STATE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_WLAN_STATE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_WLAN_STATE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_WLAN_STATE_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_WLAN_STATE_H 
#endif
// End: added by script change_export_macros.sh.


//--------------------------------------------------

class abs_eap_am_tools_c;


/// wlan_state_c class stores information of one supported EAP-type.
class EAP_CLASS_VISIBILITY_EAPOL_WLAN_STATE_H eapol_wlan_state_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	bool m_is_valid;

	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eapol_wlan_state_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_STATE_H virtual ~eapol_wlan_state_c();

	/**
	 * The constructor of the eapol_wlan_state_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_STATE_H eapol_wlan_state_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the object.
	 * @return True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_WLAN_STATE_H bool get_is_valid() const;

}; // class eapol_wlan_state_c


#endif //#if !defined(_EAPOL_WLAN_STATE_H_)

//--------------------------------------------------


// End.
