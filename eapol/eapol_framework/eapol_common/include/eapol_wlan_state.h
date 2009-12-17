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




#if !defined(_EAPOL_WLAN_STATE_H_)
#define _EAPOL_WLAN_STATE_H_

#include "eap_type_selection.h"
#include "eap_array.h"
#include "eapol_key_state.h"

//--------------------------------------------------

class abs_eap_am_tools_c;


/// wlan_state_c class stores information of one supported EAP-type.
class EAP_EXPORT eapol_wlan_state_c
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
	EAP_FUNC_IMPORT virtual ~eapol_wlan_state_c();

	/**
	 * The constructor of the eapol_wlan_state_c class does nothing special.
	 */
	EAP_FUNC_IMPORT eapol_wlan_state_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the object.
	 * @return True indicates the object is initialized.
	 */
	EAP_FUNC_IMPORT bool get_is_valid() const;

}; // class eapol_wlan_state_c


#endif //#if !defined(_EAPOL_WLAN_STATE_H_)

//--------------------------------------------------


// End.
