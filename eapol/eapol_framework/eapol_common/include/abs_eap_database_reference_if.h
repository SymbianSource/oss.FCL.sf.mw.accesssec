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

#if !defined(_ABS_EAPOL_WLAN_DATABASE_REFERENCE_IF_H_)
#define _ABS_EAPOL_WLAN_DATABASE_REFERENCE_IF_H_

//--------------------------------------------------

#include "eap_am_export.h"
#include "eap_am_types.h"
#include "eap_status.h"


/// This class is abstract interface to reference of WLAN database of the current connection.
class EAP_EXPORT abs_eap_database_reference_if_c_deprecated
{

private:
	//--------------------------------------------------

	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~abs_eap_database_reference_if_c_deprecated()
	{
	}

	/**
	 * The constructor of the abs_eap_database_reference_if_c class does nothing special.
	 */
	virtual eap_status_e get_wlan_database_reference_values(
		eap_variable_data_c * const reference) const = 0;

}; // class abs_eap_database_reference_if_c


#endif //#if !defined(_ABS_EAPOL_WLAN_DATABASE_REFERENCE_IF_H_)

//--------------------------------------------------


// End.
