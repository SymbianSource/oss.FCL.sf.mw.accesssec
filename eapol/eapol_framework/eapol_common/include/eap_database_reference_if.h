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

#if !defined(_EAPOL_WLAN_DATABASE_REFERENCE_IF_H_)
#define _EAPOL_WLAN_DATABASE_REFERENCE_IF_H_

//--------------------------------------------------

#include "eap_am_export.h"
#include "eap_am_types.h"
#include "eap_status.h"


/// This class is abstract interface to reference of WLAN database of the current connection.
class EAP_EXPORT eap_database_reference_if_c
{

private:
	//--------------------------------------------------

	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~eap_database_reference_if_c()
	{
	}

	virtual eap_status_e set_eap_database_reference_values(
		const eap_variable_data_c * const reference) = 0;

}; // class eap_database_reference_if_c


#endif //#if !defined(_EAPOL_WLAN_DATABASE_REFERENCE_IF_H_)

//--------------------------------------------------


// End.
