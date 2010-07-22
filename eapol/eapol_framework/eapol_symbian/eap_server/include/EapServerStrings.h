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
* %version: 5 %
*/

#if !defined( _EAP_SERVER_STRINGS_H_ )
#define _EAP_SERVER_STRINGS_H_

/** @file */

#include "EapServerClientDef.h"
#include "eap_am_types.h"

//----------------------------------------------------------------------------------

/// This class includes the debug strings of the EAP-SERVER.
class EapServerStrings
{
public:

	IMPORT_C virtual ~EapServerStrings();

	IMPORT_C EapServerStrings();

	/**
	 * Function returns string of TEapRequests.
	 * @param request is the queried string.
	 */
	IMPORT_C static eap_const_string GetEapRequestsString(const TEapRequests request);

	/**
	 * Function returns string of TEapRequests.
	 * @param request is the queried string.
	 */
	IMPORT_C static eap_const_string GetEapRequestsString(const TInt request);

};

//----------------------------------------------------------------------------------

#endif //#if !defined( _EAP_SERVER_STRINGS_H_ )

// End.
