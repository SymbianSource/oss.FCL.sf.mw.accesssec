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
* %version: 6.1.7 %
*/

#ifndef EAPSECURIDDBUTILS_H
#define EAPSECURIDDBUTILS_H

// INCLUDES
#include <d32dbms.h>
#include <EapType.h>
#include "eap_header.h"

// LOCAL CONSTANTS

// For EAP-GTC private database. Database will be in the private folder of EAP-server (20026FCB).
// The maximum length of database name is 0x40 (KDbMaxName), which is defined in d32dbms.h.

_LIT(KSecurIDDatabaseName, "eapsecurid.dat");

_LIT(KSecurIDTableName, "eapsecurid");

// CLASS DECLARATION
class EapSecurIDDbUtils 
{
public:
	
	/**
	* Opens database
	* @param aDatabase Handle to database
	* @param aSession Handle to session
	* @param aIndexType Bearer type
	* @param aIndex Index
	*/
	static void OpenDatabaseL(
		RDbNamedDatabase& aDatabase,
		RFs& aFileServerSession,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType);
};

#endif // EAPSECURIDDBUTILS_H

// End of File
