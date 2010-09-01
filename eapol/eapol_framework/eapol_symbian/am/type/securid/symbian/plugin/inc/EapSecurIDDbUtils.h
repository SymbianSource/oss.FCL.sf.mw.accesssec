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
* %version: 8 %
*/

#ifndef EAPSECURIDDBUTILS_H
#define EAPSECURIDDBUTILS_H

// INCLUDES
#include <d32dbms.h>
#include <EapType.h>
#include "eap_header.h"

// LOCAL CONSTANTS

#ifdef SYMBIAN_SECURE_DBMS
// For EAP SecureID secure database.
// Full path is not needed. The database eapsecurid.dat will be saved in the 
// data cage path for DBMS. So it will be in "\private\100012a5\eapsecurid.dat" in C: drive.
// The maximum length of database name is 0x40 (KDbMaxName) , which is defined in d32dbms.h.

_LIT(KDatabaseName, "c:eapsecurid.dat");

_LIT(KSecureUIDFormat, "SECURE[102072e9]"); // For the security policy.

#else

_LIT(KDatabaseName, "c:\\system\\data\\eapsecurid.dat");

#endif // #ifdef SYMBIAN_SECURE_DBMS

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
		RDbs& aSession, 
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType);
};

#endif // EAPSECURIDDBUTILS_H

// End of File
