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
* %version: 10 %
*/

#ifndef _EAPSIMDBUTILS_H_
#define _EAPSIMDBUTILS_H_

// INCLUDES
#include <d32dbms.h>
#include <EapType.h>
#include "eap_header.h"

// LOCAL CONSTANTS

#ifdef SYMBIAN_SECURE_DBMS
// For EAP SIM secure database.
// Full path is not needed. The database eapsim.dat will be saved in the 
// data cage path for DBMS. So it will be in "\private\100012a5\eapsim.dat" in C: drive.
// The maximum length of database name is 0x40 (KDbMaxName) , which is defined in d32dbms.h.

_LIT(KDatabaseName, "c:eapsim.dat");

_LIT(KSecureUIDFormat, "SECURE[102072e9]"); // For the security policy.

#else

_LIT(KDatabaseName, "c:\\system\\data\\eapsim.dat");

#endif //#ifdef SYMBIAN_SECURE_DBMS

_LIT(KSimTableName, "eapsim");


// CLASS DECLARATION
class EapSimDbUtils 
{
public:
	
	static void OpenDatabaseL(
		RDbNamedDatabase& aDatabase, 
		RDbs& aSession, 
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType);

	/**
	* Changes the settings' index
	*/	
	static void SetIndexL(
		RDbNamedDatabase& aDatabase, 		
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const TIndexType aNewIndexType,
		const TInt aNewIndex,
		const eap_type_value_e aNewTunnelingType);

	static void SetConfigurationL(
		RDbNamedDatabase& aDatabase,
		const EAPSettings& aSettings, 
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType);

	static void GetConfigurationL(
		RDbNamedDatabase& aDatabase,
		EAPSettings& aSettings, 
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType);
		
	static void CopySettingsL(
		RDbNamedDatabase& aDatabase, 		
		const TIndexType aSrcIndexType,
		const TInt aSrcIndex,
		const eap_type_value_e aSrcTunnelingType,
		const TIndexType aDestIndexType,
		const TInt aDestIndex,
		const eap_type_value_e aDestTunnelingType);
	
	static void DeleteConfigurationL(		
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType);

};

#endif // _EAPSIMDBUTILS_H_

// End of file
