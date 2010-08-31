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
* %version: 9 %
*/

#if !defined(_EAPPLUGINTOOLS_H_)
#define _EAPPLUGINTOOLS_H_

#include <d32dbms.h>
#include <EapExpandedType.h>
#include <EapTypeDefinitions.h>

/** @file */

class EapPluginTools
{

public:

	// ----------------------------------------------------------------------

	IMPORT_C EapPluginTools();

	IMPORT_C virtual ~EapPluginTools();

	IMPORT_C void ListAllEapPluginsL(const TIndexType aIndexType, const TEapExpandedType & aTunnelingEapType, RPointerArray<TEapExpandedType> & aPlugins);

	IMPORT_C static void CleanupImplArray( TAny* aAny );

	IMPORT_C static void GetPrivatePathL(
		RFs& aFileServerSession,
		TFileName& aPrivateDatabasePathName);

	IMPORT_C static void GetPrivatePathL(
		TFileName& aPrivateDatabasePathName);

	IMPORT_C static void CreateDatabaseLC(
		RDbNamedDatabase& aDatabase,
		RFs& aFileServerSession,
		TInt& error,
		const TDesC& aDatabaseName,
		TFileName& aPrivateDatabasePathName);

	// ----------------------------------------------------------------------

private:

	// ----------------------------------------------------------------------

	// ----------------------------------------------------------------------

};

#define EAP_LITERAL_SYMBIAN(name, string) \
	_LIT8(name##_8bit, string); \
	_LIT(name, string)

#endif //#if !defined(_EAPPLUGINTOOLS_H_)


//--------------------------------------------------
// End
