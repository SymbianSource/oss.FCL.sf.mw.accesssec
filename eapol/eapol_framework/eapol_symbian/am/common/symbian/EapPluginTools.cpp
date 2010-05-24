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
* %version: 11 %
*/

#include <EapTraceSymbian.h>
#include <EapAutomatic.h>
#include <EapPluginTools.h>
#include <EapTypePlugin.h>
#include <ecom.h>

/** @file */

// ----------------------------------------------------------------------

EXPORT_C EapPluginTools::EapPluginTools()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::EapPluginTools(): this=0x%08x.\n"),
		this));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapPluginTools::EapPluginTools()"));
}

// ----------------------------------------------------------------------

EXPORT_C EapPluginTools::~EapPluginTools()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::~EapPluginTools(): this=0x%08x.\n"),
		this));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapPluginTools::~EapPluginTools()"));
}

// ----------------------------------------------------------------------

EXPORT_C void EapPluginTools::CleanupImplArray( TAny* aAny )
{
	RImplInfoPtrArray* implArray = 
		reinterpret_cast<RImplInfoPtrArray*>( aAny );

	implArray->ResetAndDestroy();
	implArray->Close();
}

// ----------------------------------------------------------------------

EXPORT_C void EapPluginTools::ListAllEapPluginsL(const TEapExpandedType & aTunnelingEapType, RPointerArray<TEapExpandedType> & aPlugins)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::ListAllEapPluginsL(): this=0x%08x, aTunnelingEapType=0xfe%06x%08x.\n"),
		this,
		aTunnelingEapType.GetVendorId(),
		aTunnelingEapType.GetVendorType()));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapPluginTools::ListAllEapPluginsL()"));

	aPlugins.Reset();   // Reset this first

	RImplInfoPtrArray aEapArray;

	CleanupStack::PushL( TCleanupItem( CleanupImplArray, &aEapArray ) );

	REComSession::ListImplementationsL( KEapTypeInterfaceUid, aEapArray );

	// EAP plugin interface dialog should show only the EAP types that allowed
	// outside EAP-PEAP, EAP-TTLS and EAP-FAST.

	for( TInt counter = 0; counter < aEapArray.Count(); counter++ )
	{
		TEapExpandedType plugin_type(aEapArray[counter]->DataType());

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::ListAllEapPluginsL(): aEapArray[%d] EAP-type=0xfe%06x%08x\n"),
			counter,
			plugin_type.GetVendorId(),
			plugin_type.GetVendorType()));

		TBool aNotAllowed(EFalse);

		if (aTunnelingEapType == (*EapExpandedTypeNone.GetType()))
		{
			// Filter out the EAP types which are NOT allowed outside PEAP, TTLS or FAST.
			if( CEapTypePlugin::IsDisallowedOutsidePEAP( *aEapArray[counter] ) )
			{
				EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::ListAllEapPluginsL(): aEapArray[%d] EAP-type=0xfe%06x%08x, IsDisallowedOutsidePEAP()\n"),
					counter,
					plugin_type.GetVendorId(),
					plugin_type.GetVendorType()));

				aNotAllowed = ETrue;
			}
		}
		else if (aTunnelingEapType == (*EapExpandedTypePeap.GetType())
			|| aTunnelingEapType == (*EapExpandedTypeFast.GetType()))
		{
			// Filter out the EAP types which are NOT allowed inside PEAP or FAST.
			if( CEapTypePlugin::IsDisallowedInsidePEAP( *aEapArray[counter] ) )
			{
				EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::ListAllEapPluginsL(): aEapArray[%d] EAP-type=0xfe%06x%08x, IsDisallowedInsidePEAP()\n"),
					counter,
					plugin_type.GetVendorId(),
					plugin_type.GetVendorType()));

				aNotAllowed = ETrue;
			}
		}
		else if (aTunnelingEapType == (*EapExpandedTypeTtls.GetType()))
		{
			// Filter out the EAP types which are NOT allowed inside TTLS.
			if( CEapTypePlugin::IsDisallowedInsideTTLS( *aEapArray[counter] ) )
			{
				EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::ListAllEapPluginsL(): aEapArray[%d] EAP-type=0xfe%06x%08x, IsDisallowedInsideTTLS()\n"),
					counter,
					plugin_type.GetVendorId(),
					plugin_type.GetVendorType()));

				aNotAllowed = ETrue;
			}
		}

		if (aNotAllowed)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::ListAllEapPluginsL(): Removes EAP-plugin aEapArray[%d] EAP-type=0xfe%06x%08x\n"),
				counter,
				plugin_type.GetVendorId(),
				plugin_type.GetVendorType()));

			// Delete the EAP type, which isn't allowed here from the array.
			delete aEapArray[counter];
			aEapArray.Remove( counter );

			// One item removed from the array. So reduce the item counter.
			counter--;
		}
	}

	for (TInt ind = 0; ind < aEapArray.Count(); ind++ )
	{
		TEapExpandedType * eap_type = new TEapExpandedType;
		if (eap_type != 0)
		{
			*eap_type = aEapArray[ind]->DataType();

			EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::ListAllEapPluginsL(): aEapArray[%d] EAP-type=0xfe%06x%08x\n"),
				ind,
				eap_type->GetVendorId(),
				eap_type->GetVendorType()));

			User::LeaveIfError( aPlugins.Append( eap_type ) );
		}
	}

	CleanupStack::PopAndDestroy(&aEapArray);
}

// ----------------------------------------------------------------------

EXPORT_C void EapPluginTools::GetPrivatePathL(
	RFs& aFileServerSession,
	TFileName& aPrivateDatabasePathName)
{
	// Reads the private folder.

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::GetPrivatePathL(): - calls aFileServerSession.Connect()\n")));

	TInt error = aFileServerSession.Connect();

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::GetPrivatePathL(): - aFileServerSession.Connect(), error=%d\n"), error));

	User::LeaveIfError(error);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::GetPrivatePathL(): - calls aFileServerSession.PrivatePath()\n")));

	aPrivateDatabasePathName.SetLength(0);

	error = aFileServerSession.PrivatePath(aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::GetPrivatePathL(): - aFileServerSession.PrivatePath(), error=%d\n"), error));

	User::LeaveIfError(error);

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("aPrivateDatabasePathName",
		aPrivateDatabasePathName.Ptr(),
		aPrivateDatabasePathName.Size()));
}

// ----------------------------------------------------------------------

EXPORT_C void EapPluginTools::GetPrivatePathL(
	TFileName& aPrivateDatabasePathName)
{
	// Reads the private folder.

	RFs aFileServerSession;

	EapPluginTools::GetPrivatePathL(
		aFileServerSession,
		aPrivateDatabasePathName);
}

// ----------------------------------------------------------------------

EXPORT_C void EapPluginTools::CreateDatabaseLC(
	RDbNamedDatabase& aDatabase,
	RFs& aFileServerSession,
	TInt& error,
	const TDesC& aDatabaseName,
	TFileName& aPrivateDatabasePathName)
{
	CleanupClosePushL(aFileServerSession);
	CleanupClosePushL(aDatabase);

	// aDatabase is pushed to the cleanup stack even though they may be member
	// variables of the calling class and would be closed in the destructor anyway. This ensures
	// that if they are not member variables they will be closed. Closing the handle twice
	// does no harm.	

	// Create the private database in the private folder of EAP-server.

	EapPluginTools::GetPrivatePathL(
		aFileServerSession,
		aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::CreateDatabaseLC(): - calls aPrivateDatabasePathName.Append()\n")));

	aPrivateDatabasePathName.Append(aDatabaseName);

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("aPrivateDatabasePathName",
		aPrivateDatabasePathName.Ptr(),
		aPrivateDatabasePathName.Size()));

	User::LeaveIfError(error);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::CreateDatabaseLC(): - calls aDatabase.Create()\n")));

	error = aDatabase.Create(aFileServerSession, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapPluginTools::CreateDatabaseLC(): - Created private DB for %S. error=%d, (%d is KErrAlreadyExists)\n"),
		&aDatabaseName,
		error,
		KErrAlreadyExists));
}

// ----------------------------------------------------------------------
// End
