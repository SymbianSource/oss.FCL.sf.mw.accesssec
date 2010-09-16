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
* %version: 35 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 292 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "EapMsChapV2.h"
#include "eap_am_type_mschapv2_symbian.h"
#include "eap_type_mschapv2.h"
#include "EapMsChapV2Global.h"
#include <EapTypeInfo.h>
#include "EapMsChapV2DbUtils.h"

#include "EapConversion.h"
#include "EapTraceSymbian.h"

// LOCAL CONSTANTS

// The version number of this interface.
const TUint KInterfaceVersion = 1;


// ================= MEMBER FUNCTIONS =======================


CEapMsChapV2::CEapMsChapV2(
	const TIndexType aIndexType,	
	const TInt aIndex,
	const eap_type_value_e aEapType)
: iIndexType(aIndexType)
, iIndex(aIndex)
, iTunnelingType(eap_type_none)
, iEapType(aEapType)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::CEapMsChapV2()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapMsChapV2::CEapMsChapV2()\n"));

}

// ----------------------------------------------------------

CEapMsChapV2* CEapMsChapV2::NewL(SPluginInfo *aIapInfo)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::NewL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapMsChapV2::NewL()\n"));

	return new (ELeave) CEapMsChapV2(aIapInfo->indexType, aIapInfo->index, eap_type_mschapv2);
}

// ----------------------------------------------------------

CEapMsChapV2* CEapMsChapV2::NewPlainMSCHAPv2L(SPluginInfo *aIapInfo)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::NewPlainMSCHAPv2L()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapMsChapV2::NewPlainMSCHAPv2L()\n"));

	return new (ELeave) CEapMsChapV2(
		aIapInfo->indexType,
		aIapInfo->index,
		eap_expanded_type_ttls_plain_mschapv2.get_type()
		);
}


// ----------------------------------------------------------

CEapMsChapV2::~CEapMsChapV2()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::~CEapMsChapV2()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapMsChapV2::~CEapMsChapV2()\n"));

}

// ----------------------------------------------------------

#ifdef USE_EAP_SIMPLE_CONFIG

eap_base_type_c* CEapMsChapV2::GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
											   abs_eap_base_type_c* const aPartner,
											   const bool is_client_when_true,
											   const eap_am_network_id_c * const receive_network_id,
											   abs_eap_configuration_if_c * const /*configuration_if*/)
	
#else
	
eap_base_type_c* CEapMsChapV2::GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
											abs_eap_base_type_c* const aPartner,
											const bool is_client_when_true,
											const eap_am_network_id_c * const receive_network_id)
	
#endif // #ifdef USE_EAP_SIMPLE_CONFIG
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::GetStackInterfaceL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapMsChapV2::GetStackInterfaceL()\n"));

	// Create AM
	eap_am_type_mschapv2_symbian_c* amEapType = eap_am_type_mschapv2_symbian_c::NewL(
		aTools,
		aPartner,
		iIndexType,
		iIndex,
		iTunnelingType,
		is_client_when_true,
		receive_network_id);
	if (amEapType->get_is_valid() == false)
	{
		amEapType->shutdown();
		delete amEapType;
		User::Leave(KErrGeneral);
	}	
	eap_base_type_c* type = 0;

	type = new eap_type_mschapv2_c(
		aTools,
		aPartner,
		amEapType,
		true /* free_am */,
		is_client_when_true,
		receive_network_id);
	
	if (type == 0)
	{
		// Out of memory
		amEapType->shutdown();
		delete amEapType;
		User::Leave(KErrNoMemory);
	}
	else if (type->get_is_valid() == false) 
	{		
		type->shutdown();
		// amEapType is freed by eap_type_mschapv2_c
		delete type;		
		User::Leave(KErrGeneral);
	}
	return type;

}

// ----------------------------------------------------------

TUint CEapMsChapV2::GetInterfaceVersion() 
{ 
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::GetInterfaceVersion()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapMsChapV2::GetInterfaceVersion()\n"));

	return KInterfaceVersion; 
}

// ----------------------------------------------------------

CEapTypeInfo* CEapMsChapV2::GetInfoL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::GetInfoL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapMsChapV2::GetInfoL()\n"));

	CEapTypeInfo* info = new(ELeave) CEapTypeInfo(
		(TDesC&)KReleaseDate, 
		(TDesC&)KEapTypeVersion,
		(TDesC&)KManufacturer);

	return info;
}

// ----------------------------------------------------------

void CEapMsChapV2::DeleteConfigurationL()
{		
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::DeleteConfigurationL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapMsChapV2::DeleteConfigurationL()\n"));

	EapMsChapV2DbUtils::DeleteConfigurationL(iIndexType, iIndex, iTunnelingType);
}

// ----------------------------------------------------------

void CEapMsChapV2::SetTunnelingType(const TEapExpandedType aTunnelingType)
    {
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::SetTunnelingType()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapMsChapV2::SetTunnelingType()\n"));

    EAP_TRACE_DATA_DEBUG_SYMBIAN(
        (EAPL("CEapMsChapV2::SetTunnelingType - tunneling type"),
        aTunnelingType.GetValue().Ptr(), aTunnelingType.GetValue().Length()));
    
    eap_type_value_e aInternalType;
    
    TInt err = CEapConversion::ConvertExpandedEAPTypeToInternalType(
            &aTunnelingType,
            &aInternalType);
    
    iTunnelingType = aInternalType;
    
    }

// ----------------------------------------------------------

void CEapMsChapV2::SetIndexL(
		const TIndexType aIndexType, 
		const TInt aIndex)
{		
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::SetIndexL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapMsChapV2::SetIndexL()\n"));

	// First delete the target configuration
	TIndexType tmpIndexType = iIndexType;
	TInt tmpIndex = iIndex;
		
	iIndexType = aIndexType;
	iIndex = aIndex;
	
	TInt err(KErrNone);
	TRAP(err, DeleteConfigurationL());
	// Ignore error on purpose
	
	// Return the indices
	iIndexType = tmpIndexType;
	iIndex = tmpIndex;

	RDbNamedDatabase db;

	RFs session;
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
	TInt error = session.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::SetIndexL(): - session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	EapMsChapV2DbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);

	EapMsChapV2DbUtils::SetIndexL(
		db, 
		iIndexType, 
		iIndex, 
		iTunnelingType, 
		aIndexType, 
		aIndex,
		iTunnelingType);
	
	iIndexType = aIndexType;
	iIndex = aIndex;

	db.Close();
	session.Close();

	CleanupStack::PopAndDestroy(&db);
	CleanupStack::PopAndDestroy(&session);
}

// ----------------------------------------------------------

void CEapMsChapV2::SetConfigurationL(const EAPSettings& aSettings)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::SetConfigurationL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapMsChapV2::SetConfigurationL()\n"));

	RDbNamedDatabase db;

	RFs session;
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
	TInt error = session.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::SetConfigurationL(): - session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	// This also creates the IAP entry if it doesn't exist
	EapMsChapV2DbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);

	EapMsChapV2DbUtils::SetConfigurationL(
		db,
		aSettings, 
		iIndexType,
		iIndex,
		iTunnelingType);		
		
	db.Close();
	session.Close();

	CleanupStack::PopAndDestroy(&db);
	CleanupStack::PopAndDestroy(&session);
}

// ----------------------------------------------------------

void CEapMsChapV2::GetConfigurationL(EAPSettings& aSettings)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::GetConfigurationL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapMsChapV2::GetConfigurationL()\n"));

	RDbNamedDatabase db;

	RFs session;
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
	TInt error = session.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::GetConfigurationL(): - session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	// This also creates the IAP entry if it doesn't exist
	EapMsChapV2DbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);

	EapMsChapV2DbUtils::GetConfigurationL(
		db,
		aSettings, 
		iIndexType,
		iIndex,
		iTunnelingType);

	// Plain-MsChapv2 and EAP-MsChapv2 uses the same database.
	// Here we set the correct authentication method to read settings.
	error = CEapConversion::ConvertInternalTypeToExpandedEAPType(
		&iEapType,
		&aSettings.iEAPExpandedType);
	if (error != KErrNone)
	{
		User::Leave(error);
	}
		
	db.Close();
	session.Close();

	CleanupStack::PopAndDestroy(&db);
	CleanupStack::PopAndDestroy(&session);
}

// ----------------------------------------------------------

void CEapMsChapV2::CopySettingsL(
	const TIndexType aDestinationIndexType,
	const TInt aDestinationIndex)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::CopySettingsL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapMsChapV2::CopySettingsL()\n"));

	// First delete the target configuration
	TIndexType tmpIndexType = iIndexType;
	TInt tmpIndex = iIndex;
		
	iIndexType = aDestinationIndexType;
	iIndex = aDestinationIndex;
	
	TInt err(KErrNone);
	TRAP(err, DeleteConfigurationL());
	// Ignore error on purpose
	
	// Return the indices
	iIndexType = tmpIndexType;
	iIndex = tmpIndex;

	RDbNamedDatabase db;

	RFs session;
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
	TInt error = session.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2::CopySettingsL(): - session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	EapMsChapV2DbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);

	EapMsChapV2DbUtils::CopySettingsL(
		db,
		iIndexType,
		iIndex,
		iTunnelingType, 
		aDestinationIndexType, 
		aDestinationIndex, 
		iTunnelingType);
		
	db.Close();
	session.Close();

	CleanupStack::PopAndDestroy(&db);
	CleanupStack::PopAndDestroy(&session);
	
}

// ----------------------------------------------------------

TInt CEapMsChapV2::InitialisePacStore(AbsPacStoreInitializer * const /* initializer */)
{
	return KErrNone;
}

// ----------------------------------------------------------

// End of file
