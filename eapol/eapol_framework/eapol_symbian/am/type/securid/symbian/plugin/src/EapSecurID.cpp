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
* %version: 29 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 347 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "EapSecurID.h"
#include "eap_am_type_securid_symbian.h"
#include "eap_type_securid.h"
#include "EapSecurIDGlobal.h"
#include <EapTypeInfo.h>
#include "EapGtcDbUtils.h"

#include "eap_am_tools_symbian.h"
#include "EapConversion.h"
#include "EapTraceSymbian.h"

// LOCAL CONSTANTS

// The version number of this interface.
const TUint KInterfaceVersion = 1;

// ================= MEMBER FUNCTIONS =======================

CEapSecurID::CEapSecurID(
	const TIndexType aIndexType,	
	const TInt aIndex,
	const eap_type_value_e aEapType)
	: iIndexType(aIndexType)
	, iIndex(aIndex)
	, iEapType(aEapType)
	, iTunnelingType(eap_type_none)
{
}

// ----------------------------------------------------------

CEapSecurID* CEapSecurID::NewSecurIdL(SPluginInfo *aIapInfo)
{
	return new(ELeave) CEapSecurID(aIapInfo->indexType, aIapInfo->index, eap_type_securid);
}

// ----------------------------------------------------------

CEapSecurID* CEapSecurID::NewGtcL(SPluginInfo *aIapInfo)
{
	return new(ELeave) CEapSecurID(aIapInfo->indexType, aIapInfo->index, eap_type_generic_token_card);
}

// ----------------------------------------------------------

CEapSecurID::~CEapSecurID()
{
}

// ----------------------------------------------------------

#ifdef USE_EAP_SIMPLE_CONFIG

eap_base_type_c* CEapSecurID::GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
											   abs_eap_base_type_c* const aPartner,
											   const bool is_client_when_true,
											   const eap_am_network_id_c * const receive_network_id,
											   abs_eap_configuration_if_c * const /*configuration_if*/)
	
#else
	
eap_base_type_c* CEapSecurID::GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
											abs_eap_base_type_c* const aPartner,
											const bool is_client_when_true,
											const eap_am_network_id_c * const receive_network_id)
	
#endif // #ifdef USE_EAP_SIMPLE_CONFIG
{
	// Create AM
	eap_am_type_securid_symbian_c* amEapType = eap_am_type_securid_symbian_c::NewL(
		aTools, 
		aPartner, 
		iIndexType, 
		iIndex, 
		iTunnelingType, 
		iEapType,
		is_client_when_true,
		receive_network_id);
	if (amEapType->get_is_valid() == false)
	{
		amEapType->shutdown();
		delete amEapType;
		User::Leave(KErrGeneral);
	}	
	eap_base_type_c* type = 0;

	type = new eap_type_securid_c(
		aTools,
		aPartner,
		amEapType,
		true /* free_am */,
		iEapType,
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
		// amEapType is freed by eap_type_securid_c
		delete type;		
		User::Leave(KErrGeneral);
	}
	return type;
}

// ----------------------------------------------------------

TUint CEapSecurID::GetInterfaceVersion() 
{ 
	return KInterfaceVersion; 
}

// ----------------------------------------------------------

CEapTypeInfo* CEapSecurID::GetInfoL()
{
	CEapTypeInfo* info = new(ELeave) CEapTypeInfo(
		(TDesC&) KReleaseDate,
		(TDesC&) KEapTypeVersion,
		(TDesC&) KManufacturer);

	return info;
}

// ----------------------------------------------------------

void CEapSecurID::DeleteConfigurationL()
{
	EapGtcDbUtils::DeleteConfigurationL(iIndexType, iIndex, iTunnelingType);
}

// ----------------------------------------------------------

void CEapSecurID::SetTunnelingType(const TEapExpandedType aTunnelingType)
    {
    EAP_TRACE_DATA_DEBUG_SYMBIAN(
        (EAPL("CEapSecurID::SetTunnelingType - tunneling type"),
        aTunnelingType.GetValue().Ptr(), aTunnelingType.GetValue().Length()));
    
    eap_type_value_e aInternalType;
    
    TInt err = CEapConversion::ConvertExpandedEAPTypeToInternalType(
            &aTunnelingType,
            &aInternalType);
    
    iTunnelingType = aInternalType;
    }

// ----------------------------------------------------------

void CEapSecurID::SetIndexL(
		const TIndexType aIndexType, 
		const TInt aIndex)
{		
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
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapSecurID::SetIndexL(): - session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	EapGtcDbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);

	EapGtcDbUtils::SetIndexL(
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

void CEapSecurID::SetConfigurationL(const EAPSettings& aSettings)
{
	RDbNamedDatabase db;

	RFs session;
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
	TInt error = session.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapSecurID::SetConfigurationL(): - session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	// This also creates the IAP entry if it doesn't exist
	EapGtcDbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);

	EapGtcDbUtils::SetConfigurationL(
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

void CEapSecurID::GetConfigurationL(EAPSettings& aSettings)
{
	RDbNamedDatabase db;

	RFs session;
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
	TInt error = session.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapSecurID::GetConfigurationL(): - session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	// This also creates the IAP entry if it doesn't exist
	EapGtcDbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);

	EapGtcDbUtils::GetConfigurationL(
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

void CEapSecurID::CopySettingsL(
	const TIndexType aDestinationIndexType,
	const TInt aDestinationIndex)
{
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
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapSecurID::CopySettingsL(): - session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	EapGtcDbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);

	EapGtcDbUtils::CopySettingsL(
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

TInt CEapSecurID::InitialisePacStore(AbsPacStoreInitializer * const /* initializer */)
{
	return KErrNone;
}

// ----------------------------------------------------------

// End of File
