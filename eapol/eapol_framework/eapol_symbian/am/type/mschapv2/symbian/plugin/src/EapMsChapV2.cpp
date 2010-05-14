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
* %version: 17.1.4 %
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


// LOCAL CONSTANTS

// The version number of this interface.
const TUint KInterfaceVersion = 1;


// ================= MEMBER FUNCTIONS =======================


CEapMsChapV2::CEapMsChapV2(const TIndexType aIndexType,	
				 const TInt aIndex, const eap_type_value_e aEapType /* =eap_type_mschapv2 */)
: iIndexType(aIndexType)
, iIndex(aIndex)
, iTunnelingType(eap_type_none)
, iEapType(aEapType)
{
}

// ----------------------------------------------------------

CEapMsChapV2* CEapMsChapV2::NewL(SIapInfo *aIapInfo)
{
	return new (ELeave) CEapMsChapV2(aIapInfo->indexType, aIapInfo->index);
}

// ----------------------------------------------------------

CEapMsChapV2* CEapMsChapV2::NewPlainMSCHAPv2L(SIapInfo *aIapInfo)
{
	return new (ELeave) CEapMsChapV2(
		aIapInfo->indexType,
		aIapInfo->index,
#if defined(USE_EAP_EXPANDED_TYPES)
		eap_expanded_type_ttls_plain_mschapv2.get_type()
#else
		eap_type_plain_mschapv2
#endif //#if defined(USE_EAP_EXPANDED_TYPES)
		);
}


// ----------------------------------------------------------

CEapMsChapV2::~CEapMsChapV2()
{
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
	return KInterfaceVersion; 
}


// ----------------------------------------------------------
TInt CEapMsChapV2::InvokeUiL()
{
	TInt buttonId(0);

	return buttonId;
}


// ----------------------------------------------------------
CEapTypeInfo* CEapMsChapV2::GetInfoLC()
{
	CEapTypeInfo* info = new(ELeave) CEapTypeInfo(
		(TDesC&)KReleaseDate, 
		(TDesC&)KEapTypeVersion,
		(TDesC&)KManufacturer);

	CleanupStack::PushL(info);
	return info;
}

// ----------------------------------------------------------

void CEapMsChapV2::DeleteConfigurationL()
{		
	EapMsChapV2DbUtils::DeleteConfigurationL(iIndexType, iIndex, iTunnelingType);
}

// ----------------------------------------------------------

void CEapMsChapV2::SetTunnelingType(const TInt aTunnelingType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	// Vendor id is eap_type_vendor_id_ietf always in this plugin.
	iTunnelingType.set_eap_type_values(eap_type_vendor_id_ietf, aTunnelingType);

#else

	iTunnelingType = static_cast<eap_type_value_e>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES
}

// ----------------------------------------------------------
void CEapMsChapV2::SetIndexL(
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

	RDbs session;
	
	EapMsChapV2DbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
		
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

	CleanupStack::PopAndDestroy(2); // db
}

void CEapMsChapV2::SetConfigurationL(const EAPSettings& aSettings)
{
	RDbNamedDatabase db;

	RDbs session;	
	
	// This also creates the IAP entry if it doesn't exist
	EapMsChapV2DbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);

	EapMsChapV2DbUtils::SetConfigurationL(
		db,
		aSettings, 
		iIndexType,
		iIndex,
		iTunnelingType);		
		
	CleanupStack::PopAndDestroy(2); // db, session
}

void CEapMsChapV2::GetConfigurationL(EAPSettings& aSettings)
{
	RDbNamedDatabase db;

	RDbs session;
	
	// This also creates the IAP entry if it doesn't exist
	EapMsChapV2DbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);

	EapMsChapV2DbUtils::GetConfigurationL(
		db,
		aSettings, 
		iIndexType,
		iIndex,
		iTunnelingType);
		
	CleanupStack::PopAndDestroy(2); // db, session
}

void CEapMsChapV2::CopySettingsL(
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

	RDbs session;
	
	EapMsChapV2DbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
		
	EapMsChapV2DbUtils::CopySettingsL(
		db,
		iIndexType,
		iIndex,
		iTunnelingType, 
		aDestinationIndexType, 
		aDestinationIndex, 
		iTunnelingType);
		
	CleanupStack::PopAndDestroy(2); // db
	
}

// End of file
