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
* %version: 15.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 605 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "EapAka.h"
#include "eap_base_type.h"
#include "eap_type_aka.h"
#include "EapAkaGlobal.h"
#include <EapTypeInfo.h>
#include "eap_am_type_aka_symbian.h"
#include "EapAkaDbUtils.h"

#include <EapAkaUiConnection.h>
#include "EapAkaUi.h"


#include "eap_am_tools_symbian.h"

// LOCAL CONSTANTS

// The version number of this interface.
const TUint KInterfaceVersion = 1;


// ================= MEMBER FUNCTIONS =======================


CEapAka::CEapAka(const TIndexType aIndexType,	
				 const TInt aIndex)
: iIndexType(aIndexType)
, iIndex(aIndex)
, iTunnelingType(eap_type_none)
{
}

// ----------------------------------------------------------

CEapAka* CEapAka::NewL(SIapInfo *aIapInfo)
{
	return new (ELeave) CEapAka(aIapInfo->indexType, aIapInfo->index);
}

// ----------------------------------------------------------

CEapAka::~CEapAka()
{
}

// ----------------------------------------------------------

#ifdef USE_EAP_SIMPLE_CONFIG

eap_base_type_c* CEapAka::GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
											   abs_eap_base_type_c* const aPartner,
											   const bool is_client_when_true,
											   const eap_am_network_id_c * const receive_network_id,
											   abs_eap_configuration_if_c * const /*configuration_if*/)
	
#else
	
eap_base_type_c* CEapAka::GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
											abs_eap_base_type_c* const aPartner,
											const bool is_client_when_true,
											const eap_am_network_id_c * const receive_network_id)
	
#endif // #ifdef USE_EAP_SIMPLE_CONFIG
{
	// Create AM
	eap_am_type_aka_symbian_c* amEapType = eap_am_type_aka_symbian_c::NewL(
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

	type = new eap_type_aka_c(
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
		// amEapType is freed by eap_type_aka_c
		delete type;		
		User::Leave(KErrGeneral);
	}
	return type;
}

// ----------------------------------------------------------
TInt CEapAka::InvokeUiL()
{
	TInt buttonId(0);
 
#ifdef USE_EAP_EXPANDED_TYPES

    CEapAkaUiConnection uiConn(iIndexType, iIndex, iTunnelingType.get_vendor_type());
	
#else

    CEapAkaUiConnection uiConn(iIndexType, iIndex, iTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES
 
	CEapAkaUi* ui = CEapAkaUi::NewL(&uiConn);
	CleanupStack::PushL(ui);
	buttonId = ui->InvokeUiL();
	CleanupStack::PopAndDestroy(ui);
	return buttonId;
}

// ----------------------------------------------------------
CEapTypeInfo* CEapAka::GetInfoLC()
{
	CEapTypeInfo* info = new(ELeave) CEapTypeInfo(
		(TDesC&)KReleaseDate, 
		(TDesC&)KEapTypeVersion,
		(TDesC&)KManufacturer);

	CleanupStack::PushL(info);
	return info;
}

// ----------------------------------------------------------
void CEapAka::DeleteConfigurationL()
{		
	EapAkaDbUtils::DeleteConfigurationL(iIndexType, iIndex, iTunnelingType);
}

// ----------------------------------------------------------

TUint CEapAka::GetInterfaceVersion()
{
	return KInterfaceVersion;
}

// ----------------------------------------------------------

void CEapAka::SetTunnelingType(const TInt aTunnelingType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	// Vendor id is eap_type_vendor_id_ietf always in this plugin.
	iTunnelingType.set_eap_type_values(eap_type_vendor_id_ietf, aTunnelingType);

#else

	iTunnelingType = static_cast<eap_type_value_e>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES
}


// ----------------------------------------------------------
void CEapAka::SetIndexL(
		const TIndexType aIndexType, 
		const TInt aIndex )
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
	
	EapAkaDbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
		
	EapAkaDbUtils::SetIndexL(
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

// ----------------------------------------------------------

void CEapAka::SetConfigurationL(const EAPSettings& aSettings)
{
	RDbNamedDatabase db;

	RDbs session;	
	
	// This also creates the IAP entry if it doesn't exist
	EapAkaDbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);

	EapAkaDbUtils::SetConfigurationL(
		db,
		aSettings, 
		iIndexType,
		iIndex,
		iTunnelingType);		
		
	CleanupStack::PopAndDestroy(2); // db, session
}

// ----------------------------------------------------------

void CEapAka::GetConfigurationL(EAPSettings& aSettings)
{
	RDbNamedDatabase db;

	RDbs session;
	
	// This also creates the IAP entry if it doesn't exist
	EapAkaDbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);

	EapAkaDbUtils::GetConfigurationL(
		db,
		aSettings, 
		iIndexType,
		iIndex,
		iTunnelingType);
		
	CleanupStack::PopAndDestroy(2); // db, session
}

// ----------------------------------------------------------

void CEapAka::CopySettingsL(
	const TIndexType aDestinationIndexType,
	const TInt aDestinationIndex)
{
	// First delete the target configuration
	TIndexType tmpIndexType = iIndexType;
	TInt tmpIndex = iIndex;
		
	iIndexType = aDestinationIndexType;
	iIndex = aDestinationIndex;

	TInt err(KErrNone)	;
	TRAP(err, DeleteConfigurationL());
	// Ignore error on purpose
	
	// Return the indices
	iIndexType = tmpIndexType;
	iIndex = tmpIndex;

	RDbNamedDatabase db;

	RDbs session;
	
	EapAkaDbUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType);
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
		
	EapAkaDbUtils::CopySettingsL(
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
