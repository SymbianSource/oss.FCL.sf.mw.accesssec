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
* %version: 24 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 176 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "EapProtectedSetup.h"
#include "eap_base_type.h"
#include "simple_config_types.h"
#include "eap_type_simple_config.h"
#include "simple_config_record.h"
#include "abs_eap_configuration_if.h"

#include <EapTypeInfo.h>
#include "eap_am_type_protected_setup_symbian.h"
#include "EapProtectedSetupGlobal.h"
#include "EapTraceSymbian.h"
#include "EapConversion.h"

#include "eap_am_tools_symbian.h"

// LOCAL CONSTANTS

// The version number of this interface.
const TUint KInterfaceVersion = 1;


// ================= MEMBER FUNCTIONS =======================


CEapProtectedSetup::CEapProtectedSetup(const TIndexType aIndexType,	
				 const TInt aIndex)
: iIndexType(aIndexType)
, iIndex(aIndex)
, iTunnelingType(eap_type_none)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapProtectedSetup::CEapProtectedSetup index type=%d, index=%d, tunneling type=%d"),
		iIndexType, iIndex, iTunnelingType.get_vendor_type()));

}

// ----------------------------------------------------------

CEapProtectedSetup* CEapProtectedSetup::NewL(SPluginInfo *aIapInfo)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapProtectedSetup::NewL index type=%d, index=%d"),
		aIapInfo->indexType, aIapInfo->index));

	return new (ELeave) CEapProtectedSetup(aIapInfo->indexType, aIapInfo->index);
}

// ----------------------------------------------------------

CEapProtectedSetup::~CEapProtectedSetup()
{
}

// ----------------------------------------------------------

eap_base_type_c* CEapProtectedSetup::GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
											abs_eap_base_type_c* const aPartner,
											const bool is_client_when_true,
											const eap_am_network_id_c * const receive_network_id,
											abs_eap_configuration_if_c * const configuration_if)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapProtectedSetup::GetStackInterfaceL - Start")));

	// Create AM
	CEapAmProtectedSetupSymbian* amEapType = CEapAmProtectedSetupSymbian::NewL(
		aTools, 
		aPartner, 
		iIndexType,
		iIndex,
		iTunnelingType,
		eap_expanded_type_simple_config.get_type(), 
		is_client_when_true, 
		receive_network_id,
		configuration_if);

	if (amEapType == 0 || amEapType->get_is_valid() == false)
	{
	
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("ERROR: GetStackInterfaceL : CEapAmProtectedSetupSymbian(): failed.")));
	
		delete amEapType;
		User::Leave(KErrNoMemory);
	}	
	
	simple_config_record_c* simple_config_record = new simple_config_record_c(
		aTools,
		amEapType,
		false /*  NO Free */,
		is_client_when_true,
		receive_network_id);
	
	if (simple_config_record == 0
		|| simple_config_record->get_is_valid() == false)
	{
	
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("ERROR: GetStackInterfaceL : simple_config_record_c(): failed.")));

		EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);

		delete simple_config_record;
		User::Leave(KErrNoMemory);
	}	
	
	eap_base_type_c* type = 0;

	type = new eap_type_simple_config_c(
		aTools,
		aPartner,
		amEapType,
		true, /* Free AM */		
		simple_config_record,
		true, /*Free record*/
		is_client_when_true,		
		eap_expanded_type_simple_config.get_type(), // This gets the EAP type (Protected Setup)	.
		receive_network_id);
	
	if (type == 0)
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("ERROR: GetStackInterfaceL : eap_type_simple_config_c(): failed.")));
	
		// Out of memory
		amEapType->shutdown();
		delete amEapType;
		
		simple_config_record->shutdown();
		delete simple_config_record;
		
		User::Leave(KErrNoMemory);
	}
	else if (type->get_is_valid() == false) 
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("ERROR: GetStackInterfaceL : type->get_is_valid(): not valid.")));
		
		type->shutdown();
		// amEapType is freed by eap_type_simple_config_c
		delete type;
		
		User::Leave(KErrGeneral);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapProtectedSetup::GetStackInterfaceL - End")));
	
	return type;
}

// ----------------------------------------------------------

CEapTypeInfo* CEapProtectedSetup::GetInfoL()
{
	CEapTypeInfo* info = new(ELeave) CEapTypeInfo(
		(TDesC&)KReleaseDate, 
		(TDesC&)KEapTypeVersion,
		(TDesC&)KManufacturer);

	return info;
}

// ----------------------------------------------------------

void CEapProtectedSetup::DeleteConfigurationL()
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("WARNING: CEapProtectedSetup::DeleteConfigurationL - THIS IS NOT SUPPORTED")));
}

// ----------------------------------------------------------

TUint CEapProtectedSetup::GetInterfaceVersion()
{
	return KInterfaceVersion;
}

// ----------------------------------------------------------

void CEapProtectedSetup::SetTunnelingType(const TEapExpandedType aTunnelingType)
{
	EAP_TRACE_DATA_DEBUG_SYMBIAN(
		(EAPL("CEapProtectedSetup::SetTunnelingType - tunneling type"),
		aTunnelingType.GetValue().Ptr(), aTunnelingType.GetValue().Length()));

	eap_type_value_e aInternalType;

	    TInt err = CEapConversion::ConvertExpandedEAPTypeToInternalType(
	            &aTunnelingType,
	            &aInternalType);

	    iTunnelingType = aInternalType;

}

// ----------------------------------------------------------

void CEapProtectedSetup::SetIndexL(
		const TIndexType /*aIndexType*/, 
		const TInt /*aIndex*/ )
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("ERROR: CEapProtectedSetup::SetIndexL - THIS IS NOT SUPPORTED")));
}

// ----------------------------------------------------------

void CEapProtectedSetup::SetConfigurationL(const EAPSettings& /*aSettings*/)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("ERROR: CEapProtectedSetup::SetConfigurationL - THIS IS NOT SUPPORTED")));
}

// ----------------------------------------------------------

void CEapProtectedSetup::GetConfigurationL(EAPSettings& /*aSettings*/)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("ERROR: CEapProtectedSetup::GetConfigurationL - THIS IS NOT SUPPORTED")));
}

// ----------------------------------------------------------

void CEapProtectedSetup::CopySettingsL(
	const TIndexType /*aDestinationIndexType*/,
	const TInt /*aDestinationIndex*/)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("ERROR: CEapProtectedSetup::CopySettingsL - THIS IS NOT SUPPORTED")));
}

// ----------------------------------------------------------

TInt CEapProtectedSetup::InitialisePacStore(AbsPacStoreInitializer * const /* initializer */)
{
	return KErrNone;
}

// ----------------------------------------------------------

// End of file
