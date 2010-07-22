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
* %version: 64 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 417 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "EapTlsPeap.h"
#include "eap_base_type.h"
#include "EapTlsPeapGlobal.h"
#include <EapTypeInfo.h>

#if defined(USE_FAST_EAP_TYPE)
#include "tls_application_eap_fast.h"
#endif 

#include "eap_am_type_tls_peap_symbian.h"
#include "eap_type_tls_peap.h"
#include "tls_record.h"
#include "dummy_eap_core.h"
#include "eap_core.h"
#include "tls_application_eap_core.h"
#include "eap_am_tools_symbian.h"
#include "EapTraceSymbian.h"
#include "EapConversion.h"
#include "EapExpandedType.h"

#ifdef USE_PAC_STORE
#include "pac_store_db_symbian.h"
#endif

#include "eapol_key_types.h"

// LOCAL CONSTANTS

// The version number of this interface. At the moment this version number is
// common for all three plug-in interfaces.
const TUint KInterfaceVersion = 1;

#if defined(USE_FAST_EAP_TYPE)
	const u8_t EAP_RAS_SOURCE[] = "ras_src";
	const u8_t EAP_RAS_DESTINATION[] = "ras_des";
#endif //#if defined(USE_FAST_EAP_TYPE)

// ================= MEMBER FUNCTIONS =======================


CEapTlsPeap::CEapTlsPeap(const TIndexType aIndexType,	
				 const TInt aIndex,
				 const eap_type_value_e aEapType)
: iIndexType(aIndexType)
, iIndex(aIndex)
, iEapType(aEapType)
, iTunnelingType(eap_type_none)
#if defined(USE_FAST_EAP_TYPE)
, iApplication(NULL)
#endif
, m_am_tools(abs_eap_am_tools_c::new_abs_eap_am_tools_c())
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::CEapTlsPeap()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::CEapTlsPeap()\n"));

	if (m_am_tools == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	ASSERT(iEapType.get_vendor_id() == eap_type_vendor_id_ietf);
	ASSERT(iTunnelingType.get_vendor_id() == eap_type_vendor_id_ietf);

#if defined(USE_FAST_EAP_TYPE)
	if(iEapType == eap_type_fast)
	{
		eap_variable_data_c source(m_am_tools);

		eap_status_e status = source.set_copy_of_buffer(
			EAP_RAS_SOURCE,
			sizeof(EAP_RAS_SOURCE));
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeap::CEapTlsPeap(): status = %s\n"),
				eap_status_string_c::get_status_string(status)));
			return;
		}

		eap_variable_data_c destination(m_am_tools);

		status = destination.set_copy_of_buffer(
			EAP_RAS_DESTINATION,
			sizeof(EAP_RAS_DESTINATION));
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeap::CEapTlsPeap(): status = %s\n"),
				eap_status_string_c::get_status_string(status)));
			return;
		}

		eap_am_network_id_c dummy_id(m_am_tools, &source, &destination, eapol_ethernet_type_pae);
	
		if (dummy_id.get_is_valid() == false)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeap::NewPeapL() dummy_id not valid\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}
	
		if (dummy_id.get_is_valid_data() == false)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeap::NewPeapL() dummy_id data not valid\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}
	
		
		TRAPD(err, iApplication = GetTlsInterfaceL(
			m_am_tools, 
			true,
			&dummy_id));
		if (err)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeap::NewPeapL() iApplication couldn't be created\n")));
				
		}
	}
#endif //#if defined(USE_FAST_EAP_TYPE)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

}

// ----------------------------------------------------------

CEapTlsPeap* CEapTlsPeap::NewTlsL(SIapInfo *aIapInfo)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::NewTlsL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::NewTlsL()\n"));

	return new (ELeave) CEapTlsPeap(aIapInfo->indexType, aIapInfo->index, eap_type_tls);
}

// ----------------------------------------------------------

CEapTlsPeap* CEapTlsPeap::NewPeapL(SIapInfo *aIapInfo)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::NewPeapL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::NewPeapL()\n"));

	return new (ELeave) CEapTlsPeap(aIapInfo->indexType, aIapInfo->index, eap_type_peap);
}

// ----------------------------------------------------------

#if defined(USE_TTLS_EAP_TYPE)

CEapTlsPeap* CEapTlsPeap::NewTtlsL(SIapInfo *aIapInfo)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::NewTtlsL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::NewTtlsL()\n"));

	return new (ELeave) CEapTlsPeap(aIapInfo->indexType, aIapInfo->index, eap_type_ttls);
}

#endif // #if defined(USE_TTLS_EAP_TYPE)

// ----------------------------------------------------------


// ---------------------------------------------------------
// CEapTtlsPapActive::NewTtlsPapL()
// ---------------------------------------------------------
// 

CEapTlsPeap* CEapTlsPeap::NewTtlsPapL( SIapInfo* aIapInfo )
    {
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::NewTtlsPapL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::NewTtlsPapL()\n"));

	return new (ELeave) CEapTlsPeap(
		aIapInfo->indexType, aIapInfo->index, eap_type_ttls_plain_pap );    
    }


// ----------------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

CEapTlsPeap* CEapTlsPeap::NewFastL(SIapInfo *aIapInfo)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::NewFastL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::NewFastL()\n"));

	return new (ELeave) CEapTlsPeap(aIapInfo->indexType, aIapInfo->index, eap_type_fast);
}

#endif // #if defined(USE_FAST_EAP_TYPE)

// ----------------------------------------------------------

CEapTlsPeap::~CEapTlsPeap()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::~CEapTlsPeap()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::~CEapTlsPeap()\n"));

	iEapArray.ResetAndDestroy();
	
	if (iType != NULL)
		{
		iType->shutdown();
		// type deletes all
		delete iType;
		iType = NULL;
		}
		
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::~CEapTlsPeap() iType deleted\n")));

#if defined(USE_FAST_EAP_TYPE)
	if (iApplication != NULL)
		{
//		iApplication->shutdown();
//		delete iApplication;
		iApplication = NULL;
		}
#endif //#if defined(USE_FAST_EAP_TYPE)
		
	abs_eap_am_tools_c::delete_abs_eap_am_tools_c(m_am_tools);
}

#if defined(USE_FAST_EAP_TYPE)
// ----------------------------------------------------------
tls_application_eap_fast_c* CEapTlsPeap::GetTlsInterfaceL(abs_eap_am_tools_c* const aTools, 
											   const bool is_client_when_true,
											   const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::GetTlsInterfaceL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::GetTlsInterfaceL()\n"));

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeap::GetTlsInterfaceL -Start- iIndexType=%d, iIndex=%d, Tunneling vendor type=%d, Eap vendor type=%d \n"),
		iIndexType,iIndex, iTunnelingType.get_vendor_type(), iEapType.get_vendor_type()));

	// Create adaptation layer
	eap_am_type_tls_peap_symbian_c* amEapType;
	tls_record_c* record;

	eap_core_c* const eap_core = reinterpret_cast<eap_core_c *> (new dummy_eap_core_c(
		aTools,
		0,
		is_client_when_true,
		receive_network_id,
		true));
	if (eap_core == 0)
	{
		// Out of memory
		User::Leave(KErrNoMemory);
	} 
	else if (eap_core->get_is_valid() == false)
	{
		// Out of memory
		eap_core->shutdown();
		delete eap_core;
		User::Leave(KErrGeneral);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeap::GetTlsInterfaceL - created eap_core_c \n")));

	amEapType = eap_am_type_tls_peap_symbian_c::NewL(
		aTools,
		eap_core,
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
	
	amEapType->configure();
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeap::GetTlsInterfaceL - created eap_am_type_tls_peap_symbian_c \n")));

	tls_application_eap_fast_c* application = 0;
		
	if(iEapType == eap_type_fast)
	{
		application = new tls_application_eap_fast_c(
			aTools,
			eap_core,
			true,
			is_client_when_true,
			iEapType,
			receive_network_id,
			amEapType);
		
		if (application)
			{
			application->configure();
		
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeap::GetTlsInterfaceL - created tls_application_eap_fast_c \n")));			
			application->start_initialize_PAC_store();
			}
	}


	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeap::GetTlsInterfaceL - Creating tls_record_c \n")));

	record = new tls_record_c(
		aTools,
		amEapType,
		false,
		application,
		true,
		is_client_when_true,
		iEapType,
		receive_network_id);		
	if (record == 0)
	{
		// Out of memory
		// application takes care of eap_core_c deletion
		application->shutdown();
		delete application;
		amEapType->shutdown();
		delete amEapType;
		User::Leave(KErrGeneral);		
	}
	else if (record->get_is_valid() == false)
	{
		// Out of memory
		// record takes care of application deletion
		record->shutdown();
		delete record;
		amEapType->shutdown();
		delete amEapType;
		User::Leave(KErrGeneral);					
	}	

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeap::GetTlsInterfaceL - Creating the OS independent portion - eap_type_tls_peap_c \n")));
	
	// Create the OS independent portion
	
	iType = new eap_type_tls_peap_c(
		aTools, 
		eap_core, 
		amEapType, 
		true, 
		record, 
		true, 
		is_client_when_true, 
		iEapType, 
		receive_network_id);	
	if (iType == 0)
	{
		// Out of memory
		// record takes care of application deletion
		record->shutdown();
		delete record;
		amEapType->shutdown();
		delete amEapType;
		User::Leave(KErrNoMemory);							
	}
	else if(iType->get_is_valid() == false)
	{
		iType->shutdown();
		// type deletes all
		delete iType;
		iType = NULL;
		User::Leave(KErrGeneral);		
	}
	
	return application;
}
#endif
// ----------------------------------------------------------

#ifdef USE_EAP_SIMPLE_CONFIG

eap_base_type_c* CEapTlsPeap::GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
											   abs_eap_base_type_c* const aPartner,
											   const bool is_client_when_true,
											   const eap_am_network_id_c * const receive_network_id,
											   abs_eap_configuration_if_c * const /*configuration_if*/)
	
#else
	
eap_base_type_c* CEapTlsPeap::GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
											abs_eap_base_type_c* const aPartner,
											const bool is_client_when_true,
											const eap_am_network_id_c * const receive_network_id)
	
#endif // #ifdef USE_EAP_SIMPLE_CONFIG
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::GetStackInterfaceL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::GetStackInterfaceL()\n"));

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeap::GetStackInterfaceL -Start- iIndexType=%d, iIndex=%d, Tunneling vendor type=%d, Eap vendor type=%d \n"),
		iIndexType,iIndex, iTunnelingType.get_vendor_type(), iEapType.get_vendor_type()));

	// Create adaptation layer
	eap_am_type_tls_peap_symbian_c* amEapType;
	eap_base_type_c* type;
	tls_record_c* record;

	amEapType = eap_am_type_tls_peap_symbian_c::NewL(
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
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeap::GetStackInterfaceL - created eap_am_type_tls_peap_symbian_c \n")));

	if (iEapType == eap_type_tls)
	{
		// TLS
		record = new tls_record_c(
			aTools,
			amEapType,
			false,
			0,
			false,
			is_client_when_true,
			iEapType,
			receive_network_id);
		if (record == 0)
		{
			// Out of memory
			amEapType->shutdown();
			delete amEapType;
			User::Leave(KErrNoMemory);
		}
		else if (record->get_is_valid() == false)
		{
			record->shutdown();
			delete record;
			amEapType->shutdown();
			delete amEapType;
			User::Leave(KErrGeneral);
		}	
	}
	else
	{
		// PEAP, TTLS and FAST.
	
		eap_core_c* eap_core = new eap_core_c(
			aTools,
			0,
			is_client_when_true,
			receive_network_id,
			true);
		if (eap_core == 0)
		{
			// Out of memory
			amEapType->shutdown();
			delete amEapType;
			User::Leave(KErrNoMemory);
		} 
		else if (eap_core->get_is_valid() == false)
		{
			// Out of memory
			eap_core->shutdown();
			delete eap_core;
			amEapType->shutdown();
			delete amEapType;
			User::Leave(KErrGeneral);
		}
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeap::GetStackInterfaceL - created eap_core_c \n")));
		
		tls_base_application_c* application;
		
#if defined (USE_FAST_EAP_TYPE)		
		if(iEapType == eap_type_fast)
		{
			application = new tls_application_eap_fast_c(
				aTools,
				eap_core,
				true,
				is_client_when_true,
				iEapType,
				receive_network_id,
				amEapType);
			
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeap::GetStackInterfaceL - created tls_application_eap_fast_c \n")));			
		}
		else		
#endif // End: #if defined (USE_FAST_EAP_TYPE)
		{			
			application = new tls_application_eap_core_c(
				aTools,
				eap_core,
				true,
				is_client_when_true,
				iEapType,
				receive_network_id);
			
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeap::GetStackInterfaceL - created tls_application_eap_core_c \n")));	
		}
		if (application == 0)
		{
			// Out of memory
			eap_core->shutdown();
			delete eap_core;
			amEapType->shutdown();
			delete amEapType;
			User::Leave(KErrNoMemory);			
		} 
		else if (application->get_is_valid() == false)
		{
			// Out of memory
			// application takes care of eap_core_c deletion
			application->shutdown();
			delete application;
			amEapType->shutdown();
			delete amEapType;
			User::Leave(KErrGeneral);
		}

		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeap::GetStackInterfaceL - application is valid \n")));	
		
		record = new tls_record_c(
			aTools,
			amEapType,
			false,
			application,
			true,
			is_client_when_true,
			iEapType,
			receive_network_id);		
		if (record == 0)
		{
			// Out of memory
			// application takes care of eap_core_c deletion
			application->shutdown();
			delete application;
			amEapType->shutdown();
			delete amEapType;
			User::Leave(KErrGeneral);		
		}
		else if (record->get_is_valid() == false)
		{
			// Out of memory
			// record takes care of application deletion
			record->shutdown();
			delete record;
			amEapType->shutdown();
			delete amEapType;
			User::Leave(KErrGeneral);					
		}	

	}	

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeap::GetStackInterfaceL - Creating the OS independent portion - eap_type_tls_peap_c \n")));
	
	// Create the OS independent portion
	
	type = new eap_type_tls_peap_c(
		aTools, 
		aPartner, 
		amEapType, 
		true, 
		record, 
		true, 
		is_client_when_true, 
		iEapType, 
		receive_network_id);	
	if (type == 0)
	{
		// Out of memory
		// record takes care of application deletion
		record->shutdown();
		delete record;
		amEapType->shutdown();
		delete amEapType;
		User::Leave(KErrNoMemory);							
	}
	else if(type->get_is_valid() == false)
	{
		type->shutdown();
		// type deletes all
		delete type;
		User::Leave(KErrGeneral);		
	}
	
	return type;
}

// ----------------------------------------------------------

CEapTypeInfo* CEapTlsPeap::GetInfoL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::GetInfoL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::GetInfoL()\n"));

	CEapTypeInfo* info = new(ELeave) CEapTypeInfo((TDesC&)KReleaseDate, (TDesC&)KEapTypeVersion,
												   (TDesC&)KManufacturer);

	return info;
}

// ----------------------------------------------------------

void CEapTlsPeap::DeleteConfigurationL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::DeleteConfigurationL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::DeleteConfigurationL()\n"));

	TUint aTunnelingVendorType = iTunnelingType.get_vendor_type();
	TUint aEapVendorType = iEapType.get_vendor_type();

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::DeleteConfigurationL:Start:iIndexType=%d,iIndex=%d,TunnelingType=%d,EapType=%d"),
			iIndexType, iIndex, aTunnelingVendorType, aEapVendorType));

    EapTlsPeapUtils::DeleteConfigurationL(iIndexType, iIndex, iTunnelingType, iEapType);
	
	// For Encapsulated types
	
	if (iEapType == eap_type_peap
		|| iEapType == eap_type_ttls

#ifdef USE_FAST_EAP_TYPE
		|| iEapType == eap_type_fast
#endif		

		|| iEapType == eap_type_ttls_plain_pap


	) 
	{
		iEapArray.ResetAndDestroy();
		REComSession::ListImplementationsL(KEapTypeInterfaceUid, iEapArray);
			
		for (TInt i = 0; i < iEapArray.Count(); i++)
		{
			if ((iEapType == eap_type_peap && !CEapTypePlugin::IsDisallowedInsidePEAP(*iEapArray[i])) 
				|| (iEapType == eap_type_ttls && !CEapTypePlugin::IsDisallowedInsideTTLS(*iEapArray[i]))
				
#ifdef USE_FAST_EAP_TYPE
				|| (iEapType == eap_type_fast && !CEapTypePlugin::IsDisallowedInsidePEAP(*iEapArray[i]))
#endif						

				|| (iEapType == eap_type_ttls_plain_pap && !CEapTypePlugin::IsDisallowedInsidePEAP(*iEapArray[i]))
					

			)
			{
				// Deleting the encapsulated EAP type configurations possible inside PEAP, TTLS and FAST.

				EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::DeleteConfigurationL: Deleting encapsulated types for EAP type=%d"),
						aEapVendorType));
			
				CEapTypePlugin* eapType;
			
				TEapExpandedType expandedCue = iEapArray[i]->DataType();
			
				EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeap::DeleteConfigurationL: Expanded cue:",
					expandedCue.GetValue().Ptr(), expandedCue.GetValue().Size()));
			
				eapType = CEapTypePlugin::NewL(expandedCue.GetValue(), iIndexType, iIndex);
				
				if(eapType == NULL)
				{
					EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::DeleteConfigurationL: Ecom Error - No specified Expanded EAP plugin")) );
					User::Leave(KErrNotFound);
				}
				
//				eapType->SetTunnelingType(iEapType.get_vendor_type());						
			    TEapExpandedType aExpandedType;
			    
                TInt err = CEapConversion::ConvertInternalTypeToExpandedEAPType(
			            &iEapType,
			            &aExpandedType);

			    eapType->SetTunnelingType(aExpandedType);

#ifdef USE_FAST_EAP_TYPE
				
				// This IAP is deleted. Update the PAC store cleanup table if this IAP is 
				// for EAP-FAST.
				
				if(iEapType == eap_type_fast)
				{
				
#ifdef USE_PAC_STORE
				
					TRAPD(error, UpdatePacStoreCleanupTableL(iIndexType, iIndex, iTunnelingType));
					
					if(error != KErrNone)
					{
						EAP_TRACE_DEBUG_SYMBIAN(
						(_L("CEapTlsPeap::DeleteConfigurationL: WARNING: LEAVE: from UpdatePacStoreCleanupTableL, error=%d"),
						error));			
					}
					else
					{
						EAP_TRACE_DEBUG_SYMBIAN(
						(_L("CEapTlsPeap::DeleteConfigurationL: successfully done UpdatePacStoreCleanupTableL")));						
					}
					
#endif // #ifdef USE_PAC_STORE
					
				}
				
#endif // #ifdef USE_FAST_EAP_TYPE
	
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("CEapTlsPeap::DeleteConfigurationL: PushL(...)")));	
				
				CleanupStack::PushL(eapType);
				
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("CEapTlsPeap::DeleteConfigurationL: DeleteConfigurationL()")));	
				
				eapType->DeleteConfigurationL();
				
				CleanupStack::PopAndDestroy();			
			}
		}	
	} // End: 	if (iEapType == eap_type_peap
	

}

// ----------------------------------------------------------

TUint CEapTlsPeap::GetInterfaceVersion()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::GetInterfaceVersion()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::GetInterfaceVersion()\n"));

	return KInterfaceVersion;
}

// ----------------------------------------------------------

void CEapTlsPeap::SetTunnelingType(const TEapExpandedType aTunnelingType)
    {
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::SetTunnelingType()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::SetTunnelingType()\n"));

    EAP_TRACE_DATA_DEBUG_SYMBIAN(
        (EAPL("CEapTlsPeap::SetTunnelingType - tunneling type"),
        aTunnelingType.GetValue().Ptr(), aTunnelingType.GetValue().Length()));
    
    eap_type_value_e aInternalType;
    
    TInt err = CEapConversion::ConvertExpandedEAPTypeToInternalType(
            &aTunnelingType,
            &aInternalType);
    
    iTunnelingType = aInternalType;
    }

// ----------------------------------------------------------

void CEapTlsPeap::SetIndexL(
		const TIndexType aIndexType, 
		const TInt aIndex)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::SetIndexL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::SetIndexL()\n"));

	TUint aTunnelingVendorType = iTunnelingType.get_vendor_type();
	TUint aEapVendorType = iEapType.get_vendor_type();

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::SetIndexL:Start: Old: iIndexType=%d,iIndex=%d,TunnelingType=%d,EapType=%d"),
			iIndexType, iIndex, aTunnelingVendorType, aEapVendorType));
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::SetIndexL: New: IndexType=%d,Index=%d"),
			aIndexType, aIndex));
	
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
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::SetIndexL(): - session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

    EapTlsPeapUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType, iEapType);

	TPtrC settings;
	TPtrC usercerts;
	TPtrC cacerts;
	TPtrC ciphersuites;

#ifdef USE_FAST_EAP_TYPE
	TPtrC fastSpecialSettings;
#endif
	
	if (iEapType == eap_type_tls)
	{
		settings.Set(KTlsDatabaseTableName);
		usercerts.Set(KTlsAllowedUserCertsDatabaseTableName);
		cacerts.Set(KTlsAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KTlsAllowedCipherSuitesDatabaseTableName);
	}
	else if (iEapType == eap_type_peap)
	{
		settings.Set(KPeapDatabaseTableName);
		usercerts.Set(KPeapAllowedUserCertsDatabaseTableName);
		cacerts.Set(KPeapAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KPeapAllowedCipherSuitesDatabaseTableName);
	}
#if defined (USE_TTLS_EAP_TYPE)
	else if (iEapType == eap_type_ttls)
	{
		settings.Set(KTtlsDatabaseTableName);
		usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
		cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
	}
#endif
#ifdef USE_FAST_EAP_TYPE
	else if (iEapType == eap_type_fast)
	{
		settings.Set(KFastGeneralSettingsDBTableName); // This is general settings for FAST.
		fastSpecialSettings.Set(KFastSpecialSettingsDBTableName);
		
		usercerts.Set(KFastAllowedUserCertsDatabaseTableName);
		cacerts.Set(KFastAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KFastAllowedCipherSuitesDatabaseTableName);			
	}
#endif		
	else if (iEapType == eap_type_ttls_plain_pap)
	{
		settings.Set(KTtlsDatabaseTableName);
		usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
		cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
	}
	else
	{
		// Should never happen
		User::Leave(KErrArgument);
	}	
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetIndexL - Setting indices to the tables\n")));
	
	// For the settings db. For EAP-FAST this is the general settings.
	EapTlsPeapUtils::SetIndexL(
		db, 
		settings,
		iIndexType, 
		iIndex, 
		iTunnelingType, 
		aIndexType, 
		aIndex, 
		iTunnelingType);

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetIndexL - Set the index to (general) settings table\n")));
	
	// For the USER certificate db.		
	EapTlsPeapUtils::SetIndexL(
		db, 
		usercerts,
		iIndexType, 
		iIndex, 
		iTunnelingType, 
		aIndexType, 
		aIndex, 
		iTunnelingType);		

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetIndexL - Set the index to USER cert table\n")));
	
	// For the CA certificate db.
	EapTlsPeapUtils::SetIndexL(
		db, 
		cacerts,
		iIndexType, 
		iIndex, 
		iTunnelingType, 
		aIndexType, 
		aIndex, 
		iTunnelingType);

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetIndexL - Set the index to CA cert table\n")));
	
	// For the ciphersuites db.		
	EapTlsPeapUtils::SetIndexL(
		db, 
		ciphersuites,
		iIndexType, 
		iIndex, 
		iTunnelingType, 
		aIndexType, 
		aIndex, 
		iTunnelingType);		

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetIndexL - Set the index to Cipher suite table\n")));
	
#ifdef USE_FAST_EAP_TYPE
	// This special settings is only for EAP-FAST
	if(iEapType == eap_type_fast)
	{
		EapTlsPeapUtils::SetIndexL(
			db, 
			fastSpecialSettings,
			iIndexType, 
			iIndex, 
			iTunnelingType, 
			aIndexType, 
			aIndex, 
			iTunnelingType);
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::SetIndexL - Set the index to EAP-FAST Special settings table\n")));		
		
	}// End: if(iEapType == eap_type_fast)
	
#endif // End: #ifdef USE_FAST_EAP_TYPE
		
	db.Close();
	session.Close();

	CleanupStack::PopAndDestroy(&db);
	CleanupStack::PopAndDestroy(&session);
	
	//////// Encapsulated types

	if (iEapType == eap_type_peap
		|| iEapType == eap_type_ttls

#ifdef USE_FAST_EAP_TYPE
		|| iEapType == eap_type_fast
#endif				

		|| iEapType == eap_type_ttls_plain_pap
			

	)
	{
		iEapArray.ResetAndDestroy();
		REComSession::ListImplementationsL(KEapTypeInterfaceUid, iEapArray);
				
		for (TInt i = 0; i < iEapArray.Count(); i++)
		{
			if ((iEapType == eap_type_peap && !CEapTypePlugin::IsDisallowedInsidePEAP(*iEapArray[i])) 
				|| (iEapType == eap_type_ttls && !CEapTypePlugin::IsDisallowedInsideTTLS(*iEapArray[i]))

#ifdef USE_FAST_EAP_TYPE
				|| (iEapType == eap_type_fast && !CEapTypePlugin::IsDisallowedInsidePEAP(*iEapArray[i]))
#endif										

				|| (iEapType == eap_type_ttls_plain_pap && !CEapTypePlugin::IsDisallowedInsidePEAP(*iEapArray[i]))
										

			)
			{
				// Setting the  index for encapsulated EAP type configurations possible 
				// inside PEAP, TTLS and FAST.

				EAP_TRACE_DEBUG_SYMBIAN(
		    		(_L("EapTlsPeapUtils::SetIndexL - Setting the index to encapsulated EAP types\n")));	
				
				CEapTypePlugin* eapType;
			
				TEapExpandedType expandedCue = iEapArray[i]->DataType();
			
				EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeap::SetIndexL: Expanded cue:",
					expandedCue.GetValue().Ptr(), expandedCue.GetValue().Size()));
			
				eapType = CEapTypePlugin::NewL(expandedCue.GetValue(), iIndexType, iIndex);

				if(eapType == NULL)
				{
					EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::SetIndexL: Ecom Error - No specified Expanded EAP plugin")) );
					User::Leave(KErrNotFound);
				}				
				
			    TEapExpandedType aExpandedType;
			    
			    eap_type_value_e value = iEapType;//.get_vendor_type();
			    TInt err = CEapConversion::ConvertInternalTypeToExpandedEAPType(
			            &value,
			            &aExpandedType);

			    eapType->SetTunnelingType(aExpandedType);						

				CleanupStack::PushL(eapType);
				
				eapType->SetIndexL(aIndexType, aIndex);
				
				EAP_TRACE_DEBUG_SYMBIAN(
		    		(_L("EapTlsPeapUtils::SetIndexL - Set the index to encapsulated EAP types\n")));	
								
				CleanupStack::PopAndDestroy();
			}
		}	
	}
	iIndexType = aIndexType;
	iIndex = aIndex;
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetIndexL - End\n")));		
}

// ----------------------------------------------------------

void CEapTlsPeap::SetConfigurationL(const EAPSettings& aSettings)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::SetConfigurationL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::SetConfigurationL()\n"));

	RDbNamedDatabase db;

	RFs session;

	CleanupClosePushL(session);
	CleanupClosePushL(db);
	TInt error = session.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::SetConfigurationL(): - session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	// This also creates the IAP entry if it doesn't exist
	EapTlsPeapUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType, iEapType);

	EapTlsPeapUtils::SetConfigurationL(
		db,
		aSettings, 
		iIndexType,
		iIndex,
		iTunnelingType,
		iEapType);		
		
	db.Close();
	session.Close();

	CleanupStack::PopAndDestroy(&db);
	CleanupStack::PopAndDestroy(&session);
}

// ----------------------------------------------------------

void CEapTlsPeap::GetConfigurationL(EAPSettings& aSettings)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::GetConfigurationL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::GetConfigurationL()\n"));

	RDbNamedDatabase db;

	RFs session;
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
	TInt error = session.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::GetConfigurationL(): - session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	// This also creates the IAP entry if it doesn't exist
	EapTlsPeapUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType, iEapType);

	EapTlsPeapUtils::GetConfigurationL(
		db,
		aSettings, 
		iIndexType,
		iIndex,
		iTunnelingType,
		iEapType);
		
	db.Close();
	session.Close();

	CleanupStack::PopAndDestroy(&db);
	CleanupStack::PopAndDestroy(&session);
}

// ----------------------------------------------------------

void CEapTlsPeap::CopySettingsL(
	const TIndexType aDestinationIndexType,
	const TInt aDestinationIndex)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::CopySettingsL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::CopySettingsL()\n"));

	TUint aTunnelingVendorType = iTunnelingType.get_vendor_type();
	TUint aEapVendorType = iEapType.get_vendor_type();

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::CopySettingsL:Start:iIndexType=%d,iIndex=%d,TunnelingType=%d,EapType=%d"),
			iIndexType, iIndex, aTunnelingVendorType, aEapVendorType));
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::CopySettingsL: DestinationIndexType=%d,DestinationIndex=%d"),
			aDestinationIndexType, aDestinationIndex));

	// First delete the target configuration
	TIndexType tmpIndexType = iIndexType;
	TInt tmpIndex = iIndex;
			
	iIndexType = aDestinationIndexType;
	iIndex = aDestinationIndex;
	
	// Return the indices
	iIndexType = tmpIndexType;
	iIndex = tmpIndex;
	
	RDbNamedDatabase db;

	RFs session;
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
	TInt error = session.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::CopySettingsL(): - session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	EapTlsPeapUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType, iEapType);

	TPtrC settings;
	TPtrC usercerts;
	TPtrC cacerts;
	TPtrC ciphersuites;

#ifdef USE_FAST_EAP_TYPE
	TPtrC fastSpecialSettings;
#endif
	
	if (iEapType == eap_type_tls)
	{
		settings.Set(KTlsDatabaseTableName);
		usercerts.Set(KTlsAllowedUserCertsDatabaseTableName);
		cacerts.Set(KTlsAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KTlsAllowedCipherSuitesDatabaseTableName);
	}
	else if (iEapType == eap_type_peap)
	{
		settings.Set(KPeapDatabaseTableName);
		usercerts.Set(KPeapAllowedUserCertsDatabaseTableName);
		cacerts.Set(KPeapAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KPeapAllowedCipherSuitesDatabaseTableName);
	}
#if defined (USE_TTLS_EAP_TYPE)
	else if (iEapType == eap_type_ttls)
	{
		settings.Set(KTtlsDatabaseTableName);
		usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
		cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
	}
#endif
	else if (iEapType == eap_type_ttls_plain_pap)
	{
		settings.Set(KTtlsDatabaseTableName);
		usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
		cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
	}
#ifdef USE_FAST_EAP_TYPE
	else if (iEapType == eap_type_fast)
	{
		settings.Set(KFastGeneralSettingsDBTableName); // This is general settings for FAST.
		fastSpecialSettings.Set(KFastSpecialSettingsDBTableName);
		
		usercerts.Set(KFastAllowedUserCertsDatabaseTableName);
		cacerts.Set(KFastAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KFastAllowedCipherSuitesDatabaseTableName);			
	}
#endif		
	else
	{
		// Should never happen
		User::Leave(KErrArgument);
	}	

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CopySettingsL - Copying the tables\n")));
	
	// For the settings db. For EAP-FAST this is the general settings.
	EapTlsPeapUtils::CopySettingsL(
		db, 
		settings,
		iIndexType, 
		iIndex, 
		iTunnelingType, 
		aDestinationIndexType, 
		aDestinationIndex, 
		iTunnelingType);

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CopySettingsL - Copied the (general) settings table\n")));
	
	// For the USER certificate db.				
	EapTlsPeapUtils::CopySettingsL(
		db, 
		usercerts,
		iIndexType, 
		iIndex, 
		iTunnelingType, 
		aDestinationIndexType, 
		aDestinationIndex, 
		iTunnelingType);		

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CopySettingsL - Copied the USER certs table\n")));
	
	// For the CA certificate db.
	EapTlsPeapUtils::CopySettingsL(
		db, 
		cacerts,
		iIndexType, 
		iIndex, 
		iTunnelingType, 
		aDestinationIndexType, 
		aDestinationIndex, 
		iTunnelingType);
		
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CopySettingsL - Copied the CA certs table\n")));
	
	// For the ciphersuites db.		
	EapTlsPeapUtils::CopySettingsL(
		db, 
		ciphersuites,
		iIndexType, 
		iIndex, 
		iTunnelingType, 
		aDestinationIndexType, 
		aDestinationIndex, 
		iTunnelingType);

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CopySettingsL - Copied the Cipher suites table\n")));
	
#ifdef USE_FAST_EAP_TYPE
	// This special settings is only for EAP-FAST
	if(iEapType == eap_type_fast)
	{
		EapTlsPeapUtils::CopySettingsL(
			db, 
			fastSpecialSettings,
			iIndexType, 
			iIndex, 
			iTunnelingType, 
			aDestinationIndexType, 
			aDestinationIndex, 
			iTunnelingType);
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::CopySettingsL - Copied the EAP-FAST Special settings table\n")));		
		
	} // End: if(iEapType == eap_type_fast)
	
#endif // End: #ifdef USE_FAST_EAP_TYPE	
	
	db.Close();
	session.Close();

	CleanupStack::PopAndDestroy(&db);
	CleanupStack::PopAndDestroy(&session);
	
	//////// Copy Encapsulated types
	
	// Operator == takes care of expanded EAP type conversion automatically.
	if (iEapType == eap_type_peap
		|| iEapType == eap_type_ttls

#ifdef USE_FAST_EAP_TYPE
		|| iEapType == eap_type_fast
#endif						

		|| iEapType == eap_type_ttls_plain_pap
						

	)
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::CopySettingsL - Copying encapsulated EAP types\n")));		
		
		iEapArray.ResetAndDestroy();
		REComSession::ListImplementationsL(KEapTypeInterfaceUid, iEapArray);
				
		for (TInt i = 0; i < iEapArray.Count(); i++)
		{
			if ((iEapType == eap_type_peap && !CEapTypePlugin::IsDisallowedInsidePEAP(*iEapArray[i])) 
				|| (iEapType == eap_type_ttls && !CEapTypePlugin::IsDisallowedInsideTTLS(*iEapArray[i]))

#ifdef USE_FAST_EAP_TYPE
				|| (iEapType == eap_type_fast && !CEapTypePlugin::IsDisallowedInsidePEAP(*iEapArray[i]))
#endif										

				|| (iEapType == eap_type_ttls_plain_pap && !CEapTypePlugin::IsDisallowedInsidePEAP(*iEapArray[i]))
									
			)
			{
				// Copying the settings of encapsulated EAP type configurations possible inside PEAP and TTLS.
			
				CEapTypePlugin* eapType;
			
				TEapExpandedType expandedCue = iEapArray[i]->DataType();
			
				EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeap::CopySettingsL: Expanded cue:",
					expandedCue.GetValue().Ptr(), expandedCue.GetValue().Size()));
			
				eapType = CEapTypePlugin::NewL(expandedCue.GetValue(), iIndexType, iIndex);
				
				if(eapType == NULL)
				{
					EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::CopySettingsL: Ecom Error - No specified Expanded EAP plugin")) );
					User::Leave(KErrNotFound);
				}
				
                TEapExpandedType aExpandedType;
                
                TInt err = CEapConversion::ConvertInternalTypeToExpandedEAPType(
                        &iEapType,
                        &aExpandedType);

                eapType->SetTunnelingType(aExpandedType);

                //eapType->SetTunnelingType(iEapType.get_vendor_type());						

				CleanupStack::PushL(eapType);
				
				eapType->CopySettingsL(aDestinationIndexType, aDestinationIndex);
				
				EAP_TRACE_DEBUG_SYMBIAN(
					(_L("EapTlsPeapUtils::CopySettingsL - Copied the encapsulated settings\n")));	
		
				CleanupStack::PopAndDestroy();
			}
		}	
	}
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CopySettingsL - End \n")));	

}

// ----------------------------------------------------------

#ifdef USE_PAC_STORE

void CEapTlsPeap::UpdatePacStoreCleanupTableL(const TIndexType aIndexType,
	const TInt aIndex, 
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::UpdatePacStoreCleanupTableL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::UpdatePacStoreCleanupTableL()\n"));

	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("CEapTlsPeap::UpdatePacStoreCleanupTableL: Start")));
	
	CPacStoreDatabase * pacStoreDb	= CPacStoreDatabase::NewL();
	User::LeaveIfNull(pacStoreDb);
	
	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("CEapTlsPeap::UpdatePacStoreCleanupTableL Created PAC store")));	
	
	pacStoreDb->OpenPacStoreL();
	
	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("CEapTlsPeap::UpdatePacStoreCleanupTableL Opened PAC store")));	

	pacStoreDb->AddACleanupReferenceEntryL(aIndexType, aIndex, aTunnelingType);	
	
	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("CEapTlsPeap::UpdatePacStoreCleanupTableL: AddACleanupReferenceEntryL returns")));					
		
	pacStoreDb->Close();

	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeap::UpdatePacStoreCleanupTableL: pacStoreDb Closed")));					
	
	delete pacStoreDb;
			
	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("CEapTlsPeap::UpdatePacStoreCleanupTableL: End")));	

}

#endif // #ifdef USE_PAC_STORE

// ----------------------------------------------------------
// End of file

