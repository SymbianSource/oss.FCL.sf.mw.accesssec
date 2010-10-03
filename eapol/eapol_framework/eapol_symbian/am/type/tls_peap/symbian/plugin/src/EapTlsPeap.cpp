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
* %version: 79 %
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
	#if defined(USE_PAC_STORE)
		#include "pac_store_db_symbian.h"
	#endif //#if defined(USE_PAC_STORE)
#endif //#if defined(USE_FAST_EAP_TYPE)

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


#include "eapol_key_types.h"

// LOCAL CONSTANTS

// The version number of this interface. At the moment this version number is
// common for all three plug-in interfaces.
const TUint KInterfaceVersion = 1;

#if defined(USE_FAST_EAP_TYPE)
	const u32_t KRemovePacStoreInitializationTimerID = 0;
#endif //#if defined(USE_FAST_EAP_TYPE)

// ================= MEMBER FUNCTIONS =======================

CEapTlsPeap::CEapTlsPeap(const TIndexType aIndexType,	
				 const TInt aIndex,
				 const eap_type_value_e aEapType,
				 abs_eap_am_tools_c * const aTools)
: iIndexType(aIndexType)
, iIndex(aIndex)
, iEapType(aEapType)
, iTunnelingType(eap_type_none)
, m_am_tools(aTools)
#if defined(USE_FAST_EAP_TYPE)
, iPacStoreInitialization(NULL)
, iInitializer(NULL)
#endif //#if defined(USE_FAST_EAP_TYPE)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::CEapTlsPeap()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::CEapTlsPeap()\n"));
}

// ----------------------------------------------------------

CEapTlsPeap* CEapTlsPeap::NewTlsL(SPluginInfo *aIapInfo)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::NewTlsL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::NewTlsL()\n"));

	CEapTlsPeap* self = new (ELeave) CEapTlsPeap(aIapInfo->indexType, aIapInfo->index, eap_type_tls, aIapInfo->aTools);

	CleanupStack::PushL(self);

	self->ConstructL();
	
	CleanupStack::Pop(self);

	return self;
}

// ----------------------------------------------------------

CEapTlsPeap* CEapTlsPeap::NewPeapL(SPluginInfo *aIapInfo)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::NewPeapL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::NewPeapL()\n"));

	CEapTlsPeap* self = new (ELeave) CEapTlsPeap(aIapInfo->indexType, aIapInfo->index, eap_type_peap, aIapInfo->aTools);

	CleanupStack::PushL(self);

	self->ConstructL();
	
	CleanupStack::Pop(self);

	return self;
}

// ----------------------------------------------------------

#if defined(USE_TTLS_EAP_TYPE)

CEapTlsPeap* CEapTlsPeap::NewTtlsL(SPluginInfo *aIapInfo)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::NewTtlsL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::NewTtlsL()\n"));

	CEapTlsPeap* self = new (ELeave) CEapTlsPeap(aIapInfo->indexType, aIapInfo->index, eap_type_ttls, aIapInfo->aTools);

	CleanupStack::PushL(self);

	self->ConstructL();
	
	CleanupStack::Pop(self);

	return self;
}

#endif // #if defined(USE_TTLS_EAP_TYPE)

// ----------------------------------------------------------


// ---------------------------------------------------------
// CEapTtlsPapActive::NewTtlsPapL()
// ---------------------------------------------------------
// 

CEapTlsPeap* CEapTlsPeap::NewTtlsPapL( SPluginInfo* aIapInfo )
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::NewTtlsPapL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::NewTtlsPapL()\n"));

	CEapTlsPeap* self = new (ELeave) CEapTlsPeap(aIapInfo->indexType, aIapInfo->index, eap_expanded_type_ttls_plain_pap.get_type(), aIapInfo->aTools);

	CleanupStack::PushL(self);

	self->ConstructL();
	
	CleanupStack::Pop(self);

	return self;
}


// ----------------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

CEapTlsPeap* CEapTlsPeap::NewFastL(SPluginInfo *aIapInfo)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::NewFastL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::NewFastL()\n"));

	CEapTlsPeap* self = new (ELeave) CEapTlsPeap(aIapInfo->indexType, aIapInfo->index, eap_type_fast, aIapInfo->aTools);

	CleanupStack::PushL(self);

	self->ConstructL();
	
	CleanupStack::Pop(self);

	return self;
}

#endif // #if defined(USE_FAST_EAP_TYPE)

//--------------------------------------------------

//
void CEapTlsPeap::ConstructL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::ConstructL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::ConstructL()\n"));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	{
		const u8_t DEFAULT_PREFIX[] = "EAP-SERVER";
		eap_variable_data_c tmp_prefix(m_am_tools);

		if (tmp_prefix.get_is_valid() == false)
		{
			status = eap_status_allocation_error;
			(void) EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (status == eap_status_ok)
		{
			status = tmp_prefix.set_copy_of_buffer(DEFAULT_PREFIX, sizeof(DEFAULT_PREFIX)-1ul);;
			if (status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (status == eap_status_ok)
		{
			status = tmp_prefix.add_end_null();
			if (status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (status == eap_status_ok)
		{
			status = m_am_tools->set_trace_prefix(&tmp_prefix);
			if (status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	if (status != eap_status_ok)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
}

// ----------------------------------------------------------

CEapTlsPeap::~CEapTlsPeap()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::~CEapTlsPeap()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeap::~CEapTlsPeap()\n"));

	iEapArray.ResetAndDestroy();
	
#if defined(USE_FAST_EAP_TYPE)
	delete iPacStoreInitialization;
	iPacStoreInitialization = 0;
	iInitializer = 0;
#endif // #if defined(USE_FAST_EAP_TYPE)

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::~CEapTlsPeap() iType deleted\n")));
}

// ----------------------------------------------------------

#ifdef USE_EAP_SIMPLE_CONFIG

eap_base_type_c* CEapTlsPeap::GetStackInterfaceL(
	abs_eap_am_tools_c* const aTools, 
	abs_eap_base_type_c* const aPartner,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id,
	abs_eap_configuration_if_c * const /*configuration_if*/)
	
#else
	
eap_base_type_c* CEapTlsPeap::GetStackInterfaceL(
	abs_eap_am_tools_c* const aTools, 
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
	eap_am_type_tls_peap_symbian_c* amEapType = 0;
	eap_base_type_c* type = 0;
	tls_record_c* record = 0;

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
				amEapType,
				0);
			
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

		|| iEapType == eap_expanded_type_ttls_plain_pap.get_type()


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

				|| (iEapType == eap_expanded_type_ttls_plain_pap.get_type() && !CEapTypePlugin::IsDisallowedInsidePEAP(*iEapArray[i]))
					

			)
			{
				// Deleting the encapsulated EAP type configurations possible inside PEAP, TTLS and FAST.

				EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::DeleteConfigurationL: Deleting encapsulated types for EAP type=%d"),
						aEapVendorType));
			
				CEapTypePlugin* eapType;
			
				TEapExpandedType expandedCue = iEapArray[i]->DataType();
			
				EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeap::DeleteConfigurationL: Expanded cue:",
					expandedCue.GetValue().Ptr(), expandedCue.GetValue().Size()));
			
				eapType = CEapTypePlugin::NewL(expandedCue.GetValue(), iIndexType, iIndex, m_am_tools);
				
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
	else if (iEapType == eap_expanded_type_ttls_plain_pap.get_type())
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

		|| iEapType == eap_expanded_type_ttls_plain_pap.get_type()
			

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

				|| (iEapType == eap_expanded_type_ttls_plain_pap.get_type() && !CEapTypePlugin::IsDisallowedInsidePEAP(*iEapArray[i]))
										

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
			
				eapType = CEapTypePlugin::NewL(expandedCue.GetValue(), iIndexType, iIndex, m_am_tools);

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
	else if (iEapType == eap_expanded_type_ttls_plain_pap.get_type())
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

		|| iEapType == eap_expanded_type_ttls_plain_pap.get_type()
						

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

				|| (iEapType == eap_expanded_type_ttls_plain_pap.get_type() && !CEapTypePlugin::IsDisallowedInsidePEAP(*iEapArray[i]))
									
			)
			{
				// Copying the settings of encapsulated EAP type configurations possible inside PEAP and TTLS.
			
				CEapTypePlugin* eapType;
			
				TEapExpandedType expandedCue = iEapArray[i]->DataType();
			
				EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeap::CopySettingsL: Expanded cue:",
					expandedCue.GetValue().Ptr(), expandedCue.GetValue().Size()));
			
				eapType = CEapTypePlugin::NewL(expandedCue.GetValue(), iIndexType, iIndex, m_am_tools);
				
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

TInt CEapTlsPeap::InitialisePacStore(AbsPacStoreInitializer * const initializer)
{

#if defined(USE_FAST_EAP_TYPE)

	if (iEapType == eap_type_fast)
	{
		iInitializer = 0;

		delete iPacStoreInitialization;

		TRAPD(error, (iPacStoreInitialization = CPacStoreInitialization::NewL(iIndexType, iIndex, iEapType, m_am_tools)));
		if (error != KErrNone)
		{
			if (iPacStoreInitialization != 0)
			{
				delete iPacStoreInitialization;
				iPacStoreInitialization = 0;
			}

			return error;
		}

		iInitializer = initializer;

		eap_status_e status = iPacStoreInitialization->InitialisePacStore(this);
		if (status != eap_status_ok)
		{
			return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));
		}
	}

#else

	EAP_UNREFERENCED_PARAMETER(initializer);

#endif //#if defined(USE_FAST_EAP_TYPE)

	return KErrNone;

}

//--------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

eap_status_e CEapTlsPeap::complete_start_initialize_PAC_store(
	const eap_fast_completion_operation_e completion_operation,
	const eap_fast_initialize_pac_store_completion_e completion)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("this = 0x%08x, message_function: starts: CEapTlsPeap::complete_start_initialize_PAC_store(): completion_operation=%d, completion=%d\n"),
		 this,
		 completion_operation,
		 completion));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapTlsPeap::complete_start_initialize_PAC_store()");

	EAP_UNREFERENCED_PARAMETER(completion_operation);
	EAP_UNREFERENCED_PARAMETER(completion);

	EAP_ASSERT(completion_operation == eap_fast_completion_operation_none);
	EAP_ASSERT(completion == eap_fast_initialize_pac_store_only);

	TInt error = iInitializer->CompleteInitialisePacStore();

	if (error != KErrNone)
	{
		delete iPacStoreInitialization;
		iPacStoreInitialization = 0;
		iInitializer = 0;
	}
	else
	{
   		eap_status_e status = m_am_tools->am_set_timer(
			this,
			KRemovePacStoreInitializationTimerID,
			0,
			0);

		error = m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));
	}

	return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
}

#endif //#if defined(USE_FAST_EAP_TYPE)

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
	
	CPacStoreDatabase * pacStoreDb	= CPacStoreDatabase::NewL(m_am_tools);
	User::LeaveIfNull(pacStoreDb);
    CleanupStack::PushL(pacStoreDb);

	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("CEapTlsPeap::UpdatePacStoreCleanupTableL Created PAC store")));	
	
	//pacStoreDb->OpenPacStoreL();
	
	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("CEapTlsPeap::UpdatePacStoreCleanupTableL Opened PAC store")));	

	pacStoreDb->AddACleanupReferenceEntryL(aIndexType, aIndex, aTunnelingType);	
	
	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("CEapTlsPeap::UpdatePacStoreCleanupTableL: AddACleanupReferenceEntryL returns")));					
		
	//pacStoreDb->Close();

	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeap::UpdatePacStoreCleanupTableL: pacStoreDb Closed")));					

	CleanupStack::PopAndDestroy(pacStoreDb);

	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("CEapTlsPeap::UpdatePacStoreCleanupTableL: End")));	

}

#endif // #ifdef USE_PAC_STORE

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e CEapTlsPeap::timer_expired(
	const u32_t id,
	void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(id); // in release
	EAP_UNREFERENCED_PARAMETER(data); // in release

	eap_status_e status = eap_status_ok;

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TIMER: [0x%08x]->CEapTlsPeap::timer_expired(id 0x%02x, data 0x%08x).\n"),
		this, id, data));

#if defined(USE_FAST_EAP_TYPE)

	if(id == KRemovePacStoreInitializationTimerID)
	{
		delete iPacStoreInitialization;
		iPacStoreInitialization = 0;
		iInitializer = 0;
	}

#endif // #if defined(USE_FAST_EAP_TYPE)

	return EAP_STATUS_RETURN(m_am_tools, status);

}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e CEapTlsPeap::timer_delete_data(
	const u32_t id,
	void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(id); // in release
	EAP_UNREFERENCED_PARAMETER(data); // in release

	eap_status_e status = eap_status_ok;

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TIMER: [0x%08x]->CEapTlsPeap::timer_delete_data(id 0x%02x, data 0x%08x).\n"),
		this, id, data));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

// ----------------------------------------------------------
// End of file

