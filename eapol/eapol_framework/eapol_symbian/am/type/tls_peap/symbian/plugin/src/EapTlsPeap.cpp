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
* %version: 35.1.3 %
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

#include <EapTlsPeapUiConnection.h>
#include <EapTlsUi.h>
#include <EapPeapUi.h>
#if defined(USE_TTLS_EAP_TYPE)
	#include <EapTtlsUi.h>
#endif

#if defined(USE_FAST_EAP_TYPE)
#include <eapfastui.h>
#include "tls_application_eap_fast.h"
#endif 

#include "eap_am_type_tls_peap_symbian.h"
#include "eap_type_tls_peap.h"
#include "tls_record.h"
#include "eap_core.h"
#include "tls_application_eap_core.h"
#include "eap_am_tools_symbian.h"
#include "eap_am_trace_symbian.h"

#ifdef USE_PAC_STORE
#include "pac_store_db_symbian.h"
#endif

#include <papui.h>

// LOCAL CONSTANTS

// The version number of this interface. At the moment this version number is
// common for all three plug-in interfaces.
const TUint KInterfaceVersion = 1;


// ================= MEMBER FUNCTIONS =======================


CEapTlsPeap::CEapTlsPeap(const TIndexType aIndexType,	
				 const TInt aIndex,
				 const eap_type_value_e aEapType)
: iIndexType(aIndexType)
, iIndex(aIndex)
, iEapType(aEapType)
, iTunnelingType(eap_type_none)
{

#ifdef USE_EAP_EXPANDED_TYPES

	ASSERT(iEapType.get_vendor_id() == eap_type_vendor_id_ietf);
	ASSERT(iTunnelingType.get_vendor_id() == eap_type_vendor_id_ietf);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

}

// ----------------------------------------------------------

CEapTlsPeap* CEapTlsPeap::NewTlsL(SIapInfo *aIapInfo)
{
	return new (ELeave) CEapTlsPeap(aIapInfo->indexType, aIapInfo->index, eap_type_tls);
}

// ----------------------------------------------------------

CEapTlsPeap* CEapTlsPeap::NewPeapL(SIapInfo *aIapInfo)
{
	return new (ELeave) CEapTlsPeap(aIapInfo->indexType, aIapInfo->index, eap_type_peap);
}

// ----------------------------------------------------------

#if defined(USE_TTLS_EAP_TYPE)

CEapTlsPeap* CEapTlsPeap::NewTtlsL(SIapInfo *aIapInfo)
{
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
	return new (ELeave) CEapTlsPeap(
		aIapInfo->indexType, aIapInfo->index, eap_type_ttls_plain_pap );    
    }


// ----------------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

CEapTlsPeap* CEapTlsPeap::NewFastL(SIapInfo *aIapInfo)
{
	return new (ELeave) CEapTlsPeap(aIapInfo->indexType, aIapInfo->index, eap_type_fast);
}

#endif // #if defined(USE_FAST_EAP_TYPE)

// ----------------------------------------------------------

CEapTlsPeap::~CEapTlsPeap()
{
	iEapArray.ResetAndDestroy();
}

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
#ifdef USE_EAP_EXPANDED_TYPES
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeap::GetStackInterfaceL -Start- iIndexType=%d, iIndex=%d, Tunneling vendor type=%d, Eap vendor type=%d \n"),
		iIndexType,iIndex, iTunnelingType.get_vendor_type(), iEapType.get_vendor_type()));
	
#else
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeap::GetStackInterfaceL -Start- iIndexType=%d, iIndex=%d, iTunnelingType=%d, iEapType=%d \n"),
		iIndexType, iIndex, iTunnelingType, iEapType));
	
#endif //#ifdef USE_EAP_EXPANDED_TYPES

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
TInt CEapTlsPeap::InvokeUiL()
{
	TInt buttonId(0);

#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeap::InvokeUiL -Start- iIndexType=%d, iIndex=%d, Tunneling vendor type=%d, Eap vendor type=%d \n"),
		iIndexType,iIndex, iTunnelingType.get_vendor_type(), iEapType.get_vendor_type()));

	CEapTlsPeapUiConnection uiConn(iIndexType, iIndex, 
									iTunnelingType.get_vendor_type(), iEapType.get_vendor_type());
	
#else

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeap::InvokeUiL -Start- iIndexType=%d, iIndex=%d, iTunnelingType=%d, iEapType=%d \n"),
		iIndexType, iIndex, iTunnelingType, iEapType));

    CEapTlsPeapUiConnection uiConn(iIndexType, iIndex, iTunnelingType, iEapType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeap::InvokeUiL Created UI connection \n")));

#ifdef USE_EAP_EXPANDED_TYPES

	switch (iEapType.get_vendor_type())
	
#else

	switch (iEapType)

#endif //#ifdef USE_EAP_EXPANDED_TYPES
	{
	case eap_type_tls:
		{
			CEapTlsUi* tls_ui = CEapTlsUi::NewL(&uiConn);	
			CleanupStack::PushL(tls_ui);
			buttonId = tls_ui->InvokeUiL();
			CleanupStack::PopAndDestroy(tls_ui);	
		}
		break;

	case eap_type_peap:
		{
			CEapPeapUi* peap_ui = CEapPeapUi::NewL(&uiConn, iIndexType, iIndex);
			CleanupStack::PushL(peap_ui);
			buttonId = peap_ui->InvokeUiL();
			CleanupStack::PopAndDestroy(peap_ui);
		}
		break;

#if defined (USE_TTLS_EAP_TYPE)
	case eap_type_ttls:
		{
			CEapTtlsUi* ttls_ui = CEapTtlsUi::NewL(&uiConn, iIndexType, iIndex);
			CleanupStack::PushL(ttls_ui);
			buttonId = ttls_ui->InvokeUiL();
			CleanupStack::PopAndDestroy(ttls_ui);
		}
		break;
#endif

#if defined (USE_FAST_EAP_TYPE)
	case eap_type_fast:
		{
			CEapFastUi* fast_ui = CEapFastUi::NewL(&uiConn, iIndexType, iIndex);
			CleanupStack::PushL(fast_ui);
			buttonId = fast_ui->InvokeUiL();
			CleanupStack::PopAndDestroy(fast_ui);
		}
		break;
#endif
		
	case eap_type_ttls_plain_pap:
	    {
	        CPapUi* papUi = CPapUi::NewL( &uiConn );
	        CleanupStack::PushL( papUi );
	        buttonId = papUi->InvokeUiL();
	        CleanupStack::PopAndDestroy( papUi );
	    }
	    break;

	default:
		// Should never happen
		User::Leave(KErrArgument);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeap::InvokeUiL -End-\n")));
	
	return buttonId;
}
// ----------------------------------------------------------
CEapTypeInfo* CEapTlsPeap::GetInfoLC()
{
	CEapTypeInfo* info = new(ELeave) CEapTypeInfo((TDesC&)KReleaseDate, (TDesC&)KEapTypeVersion,
												   (TDesC&)KManufacturer);
	CleanupStack::PushL(info);
	return info;
}

// ----------------------------------------------------------

void CEapTlsPeap::DeleteConfigurationL()
{
#ifdef USE_EAP_EXPANDED_TYPES
	
	TUint aTunnelingVendorType = iTunnelingType.get_vendor_type();
	TUint aEapVendorType = iEapType.get_vendor_type();
	
#else
	
	TUint aTunnelingVendorType = static_cast<TUint>(iTunnelingType);
	TUint aEapVendorType = static_cast<TUint>(iEapType);
	
#endif //#ifdef USE_EAP_EXPANDED_TYPES

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
			if ((iEapType == eap_type_peap && !CEapType::IsDisallowedInsidePEAP(*iEapArray[i])) 
				|| (iEapType == eap_type_ttls && !CEapType::IsDisallowedInsideTTLS(*iEapArray[i]))
				
#ifdef USE_FAST_EAP_TYPE
				|| (iEapType == eap_type_fast && !CEapType::IsDisallowedInsidePEAP(*iEapArray[i]))
#endif						

				|| (iEapType == eap_type_ttls_plain_pap && !CEapType::IsDisallowedInsidePEAP(*iEapArray[i]))
					

			)
			{
				// Deleting the encapsulated EAP type configurations possible inside PEAP, TTLS and FAST.

				EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::DeleteConfigurationL: Deleting encapsulated types for EAP type=%d"),
						aEapVendorType));
			
				CEapType* eapType;
			
#ifdef USE_EAP_EXPANDED_TYPES		
			
				TBuf8<KExpandedEAPTypeSize> expandedCue = iEapArray[i]->DataType();
			
				EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeap::DeleteConfigurationL: Expanded cue:",
				expandedCue.Ptr(), expandedCue.Size()));
			
				eapType = CEapType::NewL(expandedCue, iIndexType, iIndex);
				
				if(eapType == NULL)
				{
					EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::DeleteConfigurationL: Ecom Error - No specified Expanded EAP plugin")) );
					User::Leave(KErrNotFound);
				}
				
				eapType->SetTunnelingType(iEapType.get_vendor_type());						

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
#endif // USE_EAP_EXPANDED_TYPES		
	

#ifndef USE_EAP_EXPANDED_TYPES		
//#else // For normal EAP types.
			
				TBuf8<3> cue = iEapArray[i]->DataType();

				EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeap::DeleteConfigurationL: cue:",
						cue.Ptr(), cue.Size()));

				eapType = CEapType::NewL(cue, iIndexType, iIndex);	

				if(eapType == NULL)
					{
						EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::DeleteConfigurationL: Ecom Error - No specified EAP plugin")) );
						User::Leave(KErrNotFound);
					}
				
				eapType->SetTunnelingType(iEapType);					

#endif //#ifndef USE_EAP_EXPANDED_TYPES
								
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
	return KInterfaceVersion;
}

// ----------------------------------------------------------

void CEapTlsPeap::SetTunnelingType(const TInt aTunnelingType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	// Vendor id is eap_type_vendor_id_ietf always in this plugin.
	iTunnelingType.set_eap_type_values(eap_type_vendor_id_ietf, aTunnelingType);

#else

	iTunnelingType = static_cast<eap_type_value_e>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES
}

// ----------------------------------------------------------
void CEapTlsPeap::SetIndexL(
		const TIndexType aIndexType, 
		const TInt aIndex)
{
#ifdef USE_EAP_EXPANDED_TYPES
	
	TUint aTunnelingVendorType = iTunnelingType.get_vendor_type();
	TUint aEapVendorType = iEapType.get_vendor_type();
	
#else
	
	TUint aTunnelingVendorType = static_cast<TUint>(iTunnelingType);
	TUint aEapVendorType = static_cast<TUint>(iEapType);
	
#endif //#ifdef USE_EAP_EXPANDED_TYPES

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

	RDbs session;

    EapTlsPeapUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType, iEapType);
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
	
	TPtrC settings;
	TPtrC usercerts;
	TPtrC cacerts;
	TPtrC ciphersuites;

#ifdef USE_FAST_EAP_TYPE
	TPtrC fastSpecialSettings;
#endif
	
#ifdef USE_EAP_EXPANDED_TYPES

	switch (iEapType.get_vendor_type())
	
#else

	switch (iEapType)

#endif //#ifdef USE_EAP_EXPANDED_TYPES
	{
	case eap_type_tls:
		{
			settings.Set(KTlsDatabaseTableName);
			usercerts.Set(KTlsAllowedUserCertsDatabaseTableName);
			cacerts.Set(KTlsAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KTlsAllowedCipherSuitesDatabaseTableName);
		}
		break;

	case eap_type_peap:
		{
			settings.Set(KPeapDatabaseTableName);
			usercerts.Set(KPeapAllowedUserCertsDatabaseTableName);
			cacerts.Set(KPeapAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KPeapAllowedCipherSuitesDatabaseTableName);
		}
		break;

#if defined (USE_TTLS_EAP_TYPE)
	case eap_type_ttls:
		{
			settings.Set(KTtlsDatabaseTableName);
			usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
			cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
		}
		break;
#endif

#ifdef USE_FAST_EAP_TYPE
	case eap_type_fast:
		{
			settings.Set(KFastGeneralSettingsDBTableName); // This is general settings for FAST.
			fastSpecialSettings.Set(KFastSpecialSettingsDBTableName);
			
			usercerts.Set(KFastAllowedUserCertsDatabaseTableName);
			cacerts.Set(KFastAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KFastAllowedCipherSuitesDatabaseTableName);			
		}
		break;
#endif		

	case eap_type_ttls_plain_pap:
		{
			settings.Set(KTtlsDatabaseTableName);
			usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
			cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
		}
		break;
		
	default:
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
	CleanupStack::PopAndDestroy(2); // db, session.
	
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
			if ((iEapType == eap_type_peap && !CEapType::IsDisallowedInsidePEAP(*iEapArray[i])) 
				|| (iEapType == eap_type_ttls && !CEapType::IsDisallowedInsideTTLS(*iEapArray[i]))

#ifdef USE_FAST_EAP_TYPE
				|| (iEapType == eap_type_fast && !CEapType::IsDisallowedInsidePEAP(*iEapArray[i]))
#endif										

				|| (iEapType == eap_type_ttls_plain_pap && !CEapType::IsDisallowedInsidePEAP(*iEapArray[i]))
										

			)
			{
				// Setting the  index for encapsulated EAP type configurations possible 
				// inside PEAP, TTLS and FAST.

				EAP_TRACE_DEBUG_SYMBIAN(
		    		(_L("EapTlsPeapUtils::SetIndexL - Setting the index to encapsulated EAP types\n")));	
				
				CEapType* eapType;
			
#ifdef USE_EAP_EXPANDED_TYPES		
			
				TBuf8<KExpandedEAPTypeSize> expandedCue = iEapArray[i]->DataType();
			
				EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeap::SetIndexL: Expanded cue:",
				expandedCue.Ptr(), expandedCue.Size()));
			
				eapType = CEapType::NewL(expandedCue, iIndexType, iIndex);

				if(eapType == NULL)
				{
					EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::SetIndexL: Ecom Error - No specified Expanded EAP plugin")) );
					User::Leave(KErrNotFound);
				}				
				
				eapType->SetTunnelingType(iEapType.get_vendor_type());						

#else // For normal EAP types.
			
				TBuf8<3> cue = iEapArray[i]->DataType();
			
				eapType = CEapType::NewL(cue, iIndexType, iIndex);	
				
				eapType->SetTunnelingType(iEapType);					

#endif //#ifdef USE_EAP_EXPANDED_TYPES

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

void CEapTlsPeap::SetConfigurationL(const EAPSettings& aSettings)
{
	RDbNamedDatabase db;

	RDbs session;	
	
	// This also creates the IAP entry if it doesn't exist
	EapTlsPeapUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType, iEapType);
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);

	EapTlsPeapUtils::SetConfigurationL(
		db,
		aSettings, 
		iIndexType,
		iIndex,
		iTunnelingType,
		iEapType);		
		
	CleanupStack::PopAndDestroy(2); // db, session
}

void CEapTlsPeap::GetConfigurationL(EAPSettings& aSettings)
{
	RDbNamedDatabase db;

	RDbs session;
	
	// This also creates the IAP entry if it doesn't exist
	EapTlsPeapUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType, iEapType);
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);

	EapTlsPeapUtils::GetConfigurationL(
		db,
		aSettings, 
		iIndexType,
		iIndex,
		iTunnelingType,
		iEapType);
		
	db.Close();
	CleanupStack::PopAndDestroy(2); // db, session
}

void CEapTlsPeap::CopySettingsL(
	const TIndexType aDestinationIndexType,
	const TInt aDestinationIndex)
{
#ifdef USE_EAP_EXPANDED_TYPES
	
	TUint aTunnelingVendorType = iTunnelingType.get_vendor_type();
	TUint aEapVendorType = iEapType.get_vendor_type();
	
#else
	
	TUint aTunnelingVendorType = static_cast<TUint>(iTunnelingType);
	TUint aEapVendorType = static_cast<TUint>(iEapType);
	
#endif //#ifdef USE_EAP_EXPANDED_TYPES

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

	RDbs session;
	
	EapTlsPeapUtils::OpenDatabaseL(db, session, iIndexType, iIndex, iTunnelingType, iEapType);
	
	CleanupClosePushL(session);
	CleanupClosePushL(db);
	
	TPtrC settings;
	TPtrC usercerts;
	TPtrC cacerts;
	TPtrC ciphersuites;

#ifdef USE_FAST_EAP_TYPE
	TPtrC fastSpecialSettings;
#endif
	
#ifdef USE_EAP_EXPANDED_TYPES

	switch (iEapType.get_vendor_type())
	
#else

	switch (iEapType)

#endif //#ifdef USE_EAP_EXPANDED_TYPES
	{
	case eap_type_tls:
		{
			settings.Set(KTlsDatabaseTableName);
			usercerts.Set(KTlsAllowedUserCertsDatabaseTableName);
			cacerts.Set(KTlsAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KTlsAllowedCipherSuitesDatabaseTableName);
		}
		break;

	case eap_type_peap:
		{
			settings.Set(KPeapDatabaseTableName);
			usercerts.Set(KPeapAllowedUserCertsDatabaseTableName);
			cacerts.Set(KPeapAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KPeapAllowedCipherSuitesDatabaseTableName);
		}
		break;

#if defined (USE_TTLS_EAP_TYPE)
	case eap_type_ttls:
		{
			settings.Set(KTtlsDatabaseTableName);
			usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
			cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
		}
		break;
#endif

	case eap_type_ttls_plain_pap:
		{
			settings.Set(KTtlsDatabaseTableName);
			usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
			cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
		}
		break;
		
#ifdef USE_FAST_EAP_TYPE
	case eap_type_fast:
		{
			settings.Set(KFastGeneralSettingsDBTableName); // This is general settings for FAST.
			fastSpecialSettings.Set(KFastSpecialSettingsDBTableName);
			
			usercerts.Set(KFastAllowedUserCertsDatabaseTableName);
			cacerts.Set(KFastAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KFastAllowedCipherSuitesDatabaseTableName);			
		}
		break;
#endif		

	default:
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
	CleanupStack::PopAndDestroy(2); // db, session
	
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
			if ((iEapType == eap_type_peap && !CEapType::IsDisallowedInsidePEAP(*iEapArray[i])) 
				|| (iEapType == eap_type_ttls && !CEapType::IsDisallowedInsideTTLS(*iEapArray[i]))

#ifdef USE_FAST_EAP_TYPE
				|| (iEapType == eap_type_fast && !CEapType::IsDisallowedInsidePEAP(*iEapArray[i]))
#endif										

				|| (iEapType == eap_type_ttls_plain_pap && !CEapType::IsDisallowedInsidePEAP(*iEapArray[i]))
									
			)
			{
				// Copying the settings of encapsulated EAP type configurations possible inside PEAP and TTLS.
			
				CEapType* eapType;
			
#ifdef USE_EAP_EXPANDED_TYPES		
			
				TBuf8<KExpandedEAPTypeSize> expandedCue = iEapArray[i]->DataType();
			
				EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeap::CopySettingsL: Expanded cue:",
				expandedCue.Ptr(), expandedCue.Size()));
			
				eapType = CEapType::NewL(expandedCue, iIndexType, iIndex);
				
				if(eapType == NULL)
				{
					EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeap::CopySettingsL: Ecom Error - No specified Expanded EAP plugin")) );
					User::Leave(KErrNotFound);
				}
				
				eapType->SetTunnelingType(iEapType.get_vendor_type());						

#else // For normal EAP types.
			
				TBuf8<3> cue = iEapArray[i]->DataType();
			
				eapType = CEapType::NewL(cue, iIndexType, iIndex);	
				
				eapType->SetTunnelingType(iEapType);					

#endif //#ifdef USE_EAP_EXPANDED_TYPES
				
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

#ifdef USE_PAC_STORE

void CEapTlsPeap::UpdatePacStoreCleanupTableL(const TIndexType aIndexType,
	const TInt aIndex, 
	const eap_type_value_e aTunnelingType)
{
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
	User::Leave(KErrNone);
}

#endif // #ifdef USE_PAC_STORE

// End of file

