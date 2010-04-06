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
* %version: 253 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 388 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_type_tls_peap_symbian.h"
#include "abs_eap_am_crypto.h"
#include "abs_eap_am_mutex.h"
#include "eap_crypto_api.h"
#include "abs_eap_base_type.h"
#include "eap_type_tls_peap_types.h"
#include "eap_am_tools_symbian.h"
#include "abs_tls_am_services.h"
#include "eap_base_type.h"
#include "eap_array_algorithms.h"

#include "EapTlsPeapUtils.h"
#include "EapTlsPeapDbDefaults.h"
#include "EapTlsPeapDbParameterNames.h"
#include "EapTlsPeapCertInterface.h"

#include <x509cert.h>
#include <x509keys.h>
#include "eap_am_dh_primes.h"
#include <asn1dec.h>
#include <asn1enc.h>
#include "EapTlsPeapTimerValues.h"
#include "eap_state_notification.h"
#include "eap_am_trace_symbian.h"
#include "eap_automatic_variable.h"

#if defined(USE_FAST_EAP_TYPE)
#include "abs_tls_am_application_eap_fast.h"
#include "eap_fast_strings.h"
#include "eap_fast_tlv_payloads.h"
//#include "eap_am_async_wait_symbian.h"
#include "EapFastActive.h"
#include "eap_tlv_header.h"
#include "eap_tlv_message_data.h"
#endif

#include "eap_ttls_pap_active.h"

#ifdef USE_PAC_STORE
#include "pac_store_db_symbian.h"
#include <f32file.h>
#endif

#ifdef USE_EAP_EXPANDED_TYPES
#include "eap_header_string.h"
#endif //#ifdef USE_EAP_EXPANDED_TYPES

#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)
#include "eap_config.h"
#include "eap_file_config.h"
#include "eap_am_file_input_symbian.h"
#endif

const TUint KMaxSqlQueryLength = 512;
const TUint KMaxDBFieldNameLength = 255;
const TUint KDSASignatureLength = 40;
const TInt 	KDefaultColumnInView_One = 1; // For DB view.
const TInt 	KMicroSecsInASecond = 1000000; // 1000000 micro seconds is 1 second.
		
/**
 * Length of the MAC address
 */
#ifdef USE_FAST_EAP_TYPE
 const TUint8 KMacAddressLength = 6;
#endif
//--------------------------------------------------

eap_am_type_tls_peap_symbian_c::eap_am_type_tls_peap_symbian_c(
	abs_eap_am_tools_c * const aTools,
	abs_eap_base_type_c * const aPartner,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType,
	const bool aIsClient,
	const eap_am_network_id_c * const receive_network_id)
	: CActive(CActive::EPriorityStandard)
	  , m_index_type(aIndexType)
	  , m_index(aIndex)
	  , m_tunneling_type(aTunnelingType)
	  , m_partner(aPartner)
	  , m_am_tools(static_cast<eap_am_tools_symbian_c*> (aTools))
	  , m_tls_am_partner(0)
#if defined(USE_FAST_EAP_TYPE)
	  , m_tls_application(0)
	  //, iWaitNoteCancelled( EFalse )
      , iEapFastActiveWaitNote( NULL )
      , iEapFastActiveNotes( NULL )
#endif //#if defined(USE_FAST_EAP_TYPE)
	  , m_is_valid(false)
	  , m_is_client(aIsClient)
	  , m_current_eap_type(aEapType)
	  , m_max_count_of_session_resumes(0ul)
	  , m_cipher_suite(tls_cipher_suites_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA)
	  , m_ca_certificate(0)
	  , m_own_certificate(0)
	  , m_peer_certificate(0)
	  , m_cert_if(0)
	  , m_receive_network_id(aTools)
	  , m_eap_identifier(0u)
	  , m_subject_key_id(0)
	  , m_allowed_user_certs(1)
	  , m_allowed_server_certs(1)
	  , m_peer_public_key(aTools)
	  , m_param_p(aTools)
	  , m_param_q(aTools)
	  , m_param_g(aTools)
	  , m_shutdown_was_called(false)
	  , m_identity_info(0)
	  , m_tunneled_type(eap_type_none)
	  , m_verify_certificate_realm(true)
	  , m_allow_subdomain_matching(false)
	  , m_latest_alert_description(tls_alert_description_none)
	  , m_use_manual_username(false)
	  , m_manual_username(aTools)
	  , m_use_manual_realm(false)
	  , m_manual_realm(aTools)
	  , m_tls_peap_server_authenticates_client_policy_flag(true)
	  , m_configured(false)
	  , m_max_session_time(0)
#if defined(USE_EAP_TLS_SESSION_TICKET)
	  , m_use_session_ticket(false)
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)

#if defined(USE_FAST_EAP_TYPE)
	, m_received_tunnel_pac_in_session_ticket(0)
	, m_received_user_authorization_pac_in_session_ticket(0)
	, m_saved_pac_type(eap_fast_pac_type_none)
	, m_completion_operation(eap_fast_completion_operation_none)
	//, m_new_pac_tlv(aTools)
	, m_verification_status(eap_status_process_general_error)
	, m_pac_type(eap_fast_pac_type_none)
	, m_PAC_store_password(aTools)
	//, m_PAC_store_device_seed(aTools)
	, m_imported_PAC_data_password(aTools)
	, m_PAC_store_path(aTools)
	, m_EAP_FAST_IAP_reference(aTools)
	, m_EAP_FAST_Group_reference(aTools)
	, m_EAP_FAST_import_path(aTools)
	, m_eap_fast_completion_status(eap_status_process_general_error)
	, m_eap_fast_pac_store_pending_operation(eap_fast_pac_store_pending_operation_none)
	, m_references_and_data_blocks(aTools)
	, m_new_references_and_data_blocks(aTools)
	, m_ready_references_and_data_blocks(aTools)
	, m_serv_unauth_prov_mode(false)
	, m_serv_auth_prov_mode(false)
	, m_is_notifier_connected(false)
	, m_notifier_data_to_user(NULL)
	, m_notifier_data_pckg_to_user(NULL)
	, m_notifier_data_from_user(NULL)
	, m_notifier_data_pckg_from_user(NULL)
	, m_completed_with_zero(false)
	, m_verificationStatus(false)
	, m_data_reference(m_am_tools)
	, m_notifier_complete(false)
	, m_userResponse(m_am_tools)
	, m_both_completed(0)
	, m_both_asked(0)
#endif //#if defined(USE_FAST_EAP_TYPE)

#ifdef USE_PAC_STORE
	,iPacStoreDb(NULL)
#endif    
	
#ifdef USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS
, m_skip_user_interactions(false)
, m_fileconfig(0)
#endif
	
	
	
    , iEapTtlsPapMaxSessionConfigTime( 0 )
    , iEapTtlsPapActive( NULL )
    
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

#ifdef USE_EAP_EXPANDED_TYPES

	m_tunneling_vendor_type = m_tunneling_type.get_vendor_type();
	m_current_eap_vendor_type = m_current_eap_type.get_vendor_type();

#else

	m_tunneling_vendor_type = static_cast<TUint>(m_tunneling_type);
	m_current_eap_vendor_type = static_cast<TUint>(m_current_eap_type);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	// Set the database table name based on the type
	switch (m_current_eap_vendor_type)
	{
		case eap_type_tls:
			m_db_table_name = KTlsDatabaseTableName;
			m_db_user_cert_table_name = KTlsAllowedUserCertsDatabaseTableName;
			m_db_ca_cert_table_name = KTlsAllowedCACertsDatabaseTableName;
			m_db_cipher_suite_table_name = KTlsAllowedCipherSuitesDatabaseTableName;
			m_db_name = KTlsDatabaseName;	
			break;
		
		case eap_type_peap:
			m_db_table_name = KPeapDatabaseTableName;
			m_db_user_cert_table_name = KPeapAllowedUserCertsDatabaseTableName;
			m_db_ca_cert_table_name = KPeapAllowedCACertsDatabaseTableName;
			m_db_cipher_suite_table_name = KPeapAllowedCipherSuitesDatabaseTableName;
			m_db_name = KPeapDatabaseName;	
			break;
			
		case eap_type_ttls_plain_pap:
		    // use the same case as for eap_type_ttls;
		    // break is not needed
		
		case eap_type_ttls:
			m_db_table_name = KTtlsDatabaseTableName;
			m_db_user_cert_table_name = KTtlsAllowedUserCertsDatabaseTableName;
			m_db_ca_cert_table_name = KTtlsAllowedCACertsDatabaseTableName;
			m_db_cipher_suite_table_name = KTtlsAllowedCipherSuitesDatabaseTableName;
			m_db_name = KTtlsDatabaseName;
			break;
			
#if defined (USE_FAST_EAP_TYPE)
			case eap_type_fast:
			m_db_table_name = KFastGeneralSettingsDBTableName; // General settings
			m_db_fast_special_table_name = KFastSpecialSettingsDBTableName; // Special settings  for only FAST
			m_db_user_cert_table_name = KFastAllowedUserCertsDatabaseTableName;
			m_db_ca_cert_table_name = KFastAllowedCACertsDatabaseTableName;
			m_db_cipher_suite_table_name = KFastAllowedCipherSuitesDatabaseTableName;
			m_db_name = KFastDatabaseName;
			break;
#endif // #if defined (USE_FAST_EAP_TYPE)			
		default:
			{
				// Unsupported type		
				// Should never happen
				EAP_TRACE_ERROR(m_am_tools, 
					TRACE_FLAGS_DEFAULT, (
					EAPL("Unsupported EAP type, m_current_eap_vendor_type=%d \n"),
					m_current_eap_vendor_type));
		
				return;
			}
	}

	if (receive_network_id != 0
		&& receive_network_id->get_is_valid_data() == true)
	{
		eap_status_e status = m_receive_network_id.set_copy_of_network_id(
			receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return;
		}
	}

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
eap_am_type_tls_peap_symbian_c* eap_am_type_tls_peap_symbian_c::NewL(
	abs_eap_am_tools_c * const aTools,
	abs_eap_base_type_c * const aPartner,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType,
	const bool aIsClient,
	const eap_am_network_id_c * const receive_network_id)
{
	if (aEapType != eap_type_tls
		&& aEapType != eap_type_peap
#if defined(USE_TTLS_EAP_TYPE)
		&& aEapType != eap_type_ttls
#endif // #if defined(USE_TTLS_EAP_TYPE)

	    && aEapType != eap_type_ttls_plain_pap
		
#if defined (USE_FAST_EAP_TYPE)
		&& aEapType != eap_type_fast
#endif // #if defined (USE_FAST_EAP_TYPE)	
		)
	{
		User::Leave(KErrNotSupported);
	}

	eap_am_type_tls_peap_symbian_c* self = new(ELeave) eap_am_type_tls_peap_symbian_c(
		aTools, 
		aPartner, 
		aIndexType, 
		aIndex, 
		aTunnelingType,
		aEapType, 
		aIsClient,
		receive_network_id);

	CleanupStack::PushL(self);

	if (self->get_is_valid() != true)
	{
		User::Leave(KErrGeneral);
	}

	self->ConstructL();
	
	CleanupStack::Pop();
	return self;
}

//--------------------------------------------------

//
void eap_am_type_tls_peap_symbian_c::ConstructL()
{
	// Open/create database
	EapTlsPeapUtils::OpenDatabaseL(m_database, m_session, m_index_type, m_index, m_tunneling_type, m_current_eap_type);

	m_cert_if = CEapTlsPeapCertInterface::NewL(m_am_tools, this);

	CActiveScheduler::Add(this);

	// Create and open PAC store (only for EAP-FAST at the moment)
#ifdef USE_PAC_STORE
#ifdef USE_FAST_EAP_TYPE
	
	if(m_current_eap_type == eap_type_fast && iPacStoreDb == NULL)
	{
		iPacStoreDb = CPacStoreDatabase::NewL( this );
		User::LeaveIfNull(iPacStoreDb);
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::ConstructL Created PAC store")));	
		
		iPacStoreDb->OpenPacStoreL();
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::ConstructL Opened PAC store")));		
	}
	m_info_array.Reset();
	
#endif	// End: #ifdef USE_FAST_EAP_TYPE
#endif // End: 	#ifdef USE_PAC_STORE

#ifdef USE_FAST_EAP_TYPE
	
	if(m_current_eap_type == eap_type_fast)
	{
		m_notifier_data_to_user = new(ELeave) TEapFastNotifierStruct;
		m_notifier_data_pckg_to_user = new(ELeave) TPckg<TEapFastNotifierStruct> (*m_notifier_data_to_user);
		
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_tls_peap_symbian_c::ConstructL m_notifier_data_pckg_to_user"),
			m_notifier_data_pckg_to_user->Ptr(),
			m_notifier_data_pckg_to_user->Size()));	
		
		m_notifier_data_from_user = new(ELeave) TEapFastNotifierStruct;
		m_notifier_data_pckg_from_user = new(ELeave) TPckg<TEapFastNotifierStruct> (*m_notifier_data_from_user);		
	}	
#endif	// End: #ifdef USE_FAST_EAP_TYPE	
	

}

//--------------------------------------------------

//

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: function: eap_am_type_tls_peap_symbian_c::shutdown()\n"),
		 (m_is_client == true ? "client": "server")));

	if(IsActive())
	{
	    RDebug::Print( _L("eap_am_type_tls_peap_symbian_c::shutdown() cancelling active object") );
		Cancel();		
	}
	
	else
	{
		if(m_cert_if->IsActive())
		{
			m_cert_if->Cancel();
		}		
	}
	
	if ( iEapTtlsPapActive )
		{
		if ( iEapTtlsPapActive->IsActive() )
			{
			EAP_TRACE_DEBUG_SYMBIAN(
				( _L( " eap_am_type_tls_peap_symbian_c::shutdown() \
				Cancelling iEapTtlsPapActive." ) ) );
			iEapTtlsPapActive->Cancel();
			}
		EAP_TRACE_DEBUG_SYMBIAN(
			( _L( " eap_am_type_tls_peap_symbian_c::shutdown() \
			Deleting iEapTtlsPapActive." ) ) );
		delete iEapTtlsPapActive;
		iEapTtlsPapActive = NULL;
		}
	
#if defined(USE_FAST_EAP_TYPE)		
		if( m_is_notifier_connected )
		{
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L(" eap_am_type_tls_peap_symbian_c::shutdown - calling m_notifier.CancelNotifier")));
			if(IsActive())
				{
				TInt error = m_notifier.CancelNotifier(KEapFastNotifierUid);
				EAP_TRACE_DEBUG_SYMBIAN(
					(_L("eap_am_type_tls_peap_symbian_c::shutdown - CancelNotifier=%d"), error));
				}	
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L(" eap_am_type_securid_symbian_c::shutdown - calling m_notifier.Close()")));
			
			m_notifier.Close(); // Call close only if it is connected.	
			
			m_is_notifier_connected = false;
			
		} // End: if( m_is_notifier_connected )	

		if (m_partner != NULL)
		    {
		    EAP_TRACE_DEBUG_SYMBIAN(
				(_L(" eap_am_type_tls_peap_symbian_c::shutdown - Cancel timers ...")));

		    m_partner->cancel_timer(
				this, 
				KRemoveIAPReferenceTimerID);

		    m_partner->cancel_timer(
				this, 
				KImportFileTimerID);
		
		    m_partner->cancel_timer(
				this, 
				KCompleteReadPacstoreTimerID);

		    m_partner->cancel_timer(
				this, 
				KHandleReadPacstoreTimerID);

		    EAP_TRACE_DEBUG_SYMBIAN(
				(_L(" eap_am_type_tls_peap_symbian_c::shutdown - Timers canceled")));
		    }
		
		if ( iEapFastActiveWaitNote )
			{
			if ( iEapFastActiveWaitNote->IsActive() )
				{
				iEapFastActiveWaitNote->Cancel();
				}
			delete iEapFastActiveWaitNote;
			iEapFastActiveWaitNote = NULL;
			}

		if ( iEapFastActiveNotes )
			{
			if ( iEapFastActiveNotes->IsActive() )
				{
			    iEapFastActiveNotes->Cancel();
				}
			delete iEapFastActiveNotes;
			iEapFastActiveNotes = NULL;
			}
#endif // #if defined(USE_FAST_EAP_TYPE)
	

	m_allowed_server_certs.Reset();
	m_allowed_ca_certs.Close();			
	m_allowed_cipher_suites.Close();			
	m_allowed_user_certs.Reset();			

#ifdef USE_PAC_STORE
#ifdef USE_FAST_EAP_TYPE
	
	if(m_current_eap_type == eap_type_fast && iPacStoreDb != NULL)
	{
		iPacStoreDb->Close();
	}
	
	TInt count=0;
	while (count < m_info_array.Count())
		{
		delete m_info_array[count].iData;
		delete m_info_array[count].iReference;
		}
	m_info_array.Reset();

	EAP_TRACE_DEBUG_SYMBIAN(
			(_L(" eap_am_type_tls_peap_symbian_c::shutdown - Arrays cleared")));

#endif	// End: #ifdef USE_FAST_EAP_TYPE	
#endif	// End: #ifdef USE_PAC_STORE
		
	m_shutdown_was_called = true;
	
#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)
   delete m_fileconfig;
   m_fileconfig = 0;
#endif

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: function: eap_am_type_tls_peap_symbian_c::shutdown() returns\n"),
		 (m_is_client == true ? "client": "server")));

	return eap_status_ok;
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_type_tls_peap_symbian_c::~eap_am_type_tls_peap_symbian_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_type_tls_peap_symbian_c::~eap_am_type_tls_peap_symbian_c()");

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: function: eap_am_type_tls_peap_symbian_c::~eap_am_type_tls_peap_symbian_c()\n"),
		 (m_is_client == true ? "client": "server")));

	EAP_ASSERT(m_shutdown_was_called == true);	

	m_database.Close();
	m_session.Close();

#ifdef USE_FAST_EAP_TYPE
	
	if(m_current_eap_type == eap_type_fast)
	{
		delete m_notifier_data_to_user;
		delete m_notifier_data_pckg_to_user;
		
		delete m_notifier_data_from_user;
		delete m_notifier_data_pckg_from_user;		
	}	
#endif	// End: #ifdef USE_FAST_EAP_TYPE	
		
	delete m_cert_if;

	delete m_ca_certificate;
	delete m_own_certificate;
	delete m_peer_certificate;
	delete m_identity_info;

#ifdef USE_EAP_EXPANDED_TYPES

	m_enabled_tunneling_exp_eap_array.ResetAndDestroy();
	m_disabled_tunneling_exp_eap_array.ResetAndDestroy();

	EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_tls_peap_symbian_c::~eap_am_type_tls_peap_symbian_c() tunneling done.\n")));

#else

	m_iap_eap_array.ResetAndDestroy();

#endif  // #ifdef USE_EAP_EXPANDED_TYPES

#ifdef USE_PAC_STORE
	
	delete iPacStoreDb;
	
#endif	// End: #ifdef USE_PAC_STORE	
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}
//--------------------------------------------------

//

void eap_am_type_tls_peap_symbian_c::RunL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);		
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::RunL - iStatus.Int()=%d, m_state=%d "),
		iStatus.Int() , m_state));
	
#ifdef USE_FAST_EAP_TYPE
	eap_status_e status(eap_status_ok);

	if (m_notifier_complete)
	{
	
		TRAPD(err, CompleteNotifierL());// Only for the notifiers.
		if (err != KErrNone)
			{
			EAP_TRACE_ERROR(m_am_tools, 
					TRACE_FLAGS_DEFAULT, (
					EAPL("eap_am_type_tls_peap_symbian_c::RunL LEAVE from CompleteNotifierL, Error =%d \n"),
					err));
			}

		m_notifier_complete = EFalse;
	}

	if ( m_state == EPasswordCancel ||
		 m_state == EMasterkeyQuery ||
		 m_state == EPasswordQuery ||
		 m_state == EWrongPassword ||
		 m_state == EFilePasswordQuery )
		{
		m_eap_fast_completion_status = m_partner->set_timer(
				this,
				KHandleReadPacstoreTimerID, 
				&status,
				0);
		return;
		}
	if (m_state == ENone)
		{
		return;		
		}

#endif // #ifdef USE_FAST_EAP_TYPE

	if (iStatus.Int() != KErrNone)
	{
		// Notifier was cancelled or something went wrong
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: EAP-TLS: Certificate selection notifier was cancelled or failed, error=%d, m_state=%d.\n"),
			iStatus.Int(),
			m_state));

		switch (m_state)
		{
		case EHandlingIdentityQuery:
		case EHandlingManualIdentityQuery:

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: EAP-TLS: Cannot read user certificate.\n")));

			get_am_partner()->complete_eap_identity_query(
				0, // 0 because identity query failed
				&m_receive_network_id,
				m_eap_identifier,
				eap_status_process_general_error,
				false,
				0,
				false,
				0);			
			return;			

		case EHandlingChainQuery:
			// Notifier was cancelled or something went wrong		
			get_tls_am_partner()->complete_query_certificate_chain(
				0, 
				eap_status_process_general_error);			
			return;
		default:
			return;
		}
	}

	if (m_state == EHandlingIdentityQuery
		|| m_state == EHandlingChainQuery)
	{
		TUint index(0);
		if (m_selector_output.Length() > 0)
		{				
			TPckg<TUint> data(index);
			data.Copy(m_selector_output);				
		} 
		else
		{
			// There is only one certificate. Use that.
			index = 0;
		}
		
		if(m_allowed_user_certs.Count() > 0)
		{
			m_own_certificate_info = m_allowed_user_certs[index];			
		}
		
		TBool retrieve_chain;

		if (m_state == EHandlingChainQuery)
		{
			retrieve_chain = true;
		}
		else
		{
			retrieve_chain = false;
		}
		
		TInt allowed_user_cert_count = m_allowed_user_certs.Count();
		TInt err(KErrNone);
		
		if(allowed_user_cert_count > 0)
		{
			TRAP(err, m_cert_if->ReadCertificateL(m_allowed_user_certs[index], retrieve_chain));			
		}
		if (err != KErrNone || allowed_user_cert_count <= 0)
		{
			EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: Certificate reading failed or no user cert, user cert count=%d\n"),
			allowed_user_cert_count));

			switch (m_state)
			{
			case EHandlingIdentityQuery:			
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: EAP-TLS: EHandlingIdentityQuery: Cannot read user certificate.\n")));

				get_am_partner()->complete_eap_identity_query(
					0, // 0 because identity query failed
					&m_receive_network_id,
					m_eap_identifier,
					eap_status_process_general_error,
					false,
					0,
					false,
					0);
				return;			

			case EHandlingChainQuery:
				// Notifier was cancelled or something went wrong
				get_tls_am_partner()->complete_query_certificate_chain(
					0, 
					eap_status_process_general_error);			
				return;
			default:
				return;
			}
		}
	}
	else if (m_state == EHandlingManualIdentityQuery)
	{
		// Convert to 8-bit text
		TBuf8<KIdentityFieldLength> buf;
		buf.Copy(m_identity_info->iUsername);
		
		eap_status_e status = m_manual_username.set_copy_of_buffer(
			buf.Ptr(), 
			buf.Size());

		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: EAP-TLS: EHandlingIdentityQuery: Cannot read manual username.\n")));

			get_am_partner()->complete_eap_identity_query(
				0, // 0 because identity query failed
				&m_receive_network_id,
				m_eap_identifier,
				status,
				false,
				0,
				false,
				0);
		}

		buf.Copy(m_identity_info->iRealm);
		status = m_manual_realm.set_copy_of_buffer(
			buf.Ptr(), 
			buf.Size());

		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: EAP-TLS: EHandlingIdentityQuery: Cannot read manual realm.\n")));

			get_am_partner()->complete_eap_identity_query(
				0, // 0 because identity query failed
				&m_receive_network_id,
				m_eap_identifier,
				status,
				false,
				0,
				false,
				0);
		}

		// This must be true
		m_use_manual_realm = true; 
		
		if (m_identity_info->iUseManualUsername)
		{
			m_use_manual_username = true;
		}
		else
		{
			m_use_manual_username = false;
		}
		
		
		get_am_partner()->complete_eap_identity_query(
			0, // 0 because identity query failed
			&m_receive_network_id,
			m_eap_identifier,
			eap_status_ok,
			m_use_manual_username,
			&m_manual_username,
			m_use_manual_realm,
			&m_manual_realm);
		
		TRAPD(err, SaveManualIdentityL( 
				m_identity_info->iUseManualUsername,
				m_identity_info->iUsername,
				ETrue,
				m_identity_info->iRealm));

		(void)EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));

		// Ignore return value on purpose. It's not fatal if saving fails.							
					
		delete m_identity_info; 
		m_identity_info = 0;

	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

//


void eap_am_type_tls_peap_symbian_c::DoCancel()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
    
	RDebug::Print( _L("eap_am_type_tls_peap_symbian_c::DoCancel()\n") );

	if(m_cert_if->IsActive())
	{
		m_cert_if->Cancel();		
	}

	if ( iEapTtlsPapActive )
		{
		if ( iEapTtlsPapActive->IsActive() )
			{
			EAP_TRACE_DEBUG_SYMBIAN(
				( _L( " eap_am_type_tls_peap_symbian_c::DoCancel() \
				Cancelling iEapTtlsPapActive." ) ) );
			iEapTtlsPapActive->Cancel();
			}
		}
	
#if defined(USE_FAST_EAP_TYPE)

	m_partner->cancel_timer(
			this, 
			KRemoveIAPReferenceTimerID);

	m_partner->cancel_timer(
			this, 
			KImportFileTimerID);

	m_partner->cancel_timer(
			this, 
			KCompleteReadPacstoreTimerID);

	m_partner->cancel_timer(
			this, 
			KHandleReadPacstoreTimerID);

	if( m_is_notifier_connected )
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L(" eap_am_type_tls_peap_symbian_c::DoCancel - calling m_notifier.CancelNotifier")));
		if(IsActive())
			{
			TInt error = m_notifier.CancelNotifier(KEapFastNotifierUid);
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::DoCancel:CancelNotifier=%d"),
				error));
			}

		m_notifier.Close(); // Call close only if it is connected.	
			
		m_is_notifier_connected = false;

	} // End: if( m_is_notifier_connected )		

#endif // #if defined(USE_FAST_EAP_TYPE)
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

//

eap_status_e eap_am_type_tls_peap_symbian_c::SaveManualIdentityL( 
	const TBool use_manual_username,
	TDesC& manual_username,
	const TBool use_manual_realm,
	TDesC& manual_realm)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	// Validate length.
	if(manual_username.Length() > KMaxManualUsernameLengthInDB
		|| manual_realm.Length() > KMaxManualRealmLengthInDB)
	{
		// Username or realm too long. Can not be stored in DB.
		EAP_TRACE_DEBUG_SYMBIAN((_L("eap_am_type_tls_peap_symbian_c::SaveManualIdentityL: Too long username or realm. Length: UN=%d, Realm=%d\n"),
		manual_username.Length(), manual_realm.Length()));
		
		User::Leave(KErrArgument);
	}
		
	HBufC* sqlbuf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = sqlbuf->Des();

	RDbView view;

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	sqlStatement.Format(KSQL, &m_db_table_name, 
		&KServiceType, m_index_type, &KServiceIndex, m_index, &KTunnelingType, m_tunneling_vendor_type);
	
	User::LeaveIfError(view.Prepare(m_database, TDbQuery(sqlStatement), TDbWindow::EUnlimited));	
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());

	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	view.FirstL();

	view.UpdateL();
		
	view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal), static_cast<TUint>(use_manual_realm) );

	view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal), manual_realm); // realm

	view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal), static_cast<TUint>(use_manual_username) );
	
	view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal), manual_username); 

	view.PutL();

	CleanupStack::PopAndDestroy(3); // colset, view, session

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}	


//--------------------------------------------------

abs_eap_am_type_tls_peap_c * eap_am_type_tls_peap_symbian_c::get_am_partner()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_am_partner;
}

//--------------------------------------------------

void eap_am_type_tls_peap_symbian_c::set_am_partner(abs_eap_am_type_tls_peap_c * const partner)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_am_partner = partner;
}

//--------------------------------------------------

EAP_FUNC_EXPORT abs_tls_am_services_c * eap_am_type_tls_peap_symbian_c::get_tls_am_partner()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT_ALWAYS(m_tls_am_partner != 0);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_tls_am_partner;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_am_type_tls_peap_symbian_c::set_tls_am_partner(abs_tls_am_services_c * const tls_am_partner)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_tls_am_partner = tls_am_partner;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

// ---------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::SendErrorNotification()
// ---------------------------------------------------------
//
void eap_am_type_tls_peap_symbian_c::SendErrorNotification(
	const eap_status_e aError )
	{
	send_error_notification( aError );
	}
//--------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

EAP_FUNC_EXPORT void eap_am_type_tls_peap_symbian_c::set_tls_application(
	abs_tls_am_application_eap_fast_c * const tls_application)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_tls_application = tls_application;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}




// ---------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::IsProvisioningMode()
// ---------------------------------------------------------
//
TBool eap_am_type_tls_peap_symbian_c::IsProvisioningMode()
	{
	return ( m_provisioning_mode ==
        eap_fast_completion_operation_server_authenticated_provisioning_mode ) ? ETrue : EFalse;
	}


// ---------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::CompleteQueryUserPermissionForAid()
// ---------------------------------------------------------
//
eap_status_e
eap_am_type_tls_peap_symbian_c::CompleteQueryUserPermissionForAid(
	EEapFastNotifierUserAction aUserAction )
	{
	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::CompleteQueryUserPermissionForAid")));
	if ( aUserAction == EEapFastNotifierUserActionOk )
		{
		EAP_TRACE_DEBUG_SYMBIAN(
		    (_L("eap_am_type_tls_peap_symbian_c::CompleteQueryUserPermissionForAid eap_status_ok")));
		m_eap_fast_completion_status = m_tls_application->
		    complete_query_user_permission_for_A_ID(
			eap_status_ok,
			m_pending_operation );
 		}
  	else //if (userAction == EEapFastNotifierUserActionCancel)
  		{
		EAP_TRACE_DEBUG_SYMBIAN(
				_L("eap_am_type_tls_peap_symbian_c::CompleteQueryUserPermissionForAid eap_status_user_cancel_authentication"));

		// comlete query
  		m_eap_fast_completion_status = m_tls_application->
  		    complete_query_user_permission_for_A_ID(
  			    eap_status_user_cancel_authentication,
  		        m_pending_operation );
  		} 
	return m_eap_fast_completion_status;
	}


#endif //#if defined(USE_FAST_EAP_TYPE)

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_am_type_tls_peap_symbian_c::notify_configuration_error(
	const eap_status_e configuration_status)
{
	if (m_is_client == true)
	{
		EAP_UNREFERENCED_PARAMETER(configuration_status); // in release

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("EAP-TLS: Configuration error notification, %d.\n"),
			configuration_status));

		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(m_am_tools,
			m_receive_network_id.get_destination_id(),
			m_receive_network_id.get_source_id(),
			m_receive_network_id.get_type());

		// Send a notification that configuration is incorrect.
		eap_state_notification_c notification(
			m_am_tools,
			&send_network_id,
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_general, // This must be used with eap_general_state_configuration_error.
			m_current_eap_type,
			eap_state_none,
			eap_general_state_configuration_error,
			0,
			false);

		notification.set_authentication_error(configuration_status);

		m_partner->state_notification(&notification);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::configure()
{
	eap_status_e status(eap_status_ok);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: function: eap_am_type_tls_peap_symbian_c::configure()\n"),
		 (m_is_client == true ? "client": "server")));

	
	
	if (m_configured == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: function: eap_am_type_tls_peap_symbian_c::configure(): Already configured.\n"),
			 (m_is_client == true ? "client": "server")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	//----------------------------------------------------------

	{
		TRAPD(err, EapTlsPeapUtils::ReadCertRowsToArrayL(
			m_database,
			m_am_tools, 			
			m_db_user_cert_table_name, 			 
			m_index_type, 
			m_index, 
			m_tunneling_type,
			m_allowed_user_certs));

		if (err != KErrNone)
		{
			EAP_TRACE_ERROR(m_am_tools, 
				TRACE_FLAGS_DEFAULT, (
				EAPL("eap_am_type_tls_peap_symbian_c::configure - ReadCertRowsToArrayL, User cert, Error =%d \n"),
				err));
		
			// Convert the leave error code to EAPOL stack error code.
			status = m_am_tools->convert_am_error_to_eapol_error(err);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::configure, EapTlsPeapUtils::ReadCertRowsToArrayL success, m_allowed_user_certs count=%d"),
			m_allowed_user_certs.Count()));	
		}

		TRAP(err, EapTlsPeapUtils::ReadCertRowsToArrayL(
			m_database,
			m_am_tools, 			
			m_db_ca_cert_table_name, 
			m_index_type, 
			m_index, 
			m_tunneling_type,
			m_allowed_ca_certs));
		if (err != KErrNone)
		{
			EAP_TRACE_ERROR(m_am_tools, 
				TRACE_FLAGS_DEFAULT, (
				EAPL("eap_am_type_tls_peap_symbian_c::configure - ReadCertRowsToArrayL, CA cert, Error =%d \n"),
				err));
		
			// Convert the leave error code to EAPOL stack error code.
			status = m_am_tools->convert_am_error_to_eapol_error(err);			
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::configure, EapTlsPeapUtils::ReadCertRowsToArrayL success, m_allowed_ca_certs count=%d"),
			m_allowed_ca_certs.Count()));	
		}
		
		TRAP(err, EapTlsPeapUtils::ReadUintRowsToArrayL(
			m_database,
			m_am_tools, 
			m_db_cipher_suite_table_name, 
			KCipherSuite, 
			m_index_type, 
			m_index, 
			m_tunneling_type,
			m_allowed_cipher_suites));
		if (err != KErrNone)
		{
			EAP_TRACE_ERROR(m_am_tools, 
				TRACE_FLAGS_DEFAULT, (
				EAPL("eap_am_type_tls_peap_symbian_c::configure - ReadUintRowsToArrayL, CipherSuit, Error =%d \n"),
				err));

			// Convert the leave error code to EAPOL stack error code.
			status = m_am_tools->convert_am_error_to_eapol_error(err);			
			return EAP_STATUS_RETURN(m_am_tools, status);
		}	
	}

	//----------------------------------------------------------

	if (m_current_eap_type == eap_type_peap
#if defined(USE_TTLS_EAP_TYPE)	
		|| m_current_eap_type == eap_type_ttls
#endif

#if defined(USE_FAST_EAP_TYPE)
		|| m_current_eap_type == eap_type_fast
#endif

		
		)
	{
#ifdef USE_EAP_EXPANDED_TYPES

		TRAPD(err, EapTlsPeapUtils::GetTunnelingExpandedEapDataL(
			m_database,
			m_am_tools,
			m_enabled_tunneling_exp_eap_array,
			m_disabled_tunneling_exp_eap_array,
			m_index_type,
			m_index,
			m_tunneling_type,
			m_current_eap_type));

#else
		TRAPD(err, EapTlsPeapUtils::GetEapDataL(
			m_database,
			m_am_tools,
			m_iap_eap_array,
			m_index_type,
			m_index,
			m_tunneling_type,
			m_current_eap_type));

#endif //#ifdef USE_EAP_EXPANDED_TYPES
	
		if (err != KErrNone)
		{
			EAP_TRACE_ERROR(m_am_tools, 
				TRACE_FLAGS_DEFAULT, (
				EAPL("eap_am_type_tls_peap_symbian_c::configure - GetEapDataL or GetTunnelingExpandedEapDataL, Error =%d \n"),
				err));

			// Convert the leave error code to EAPOL stack error code.
			status = m_am_tools->convert_am_error_to_eapol_error(err);			
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c verify_certificate_realm(m_am_tools);

		eap_status_e status = type_configure_read(
			cf_str_EAP_TLS_PEAP_verify_certificate_realm.get_field(),
			&verify_certificate_realm);
		if (status == eap_status_ok
			&& verify_certificate_realm.get_is_valid_data() == true
			&& verify_certificate_realm.get_data_length() == sizeof(u32_t)
			&& verify_certificate_realm.get_data(sizeof(u32_t)) != 0)
		{
			// OK
			// This is optional value.			
			if (*(reinterpret_cast<u32_t *>(
					  verify_certificate_realm.get_data(sizeof(u32_t)))) == 1)
			{
				m_verify_certificate_realm = true;
			}
			else
			{
				m_verify_certificate_realm = false;
			}		
		}
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c allow_subdomain_matching(m_am_tools);

		eap_status_e status = type_configure_read(
			cf_str_EAP_TLS_PEAP_allow_subdomain_matching.get_field(),
			&allow_subdomain_matching);
		if (status == eap_status_ok
			&& allow_subdomain_matching.get_is_valid_data() == true
			&& allow_subdomain_matching.get_data_length() == sizeof(u32_t)
			&& allow_subdomain_matching.get_data(sizeof(u32_t)) != 0)
		{
			// OK
			// This is optional value.
			if (*(reinterpret_cast<u32_t *>(
					  allow_subdomain_matching.get_data(sizeof(u32_t)))) == 1)
			{
				m_allow_subdomain_matching = true;
			}
			else
			{
				m_allow_subdomain_matching = false;
			}		
		}
	}

	//----------------------------------------------------------

	// This is only for server
	{
		eap_variable_data_c cipher_suite(m_am_tools);

		eap_status_e status = type_configure_read(
			cf_str_EAP_TLS_PEAP_cipher_suite.get_field(),
			&cipher_suite);
		if (status == eap_status_ok
			&& cipher_suite.get_is_valid_data() == true
			&& cipher_suite.get_data_length() == sizeof(u32_t)
			&& cipher_suite.get_data(sizeof(u32_t)) != 0)
		{
			// OK
			// This is optional value.
			m_cipher_suite = (tls_cipher_suites_e)*reinterpret_cast<u32_t *>(
				cipher_suite.get_data(sizeof(u32_t)));
		}
	}
	
	//----------------------------------------------------------

#ifndef USE_EAP_EXPANDED_TYPES // This is not needed it seems. Still keeping it for normal EAP types.
								  // Intention of this is to get tunneled EAP types, but m_tunneled_type is not used
								  // anywhere other than this place.

	if (m_current_eap_type == eap_type_peap
#if defined(USE_TTLS_EAP_TYPE)
		|| m_current_eap_type == eap_type_ttls
#endif // #if defined(USE_TTLS_EAP_TYPE)

#if defined(USE_FAST_EAP_TYPE)
		|| m_current_eap_type == eap_type_fast
#endif
	
		
		)
	{
		eap_variable_data_c tunneled_type(m_am_tools);

		eap_status_e status = type_configure_read(
			cf_str_PEAP_tunneled_eap_type_hex_data.get_field(),
			&tunneled_type);
		if (status == eap_status_illegal_configure_type)
		{
			status = m_partner->read_configure(
				cf_str_PEAP_tunneled_eap_type_u32_t.get_field(),
				&tunneled_type);
		}
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (tunneled_type.get_is_valid_data() == true
			&& tunneled_type.get_data_length() == sizeof(u32_t)
			&& tunneled_type.get_data(sizeof(u32_t)) != 0)
		{
			m_tunneled_type = static_cast<eap_type_value_e>(
				*reinterpret_cast<u32_t *>(tunneled_type.get_data(sizeof(u32_t))));
		}
		else if (tunneled_type.get_data_length()
				 == eap_expanded_type_c::get_eap_expanded_type_size()
				 && tunneled_type.get_data(tunneled_type.get_data_length()) != 0)
		{
			eap_expanded_type_c eap_type(eap_type_none);

			status = eap_type.set_expanded_type_data(
				m_am_tools,
				&tunneled_type);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = eap_type.get_type_data(
				m_am_tools,
				&m_tunneled_type);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
  
#endif //#ifndef USE_EAP_EXPANDED_TYPES

	//----------------------------------------------------------

	{
		eap_variable_data_c use_manual_username(m_am_tools);

		eap_status_e status = type_configure_read(
			cf_str_EAP_TLS_PEAP_use_manual_username.get_field(),
			&use_manual_username);		
		if (status == eap_status_ok
			&& use_manual_username.get_is_valid_data() == true
			&& use_manual_username.get_data_length() == sizeof(u32_t)
			&& use_manual_username.get_data(sizeof(u32_t)) != 0)
		{
			// OK
			// This is optional value.
			if (*(reinterpret_cast<u32_t *>(use_manual_username.get_data(sizeof(u32_t)))) == 1)
			{
				m_use_manual_username = true;
			}
			else
			{
				m_use_manual_username = false;
			}		
		}
	}

	//----------------------------------------------------------

	{
		(void) type_configure_read(
			cf_str_EAP_TLS_PEAP_manual_username.get_field(),
			&m_manual_username);	
		// return value ignored on purpose (optional parameter)
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c use_manual_realm(m_am_tools);
		
		eap_status_e status = type_configure_read(
			cf_str_EAP_TLS_PEAP_use_manual_realm.get_field(),
			&use_manual_realm);
		if (status == eap_status_ok
			&& use_manual_realm.get_is_valid_data() == true
			&& use_manual_realm.get_data_length() == sizeof(u32_t)
			&& use_manual_realm.get_data(sizeof(u32_t)) != 0)
		{
			// OK
			// This is optional value.
			if (*(reinterpret_cast<u32_t *>(
					  use_manual_realm.get_data(sizeof(u32_t)))) == 1)
			{
				m_use_manual_realm = true;
			}
			else
			{
				m_use_manual_realm = false;
			}		
		}
	}
	
	//----------------------------------------------------------

	{
		(void) type_configure_read(
			cf_str_EAP_TLS_PEAP_manual_realm.get_field(),
			&m_manual_realm);		
		// return value ignored on purpose (optional parameter)
	}
	
	//----------------------------------------------------------

#if defined(USE_EAP_TLS_SESSION_TICKET)
	{
		eap_variable_data_c use_session_ticket(m_am_tools);

		eap_status_e status = m_partner->read_configure(
			cf_str_EAP_TLS_PEAP_use_session_ticket.get_field(),
			&use_session_ticket);
		if (status == eap_status_ok
			&& use_session_ticket.get_is_valid_data() == true)
		{
			u32_t *use_manual_realm_flag = reinterpret_cast<u32_t *>(
				use_session_ticket.get_data(sizeof(u32_t)));
			if (use_manual_realm_flag != 0
				&& *use_manual_realm_flag != 0)
			{
				m_use_session_ticket = true;
			}
		}
	}
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)

	//----------------------------------------------------------
	
	if (m_current_eap_type == eap_type_peap
#if defined(USE_TTLS_EAP_TYPE)
		|| m_current_eap_type == eap_type_ttls
#endif // #if defined(USE_TTLS_EAP_TYPE)
		
#if defined(USE_FAST_EAP_TYPE)
		|| m_current_eap_type == eap_type_fast
#endif
		
		)
	{
		m_tls_peap_server_authenticates_client_policy_flag = false;
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c server_authenticates_client(m_am_tools);

		status = type_configure_read(
			cf_str_TLS_server_authenticates_client_policy_in_client.get_field(),
			&server_authenticates_client);
		if (status == eap_status_ok
			&& server_authenticates_client.get_is_valid_data() == true
			&& server_authenticates_client.get_data_length() == sizeof(u32_t)
			&& server_authenticates_client.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				server_authenticates_client.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_tls_peap_server_authenticates_client_policy_flag = false;
				}
				else
				{
					m_tls_peap_server_authenticates_client_policy_flag = true;
				}
			}
		}
	}

	//----------------------------------------------------------

	{
		// Read Maximum Session Validity Time from the config file
		eap_variable_data_c sessionTimeFromFile(m_am_tools);
		
		eap_status_e status(eap_status_ok);

		switch (m_current_eap_vendor_type)
		{
		case eap_type_tls:
			{
				status = m_partner->read_configure(
					cf_str_EAP_TLS_max_session_validity_time.get_field(),
					&sessionTimeFromFile);
			}
			break;

		case eap_type_peap:
			{
				status = m_partner->read_configure(
					cf_str_EAP_PEAP_max_session_validity_time.get_field(),
					&sessionTimeFromFile);
			}
			break;

		case eap_type_ttls:
			{
				status = m_partner->read_configure(
					cf_str_EAP_TTLS_max_session_validity_time.get_field(),
					&sessionTimeFromFile);
			}
			break;

		case eap_type_ttls_plain_pap:
			{
			// read PAP session time
			status = m_partner->read_configure(
				cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time.get_field(),
				&sessionTimeFromFile );
			}
			break;
			
#if defined(USE_FAST_EAP_TYPE)
		case eap_type_fast:
			{
				status = m_partner->read_configure(
					cf_str_EAP_FAST_max_session_validity_time.get_field(),
					&sessionTimeFromFile);
			}
			break;
#endif
			
		default:
			{
				// Should never happen
				EAP_TRACE_ERROR(m_am_tools, 
					TRACE_FLAGS_DEFAULT, (
					EAPL("eap_am_type_tls_peap_symbian_c::configure - Unsupported EAP type, m_current_eap_vendor_type=%d \n"),
					m_current_eap_vendor_type));
			}
		}	

		// set m_max_session_time
		if (status == eap_status_ok
			&& sessionTimeFromFile.get_is_valid_data() == true
			&& sessionTimeFromFile.get_data_length() == sizeof(u32_t))
		{
			u32_t *session = reinterpret_cast<u32_t *>(sessionTimeFromFile.get_data());
			if (session != 0)
			{
				// Update the max session time (in micro seconds).
				// configuration file saves the time in seconds. We have to convert it to micro seconds.
				m_max_session_time = static_cast<TInt64>(*session) * static_cast<TInt64>(KMicroSecsInASecond);
			}
		}
		// set max session time for protocol in tunnel;
		// currently for PAP
		if ( status == eap_status_ok &&
			sessionTimeFromFile.get_is_valid_data() == true &&
			sessionTimeFromFile.get_data_length() == sizeof( u32_t ) )

			{
				u32_t* session = reinterpret_cast<u32_t*>( sessionTimeFromFile.get_data() );
				if ( session != 0 )
				    {
					// Update the max session time (in micro seconds).
					// configuration file saves the time in seconds.
				    // We have to convert it to micro seconds.
				    iEapTtlsPapMaxSessionConfigTime = static_cast<TInt64>
				        ( *session ) * static_cast<TInt64>( KMicroSecsInASecond );
				    }
			}		
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	
#if defined(USE_FAST_EAP_TYPE)
	
	// Read UnAuthenticated provisioning mode from database.
	// We need this only for EAP-FAST
	
	if(m_current_eap_type == eap_type_fast)
	{
		//----------------------------------------------------------
		{
			eap_variable_data_c allow_serv_unauth_prov_mode(m_am_tools);
			
			eap_status_e status = type_configure_read(
				cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP.get_field(),
				&allow_serv_unauth_prov_mode);
			if (status == eap_status_ok
				&& allow_serv_unauth_prov_mode.get_is_valid_data() == true
				&& allow_serv_unauth_prov_mode.get_data_length() == sizeof(u32_t)
				&& allow_serv_unauth_prov_mode.get_data(sizeof(u32_t)) != 0)
			{
				// OK
				if (*(reinterpret_cast<u32_t *>(
						  allow_serv_unauth_prov_mode.get_data(sizeof(u32_t)))) == 1)
				{
					m_serv_unauth_prov_mode = true;
				}
				else
				{
					m_serv_unauth_prov_mode = false;
				}		
			}
		}
		//----------------------------------------------------------
		{
			eap_variable_data_c allow_serv_auth_prov_mode(m_am_tools);
			
			eap_status_e status = type_configure_read(
				cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode.get_field(),
				&allow_serv_auth_prov_mode);
			if (status == eap_status_ok
				&& allow_serv_auth_prov_mode.get_is_valid_data() == true
				&& allow_serv_auth_prov_mode.get_data_length() == sizeof(u32_t)
				&& allow_serv_auth_prov_mode.get_data(sizeof(u32_t)) != 0)
			{
				// OK
				if (*(reinterpret_cast<u32_t *>(
						  allow_serv_auth_prov_mode.get_data(sizeof(u32_t)))) == 1)
				{
					m_serv_auth_prov_mode = true;
				}
				else
				{
					m_serv_auth_prov_mode = false;
				}		
			}
		}
		//----------------------------------------------------------		

	} // End: if(m_current_eap_type == eap_type_fast)
	
#endif // #if defined(USE_FAST_EAP_TYPE)	
	
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -	
	
	status = eap_status_ok;

	if (m_allowed_ca_certs.Count() == 0)
	{		
	// needed because of nonworking wrong settings
#if defined(USE_FAST_EAP_TYPE)
		if(m_current_eap_type == eap_type_fast &&
			m_serv_auth_prov_mode != true)
		{
			// In the case of EAP-FAST, CA cert is must if m_serv_auth_prov_mode is TRUE.
			status = eap_status_ok;
			
			EAP_TRACE_DEBUG(m_am_tools, 
				TRACE_FLAGS_DEFAULT, (
				EAPL("eap_am_type_tls_peap_symbian_c::configure - No CA certificate but exception for EAP-FAST as m_serv_auth_prov_mode is FALSE and for all m_serv_unauth_prov_mode \n")));				
		}
		else	
#endif // #if defined(USE_FAST_EAP_TYPE)
		{
			EAP_TRACE_ERROR(m_am_tools, 
				TRACE_FLAGS_DEFAULT, (
				EAPL("eap_am_type_tls_peap_symbian_c::configure - Error - No CA certificate\n")));
		
			// No root certificate selected. Cannot continue.
			status = eap_status_ca_certificate_unknown;
			send_error_notification(status);
		}			
	}
	
	if(m_allowed_user_certs.Count() == 0)
		{
#if defined(USE_FAST_EAP_TYPE)
		if(m_current_eap_type == eap_type_fast)
			{
			m_use_manual_realm = true;

			if (m_use_manual_username == false)
				{
				TRAPD(err, status=ConfigureL());
				if (err != KErrNone)
					{
					EAP_TRACE_ERROR(m_am_tools, 
							TRACE_FLAGS_DEFAULT, (
							EAPL("eap_am_type_tls_peap_symbian_c::configure LEAVE from ConfigureL, Error =%d \n"),
							err));
					}
				}
			}
#endif // #if defined(USE_FAST_EAP_TYPE)
		}
	if (m_tls_peap_server_authenticates_client_policy_flag == true
		&& m_allowed_user_certs.Count() == 0)
	{
#if defined(USE_FAST_EAP_TYPE)
    if (m_current_eap_type == eap_type_fast)
        {
        EAP_TRACE_DEBUG(m_am_tools, 
            TRACE_FLAGS_DEFAULT, 
            (EAPL("eap_am_type_tls_peap_symbian_c::configure - No USER certificate, but in eap_fast it's not mandatory\n")));  
    
        }
	else
#endif // #if defined(USE_FAST_EAP_TYPE)
	    {
	    EAP_TRACE_ERROR(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("eap_am_type_tls_peap_symbian_c::configure - Error - No USER certificate\n")));
	
		// No user certificate selected. Cannot continue.
		status = eap_status_user_certificate_unknown;
		send_error_notification(status);
	    }
	}

	if (m_allowed_cipher_suites.Count() == 0)
	{
		EAP_TRACE_ERROR(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("eap_am_type_tls_peap_symbian_c::configure - Error - No cipher suit\n")));

		// No sipher suites selected. Cannot continue.
		status = eap_status_illegal_cipher_suite;
		send_error_notification(status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (status != eap_status_ok)
	{
		notify_configuration_error(status);
	}
	
	m_configured = true;
	
	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_tls_peap_symbian_c::configure - END \n")));	
	

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
#if defined(USE_FAST_EAP_TYPE)

eap_status_e eap_am_type_tls_peap_symbian_c::ConfigureL()
	{
	
	eap_status_e status(eap_status_ok);
	
	_LIT(KTempUserName, "EAP-FAST-");
	TBuf8<10> TempUserName;	

	TempUserName.Copy(KTempUserName);
	
	HBufC8* buf = HBufC8::NewLC(KIdentityFieldLength);
	TPtr8 bufPtr = buf->Des();

	HBufC8* tempUserBuf8 = HBufC8::NewLC(KMacAddressLength);
	TPtr8 tempUserBufPtr8 = tempUserBuf8->Des();

	HBufC8* ConvertedtempUserBuf8 = HBufC8::NewLC(KMacAddressLength*2);
	TPtr8 ConvertedtempUserBufPtr8 = ConvertedtempUserBuf8->Des();
	
	if (m_receive_network_id.get_destination_length()>0)
		{
		tempUserBufPtr8.Copy(m_receive_network_id.get_destination(), m_receive_network_id.get_destination_length());
	
		u32_t toBinaryPtr8SizeForTools = static_cast<u32_t>(KMacAddressLength*2);
		u32_t fromTextPtr8SizeForTools = static_cast<u32_t>(tempUserBufPtr8.Size());
		
		u8_t * toBinaryPtr8ForTools = const_cast<u8_t *>(ConvertedtempUserBuf8->Ptr());
		
		EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::configure,Call convert_bytes_to_hex_ascii, toBinaryPtr8SizeForTools=%d"),
		toBinaryPtr8SizeForTools));	
		
		// Convert hex to ascii string.
		status = m_am_tools->convert_bytes_to_hex_ascii(
			tempUserBufPtr8.Ptr(),
			fromTextPtr8SizeForTools,
			toBinaryPtr8ForTools,
			&toBinaryPtr8SizeForTools);	

		if(status != eap_status_ok)
		{
			EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::configure, Error in convert_hex_ascii_to_bytes. status=%d"),
			status));		
		
			User::Leave(m_am_tools->convert_eapol_error_to_am_error(status));
		}
		
		ConvertedtempUserBufPtr8.SetLength(KMacAddressLength*2);
		
		EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("MAC"),
						ConvertedtempUserBuf8->Ptr(),
						ConvertedtempUserBuf8->Size()));

		EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_type_tls_peap_symbian_c::config: user size = %d, MAC size= %d \n"),
						TempUserName.Size(), ConvertedtempUserBuf8->Size()));
		
		bufPtr.Append(TempUserName.Ptr(), TempUserName.Size());
		bufPtr.Append(ConvertedtempUserBuf8->Ptr(),ConvertedtempUserBuf8->Size());
		
		EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("UserName"),
						bufPtr.Ptr(),
						bufPtr.Size()));

		status = m_manual_username.set_copy_of_buffer(
				bufPtr.Ptr(), 
				bufPtr.Size());
		}
	EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_tls_peap_symbian_c::config: UserName = %s \n"),
			 bufPtr.Ptr(), bufPtr.Size()));

	CleanupStack::PopAndDestroy(ConvertedtempUserBuf8);
	CleanupStack::PopAndDestroy(tempUserBuf8);
	CleanupStack::PopAndDestroy(buf);

	m_use_manual_username = true;
	
	return status;
	}

#endif // #if defined(USE_FAST_EAP_TYPE)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::reset()
{

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::authentication_finished(
	const bool true_when_successful,
	const tls_session_type_e tls_session_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	TRAPD(err, authentication_finishedL(true_when_successful, tls_session_type));
	if (err != KErrNone)
	{
		EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_am_type_tls_peap_symbian_c::authentication_finished, TRAP ERROR=%d\n"),
			err));	
	
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		send_error_notification(status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

void eap_am_type_tls_peap_symbian_c::authentication_finishedL(
	const bool true_when_successful,
	const tls_session_type_e tls_session_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_is_client == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}
	
	// In EAP-FAST this could be called when provisioning is successfull.
	// If there was provisioning, We have to toggle 
	// cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal 
	
#if defined(USE_FAST_EAP_TYPE)
	
	if(m_current_eap_type == eap_type_fast &&
	   m_serv_unauth_prov_mode == true)
	{		
		EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::authentication_finishedL EAP-FAST Provisioning!")));			
		
		eap_variable_data_c unauthProvMode(m_am_tools);		
		unauthProvMode.set_copy_of_buffer(
				&default_EAP_FAST_Unauth_Prov_Mode_Allowed, 
				sizeof(default_EAP_FAST_Unauth_Prov_Mode_Allowed));
		
		EapTlsPeapUtils::SetEapSettingsDataL(
			m_database,
			m_index_type,
			m_index,
			m_tunneling_type,
			m_current_eap_type,
			cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal,
			&unauthProvMode);	
		
		EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::authentication_finishedL Unauth Prov mode set to default (NO)!")));					
	}
#endif
	
	// Store the authentication time if the full authentication is successful
	if (true_when_successful == true
		&& tls_session_type == tls_session_type_full_authentication)
	{
		store_authentication_timeL();
	}
	
	if (m_latest_alert_description == tls_alert_description_certificate_expired)
	{
		send_error_notification(eap_status_certificate_expired);
	}
	else if (m_latest_alert_description == tls_alert_description_bad_certificate)
	{
		send_error_notification(eap_status_bad_certificate);
	}
	else if (m_latest_alert_description == tls_alert_description_unsupported_certificate)
	{
		send_error_notification(eap_status_unsupported_certificate);
	}
	else if (m_latest_alert_description == tls_alert_description_certificate_revoked)
	{
		send_error_notification(eap_status_certificate_revoked);
	}
	else if (m_latest_alert_description == tls_alert_description_certificate_unknown)
	{
		send_error_notification(eap_status_user_certificate_unknown);
	}
	else if(m_latest_alert_description != tls_alert_description_none)
	{
		// Send error notification any alert other than tls_alert_description_none.
		send_error_notification(eap_status_process_general_error);
	}

	if (true_when_successful == false)
	{
		ResetSessionIdL();	
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::query_eap_identity(
	eap_variable_data_c * const /*identity*/,
	const eap_am_network_id_c * const /* receive_network_id */,
	const u8_t eap_identifier,
	bool * const /*use_manual_username*/,
	eap_variable_data_c * const /*manual_username*/,
	bool *const /*use_manual_realm*/,
	eap_variable_data_c * const /*manual_realm*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_pending_request);

	// Store parameters
	m_eap_identifier = eap_identifier;	
	m_state = EHandlingIdentityQuery;
		
	// Get the own certificate only if it has already been retrieved
	if (m_own_certificate == 0)
	{
		TRAPD(err, m_cert_if->GetMatchingCertificatesL(
			m_allowed_user_certs, 
			EFalse, 
			0, 
			EFalse, 
			0, 
			ETrue, 
			m_allowed_cipher_suites));
		if (err != KErrNone)
		{
			status = m_am_tools->convert_am_error_to_eapol_error(err);
		}
		else
		{
			status = eap_status_pending_request;
		}
	}
	else
	{
		RPointerArray<CX509Certificate> tmp;
		if (tmp.Append(m_own_certificate) != KErrNone)
		{
			status = m_am_tools->convert_am_error_to_eapol_error(eap_status_allocation_error);
		}
		else 
		{
			status = complete_read_own_certificate(tmp, eap_status_ok);
		}
		tmp.Reset();
		
	}
		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


eap_status_e eap_am_type_tls_peap_symbian_c::complete_read_own_certificate(
	const RPointerArray<CX509Certificate>& aCertChain, eap_status_e aStatus)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
	eap_status_e status = eap_status_process_general_error;
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::complete_read_own_certificate -start- cert chain count = %d, aStatus=%d\n"),
		aCertChain.Count(), aStatus));
	
	if (aStatus != eap_status_ok)
	{
		switch (m_state)
		{
		case EHandlingIdentityQuery:
			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: EAP-TLS: EHandlingIdentityQuery: Cannot read own certificate.\n")));

			status = get_am_partner()->complete_eap_identity_query(
				0, // 0 because identity query failed
				&m_receive_network_id,
				m_eap_identifier,
				aStatus,
				false,
				0,
				false,
				0);
			break;
		
		case EHandlingChainQuery:	
			status = get_tls_am_partner()->complete_query_certificate_chain(0, aStatus);
			break;

		default:
			// This should never happen
			User::Panic(_L("EAPOL"), 1);
		}
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	// Handle errors - if certificate is 0 then an error has occurred.
	if (aCertChain.Count() == 0)
	{
		switch (m_state)
		{
		case EHandlingIdentityQuery:
			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: Could not read own certificate.\n")));

			status = get_am_partner()->complete_eap_identity_query(
				0, // 0 because identity query failed
				&m_receive_network_id,
				m_eap_identifier,
				eap_status_illegal_eap_identity,
				false,
				0,
				false,
				0);
			break;
		
		case EHandlingChainQuery:	
			EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Could not read own certificate.\n")));
			status = get_tls_am_partner()->complete_query_certificate_chain(0, eap_status_illegal_certificate);
			break;

		default:
			// This should never happen
			User::Panic(_L("EAPOL"), 1);
		}
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	TBool aEqual = EFalse;
	if (m_own_certificate != 0)
	{
		TRAPD(err1, aEqual = m_own_certificate->IsEqualL(*aCertChain[0]));
		if (err1 != KErrNone)
		{				
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}
	
	// Store certificate 
	if (m_own_certificate == 0
		|| aEqual == EFalse)
	{
		delete m_own_certificate;
	
		// Create a copy of the certificate
		TRAPD(err, m_own_certificate = CX509Certificate::NewL(*aCertChain[0]));
		if (err != KErrNone)
		{				
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}
	
	switch (m_state)
	{
	case EHandlingIdentityQuery:
		{
			eap_variable_data_c subjectIdentity(m_am_tools);
			eap_variable_data_c IssuerIdentity(m_am_tools);
			
			TRAPD(err, get_identity_from_alternative_nameL(m_own_certificate, &subjectIdentity));
			if (err != KErrNone)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Could not find identity in SubjectAltName field.\n")));

				TRAPD(err, get_identities_from_distinguished_namesL(m_own_certificate, &subjectIdentity, &IssuerIdentity));
				if (err != KErrNone)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: Could not find subject identity from certificate.\n")));
					
					status = get_am_partner()->complete_eap_identity_query(
						0, // 0 because identity query failed
						&m_receive_network_id,
						m_eap_identifier,
						eap_status_illegal_eap_identity,
						false,
						0,
						false,
						0);
					break;
				}
				else
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("Found subject identity from certificate.\n")));
				}
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Found identity in SubjectAltName field.\n")));
			}

			// The completition function return a status value but there is no need to check them.
			status = get_am_partner()->complete_eap_identity_query(
				&subjectIdentity,
				&m_receive_network_id,
				m_eap_identifier,
				eap_status_ok,
				m_use_manual_username,
				&m_manual_username,
				m_use_manual_realm,
				&m_manual_realm);
			if (status == eap_status_ok 
				|| status == eap_status_pending_request)
			{
				status = eap_status_completed_request;
			}				
		}
		break;
	case EHandlingChainQuery:
		{
			eap_array_c<eap_variable_data_c> chain(m_am_tools);

			// Check if the certificate cipher suite is correct
			const CSubjectPublicKeyInfo& pubkey = m_own_certificate->PublicKey();
			TAlgorithmId algorithm = pubkey.AlgorithmId();

			if (EapTlsPeapUtils::CipherSuiteUseRSAKeys(m_cipher_suite) 
				&& algorithm != ERSA)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: Tried to use DSA certificate with RSA cipher suite.\n")));

				send_error_notification(eap_status_illegal_cipher_suite);

				status = get_tls_am_partner()->complete_query_certificate_chain(0, eap_status_illegal_cipher_suite);

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);		
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (EapTlsPeapUtils::CipherSuiteUseDSAKeys(m_cipher_suite)
				&& algorithm != EDSA)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: Tried to use RSA certificate with DSS cipher suite.\n")));

				send_error_notification(eap_status_illegal_cipher_suite);

				status = get_tls_am_partner()->complete_query_certificate_chain(0, eap_status_illegal_cipher_suite);

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);		
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Add the chain certificates to eap_array_c
			TInt i(0);
			for (i = 0; i < aCertChain.Count(); i++)
			{
				eap_variable_data_c * cert = new eap_variable_data_c(m_am_tools);
				if (cert == 0)
				{
					status = get_tls_am_partner()->complete_query_certificate_chain(0, eap_status_allocation_error);
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);	
				}

				status = cert->set_buffer(
					aCertChain[i]->Encoding().Ptr(), 
					aCertChain[i]->Encoding().Size(), 
					false, 
					false);
				if (status != eap_status_ok)
				{
					delete cert;
					status = get_tls_am_partner()->complete_query_certificate_chain(0, eap_status_process_general_error);
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);		
					return EAP_STATUS_RETURN(m_am_tools, status);
				}	
				status = chain.add_object(cert, true);
				if (status != eap_status_ok)
				{
					status = get_tls_am_partner()->complete_query_certificate_chain(0, eap_status_allocation_error);
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);		
					return EAP_STATUS_RETURN(m_am_tools, status);
				}		
			}
			// Complete query
			status = get_tls_am_partner()->complete_query_certificate_chain(&chain, eap_status_ok);			
		}
		break;

		default:
			// This should never happen
			User::Panic(_L("EAPOL"), 1);
	}		
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

eap_status_e eap_am_type_tls_peap_symbian_c::complete_read_ca_certificate(
		const RPointerArray<CX509Certificate>& aCertChain, eap_status_e aStatus)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_tls_peap_symbian_c::complete_read_ca_certificate. Cert Chain count=%d, aStatus=%d\n"),
		aCertChain.Count(), aStatus));	

	if (aStatus != eap_status_ok)
	{
		switch (m_state)
		{
		case EHandlingIdentityQuery:
			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: Could not CA certificate.\n")));

			get_am_partner()->complete_eap_identity_query(
				0, // 0 because identity query failed
				&m_receive_network_id,
				m_eap_identifier,
				aStatus,
				false,
				0,
				false,
				0);

			break;
		
		case EHandlingCipherSuiteQuery:	
			get_tls_am_partner()->complete_query_certificate_chain(0, aStatus);
			break;
			
		default:
			// This should never happen
			User::Panic(_L("EAPOL"), 1);
		}
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	// Check the error case first	
	if (aCertChain.Count() == 0)
	{
		switch (m_state)
		{
		case EHandlingIdentityQuery:
			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: Could not read ca certificate.\n")));

			get_am_partner()->complete_eap_identity_query(
				0, // 0 because identity query failed
				&m_receive_network_id,
				m_eap_identifier,
				eap_status_illegal_eap_identity,
				false,
				0,
				false,
				0);

			break;
		
		case EHandlingCipherSuiteQuery:	
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: Could not read own certificate.\n")));
			get_tls_am_partner()->complete_query_certificate_chain(0, eap_status_illegal_certificate);
			break;
			
		default:
			// This should never happen
			User::Panic(_L("EAPOL"), 1);
		}
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	
	// Store certificate 
	TBool aEqual = EFalse;
	if (m_ca_certificate != 0)
	{
		TRAPD(err1, aEqual = m_ca_certificate->IsEqualL(*aCertChain[0]));
		if (err1 != KErrNone)
		{				
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}

	if (m_ca_certificate == 0
		|| aEqual == EFalse)
	{
		delete m_ca_certificate;
	
		// Create a copy of the certificate
		TRAPD(err, m_ca_certificate = CX509Certificate::NewL(*aCertChain[0]));
		if (err != KErrNone)
		{				
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}
		
	
	switch (m_state)
	{
		case EHandlingIdentityQuery:
		{
			
			// Get the realm from the CA certificate
			eap_variable_data_c tmp(m_am_tools);

			eap_status_e status = get_realms_from_certificate(
				m_ca_certificate, 
				&m_manual_realm,
				&tmp);
			if (status != eap_status_ok)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: Could not read realms from ca certificate.\n")));

				get_am_partner()->complete_eap_identity_query(
					0, // 0 because identity query failed
					&m_receive_network_id,
					m_eap_identifier,
					eap_status_illegal_eap_identity,
					false,
					0,
					false,
					0);

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Got realm from CA certificate"),
		 		m_manual_realm.get_data(m_manual_realm.get_data_length()),
		 		m_manual_realm.get_data_length()));		 			
			
			get_am_partner()->complete_eap_identity_query(
				0, // 0 because certificate query failed
				&m_receive_network_id,
				m_eap_identifier,
				eap_status_ok, 
				m_use_manual_username, 
				&m_manual_username, 
				true, 
				&m_manual_realm);
		}
		break;
		
		case EHandlingCipherSuiteQuery:
		{
			
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("Got CA certificate. Resume cipher suite selection.\n")));	
			
			query_cipher_suites_and_previous_session();
		}
		break;
		
		default:
			// This should never happen
			User::Panic(_L("EAPOL"), 1);

	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);	
}

void eap_am_type_tls_peap_symbian_c::get_identities_from_distinguished_namesL(
	const CX509Certificate * const aCertificate, 
	eap_variable_data_c * const aSubjectIdentity,
	eap_variable_data_c * const aIssuerIdentity)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	if (aSubjectIdentity == 0
		|| aIssuerIdentity == 0
		|| aCertificate == 0)
	{
		User::Leave(KErrArgument);
	}

	TInt i(0);
	HBufC *value = 0;
	// Loop the distinguished name field and try to find common name
	const CX500DistinguishedName& dn = aCertificate->SubjectName();
	
	for (i = 0; i < dn.Count(); i++)
	{
		const CX520AttributeTypeAndValue& attribute = dn.Element(i);
		
		if (attribute.Type() == KX520CommonName)
		{					
			value = attribute.ValueL();
			CleanupStack::PushL(value);
			
			// Convert to 8-bit text
			HBufC8* tmp = HBufC8::NewLC(value->Length());

			if (NULL == tmp)
			{
				User::Leave(KErrNoMemory);
			}
			
			TPtr8 tmpptr = tmp->Des();
			tmpptr.Copy(*value);
			
			eap_status_e status = aSubjectIdentity->set_copy_of_buffer(
				tmpptr.Ptr(),
				tmpptr.Size());

			if (status != eap_status_ok)
			{
				User::Leave(KErrNoMemory);
			}
			
			EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_tls_peap_symbian_c::get_identities_from_distinguished_namesL:SubjectIdentity:"),
	 		tmpptr.Ptr(),
	 		tmpptr.Size()));	 			
			
			CleanupStack::PopAndDestroy(tmp);
			CleanupStack::PopAndDestroy(value);
		}				
	}
	const CX500DistinguishedName& dn2 = aCertificate->IssuerName();
	
	for (i = 0; i < dn2.Count(); i++)
	{
		const CX520AttributeTypeAndValue& attribute = dn2.Element(i);
		
		if (attribute.Type() == KX520CommonName)
		{					
			value = attribute.ValueL();
			CleanupStack::PushL(value);
			// Convert to 8-bit text
			HBufC8* tmp = HBufC8::NewLC(value->Length());

			if (NULL == tmp)
			{
				User::Leave(KErrNoMemory);
			}
			
			TPtr8 tmpptr = tmp->Des();
			tmpptr.Copy(*value);
			
			eap_status_e status = aIssuerIdentity->set_copy_of_buffer(
				tmpptr.Ptr(),
				tmpptr.Size());

			if (status != eap_status_ok)
			{
				User::Leave(KErrNoMemory);
			}

			EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_tls_peap_symbian_c::get_identities_from_distinguished_namesL:IssuerIdentity:"),
	 		tmpptr.Ptr(),
	 		tmpptr.Size()));	 			
			
			CleanupStack::PopAndDestroy(tmp);
			CleanupStack::PopAndDestroy(value);
		}				
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

void eap_am_type_tls_peap_symbian_c::get_identity_from_alternative_nameL(
	const CX509Certificate * const aCertificate, 
	eap_variable_data_c * const aIdentity)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	/********************************************************************
	SubjectAltName ::= GeneralNames

	GeneralNames ::= SEQUENCE OF GeneralName

	GeneralName ::= CHOICE {
		 otherName                       [0]     AnotherName,
		 rfc822Name                      [1]     IA5String,
		 dNSName                         [2]     IA5String,
		 x400Address                     [3]     ANY, --ORAddress,
		 directoryName                   [4]     Name,
		 ediPartyName                    [5]     EDIPartyName,
		 uniformResourceIdentifier       [6]     IA5String,
		 iPAddress                       [7]     OCTET STRING,
		 registeredID                    [8]     OBJECT IDENTIFIER }

	-- AnotherName replaces OTHER-NAME ::= TYPE-IDENTIFIER, as
	-- TYPE-IDENTIFIER is not supported in the '88 ASN.1 syntax

	AnotherName ::= SEQUENCE {
		 type    OBJECT IDENTIFIER,
		 value      [0] EXPLICIT ANY } --DEFINED BY type-id }
	**********************************************************************/

	const CX509CertExtension* ext = aCertificate->Extension(KSubjectAltName);
	// Check if there is alternative name extension (Windows provided certificates usually do)
	if (ext != 0)
	{
		// Start parsing the alt. name
		TPtrC8 name = ext->Data();
	
		EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::get_identity_from_alternative_nameL: Alt Name from Cert extn:"),
 		name.Ptr(),
 		name.Size()));		 			

		if(0 == name.Size())
		{
			EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR:get_identity_from_alternative_nameL:No Alternative Name in cert extension\n")));
					
			User::Leave(KErrNotFound);			
		}
		
		// Extension is inside an octet string
		TASN1DecOctetString octetstring;
		TInt pos(0);
		HBufC8* pOct = octetstring.DecodeDERL(name, pos);		

		if(NULL == pOct)
		{
			EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR:get_identity_from_alternative_nameL:No ASN1DecOctetString or DecodeDER failed\n")));
					
			User::Leave(KErrNotFound);			
		}

		CleanupStack::PushL(pOct);

		// Then there is SEQUENCE
		TASN1DecSequence seq;
		pos = 0;		
		CArrayPtrFlat<TASN1DecGeneric>* pSeq = seq.DecodeDERLC(pOct->Des(), pos);
		
		if(0 == pSeq->Count())
		{
			EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR:get_identity_from_alternative_nameL:No ASN1DecSequence or DecodeDER failed\n")));
					
			User::Leave(KErrNotFound);			
		}
		
		// Get the first item in the sequence (ignore other possible items)
		TASN1DecGeneric* gen;
		gen = pSeq->At(0);
		if (gen == 0)
		{
			EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR:get_identity_from_alternative_nameL:No ASN1DecGeneric\n")));

			User::Leave(KErrNotFound);
		}
		if (gen->Tag() != 0)  // Only parse otherName in the CHOICE at the moment.
		{
			EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR:get_identity_from_alternative_nameL:Some Tag in ASN1DecGeneric\n")));
		
			User::Leave(KErrNotSupported);
		}
	
		TPtrC8 pOtherName = gen->GetContentDER(); 

		TASN1DecObjectIdentifier objid;
		
		pos = 0;
		HBufC* objId = objid.DecodeDERL(pOtherName, pos);
		
		if(NULL == objId)
		{
			EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR:get_identity_from_alternative_name_L:No ASN1DecObjectIdentifier or DecodeDER failed\n")));
					
			User::Leave(KErrNotFound);			
		}
		
		CleanupStack::PushL(objId);

		// http://asn1.elibel.tm.fr/oid/
		_LIT(KMSObjectId, "1.3.6.1.4.1.311.20.2.3");
		if (objId->Compare(KMSObjectId) != 0)
		{
			// Not supported object type
		
			EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR:get_identity_from_alternative_nameL:Not supported object type\n")));

			User::Leave(KErrNotSupported);
		}

		pos += 2; // Skip over explicit tag

		TASN1DecUTF8String utf8;
		HBufC* utf8name = utf8.DecodeDERL(pOtherName, pos);
		
		if(NULL == utf8name)
		{
			EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR:get_identity_from_alternative_nameL:No ASN1DecUTF8String or DecodeDER failed\n")));
					
			User::Leave(KErrNotFound);			
		}
		
		CleanupStack::PushL(utf8name);
	
		HBufC8* buf= HBufC8::NewLC(128);
		if (NULL == buf)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			User::Leave(KErrNoMemory);
		}
		
		TPtr8 nname = buf->Des();

		nname.Copy(utf8name->Des());

		eap_status_e status = aIdentity->set_copy_of_buffer(
			nname.Ptr(),
			nname.Size());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			User::Leave(KErrNoMemory);
		}
		
		EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::get_identity_from_alternative_nameL: Identity from Alt Name:"),
 		nname.Ptr(),
 		nname.Size()));

		CleanupStack::PopAndDestroy(5);
	} 
	else
	{
		EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("get_identity_from_alternative_nameL:No X509 Cert Extension\n")));
	
		User::Leave(KErrNotFound);
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(id); // in release
	EAP_UNREFERENCED_PARAMETER(data); // in release

	eap_status_e status = eap_status_ok;

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TIMER: [0x%08x]->eap_am_type_tls_peap_symbian_c::timer_expired(id 0x%02x, data 0x%08x).\n"),
		this, id, data));

#if defined(USE_FAST_EAP_TYPE)

	if(id == KHandleCompletePacstoreNokTimerID)
	    {
        m_eap_fast_completion_status = eap_status_file_does_not_exist;
        m_tls_application->complete_initialize_PAC_store( iCompletionOperation, iCompletion );
        return eap_status_ok;
	    }
    if(id == KHandleCompletePacstoreOkTimerID)
        {
        m_eap_fast_completion_status = eap_status_ok;
        m_tls_application->complete_initialize_PAC_store( iCompletionOperation, iCompletion );
        return eap_status_ok;
        }
    if (id == KRemoveIAPReferenceTimerID)
		{
		status = RemoveIAPReference();

		}
	if (id == KImportFileTimerID)
		{
		TRAPD(err, status = ImportFilesL());
		if (err != KErrNone)
			{
			EAP_TRACE_DEBUG(m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - Leave From ImportFilesL %d\n"),err));
			}
		}

	if (id == KCompleteReadPacstoreTimerID)
		{
		TRAPD(err, FinalCompleteReadPACStoreDataL(m_eap_fast_completion_status));
		if (err != KErrNone)
			{
			EAP_TRACE_DEBUG(m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - Leave From FinalCompleteReadPACStoreDataL %d\n"),err));
			}
		}

	if (id == KHandleReadPacstoreTimerID)
		{
		if (m_state == EPasswordCancel)
			{
			m_eap_fast_completion_status = eap_status_user_cancel_authentication;
			EAP_TRACE_DEBUG(m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - PW query Cancel\n")));
			
			
			status = m_partner->set_timer(
					this,
					KCompleteReadPacstoreTimerID, 
					0,
					0);
			return eap_status_ok;
			}
		if (m_state == EMasterkeyQuery && m_verificationStatus == EFalse)
			{
			if (m_userResponse.get_data_length()>0)
				{
				EAP_TRACE_DEBUG(m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - Masterkey Create\n")));
				m_verificationStatus = ETrue;
				TRAPD(err, m_eap_fast_completion_status=CreateMasterkeyL());
				if (err != KErrNone)
					{
					EAP_TRACE_DEBUG(m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - Leave From CreateMasterkeyL %d\n"),err));
					}
				}
			else
				{
				EAP_TRACE_DEBUG(m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - Masterkey, no data -> final complete for PW\n")));
				m_state = EWrongPassword;
				m_verificationStatus = EFalse;

	        	status = m_partner->set_timer(
						this,
						KCompleteReadPacstoreTimerID,  
						0,
						0);

	        	return status;
				}
			}

		if (m_state == EPasswordQuery || m_state == EWrongPassword || m_state == EMasterkeyQuery)
			{
			if (m_verificationStatus == EFalse)
				{
				TRAPD(err, status = PasswordQueryL());
				m_eap_fast_completion_status = m_am_tools->convert_am_error_to_eapol_error(status);
				if (err != KErrNone)
					{
					EAP_TRACE_DEBUG(m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - Leave From PasswordQueryL %d\n"),err));
					}

				if (m_eap_fast_completion_status != eap_status_ok)
					{
					EAP_TRACE_DEBUG(m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - PW query NOK, final complete for PW\n")));
					
					status = m_partner->set_timer(
							this,
							KCompleteReadPacstoreTimerID, 
							0,
							0);
					}
				}
			if (m_verificationStatus != EFalse)
				{
				TRAPD(err, CompletePasswordQueryL());
				if (err != KErrNone)
					{
					EAP_TRACE_DEBUG(m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - Leave From CompletePasswordQueryL %d\n"),err));
					}

				EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - Complete_password_query, m_both_completed=%d, m_both_asked=%d status=%d.\n"),
								m_both_completed,
								m_both_asked,
								m_eap_fast_completion_status));
				if (m_both_completed == m_both_asked)
					{
					m_both_completed = 0;
					m_both_asked = 0;
					m_verificationStatus = EFalse;
					
					EAP_TRACE_DEBUG(m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - All OK, final complete for PW\n")));
					status = m_partner->set_timer(
							this,
							KCompleteReadPacstoreTimerID,  
							0,
							0);
					return status;
					}
				}
			}

		if (m_state == EFilePasswordQuery)
			{
			TRAPD( err, status = CompleteFilePasswordQueryL());
			if (err != KErrNone)
				{
				EAP_TRACE_DEBUG(m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - Leave From CompleteFilePasswordQueryL %d\n"),err));
				}

			EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - Complete_file_password_query, m_both_completed=%d, m_both_asked=%d status=%d.\n"),
							m_both_completed,
							m_both_asked,
							status));
			if (status != eap_status_ok)
				{
				EAP_TRACE_DEBUG(m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - PW query NOK, final complete for PW\n")));
				status = m_partner->set_timer(
						this,
						KCompleteReadPacstoreTimerID,  
						&status,
						0);
				return status;
				}
			if (m_both_completed == m_both_asked)
				{
				EAP_TRACE_DEBUG(m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_am_type_tls_peap_symbian_c::timer_expired - All ok, final complete for PW\n")));
				m_both_completed = 0;
				m_both_asked = 0;
				status = m_partner->set_timer(
						this,
						KCompleteReadPacstoreTimerID,  
						&status,
						0);
				}
			return status;
			}
		}
#endif //#if defined(USE_FAST_EAP_TYPE)
		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_am_type_tls_peap_symbian_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_am_type_tls_peap_symbian_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(id); // in release
	EAP_UNREFERENCED_PARAMETER(data); // in release

	eap_status_e status = eap_status_ok;

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TIMER: [0x%08x]->eap_am_type_tls_peap_symbian_c::timer_delete_data(id 0x%02x, data 0x%08x).\n"),
		this, id, data));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::type_configure_read(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_ASSERT(data != NULL);
	// Trap must be set here because the OS independent portion of EAP TLS
	// that calls this function does not know anything about Symbian.	
	eap_status_e status(eap_status_ok);
	
	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_tls_peap_symbian_c::type_configure_read - Start\n")));
	
	if (m_current_eap_type == eap_type_peap
#if defined(USE_TTLS_EAP_TYPE)
		|| m_current_eap_type == eap_type_ttls
#endif // #if defined(USE_TTLS_EAP_TYPE)
#if defined(USE_FAST_EAP_TYPE)
		|| m_current_eap_type == eap_type_fast
#endif

		|| m_current_eap_type == eap_type_ttls_plain_pap
	
		)
	{
		// Check if the wanted parameter is default type
		eap_variable_data_c wanted_field(m_am_tools);
		eap_variable_data_c type_field(m_am_tools);
		eap_variable_data_c type_field_server(m_am_tools);
		
		status = wanted_field.set_buffer(
			field->get_field(),
			field->get_field_length(),
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = type_field.set_buffer(
			cf_str_PEAP_tunneled_eap_type_hex_data.get_field()->get_field(),
			cf_str_PEAP_tunneled_eap_type_hex_data.get_field()->get_field_length(),
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = type_field_server.set_buffer(
			cf_str_PEAP_server_tunneled_eap_type_hex_data.get_field()->get_field(),
			cf_str_PEAP_server_tunneled_eap_type_hex_data.get_field()->get_field_length(),
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		if (!wanted_field.compare(&type_field_server))
		{
			// Change the name of the parameter because Symbian AM does not have separate config
			// for the server
			status = wanted_field.set_buffer(
				cf_str_PEAP_tunneled_eap_type_hex_data.get_field()->get_field(),
				cf_str_PEAP_tunneled_eap_type_hex_data.get_field()->get_field_length(),
				false,
				false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}


		if (!wanted_field.compare(&type_field))
		{
			// We are asked to return cf_str_PEAP_tunneled_eap_type_hex_data
			
#ifdef USE_EAP_EXPANDED_TYPES
	
			// We need to return here the next ENABLED tunneled EAP type we should try. 
	
			if (0 == m_enabled_tunneling_exp_eap_array.Count())
			{
				// No EAP types are ENABLED as tunneling type.
				if (m_is_client)
				{
					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: No ENABLED encapsulated EAP types.\n")));
				}
				
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
			}
			else
			{
				// Get the first enabled EAP type (tunneling).

				TBuf8<KExpandedEAPTypeSize> tmpExpEAP(m_enabled_tunneling_exp_eap_array[0]->iExpandedEAPType); //first item.

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("type_configure_read:Enabled expanded tunneling EAP type:"),
					tmpExpEAP.Ptr(),
					tmpExpEAP.Size()));
					
					status = data->set_copy_of_buffer(tmpExpEAP.Ptr(), KExpandedEAPTypeSize);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);			
					}
					
				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAP-PEAP or EAP-TTLS: Trying encapsulated EAP type:"),
					tmpExpEAP.Ptr(),
					tmpExpEAP.Size()));
			}
	
#else // For normal EAP types.
			
			// We need to return here the next tunneled EAP type we should try. 
			TInt i;

			for (i = 0; i < m_iap_eap_array.Count(); i++)
			{
				// Find the first enabled EAP type (highest priority)
				TEap *eapType = m_iap_eap_array[i];			
				if (eapType->Enabled == 1)
				{
					// Convert the string to integer
					TLex8 tmp(eapType->UID);
					TInt val(0);
					tmp.Val(val);
					status = data->set_copy_of_buffer(reinterpret_cast<u8_t *>(&val), sizeof(TUint));
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);			
					}
					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("EAP-PEAP: Trying encapsulated EAP type: %d.\n"), val));
					break;
				}
			}		
			if (i == m_iap_eap_array.Count())
			{
				// Not found
				if (m_is_client)
				{
					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: No configured encapsulated EAP types.\n")));
				}
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
			}
			
#endif //#ifdef USE_EAP_EXPANDED_TYPES
					
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		
		} // End of  if (!wanted_field.compare(&type_field))
		
#if !defined(USE_EAP_EXPANDED_TYPES)

		// cf_str_PEAP_accepted_tunneled_client_types_hex_data is available only for expaned EAP types.
		// cf_str_PEAP_accepted_tunneled_client_types_u32array should be used otherwise.
		// So for cf_str_PEAP_accepted_tunneled_client_types_hex_data and eap_configure_type_hex_data
		// we should return eap_status_illegal_configure_field.
		// This is needed only if USE_EAP_EXPANDED_TYPES is not defined. Otherwise the field 
		// cf_str_PEAP_accepted_tunneled_client_types_hex_data can be read from the database using
		// type_configure_readL (let it fall through).

		eap_variable_data_c tunneled_type_field(m_am_tools);

		status = tunneled_type_field.set_buffer(
			cf_str_PEAP_accepted_tunneled_client_types_hex_data.get_field()->get_field(),
			cf_str_PEAP_accepted_tunneled_client_types_hex_data.get_field()->get_field_length(),
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (!wanted_field.compare(&tunneled_type_field))
		{
			// Check if the type is eap_configure_type_hex_data.
			
			if( eap_configure_type_hex_data ==  field->get_type() )
			{
				// This field is used only for exapanded EAP types.
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_type);
			}
		}
		
#else // For expanded EAP type.

		// cf_str_PEAP_accepted_tunneled_client_types_u32array is available only for normal EAP types.
		// So for cf_str_PEAP_accepted_tunneled_client_types_u32array and eap_configure_type_u32array
		// we should return eap_status_illegal_configure_field.
		
		eap_variable_data_c tunneled_type_field(m_am_tools);

		status = tunneled_type_field.set_buffer(
			cf_str_PEAP_accepted_tunneled_client_types_u32array.get_field()->get_field(),
			cf_str_PEAP_accepted_tunneled_client_types_u32array.get_field()->get_field_length(),
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (!wanted_field.compare(&tunneled_type_field))
		{
			// Check if the type is eap_configure_type_u32array.
			
			if( eap_configure_type_u32array ==  field->get_type() )
			{
				// This field is used only for Normal EAP types. This is illegal here.
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_type);
			}
		}
		
#endif // End of #if !defined(USE_EAP_EXPANDED_TYPES)
		
	} // End of if (m_current_eap_type == eap_type_peap
	
	TRAPD(err, type_configure_readL(
		field->get_field(),
		field->get_field_length(),
		data));
	if (err != KErrNone) 
	{	
		status = m_am_tools->convert_am_error_to_eapol_error(err);
	}

	m_am_tools->trace_configuration(
		status,
		field,
		data);
        
	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_tls_peap_symbian_c::type_configure_read - End\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
void eap_am_type_tls_peap_symbian_c::type_configure_readL(
	eap_config_string field,
	const u32_t field_length,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(field_length);

	// Create a buffer for the ascii strings - initialised with the argument
	HBufC8* asciibuf = HBufC8::NewLC(KMaxDBFieldNameLength);
	TPtr8 asciiString = asciibuf->Des();
	asciiString.Copy(reinterpret_cast<const unsigned char *>(field));

	EAP_TRACE_DATA_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_tls_peap_symbian_c::type_configure_readL: Reading field:"),
		asciiString.Ptr(),
		asciiString.Size()));

	// Buffer for unicode parameter
	HBufC* unicodebuf = HBufC::NewLC(KMaxDBFieldNameLength);
	TPtr unicodeString = unicodebuf->Des();
	
	// Convert to unicode 
	unicodeString.Copy(asciiString);
	
	// Now do the database query
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");	
	
#if defined(USE_FAST_EAP_TYPE)
	
	// Unlike other EAP types, EAP-FAST has some settings in special settings table
	// (m_db_fast_special_table_name)
	
	if(m_current_eap_type == eap_type_fast
	   && ((unicodeString.Compare(cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal) == 0)
	   || (unicodeString.Compare(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal) == 0)
	   || (unicodeString.Compare(cf_str_EAP_FAST_warn_ADHP_no_PAC_literal) == 0)
	   || (unicodeString.Compare(cf_str_EAP_FAST_warn_ADHP_no_matching_PAC_literal) == 0)
	   || (unicodeString.Compare(cf_str_EAP_FAST_warn_ADHP_not_default_server_literal) == 0)
	   || (unicodeString.Compare(KFASTPACGroupImportReferenceCollection) == 0)
	   || (unicodeString.Compare(KFASTPACGroupDBReferenceCollection) == 0)))
	    {
	    if (unicodeString.Compare(cf_str_EAP_FAST_warn_ADHP_no_matching_PAC_literal) == 0)
	        {
	        unicodeString.Copy(KFASTWarnADHPNoMatchingPAC);
	        }
        if (unicodeString.Compare(cf_str_EAP_FAST_warn_ADHP_no_PAC_literal) == 0)
            {
            unicodeString.Copy(KFASTWarnADHPNoPAC);
            }
        if (unicodeString.Compare(cf_str_EAP_FAST_warn_ADHP_not_default_server_literal) == 0)
            {
            unicodeString.Copy(KFASTWarnNotDefaultServer);
            }
		EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_am_type_tls_peap_symbian_c::type_configure_readL This field will be read from EAP-FAST's special table\n")));
		
		sqlStatement.Format(KSQLQueryRow, &unicodeString, &m_db_fast_special_table_name, 
			&KServiceType, m_index_type, &KServiceIndex, m_index, &KTunnelingType, m_tunneling_vendor_type);		
	    }
	else
	    {
		sqlStatement.Format(KSQLQueryRow, &unicodeString, &m_db_table_name, 
			&KServiceType, m_index_type, &KServiceIndex, m_index, &KTunnelingType, m_tunneling_vendor_type);		
	    }
	
#else

	sqlStatement.Format(KSQLQueryRow, &unicodeString, &m_db_table_name, 
		&KServiceType, m_index_type, &KServiceIndex, m_index, &KTunnelingType, m_tunneling_vendor_type);
		
#endif // End: #if defined(USE_FAST_EAP_TYPE)
	
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());	
	if (view.FirstL())
	{
		eap_status_e status;
		view.GetL();		
		switch (view.ColType(KDefaultColumnInView_One))
		{
		case EDbColText:				
			{
				unicodeString = view.ColDes(KDefaultColumnInView_One);
				// Convert to 8-bit
				asciiString.Copy(unicodeString);
				if (asciiString.Size() > 0)
				{
					status = data->set_copy_of_buffer(asciiString.Ptr(), asciiString.Size());
					if (status != eap_status_ok)
					{
						User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
					}
				} 
				else 
				{
					status = data->init(0);
					if (status != eap_status_ok)
					{
						User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
					}
					data->set_is_valid();					
					break;					
				}
			}
			break;
		case EDbColUint32:
			{
				TUint value;
				value = view.ColUint32(KDefaultColumnInView_One);
				status = data->set_copy_of_buffer(&value, sizeof(value));
				if (status != eap_status_ok)
				{
					User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
				}				
			}
			break;

		case EDbColBinary:
			{
				TPtrC8 value = view.ColDes8(KDefaultColumnInView_One);
				status = data->set_copy_of_buffer(value.Ptr(), value.Length());
				if (status != eap_status_ok)
				{
					User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
				}
			}
			break;
		default:
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("type_configure_readL: Unexpected column type.\n")));
			User::Leave(KErrGeneral);
			break;
		}
	}
	else
	{
		// Could not find parameter
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("type_configure_readL: Could not find configuration parameter.\n")));
		User::Leave(KErrArgument);
	}		

	// Close database
	CleanupStack::PopAndDestroy(4); // view

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}
//--------------------------------------------------

//

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::type_configure_write(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	// Here configuration data must be read from type spesific database.

	// NOTE: This is really just for simulation.
	// Write is routed to partner object.
	eap_status_e status = m_partner->write_configure(
			field,
			data);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//

void eap_am_type_tls_peap_symbian_c::WriteBinaryParamL(
	eap_config_string field,
	const u32_t field_length,
	const eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	// Form the insertion command
	TPtrC8 p(reinterpret_cast<const unsigned char *>(field), field_length);

	HBufC* fieldbuf = HBufC::NewLC(KMaxDBFieldNameLength);
	TPtr field_name = fieldbuf->Des();

	field_name.Copy(p);
	
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLInsert, "SELECT %s FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLInsert, field_name.PtrZ(), &m_db_table_name, 
		&KServiceType, m_index_type, &KServiceIndex, m_index, &KTunnelingType, m_tunneling_vendor_type);
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	// Update the columns in the database
	view.FirstL();

	view.UpdateL();
	
	if (data->get_is_valid_data() == true)
	{
		TPtrC8 data_ptr(data->get_data(data->get_data_length()), data->get_data_length());
		view.SetColL(KDefaultColumnInView_One, data_ptr); 
	}
	else
	{
		view.SetColNullL(KDefaultColumnInView_One); 
	}	
	view.PutL();

	// Close database
	CleanupStack::PopAndDestroy(3); // view, 2 strings

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

void eap_am_type_tls_peap_symbian_c::WriteIntParamL(
	eap_config_string field,
	const u32_t field_length,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	TPtrC8 p(reinterpret_cast<const unsigned char *>(field), field_length);
	
	HBufC* fieldbuf = HBufC::NewLC(KMaxDBFieldNameLength);
	TPtr field_name = fieldbuf->Des();
	
	field_name.Copy(p);	
	
	// Form the insertion command
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLInsert, "SELECT %s FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLInsert, field_name.PtrZ(), &m_db_table_name, 
		&KServiceType, m_index_type, &KServiceIndex, m_index, &KTunnelingType, m_tunneling_vendor_type);
	
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	// Create pointers to the data
	TPtrC8 data_ptr(data->get_data(data->get_data_length()), data->get_data_length());

	// Convert the string to integer
	const TInt val = *( reinterpret_cast<const TInt*>(data_ptr.Ptr()) );
	
	// Update the columns in the database
	view.FirstL();
	
	view.UpdateL();

	view.SetColL(KDefaultColumnInView_One, val); 	
	view.PutL();
	
	// Close database
	CleanupStack::PopAndDestroy(3); // view, buf, 2nd buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

void eap_am_type_tls_peap_symbian_c::WriteIntParamL(
	eap_config_string field,
	const u32_t field_length,
	const u32_t value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	TPtrC8 p(reinterpret_cast<const unsigned char *>(field), field_length);
	
	HBufC* fieldbuf = HBufC::NewLC(KMaxDBFieldNameLength);
	TPtr field_name = fieldbuf->Des();
	
	field_name.Copy(p);	
	
	// Form the insertion command
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLInsert, "SELECT %s FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLInsert, field_name.PtrZ(), &m_db_table_name, 
		&KServiceType, m_index_type, &KServiceIndex, m_index, &KTunnelingType, m_tunneling_vendor_type);
	
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	// Update the columns in the database
	view.FirstL();

	view.UpdateL();
	
	view.SetColL(KDefaultColumnInView_One, value); 	
	view.PutL();
	
	// Close database
	CleanupStack::PopAndDestroy(3); // view, buf, 2nd buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void eap_am_type_tls_peap_symbian_c::ResetSessionIdL()
{	
	eap_variable_data_c count_of_session_resumes(m_am_tools);
	eap_variable_data_c session_id(m_am_tools);
	eap_variable_data_c master_secret(m_am_tools);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, 
		(EAPL("ResetSessionIdL - clearing session resume info.\n")));
		
	{	
		session_id.reset();
		WriteBinaryParamL(
			cf_str_EAP_TLS_PEAP_saved_session_id.get_field()->get_field(),
			cf_str_EAP_TLS_PEAP_saved_session_id.get_field()->get_field_length(),
			&session_id);
	}

	{
		master_secret.reset();
		WriteBinaryParamL(
			cf_str_EAP_TLS_PEAP_saved_master_secret.get_field()->get_field(),
			cf_str_EAP_TLS_PEAP_saved_master_secret.get_field()->get_field_length(),
			&master_secret);
	}

	{
		WriteIntParamL(
			cf_str_EAP_TLS_PEAP_saved_cipher_suite.get_field()->get_field(),
			cf_str_EAP_TLS_PEAP_saved_cipher_suite.get_field()->get_field_length(),
			tls_cipher_suites_TLS_NULL_WITH_NULL_NULL);
	}	
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::alert_received(
	const tls_alert_level_e alert_level,
	const tls_alert_description_e alert_description)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(alert_description); // in release
	EAP_UNREFERENCED_PARAMETER(alert_level); // in release

	eap_tls_trace_string_c tls_trace;

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ERROR: %s: message_function: alert_received(), level %d=%s, description %d=%s\n"),
		 (m_is_client == true ? "client": "server"),
		 alert_level,
		 tls_trace.get_alert_level_string(alert_level),
		 alert_description,
		 tls_trace.get_alert_description_string(alert_description)));
	
	// Store alert description so that it is possible to disallow certificates based
	// on that information.
	m_latest_alert_description = alert_description;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------


EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::query_cipher_suites_and_previous_session()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: %s: function: query_cipher_suites_and_previous_session()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_ASSERT_ALWAYS(m_is_client == true);

	eap_status_e status(eap_status_process_general_error);
	
	TAlgorithmId certAlgorithm(ERSA);

	bool select_all_cipher_suites = false;
	
	eap_variable_data_c session_id(m_am_tools);
	eap_variable_data_c master_secret(m_am_tools);
	tls_cipher_suites_e used_cipher_suite(tls_cipher_suites_TLS_NULL_WITH_NULL_NULL);
	tls_session_type_e tls_session_type(tls_session_type_full_authentication);	

	eap_array_c<u16_t> cipher_suites(m_am_tools);
		
#if defined(USE_FAST_EAP_TYPE)
		
	if(m_current_eap_type == eap_type_fast &&
	   m_serv_unauth_prov_mode == true)
	{
		EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("eap_am_type_tls_peap_symbian_c::query_cipher_suites_and_previous_session-Exception for EAP-FAST as m_serv_unauth_prov_mode is true \n")));			
			
		tls_session_type = tls_session_type_eap_fast_server_unauthenticated_provisioning_mode_ADHP;
		
		// This is the only cipher suite needed in this case.		
		{
			u16_t *tmp_object = new u16_t;
			if (tmp_object == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			*tmp_object = eap_htons(tls_cipher_suites_TLS_DH_anon_WITH_AES_128_CBC_SHA);
			
			status = cipher_suites.add_object(tmp_object, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		
		
	}
	else		
#endif // #if defined(USE_FAST_EAP_TYPE)
	
	{
		// This is the normal case for all EAP types (for EAP-FAST with m_serv_unauth_prov_mode = false).

		if (m_own_certificate == 0
			&& m_ca_certificate == 0)
		{
			// Since there is no user certificate and CA cert has not been read yet
			// we need to read the CA cert.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("query_cipher_suites_and_previous_session(): No user or CA certificate. Read CA certificate.\n")));
			
			if (m_allowed_ca_certs.Count() != 0)
			{		
#if defined(USE_FAST_EAP_TYPE)
				
				if(m_current_eap_type == eap_type_fast)
				{
					// Exception for EAP-FAST
					
					EAP_TRACE_DEBUG(m_am_tools, 
					TRACE_FLAGS_DEFAULT, (
					EAPL("eap_am_type_tls_peap_symbian_c::query_cipher_suites_and_previous_session - No CA certificate but exception for EAP-FAST\n")));				
				}
				else	
#endif // #if defined(USE_FAST_EAP_TYPE)
				{
					m_state = EHandlingCipherSuiteQuery;
					
					TRAPD(err, m_cert_if->ReadCACertificateL(m_allowed_ca_certs[0]));
					if (err != KErrNone)
					{
						// Error occurred. Just select all cipher suites.
						select_all_cipher_suites = true;
					}
					else
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_pending_request);
					}
				}
			} // End: if (m_allowed_ca_certs.Count() != 0)
		}
		else if (m_own_certificate != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("Selecting cipher suites based on user certificate algorithm.\n")));
			
			select_all_cipher_suites = false;
			
			const CSubjectPublicKeyInfo& public_key = m_own_certificate->PublicKey();

			certAlgorithm = public_key.AlgorithmId();				
		}
		else 
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("Selecting cipher suites based on CA certificate algorithm.\n")));
		
			select_all_cipher_suites = false;
			
			const CSubjectPublicKeyInfo& public_key = m_ca_certificate->PublicKey();

			certAlgorithm = public_key.AlgorithmId();				
		}
		
			// IF cipher suite is allowed
		if (m_allowed_cipher_suites.Find(tls_cipher_suites_TLS_RSA_WITH_3DES_EDE_CBC_SHA) != KErrNotFound
			// AND the algorithm matches the certificates algorithm
			&& (select_all_cipher_suites == true
				|| certAlgorithm == ERSA))
			// THEN add it to list.
		{
			u16_t *tmp_object = new u16_t;
			if (tmp_object == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			*tmp_object = eap_htons(tls_cipher_suites_TLS_RSA_WITH_3DES_EDE_CBC_SHA);
			
			status = cipher_suites.add_object(tmp_object, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		if (m_allowed_cipher_suites.Find(tls_cipher_suites_TLS_RSA_WITH_AES_128_CBC_SHA) != KErrNotFound
			// AND the algorithm matches the certificates algorithm
			&& (select_all_cipher_suites == true
				|| certAlgorithm == ERSA))
			// THEN add it to list.
		{
			u16_t *tmp_object = new u16_t;
			if (tmp_object == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			*tmp_object = eap_htons(tls_cipher_suites_TLS_RSA_WITH_AES_128_CBC_SHA);
			
			status = cipher_suites.add_object(tmp_object, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		if (m_allowed_cipher_suites.Find(tls_cipher_suites_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA) != KErrNotFound
			// AND the algorithm matches the certificates algorithm
			&& (select_all_cipher_suites == true
				|| certAlgorithm == EDSA))
			// THEN add it to list.
		{
			u16_t *tmp_object = new u16_t;
			if (tmp_object == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			*tmp_object = eap_htons(tls_cipher_suites_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
			
			status = cipher_suites.add_object(tmp_object, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		if (m_allowed_cipher_suites.Find(tls_cipher_suites_TLS_DHE_DSS_WITH_AES_128_CBC_SHA) != KErrNotFound
			// AND the algorithm matches the certificates algorithm
			&& (select_all_cipher_suites == true
				|| certAlgorithm == EDSA))
			// THEN add it to list.
		{
			u16_t *tmp_object = new u16_t;
			if (tmp_object == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			*tmp_object = eap_htons(tls_cipher_suites_TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
			
			status = cipher_suites.add_object(tmp_object, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		if (m_allowed_cipher_suites.Find(tls_cipher_suites_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA) != KErrNotFound
			// AND the algorithm matches the certificates algorithm
			&& (select_all_cipher_suites == true
				|| certAlgorithm == ERSA))
			// THEN add it to list.
		{
			u16_t *tmp_object = new u16_t;
			if (tmp_object == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			*tmp_object = eap_htons(tls_cipher_suites_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
			
			status = cipher_suites.add_object(tmp_object, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		if (m_allowed_cipher_suites.Find(tls_cipher_suites_TLS_DHE_RSA_WITH_AES_128_CBC_SHA) != KErrNotFound
			// AND the algorithm matches the certificates algorithm
			&& (select_all_cipher_suites == true
				|| certAlgorithm == ERSA))
			// THEN add it to list.
		{
			u16_t *tmp_object = new u16_t;
			if (tmp_object == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			*tmp_object = eap_htons(tls_cipher_suites_TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
			
			status = cipher_suites.add_object(tmp_object, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		if (m_allowed_cipher_suites.Find(tls_cipher_suites_TLS_RSA_WITH_RC4_128_MD5) != KErrNotFound
			// AND the algorithm matches the certificates algorithm
			&& (select_all_cipher_suites == true
				|| certAlgorithm == ERSA))
			// THEN add it to list.
		{
			u16_t *tmp_object = new u16_t;
			if (tmp_object == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			*tmp_object = eap_htons(tls_cipher_suites_TLS_RSA_WITH_RC4_128_MD5);
			
			status = cipher_suites.add_object(tmp_object, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		if (m_allowed_cipher_suites.Find(tls_cipher_suites_TLS_RSA_WITH_RC4_128_SHA) != KErrNotFound
			// AND the algorithm matches the certificates algorithm
			&& (select_all_cipher_suites == true
				|| certAlgorithm == ERSA))
			// THEN add it to list.)
		{
			u16_t *tmp_object = new u16_t;
			if (tmp_object == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			*tmp_object = eap_htons(tls_cipher_suites_TLS_RSA_WITH_RC4_128_SHA);
			
			status = cipher_suites.add_object(tmp_object, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		
		if (is_session_valid())
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Trying to resume previous session as previous session is still valid\n")));		

			// OK, previous session will be restored.
			
			// Read database fields.
			{
				eap_status_e status = type_configure_read(
					cf_str_EAP_TLS_PEAP_saved_session_id.get_field(),
					&session_id);
				if (status != eap_status_ok
					|| session_id.get_is_valid_data() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);					
				}
			}

			{
				eap_status_e status = type_configure_read(
					cf_str_EAP_TLS_PEAP_saved_master_secret.get_field(),
					&master_secret);
				if (status != eap_status_ok
					|| master_secret.get_is_valid_data() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);					
				}
			}

			{
				eap_variable_data_c saved_cipher_suite(m_am_tools);
				
				eap_status_e status = type_configure_read(
					cf_str_EAP_TLS_PEAP_saved_cipher_suite.get_field(),
					&saved_cipher_suite);
				if (status == eap_status_ok
					&& saved_cipher_suite.get_is_valid_data() == true
					&& saved_cipher_suite.get_data_length() == sizeof(u32_t)
					&& saved_cipher_suite.get_data(sizeof(u32_t)) != 0)
				{	
					// OK			
					used_cipher_suite = static_cast<tls_cipher_suites_e>(*(reinterpret_cast<u32_t *>(saved_cipher_suite.get_data(sizeof(u32_t)))));
					
					u16_t tmp_object = eap_htons(static_cast<u16_t> (used_cipher_suite));
					
					tls_session_type = tls_session_type_original_session_resumption;

					if( 0 > find_simple<u16_t>( &cipher_suites, 
						&tmp_object, 
						m_am_tools ) )
					{	
						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("TLS: %s: cipher suite of the resumed session is NOT included in the cipher_suites list.\n"),
							(m_is_client == true ? "client": "server")));
					
						used_cipher_suite = tls_cipher_suites_TLS_NULL_WITH_NULL_NULL;
						
						master_secret.reset();
						
						session_id.reset();	
					}
				}			
			}		
		}
		
		if(used_cipher_suite == tls_cipher_suites_TLS_NULL_WITH_NULL_NULL)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TLS: %s: query_cipher_suites_and_previous_session(): creates new session.\n"),
				(m_is_client == true ? "client": "server")));

			TRAPD(err, ResetSessionIdL());
			if (err != KErrNone)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);					
			}

			tls_session_type = tls_session_type_full_authentication;
		}
		
	} // End : 	if(m_current_eap_type == eap_type_fast &&
	  //		m_serv_unauth_prov_mode == true)
 

	// Compression methods. TLS supports only null compression at the moment.
	eap_array_c<u8_t> compression_methods(m_am_tools);
	{
		u8_t *tmp_object = new u8_t;
		if (tmp_object == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		*tmp_object = tls_compression_method_null;
		status = compression_methods.add_object(tmp_object, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = get_tls_am_partner()->complete_query_cipher_suites_and_previous_session(
		tls_session_type,
		&cipher_suites,
		&compression_methods,
#if defined(USE_EAP_TLS_SESSION_TICKET)
		0,
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
		&session_id,
		&master_secret,
		used_cipher_suite,
		eap_status_ok);
	if (status == eap_status_ok ||
		status == eap_status_pending_request)	
	{
		status = eap_status_completed_request;
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TLS_SESSION_TICKET)

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::query_new_session_ticket()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: query_new_session_ticket()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_ASSERT_ALWAYS(m_is_client == false);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::select_cipher_suite_and_check_session_id(
	EAP_TEMPLATE_CONST eap_array_c<u16_t> * const cipher_suite_proposal,
	const eap_variable_data_c * const session_id
#if defined(USE_EAP_TLS_SESSION_TICKET)
	, const tls_extension_c * const /* session_ticket */
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: %s: function: select_cipher_suite_and_check_session_id()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_ASSERT_ALWAYS(m_is_client == false);

	eap_status_e status = eap_status_illegal_payload;
	u16_t *tmp_object = 0;

	tls_session_type_e tls_session_type(tls_session_type_full_authentication);

	for (u32_t ind = 0; ind < cipher_suite_proposal->get_object_count(); ind++)
	{
		tmp_object = cipher_suite_proposal->get_object(ind);
		if (tmp_object == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
						
		if (m_allowed_cipher_suites.Find(*tmp_object) != KErrNotFound)
		{			
			// Read stored session id		
			eap_variable_data_c stored_session_id(m_am_tools);
			eap_variable_data_c stored_master_secret(m_am_tools);
			tls_cipher_suites_e stored_cipher_suite(tls_cipher_suites_TLS_NULL_WITH_NULL_NULL);

			eap_variable_data_c count_of_session_resumes(m_am_tools);

			{
				status = type_configure_read(
					cf_str_EAP_TLS_PEAP_saved_session_id.get_field(),
					&stored_session_id);
				if (status != eap_status_ok
					|| stored_session_id.get_is_valid_data() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);									
				}
			}

			if (session_id != 0
				&& session_id->get_is_valid_data() == true
				&& session_id->compare(&stored_session_id) == 0
				&& is_session_valid())
			{
				// OK, previous session will be restored.
				
				// Read database fields.
				{
					eap_status_e status = type_configure_read(
						cf_str_EAP_TLS_PEAP_saved_session_id.get_field(),
						&stored_session_id);
					if (status != eap_status_ok
						|| stored_session_id.get_is_valid_data() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
					}
				}

				{
					eap_status_e status = type_configure_read(
						cf_str_EAP_TLS_PEAP_saved_master_secret.get_field(),
						&stored_master_secret);
					if (status != eap_status_ok
						|| stored_master_secret.get_is_valid_data() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
					}
				}

				{
					eap_variable_data_c saved_cipher_suite(m_am_tools);
					
					eap_status_e status = type_configure_read(
						cf_str_EAP_TLS_PEAP_saved_cipher_suite.get_field(),
						&saved_cipher_suite);
					if (status == eap_status_ok
						&& saved_cipher_suite.get_is_valid_data() == true
						&& saved_cipher_suite.get_data_length() == sizeof(u32_t)
						&& saved_cipher_suite.get_data(sizeof(u32_t)) != 0)
					{	
						// OK			

						stored_cipher_suite = static_cast<tls_cipher_suites_e>(*(reinterpret_cast<u32_t *>(saved_cipher_suite.get_data(sizeof(u32_t)))));						
					}			
					else
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
					}
				}

				tls_session_type = tls_session_type_original_session_resumption;

			}
			else
			{
				{	
					stored_session_id.reset();

					TRAPD(err, WriteBinaryParamL(
						cf_str_EAP_TLS_PEAP_saved_session_id.get_field()->get_field(),
						cf_str_EAP_TLS_PEAP_saved_session_id.get_field()->get_field_length(),
						&stored_session_id));
					if (err != KErrNone)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
					}
				}

				{
					stored_master_secret.reset();

					TRAPD(err, WriteBinaryParamL(
						cf_str_EAP_TLS_PEAP_saved_master_secret.get_field()->get_field(),
						cf_str_EAP_TLS_PEAP_saved_master_secret.get_field()->get_field_length(),
						&stored_master_secret));
					if (err != KErrNone)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
					}
				}					

				{
					TRAPD(err, WriteIntParamL(
						cf_str_EAP_TLS_PEAP_saved_cipher_suite.get_field()->get_field(),
						cf_str_EAP_TLS_PEAP_saved_cipher_suite.get_field()->get_field_length(),
						tls_cipher_suites_TLS_NULL_WITH_NULL_NULL));
					if (err != KErrNone)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);					
					}
				}					
			}

			if (stored_cipher_suite != tls_cipher_suites_TLS_NULL_WITH_NULL_NULL)
			{
				// We got saved cipher suite from previous session
				m_cipher_suite = stored_cipher_suite;
			}
			else
			{
				// Use the first cipher suite the client offered
				m_cipher_suite = static_cast<tls_cipher_suites_e>(*tmp_object);
			}

			status = get_tls_am_partner()->complete_select_cipher_suite_and_check_session_id(
				tls_session_type,
				static_cast<u8_t>(m_cipher_suite),
				&stored_session_id,
				&stored_master_secret,
#if defined(USE_EAP_TLS_SESSION_TICKET)
				0,
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
				eap_status_ok);

			break;
		}
	} // for()

	if (status == eap_status_ok ||
		status == eap_status_pending_request)	
	{
		status = eap_status_completed_request;
	}

	if (status != eap_status_completed_request)
	{
		// Could not find matching cipher suite
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Server: Could not find matching cipher suite in client's proposal.\n")));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::verify_certificate_chain(
	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain,
	const tls_cipher_suites_e required_cipher_suite)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: %s: message_function: verify_certificate_chain_and_query_public_key()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_ASSERT_ALWAYS(certificate_chain->get_object_count() > 0);

	eap_status_e status(eap_status_ok);

	TRAPD(err, verify_certificate_chainL(certificate_chain, required_cipher_suite));
	if (err != KErrNone)
	{
		if (err == KErrArgument)
		{
			status = eap_status_illegal_certificate;
		}
		else
		{
			status = m_am_tools->convert_am_error_to_eapol_error(err);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

void eap_am_type_tls_peap_symbian_c::verify_certificate_chainL(
	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_chain,
	const tls_cipher_suites_e required_cipher_suite)
{
	EAP_TRACE_DEBUG(m_am_tools, 
	TRACE_FLAGS_DEFAULT, 
	(EAPL("eap_am_type_tls_peap_symbian_c::verify_certificate_chainL: Number of certificates in chain=%d\n"),
		certificate_chain->get_object_count()));

	eap_status_e status(eap_status_process_general_error);
	if (m_is_client)
	{
		m_cipher_suite = required_cipher_suite;
	}
	
	// Verify that server certificate's realm matches with our identity realm
	// If server does not verify client then we don't necessarily have a certificate
	// and thus we cannot verify server here. 	
	if (m_is_client
		&& m_verify_certificate_realm == true
		&& (m_own_certificate != 0
			|| (m_use_manual_realm == true
				&& m_manual_realm.get_is_valid_data() == true)))
	{
		eap_variable_data_c client_subject_realm(m_am_tools);
		eap_variable_data_c manual_client_subject_realm(m_am_tools);
		eap_variable_data_c client_issuer_realm(m_am_tools);

		if (m_own_certificate != 0)
		{
			status = get_realms_from_certificate(
				m_own_certificate, 
				&client_subject_realm,
				&client_issuer_realm);
			if (status != eap_status_ok)
			{
				// Could not find realms... Give up.
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: EAP-TLS: Could not find realm from client certificate.\n")));
				User::Leave(KErrArgument);
			}
		} 
		else 
		{
			status = client_subject_realm.init(0);
			if (status != eap_status_ok)
			{
				User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
			}

			client_subject_realm.set_is_valid();					

			status = client_issuer_realm.init(0);
			if (status != eap_status_ok)
			{
				User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
			}

			client_issuer_realm.set_is_valid();					
		}
		
		if (m_use_manual_realm == true
				&& m_manual_realm.get_is_valid_data() == true)
		{
			status = manual_client_subject_realm.set_copy_of_buffer(&m_manual_realm);
			if (status != eap_status_ok)
			{
				User::Leave(KErrNoMemory);
			}						
		}

		eap_variable_data_c server_subject_realm(m_am_tools);
		eap_variable_data_c server_issuer_realm(m_am_tools);

		eap_variable_data_c* cert;
		cert = certificate_chain->get_object(0);
		
		if( cert == NULL )
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: EAP-TLS: No certs in certificate_chain\n")));		
				
			User::Leave(KErrArgument);		
		}
		
		TPtr8 ptr(
			cert->get_data(cert->get_data_length()), 
			cert->get_data_length(),
			cert->get_data_length());
		CX509Certificate* server_certificate = CX509Certificate::NewL(ptr);	

		if( server_certificate == NULL )
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: EAP-TLS: No memory for server_certificate\n")));		
				
			User::Leave(KErrNoMemory);		
		}
		
		CleanupStack::PushL(server_certificate);

		status = get_realms_from_certificate(
			server_certificate, 
			&server_subject_realm, 
			&server_issuer_realm);
		if (status != eap_status_ok
			|| server_subject_realm.get_is_valid_data() == false
			|| server_issuer_realm.get_is_valid_data() == false)
		{	
			// Could not find realms... Give up.
			EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: EAP-TLS: Could not find realm from server certificate.\n")));
			User::Leave(KErrArgument);
		}
		CleanupStack::PopAndDestroy(server_certificate);
				
		if (client_subject_realm.get_is_valid_data() == true)
		{
			EAP_TRACE_DATA_DEBUG(m_am_tools, 
				TRACE_FLAGS_DEFAULT, (EAPL("Client subject realm:"),
				client_subject_realm.get_data(client_subject_realm.get_data_length()),
				client_subject_realm.get_data_length()));
		}
		else
		{
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Client subject realm is empty.\n")));
		}
		
		if (manual_client_subject_realm.get_is_valid_data() == true)
		{
			EAP_TRACE_DATA_DEBUG(m_am_tools, 
				TRACE_FLAGS_DEFAULT, (EAPL("Client manual realm:"),
				manual_client_subject_realm.get_data(manual_client_subject_realm.get_data_length()),
				manual_client_subject_realm.get_data_length()));
		}
		else
		{
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Client manual realm is empty.\n")));
		}
		
		EAP_TRACE_DATA_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (EAPL("Server subject realm:"),
			server_subject_realm.get_data(server_subject_realm.get_data_length()),
			server_subject_realm.get_data_length()));
		
		EAP_TRACE_DATA_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (EAPL("Server issuer realm:"),
			server_issuer_realm.get_data(server_issuer_realm.get_data_length()),
			server_issuer_realm.get_data_length()));

		// First check exact match with client subject realm and server subject and issuer realms
		if (client_subject_realm.get_is_valid_data() == false
			|| (client_subject_realm.get_is_valid_data() == true
				&& client_subject_realm.compare(&server_subject_realm) != 0
				&& client_subject_realm.compare(&server_issuer_realm) != 0))
		{
			// Check if manual realm matches
			if (manual_client_subject_realm.get_is_valid_data() == false 
				|| (manual_client_subject_realm.get_is_valid_data() == true
					&& manual_client_subject_realm.compare(&server_subject_realm) != 0
					&& manual_client_subject_realm.compare(&server_issuer_realm) != 0))
			{			
				// Realms did not match! Are we allowed to do relaxed subdomain checking?
				if (m_allow_subdomain_matching == true)
				{										
						
					TPtr8 client_subject_ptr(
						client_subject_realm.get_data(client_subject_realm.get_data_length()), 
						client_subject_realm.get_data_length(),
						client_subject_realm.get_data_length());
															
					TPtr8 server_subject_ptr(
						server_subject_realm.get_data(server_subject_realm.get_data_length()), 
						server_subject_realm.get_data_length(),
						server_subject_realm.get_data_length());

					TPtr8 server_issuer_ptr(
						server_issuer_realm.get_data(server_issuer_realm.get_data_length()), 
						server_issuer_realm.get_data_length(),
						server_issuer_realm.get_data_length());

					if (client_subject_ptr.Length() == 0
						|| (server_subject_ptr.Find(client_subject_ptr) == KErrNotFound
						&& server_issuer_ptr.Find(client_subject_ptr) == KErrNotFound))
					{
						// still not ok	
								
						// One more test: subdomain matching with manual realm
						if (manual_client_subject_realm.get_is_valid_data() == true)
						{	
							TPtr8 manual_client_subject_ptr(
								manual_client_subject_realm.get_data(manual_client_subject_realm.get_data_length()), 
								manual_client_subject_realm.get_data_length(),
								manual_client_subject_realm.get_data_length());

							if (manual_client_subject_ptr.Length() == 0
								|| (server_subject_ptr.Find(manual_client_subject_ptr) == KErrNotFound
								&& server_issuer_ptr.Find(manual_client_subject_ptr) == KErrNotFound))
							{
								EAP_TRACE_ERROR(
									m_am_tools,
									TRACE_FLAGS_DEFAULT,
									(EAPL("ERROR: EAP-TLS: Client and server realms do not match.\n")));

								send_error_notification(eap_status_realm_check_failed);

								User::Leave(KErrArgument);
							}
						}
						else
						{
							EAP_TRACE_ERROR(
								m_am_tools,
								TRACE_FLAGS_DEFAULT,
								(EAPL("ERROR: EAP-TLS: Client and server realms do not match.\n")));

							send_error_notification(eap_status_realm_check_failed);

							User::Leave(KErrArgument);
						}
					}
				}	
				else
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: EAP-TLS: Client and server realms do not match.\n")));				

					send_error_notification(eap_status_realm_check_failed);

					User::Leave(KErrArgument);
				}
			}
		}
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Server certificate realm verification OK.\n")));
	}

	HBufC8* chain = HBufC8::NewL(0);
	HBufC8* temp;
	eap_variable_data_c* cert;
	
	for (u32_t i = 0; i < certificate_chain->get_object_count(); i++)
	{
		cert = certificate_chain->get_object(i);

		if( cert == NULL )
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: EAP-TLS: Problem in certificate_chain\n")));		
				
			User::Leave(KErrArgument);		
		}
	
#if defined(_DEBUG) || defined(DEBUG)

		TPtr8 certPtr(
			cert->get_data(cert->get_data_length()), 
			cert->get_data_length(),
			cert->get_data_length());
		CX509Certificate* x509Cert = CX509Certificate::NewL(certPtr);

		if( x509Cert != NULL )
		{				
			CleanupStack::PushL(x509Cert);

			TKeyIdentifier KeyIdentifier = x509Cert->KeyIdentifierL();
			
			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Key identifier is"),
				KeyIdentifier.Ptr(),
				KeyIdentifier.Size()));
								
			// This is for subject key id.
			const CX509CertExtension* certExt = x509Cert->Extension(KSubjectKeyId);
			
			if (certExt)
			{
				const CX509SubjectKeyIdExt* subKeyExt = CX509SubjectKeyIdExt::NewLC(certExt->Data());
				EAP_UNREFERENCED_PARAMETER(subKeyExt);

				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("The Subject key Id is:"),
					subKeyExt->KeyId().Ptr(),
					subKeyExt->KeyId().Size()));					
				
				CleanupStack::PopAndDestroy(); // subKeyExt					
			}
			else
			{
				EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: verify_certificate_chainL - No extension for this certificate\n")));			
			}
			
			CleanupStack::PopAndDestroy(x509Cert);
		}

#endif

		CleanupStack::PushL(chain);
		temp = chain->ReAllocL(chain->Length() + cert->get_data_length());
		chain = temp;
		TPtr8 ptr = chain->Des();
		ptr.Append(cert->get_data(cert->get_data_length()), cert->get_data_length());
		if (i == 0)
		{
			// This is the peer certificate. Save it.
			if (m_peer_certificate != 0)
			{
				delete m_peer_certificate;
			}
			m_peer_certificate = CX509Certificate::NewL(ptr);
		}
		CleanupStack::Pop();
	}
	CleanupStack::PushL(chain);
	TPtr8 certChain = chain->Des();
	m_cert_if->ValidateChainL(certChain, m_allowed_ca_certs);
	
	CleanupStack::PopAndDestroy();
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	// This returns eap_status_pending_request
	User::Leave(KErrCompletion);

}


void eap_am_type_tls_peap_symbian_c::complete_validate_chain(
	CPKIXValidationResult& aValidationResult, eap_status_e aStatus)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	if(aStatus != eap_status_ok)
	{
		get_tls_am_partner()->complete_verify_certificate_chain(aStatus);
		return;
	}
	
	eap_status_e result;	
	if (aValidationResult.Error().iReason == EValidatedOK) 
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, 
			(EAPL("Certificate chain validation OK. Reason: %d\n"), 
			aValidationResult.Error().iReason));
		result = eap_status_ok;
	}
	else
	{
		if (aValidationResult.Error().iReason == EDateOutOfRange)
		{
			send_error_notification(eap_status_certificate_expired);
			// Ignore error on purpose
		}
		else
		{
			send_error_notification(eap_status_illegal_certificate);
			// Ignore error on purpose			
		}

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: Certificate chain validation FAILED. Reason: %d\n"), 
			aValidationResult.Error().iReason));
			
		result = eap_status_illegal_certificate;
	}

	// Copy the public key
	const CSubjectPublicKeyInfo& publicKey = m_peer_certificate->PublicKey();
	TPtrC8 ptr = publicKey.KeyData();			
	m_peer_public_key.reset();
	eap_status_e status = m_peer_public_key.set_copy_of_buffer(ptr.Ptr(), ptr.Length());
	if (status != eap_status_ok)
	{		
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: complete_validate_chain: could not allocate memory.")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return;
	}

	get_tls_am_partner()->complete_verify_certificate_chain(result);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

#if defined(USE_FAST_EAP_TYPE)
#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)
eap_status_e eap_am_type_tls_peap_symbian_c::ReadFileConfig()
    {
        eap_status_e status = eap_status_ok;
        
        eap_am_file_input_symbian_c * const fileio = new eap_am_file_input_symbian_c(m_am_tools);

        eap_automatic_variable_c<eap_am_file_input_symbian_c> automatic_fileio(m_am_tools, fileio);

        if (fileio != 0
            && fileio->get_is_valid() == true)
        {
            EAP_TRACE_DEBUG(
                m_am_tools,
                TRACE_FLAGS_DEFAULT,
                (EAPL("Initialize file configuration.\n")));

            eap_variable_data_c file_name_c_data(m_am_tools);

             {
                #if defined(EAPOL_SYMBIAN_VERSION_7_0_s)
                    eap_const_string const FILECONFIG_FILENAME_C
                        = "c:\\system\\data\\eap.conf";
                #else
                    eap_const_string const FILECONFIG_FILENAME_C
                        = "c:\\private\\101F8EC5\\eap.conf";
                #endif

                status = file_name_c_data.set_copy_of_buffer(
                    FILECONFIG_FILENAME_C,
                    m_am_tools->strlen(FILECONFIG_FILENAME_C));
                if (status != eap_status_ok)
                {
                    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                    return EAP_STATUS_RETURN(m_am_tools, status);
                }

                status = file_name_c_data.add_end_null();
                if (status != eap_status_ok)
                {
                    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                    return EAP_STATUS_RETURN(m_am_tools, status);
                }
            }

            eap_variable_data_c file_name_z_data(m_am_tools);

            {
                #if defined(EAPOL_SYMBIAN_VERSION_7_0_s)
                    eap_const_string const FILECONFIG_FILENAME_Z
                        = "z:\\system\\data\\eap.conf";
                #else
                    eap_const_string const FILECONFIG_FILENAME_Z
                        = "z:\\private\\101F8EC5\\eap.conf";
                #endif

                status = file_name_z_data.set_copy_of_buffer(
                    FILECONFIG_FILENAME_Z,
                    m_am_tools->strlen(FILECONFIG_FILENAME_Z));
                if (status != eap_status_ok)
                {
                    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                    return EAP_STATUS_RETURN(m_am_tools, status);
                }

                status = file_name_z_data.add_end_null();
                if (status != eap_status_ok)
                {
                    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                    return EAP_STATUS_RETURN(m_am_tools, status);
                }
            }



            if (status == eap_status_ok)
            {
                // First try open from C: disk.
                status = fileio->file_open(
                    &file_name_c_data,
                    eap_file_io_direction_read);
                if (status == eap_status_ok)
                {
                    EAP_TRACE_DEBUG(
                        m_am_tools,
                        TRACE_FLAGS_DEFAULT,
                        (EAPL("Opens configure file %s\n"),
                        file_name_c_data.get_data(file_name_c_data.get_data_length())));
                }
                else if (status != eap_status_ok)
                {
                    // Second try open from Z: disk.
                    status = fileio->file_open(
                        &file_name_z_data,
                        eap_file_io_direction_read);
                    if (status == eap_status_ok)
                    {
                        EAP_TRACE_DEBUG(
                            m_am_tools,
                            TRACE_FLAGS_DEFAULT,
                            (EAPL("Opens configure file %s\n"),
                             file_name_z_data.get_data(file_name_z_data.get_data_length())));
                    }
                }

                if (status == eap_status_ok)
                {
                    // Some of the files were opened.

                    m_fileconfig = new eap_file_config_c(m_am_tools);
                    if (m_fileconfig != 0
                        && m_fileconfig->get_is_valid() == true)
                    {
                        status = m_fileconfig->configure(fileio);
                        if (status != eap_status_ok)
                        {
                            EAP_TRACE_DEBUG(
                                m_am_tools,
                                TRACE_FLAGS_DEFAULT,
                                (EAPL("ERROR: Configure read from %s failed.\n"),
                                file_name_c_data.get_data(file_name_c_data.get_data_length())));
                        }
                        else
                        {
                            EAP_TRACE_DEBUG(
                                m_am_tools,
                                TRACE_FLAGS_DEFAULT,
                                (EAPL("Configure read from %s\n"),
                                file_name_c_data.get_data(file_name_c_data.get_data_length())));
                        }
                    }
                    else
                    {
                        // No file configuration.
                        delete m_fileconfig;
                        m_fileconfig = 0;

                        EAP_TRACE_DEBUG(
                            m_am_tools,
                            TRACE_FLAGS_DEFAULT,
                            (EAPL("ERROR: Cannot create configure object for file %s\n"),
                            file_name_c_data.get_data(file_name_c_data.get_data_length())));
                    }
                }
                else
                {
                    EAP_TRACE_DEBUG(
                        m_am_tools,
                        TRACE_FLAGS_DEFAULT,
                        (EAPL("ERROR: Cannot open configure file neither %s nor %s\n"),
                        file_name_c_data.get_data(file_name_c_data.get_data_length()),
                        file_name_z_data.get_data(file_name_z_data.get_data_length())));
                }
            }
        }
        else
        {
            EAP_TRACE_DEBUG(
                m_am_tools,
                TRACE_FLAGS_DEFAULT,
                (EAPL("Skips file configuration.\n")));
        }

    eap_variable_data_c skip_user_interactions(m_am_tools);

    if (m_fileconfig != 0
            && m_fileconfig->get_is_valid() == true)
        {
            // Here we could try the final configuration option.
            status = m_fileconfig->read_configure(
                    cf_str_EAP_skip_user_interactions_for_testing_purposes.get_field(),
                    &skip_user_interactions);
        }

    if (status == eap_status_ok
        && skip_user_interactions.get_is_valid_data() == true)
    {
        u32_t *skip_user_interactions_flag = reinterpret_cast<u32_t *>(
            skip_user_interactions.get_data(sizeof(u32_t)));
        if (skip_user_interactions_flag != 0)
        {
            if (*skip_user_interactions_flag != 0)
            {
                m_skip_user_interactions = true;
            }
            else
            {
                m_skip_user_interactions = false;
            }
        }
    }

    iPacStoreDb->SkipUserActions (m_skip_user_interactions);        
    
     return status;
    }
#endif //#if defined(USE_EAP_CONFIGURATION_TO_SKIP_USER_INTERACTIONS)
#endif


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::query_certificate_chain(
	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const certificate_authorities,
	EAP_TEMPLATE_CONST eap_array_c<u8_t> * const certificate_types,
	const tls_cipher_suites_e required_cipher_suite)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_is_client)
	{
		m_cipher_suite = required_cipher_suite;
	}

	eap_status_e status(eap_status_pending_request);
	m_state = EHandlingChainQuery;
	TInt err(KErrNone);

	if (m_is_client)
	{
		// Get the matching certificates
		TRAPD(err, m_cert_if->GetMatchingCertificatesL(
			m_allowed_user_certs, 
			ETrue, 
			certificate_authorities, 
			ETrue, 
			certificate_types, 
			ETrue, 
			m_allowed_cipher_suites));
	
		(void)EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
	}
	else
	{
		// server
		TRAPD(err, m_cert_if->GetMatchingCertificatesL(
				m_allowed_user_certs, 
				EFalse, 
				0, 
				EFalse, 
				0, 
				ETrue, 
				m_allowed_cipher_suites));

		if (err != KErrNone)
		{
			status = m_am_tools->convert_am_error_to_eapol_error(err);
		}		
	}

	if (err == KErrNone)
	{
		status = eap_status_pending_request;
	} 
	else
	{	
		// Convert the leave error code to EAPOL stack error code.
		status = m_am_tools->convert_am_error_to_eapol_error(err);
	}	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);

}

void eap_am_type_tls_peap_symbian_c::complete_get_matching_certificates(
	CArrayFixFlat<SCertEntry>& aMatchingCerts,
	eap_status_e aStatus)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(aStatus);

	EAP_TRACE_DEBUG(m_am_tools, 
	TRACE_FLAGS_DEFAULT, 
	(EAPL("eap_am_type_tls_peap_symbian_c::complete_get_matching_certificates-Matching cert count after possible cert removal=%d, m_state=%d, aStatus=%d\n"),
	aMatchingCerts.Count(), m_state, aStatus));
	
	if (m_state == EHandlingIdentityQuery)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_tls_peap_symbian_c::complete_get_matching_certificates(): EHandlingIdentityQuery\n")));

		// Add found certs to allowed certificate list.
		// This list is updated here because there might be certificates that have been removed.
		m_allowed_user_certs.Reset();
		for (TInt i = 0; i < aMatchingCerts.Count(); i++)
		{
			TRAPD(err, m_allowed_user_certs.AppendL(aMatchingCerts[i]));
			if (err != KErrNone)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: eap_am_type_tls_peap_symbian_c::complete_get_matching_certificates -EHandlingIdentityQuery- Error=%d\n"),
					err));
			
				get_am_partner()->complete_eap_identity_query(
					0, // 0 because identity query failed
					&m_receive_network_id,
					m_eap_identifier,
					eap_status_allocation_error, 
					false, 
					0, 
					false, 
					0);
				
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				return;		
			}
		}

		if (m_allowed_user_certs.Count() == 0)
		{
			// No allowed user certificates. 
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("EAP-TLS: No allowed user certificates configured.\n")));
			
			if (m_tls_peap_server_authenticates_client_policy_flag == true)
			{
                // Certificate is really required
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: EAP-TLS: Could not find proper user certificate.\n")));

				send_error_notification(eap_status_user_certificate_unknown);

				get_am_partner()->complete_eap_identity_query(
					0, // 0 because identity query failed
					&m_receive_network_id,
					m_eap_identifier,
					eap_status_illegal_certificate, 
					false, 
					0, 
					false, 
					0);		
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return;
			}

			if (m_use_manual_realm == false)
			{
				// Since there is no user certificate or manual realm configured
				// the realm needs to be dig out from the CA certificate.
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_am_type_tls_peap_symbian_c: no manual realm - no user cert. Get realm from CA certificate.\n")));
				
				TInt allowed_ca_cert_count = m_allowed_ca_certs.Count();
				TInt err(KErrNone);
				
				if(allowed_ca_cert_count > 0)
				{
					TRAP(err, m_cert_if->ReadCACertificateL(m_allowed_ca_certs[0]));
				}
				if (err != KErrNone || allowed_ca_cert_count <= 0)
				{
					EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: EAP-TLS: Cannot read user certificate or No CA cert configured, CA cert count=%d.\n"),
					allowed_ca_cert_count));

					get_am_partner()->complete_eap_identity_query(
						0, // 0 because identity query failed
						&m_receive_network_id,
						m_eap_identifier,
						eap_status_illegal_certificate, 
						false, 
						0, 
						false, 
						0);
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return;	
				}
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return;
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAP-TLS: Uses manual realm.\n")));

				get_am_partner()->complete_eap_identity_query(
						0, // 0 because certificate query failed
						&m_receive_network_id,
						m_eap_identifier,
						eap_status_ok, 
						m_use_manual_username, 
						&m_manual_username, 
						m_use_manual_realm, 
						&m_manual_realm);

			}
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return;
		}
							
		// Just complete (this selects the first certificate in the array)
		m_selector_output.SetLength(0);
		TRequestStatus* reqStatus = &iStatus;
		User::RequestComplete(reqStatus, KErrNone);		
		SetActive();
	}
	else if (m_state == EHandlingChainQuery)
	{
		
		if (aMatchingCerts.Count() > 0)
		{
				m_allowed_user_certs.Reset();
			
				for (TInt i = 0; i < aMatchingCerts.Count(); i++)
				{
					TRAPD(err, m_allowed_user_certs.AppendL(aMatchingCerts[i]));
					if (err != KErrNone)
					{
						EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_tls_peap_symbian_c::complete_get_matching_certificates -EHandlingChainQuery- Error=%d\n"),
						err));
									
						get_tls_am_partner()->complete_query_certificate_chain(0, eap_status_allocation_error);
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);		
						return;					
					} 
			}	
		}

		if (m_allowed_user_certs.Count() == 0)
		{
			// No matching or allowed certs and no pre-loaded cert.
			// Could not find matching certificate

			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("EAP-TLS: Could not find proper user certificate.\n")));

			if (m_tls_peap_server_authenticates_client_policy_flag == true)
			{
				send_error_notification(eap_status_user_certificate_unknown);
			}

			get_tls_am_partner()->complete_query_certificate_chain(0, eap_status_illegal_certificate);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);		
			return;
		}

		// We got at least one allowed user cert. 
		// Just use the first allowed certificate
		// Don't ask user. Just complete (this selects the first certificate in the array)
		m_selector_output.SetLength(0);
		TRequestStatus* reqStatus = &iStatus;
		User::RequestComplete(reqStatus, KErrNone);
		SetActive();
		
	}
	else
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("EAP-TLS: Illegal state in complete_get_matching_certs.\n")));
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return;
}


EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::query_certificate_authorities_and_types()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: %s: message_function: query_certificate_authorities_and_types()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_ASSERT_ALWAYS(!m_is_client);

	eap_status_e status;
	eap_array_c<eap_variable_data_c> certificate_authorities(m_am_tools);
	eap_variable_data_c ca_dn(m_am_tools);
	
	// TEST CODE: This is not a proper CA DN.
	_LIT8(KTestCA, "ca.eapsim.foo");
	status = ca_dn.add_data(KTestCA().Ptr(), KTestCA().Size());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = certificate_authorities.add_object(&ca_dn, false);	
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	eap_array_c<u8_t> certificate_types(m_am_tools);

	{
		u8_t * const dummy_certificate_type = new u8_t;
		if (dummy_certificate_type == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		*dummy_certificate_type = tls_certificate_type_rsa_sign;

		status = certificate_types.add_object(dummy_certificate_type, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	{
		u8_t * const dummy_certificate_type = new u8_t;
		if (dummy_certificate_type == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		*dummy_certificate_type = tls_certificate_type_dss_sign;

		status = certificate_types.add_object(dummy_certificate_type, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	status = get_tls_am_partner()->complete_query_certificate_authorities_and_types(
		&certificate_authorities,
		&certificate_types,
		eap_status_ok);
	if (status == eap_status_ok ||
		status == eap_status_pending_request)
	{
		status = eap_status_completed_request;
	}	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::query_dh_parameters(
	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const /*certificate_chain*/,
	const tls_cipher_suites_e required_cipher_suite)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: %s: message_function: query_dh_parameters()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status = eap_status_process_general_error;

	if (required_cipher_suite != m_cipher_suite)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_cipher_suite);
	}

	if (EapTlsPeapUtils::CipherSuiteIsEphemeralDHKeyExchange(m_cipher_suite))
	{
		eap_variable_data_c dhe_prime(m_am_tools);
		status = dhe_prime.set_copy_of_buffer(SAE_GROUP_PRIME, SAE_GROUP_PRIME_LENGTH); 
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	
		eap_variable_data_c dhe_group_generator(m_am_tools);
	
		status = dhe_group_generator.set_copy_of_buffer(SAE_GROUP_GENERATOR, SAE_GROUP_GENERATOR_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = get_tls_am_partner()->complete_query_dh_parameters(
			&dhe_prime, 
			&dhe_group_generator, 
			eap_status_ok);
	} 
	else 
	{
		status = eap_status_not_supported;
	}
	
	if (status == eap_status_ok ||
		status == eap_status_pending_request)		
	{
		status = eap_status_completed_request;
	}	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::query_realm(
	EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const /*certificate_chain*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

eap_status_e eap_am_type_tls_peap_symbian_c::get_realms_from_certificate(
	CX509Certificate* certificate,
	eap_variable_data_c * const subject_realm,
	eap_variable_data_c * const issuer_realm)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_process_general_error);
	_LIT8(KAt, "@");
	eap_variable_data_c subject_identity(m_am_tools);
	eap_variable_data_c issuer_identity(m_am_tools);

	TInt offset = KErrNotFound;

	// SUBJECT
	// Try alternative name first
	TRAPD(err, get_identity_from_alternative_nameL(certificate, &subject_identity));
	if (err == KErrNone)
	{
		// Parse realm from identity
		TPtr8 ptr(
			subject_identity.get_data(subject_identity.get_data_length()), 
			subject_identity.get_data_length(),
			subject_identity.get_data_length());		
		
		offset = ptr.Find(KAt);		
	}

	if (offset == KErrNotFound)
	{
		// Check DN
		TRAPD(err, get_identities_from_distinguished_namesL(certificate, &subject_identity, &issuer_identity));	
		if (err != KErrNone)
		{
			EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: EAP-TLS: Could not find realm from certificate.\n")));
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_certificate);
		}

		// Parse realm from identity
		TPtr8 ptr(
			subject_identity.get_data(subject_identity.get_data_length()), 
			subject_identity.get_data_length(),
			subject_identity.get_data_length());		
		offset = ptr.Find(KAt);	
		// Don't worry if @ is not found. Then just use the whole CN as realm. 
		// It probably is the realm in CA certificates.
	}
	
	TPtr8 ptr(
		subject_identity.get_data(subject_identity.get_data_length()), 
		subject_identity.get_data_length(),
		subject_identity.get_data_length());		

	status = subject_realm->set_copy_of_buffer((ptr.Mid(offset + 1)).Ptr(), ptr.Length() - offset - 1);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}	
	
	// ISSUER
	// Check DN
	TRAP(err, get_identities_from_distinguished_namesL(certificate, &subject_identity, &issuer_identity));	
	if (err != KErrNone)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: EAP-TLS: Could not find realm from certificate.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_certificate);
	}

	// Parse realm from identity
	TPtr8 ptr2(
		issuer_identity.get_data(issuer_identity.get_data_length()), 
		issuer_identity.get_data_length(),
		issuer_identity.get_data_length());		
		
	offset = ptr2.Find(KAt);

	status = issuer_realm->set_copy_of_buffer((ptr2.Mid(offset + 1)).Ptr(), ptr2.Length() - offset - 1);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------


EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::save_tls_session(
	const eap_variable_data_c * const session_id,
	const eap_variable_data_c * const master_secret,
	const tls_cipher_suites_e used_cipher_suite
#if defined(USE_EAP_TLS_SESSION_TICKET)
	, const tls_extension_c * const new_session_ticket
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_ok;

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: %s: save_tls_session()\n"),
		(m_is_client == true ? "client": "server")));

	// Save current session.
	if (session_id != 0 
		&& session_id->get_is_valid_data() == true
		&& master_secret != 0 
		&& master_secret->get_is_valid_data() == true)
	{	
		// Send error if any of the parameters are too long.
		if(session_id->get_data_length() > KMaxSessionIdLengthInDB 
			|| master_secret->get_data_length() > KMaxMasterSecretLengthInDB)
		{
			// Some of the parameters are too long. Can't store them in DB.
			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_type_tls_peap_symbian_c::save_tls_session: ")
				 EAPL("Too long parameters. Length: session_id=%d, master_secret=%d \n"),
				 session_id->get_data_length(), master_secret->get_data_length()));
			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}
	
		{			
			TRAPD(err, WriteBinaryParamL(
				cf_str_EAP_TLS_PEAP_saved_session_id.get_field()->get_field(),
				cf_str_EAP_TLS_PEAP_saved_session_id.get_field()->get_field_length(),
				session_id));
			if (err != KErrNone)
			{
				// Convert the leave error code to EAPOL stack error code.
				status = m_am_tools->convert_am_error_to_eapol_error(err);
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		{
			TRAPD(err, WriteBinaryParamL(
				cf_str_EAP_TLS_PEAP_saved_master_secret.get_field()->get_field(),
				cf_str_EAP_TLS_PEAP_saved_master_secret.get_field()->get_field_length(),
				master_secret));
			if (err != KErrNone)
			{
				// Convert the leave error code to EAPOL stack error code.
				status = m_am_tools->convert_am_error_to_eapol_error(err);
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		{
			TRAPD(err, WriteIntParamL(
				cf_str_EAP_TLS_PEAP_saved_cipher_suite.get_field()->get_field(),
				cf_str_EAP_TLS_PEAP_saved_cipher_suite.get_field()->get_field_length(),
				used_cipher_suite));
			if (err != KErrNone)
			{
				// Convert the leave error code to EAPOL stack error code.
				status = m_am_tools->convert_am_error_to_eapol_error(err);
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}		
	}

#if defined(USE_EAP_TLS_SESSION_TICKET)
	if (m_use_session_ticket == true
		&& new_session_ticket != 0)
	{
		// Save new session ticket.
	}
#endif //#if defined(USE_EAP_TLS_SESSION_TICKET)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::rsa_encrypt_with_public_key(
	const eap_variable_data_c * const premaster_secret)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: %s: message_function: rsa_encrypt_with_public_key()\n"),
		(m_is_client == true ? "client": "server")));	

	if (m_peer_public_key.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, (EAPL("TLS: rsa_encrypt_with_public_key() m_peer_public_key"),
		   m_peer_public_key.get_data(m_peer_public_key.get_data_length()),
		   m_peer_public_key.get_data_length()));


	crypto_rsa_c rsa(m_am_tools);

	eap_variable_data_c encrypted_premaster_secret(m_am_tools);

	eap_status_e status = rsa.encrypt_with_public_key(
		&m_peer_public_key, 
		premaster_secret, 
		&encrypted_premaster_secret);

	status = get_tls_am_partner()->complete_rsa_encrypt_with_public_key(
		&encrypted_premaster_secret, 
		eap_status_ok);
	if (status == eap_status_ok
		|| status == eap_status_pending_request)
	{
		status = eap_status_completed_request;
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::rsa_decrypt_with_private_key(
	const eap_variable_data_c * const encrypted_premaster_secret)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: %s: message_function: rsa_decrypt_with_private_key()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_pending_request);
	if (m_own_certificate == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	HBufC8* data = 0;

	TRAPD(err, data = HBufC8::NewL(encrypted_premaster_secret->get_data_length()));
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	TPtr8 ptr = data->Des();

	ptr.Copy(encrypted_premaster_secret->get_data(encrypted_premaster_secret->get_data_length()), 
		encrypted_premaster_secret->get_data_length());

	TRAP(err, m_cert_if->DecryptL(m_own_certificate_info.iSubjectKeyId, *data));

	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
	}
	else
	{
		status = eap_status_pending_request;
	}

	delete data;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_type_tls_peap_symbian_c::complete_decrypt(TDes8& aData, eap_status_e aStatus)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (aStatus != eap_status_ok)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: eap_am_type_tls_peap_symbian_c::complete_decrypt, aStatus=%d\n"),
		aStatus));
		
		get_tls_am_partner()->complete_rsa_decrypt_with_private_key(0, aStatus);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	if (aData.Length() == 0)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Decrypt with private key failed.\n")));
		get_tls_am_partner()->complete_rsa_decrypt_with_private_key(0, eap_status_decryption_failure);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	eap_variable_data_c decrypted_data(m_am_tools);
	eap_status_e status = decrypted_data.set_copy_of_buffer(aData.Ptr(), aData.Length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: rsa_decrypt_with_private_key() decrypted data"),
		 decrypted_data.get_data(decrypted_data.get_data_length()),
		 decrypted_data.get_data_length()));

	status = get_tls_am_partner()->complete_rsa_decrypt_with_private_key(&decrypted_data, eap_status_ok);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::sign_with_private_key(
	const eap_variable_data_c * const message_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: %s: message_function: sign_with_private_key()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_pending_request);
	if (m_own_certificate == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: sign_with_private_key() message_hash"),
		 message_hash->get_data(message_hash->get_data_length()),
		 message_hash->get_data_length()));


	HBufC8* buf = 0;
	TRAPD(err, buf = HBufC8::NewL(message_hash->get_data_length()))
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	TPtr8 hash = buf->Des();

	hash.Copy(message_hash->get_data(message_hash->get_data_length()), message_hash->get_data_length());


	// Calculate the signature length based on algorithm and public key lenght
	TUint signature_length(0);

	const CSubjectPublicKeyInfo& public_key = m_own_certificate->PublicKey();
	
	if (public_key.AlgorithmId() == EDSA)
	{
		// DSA signatures are always 40 bytes (320 bits)
		signature_length = KDSASignatureLength;
	}
	else
	{
		// RSA signature is the same length as public key.
		TPtrC8 public_key_data = public_key.KeyData();
		
		// public_key_data actually has the asn.1 header so it is a few bytes longer
		// than the actual signature.
		signature_length = public_key_data.Size();
	}

	TRAP(err, m_cert_if->SignL(m_own_certificate_info.iSubjectKeyId, hash, signature_length));
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
	}
	else
	{
		status = eap_status_pending_request;
	}	
	
	delete buf;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
		
}
//--------------------------------------------------
void eap_am_type_tls_peap_symbian_c::complete_sign(
	const RInteger& aR, const RInteger& aS, eap_status_e aStatus)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if(aStatus != eap_status_ok)
	{
		get_tls_am_partner()->complete_sign_with_private_key(0, aStatus);
		return;
	}
	
	TRAPD(err, complete_signL(aR, aS, eap_status_ok));
	if (err != KErrNone)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: complete_signL leaved.\n")));
		get_tls_am_partner()->complete_sign_with_private_key(0, m_am_tools->convert_am_error_to_eapol_error(err));
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

void eap_am_type_tls_peap_symbian_c::complete_signL(
	const RInteger& aR, const RInteger& aS, eap_status_e aStatus)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	if(aStatus != eap_status_ok)
	{
		get_tls_am_partner()->complete_sign_with_private_key(0, aStatus);
		return;
	}
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AM: Signing completed.\n")));	

	eap_variable_data_c signed_message_hash(m_am_tools);
	eap_status_e status(eap_status_process_general_error);

	if (EapTlsPeapUtils::CipherSuiteUseDSAKeys(m_cipher_suite))
	{		
		CASN1EncSequence* sequence = CASN1EncSequence::NewLC();
		CASN1EncBigInt* enc_r = CASN1EncBigInt::NewLC(aR);
		CASN1EncBigInt* enc_s = CASN1EncBigInt::NewLC(aS);
		sequence->AddChildL(enc_r);
		sequence->AddChildL(enc_s);
		
		HBufC8* buf = HBufC8::NewLC(sequence->LengthDER());
		TPtr8 tmp = buf->Des();

		tmp.SetLength(sequence->LengthDER());
		TInt pos = 0;
		sequence->WriteDERL(tmp, (TUint&) pos);

		status = signed_message_hash.set_copy_of_buffer(tmp.Ptr(), tmp.Length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}

		CleanupStack::PopAndDestroy(); // buf
		CleanupStack::Pop(2);		// BigInts are deleted by the sequence
		CleanupStack::PopAndDestroy(1); // Sequence
	}
	else if (EapTlsPeapUtils::CipherSuiteUseRSAKeys(m_cipher_suite))
	{
		HBufC8* buf = aS.BufferLC();
		
		// RSA signing. Just use the data as it is.		
		eap_status_e status = signed_message_hash.set_copy_of_buffer(buf->Ptr(), buf->Length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			User::Leave(KErrNoMemory);
		}
		CleanupStack::PopAndDestroy(); // buf
	}
	else
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Unsupported cipher suite.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		User::Leave(KErrNotSupported);
	}
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: sign_with_private_key() signed_message_hash"),
		 signed_message_hash.get_data(signed_message_hash.get_data_length()),
		 signed_message_hash.get_data_length()));

	status = get_tls_am_partner()->complete_sign_with_private_key(
		&signed_message_hash, 
		eap_status_ok);

	// Ignore return value on purpose
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::verify_with_public_key(
	const eap_variable_data_c * const message_hash,
	const eap_variable_data_c * const signed_message_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("TLS: %s: message_function: verify_with_public_key()\n"),
		(m_is_client == true ? "client": "server")));

	if (m_peer_public_key.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: verify_with_public_key() m_peer_public_key"),
		 m_peer_public_key.get_data(m_peer_public_key.get_data_length()),
		 m_peer_public_key.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: verify_with_public_key() message_hash"),
		 message_hash->get_data(message_hash->get_data_length()),
		 message_hash->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: verify_with_public_key() signed_message_hash"),
		 signed_message_hash->get_data(signed_message_hash->get_data_length()),
		 signed_message_hash->get_data_length()));

	eap_status_e status = eap_status_process_general_error;

	if (EapTlsPeapUtils::CipherSuiteUseDSAKeys(m_cipher_suite))
	{
		TRAPD(err, read_dsa_parametersL());
		if (err != KErrNone)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
		}
		crypto_dsa_c dsa(m_am_tools);

		status = dsa.init();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = dsa.verify(
			&m_peer_public_key,
			&m_param_p,
			&m_param_q,
			&m_param_g,
			message_hash,
			signed_message_hash);
	}
	else if (EapTlsPeapUtils::CipherSuiteUseRSAKeys(m_cipher_suite))
	{
		crypto_rsa_c rsa(m_am_tools);

		status = rsa.init();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = rsa.verify(
			&m_peer_public_key,
			message_hash,
			signed_message_hash);
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: Signing with private key failed.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	}

	status = get_tls_am_partner()->complete_verify_with_public_key(status); 

	if (status == eap_status_ok
		|| status == eap_status_pending_request)
	{
		status = eap_status_completed_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

void eap_am_type_tls_peap_symbian_c::read_dsa_parametersL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT); 
	if (m_peer_certificate == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		User::Leave(KErrArgument);
	}
	// Peer cert is the first one
	const CSubjectPublicKeyInfo& key = m_peer_certificate->PublicKey();
	const TPtrC8 params = key.EncodedParams();
	
	CDSAParameters* dsaParams = CX509DSAPublicKey::DSAParametersL(params);

	CleanupStack::PushL(dsaParams);
	
	RInteger P = RInteger::NewL(dsaParams->P());
	CleanupStack::PushL(P);
	RInteger Q = RInteger::NewL(dsaParams->Q());
	CleanupStack::PushL(Q);
	RInteger G = RInteger::NewL(dsaParams->G());
	CleanupStack::PushL(G);
	
	HBufC8* buf = P.BufferLC();
	
	// Copy the shared key
	m_param_p.reset();
	eap_status_e status = m_param_p.set_copy_of_buffer(buf->Des().Ptr(), buf->Length());
	if (status != eap_status_ok)
	{
		User::Leave(KErrNoMemory);
	}

	buf = Q.BufferLC();
	m_param_q.reset();
	status = m_param_q.set_copy_of_buffer(buf->Des().Ptr(), buf->Length());
	if (status != eap_status_ok)
	{
		User::Leave(KErrNoMemory);
	}
	
	buf = G.BufferLC();
	m_param_g.reset();
	status = m_param_g.set_copy_of_buffer(buf->Des().Ptr(), buf->Length());
	if (status != eap_status_ok)
	{
		User::Leave(KErrNoMemory);
	}

	CleanupStack::PopAndDestroy(7);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------
// MODULE HANDLING FUNCTIONS
//--------------------------------------------------
eap_status_e eap_am_type_tls_peap_symbian_c::load_module(
		const eap_type_value_e /*type*/,
		const eap_type_value_e /* tunneling_type */,
		abs_eap_base_type_c * const /*partner*/,
		eap_base_type_c ** const /*eap_type_if*/,
		const bool /*is_client_when_true*/,
		const eap_am_network_id_c * const /*receive_network_id*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

eap_status_e eap_am_type_tls_peap_symbian_c::check_is_valid_eap_type(const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	eap_status_e status(eap_status_illegal_eap_type);
	
#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_tls_peap_symbian_c::check_is_valid_eap_type:Given EAP vendor ID=%x, type=%x\n"),
		eap_type.get_vendor_id(), eap_type.get_vendor_type()));	
		
	for (TInt i = 0; i < m_enabled_tunneling_exp_eap_array.Count(); i++)
	{
		eap_expanded_type_c expEAPTmp;
		
		// This will read the expanded EAP from enabledEAPTypes[i]->iExpandedEAPType to expEAPTmp.
		// This makes easy to get the vendor type.
		eap_expanded_type_c::read_type( m_am_tools,
										0,
										m_enabled_tunneling_exp_eap_array[i]->iExpandedEAPType.Ptr(),
										KExpandedEAPTypeSize,
										&expEAPTmp);
		
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("check_is_valid_eap_type:Checking with EAP type:"),
	 		m_enabled_tunneling_exp_eap_array[i]->iExpandedEAPType.Ptr(),
	 		m_enabled_tunneling_exp_eap_array[i]->iExpandedEAPType.Size()));	 			
		
		if (eap_type == expEAPTmp)
		{
			// This EAp type is one among the enabled ones. Hence a valid EAP type.
			status = eap_status_ok;
			break;			
		}
	}

#else // For normal EAP types.
	
	TEap *eapType = 0; 
	
	TInt i(0);
		
	for (i = 0; i < m_iap_eap_array.Count(); i++)
	{
		// Try next EAP type
		eapType = m_iap_eap_array[i];
		if (eapType->Enabled == 1)
		{	
			// Convert the string to integer
			TLex8 tmp(eapType->UID);
			TInt val(0);
			tmp.Val(val);
			if (val == eap_type)
			{
				// Allowed
				status = eap_status_ok;
				break;
			}	
		}
	}
	
#endif //#ifdef USE_EAP_EXPANDED_TYPES	
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_tls_peap_symbian_c::get_eap_type_list - Start\n")));	

	eap_status_e status(eap_status_illegal_eap_type);

#ifdef USE_EAP_EXPANDED_TYPES

	// We need to return only the EAP types available as enabled types.
	// It means only the ones available in m_enabled_tunneling_exp_eap_array.
	
	for (TInt i = 0; i < m_enabled_tunneling_exp_eap_array.Count(); i++)
	{	
		TBuf8<KExpandedEAPTypeSize> tmpExpEAP(m_enabled_tunneling_exp_eap_array[i]->iExpandedEAPType);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_am_type_tls_peap_symbian_c::get_eap_type_list:Enabled expanded EAP type at index=%d\n"),
			 i));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Enabled expanded EAP type:"),
			tmpExpEAP.Ptr(),
			tmpExpEAP.Size()));

		// This is for one expanded EAP type (for the above one).
		eap_type_value_e * expandedEAPType = new eap_type_value_e();
				
		// Read the expanded EAP type details from an item in m_enabled_tunneling_exp_eap_array.
		status = eap_type_value_e::read_type(m_am_tools,
												0,
												&tmpExpEAP,
												tmpExpEAP.Length(),
												expandedEAPType);
		if (status != eap_status_ok)
		{
			delete expandedEAPType;
			expandedEAPType = 0;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Add EAP-type to list.		
		status = eap_type_list->add_object(expandedEAPType, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}		
		
		eap_header_string_c eap_string;
		EAP_UNREFERENCED_PARAMETER(eap_string);
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("get_eap_type_list():added EAP-type=0x%08x=%s\n"),
			expandedEAPType->get_vendor_type(),
			eap_string.get_eap_type_string(*expandedEAPType)));			
	
	}// for()

#else // for normal EAP types.

	TEap *eapType = 0; 

	status = eap_type_list->reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (TInt i = 0; i < m_iap_eap_array.Count(); i++)
	{
		// Check if type is enabled
		eapType = m_iap_eap_array[i];
		if (eapType->Enabled == 1)
		{	
			TLex8 tmp(eapType->UID);
			TInt val(0);
			tmp.Val(val);

			eap_type_value_e * const eap_type = new eap_type_value_e(static_cast<eap_type_ietf_values_e>(val));
			if (eap_type == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = eap_type_list->add_object(eap_type, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	} // for()

#endif // #ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

eap_status_e eap_am_type_tls_peap_symbian_c::unload_module(const eap_type_value_e /*type*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}


void eap_am_type_tls_peap_symbian_c::send_error_notification(const eap_status_e error)
{
	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_tls_peap_symbian_c::send_error_notification, error=%d\n"),
		error));	

	eap_general_state_variable_e general_state_variable(eap_general_state_authentication_error);

	if (error == eap_status_user_cancel_authentication)
	{
		general_state_variable = eap_general_state_authentication_cancelled;
	}
	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		m_receive_network_id.get_destination_id(),
		m_receive_network_id.get_source_id(),
		m_receive_network_id.get_type());

	// Notifies the lower level of an authentication error.
	eap_state_notification_c notification(
		m_am_tools,
		&send_network_id,
		m_is_client,
		eap_state_notification_eap,
		eap_protocol_layer_general,
		m_current_eap_type,
		eap_state_none,
		general_state_variable,
		0,
		false);

	notification.set_authentication_error(error);

	m_partner->state_notification(&notification);
}

eap_status_e eap_am_type_tls_peap_symbian_c::show_certificate_selection_dialog()
{
	return eap_status_ok;
}

eap_status_e eap_am_type_tls_peap_symbian_c::show_manual_identity_dialog()
{
	return eap_status_ok;
}

//--------------------------------------------------
// CANCELLATION FUNCTIONS
//--------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_identity_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_identity_query()\n")));
	
	m_cert_if->Cancel(); 
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_query_cipher_suites_and_previous_session()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_query_cipher_suites_and_previous_session()\n")));

	// This is synchronous
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_select_cipher_suite_and_check_session_id()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_select_cipher_suite_and_check_session_id()\n")));

	// This is synchronous
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_verify_certificate_chain()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_verify_certificate_chain()\n")));

	m_cert_if->Cancel();
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_query_certificate_chain()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_query_certificate_chain()\n")));

	m_cert_if->Cancel();
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_query_certificate_authorities_and_types()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_query_certificate_authorities_and_types()\n")));

	// This is synchronous
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_query_dh_parameters()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_query_dh_parameters()\n")));

	// This is synchronous
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_query_dsa_parameters()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_query_dsa_parameters()\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_query_realm()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_query_realm()\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_rsa_encrypt_with_public_key()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_rsa_encrypt_with_public_key()\n")));

	// This is synchronous
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_rsa_decrypt_with_private_key()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_rsa_decrypt_with_private_key()\n")));

	m_cert_if->Cancel();
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_sign_with_private_key()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_sign_with_private_key()\n")));

	m_cert_if->CancelSignWithPrivateKey(); // Lets see if separate cancelling works.
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_sign_with_private_key() returns\n")));
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_verify_with_public_key()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_tls_peap_symbian_c::cancel_verify_with_public_key()\n")));

	// This is synchronous
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

bool eap_am_type_tls_peap_symbian_c::is_session_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	bool sessionValidity(false);
	
	TRAPD(err, sessionValidity = is_session_validL());
	if (err != KErrNone) 
	{
		EAP_TRACE_ERROR(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("eap_am_type_tls_peap_symbian_c::is_session_valid - LEAVE - error=%d, Assuming session is invalid \n"),
			err));
			
		sessionValidity = false;
	}
	 		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	return sessionValidity;
}

//--------------------------------------------------

bool eap_am_type_tls_peap_symbian_c::is_session_validL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, (
		EAPL("eap_am_type_tls_peap_symbian_c::is_session_valid - m_current_eap_vendor_type=%d \n"),
		m_current_eap_vendor_type));

	TPtrC maxSessionTimeString;
	TPtrC lastFullAuthTimeString;

	switch (m_current_eap_vendor_type)
	{
	case eap_type_tls:
		{
			maxSessionTimeString.Set(cf_str_EAP_TLS_max_session_validity_time_literal);
			lastFullAuthTimeString.Set(KTLSLastFullAuthTime);
		}
		break;

	case eap_type_peap:
		{
			maxSessionTimeString.Set(cf_str_EAP_PEAP_max_session_validity_time_literal);
			lastFullAuthTimeString.Set(KPEAPLastFullAuthTime);
		}
		break;
	
	case eap_type_ttls:
		{
			maxSessionTimeString.Set(cf_str_EAP_TTLS_max_session_validity_time_literal);
			lastFullAuthTimeString.Set(KTTLSLastFullAuthTime);
		}
		break;

#if defined(USE_FAST_EAP_TYPE)		
	case eap_type_fast:
		{
			maxSessionTimeString.Set(cf_str_EAP_FAST_max_session_validity_time_literal);
			lastFullAuthTimeString.Set(KFASTLastFullAuthTime);
		}
		break;
#endif
		
	case eap_type_ttls_plain_pap:
	    {
	        // we should not come here, ttls pap has its own
	        // method for checking session validity
	        EAP_TRACE_ERROR( m_am_tools, TRACE_FLAGS_DEFAULT, (
	            EAPL( "ERROR: wrong eap type.\n" ) ) );
	        return false;
	    }
	    
	default:
		{
			// Should never happen
			EAP_TRACE_ERROR(m_am_tools, 
				TRACE_FLAGS_DEFAULT, (
				EAPL("Unsupported EAP type, m_current_eap_vendor_type=%d \n"),
				m_current_eap_vendor_type));
				
			return false; // Treat this as Session invalid.
		}
	}	

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT(KSQLQuery, "SELECT %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLQuery, &maxSessionTimeString, &lastFullAuthTimeString, &m_db_table_name,
						&KServiceType, m_index_type, 
						&KServiceIndex, m_index, &KTunnelingType, m_tunneling_vendor_type);

	RDbView view;
	// Evaluate view
	User::LeaveIfError(view.Prepare(m_database, TDbQuery(sqlStatement)));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	// Get the first (and only) row
	view.FirstL();
	view.GetL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);
		
	TInt64 maxSessionTime = view.ColInt64(colSet->ColNo(maxSessionTimeString));
	TInt64 fullAuthTime = view.ColInt64(colSet->ColNo(lastFullAuthTimeString));

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	CleanupStack::PopAndDestroy(&view); // Close view.
	CleanupStack::PopAndDestroy(buf); // Delete buf.
	
	// If the max session time from DB is zero then we use the 
	// one read from configuration file.
	
	if( maxSessionTime == 0)
	{
		EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("Session Validity - Using max session validity time from config file\n")));
	
		maxSessionTime = m_max_session_time; // value from configuration file.
	}
	
	// Get the current time.
	TTime currentTime;
	currentTime.UniversalTime();
	
	TTime lastFullAuthTime(fullAuthTime);
	
#if defined(_DEBUG) || defined(DEBUG)	
	
	TDateTime currentDateTime = currentTime.DateTime();
		
	TDateTime fullAuthDateTime = lastFullAuthTime.DateTime();
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
	(EAPL("Session Validity - Current Time,        %2d-%2d-%4d : %2d-%2d-%2d-%d\n"), 
	currentDateTime.Day()+1, currentDateTime.Month()+1, currentDateTime.Year(), currentDateTime.Hour(),
	currentDateTime.Minute(), currentDateTime.Second(), currentDateTime.MicroSecond()));

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
	(EAPL("Session Validity - Last Full Auth Time, %2d-%2d-%4d : %2d-%2d-%2d-%d\n"), 
	fullAuthDateTime.Day()+1, fullAuthDateTime.Month()+1, fullAuthDateTime.Year(), fullAuthDateTime.Hour(),
	fullAuthDateTime.Minute(), fullAuthDateTime.Second(), fullAuthDateTime.MicroSecond()));

#endif

	TTimeIntervalMicroSeconds interval = currentTime.MicroSecondsFrom(lastFullAuthTime);
		
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("eap_am_type_tls_peap_symbian_c::is_session_valid:interval in microseconds:"),
			&(interval.Int64()),
			sizeof(interval.Int64()) ) );
			
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("eap_am_type_tls_peap_symbian_c::is_session_valid:max session time in microseconds:"),
			&(maxSessionTime),
			sizeof(maxSessionTime) ) );
	
#if defined(_DEBUG) || defined(DEBUG)

	TTimeIntervalMinutes intervalMins;
	TInt error = currentTime.MinutesFrom(lastFullAuthTime, intervalMins);
	
	if(error == KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_tls_peap_symbian_c::is_session_validL()")
			 EAPL("interval in Minutes =%d\n"),
			 intervalMins.Int()));
	}
	
#endif

	if( maxSessionTime >= interval.Int64() )
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_tls_peap_symbian_c::is_session_valid - Session Valid \n")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			

		return true;	
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_tls_peap_symbian_c::is_session_valid - Session NOT Valid \n")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			
		
		return false;	
	}
}

//--------------------------------------------------

void eap_am_type_tls_peap_symbian_c::store_authentication_timeL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_tls_peap_symbian_c::store_authentication_timeL, index type=%d, index=%d, tunneling type=%d, current eap type=%d\n"),
		m_index_type, m_index, m_tunneling_vendor_type, m_current_eap_vendor_type));	

	TPtrC lastFullAuthTimeString;

	switch (m_current_eap_vendor_type)
	{
	case eap_type_tls:
		{
			lastFullAuthTimeString.Set(KTLSLastFullAuthTime);
		}
		break;

	case eap_type_peap:
		{
			lastFullAuthTimeString.Set(KPEAPLastFullAuthTime);
		}
		break;

	case eap_type_ttls:
		{
			lastFullAuthTimeString.Set(KTTLSLastFullAuthTime);
		}
		break;
		
	case eap_type_ttls_plain_pap:
		{
		lastFullAuthTimeString.Set( KTTLSPAPLastFullAuthTime );
		}
		break;

#if defined(USE_FAST_EAP_TYPE)
	case eap_type_fast:
		{
			lastFullAuthTimeString.Set(KFASTLastFullAuthTime);
		}
		break;
#endif
		
	default:
		{
			// Should never happen
			EAP_TRACE_ERROR(m_am_tools, 
				TRACE_FLAGS_DEFAULT, (
				EAPL("Unsupported EAP type, m_current_eap_vendor_type=%d \n"),
				m_current_eap_vendor_type));
				
			User::Leave(KErrNotSupported);
		}
	}	

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT(KSQLQuery, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLQuery, &lastFullAuthTimeString, &m_db_table_name,
						&KServiceType, m_index_type, 
						&KServiceIndex, m_index, &KTunnelingType, m_tunneling_vendor_type);

	RDbView view;
	// Evaluate view
	User::LeaveIfError(view.Prepare(m_database, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	// Get the first (and only) row for updation.
	view.FirstL();
	view.UpdateL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	// Get the current universal time.
	TTime currentTime;
	currentTime.UniversalTime();
		
#if defined(_DEBUG) || defined(DEBUG)	
	
	TDateTime currentDateTime = currentTime.DateTime();
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
	(EAPL("eap_am_type_tls_peap_symbian_c::store_authentication_time, %2d-%2d-%4d : %2d-%2d-%2d-%d\n"), 
	currentDateTime.Day()+1, currentDateTime.Month()+1,currentDateTime.Year(), currentDateTime.Hour(),
	currentDateTime.Minute(), currentDateTime.Second(), currentDateTime.MicroSecond()));

#endif

	TInt64 fullAuthTime = currentTime.Int64();
	
	view.SetColL(colSet->ColNo(lastFullAuthTimeString), fullAuthTime);

	view.PutL();	

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	CleanupStack::PopAndDestroy(&view); // Close view.
	CleanupStack::PopAndDestroy(buf); // Delete buf.

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_tls_peap_symbian_c::store_authentication_timeL - End \n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_am_type_tls_peap_symbian_c::set_peap_version(
	const peap_version_e /* peap_version */,
	const bool /* use_tppd_tls_peap */,
	const bool /* use_tppd_peapv1_acknowledge_hack */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

#if defined(USE_FAST_EAP_TYPE)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::read_authority_identity(eap_variable_data_c * const /* authority_identity */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: %s: crypto_function: eap_am_type_tls_peap_symbian_c::read_authority_identity(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

// This is commented in tls_am_application_eap_fast_c::query_pac_of_type().
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::query_pac_of_type(
		const eap_fast_pac_type_e /* pac_type */)
		
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: %s: crypto_function: eap_am_type_tls_peap_symbian_c::query_pac_of_type(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

#if defined(USE_EAP_CORE_SERVER)
/**
 * This function call is always asyncronous.
 * It will be completed always with complete_verify_pac() function call.
 * Function verifies the received PAC is valid.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::verify_pac(const eap_fast_variable_data_c * const /* tlv_pac */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: %s: crypto_function: eap_am_type_tls_peap_symbian_c::verify_pac(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

#endif //#if defined(USE_EAP_CORE_SERVER)
//--------------------------------------------------


// This is commented in eap_am_fast_pac_store_services_c::query_user_permission_for_A_ID().
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::query_user_permission_for_A_ID(
	const eap_fast_pac_store_pending_operation_e in_pending_operation,
	const eap_fast_variable_data_c * const in_pac_attribute_A_ID_info,
	const eap_fast_variable_data_c * const in_pac_attribute_A_ID)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: %s: eap_am_type_tls_peap_symbian_c::query_user_permission_for_A_ID(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	eap_status_e status(eap_status_ok);
	
	m_pending_operation = in_pending_operation;

 	if (in_pac_attribute_A_ID_info->get_data_length()>0)
		{
		TRAPD(err, status = QueryUserPermissionForAIDL(in_pac_attribute_A_ID_info, in_pac_attribute_A_ID ));
		if (err != KErrNone)
			{
			EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::read_PAC_store_data() ERROR: LEAVE from QueryUserPermissionForAIDL error=%d"),
					err));
					
				m_eap_fast_completion_status = m_am_tools->convert_am_error_to_eapol_error(err);
			 	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
			}
		}
 	if (status == KErrNone)
 		{
 		m_eap_fast_completion_status = eap_status_pending_request;
 		}
 	else
 		{
 		m_eap_fast_completion_status = status;
 		}
 	
 	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
}		

//--------------------------------------------------

eap_status_e eap_am_type_tls_peap_symbian_c::QueryUserPermissionForAIDL(
		const eap_fast_variable_data_c * const in_pac_attribute_A_ID_info,
		const eap_fast_variable_data_c * const in_pac_attribute_A_ID)
	{
	eap_status_e status(eap_status_ok);
	
	HBufC8* A_ID_info8 = HBufC8::NewLC((in_pac_attribute_A_ID_info->get_data_length()));
	TPtr8 A_ID_infoPtr8 = A_ID_info8->Des();

	HBufC* A_ID_info = HBufC::NewLC((in_pac_attribute_A_ID_info->get_data_length()));
	TPtr A_ID_infoPtr = A_ID_info->Des();

	HBufC8* A_ID = HBufC8::NewLC((in_pac_attribute_A_ID->get_data_length()));
	TPtr8 A_IDPtr = A_ID->Des();

	A_ID_infoPtr8.Copy(in_pac_attribute_A_ID_info->get_data(in_pac_attribute_A_ID_info->get_data_length()),in_pac_attribute_A_ID_info->get_data_length() );
	A_ID_infoPtr.Copy(A_ID_infoPtr8);
	
	A_IDPtr.Copy(in_pac_attribute_A_ID->get_data(in_pac_attribute_A_ID->get_data_length()),in_pac_attribute_A_ID->get_data_length() );

	EAP_TRACE_DATA_DEBUG_SYMBIAN(
			("eap_am_type_tls_peap_symbian_c::query_user_permission_for_A_ID(): in_pac_attribute_A_ID_info",
			(A_ID_infoPtr.Ptr()),
			(in_pac_attribute_A_ID_info->get_data_length())));

 	EAP_TRACE_DATA_DEBUG_SYMBIAN(
			("eap_am_type_tls_peap_symbian_c::query_user_permission_for_A_ID(): in_pac_attribute_A_ID",
			(A_IDPtr.Ptr()),
			(in_pac_attribute_A_ID->get_data_length())));

 	if (A_ID_infoPtr.Size()>KMaxEapFastNotifierBufLength)
	{
  		CleanupStack::PopAndDestroy(3); // A_ID, A_ID_info
  		status = m_am_tools->convert_am_error_to_eapol_error(KErrArgument);

 		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
 		return EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
	}

 	TBool startedOk = ETrue;
 	
 	if (!iEapFastActiveNotes)
         {
         TRAPD( err, iEapFastActiveNotes = CEapFastActive::NewL( this ) );
         
         if ( err != KErrNone )
             {
             status = eap_status_allocation_error;
             }   
        }
 	if ( status == KErrNone )
 		{
	    //update buffer
 		iEapFastActiveNotes->UpdateInputBuf( A_ID_infoPtr );
        // start query install dialog
 		// asynch. call, return immediately
 		startedOk = iEapFastActiveNotes->Start(
 		    CEapFastActive::EEapFastActiveInstallPacQueryDialog );
 		if ( startedOk == EFalse )
 			{
 			status = eap_status_process_general_error;
 			}
 		}
 	else
 		{
 		status = eap_status_process_general_error;	
 		}

 	CleanupStack::PopAndDestroy(3); // A_ID, A_ID_info
 	
 	return status;
	}


EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::read_PAC_store_data(
	const eap_fast_pac_store_pending_operation_e in_pending_operation,
	EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_store_data_c> * const in_references)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_eap_fast_pac_store_pending_operation = in_pending_operation;
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::read_PAC_store_data()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_type_tls_peap_symbian_c::read_PAC_store_data()");
	
	m_eap_fast_completion_status = eap_status_ok; 
	m_both_asked = 0;
	m_both_completed = 0;

	TRAPD(error, ReadPACStoredataL(in_pending_operation, in_references));
	if(error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::read_PAC_store_data() ERROR: LEAVE from ReadPACStoredataL error=%d"),
			error));
			
		m_eap_fast_completion_status = m_am_tools->convert_am_error_to_eapol_error(error);
	}
	
	// - - - - - - - - - - - - - - - - - - - - - - - -	

	// Proceed with normal complete case.
	
	if(m_eap_fast_completion_status == eap_status_ok)
		{
		EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::complete_read_PAC_store_data(), m_eap_fast_completion_status=%d\n"),
				(m_is_client == true ? "client": "server"), m_eap_fast_completion_status));

		eap_status_e status = m_tls_application->complete_read_PAC_store_data(
			m_eap_fast_completion_status,
			m_eap_fast_pac_store_pending_operation,
			&m_references_and_data_blocks); // m_ready_references_and_data_blocks
		}
	else if (m_eap_fast_completion_status == eap_status_pending_request )
		{
	
		m_ready_references_and_data_blocks.reset();
		m_new_references_and_data_blocks.reset();
		}
	else
	{
	EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::read_PAC_store_data() ERROR =%d"),
			m_eap_fast_completion_status));

	m_references_and_data_blocks.reset();

	m_eap_fast_completion_status = m_tls_application->complete_read_PAC_store_data(
			m_eap_fast_completion_status,
			m_eap_fast_pac_store_pending_operation,
			&m_references_and_data_blocks);
		
		// ERROR.
		(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);		
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -	
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::read_PAC_store_data-End, m_eap_fast_completion_status=%d"),
		m_eap_fast_completion_status));			
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);	
}

//--------------------------------------------------

void eap_am_type_tls_peap_symbian_c::ReadPACStoredataL(
	const eap_fast_pac_store_pending_operation_e in_pending_operation,
	EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_store_data_c> * const in_references)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::ReadPACStoredataL() Start \n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_type_tls_peap_symbian_c::ReadPACStoredataL()");

	// - - - - - - - - - - - - - - - - - - - - - - - -

	m_eap_fast_completion_status = eap_status_ok;

	m_eap_fast_pac_store_pending_operation = in_pending_operation;

	(void) m_references_and_data_blocks.reset();


	for (u32_t ind = 0ul; ind < in_references->get_object_count(); ++ind)
	{
		const eap_fast_pac_store_data_c * const data_reference = in_references->get_object(ind);

		if (data_reference != 0
			&& data_reference->get_is_valid() == true)
		{
			eap_pac_store_data_type_e pacStoreDataRefType = data_reference->get_type();
			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ReadPACStoredataL(): data_reference type=%d=%s\n"),
				pacStoreDataRefType,
				eap_fast_tlv_header_string_c::get_fast_pac_store_data_string(pacStoreDataRefType)));
				
			EAP_TRACE_DATA_DEBUG_SYMBIAN(
				("ReadPACStoredataL(): data_reference reference:",
				data_reference->get_reference()->get_data(data_reference->get_reference()->get_data_length()), 
				data_reference->get_reference()->get_data_length()));
			
			switch(pacStoreDataRefType)	
			{
				case eap_pac_store_data_type_PAC_store_master_key:
				{
					// To read master key.
					
					eap_variable_data_c master_key(m_am_tools);
					
#ifdef USE_PAC_STORE
					// Get master key from PAC store DB.	
					GetPacStoreDbDataL(
						pacStoreDataRefType,
						&master_key);
				    						
#endif	// End: #ifdef USE_PAC_STORE
								
					// master_key should have the master key now.
					// Doesn't matter even if there is no master key (master_key is empty).
					// Proceed as normal case.	
					
					eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);

					eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
						m_am_tools, new_data);

					if (new_data == 0)
					{
						m_eap_fast_completion_status = eap_status_allocation_error;
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					new_data->set_type(pacStoreDataRefType);					

					// Set the reference.
					m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(data_reference->get_reference());
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
					
					m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(&master_key);

					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					automatic_new_data.do_not_free_variable();

					m_eap_fast_completion_status = m_references_and_data_blocks.add_object(new_data, true);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
					
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("eap_pac_store_data_type_PAC_store_master_key - added data",
						(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
						(new_data->get_data())->get_data_length()));						
					
					break;
					
				} // End: case eap_pac_store_data_type_PAC_store_master_key:
				
				case eap_pac_store_data_type_reference_counter:
				{
					// To read reference counter.
					
					eap_variable_data_c reference_counter(m_am_tools);
					
#ifdef USE_PAC_STORE
					// Get reference counter from PAC store DB.	
					GetPacStoreDbDataL(
						pacStoreDataRefType,
						&reference_counter);
				    						
#endif	// End: #ifdef USE_PAC_STORE
								
					// reference_counter should have the reference counter now.
					// Doesn't matter even if it is empty. Proceed as normal case.	
					
					eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);

					eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
						m_am_tools, new_data);

					if (new_data == 0)
					{
						m_eap_fast_completion_status = eap_status_allocation_error;
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					new_data->set_type(pacStoreDataRefType);
					
					// Set the reference.
					m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(data_reference->get_reference());
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
					

					m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(&reference_counter);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					automatic_new_data.do_not_free_variable();

					m_eap_fast_completion_status = m_references_and_data_blocks.add_object(new_data, true);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
					
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("eap_pac_store_data_type_reference_counter - added data",
						(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
						(new_data->get_data())->get_data_length()));
					
					break;
					
				} // End: case eap_pac_store_data_type_reference_counter:						

				case eap_pac_store_data_type_group_data: // Check the reference (the ref is data_reference->get_reference()) and provide only the value from groups table.
				{
					// To read a particular group data.
					
					eap_variable_data_c group_data(m_am_tools);
					
#ifdef USE_PAC_STORE
					// Get group data from PAC store DB, using the reference.	
					GetPacStoreDbDataL(
						pacStoreDataRefType,
						&group_data,
						data_reference->get_reference());
				    						
#endif	// End: #ifdef USE_PAC_STORE
								
					// group_data should have the value stored in PAC store now.
					// Doesn't matter even if it is empty. Proceed as normal case.	
					
					eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);

					eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
						m_am_tools, new_data);

					if (new_data == 0)
					{
						m_eap_fast_completion_status = eap_status_allocation_error;
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					new_data->set_type(pacStoreDataRefType);					

					// Set the reference.
					m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(data_reference->get_reference());
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
					
					m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(&group_data);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					automatic_new_data.do_not_free_variable();

					m_eap_fast_completion_status = m_references_and_data_blocks.add_object(new_data, true);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
					
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("eap_pac_store_data_type_group_data - added data",
						(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
						(new_data->get_data())->get_data_length()));
					
					break;
					
				} // End: case eap_pac_store_data_type_group_data:					
					
				case eap_pac_store_data_type_A_ID_data: // Check the reference and provide only the value from AIDs table.
				{
					// To read a particular AID data.
					
					eap_variable_data_c aid_data(m_am_tools);
					
#ifdef USE_PAC_STORE
					// Get AID data from PAC store DB, using the reference.	
					GetPacStoreDbDataL(
						pacStoreDataRefType,
						&aid_data,
						data_reference->get_reference());
				    						
#endif	// End: #ifdef USE_PAC_STORE
								
					// aid_data should have the value stored in PAC store now.
					// Doesn't matter even if it is empty. Proceed as normal case.	
					
					eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);

					eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
						m_am_tools, new_data);

					if (new_data == 0)
					{
						m_eap_fast_completion_status = eap_status_allocation_error;
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					new_data->set_type(pacStoreDataRefType);					

					// Set the reference.
					m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(data_reference->get_reference());
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
					
					m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(&aid_data);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					automatic_new_data.do_not_free_variable();

					m_eap_fast_completion_status = m_references_and_data_blocks.add_object(new_data, true);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}	
					
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("eap_pac_store_data_type_A_ID_data - added data",
						(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
						(new_data->get_data())->get_data_length()));
					
					break;
					
				} // End: case eap_pac_store_data_type_A_ID_data:						
					
				case eap_pac_store_data_type_PAC_data: // Check the reference and provide only the value from PACs table.
				{
					// To read a particular PAC data.
					
					eap_variable_data_c pac_data(m_am_tools);
					
#ifdef USE_PAC_STORE
					// Get PAC data from PAC store DB, using the reference.	
					GetPacStoreDbDataL(
						pacStoreDataRefType,
						&pac_data,
						data_reference->get_reference());
				    						
#endif	// End: #ifdef USE_PAC_STORE
								
					// pac_data should have the value stored in PAC store now.
					// Doesn't matter even if it is empty. Proceed as normal case.	
					
					eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);

					eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
						m_am_tools, new_data);

					if (new_data == 0)
					{
						m_eap_fast_completion_status = eap_status_allocation_error;
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					new_data->set_type(pacStoreDataRefType);					

					// Set the reference.
					m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(data_reference->get_reference());
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
					
					m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(&pac_data);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					automatic_new_data.do_not_free_variable();

					m_eap_fast_completion_status = m_references_and_data_blocks.add_object(new_data, true);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}	
					
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("eap_pac_store_data_type_PAC_data - added data",
						(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
						(new_data->get_data())->get_data_length()));
					
					break;
					
				} // End: case eap_pac_store_data_type_PAC_data:
				
				case eap_pac_store_data_type_group_info:// Provide all from groups table. Create data for one entry in the groups table.
				case eap_pac_store_data_type_A_ID_info: // Provide all from AIDs table. Create data for one entry in the AIDs table.
				case eap_pac_store_data_type_PAC_info:// Provide all from PACs table. Create data for one entry in the PACs table.
				{
						/** Read the items from DB here.*/
				TBuf<64> dbTableName;
				eap_pac_store_data_type_e dataType = eap_pac_store_data_type_none;
				
				switch(pacStoreDataRefType)	
					{
					case eap_pac_store_data_type_group_info:
					{
					dbTableName = KPacStoreGroupsTableName;
					dataType = eap_pac_store_data_type_group_data;
					break;		
					}		
					case eap_pac_store_data_type_A_ID_info:
					{
					dbTableName = KPacStoreAIDsTableName;
					dataType = eap_pac_store_data_type_A_ID_data;
					break;		
					}		
					case eap_pac_store_data_type_PAC_info:
					{
					dbTableName = KPacStorePACsTableName;
					dataType = eap_pac_store_data_type_PAC_data;
					break;		
					}		
				}
				
				TInt count = 0;
				
				m_info_array.Reset();
					
				iPacStoreDb->GetPacStoreDataL(dbTableName, m_info_array);
				
				EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::ReadPACStoredataL:Number of entries in table %S=%d\n"),
				&dbTableName, m_info_array.Count()));				
				
				while (count < m_info_array.Count())
					{
					TPtr8 infoDataPtr = m_info_array[count].iData->Des();
					TPtr8 infoRefPtr = m_info_array[count].iReference->Des();
					
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("eap_am_type_tls_peap_symbian_c::ReadPACStoredataL: BINARY value from PAC DB (reference)",
						infoRefPtr.Ptr(),
						infoRefPtr.Size()));
					
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("eap_am_type_tls_peap_symbian_c::ReadPACStoredataL: BINARY value from PAC DB (value)",
						infoDataPtr.Ptr(),
						infoDataPtr.Size()));					
					
					eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);

					eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
						m_am_tools, new_data);

					if (new_data == 0)
					{
						m_eap_fast_completion_status = eap_status_allocation_error;
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					new_data->set_type(dataType);					

					// Set the reference.
					m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(infoRefPtr.Ptr(), infoRefPtr.Size());
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						delete m_info_array[count].iData;
						delete m_info_array[count].iReference;
						break;
					}
					
					m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(infoDataPtr.Ptr(),infoDataPtr.Size() );
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						delete m_info_array[count].iData;
						delete m_info_array[count].iReference;
						break;
					}

					automatic_new_data.do_not_free_variable();

					m_eap_fast_completion_status = m_references_and_data_blocks.add_object(new_data, true);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						delete m_info_array[count].iData;
						delete m_info_array[count].iReference;
						break;
					}					
							
					delete m_info_array[count].iData;
					delete m_info_array[count].iReference;
					
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("For GROUP, AID, PAC INFOs - added data",
						(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
						(new_data->get_data())->get_data_length()));					
		
					count++;
					} // End: while
					
				
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
				
					break;
				} // End: case eap_pac_store_data_type_group_info:
			
				case eap_pac_store_data_type_PAC_store_password:
				{
					// To read PAC store PW.
					
#ifdef USE_PAC_STORE
					// Get PAC store password
					
					// First check if there is some PW in PAC store DB.						
					GetPacStoreDbDataL(
						pacStoreDataRefType,
						&m_PAC_store_password);
				    						
#endif	// End: #ifdef USE_PAC_STORE
					
					if(m_PAC_store_password.get_data_length() == 0)
					{
						// Nothing in the PAC store DB.
						
						EAP_TRACE_DEBUG_SYMBIAN(
							(_L("eap_am_type_tls_peap_symbian_c::ReadPACStoredataL: NO PW in PAC store. Try Notifier")));					
						
					
						// Show the password query notifier to get the password.
					
						m_ready_references_array_index = ind;
						
						m_verificationStatus = EFalse;
						
						m_state = EPasswordQuery;

						m_pacStoreDataRefType = pacStoreDataRefType;

						m_data_reference.get_writable_reference()->set_copy_of_buffer(data_reference->get_reference());

						m_both_asked++;

						if(iPacStoreDb->IsMasterKeyPresentL())
							{
							m_eap_fast_completion_status = ShowNotifierItemAndGetResponse(
								EEapFastNotifierPacStorePwQuery, ETrue );
							}
						else
							{
							m_state =  EMasterkeyQuery; 
				        	m_eap_fast_completion_status = ShowNotifierItemAndGetResponse(
				        		EEapFastNotifierCreateMasterkeyQuery, ETrue );
							}

						break;
					}
			
					eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);

					eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
						m_am_tools, new_data);

					if (new_data == 0)
					{
						m_eap_fast_completion_status = eap_status_allocation_error;
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					new_data->set_type(pacStoreDataRefType);
					
					// Set the reference.
					m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(data_reference->get_reference());
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}					

					m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(&m_PAC_store_password);

					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					automatic_new_data.do_not_free_variable();

					m_eap_fast_completion_status = m_references_and_data_blocks.add_object(new_data, true);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
					
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("eap_pac_store_data_type_PAC_store_password - added data",
						(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
						(new_data->get_data())->get_data_length()));
				
					m_eap_fast_completion_status = eap_status_pending_request;	
					
					break;
					
				} // End: case eap_pac_store_data_type_PAC_store_password:
				
				case eap_pac_store_data_type_PAC_store_device_seed:
				{
					// To get the device seed.
					
					// Create a device seed.
				
				    eap_variable_data_c m_PAC_store_device_seed(m_am_tools);
				    m_eap_fast_completion_status = m_PAC_store_device_seed.set_copy_of_buffer(
				    	iPacStoreDb->GetSeed() );
					if ( m_eap_fast_completion_status != eap_status_ok )
					    {
					    EAP_TRACE_DEBUG_SYMBIAN(
							(_L("eap_am_type_tls_peap_symbian_c::ReadPACStoredataL: ERROR: seed data is not valid.")));	
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					    }
				    
					// continue normally
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("Device Seed",
						m_PAC_store_device_seed.get_data(m_PAC_store_device_seed.get_data_length()),
						m_PAC_store_device_seed.get_data_length()));
										
					eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);

					eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
						m_am_tools, new_data);

					if (new_data == 0)
					{
						m_eap_fast_completion_status = eap_status_allocation_error;
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					new_data->set_type(pacStoreDataRefType);
					
					// Set the reference.
					m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(data_reference->get_reference());
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}					

					m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(&m_PAC_store_device_seed);

					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					automatic_new_data.do_not_free_variable();

					m_eap_fast_completion_status = m_references_and_data_blocks.add_object(new_data, true);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
					
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("eap_pac_store_data_type_PAC_store_device_seed - added data",
						(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
						(new_data->get_data())->get_data_length()));					
					
					break;
				} // End: case eap_pac_store_data_type_PAC_store_device_seed:
				
				case eap_pac_store_data_type_PAC_store_IAP_reference:
				{
					// To get the IAP reference.
										
					eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);

					eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
						m_am_tools, new_data);

					if (new_data == 0)
					{
						m_eap_fast_completion_status = eap_status_allocation_error;
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					new_data->set_type(pacStoreDataRefType);
					
					// Set the reference.
					m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(data_reference->get_reference());
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}					
					
					// Provide Service table id (m_index) and type (m_index_type) 
					// in the specified format.
					
					i32_t tmpIndex = static_cast<i32_t>(m_index);
					i32_t tmpIndexType = static_cast<i32_t>(m_index_type);
					
					eap_variable_data_c tmp_EAP_FAST_IAP_reference(m_am_tools);
					
					// Copy the index and index type. The order of copying is important.
					
					m_eap_fast_completion_status = tmp_EAP_FAST_IAP_reference.set_copy_of_buffer(&tmpIndex,sizeof(i32_t));
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
					
					m_eap_fast_completion_status = tmp_EAP_FAST_IAP_reference.add_data(&tmpIndexType,sizeof(i32_t));
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					if (tmp_EAP_FAST_IAP_reference.get_is_valid_data() == true)
					{
						m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(&tmp_EAP_FAST_IAP_reference);

						if (m_eap_fast_completion_status != eap_status_ok)
						{
							(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
							break;
						}
					}
					
					automatic_new_data.do_not_free_variable();					

					m_eap_fast_completion_status = m_references_and_data_blocks.add_object(new_data, true);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
						
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("eap_pac_store_data_type_PAC_store_IAP_reference - added data",
						(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
						(new_data->get_data())->get_data_length()));
					
					break;
					
				} // End : case eap_pac_store_data_type_PAC_store_IAP_reference:
				
				case eap_pac_store_data_type_PAC_store_group_reference: 
				{
					// To get the PAC store group reference
					// It is EAP_FAST_PAC_Group_DB_Reference_Collection in PAC store DB.
					
					eap_variable_data_c groupDbReferenceData(m_am_tools);
				
					EapTlsPeapUtils::GetEapSettingsDataL(
						m_database,
						m_index_type,
						m_index,
						m_tunneling_type,
						m_current_eap_type,
						KFASTPACGroupDBReferenceCollection,
						&groupDbReferenceData);
					
					// groupDbReferenceData should have the value stored in PAC store DB.
					// Doesn't matter even if it is empty. Proceed as normal case.
					
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("PAC group ref from PAC store DB",
						groupDbReferenceData.get_data(groupDbReferenceData.get_data_length()), 
						groupDbReferenceData.get_data_length()));
										
					eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);

					eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
						m_am_tools, new_data);

					if (new_data == 0)
					{
						m_eap_fast_completion_status = eap_status_allocation_error;
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					new_data->set_type(pacStoreDataRefType);
					
					// Set the reference.
					m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(&groupDbReferenceData);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}					

					eap_variable_data_c group_data_2(m_am_tools);
					
#ifdef USE_PAC_STORE
					// Get group data from PAC store DB, using the reference.	
					GetPacStoreDbDataL(
						eap_pac_store_data_type_group_data,
						&group_data_2,
						&groupDbReferenceData);
				    						
#endif	// End: #ifdef USE_PAC_STORE

					if ( group_data_2.get_data_length() == 0 )
						{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;						
						}
						
					m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(&group_data_2);

					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}

					automatic_new_data.do_not_free_variable();

					m_eap_fast_completion_status = m_references_and_data_blocks.add_object(new_data, true);
					if (m_eap_fast_completion_status != eap_status_ok)
					{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
					
					EAP_TRACE_DATA_DEBUG_SYMBIAN(
						("eap_pac_store_data_type_PAC_store_group_reference - added data",
						(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
						(new_data->get_data())->get_data_length()));										
					
					break;
					
				} // End: case eap_pac_store_data_type_PAC_store_group_reference:
				
				case eap_pac_store_data_type_PAC_file_password:
				{
					// To get the password for decrypting the PAC file.
					
					// Show the notifier to get the PAC file password.
				
					m_ready_references_array_index = ind;
					
					m_pacStoreDataRefType = pacStoreDataRefType;

					m_data_reference.get_writable_reference()->set_copy_of_buffer(data_reference->get_reference());

					m_state = EFilePasswordQuery;

					m_both_asked++;

					m_eap_fast_completion_status = ShowNotifierItemAndGetResponse(
								EEapFastNotifierPacFilePwQuery, ETrue );
					
					if (m_eap_fast_completion_status != eap_status_ok)
						{
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
						}

					break;
					
				} // End : case eap_pac_store_data_type_PAC_file_password:
			
				default:
				{
					// Unknown data query.
					
					EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::ReadPACStoredataL: ERROR: Unknown data type")));					
										
					m_eap_fast_completion_status = eap_status_not_found;
					(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
					break;
				}
				
			} // End: switch(pacStoreDataRefType)			
		}
	} // for ()
	if (m_both_asked)
		m_eap_fast_completion_status = eap_status_pending_request;
	m_info_array.Reset();
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::ReadPACStoredataL-End, m_eap_fast_completion_status=%d"),
		m_eap_fast_completion_status));			
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return; 
}
		

//--------------------------------------------------

// This is commented in eap_am_fast_pac_store_services_c::write_PAC_store_data().
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::write_PAC_store_data(
	const bool /* when_true_must_be_synchronous_operation */,
	const eap_fast_pac_store_pending_operation_e in_pending_operation,
	EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_store_data_c> * const in_references_and_data_blocks)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: %s: eap_am_type_tls_peap_symbian_c::write_PAC_store_data(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	m_eap_fast_pac_store_pending_operation = in_pending_operation;
	TRAPD(error, WritePACStoreDataL(in_pending_operation, in_references_and_data_blocks));

	if(error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::write_PAC_store_data() ERROR: LEAVE from WritePACStoreDataL error=%d"),
			error));
			
		m_eap_fast_completion_status = m_am_tools->convert_am_error_to_eapol_error(error);
	}
	
	// - - - - - - - - - - - - - - - - - - - - - - - -	

	// Proceed with normal complete case.
	
	eap_status_e status(eap_status_ok);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("FAST: %s: direct_complete_function: WritePACStoreDataL(), m_eap_fast_completion_status=%d\n"),
		(m_is_client == true ? "client": "server"), m_eap_fast_completion_status));

	if (m_eap_fast_completion_status == eap_status_ok)
	{
		status = m_tls_application->complete_write_PAC_store_data(
			m_eap_fast_completion_status,
			m_eap_fast_pac_store_pending_operation);
	}
	else
	{
		status = m_tls_application->complete_write_PAC_store_data(
			m_eap_fast_completion_status,
			m_eap_fast_pac_store_pending_operation);
		
		// ERROR.
		(void) EAP_STATUS_RETURN(m_am_tools, status);		
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -	
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::write_PAC_store_data-End, status=%d, m_eap_fast_completion_status=%d"),
		status, m_eap_fast_completion_status));			
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

		
//--------------------------------------------------

void eap_am_type_tls_peap_symbian_c::WritePACStoreDataL(
		const eap_fast_pac_store_pending_operation_e in_pending_operation,
		EAP_TEMPLATE_CONST eap_array_c<eap_fast_pac_store_data_c> * const in_references_and_data_blocks)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::WritePACStoreDataL()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_type_tls_peap_symbian_c::WritePACStoreDataL()");

	// - - - - - - - - - - - - - - - - - - - - - - - -
	
	m_eap_fast_completion_status = eap_status_ok;

	m_eap_fast_pac_store_pending_operation = in_pending_operation;

	TBuf<KMaxDBFieldNameLength> pacStoreDBColName;
	TBool writeToPacStore = EFalse;
	
	// - - - - - - - - - - - - - - - - - - - - - - - -

	for (u32_t ind = 0ul; ind < in_references_and_data_blocks->get_object_count(); ++ind)
	{
		const eap_fast_pac_store_data_c * const data_reference = in_references_and_data_blocks->get_object(ind);
		if (data_reference != 0)
		{
			const eap_pac_store_data_type_e aPacStoreDataType = data_reference->get_type();
		
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::WritePACStoreDataL(): type %d=%s\n"),
				data_reference->get_type(),
				eap_fast_tlv_header_string_c::get_fast_pac_store_data_string(data_reference->get_type())));
			
			EAP_TRACE_DATA_DEBUG_SYMBIAN(
				("WritePACStoreDataL(): data_reference data(value):",
				data_reference->get_data()->get_data(data_reference->get_data()->get_data_length()), 
				data_reference->get_data()->get_data_length()));
			
			EAP_TRACE_DATA_DEBUG_SYMBIAN(
				("WritePACStoreDataL(): data_reference reference:",
				data_reference->get_reference()->get_data(data_reference->get_reference()->get_data_length()), 
				data_reference->get_reference()->get_data_length()));
			
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::WritePACStoreDataL: change status=%d (0=eap_pac_store_data_change_status_none)"),
				data_reference->get_change_status()));

			if (data_reference != 0
				&& data_reference->get_is_valid() == true
				&& data_reference->get_type() != eap_pac_store_data_type_none
				&& data_reference->get_change_status() != eap_pac_store_data_change_status_none)
			{
				eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);

				eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
					m_am_tools, new_data);

				if (new_data == 0)
				{
					m_eap_fast_completion_status = eap_status_allocation_error;
					break;
				}
				

				/* Get the data (or value) from the input */
				HBufC8* pacStoreDBColVal8 = HBufC8::NewLC(data_reference->get_data()->get_data_length());
				TPtr8 pacStoreDBColValPtr8 = pacStoreDBColVal8->Des();
				pacStoreDBColValPtr8.Copy(data_reference->get_data()->get_data(),
										  data_reference->get_data()->get_data_length());
				
				EAP_TRACE_DATA_DEBUG_SYMBIAN(
					("write_PAC_store_dataL(): 8 bit VALUE from common:",
					pacStoreDBColValPtr8.Ptr(), 
					pacStoreDBColValPtr8.Size()));
				
				/* Get the reference from the input */			
				HBufC8* pacStoreDBColRef8 = HBufC8::NewLC(data_reference->get_reference()->get_data_length());
				TPtr8 pacStoreDBColRefPtr8 = pacStoreDBColRef8->Des();
				pacStoreDBColRefPtr8.Copy(data_reference->get_reference()->get_data(),
										  data_reference->get_reference()->get_data_length());

				EAP_TRACE_DATA_DEBUG_SYMBIAN(
					("write_PAC_store_dataL(): 8 bit REFERENCE from common:",
					pacStoreDBColRefPtr8.Ptr(), 
					pacStoreDBColRefPtr8.Size()));
			
				writeToPacStore = EFalse;
				
				TBool isNewEntry(EFalse);
				if(data_reference->get_change_status() == eap_pac_store_data_change_status_new)
				{
					isNewEntry =ETrue;
				}
				else
				{
					isNewEntry =EFalse;
				}
				
				switch(aPacStoreDataType)
				{		
					case eap_pac_store_data_type_PAC_store_master_key:
					{
						pacStoreDBColName.Copy(KPacStoreMasterKey);
						writeToPacStore = ETrue;
						
						// This can not be a new entry. Only modification possible for this.
						// Some times common side provides this as new entry.
						isNewEntry = EFalse;
						
						break;		
					}		
					case eap_pac_store_data_type_PAC_store_password:
					{
						//This is not saved anywhere.
						break;		
					}		
					case eap_pac_store_data_type_PAC_store_device_seed:
					{
						//This is not saved anywhere.
						break;		
					}		
					case eap_pac_store_data_type_PAC_store_IAP_reference:
					{
						//This is not saved anywhere.
						break;		
					}		
					case eap_pac_store_data_type_PAC_store_group_reference:
					{
						// This should be saved in FAST special settings table in EAP DB, not in PAC store.
						
						EapTlsPeapUtils::SetEapSettingsDataL(
							m_database,
							m_index_type,
							m_index,
							m_tunneling_type,
							m_current_eap_type,
							KFASTPACGroupDBReferenceCollection,
							data_reference->get_data());
						
						writeToPacStore = EFalse;
						
						break;		
					}		
					case eap_pac_store_data_type_reference_counter:
					{
						pacStoreDBColName.Copy(KPacStoreReferenceCounter);			
						writeToPacStore = ETrue;
						
						// This can not be a new entry. Only modification possible for this.
						// Some times common side provides this as new entry.
						isNewEntry = EFalse;
						
						break;		
					}		
					case eap_pac_store_data_type_PAC_file_password:
					{
						//This is not saved anywhere.
						break;		
					}		
					case eap_pac_store_data_type_group_info:
					case eap_pac_store_data_type_A_ID_info:
					case eap_pac_store_data_type_PAC_info:
					{
						//These are not saved, as such, anywhere.
						break;		
					}				
					case eap_pac_store_data_type_group_data:
					{
						pacStoreDBColName.Copy(KPacStoreGroupValue);
						writeToPacStore = ETrue;
						break;		
					}		
					case eap_pac_store_data_type_A_ID_data:
					{
						pacStoreDBColName.Copy(KPacStoreAIDValue);
						writeToPacStore = ETrue;
						break;		
					}		
					case eap_pac_store_data_type_PAC_data:
					{
						pacStoreDBColName.Copy(KPacStorePACValue);
						writeToPacStore = ETrue;
						break;		
					}
					default:
					{
						// Unknown data type.
						
						EAP_TRACE_DEBUG_SYMBIAN(
							(_L("eap_am_type_tls_peap_symbian_c::WritePACStoreDataL: ERROR: Unknown data type")));					
											
						m_eap_fast_completion_status = eap_status_not_found;
						(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						break;
					}
				} // End : switch(aPacStoreDataType)

				if (writeToPacStore)
				{	
					if(data_reference->get_change_status() == eap_pac_store_data_change_status_delete)
					{
						// We have to delete this entry from PAC store.
						
						iPacStoreDb->RemovePacStoreEntryL(
								pacStoreDBColName,
								pacStoreDBColValPtr8,
								pacStoreDBColRefPtr8);					
					}
					else
					{ 
						// Here the entry is either modified or a new entry. isNewEntry will have the correct value.
						iPacStoreDb->SetPacStoreDataL(
								pacStoreDBColName,
								pacStoreDBColValPtr8,
								pacStoreDBColRefPtr8,
								isNewEntry);						
					}
					
					m_eap_fast_completion_status = eap_status_ok;
				}

				if (m_eap_fast_completion_status != eap_status_ok)
				{
					break;
				}

				CleanupStack::PopAndDestroy(2); // pacStoreDBColVal8 (pacStoreDBColValPtr8) and 
												// pacStoreDBColRef8 (pacStoreDBColRefPtr8).
				
			}
			else if (data_reference != 0
				&& data_reference->get_is_valid() == true
				&& data_reference->get_type() == eap_pac_store_data_type_none)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: illegal reference 0x%08x: type %d\n"),
					data_reference,
					data_reference->get_type()));

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: unknown reference"),
					 data_reference->get_reference()->get_data(),
					 data_reference->get_reference()->get_data_length()));

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: unknown data"),
					 data_reference->get_data()->get_data(),
					 data_reference->get_data()->get_data_length()));
			}
		}
	} // for ()

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::WritePACStoreDataL-End, m_eap_fast_completion_status=%d"),
		m_eap_fast_completion_status));			
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);		
}

//--------------------------------------------------

// This is commented in eap_am_fast_pac_store_services_c::complete_add_imported_PAC_file().
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::complete_add_imported_PAC_file(
	const eap_status_e /* in_completion_status */,
	const eap_variable_data_c * const in_imported_PAC_filename,
	const eap_variable_data_c * const out_used_group_reference)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST: %s: eap_am_type_tls_peap_symbian_c::complete_add_imported_PAC_file(): ")
			EAPL("this = 0x%08x\n"),
			(m_is_client == true ? "client": "server"),
			this));
	
	m_eap_fast_completion_status = eap_status_ok;

	TRAPD(err, CompleteAddImportedPACFileL(in_imported_PAC_filename, out_used_group_reference));
	if (err != KErrNone)
		{
		EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::read_PAC_store_data() ERROR: LEAVE from CompleteAddImportedPACFfileL error=%d"),
				err));
				
			m_eap_fast_completion_status = m_am_tools->convert_am_error_to_eapol_error(err);
		}

   	m_eap_fast_completion_status = m_partner->set_timer(
		this,
		KImportFileTimerID, // if nothing in db & remove_IAP_reference called already with 0 -> import
		0,
		1);

	if (m_eap_fast_completion_status != eap_status_ok)
		{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
		}
 
   	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
}
	
void eap_am_type_tls_peap_symbian_c::CompleteAddImportedPACFileL(
		const eap_variable_data_c * const in_imported_PAC_filename,
		const eap_variable_data_c * const out_used_group_reference)
	{
	RFs aFs;
	aFs.Connect( KFileServerDefaultMessageSlots );

	HBufC8* buf = HBufC8::NewLC(in_imported_PAC_filename->get_data_length());
	TPtr8 bufPtr = buf->Des();

	if (in_imported_PAC_filename->get_data_length() != 0)
		{
		bufPtr.Copy(in_imported_PAC_filename->get_data(), in_imported_PAC_filename->get_data_length());
		}

	eap_variable_data_c someVariableData(m_am_tools);

	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::complete_add_imported_PAC_file: Get ImportReference from database")));					

	EapTlsPeapUtils::GetEapSettingsDataL(
		m_database,
		m_index_type,
		m_index,
		m_tunneling_type,
		m_current_eap_type,
		KFASTPACGroupImportReferenceCollection,
		&someVariableData);

	HBufC8* ref = HBufC8::NewLC(someVariableData.get_data_length()); // must be defined to correct maxs dir length
	TPtr8 refPtr = ref->Des();
	if (someVariableData.get_data_length() != 0)
		{
		refPtr.Copy(someVariableData.get_data(),someVariableData.get_data_length());

		HBufC8* tempUserBuf8 = HBufC8::NewLC(someVariableData.get_data_length());
		TPtr8 tempUserBufPtr8 = tempUserBuf8->Des();
		
		for (int i = 0; i< someVariableData.get_data_length();i++ )
			{
			tempUserBufPtr8.Append(refPtr.Ptr()[i++]);
			}
		refPtr.Copy(tempUserBufPtr8);
	  	CleanupStack::PopAndDestroy(tempUserBuf8);

		}
	else
		{
		EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::complete_add_imported_PAC_file: NO ImportReference !!!!")));	
		}
	
	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::complete_add_imported_PAC_file: Set GroupDBReference to database")));					

	if (out_used_group_reference->get_data_length()>0 && someVariableData.get_data_length()>0)
		{
		someVariableData.set_copy_of_buffer(out_used_group_reference->get_data(),
				out_used_group_reference->get_data_length());
		
		EapTlsPeapUtils::SetEapSettingsDataL(
			m_database,
			m_index_type,
			m_index,
			m_tunneling_type,
			m_current_eap_type,
			KFASTPACGroupDBReferenceCollection,
			&someVariableData);
	
		}
	else
		{
		EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::complete_add_imported_PAC_file: NO GROUP REFERENCE !!!!")));	

		}
	
	HBufC* FilePath = HBufC::NewLC(KMaxFileName); // must be defined to correct maxs dir length
	TPtr FilePathPtr = FilePath->Des();
	HBufC8* FilePath8 = HBufC8::NewLC(KMaxFileName); // must be defined to correct maxs dir length
	TPtr8 FilePathPtr8 = FilePath8->Des();
	
	_LIT8(KPacStoreSourceDir, "c:\\private\\101f8ec5\\PACGroup\\"); // in dir are dirs where from files are read
	FilePathPtr8.Zero();
	FilePathPtr8.Append(KPacStoreSourceDir);
	FilePathPtr8.Append(refPtr);
	FilePathPtr8.Append(KSeparator);
	FilePathPtr8.Append(bufPtr);

	FilePathPtr.Copy(FilePathPtr8);

	EAP_TRACE_DATA_DEBUG(
   		m_am_tools,
   		TRACE_FLAGS_DEFAULT,
   		(EAPL("eap_am_type_tls_peap_symbian_c::complete_add_imported_PAC_file: Delete File"),
   		FilePathPtr.Ptr(),
   		FilePathPtr.Size()));

   	if(aFs.Delete(FilePathPtr)!= KErrNone)
   		{
   		EAP_TRACE_DATA_DEBUG(
   				m_am_tools,
   				TRACE_FLAGS_DEFAULT,
   				(EAPL("eap_am_type_tls_peap_symbian_c::complete_add_imported_PAC_file: Couldn't delete file"),
   						FilePathPtr.Ptr(),
   						FilePathPtr.Size()));


   		m_eap_fast_completion_status = eap_status_file_does_not_exist;
   		}

	CleanupStack::PopAndDestroy(FilePath8); 
	CleanupStack::PopAndDestroy(FilePath); 
	CleanupStack::PopAndDestroy(ref); 
	CleanupStack::PopAndDestroy(buf); 
	
	}


// ---------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::ContinueInitializePacStore()
// ---------------------------------------------------------
//
void eap_am_type_tls_peap_symbian_c::ContinueInitializePacStore()

	{
	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::ContinueInitializePacStore()")));

	TRAPD(error, CheckPasswordTimeValidityL());

	if(error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::ContinueInitializePacStore() ERROR: LEAVE from CheckPasswordTimeValidityL() error=%d"),
			error));
	}
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: %s: eap_am_type_tls_peap_symbian_c::ContinueInitializePacStore(): ")
		EAPL("this = 0x%08x\n"),
		(m_is_client == true ? "client": "server"),
		this));
	
	m_eap_fast_completion_status = eap_status_ok;

	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::ContinueInitializePacStore: Remove removed IAP references")));					

	m_eap_fast_completion_status = m_partner->set_timer(
			this,
			KRemoveIAPReferenceTimerID, 
			0,
			1);

	}

//--------------------------------------------------

// This is commented in eap_am_fast_pac_store_services_c::complete_remove_PAC().
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::complete_remove_PAC(
	const eap_status_e /* completion_status */,
	const eap_variable_data_c * const /* out_used_group_reference */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: %s: crypto_function: eap_am_type_tls_peap_symbian_c::complete_remove_PAC(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

// This is commented in eap_am_fast_pac_store_services_c::complete_remove_IAP_reference().
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::complete_remove_IAP_reference(
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: %s: crypto_function: eap_am_type_tls_peap_symbian_c::complete_remove_IAP_reference(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	eap_variable_data_c aIapReference(m_am_tools);
	if (aIapReference.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c aGroupReferenceCollection(m_am_tools);
	if (aGroupReferenceCollection.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// delete previously removed entry
	TRAPD(error, iPacStoreDb->RemoveTheFirstCleanupReferenceEntryL());
	
	if(error != KErrNone)
		{
			EAP_UNREFERENCED_PARAMETER(completion_status);
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::complete_remove_IAP_reference() ERROR: LEAVE from RemoveTheFirstCleanupReferenceEntryL error=%d"),
				error));
		
			m_eap_fast_completion_status = m_am_tools->convert_am_error_to_eapol_error(error);
		}

	TRAPD(error1, iPacStoreDb->GetTheFirstCleanupReferenceEntryL(
			&aIapReference,
			&aGroupReferenceCollection));

	if(error1 != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::complete_remove_IAP_reference() ERROR: LEAVE from GetTheFirstCleanupReferenceEntryL error=%d"),
			error1));
	
		m_eap_fast_completion_status = m_am_tools->convert_am_error_to_eapol_error(error1);
	}

	if ((aIapReference.get_data_length() > 0) && !m_completed_with_zero)
		{
		m_eap_fast_completion_status = m_partner->set_timer(
			this,
			KRemoveIAPReferenceTimerID, 
			0,
			1);
		
		if (m_eap_fast_completion_status != eap_status_ok)
			{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
			}
		}
	else if (m_completed_with_zero)
		{
		m_eap_fast_completion_status = m_partner->set_timer(
			this,
			KImportFileTimerID, // if nothing in db & remove_IAP_reference called already with 0 -> import
			0,
			1);
		
		if (m_eap_fast_completion_status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
			}
		}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
}

// This is commented in eap_am_fast_pac_store_services_c::cancel_PAC_store_operations().
EAP_FUNC_EXPORT eap_status_e eap_am_type_tls_peap_symbian_c::cancel_PAC_store_operations()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: %s: crypto_function: eap_am_type_tls_peap_symbian_c::cancel_PAC_store_operations(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_type_tls_peap_symbian_c::cancel_PAC_store_operations()");

	if(iPacStoreDb)
		iPacStoreDb->Cancel();


		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------


EAP_FUNC_EXPORT eap_status_e
eap_am_type_tls_peap_symbian_c::initialize_PAC_store(
	const eap_fast_completion_operation_e aCompletionOperation,
	const eap_fast_initialize_pac_store_completion_e aCompletion )
{
    EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
    EAP_TRACE_DEBUG(m_am_tools, 
	   TRACE_FLAGS_DEFAULT, 
	   (EAPL("eap_am_type_tls_peap_symbian_c::initialize_PAC_store IN\n")));
	
    iCompletionOperation = aCompletionOperation;
    iCompletion = aCompletion;

    TRAPD( err, FixOldTableForPacStoreInitL() );
    if ( err != KErrNone )
    	{
        EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, ( EAPL(
        	"ERROR: eap_am_type_tls_peap_symbian_c::initialize_PAC_store() \
        	Failed to fix table.\n" ) ) );
    	}

    if ( iPacStoreDb )
    	{
    	
    	TBool isInitialized = EFalse;
    	TRAP( err, isInitialized = iPacStoreDb->IsInitializedL() );
    	if ( err == KErrNone )
    		{
            if ( !isInitialized )
        	    {
		        EAP_TRACE_DEBUG_SYMBIAN(
			    (_L("eap_am_type_tls_peap_symbian_c::initialize_PAC_store(): PAC store initialized, erase memorystore")));	
		        m_tls_application->remove_cached_pac_store_data();
		        TRAP( err, iPacStoreDb->SetPacStoreInitValueL(
		    	    CPacStoreDatabase::EPacStoreInitialized ) );
		        if ( err != KErrNone )
		    	    {
			        EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::initialize_PAC_store(): ERROR: Leave in SetPacStoreInitValueL()")));	
		    	    }
        	    }
		    // asynch. call, return immediately
		    iPacStoreDb->CreateDeviceSeedAsynch();
		    }
    	else
    		{
	        EAP_TRACE_DEBUG_SYMBIAN( ( _L(
	        	"ERROR: eap_am_type_tls_peap_symbian_c::initialize_PAC_store(): Leave, IsInitializedL(), err=%d.\n"),
	        	err ) );	
    		
    		return m_am_tools->convert_am_error_to_eapol_error(err);
    		}
    	}
	
	m_eap_fast_completion_status = eap_status_pending_request;
		
	EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_am_type_tls_peap_symbian_c::initialize_PAC_store() OUT\n")));
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
}

// ---------------------------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::indicates_eap_fast_provisioning_starts
// ---------------------------------------------------------------------------
//  
EAP_FUNC_EXPORT
eap_status_e eap_am_type_tls_peap_symbian_c::indicates_eap_fast_provisioning_starts(
	const eap_fast_completion_operation_e provisioning_mode,
	const eap_fast_pac_type_e pac_type )
	{
	eap_status_e status( eap_status_ok );
	m_provisioning_mode = provisioning_mode; // save provis. mode
	
	TInt err = KErrNone;	
	if ( !iEapFastActiveWaitNote )
		{
		TRAP( err, iEapFastActiveWaitNote = CEapFastActive::NewL( this ) );
		}
	if ( !iEapFastActiveNotes )
		{
		TRAP( err, iEapFastActiveNotes = CEapFastActive::NewL( this ) );
		}
	if ( err != KErrNone )
		{
		status = eap_status_allocation_error;
		}	
	/**
	* The note is started in a separate active object.
	* When user cancels waiting note,
	* SendErrorNotification( eap_status_user_cancel_authentication )
	* will be called in iEapFastActiveWaitNote->RunL().
	* Otherwise note is stopped using iEapFastActiveWaitNote.Start() method.
	*/
	TBool startedOk = ETrue;
	
	if ( pac_type == eap_fast_pac_type_tunnel_pac
		 &&
		 provisioning_mode ==
		     eap_fast_completion_operation_server_authenticated_provisioning_mode
		 &&
		 status == eap_status_ok )
		{
		EAP_TRACE_DEBUG_SYMBIAN( ( _L("eap_am_type_tls_peap_symbian_c:: \
				indicates_eap_fast_provisioning_starts Authenticated provisioning!")));			
		startedOk = iEapFastActiveWaitNote->Start(
			CEapFastActive::EEapFastActiveStartAuthProvWaitNote );
		}
	else if (
		pac_type == eap_fast_pac_type_tunnel_pac
		&&
		provisioning_mode ==
	        eap_fast_completion_operation_server_unauthenticated_provisioning_mode_ADHP
	    &&
	    status == eap_status_ok )
		{
		EAP_TRACE_DEBUG_SYMBIAN(  (_L("eap_am_type_tls_peap_symbian_c:: \
			indicates_eap_fast_provisioning_starts UnAuthenticated provisioning!")));			
		startedOk = iEapFastActiveWaitNote->Start(
        	CEapFastActive::EEapFastActiveStartUnauthProvWaitNote );        
		}
	if ( startedOk == EFalse )
        {
        status = eap_status_process_general_error;
        }
	if ( status != eap_status_ok )
		{
	    EAP_TRACE_DEBUG_SYMBIAN( (_L("eap_am_type_tls_peap_symbian_c:: \
            indicates_eap_fast_provisioning_starts ERROR: status=%d."), status ) );
		}
	return status;
	}

// ---------------------------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::indicates_eap_fast_provisioning_ends
// ---------------------------------------------------------------------------
//  
EAP_FUNC_EXPORT
eap_status_e eap_am_type_tls_peap_symbian_c::indicates_eap_fast_provisioning_ends(
    const bool provisioning_successfull,
    const eap_fast_completion_operation_e provisioning_mode,
    const eap_fast_pac_type_e pac_type )
	{	
	EAP_TRACE_DEBUG_SYMBIAN( (_L("eap_am_type_tls_peap_symbian_c:: \
	    indicates_eap_fast_provisioning_ends()")));

	EAP_UNREFERENCED_PARAMETER(provisioning_mode);

	eap_status_e status( eap_status_ok );
	
	if ( pac_type == eap_fast_pac_type_tunnel_pac )
		{
	    // stop wait note;
		if ( iEapFastActiveWaitNote )
			{
			if ( iEapFastActiveWaitNote->IsActive() )
				{
				iEapFastActiveWaitNote->Cancel();
				}
			delete iEapFastActiveWaitNote;
			iEapFastActiveWaitNote = NULL;
			}

	    if ( iEapFastActiveNotes )
		    {	    
            if( provisioning_successfull )
		        {
		        // synch. call
		        iEapFastActiveNotes->Start( CEapFastActive::
		            EEapFastActiveShowProvSuccessNote, ETrue );
		        }
            else
      	        {
      	        // synch. call
      	        iEapFastActiveNotes->Start( CEapFastActive::
      	            EapFastActiveShowProvNotSuccessNote, ETrue );
      	        }
		    }
		} // if ( pac_type == eap_fast_pac_type_tunnel_pac )

	return status;
	}

#endif //#if defined(USE_FAST_EAP_TYPE)

#ifdef USE_PAC_STORE
	
void eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL(
	const eap_pac_store_data_type_e aPacStoreDataType,
	eap_variable_data_c * aPacStoreData,
	const eap_variable_data_c * const aPacStoreReference /*=NULL*/)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL Start aPacStoreDataType=%d"),
		aPacStoreDataType));	
	
	if(m_current_eap_type != eap_type_fast || iPacStoreDb == NULL)
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL ERROR: Unknown EAP type or No PAC store DB!")));
		
		// Can't proceed.
		User::Leave(KErrNotSupported);		
	}					
	
	TBuf<KMaxDBFieldNameLength> pacStoreDBColName;
	HBufC8* pacStoreDBColValBuf8(NULL);
	eap_status_e status(eap_status_ok);
	TInt error(KErrNone);
	TBuf<KDbMaxName> dbTableName;
	HBufC8* aDbBinaryColumnValue(NULL);
	
	switch(aPacStoreDataType)
	{		
		case eap_pac_store_data_type_PAC_store_master_key:
		{
			pacStoreDBColName.Copy(KPacStoreMasterKey);			
			pacStoreDBColValBuf8 = HBufC8::NewLC(KMaxMasterKeyLengthInDB);
			break;		
		}		
		case eap_pac_store_data_type_PAC_store_password:
		{
			pacStoreDBColName.Copy(cf_str_EAP_FAST_PAC_store_password_literal);			
			pacStoreDBColValBuf8 = HBufC8::NewLC(KMaxPasswordLengthInDB);			
			break;		
		}		
		case eap_pac_store_data_type_PAC_store_device_seed:
		{
			// Not in PAC store. This should not be called.

			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL ERROR: This is not in PAC store DB!")));
			
			return;		
		}		
		case eap_pac_store_data_type_PAC_store_IAP_reference:
		{
			// Not in PAC store. This should not be called.

			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL ERROR: This is not in PAC store DB!")));
			
			return;		
		}		
		case eap_pac_store_data_type_PAC_store_group_reference:
		{
			// Not in PAC store. This should not be called.

			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL ERROR: This is not in PAC store DB!")));
			
			return;		
		}		
		case eap_pac_store_data_type_reference_counter:
		{
			pacStoreDBColName.Copy(KPacStoreReferenceCounter);			
			pacStoreDBColValBuf8 = HBufC8::NewLC(KMaxRefCounterLengthInDB);			
			break;		
		}		
		case eap_pac_store_data_type_PAC_file_password:
		{
			// Not in PAC store. This should not be called.

			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL ERROR: This is not in PAC store DB!")));
			
			return;		
		}		
		case eap_pac_store_data_type_group_info:
		{
			dbTableName = KPacStoreGroupsTableName;
			break;		
		}		
		case eap_pac_store_data_type_A_ID_info:
		{
			dbTableName = KPacStoreAIDsTableName;
			break;		
		}		
		case eap_pac_store_data_type_PAC_info:
		{
			dbTableName = KPacStorePACsTableName;
			break;		
		}		
		case eap_pac_store_data_type_group_data:
		{
			// Memory for aDbBinaryColumnValue is allocated in CPacStoreDatabase::GetPacStoreDataL
			pacStoreDBColName.Copy(KPacStoreGroupValue);
			break;		
		}		
		case eap_pac_store_data_type_A_ID_data:
		{
			// Memory for aDbBinaryColumnValue is allocated in CPacStoreDatabase::GetPacStoreDataL
			pacStoreDBColName.Copy(KPacStoreAIDValue);
			break;		
		}		
		case eap_pac_store_data_type_PAC_data:
		{
			// Memory for aDbBinaryColumnValue is allocated in CPacStoreDatabase::GetPacStoreDataL
			pacStoreDBColName.Copy(KPacStorePACValue);
			break;		
		}		
		default:
		{
			break;		
		}
	} // End : switch(aPacStoreDataType)

	switch(aPacStoreDataType)
	{		
		case eap_pac_store_data_type_PAC_store_master_key:
		case eap_pac_store_data_type_PAC_store_password:
		case eap_pac_store_data_type_reference_counter:
		{
			TPtr8 pacStoreDBColValPtr8 = pacStoreDBColValBuf8->Des();
				
			TRAPD( err, iPacStoreDb->GetPacStoreDataL(pacStoreDBColName, pacStoreDBColValPtr8) );
			if ( err )
				{
				if(pacStoreDBColValBuf8 != NULL)
					{
						CleanupStack::PopAndDestroy(pacStoreDBColValBuf8);
						pacStoreDBColValBuf8 = NULL;
						User::Leave( err );
					}
				}
			
			status = aPacStoreData->set_copy_of_buffer(
				pacStoreDBColValPtr8.Ptr(),
				pacStoreDBColValPtr8.Size());
			
			error = m_am_tools->convert_eapol_error_to_am_error(status);
			break;
		}
		case eap_pac_store_data_type_group_data:
		case eap_pac_store_data_type_A_ID_data:
		case eap_pac_store_data_type_PAC_data:
		{
			EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL: To get GROUP, PAC or AID data")));			
			
			
			if(aPacStoreReference == NULL )//|| aPacStoreReference->get_data_length() <= 0)
			{
				EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL ERROR: Empty reference")));
				
				// Can't proceed.
				User::Leave(KErrArgument);		
			}								
			if ( aPacStoreReference->get_data_length() <= 0 )
				{
				EAP_TRACE_DEBUG_SYMBIAN(
					(_L("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL reset aPacStoreData.")));				
				aPacStoreData->reset();
				break;
				}
			
			
			HBufC8 * reference8 = HBufC8::NewLC(aPacStoreReference->get_data_length());
			TPtr8 referencePtr8 = reference8->Des();
						
			referencePtr8.Copy(aPacStoreReference->get_data(),
					aPacStoreReference->get_data_length());
	
			EAP_TRACE_DATA_DEBUG_SYMBIAN(
			("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL: reference to DB",
			referencePtr8.Ptr(), 
			referencePtr8.Size()));	
			
			TPtr8 pacStoreDBColDataValPtr8(0,0);
					
			TRAPD( err, iPacStoreDb->GetPacStoreDataL(pacStoreDBColName, pacStoreDBColDataValPtr8, referencePtr8, &aDbBinaryColumnValue) );
			if ( err )
				{
				CleanupStack::PopAndDestroy(1); // reference8.
				if(pacStoreDBColValBuf8 != NULL)
					{
						CleanupStack::PopAndDestroy(pacStoreDBColValBuf8);
						pacStoreDBColValBuf8 = NULL;
						delete (aDbBinaryColumnValue);
						User::Leave( err );
					}
				}
			
			
			CleanupStack::PopAndDestroy(1); // reference8.
			
			if (aDbBinaryColumnValue != NULL)
				{
				TPtr8 aDbBinaryColumnValuePtr = aDbBinaryColumnValue->Des();
			 
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL, data size=%d"),
								aDbBinaryColumnValuePtr.Size()));	
				
				if (aDbBinaryColumnValuePtr.Size() > 0)
					{
					status = aPacStoreData->set_copy_of_buffer(
						aDbBinaryColumnValuePtr.Ptr(),
						aDbBinaryColumnValuePtr.Size());
					}
				else
					{
					EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::No data to fill !!")));	
				
					}
				delete (aDbBinaryColumnValue);
				}
			else
				{
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::Data NULL !!")));	
				}
			
			error = m_am_tools->convert_eapol_error_to_am_error(status);
			
			delete (pacStoreDBColDataValPtr8.Ptr());

			break;
		}	
		case eap_pac_store_data_type_group_info:
		case eap_pac_store_data_type_A_ID_info:
		case eap_pac_store_data_type_PAC_info:
		{
			
			EAP_TRACE_DEBUG_SYMBIAN(
					(_L("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL:ERROR: Calls for INFOs should not come here !!!")));
			
			break;
		}		
		default:
		{
			EAP_TRACE_DEBUG_SYMBIAN(
					(_L("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL - UNSUPPORTED Column !!!")));
			
			break;		
		}
	}// End: switch(aPacStoreDataType)	
		
	if(pacStoreDBColValBuf8 != NULL)
	{
		CleanupStack::PopAndDestroy(pacStoreDBColValBuf8);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::GetPacStoreDbDataL-End")));
	
	User::LeaveIfError(error); // This could be success or error. Does't matter.	
}
	
#endif	// End: #ifdef USE_PAC_STORE

//--------------------------------------------------

#if defined(USE_FAST_EAP_TYPE)

eap_status_e eap_am_type_tls_peap_symbian_c::ShowNotifierItemAndGetResponse(
	EEapFastNotifierUiItem aNotifierUiItem, TBool aSetActive )
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::ShowNotifierItem aNotifierUiItem=%d, ActiveStatus=%d "),
		aNotifierUiItem, IsActive()));

	if ( aSetActive && IsActive() )
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("ShowNotifierItemAndGetResponse: Already active when tried to show Notifier")));		
		
		return eap_status_device_busy;
	}
	
	eap_status_e status( eap_status_ok );
	
	if( !m_is_notifier_connected )
	{
		TInt error = m_notifier.Connect();
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::ShowNotifierItem - m_notifier.Connect() returned error=%d\n"), error));
		
		if( error != KErrNone)
		{
			// Can not connect to notifier.
			return m_am_tools->convert_am_error_to_eapol_error(error);		
		}
		
		m_is_notifier_connected = ETrue; // Got connectted to notifier.
	}
	
	// Update the values needed for notifier.
	m_notifier_data_to_user->iEapFastNotifierUiItem = aNotifierUiItem;
			
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("m_notifier_data_pckg_to_user"),
		m_notifier_data_pckg_to_user->Ptr(),
		m_notifier_data_pckg_to_user->Size()));
			
	m_notifier_data_from_user->iEapFastNotifierBuffer.Delete(0,KMaxEapFastNotifierBufLength);
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::ShowNotifierItem - StartNotifierAndGetResponse")));

	m_notifier.StartNotifierAndGetResponse(
		iStatus, 
		KEapFastNotifierUid, 
		*m_notifier_data_pckg_to_user, 
		*m_notifier_data_pckg_from_user);
	
	if ( aSetActive )
		{
		m_notifier_complete = ETrue;
		SetActive();
		}
	    
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::ShowNotifierItem - End")));

	return status;
}

//--------------------------------------------------

eap_status_e eap_am_type_tls_peap_symbian_c::RemoveIAPReference()
	{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::RemoveIAPReference - Start")));
	m_eap_fast_completion_status = eap_status_ok;	
			
	eap_variable_data_c aIapReference(m_am_tools);
	if (aIapReference.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c aGroupReferenceCollection(m_am_tools);
	if (aGroupReferenceCollection.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	TRAPD(error, iPacStoreDb->GetTheFirstCleanupReferenceEntryL(
			&aIapReference,
			&aGroupReferenceCollection));

	if(error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::RemoveIAPReference() ERROR: LEAVE from GetTheFirstCleanupReferenceEntryL error=%d"),
			error));
	
		m_eap_fast_completion_status = m_am_tools->convert_am_error_to_eapol_error(error);
	}
	
	if (aIapReference.get_data_length() > 0)
		{
		eap_fast_pac_store_data_c * const group_reference_and_data = new eap_fast_pac_store_data_c(m_am_tools);
	
	
		m_eap_fast_completion_status = group_reference_and_data->get_writable_data()->set_copy_of_buffer(aGroupReferenceCollection.get_data(), aGroupReferenceCollection.get_data_length());
	
		if (aIapReference.get_data_length() > 0)
			m_completed_with_zero = EFalse;
		else
			m_completed_with_zero = ETrue;
			
		
			if (m_eap_fast_completion_status == eap_status_ok)
			{
			m_eap_fast_completion_status = m_tls_application->remove_IAP_reference(
					&aIapReference,
					group_reference_and_data);
			}
		}
	else
		{
		m_eap_fast_completion_status = m_partner->set_timer(
				this,
				KImportFileTimerID, // if nothing in db, go right to file read 
				0,
				1);
		}
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::RemoveIAPReference - End")));
		
	return m_eap_fast_completion_status;
	}

eap_status_e eap_am_type_tls_peap_symbian_c::ImportFilesL()
	{

	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL - Start")));
	
	CDir* files;
		 
	RFs aFs;
	aFs.Connect( KFileServerDefaultMessageSlots );

	m_eap_fast_completion_status = eap_status_pending_request;
	
	TBool aSuccess = EFalse;
	
	eap_variable_data_c ImportReference(m_am_tools);

	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL: Get ImportReference from database")));					

	EapTlsPeapUtils::GetEapSettingsDataL(
		m_database,
		m_index_type,
		m_index,
		m_tunneling_type,
		m_current_eap_type,
		KFASTPACGroupImportReferenceCollection,
		&ImportReference);

	HBufC8* group_reference8 = HBufC8::NewLC(KMaxFileName);
	TPtr8 group_referencePtr8 = group_reference8->Des();
	
	EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_tls_peap_symbian_c::ImportFilesL: ImportReference"),
					ImportReference.get_data(),
					ImportReference.get_data_length()));

	if (ImportReference.get_data_length() != 0)
		{
		group_referencePtr8.Copy(ImportReference.get_data(), ImportReference.get_data_length());
		EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_type_tls_peap_symbian_c::ImportFilesL: Reference"),
						group_referencePtr8.Ptr(),
						group_referencePtr8.Size()));
						
		}
	else
		{
 	   	m_eap_fast_completion_status = m_partner->set_timer(
                this,
                KHandleCompletePacstoreOkTimerID, 
                &m_eap_fast_completion_status,
                1);

 	   	CleanupStack::PopAndDestroy(group_reference8);
 	   	
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
		}
	
	HBufC8* tempUserBuf8 = HBufC8::NewLC(ImportReference.get_data_length());
	TPtr8 tempUserBufPtr8 = tempUserBuf8->Des();
	for (int i = 0; i< ImportReference.get_data_length();i++ )
		{
		tempUserBufPtr8.Append(group_referencePtr8.Ptr()[i++]);
		}
	group_referencePtr8.Copy(tempUserBufPtr8);
  	CleanupStack::PopAndDestroy(tempUserBuf8);

	EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_tls_peap_symbian_c::ImportFilesL: Reformatted Reference"),
					group_referencePtr8.Ptr(),
					group_referencePtr8.Size()));
	TInt fileCounter=0;
	TBool directoryEmpty = false;
	TBool directoryExists = true;
	HBufC* buf2 = HBufC::NewLC(KMaxPath);
	HBufC8* filename8 = HBufC8::NewLC(KMaxFileName);
	TPtr FileNamePtr = buf2->Des();
	TUint filesize =0;
	TPtr8 filenamePtr8 = filename8->Des();
	TBool badFile = false;
	HBufC* Path = HBufC::NewLC(KMaxFileName);
	TPtr PathPtr = Path->Des();
	HBufC8* Path8 = HBufC8::NewLC(KMaxFileName);
	TPtr8 PathPtr8 = Path8->Des();
	HBufC8* readData = NULL;
	TBool FileFound(EFalse);
	
	PathPtr8.Zero();
	PathPtr8.Append(KPacStoreSourceDir);
	PathPtr8.Append(group_referencePtr8);
	PathPtr8.Append(KSeparator);
	EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_tls_peap_symbian_c::ImportFilesL: Path8"),
			PathPtr8.Ptr(),
			PathPtr8.Size()));
	PathPtr.Zero();
	PathPtr.Copy(PathPtr8);
	
	EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_tls_peap_symbian_c::ImportFilesL: Path"),
			PathPtr.Ptr(),
			PathPtr.Size()));
			
	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL: Check directory availability")));					

	if (aFs.GetDir(PathPtr, KEntryAttNormal, ESortByName, files) == KErrNone)
		{
		EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL: Files %d"),
						files->Count()));
		
		while (!FileFound && (fileCounter < files->Count()))
			{
			directoryExists = true;
			
			EAP_TRACE_DEBUG_SYMBIAN(
					(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL: Get directory contents")));					

			directoryEmpty = false;

			while( fileCounter < files->Count() || (!FileFound))
				{
				if (!((*files)[fileCounter].IsDir()))
					{
					filesize = (*files)[fileCounter].iSize;
					EAP_TRACE_DEBUG_SYMBIAN(
							(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL: File size %d"),
									filesize));
					filenamePtr8.Copy((*files)[fileCounter++].iName);
					EAP_TRACE_DATA_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("eap_am_type_tls_peap_symbian_c::ImportFilesL: Filename"),
							filenamePtr8.Ptr(),
							filenamePtr8.Size()));
					FileFound = ETrue;
					}
				else
					{
					fileCounter++;
					}
				}
			
			if (!FileFound)
				{
				EAP_TRACE_DEBUG_SYMBIAN(
					(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL: DirectoryEmpty")));					
				directoryEmpty = true;
				}

			if (directoryEmpty == true ||  directoryExists == false || FileFound == EFalse)
				{
				if (directoryExists)
					{
					EAP_TRACE_DEBUG_SYMBIAN(
							(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL: We would remove directory")));					
					
				   		{
				           m_eap_fast_completion_status = m_partner->set_timer(
				                    this,
				                    KHandleCompletePacstoreOkTimerID, 
				                    &m_eap_fast_completion_status,
				                    1);
					   	if (readData != NULL)
					   		CleanupStack::PopAndDestroy(readData);
					   	CleanupStack::PopAndDestroy(5); // Path, Path8, filename, buf2, group_reference8
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
				   		}
					}
				}
			else if(directoryEmpty == false &&  directoryExists == true && FileFound != EFalse)
				{
				PathPtr8.Zero();
				PathPtr8.Append(KPacStoreSourceDir);
				PathPtr8.Append(group_referencePtr8);
				PathPtr8.Append(KSeparator);
				PathPtr8.Append(filenamePtr8);
				EAP_TRACE_DATA_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("eap_am_type_tls_peap_symbian_c::ImportFilesL: Path8"),
						PathPtr8.Ptr(),
						PathPtr8.Size()));
				PathPtr.Zero();
				PathPtr.Copy(PathPtr8);
				
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL: Read file")));	
				
				RFile file;
				if(file.Open(aFs, PathPtr, EFileRead)==KErrNone)
					{
					readData= HBufC8::NewLC(filesize); 
					TPtr8 readDataPtr = readData->Des();
					file.Read(readDataPtr);
					file.Close();
					
					EAP_TRACE_DEBUG_SYMBIAN(
							(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL: Copy data")));	
					
					eap_variable_data_c * const in_imported_PAC_data = new eap_variable_data_c(m_am_tools);
					// eap_automatic_variable_c can be used in this block because no functions are leaving here.
					eap_automatic_variable_c<eap_variable_data_c> automatic_in_imported_PAC_data(m_am_tools, in_imported_PAC_data);
					if (in_imported_PAC_data == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					m_eap_fast_completion_status = in_imported_PAC_data->set_copy_of_buffer(readDataPtr.Ptr(), readDataPtr.Size());

					eap_fast_pac_store_data_c * const in_opt_group_reference_and_data = new eap_fast_pac_store_data_c(m_am_tools);
					// eap_automatic_variable_c can be used in this block because no functions are leaving here.
					eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_in_opt_group_reference_and_data(m_am_tools, in_opt_group_reference_and_data);
					if (in_opt_group_reference_and_data == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					in_opt_group_reference_and_data->get_writable_data()->set_copy_of_buffer(readDataPtr.Ptr(), readDataPtr.Size());

					eap_variable_data_c * const in_imported_PAC_filename = new eap_variable_data_c(m_am_tools);
					// eap_automatic_variable_c can be used in this block because no functions are leaving here.
					eap_automatic_variable_c<eap_variable_data_c> automatic_in_imported_PAC_filename(m_am_tools, in_imported_PAC_filename);
					if (in_imported_PAC_filename == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					m_eap_fast_completion_status = in_imported_PAC_filename->set_copy_of_buffer(filenamePtr8.Ptr(), filenamePtr8.Size());
					

					eap_variable_data_c IAP_reference(m_am_tools);
					if (IAP_reference.get_is_valid() == false)
						{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
						}
			
					u32_t reference[] = {1ul, 2ul};
					
					if (IAP_reference.get_data_length() != 0)
						m_eap_fast_completion_status = IAP_reference.set_copy_of_buffer(reference, sizeof(reference));
					else
						m_eap_fast_completion_status = IAP_reference.set_copy_of_buffer(EAP_FAST_ZERO_REFERENCE, sizeof(EAP_FAST_ZERO_REFERENCE));
						
					EAP_TRACE_DEBUG_SYMBIAN(
							(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL: Complete operation")));	
					
					if (m_eap_fast_completion_status != eap_status_ok)
						{
					   	if (readData != NULL)
							{
					   		CleanupStack::PopAndDestroy(readData);
							}
					   	CleanupStack::PopAndDestroy(5); // filename, buf2, group_reference8, Path, path8
					   	delete files;
						return EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
						}
					else
					    {
						m_eap_fast_completion_status = m_tls_application->add_imported_PAC_file(
							&IAP_reference,
							in_opt_group_reference_and_data,
							in_imported_PAC_data,
							in_imported_PAC_filename);
						aSuccess = ETrue;
					    }
					}
				}
			else
				{
				badFile = true;
				}
			}
		}
	else
		{
		EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL: No Directory")));					
		directoryExists = false;
		}
	
   	if (readData != NULL)
		{
   		CleanupStack::PopAndDestroy(readData);
		}
	CleanupStack::PopAndDestroy(5); // Path, filename8, buf2, Path8, group_reference8

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL: Operation failed or Complete")));	

	delete files;
	
	if (m_eap_fast_completion_status != eap_status_pending_request || aSuccess == EFalse)
		{
		if(badFile == true || directoryEmpty == true ||  directoryExists == false)   	
			{
			if (aSuccess == EFalse)
			    m_eap_fast_completion_status = eap_status_ok;
	        m_eap_fast_completion_status = m_partner->set_timer(
	                this,
	                KHandleCompletePacstoreNokTimerID, 
	                &m_eap_fast_completion_status,
	                1);
			}
		else
			{
		       m_eap_fast_completion_status = m_partner->set_timer(
		                this,
		                KHandleCompletePacstoreOkTimerID, 
		                &m_eap_fast_completion_status,
		                1);
			}
		}
	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::ImportFilesL - End")));

	return m_eap_fast_completion_status;
	}

// ----------------------------------------------------------------------------
eap_status_e eap_am_type_tls_peap_symbian_c::PasswordQueryL()
	{

	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::PasswordQueryL")));

	m_pacStorePWBuf8 = HBufC8::NewLC(m_userResponse.get_data_length());
	TPtr8 pacStorePWPtr8 = m_pacStorePWBuf8->Des();
	pacStorePWPtr8.Copy(m_userResponse.get_data(),m_userResponse.get_data_length() );
	m_PAC_store_password.set_copy_of_buffer(m_userResponse.get_data(), m_userResponse.get_data_length());
	EAP_TRACE_DATA_DEBUG_SYMBIAN(
	("eap_am_type_tls_peap_symbian_c::PasswordQueryL:PW used for masterkey verification (8bits)",
			pacStorePWPtr8.Ptr(), 
			pacStorePWPtr8.Size()));	    
   

    if (iPacStoreDb->IsMasterKeyPresentL() && pacStorePWPtr8.Size()>0 )
   	    m_verificationStatus = iPacStoreDb->IsMasterKeyAndPasswordMatchingL(pacStorePWPtr8);
   	
   	if ((pacStorePWPtr8.Size()==0 && (m_state == EPasswordQuery || m_state == EMasterkeyQuery ))
   			|| m_userAction == EEapFastNotifierUserActionCancel || m_state == EPasswordCancel)
   		{
    	m_verificationStatus = EFalse;
    	m_state = EPasswordCancel;
    	CleanupStack::PopAndDestroy(m_pacStorePWBuf8);
   	
   		m_eap_fast_completion_status = m_partner->set_timer(
				this,
				KHandleReadPacstoreTimerID, 
				&m_eap_fast_completion_status,
				0);
		return m_eap_fast_completion_status;
 		}
   	
   	EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST:eap_am_type_tls_peap_symbian_c::PasswordQueryL:State:%d Prev_State:%d verificationstatus:%d"),
					m_state, 
					m_prev_state,
					m_verificationStatus));
	
	eap_status_e m_eap_fast_completion_status(eap_status_ok);
	
	  if (m_state == EPasswordQuery)
		  {
		  m_state = EWrongPassword;

		  if(m_verificationStatus == EFalse)
	    	{
	    	CleanupStack::PopAndDestroy(m_pacStorePWBuf8);
	    	
	    	m_eap_fast_completion_status = ShowNotifierItemAndGetResponse(
	    		EEapFastNotifierWrongPacStorePwNote, ETrue );
			return m_eap_fast_completion_status;
			 	    
	    	}
		  else
	    	{
			m_eap_fast_completion_status = m_partner->set_timer(
					this,
					KHandleReadPacstoreTimerID, 
					&m_eap_fast_completion_status,
					0);

			CleanupStack::PopAndDestroy(m_pacStorePWBuf8);
	  		return m_eap_fast_completion_status;
	    	}
		  }
	  if (m_state == EWrongPassword)
    	{
        	m_state = EPasswordQuery;
 
       	EAP_TRACE_DEBUG(
    			m_am_tools,
    			TRACE_FLAGS_DEFAULT,
    			(EAPL("EAP-FAST:eap_am_type_tls_peap_symbian_c::PasswordQueryL (first pw ?):State:%d Prev_State:%d verificationstatus:%d"),
    					m_state, 
    					m_prev_state,
    					m_verificationStatus));
       	pacStorePWPtr8.Zero();
       	if (m_verificationStatus == EFalse)
			m_eap_fast_completion_status = ShowNotifierItemAndGetResponse(
				EEapFastNotifierPacStorePwQuery, ETrue );
		else
			m_eap_fast_completion_status = m_partner->set_timer(
				this,
				KHandleReadPacstoreTimerID, 
				&m_eap_fast_completion_status,
				0);
		
		CleanupStack::PopAndDestroy(m_pacStorePWBuf8);
		return m_eap_fast_completion_status;
    	}

    if (m_PAC_store_password.get_data_length()>0 && m_state == EMasterkeyQuery)
    	{
    	
    	if ( m_verificationStatus != EFalse)
    		{
    		EAP_TRACE_DEBUG_SYMBIAN(
    			(_L("eap_am_type_tls_peap_symbian_c::PasswordQueryL - EMasterkeyQuery - OK")));
    		}
     	else // temporary before masterkey creation is done dynamically !!!
    		{
        	m_eap_fast_completion_status = ShowNotifierItemAndGetResponse(
        			EEapFastNotifierCreateMasterkeyQuery, ETrue );
   		
			}
    	}

    CleanupStack::PopAndDestroy(m_pacStorePWBuf8);
    
	return m_eap_fast_completion_status;
	}

eap_status_e eap_am_type_tls_peap_symbian_c::CompletePasswordQueryL()
	{

	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::CompletePasswordQueryL")));

	// m_PAC_store_password should have the PW now. Proceed as normal case.	
	
	eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);

	eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
		m_am_tools, new_data);

	if (new_data == 0)
	{
		m_eap_fast_completion_status = eap_status_allocation_error;
		(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
		return m_eap_fast_completion_status;
	}
	//eap_pac_store_data_type_PAC_store_password
	EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::CompletePasswordQueryL()Datatype=%d"),
					m_pacStoreDataRefType));
	
	EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::CompletePasswordQueryL()Reference=%d"),
					m_data_reference.get_reference()->get_data(m_data_reference.get_reference()->get_data_length())));

	EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::CompletePasswordQueryL()Data=%d"),
					m_PAC_store_password.get_data(m_PAC_store_password.get_data_length())));

	new_data->set_type(eap_pac_store_data_type_PAC_store_password); //m_pacStoreDataRefType

	// Set the reference. 
	m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(m_data_reference.get_reference());
	if (m_eap_fast_completion_status != eap_status_ok)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
		return m_eap_fast_completion_status;
	}					
	
	if(m_PAC_store_password.get_data_length() >0)
		m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(&m_PAC_store_password);
	if (m_eap_fast_completion_status != eap_status_ok)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
		return m_eap_fast_completion_status;
	}

	automatic_new_data.do_not_free_variable();

	m_eap_fast_completion_status = m_new_references_and_data_blocks.add_object(new_data, true); // m_ready_references_and_data_blocks
	
	if (m_eap_fast_completion_status != eap_status_ok)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
	
	EAP_TRACE_DATA_DEBUG_SYMBIAN(
		("EAP-FAST: eap_am_type_tls_peap_symbian_c::CompletePasswordQueryL eap_pac_store_data_type_PAC_store_password - added data",
		(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
		(new_data->get_data())->get_data_length()));
	return m_eap_fast_completion_status;
	}

	m_both_completed++;

	return m_eap_fast_completion_status;
	}

eap_status_e eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL(eap_status_e status)
	{
	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL")));
	if (status == eap_status_ok && (m_new_references_and_data_blocks.get_object_count()>0))
		{
		for (u32_t ind = 0ul; ind < m_ready_references_array_index; ++ind)
			{
			eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);
	
			eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
				m_am_tools, new_data);
	
			if (new_data == 0)
			{
				m_eap_fast_completion_status = eap_status_allocation_error;
				(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
	
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
				m_ready_references_and_data_blocks.reset();
				eap_status_e status = m_tls_application->complete_read_PAC_store_data(
					m_eap_fast_completion_status,
					m_eap_fast_pac_store_pending_operation,
					&m_references_and_data_blocks);
				
				return status;
			}
	
			new_data->set_type(m_references_and_data_blocks.get_object(ind)->get_type());
			
			// Set the reference.
			m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(m_references_and_data_blocks.get_object(ind)->get_reference());
			if (m_eap_fast_completion_status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
				m_ready_references_and_data_blocks.reset();
				eap_status_e status = m_tls_application->complete_read_PAC_store_data(
					m_eap_fast_completion_status,
					m_eap_fast_pac_store_pending_operation,
					&m_references_and_data_blocks);
				
				return status;
			}					
	
			m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(m_references_and_data_blocks.get_object(ind)->get_data());
			if (m_eap_fast_completion_status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
				m_ready_references_and_data_blocks.reset();
				eap_status_e status = m_tls_application->complete_read_PAC_store_data(
					m_eap_fast_completion_status,
					m_eap_fast_pac_store_pending_operation,
					&m_references_and_data_blocks);
				
				return status;
			}
	
			automatic_new_data.do_not_free_variable();
	
			m_eap_fast_completion_status = m_ready_references_and_data_blocks.add_object(new_data, true);
			if (m_eap_fast_completion_status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
				m_ready_references_and_data_blocks.reset();
				eap_status_e status = m_tls_application->complete_read_PAC_store_data(
					m_eap_fast_completion_status,
					m_eap_fast_pac_store_pending_operation,
					&m_references_and_data_blocks);
				
				return status;
			}
			
			EAP_TRACE_DATA_DEBUG_SYMBIAN(
				("Final_complete_read_PAC_store_data - added original data",
				(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
				(new_data->get_data())->get_data_length()));										
			
			}
	
		eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);
	
		eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
			m_am_tools, new_data);
	
		if (new_data == 0)
		{
			m_eap_fast_completion_status = eap_status_allocation_error;
			(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
			EAP_TRACE_DEBUG_SYMBIAN(
					(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
			m_ready_references_and_data_blocks.reset();
			eap_status_e status = m_tls_application->complete_read_PAC_store_data(
				m_eap_fast_completion_status,
				m_eap_fast_pac_store_pending_operation,
				&m_references_and_data_blocks);
			
			return status;
		}
	
		new_data->set_type(m_new_references_and_data_blocks.get_object(m_ready_references_array_index)->get_type());
		
		// Set the reference.
		m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(m_new_references_and_data_blocks.get_object(m_ready_references_array_index)->get_reference());
		if (m_eap_fast_completion_status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
			EAP_TRACE_DEBUG_SYMBIAN(
					(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
			m_ready_references_and_data_blocks.reset();
			eap_status_e status = m_tls_application->complete_read_PAC_store_data(
				m_eap_fast_completion_status,
				m_eap_fast_pac_store_pending_operation,
				&m_references_and_data_blocks);
			
			return status;
		}					
	
		m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(m_new_references_and_data_blocks.get_object(m_ready_references_array_index)->get_data());
		if (m_eap_fast_completion_status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
			EAP_TRACE_DEBUG_SYMBIAN(
					(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
			m_ready_references_and_data_blocks.reset();
			eap_status_e status = m_tls_application->complete_read_PAC_store_data(
				m_eap_fast_completion_status,
				m_eap_fast_pac_store_pending_operation,
				&m_references_and_data_blocks);
			
			return status;
		}
	
		automatic_new_data.do_not_free_variable();
	
		m_eap_fast_completion_status = m_ready_references_and_data_blocks.add_object(new_data, true);
		if (m_eap_fast_completion_status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
			EAP_TRACE_DEBUG_SYMBIAN(
					(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
			m_ready_references_and_data_blocks.reset();
			eap_status_e status = m_tls_application->complete_read_PAC_store_data(
				m_eap_fast_completion_status,
				m_eap_fast_pac_store_pending_operation,
				&m_references_and_data_blocks);
			
			return status;
		}
		
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
			("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL - added extra data",
			(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
			(new_data->get_data())->get_data_length()));										
	
		
		for (u32_t ind = m_ready_references_array_index; ind < m_references_and_data_blocks.get_object_count(); ++ind)
			{
			eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);
	
			eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
				m_am_tools, new_data);
	
			if (new_data == 0)
			{
				m_eap_fast_completion_status = eap_status_allocation_error;
				(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
				m_ready_references_and_data_blocks.reset();
				eap_status_e status = m_tls_application->complete_read_PAC_store_data(
					m_eap_fast_completion_status,
					m_eap_fast_pac_store_pending_operation,
					&m_references_and_data_blocks);
				
				return status;
			}
	
			new_data->set_type(m_references_and_data_blocks.get_object(ind)->get_type());
			
			// Set the reference.
			m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(m_references_and_data_blocks.get_object(ind)->get_reference());
			if (m_eap_fast_completion_status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
				m_ready_references_and_data_blocks.reset();
				eap_status_e status = m_tls_application->complete_read_PAC_store_data(
					m_eap_fast_completion_status,
					m_eap_fast_pac_store_pending_operation,
					&m_references_and_data_blocks);
				
				return status;
			}					
	
			m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(m_references_and_data_blocks.get_object(ind)->get_data());
			if (m_eap_fast_completion_status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
				m_ready_references_and_data_blocks.reset();
				eap_status_e status = m_tls_application->complete_read_PAC_store_data(
					m_eap_fast_completion_status,
					m_eap_fast_pac_store_pending_operation,
					&m_references_and_data_blocks);
				
				return status;
			}
	
			automatic_new_data.do_not_free_variable();
	
			m_eap_fast_completion_status = m_ready_references_and_data_blocks.add_object(new_data, true);
			if (m_eap_fast_completion_status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
				m_ready_references_and_data_blocks.reset();
				eap_status_e status = m_tls_application->complete_read_PAC_store_data(
					m_eap_fast_completion_status,
					m_eap_fast_pac_store_pending_operation,
					&m_references_and_data_blocks);
				
				return status;
			}
			
			EAP_TRACE_DATA_DEBUG_SYMBIAN(
				("Final_complete_read_PAC_store_data - added original data",
				(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
				(new_data->get_data())->get_data_length()));										
			}
		
		if (status == eap_status_ok)
			{
			EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL: index=%d, original objects=%d, new=%d total=%d"),
							m_ready_references_array_index,
							m_references_and_data_blocks.get_object_count(),
							 m_new_references_and_data_blocks.get_object_count(),
							 m_ready_references_and_data_blocks.get_object_count())); 
			
	
			EAP_TRACE_DEBUG_SYMBIAN(
					(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL Reset unsent data")));
			
		m_references_and_data_blocks.reset();
		m_new_references_and_data_blocks.reset();

		EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL Reset Done")));
		
		eap_status_e status = m_tls_application->complete_read_PAC_store_data(
			m_eap_fast_completion_status,
			m_eap_fast_pac_store_pending_operation,
			&m_ready_references_and_data_blocks);
		}
	else
		{
		EAP_TRACE_DEBUG_SYMBIAN(
				(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
		m_eap_fast_completion_status = eap_status_user_cancel_authentication;
		m_new_references_and_data_blocks.reset();
		m_ready_references_and_data_blocks.reset();
		eap_status_e status = m_tls_application->complete_read_PAC_store_data(
			m_eap_fast_completion_status,
			m_eap_fast_pac_store_pending_operation,
			&m_references_and_data_blocks);
		}
		}
	else
	{
	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL:status nok")));
	m_eap_fast_completion_status = eap_status_user_cancel_authentication;
	m_new_references_and_data_blocks.reset();
	m_ready_references_and_data_blocks.reset();
	eap_status_e status = m_tls_application->complete_read_PAC_store_data(
		m_eap_fast_completion_status,
		m_eap_fast_pac_store_pending_operation,
		&m_references_and_data_blocks);
	}
	
	TRAPD(error, UpdatePasswordTimeL());

	if(error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::FinalCompleteReadPACStoreDataL ERROR: LEAVE from UpdatePasswordTimeL() error=%d"),
			error));
	}
	return status;
}

//--------------------------------------------------

eap_status_e eap_am_type_tls_peap_symbian_c::CompleteFilePasswordQueryL()
	{
	eap_fast_pac_store_data_c * const new_data = new eap_fast_pac_store_data_c(m_am_tools);

	eap_automatic_variable_c<eap_fast_pac_store_data_c> automatic_new_data(
		m_am_tools, new_data);

	if (new_data == 0)
	{
		m_eap_fast_completion_status = eap_status_allocation_error;
		(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
		return m_eap_fast_completion_status;
	}

	
	EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::CompleteFilePasswordQueryL()Datatype=%d"),
					m_pacStoreDataRefType));
	
	new_data->set_type(eap_pac_store_data_type_PAC_file_password); //m_pacStoreDataRefType
	
	EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::CompleteFilePasswordQueryL()Reference=%d"),
					m_data_reference.get_reference()->get_data(m_data_reference.get_reference()->get_data_length())));

	// Set the reference.
	m_eap_fast_completion_status = new_data->get_writable_reference()->set_copy_of_buffer(m_data_reference.get_reference());
	
	if (m_eap_fast_completion_status != eap_status_ok)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
		return m_eap_fast_completion_status;
	}					
	m_eap_fast_completion_status = new_data->get_writable_data()->set_copy_of_buffer(&m_userResponse);					

	if (m_eap_fast_completion_status != eap_status_ok)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
		return m_eap_fast_completion_status;
	}

	automatic_new_data.do_not_free_variable();


	m_eap_fast_completion_status = m_new_references_and_data_blocks.add_object(new_data, true); // m_ready_references_and_data_blocks
	if (m_eap_fast_completion_status != eap_status_ok)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, m_eap_fast_completion_status);
		return m_eap_fast_completion_status;
	}
	
	EAP_TRACE_DATA_DEBUG_SYMBIAN(
		("EAP-FAST: eap_am_type_tls_peap_symbian_c::CompleteFilePasswordQueryL eap_pac_store_data_type_PAC_file_password - added data",
		(new_data->get_data())->get_data((new_data->get_data())->get_data_length()), 
		(new_data->get_data())->get_data_length()));
	
	m_both_completed++;
	return m_eap_fast_completion_status;

	}

// ---------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::CompleteNotifier
// ---------------------------------------------------------
//    
eap_status_e eap_am_type_tls_peap_symbian_c::CompleteNotifierL()
	{
	eap_status_e status( eap_status_ok );
	switch ( m_state )
	    {
	    case EPasswordCancel:
	    case EPasswordQuery:
	    case EWrongPassword:
	    case EFilePasswordQuery:
	    case EMasterkeyQuery:
	    	{
	    	EAP_TRACE_DEBUG_SYMBIAN(
	    			(_L("m_notifier_data_pckg_from_user"),
	    			m_notifier_data_pckg_from_user->Ptr(),
	    			m_notifier_data_pckg_from_user->Size()));	    		
	    	if ( iStatus.Int() == KErrCancel )
	    		{
	    		EAP_TRACE_DEBUG_SYMBIAN(
	    				(_L("eap_am_type_tls_peap_symbian_c::CompleteNotifierL - User cancelled the notifier item")));
	    		m_userAction = EEapFastNotifierUserActionCancel;	
	    		}		
	    	else if( iStatus.Int() != KErrNone )
	    		{
	    		EAP_TRACE_DEBUG_SYMBIAN(
	    			(_L("eap_am_type_tls_peap_symbian_c::CompleteNotifierL - ERROR: Notifier error=%d"),
	    			iStatus.Int()));	
	    		return m_am_tools->convert_am_error_to_eapol_error(iStatus.Int());		
	    		}
    		EAP_TRACE_DEBUG_SYMBIAN(
    			(_L("CompleteNotifierL - Notifier return UiItem=%d, UserAction=%d"),
    			m_notifier_data_from_user->iEapFastNotifierUiItem,
    			m_notifier_data_from_user->iEapFastNotifierUserAction));
	    		
    		EAP_TRACE_DATA_DEBUG_SYMBIAN(
    			("CompleteNotifierL:UserInput:",
    			m_notifier_data_from_user->iEapFastNotifierBuffer.Ptr(), 
    			m_notifier_data_from_user->iEapFastNotifierBuffer.Size()));
	    			    		
	    	if ( m_notifier_data_from_user->iEapFastNotifierBuffer.Size() > 0 )
	    		{
    			HBufC8* notifier_data8 = HBufC8::NewLC(m_notifier_data_from_user->iEapFastNotifierBuffer.Size());
    			TPtr8 notifier_dataPtr8 = notifier_data8->Des();
    			
    			notifier_dataPtr8.Copy(m_notifier_data_from_user->iEapFastNotifierBuffer); // Unicode -> ascii.
    			EAP_TRACE_DEBUG_SYMBIAN(
   					(_L("eap_am_type_tls_peap_symbian_c::CompleteNotifierL ShowNotifierItem - Data copy done")));
    		    
    			EAP_TRACE_DATA_DEBUG_SYMBIAN(
	    			("eap_am_type_tls_peap_symbian_c::CompleteNotifierL ShowNotifierItem:PW from UI (8bits)",
   					notifier_dataPtr8.Ptr(), 
   					notifier_dataPtr8.Size()));	    
    		    
    			status = m_userResponse.set_copy_of_buffer(
   					notifier_dataPtr8.Ptr(),
   					notifier_dataPtr8.Size());
    			
	    		CleanupStack::PopAndDestroy( notifier_data8 );
	    		}
	    	break;
	    	}
	    default:
	    	{
	    	EAP_TRACE_DEBUG_SYMBIAN(
	    	    ( _L( "eap_am_type_tls_peap_symbian_c::CompleteNotifierL() m_state = %d not supported." ),
	    	    m_state ) );
	    	}
	    }
	return status;
	}

//--------------------------------------------------

void eap_am_type_tls_peap_symbian_c::ConvertUnicodeToAsciiL(const TDesC16& aFromUnicode, TDes8& aToAscii)
	{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
			("eap_am_type_tls_peap_symbian_c::ConvertUnicodeToAsciiL:From TEXT",
			aFromUnicode.Ptr(), 
			aFromUnicode.Size()));	
		
		if(aFromUnicode.Length() <= 0)
		{
			EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::ConvertUnicodeToAsciiL: Return: NOTHING TO CONVERT")));
			
			return;
		}	
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::ConvertUnicodeToAsciiL, aFromUnicode.Length=%d, aFromUnicode.Size=%d"),
			aFromUnicode.Length(), aFromUnicode.Size()));	
		
		// Convert from Unicode to ascii.
		HBufC8* aFromUnicodeBuf8 = HBufC8::NewLC(aFromUnicode.Length()); // Half times size of source (or length) is enough here.
		TPtr8 aFromUnicodePtr8 = aFromUnicodeBuf8->Des();
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_type_tls_peap_symbian_c::ConvertUnicodeToAsciiL, aFromUnicodePtr8.Length=%d, aFromUnicodePtr8.Size=%d, aFromUnicodePtr8.MaxLength=%d, aFromUnicodePtr8.MaxSize=%d"),
			aFromUnicodePtr8.Length(), aFromUnicodePtr8.Size(), aFromUnicodePtr8.MaxLength(), aFromUnicodePtr8.MaxSize()));				
		
		aFromUnicodePtr8.Copy(aFromUnicode); // Unicode -> ascii.
		
		aToAscii = aFromUnicodePtr8;	

		CleanupStack::PopAndDestroy(aFromUnicodeBuf8); // Delete aFromUnicodeBuf8.	

		EAP_TRACE_DATA_DEBUG_SYMBIAN(
			("eap_am_type_tls_peap_symbian_c::ConvertUnicodeToAsciiL:To ASCII",
			aToAscii.Ptr(), 
			aToAscii.Size()));	
	}


// ---------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::CheckPasswordTimeValidityL()
// ---------------------------------------------------------
//
void eap_am_type_tls_peap_symbian_c::CheckPasswordTimeValidityL()
	{
	/* Check validity of password against timelimit */
	
	EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("CheckPasswordTimeValidityL - Start\n")));

	TInt64 maxSessionTime = 0;
	TInt64 fullAuthTime = 0;
	
    // get max session time
	HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
	TPtr sqlStatement = buf->Des();	
	_LIT( KSqlQuery, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d" );
	sqlStatement.Format(
		KSqlQuery,
		&cf_str_EAP_FAST_max_session_validity_time_literal,
		&KFastGeneralSettingsDBTableName,
		&KServiceType, m_index_type, 
		&KServiceIndex, m_index,
		&KTunnelingType, m_tunneling_vendor_type );	
	TRAPD( err,  maxSessionTime =  ReadIntDbValueL(
		m_database,
		cf_str_EAP_FAST_max_session_validity_time_literal,
		sqlStatement ) );
	if ( err != KErrNone )
		{
		EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,
			( EAPL( "ERROR: Leave happened trying to read max session time,  \
			error=%d.\n" ), err ) );
		}
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, (
		EAPL("CheckPasswordTimeValidityL - maxSessionTime=%ld\n"),
		maxSessionTime ) );	
	
#ifdef USE_PAC_STORE
    sqlStatement.Zero();
	if ( !iPacStoreDb )
		{
		EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, (
			EAPL("CheckPasswordTimeValidityL - iPacStoreDb is NULL.\n")));
		CleanupStack::PopAndDestroy( buf ); // Delete buf.
		User::Leave( KErrArgument );
		}
	_LIT( KSqlQuery1, "SELECT %S FROM %S" );
	sqlStatement.Format(
		KSqlQuery1,
		&KFASTLastPasswordIdentityTime,
		&KPacStoreGeneralSettingsTableName );	
	RDbNamedDatabase& db = iPacStoreDb->GetPacStoreDb();
	TRAP( err, fullAuthTime = ReadIntDbValueL(
		db,
		KFASTLastPasswordIdentityTime,
		sqlStatement ) );
	if ( err == KErrNotFound ) // KFASTLastPasswordIdentityTime was not found
		{
		TRAP( err, FixOldTablesForPwdIdentityTimeL() );
		if ( err != KErrNone  )
			{
		    EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, ( EAPL(
		    	"ERROR: eap_am_type_tls_peap_symbian_c::CheckPasswordTimeValidityL() \
		        Leave happened trying to fix old table for pwd \
			    identity time, error=%d.\n" ), err ) );
		    User::Leave( err );
			}
		TRAP( err, fullAuthTime = ReadIntDbValueL(
			db,
			KFASTLastPasswordIdentityTime,
			sqlStatement ) );
 		if ( err != KErrNone )
			{
			EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, ( EAPL(
				"ERROR: eap_am_type_tls_peap_symbian_c::CheckPasswordTimeValidityL() \
				Leave happened trying to read full auth. time, \
			    error=%d.\n" ), err ) );		
		    User::Leave( err );
			}
		}
	else if ( err != KErrNone )
		{
		EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, ( EAPL(
			"ERROR: eap_am_type_tls_peap_symbian_c::CheckPasswordTimeValidityL() \
			Leave happened trying to read full auth. time,  \
			error=%d.\n" ), err ) );
		User::Leave( err );
		}
#else
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, (
		EAPL("CheckPasswordTimeValidityL - PAC store is not used.\n")));
	CleanupStack::PopAndDestroy( buf ); // Delete buf.
	User::Leave( KErrNotSupported );
#endif
	
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,
		( EAPL( "CheckPasswordTimeValidityL - fullAuthTime=%ld.\n" ),
	    fullAuthTime ) );		

	CleanupStack::PopAndDestroy( buf ); // Delete buf.
		
	// If the max session time from DB is zero then we use the 
	// one read from configuration file.	
	if( maxSessionTime == 0)
		{
			EAP_TRACE_DEBUG(m_am_tools, 
				TRACE_FLAGS_DEFAULT, (
				EAPL("CheckPasswordTimeValidityL - Using max session validity time from config file\n")));
		
			maxSessionTime = m_max_session_time; // value from configuration file.
		}
	
	// Get the current time.
	EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("UpdatePasswordTimeL - Get time\n")));

	TTime currentTime;
	currentTime.UniversalTime();
	
	TTime lastFullAuthTime(fullAuthTime);
	
	#if defined(_DEBUG) || defined(DEBUG)	
	
	TDateTime currentDateTime = currentTime.DateTime();
		
	TDateTime fullAuthDateTime = lastFullAuthTime.DateTime();
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
	(EAPL("CheckPasswordTimeValidityL Session Validity - Current Time,        %2d-%2d-%4d : %2d-%2d-%2d-%d\n"), 
	currentDateTime.Day()+1, currentDateTime.Month()+1, currentDateTime.Year(), currentDateTime.Hour(),
	currentDateTime.Minute(), currentDateTime.Second(), currentDateTime.MicroSecond()));
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
	(EAPL("CheckPasswordTimeValidityL Session Validity - Last Full Auth Time, %2d-%2d-%4d : %2d-%2d-%2d-%d\n"), 
	fullAuthDateTime.Day()+1, fullAuthDateTime.Month()+1, fullAuthDateTime.Year(), fullAuthDateTime.Hour(),
	fullAuthDateTime.Minute(), fullAuthDateTime.Second(), fullAuthDateTime.MicroSecond()));
	
	#endif
	
	TTimeIntervalMicroSeconds interval = currentTime.MicroSecondsFrom(lastFullAuthTime);
		
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("eap_am_type_tls_peap_symbian_c::CheckPasswordTimeValidityL:interval in microseconds:"),
			&(interval.Int64()),
			sizeof(interval.Int64()) ) );
			
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("eap_am_type_tls_peap_symbian_c::CheckPasswordTimeValidityL:max session time in microseconds:"),
			&(maxSessionTime),
			sizeof(maxSessionTime) ) );
	
	#if defined(_DEBUG) || defined(DEBUG)
	
	TTimeIntervalMinutes intervalMins;
	TInt error = currentTime.MinutesFrom(lastFullAuthTime, intervalMins);
	
	if(error == KErrNone)
		{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_tls_peap_symbian_c::CheckPasswordTimeValidityL")
			 EAPL("interval in Minutes =%d\n"),
			 intervalMins.Int()));
		}
	
	#endif
	
	if( maxSessionTime >= interval.Int64() )
		{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_tls_peap_symbian_c::CheckPasswordTimeValidityL - Session Valid \n")));
	
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			
	
		/* do nothing */	
		}
	else
		{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_tls_peap_symbian_c::CheckPasswordTimeValidityL - Session NOT Valid \n")));
	
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			
		
		m_tls_application->remove_cached_pac_store_data();
		
		TRAPD(error, UpdatePasswordTimeL());

		if(error != KErrNone)
			{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP-FAST: eap_am_type_tls_peap_symbian_c::CheckPasswordTimeValidityL() ERROR: LEAVE from UpdatePasswordTimeL() error=%d"),
				error));
		
			}
		}
	
	} // eap_am_type_tls_peap_symbian_c::CheckPasswordTimeValidityL()


// ---------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::AlterTableL()
// ---------------------------------------------------------
//
void eap_am_type_tls_peap_symbian_c::AlterTableL(
	RDbNamedDatabase& aDb,
	TAlterTableCmd aCmd,
	const TDesC& aTableName,
	const TDesC& aColumnName,
	const TDesC& aColumnDef )
	{
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, ( EAPL(
		"eap_am_type_tls_peap_symbian_c::AlterTableL() IN\n" ) ) );
	
	CDbColSet* colSet = aDb.ColSetL( aTableName );
	User::LeaveIfNull( colSet );
	CleanupStack::PushL( colSet );	
		
	EAP_TRACE_DEBUG_SYMBIAN( ( _L(
        "eap_am_type_tls_peap_symbian_c::AlterTableL() \
        Number of columns in %S table is %d.\n" ),
		&aTableName, colSet->Count() ) );
	
    if ( aCmd == EAddColumn )
    	{
    	// Check if there is a target column
    	if( colSet->ColNo( aColumnName ) != KDbNullColNo )
    		{
    		EAP_TRACE_DEBUG_SYMBIAN( ( _L(
   		        "eap_am_type_tls_peap_symbian_c::AlterTableL() \
   		        Column %S exists already in table %S.\n" ),
    			&aColumnName, &aTableName ) );
    		CleanupStack::PopAndDestroy( colSet );
    		return;
    		}
    	}
    else
    	{
    	// Check if there is a target column
    	if( colSet->ColNo( aColumnName ) == KDbNullColNo )
    		{
    		EAP_TRACE_DEBUG_SYMBIAN( ( _L(
   		        "eap_am_type_tls_peap_symbian_c::AlterTableL() \
   		        Column %S does not exists already in table %S.\n" ),
    			&aColumnName, &aTableName ) );
    		CleanupStack::PopAndDestroy( colSet );
    		return;
    		}
    	}

	HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
	TPtr sqlStatement = buf->Des();
		
	_LIT( KSqlAddCol, "ALTER TABLE %S ADD %S %S" );
	_LIT( KSqlRemoveCol, "ALTER TABLE %S DROP %S" );
	
	if ( aCmd == EAddColumn )
		{
		sqlStatement.Format( KSqlAddCol, &aTableName, 
		    &aColumnName, &aColumnDef );
		}
	else
		{
		sqlStatement.Format( KSqlRemoveCol, &aTableName, 
	        &aColumnName );
		}
		
	EAP_TRACE_DEBUG_SYMBIAN( ( _L(
		"eap_am_type_tls_peap_symbian_c::AlterTableL(): sqlStatement=%S\n"),
		&sqlStatement ) );
	
	User::LeaveIfError( aDb.Execute( sqlStatement ) );		
	CleanupStack::PopAndDestroy( buf );
	CleanupStack::PopAndDestroy( colSet );

	CDbColSet* alteredColSet = aDb.ColSetL( aTableName );
	User::LeaveIfNull( alteredColSet );
	EAP_TRACE_DEBUG_SYMBIAN( ( _L(
        "eap_am_type_tls_peap_symbian_c::AlterTableL() \
        Number of columns in %S table is %d.\n" ),
		&aTableName, alteredColSet->Count() ) );
	delete alteredColSet;
		
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "eap_am_type_tls_peap_symbian_c::AlterTableL() OUT\n" ) ) );

	} // eap_am_type_tls_peap_symbian_c::AlterTableL()


// ---------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::FixOldTablesForPwdIdentityTimeL()
// ---------------------------------------------------------
//
void eap_am_type_tls_peap_symbian_c::FixOldTablesForPwdIdentityTimeL()
	{
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "eap_am_type_tls_peap_symbian_c::FixOldTablesForPwdIdentityTimeL() IN" ) ) );	
	
	// remove password identity time from fast table	
	_LIT( KColumnDef, "BIGINT" );
	AlterTableL( m_database, ERemoveColumn, KFastGeneralSettingsDBTableName,
		KFASTLastPasswordIdentityTime );
	
	// add password identity time to PAC store table
#ifdef USE_PAC_STORE
	if ( !iPacStoreDb )
		{
		EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, ( EAPL(
			"ERROR: eap_am_type_tls_peap_symbian_c::FixOldTablesForPwdIdentityTimeL() \
			iPacStoreDb is NULL.\n" ) ) );
		User::Leave( KErrArgument );
		}
	RDbNamedDatabase& pacStoreDb = iPacStoreDb->GetPacStoreDb();
	AlterTableL( pacStoreDb, EAddColumn , KPacStoreGeneralSettingsTableName,
		KFASTLastPasswordIdentityTime, KColumnDef );
#else
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, (	EAPL(
		"ERROR: eap_am_type_tls_peap_symbian_c::FixOldTablesForPwdIdentityTimeL() \
		PAC store is not used.\n" ) ) );
		User::Leave( KErrNotSupported );
#endif
		
	// update password identity time
	UpdatePasswordTimeL();
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "eap_am_type_tls_peap_symbian_c::FixOldTablesForPwdIdentityTimeL() OUT" ) ) );
	
	} // eap_am_type_tls_peap_symbian_c::FixOldTablesForPwdIdentityTimeL()


// ---------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::FixOldTableForPacStoreInitL()
// ---------------------------------------------------------
//
void eap_am_type_tls_peap_symbian_c::FixOldTableForPacStoreInitL()
	{
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, ( EAPL(
		"eap_am_type_tls_peap_symbian_c::FixOldTableForPacStoreInitL() IN\n" ) ) );
	
#ifdef USE_PAC_STORE
	
	if ( !iPacStoreDb )
		{
		EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, ( EAPL(
			"ERROR: eap_am_type_tls_peap_symbian_c::FixOldTableForPacStoreInitL() \
			iPacStoreDb is NULL.\n" ) ) );
		User::Leave( KErrArgument );
		}
	RDbNamedDatabase& pacStoreDb = iPacStoreDb->GetPacStoreDb();
	_LIT( KColumnDef, "UNSIGNED INTEGER" );
	AlterTableL( pacStoreDb, EAddColumn, KPacStoreGeneralSettingsTableName,
        KPacStoreInitialized, KColumnDef );

#else
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, (	EAPL(
		"ERROR: eap_am_type_tls_peap_symbian_c::FixOldTableForPacStoreInitL() \
		PAC store is not used.\n" ) ) );
	User::Leave( KErrNotSupported );
#endif
		
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "eap_am_type_tls_peap_symbian_c::FixOldTableForPacStoreInitL() OUT\n" ) ) );

	} // eap_am_type_tls_peap_symbian_c::FixOldTableForPacStoreInitL()


// ---------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::ReadIntDbValue()
// ---------------------------------------------------------
//
TInt64 eap_am_type_tls_peap_symbian_c::ReadIntDbValueL(
	RDbNamedDatabase& aDb,
	const TDesC& aColumnName,
	const TDesC& aSqlStatement )
    {
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, (
			EAPL( "eap_am_type_tls_peap_symbian_c::ReadIntDbValueL()\n" ) ) );
    TPtrC columnName;    
	columnName.Set( aColumnName );
	
	RDbView view;
	// Evaluate view
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, (
		EAPL( "ReadIntDbValue() prepare view\n" ) ) );
	User::LeaveIfError( view.Prepare( aDb, TDbQuery(
		aSqlStatement ) ) );
	CleanupClosePushL( view );
	
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, (
		EAPL("ReadIntDbValue() evaluate view\n" ) ) );
	User::LeaveIfError( view.EvaluateAll() );		
	// Get the first (and only) row
	view.FirstL();
	view.GetL();
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL( colSet );
	TInt64 retVal = view.ColInt64( colSet->ColNo( columnName ) );

	CleanupStack::PopAndDestroy( colSet ); // Delete colSet.
	CleanupStack::PopAndDestroy( &view ); // Close view.

	return retVal;
    } // eap_am_type_tls_peap_symbian_c::ReadIntDbValueL


// ---------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::UpdatePasswordTimeL()
// ---------------------------------------------------------
//
void eap_am_type_tls_peap_symbian_c::UpdatePasswordTimeL()
	{
	/* update last password time */
	TPtrC lastFullPasswordTimeString;
	
	EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("UpdatePasswordTimeL - Start\n")));

	lastFullPasswordTimeString.Set(KFASTLastPasswordIdentityTime);
	
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("UpdatePasswordTimeL - prepare query\n")));
	// Query all the relevant parameters
	_LIT(KSQLQuery, "SELECT %S FROM %S");
	sqlStatement.Format( KSQLQuery, &lastFullPasswordTimeString,
        &KPacStoreGeneralSettingsTableName );

	RDbView view;
	// Evaluate view
	EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("UpdatePasswordTimeL - prepare view\n")));

#ifdef USE_PAC_STORE
	if ( !iPacStoreDb )
		{
		EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, (
			EAPL("CheckPasswordTimeValidityL - iPacStoreDb is NULL.\n")));
		CleanupStack::PopAndDestroy( buf ); // Delete buf.
		User::Leave( KErrArgument );
		}
	RDbNamedDatabase& db = iPacStoreDb->GetPacStoreDb();
	User::LeaveIfError( view.Prepare( db, TDbQuery( sqlStatement ),
		TDbWindow::EUnlimited ) );
	CleanupClosePushL( view );
#else
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT, (
		EAPL("CheckPasswordTimeValidityL - PAC store is not used.\n")));
	CleanupStack::PopAndDestroy( buf ); // Delete buf.
	User::Leave( KErrNotSupported );
#endif
	
	EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("UpdatePasswordTimeL - evaluate view\n")));
	User::LeaveIfError(view.EvaluateAll());
	
	// Get the first (and only) row for updation.
	view.FirstL();
	view.UpdateL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);
	
	// Get the current universal time.
	EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("UpdatePasswordTimeL - Get time\n")));
	TTime currentTime;
	currentTime.UniversalTime();
		
	
	TDateTime currentDateTime = currentTime.DateTime();
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
	(EAPL("eap_am_type_tls_peap_symbian_c::UpdatePasswordTimeL:store_authentication_time, %2d-%2d-%4d : %2d-%2d-%2d-%d\n"), 
	currentDateTime.Day()+1, currentDateTime.Month()+1,currentDateTime.Year(), currentDateTime.Hour(),
	currentDateTime.Minute(), currentDateTime.Second(), currentDateTime.MicroSecond()));
	
	TInt64 fullAuthTime = currentTime.Int64();
	
	view.SetColL(colSet->ColNo(lastFullPasswordTimeString), fullAuthTime);
	
	view.PutL();	
	
	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	CleanupStack::PopAndDestroy(&view); // Close view.
	CleanupStack::PopAndDestroy(buf); // Delete buf.
	
	/* update end */	
	
	} // eap_am_type_tls_peap_symbian_c::UpdatePasswordTimeL()


eap_status_e eap_am_type_tls_peap_symbian_c::CreateMasterkeyL()
	{
	HBufC8* password = HBufC8::NewLC(m_userResponse.get_data_length());
	TPtr8 passwordPtr = password->Des();
	m_PAC_store_password.set_copy_of_buffer(&m_userResponse);
	passwordPtr.Copy(m_userResponse.get_data(), m_userResponse.get_data_length());
	m_eap_fast_completion_status = m_am_tools->convert_am_error_to_eapol_error(iPacStoreDb->CreateAndSaveMasterKeyL(passwordPtr));
	CleanupStack::PopAndDestroy(password);
	return m_eap_fast_completion_status;
	}
#endif //#if defined(USE_FAST_EAP_TYPE)



// ================= TTLS-PAP public exported =======================

// ------------------------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::is_ttls_pap_session_valid()
// ------------------------------------------------------------------------
//
EAP_FUNC_EXPORT
bool eap_am_type_tls_peap_symbian_c::is_ttls_pap_session_valid()
	{
    DEBUG( "eap_am_type_tls_peap_symbian_c::is_ttls_pap_session_valid()" );    

    TBool isValid = EFalse;
    TInt err = KErrNone;
    bool retVal = false;
	
    TRAP( err, isValid = IsTtlsPapSessionValidL() );
    if ( err != KErrNone )
	    {
	    DEBUG1( "eap_am_type_tls_peap_symbian_c::is_ttls_pap_session_valid() ERROR: \
	        Leave, err==%d.", err );
	    retVal = false;
	    }
    else
    	{
    	retVal = ( isValid ) ? true : false;
    	}
    return retVal;
	}

// ------------------------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::query_ttls_pap_username_and_password()
// ------------------------------------------------------------------------
//    
EAP_FUNC_EXPORT eap_status_e
eap_am_type_tls_peap_symbian_c::query_ttls_pap_username_and_password(
	const eap_variable_data_c * const aInSrvChallengeUtf8 )
    {
    DEBUG( "eap_am_type_tls_peap_symbian_c::query_ttls_pap_username_and_password()" );    
	
    eap_status_e status( eap_status_pending_request );

    if ( !iEapTtlsPapActive )
    	{
    	TRAPD( err, iEapTtlsPapActive = CEapTtlsPapActive::NewL(
    		this, m_am_tools ) );
    	if ( err != KErrNone )
    		{
            DEBUG1( "eap_am_type_tls_peap_symbian_c::query_ttls_pap_username_and_password() \
            	ERROR: CEapTtlsPapActive::NewL(), err=%d.", err );    
    	    return ConvertAmErrorToEapolError( err );
    		}
    	}
    if ( aInSrvChallengeUtf8 != NULL )
    	{
        iEapTtlsPapActive->UpdateSrvChallenge( *aInSrvChallengeUtf8 );
    	}
    TBool startedOk = iEapTtlsPapActive->Start(
    	CEapTtlsPapActive::EEapTtlsPapActiveQueryUserNameAndPassword );
	if ( !startedOk )
        {
        status = eap_status_process_general_error;
        }
	if ( status != eap_status_pending_request )
		{
        DEBUG( "eap_am_type_tls_peap_symbian_c::query_ttls_pap_username_and_password() \
        	ERROR: status != eap_status_pending_request" );    
		}
	return status;
    }

// ================= TTLS-PAP public not exported =======================

// ------------------------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::verify_ttls_pap_username_and_password()
// ------------------------------------------------------------------------
//    
eap_status_e
eap_am_type_tls_peap_symbian_c::verify_ttls_pap_username_and_password(
	const eap_variable_data_c * const /*aUserName*/,
	const eap_variable_data_c * const /*aUserPassword*/ )
	{
	DEBUG( "eap_am_type_tls_peap_symbian_c::verify_ttls_pap_username_and_password()" );
	return eap_status_not_supported;
	}

// ================= TTLS-PAP public new =======================

// ------------------------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::CompleteQueryTtlsPapUserNameAndPassword()
// ------------------------------------------------------------------------
//    
eap_status_e
eap_am_type_tls_peap_symbian_c::CompleteQueryTtlsPapUserNameAndPassword(
	eap_status_e aStatus,
	const TDesC8& aUserNameUtf8,
	const TDesC8& aPasswordUtf8 )
	{
	DEBUG( "eap_am_type_tls_peap_symbian_c::CompleteQueryTtlsPapUserNameAndPassword()" );
	
	eap_status_e retStatus = aStatus;
	eap_status_e tmpStatus = eap_status_ok;
	
	eap_variable_data_c userNameUtf8( m_am_tools );
	eap_variable_data_c passwordUtf8( m_am_tools );
	
	tmpStatus = userNameUtf8.set_copy_of_buffer(
		aUserNameUtf8.Ptr(), aUserNameUtf8.Length() );
	if ( tmpStatus != eap_status_ok && retStatus == eap_status_ok )
		{
		retStatus = tmpStatus;
		}
	tmpStatus = passwordUtf8.set_copy_of_buffer(
			aPasswordUtf8.Ptr(), aPasswordUtf8.Length() );
	if ( tmpStatus != eap_status_ok && retStatus == eap_status_ok )
		{
		retStatus = tmpStatus;
		}
	if ( m_tls_am_partner == NULL )
		{
		DEBUG( "eap_am_type_tls_peap_symbian_c::CompleteQueryTtlsPapUserNameAndPassword() \
			ERROR: m_tls_am_partner is NULL." );
        return eap_status_process_general_error;
		}
	retStatus = m_tls_am_partner->
	    complete_query_ttls_pap_username_and_password(
		    &userNameUtf8, &passwordUtf8, retStatus );	
	return retStatus;
	} // eap_am_type_tls_peap_symbian_c::CompleteQueryTtlsPapUserNameAndPassword(


// ------------------------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::ConvertAmErrorToEapolError()
// ------------------------------------------------------------------------
//    
eap_status_e
eap_am_type_tls_peap_symbian_c::ConvertAmErrorToEapolError( TInt aErr )
	{
	DEBUG( "eap_am_type_tls_peap_symbian_c::ConvertAmErrorToEapolError()" );
    if ( m_am_tools )
    	{
    	return m_am_tools->convert_am_error_to_eapol_error( aErr );
    	}
	return eap_status_process_general_error;
	}


// ------------------------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::ReadTtlsPapDbL()
// ------------------------------------------------------------------------
//
//| EAP_TLS_PEAP_ttls_pap_password_prompt               | UNSIGNED INTEGER  | cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal           |//
//| EAP_TLS_PEAP_ttls_pap_username                      | VARCHAR(253)      | cf_str_EAP_TLS_PEAP_ttls_pap_username_literal                  |//
//| EAP_TLS_PEAP_ttls_pap_password                      | VARCHAR(128)      | cf_str_EAP_TLS_PEAP_ttls_pap_password_literal                  |//
//| EAP_TLS_PEAP_ttls_pap_max_session_validity_time		| BIGINT		   	| cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal |//
//| EAP_TLS_PEAP_ttls_pap_last_full_authentication_time	| BIGINT		   	| KTTLSPAPLastFullAuthTime	                             |//
void eap_am_type_tls_peap_symbian_c::ReadTtlsPapDbL(
	TTtlsPapDbInfo& aOutDbInfo )
	{
	DEBUG( "eap_am_type_tls_peap_symbian_c::ReadTtlsPapDbL()" );
	
	HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT( KSQLQuery,
		"SELECT %S, %S, %S, %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d" );
	sqlStatement.Format( KSQLQuery,
		&cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal,           // select´
		&cf_str_EAP_TLS_PEAP_ttls_pap_username_literal,                  // select
		&cf_str_EAP_TLS_PEAP_ttls_pap_password_literal,                  // select
		&cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal, // select
		&KTTLSPAPLastFullAuthTime,                                // select
		&KTtlsDatabaseTableName,                                         // from
		&KServiceType, m_index_type,                                     // where %S=%d
		&KServiceIndex, m_index,                                         // where %S=%d
		&KTunnelingType, eap_type_ttls );                                // where %S=%d
	
	RDbView view;
	// Evaluate view
	User::LeaveIfError( view.Prepare( m_database, TDbQuery( sqlStatement ) ) );
	CleanupClosePushL( view );
	User::LeaveIfError( view.EvaluateAll() );
	
	// Get the first (and only) row
	if (view.FirstL())
	{
			view.GetL();
			
			// Get column set so we get the correct column numbers
			CDbColSet* colSet = view.ColSetL();
			CleanupStack::PushL( colSet );
			
			// columns reading	
			aOutDbInfo.iUsrPwdInfo.iPasswordPromptEnabled = view.ColUint(
				colSet->ColNo( cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal ) );
			
			aOutDbInfo.iUsrPwdInfo.iUserName = view.ColDes(
				colSet->ColNo( cf_str_EAP_TLS_PEAP_ttls_pap_username_literal ) );
			
			aOutDbInfo.iUsrPwdInfo.iPassword = view.ColDes(
				colSet->ColNo( cf_str_EAP_TLS_PEAP_ttls_pap_password_literal ) );
			
			aOutDbInfo.iMaxSessionTime = view.ColInt64(
				colSet->ColNo( cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal ) );
			
			aOutDbInfo.iLastFullAuthTime = view.ColInt64(
					colSet->ColNo( KTTLSPAPLastFullAuthTime ) );
			
			CleanupStack::PopAndDestroy( colSet ); // Delete colSet.
	}
	CleanupStack::PopAndDestroy( &view ); // Close view.
	CleanupStack::PopAndDestroy( buf ); // Delete buf.
	
	} // eap_am_type_tls_peap_symbian_c::ReadTtlsPapDbL()


// ------------------------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::WriteTtlsPapDbL()
// ------------------------------------------------------------------------
//
//| EAP_TLS_PEAP_ttls_pap_password_prompt               | UNSIGNED INTEGER  | cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal           |//
//| EAP_TLS_PEAP_ttls_pap_username                      | VARCHAR(253)      | cf_str_EAP_TLS_PEAP_ttls_pap_username_literal                  |//
//| EAP_TLS_PEAP_ttls_pap_password                      | VARCHAR(128)      | cf_str_EAP_TLS_PEAP_ttls_pap_password_literal                  |//
//| EAP_TLS_PEAP_ttls_pap_max_session_validity_time		| BIGINT		   	| cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal |//
//| EAP_TLS_PEAP_ttls_pap_last_full_authentication_time	| BIGINT		   	| KTTLSPAPLastFullAuthTime	                             |//
void eap_am_type_tls_peap_symbian_c::WriteTtlsPapDbL(
	const TTtlsPapDbInfo& aInDbInfo )
	{
	DEBUG( "eap_am_type_tls_peap_symbian_c::WriteTtlsPapDbL()" );
	
	
	HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT( KSQLQuery,
		"SELECT %S, %S, %S, %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d" );
	sqlStatement.Format( KSQLQuery,
		&cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal,           // select´
		&cf_str_EAP_TLS_PEAP_ttls_pap_username_literal,                  // select
		&cf_str_EAP_TLS_PEAP_ttls_pap_password_literal,                  // select
		&cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal, // select
		&KTTLSPAPLastFullAuthTime,                                       // select
		&KTtlsDatabaseTableName,                                         // from
		&KServiceType, m_index_type,                                     // where %S=%d
		&KServiceIndex, m_index,                                         // where %S=%d
		&KTunnelingType, m_tunneling_vendor_type );                      // where %S=%d
	
	RDbView view;
	// Evaluate view
	User::LeaveIfError( view.Prepare( m_database, TDbQuery( sqlStatement ) ) );
	CleanupClosePushL( view );
	User::LeaveIfError( view.EvaluateAll() );
	
	// Get the first (and only) row
	if (view.FirstL())
	{
		view.UpdateL();
	
		// Get column set so we get the correct column numbers
		CDbColSet* colSet = view.ColSetL();
		CleanupStack::PushL( colSet );
	
		// columns updating
		view.SetColL( colSet->ColNo(
			cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal ),
			aInDbInfo.iUsrPwdInfo.iPasswordPromptEnabled );

		view.SetColL( colSet->ColNo(
			cf_str_EAP_TLS_PEAP_ttls_pap_username_literal ),
			aInDbInfo.iUsrPwdInfo.iUserName );

		view.SetColL( colSet->ColNo(
			cf_str_EAP_TLS_PEAP_ttls_pap_password_literal ),
			aInDbInfo.iUsrPwdInfo.iPassword );

		view.SetColL( colSet->ColNo(
			cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal ),
			aInDbInfo.iMaxSessionTime );

		view.SetColL( colSet->ColNo(
			KTTLSPAPLastFullAuthTime ),
			aInDbInfo.iLastFullAuthTime );
	
		view.PutL();

		CleanupStack::PopAndDestroy( colSet ); // Delete colSet.
	}
	
	CleanupStack::PopAndDestroy( &view ); // Close view.
	CleanupStack::PopAndDestroy( buf ); // Delete buf.
	
	} // eap_am_type_tls_peap_symbian_c::WriteTtlsPapDbL()


// ------------------------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::SetTtlsPapColumnToNullL
// ------------------------------------------------------------------------
//
void eap_am_type_tls_peap_symbian_c::SetTtlsPapColumnToNullL( const TDesC& aColName )
	{
	DEBUG( "eap_am_type_tls_peap_symbian_c::SetColumnNullL()" );

	HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT( KSQLQuery,
		"SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d" );
	sqlStatement.Format( KSQLQuery,
		&aColName,                                  // select´
		&KTtlsDatabaseTableName,                    // from
		&KServiceType, m_index_type,                // where %S=%d
		&KServiceIndex, m_index,                    // where %S=%d
		&KTunnelingType, m_tunneling_vendor_type ); // where %S=%d
	
	RDbView view;
	// Evaluate view
	User::LeaveIfError( view.Prepare( m_database, TDbQuery( sqlStatement ) ) );
	CleanupClosePushL( view );
	User::LeaveIfError( view.EvaluateAll() );
	
	// Get the first (and only) row
	if (view.FirstL())
	{
		view.UpdateL();
	
		// Get column set so we get the correct column numbers
		CDbColSet* colSet = view.ColSetL();
		CleanupStack::PushL( colSet );
	
		// set column to null
		view.SetColNullL( colSet->ColNo( aColName ) );
	
		view.PutL();

		CleanupStack::PopAndDestroy( colSet ); // Delete colSet.
	}
	
	CleanupStack::PopAndDestroy( &view ); // Close view.
	CleanupStack::PopAndDestroy( buf ); // Delete buf.
	
	} // eap_am_type_tls_peap_symbian_c::SetTtlsPapColumnToNullL()


// ================= TTLS-PAP private =======================

// ------------------------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::IsTtlsPapSessionValidL()
// ------------------------------------------------------------------------
//
TBool eap_am_type_tls_peap_symbian_c::IsTtlsPapSessionValidL()
	{
	DEBUG( "eap_am_type_tls_peap_symbian_c::IsTtlsPapSessionValidL()" );

	TTtlsPapDbInfo dbInfo;
	TInt err = KErrNone;
	TBool retValue = EFalse;
	
	TRAP( err, ReadTtlsPapDbL( dbInfo ) );
	
    if 	( err != KErrNone )
        {
        DEBUG1( "eap_am_type_tls_peap_symbian_c::IsTtlsPapSessionValidL() ERROR: \
        	Leave happened, err=%d.", err );
        retValue = EFalse;
        }
    else
    	{
	    if ( dbInfo.iUsrPwdInfo.iPasswordPromptEnabled )
		    {
			// If the max session time from DB is zero then we use the 
			// one read from configuration file.
		    if( dbInfo.iMaxSessionTime == 0 )
	            {
	            DEBUG( "eap_am_type_tls_peap_symbian_c::IsTtlsPapSessionValidL() \
	                	Using max TTLS PAP session validity time from config file." );
			
				// use value from config file
				dbInfo.iMaxSessionTime = iEapTtlsPapMaxSessionConfigTime;
			    }

		    retValue = CheckTtlsPapSessionValidity( dbInfo.iMaxSessionTime,
		    	dbInfo.iLastFullAuthTime );
		    }
    	}	
	return retValue;
	}  // eap_am_type_tls_peap_symbian_c::IsTtlsPapSessionValidL()


// ------------------------------------------------------------------------
// eap_am_type_tls_peap_symbian_c::CheckTtlsPapSessionValidity()
// ------------------------------------------------------------------------
//
TBool eap_am_type_tls_peap_symbian_c::CheckTtlsPapSessionValidity(
	const TInt64& aInMaxSessionTime,
	const TInt64& aInLastFullAuthTime )
	{
	DEBUG( "eap_am_type_tls_peap_symbian_c::CheckTtlsPapSessionValidity()" );
	
	// Get the current time.
	TTime currentTime;
	currentTime.UniversalTime();
	
	TTime lastFullAuthTime( aInLastFullAuthTime );
	
#if defined(_DEBUG) || defined(DEBUG)	
	
	TDateTime currentDateTime = currentTime.DateTime();
		
	TDateTime fullAuthDateTime = lastFullAuthTime.DateTime();
	
	EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,
	    ( EAPL( "Session Validity - Current Time,        %2d-%2d-%4d : %2d-%2d-%2d-%d\n" ), 
	    currentDateTime.Day()+1, currentDateTime.Month()+1, currentDateTime.Year(),
	    currentDateTime.Hour(), currentDateTime.Minute(), currentDateTime.Second(),
	    currentDateTime.MicroSecond() ) );

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
	    ( EAPL( "Session Validity - Last Full Auth Time, %2d-%2d-%4d : %2d-%2d-%2d-%d\n" ), 
	    fullAuthDateTime.Day()+1, fullAuthDateTime.Month()+1, fullAuthDateTime.Year(), fullAuthDateTime.Hour(),
	fullAuthDateTime.Minute(), fullAuthDateTime.Second(), fullAuthDateTime.MicroSecond()));

#endif

	TTimeIntervalMicroSeconds interval = currentTime.MicroSecondsFrom(lastFullAuthTime);
		
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,
		( EAPL( "eap_am_type_tls_peap_symbian_c::CheckTtlsPapSessionValidity:interval in microseconds:"),
		&( interval.Int64() ), sizeof( interval.Int64() ) ) );
			
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,
		( EAPL( "eap_am_type_tls_peap_symbian_c::CheckTtlsPapSessionValidity:max session time in microseconds:"),
		&( aInMaxSessionTime ), sizeof( aInMaxSessionTime ) ) );
	
#if defined(_DEBUG) || defined(DEBUG)

	TTimeIntervalMinutes intervalMins;
	TInt error = currentTime.MinutesFrom(lastFullAuthTime, intervalMins);
	
	if(error == KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_tls_peap_symbian_c::CheckTtlsPapSessionValidity()")
			 EAPL("interval in Minutes =%d\n"),
			 intervalMins.Int()));
	}
	
#endif

	if( aInMaxSessionTime >= interval.Int64() )
	    {
		EAP_TRACE_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,
			( EAPL( "eap_am_type_tls_peap_symbian_c::CheckTtlsPapSessionValidity - Session Valid \n" ) ) );
		EAP_TRACE_END( m_am_tools, TRACE_FLAGS_DEFAULT );
		
		return ETrue;	
	    }
	else
	    {
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
			( EAPL( "eap_am_type_tls_peap_symbian_c::CheckTtlsPapSessionValidity - Session NOT Valid \n" ) ) );
		EAP_TRACE_END( m_am_tools, TRACE_FLAGS_DEFAULT );			
		
		return EFalse;	
	    }
	} // eap_am_type_tls_peap_symbian_c::CheckTtlsPapSessionValidity


// End of file.
