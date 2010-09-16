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
* %version: 47.1.11 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 193 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES
#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_type_gsmsim_symbian.h"
#include "abs_eap_am_crypto.h"
#include "abs_eap_am_mutex.h"
#include "eap_am_tools_symbian.h"
#include "eap_state_notification.h"
#include "EapSimDbDefaults.h"
#include "EapSimDbParameterNames.h"
#include "EapSimDbUtils.h"
#include "EapTraceSymbian.h"

#include <d32dbms.h>	// For DBMS
#include <s32strm.h> 	// For RReadStream

#if defined (USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)

#include "EapSimInterface.h"	

#endif // End of #if defined (USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)

const TUint SIM_IMSI_LENGTH = 15u;
const TUint KIdentityHeaderLength = 2;
const TUint KMaxSqlQueryLength = 512;
const TUint KMaxDBFieldNameLength = 255;
const TInt 	KDefaultColumnInView_One = 1; // For DB view.
const TInt 	KMicroSecsInASecond = 1000000; // 1000000 micro seconds is 1 second.

#if defined(__WINS__)

const char TEST_IMSI[] = "244070100000001";

#endif

// ================= MEMBER FUNCTIONS =======================

eap_am_type_gsmsim_symbian_c::eap_am_type_gsmsim_symbian_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const bool aIsClient,
	const eap_am_network_id_c * const receive_network_id)
: eap_am_type_gsmsim_c(tools)
, m_am_tools(static_cast<eap_am_tools_symbian_c*>(tools)) // Tools class must be of type eap_am_tools_symbian because
														  // this is Symbian specific code.
, m_partner(partner)
, m_triplet_file(tools)
, m_nai_realm(tools)
, m_index_type(aIndexType)
, m_index(aIndex)
, m_tunneling_type(aTunnelingType)
, m_is_valid(false)
, m_is_client(aIsClient)
, m_stored_reauth_id(tools)
, m_stored_pseudonym(tools)
, m_previous_imsi(tools)
, m_stored_required_completion(eap_type_gsmsim_complete_none)
, m_stored_received_eap_identifier(0)
, m_shutdown_was_called(false)

#if !defined (USE_EAP_GSMSIM_INTERFACE)
, m_sim_algorithm(tools)
#endif // #if !defined (USE_EAP_GSMSIM_INTERFACE)

, m_simulator_sim_algorithm(sim_algorithm_nokia_test_network_xor)
, m_simulator_sim_ki(tools)
, m_copy_of_n_rands(tools)
, m_n_kc(tools)
, m_n_sres(tools)
, m_uma_automatic_realm_prefix(tools)
, m_receive_network_id(tools)
, m_rands_handled(0)
, m_do_rand_uniqueness_check(true)
, m_max_session_time(0)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

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

void eap_am_type_gsmsim_symbian_c::ConstructL()
{
	TInt error = m_session.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("eap_am_type_gsmsim_symbian_c::ConstructL(): - m_session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	// Open/create database
	EapSimDbUtils::OpenDatabaseL(m_database, m_session, m_index_type, m_index, m_tunneling_type);	
	
	// SIM IMSI, Kc and SRES are queried from SIM using SIM interface. 
	// If this is not used then Nokia test algorithms and test IMSI is used.
#if defined (USE_EAP_GSMSIM_INTERFACE)	&& !defined(__WINS__)
	if (m_is_client == true)
	{
		m_isa_if = CEapSimIsaInterface::NewL(m_am_tools, this);
	} 
	else
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: EAP-SIM server does not work at the moment in plugintester.\n")));
		User::Leave(KErrNotSupported);
	}
#endif //#if defined (USE_EAP_GSMSIM_INTERFACE)	&& !defined(__WINS__)
}

//--------------------------------------------------

eap_am_type_gsmsim_symbian_c* eap_am_type_gsmsim_symbian_c::NewL(
	abs_eap_am_tools_c * const aTools,
	abs_eap_base_type_c * const aPartner,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const bool aIsClient,
	const eap_am_network_id_c * const receive_network_id)
{
	eap_am_type_gsmsim_symbian_c* self = new eap_am_type_gsmsim_symbian_c(
		aTools, 
		aPartner, 
		aIndexType, 
		aIndex, 
		aTunnelingType,
		aIsClient,
		receive_network_id);

	if (self == 0
		|| self->get_is_valid() != true)
	{
		if (self != 0)
		{
			self->shutdown();
		}

		delete self;

		User::Leave(KErrGeneral);
	}

	TRAPD(error, self->ConstructL());

	if (error != KErrNone)
	{
		self->shutdown();
		delete self;

		User::Leave(error);
	}

	return self;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_type_gsmsim_symbian_c::~eap_am_type_gsmsim_symbian_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_gsmsim_symbian_c::~eap_am_type_gsmsim_symbian_c(): this = 0x%08x\n"),
		this));

	m_database.Close();
	m_session.Close();

#if defined(USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)
	if (m_is_client == true)
	{
		delete m_isa_if;
	}
#endif //#if defined(USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::store_reauth_parameters(
	const eap_variable_data_c * const XKEY,
	const eap_variable_data_c * const K_aut,
	const eap_variable_data_c * const K_encr,
	const u32_t reauth_counter)
{	
	// These kind of wrapper functions are needed because the Symbian L-functions must be executed in 
	// trap harness.
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	// Send error if any of the parameters are invalid.
	if(XKEY == NULL 
		|| K_aut == NULL
		|| K_encr == NULL)
	{
		// Some of the parameters are invalid.
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_gsmsim_symbian_c::store_reauth_parameters: ")
			 EAPL("ERROR: Invalid parameters\n")));
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	// Send error if any of the parameters are too long.
	if(XKEY->get_data_length() > KMaxXKeyLengthInDB 
		|| K_aut->get_data_length() > KMaxK_autLengthInDB 
		|| K_encr->get_data_length() > KMaxK_encrLengthInDB )
	{
		// Some of the parameters are too long. Can't store them in DB.
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_gsmsim_symbian_c::store_reauth_parameters: ")
			 EAPL("Too long parameters. Length: XKEY=%d, K_aut=%d, K_encr=%d\n"),
			 XKEY->get_data_length(), K_aut->get_data_length(), K_encr->get_data_length()));
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	eap_status_e status(eap_status_ok);
	
	TRAPD(err, store_reauth_parametersL(XKEY, K_aut, K_encr, reauth_counter));
	if (err != KErrNone)
	{
		// Convert the leave error code to EAPOL stack error code.
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		send_error_notification(status);
	} 	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

void eap_am_type_gsmsim_symbian_c::store_reauth_parametersL(
	const eap_variable_data_c * const XKEY,
	const eap_variable_data_c * const K_aut,
	const eap_variable_data_c * const K_encr,
	const u32_t reauth_counter)
{	
	// The _L functions do the actual thing.
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Form the insertion command
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLInsert, "SELECT %S, %S, %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLInsert,
		&KXKey,
		&KK_aut,
		&KK_encr,
		&KReauthCounter,
		&KSimTableName, 
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());
		
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	
	// Create pointers to the data
	TPtrC8 key(XKEY->get_data(XKEY->get_data_length()), XKEY->get_data_length());
	TPtrC8 aut(K_aut->get_data(K_aut->get_data_length()), K_aut->get_data_length());
	TPtrC8 enc(K_encr->get_data(K_encr->get_data_length()), K_encr->get_data_length());
	
	// Update the columns in the database
	view.FirstL();	
	view.UpdateL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);	
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("XKEY to DB"), key.Ptr(),	key.Length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("K_aut to DB"), aut.Ptr(),	aut.Length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("K_encr to DB"), enc.Ptr(),	enc.Length()));
	
	view.SetColL(colSet->ColNo(KXKey), key); // XKEY
	view.SetColL(colSet->ColNo(KK_aut), aut); // K_aut
	view.SetColL(colSet->ColNo(KK_encr), enc); // K_encr
	view.SetColL(colSet->ColNo(KReauthCounter), reauth_counter); // ReauthCounter
	
	CleanupStack::PopAndDestroy(colSet); // Delete colSet.	

	view.PutL();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_gsmsim_symbian_c::store_reauth_keys_L(): %s, m_saved_reauth_counter %d.\n"),
		 (m_is_client == true ? "client": "server"),
		 reauth_counter));

	// Close database
	CleanupStack::PopAndDestroy(2); // view, buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::authentication_finished(
	const bool true_when_successful,
	const eap_gsmsim_authentication_type_e authentication_type,
	const eap_type_gsmsim_identity_type identity_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);
	TInt err(KErrNone);	
	
	// Store the authentication time if the full authentication is successful
	if (true_when_successful == true
		&& authentication_type == GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH)
	{
		TRAP(err,store_authentication_timeL());
		if (err != KErrNone)
		{
			status = m_am_tools->convert_am_error_to_eapol_error(err);
			send_error_notification(status);
		}
	}	

	if (true_when_successful == false)
	{
		if( identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID 
			|| identity_type == GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID )
		{
			(void) store_pseudonym_id(0,0);
		}
		
		if( identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID 
			|| identity_type == GSMSIM_IDENTITY_TYPE_RE_AUTH_ID )
		{
			(void) store_reauthentication_id(0,0);			
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::query_reauth_parameters(
	eap_variable_data_c * const reauth_XKEY,
	eap_variable_data_c * const reauth_K_aut,
	eap_variable_data_c * const reauth_K_encr,
	u32_t * const reauth_counter)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
	eap_status_e status(eap_status_ok);
	TRAPD(err, query_reauth_parametersL(reauth_XKEY, reauth_K_aut, reauth_K_encr, reauth_counter));
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		send_error_notification(status);
	} 
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

void eap_am_type_gsmsim_symbian_c::query_reauth_parametersL(
	eap_variable_data_c * const reauth_XKEY,
	eap_variable_data_c * const reauth_K_aut,
	eap_variable_data_c * const reauth_K_encr,
	u32_t * const reauth_counter)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Form the query
	_LIT(KSQLQuery, "SELECT %S, %S, %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLQuery,
		&KXKey,
		&KK_aut,
		&KK_encr,
		&KReauthCounter,
		&KSimTableName,
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());
		
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

	// Get the values from DB
	TPtrC8 key = view.ColDes8(colSet->ColNo(KXKey));	
	TPtrC8 aut = view.ColDes8(colSet->ColNo(KK_aut));
	TPtrC8 enc = view.ColDes8(colSet->ColNo(KK_encr));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("XKEY from DB"), key.Ptr(),	key.Length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("K_aut from DB"), aut.Ptr(),	aut.Length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("K_encr from DB"), enc.Ptr(),	enc.Length()));
					
	eap_status_e status(eap_status_process_general_error);
	
	// Store the values to the supplied buffers
	status = reauth_XKEY->set_copy_of_buffer(key.Ptr(),key.Length());
	if (status != eap_status_ok)
	{
		User::Leave(
			m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, status)));
	}

	status = reauth_K_aut->set_copy_of_buffer(aut.Ptr(),aut.Length());
	if (status != eap_status_ok)
	{
		User::Leave(
			m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, status)));
	}

	status = reauth_K_encr->set_copy_of_buffer(enc.Ptr(),enc.Length());
	if (status != eap_status_ok)
	{
		User::Leave(
			m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, status)));
	}
	*reauth_counter = view.ColUint(colSet->ColNo(KReauthCounter));

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_gsmsim_symbian_c::query_reauth_parametersL(): %s, m_saved_reauth_counter %d.\n"),
		 (m_is_client == true ? "client": "server"),
		 *reauth_counter));

	// Close database
	CleanupStack::PopAndDestroy(2); // view, buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::increase_reauth_counter()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_ok);
	TRAPD(err, increase_reauth_counterL());
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		send_error_notification(status);
	} 		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

void eap_am_type_gsmsim_symbian_c::increase_reauth_counterL()
{
	// Form the insertion command
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLInsert, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLInsert,
		&KReauthCounter,
		&KSimTableName, 
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());
		
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	
	view.FirstL();
	view.GetL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);	
	
	// Get the previous value
	TUint counter = view.ColUint(colSet->ColNo(KReauthCounter));

	view.UpdateL();
	
	// Increment the value
	view.SetColL(colSet->ColNo(KReauthCounter), counter + 1); 

	counter = view.ColUint(colSet->ColNo(KReauthCounter));
	
	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_gsmsim_symbian_c::increase_reauth_counterL(): %s, m_saved_reauth_counter %d.\n"),
		 (m_is_client == true ? "client": "server"),
		 counter));

	view.PutL();

	// Close database
	CleanupStack::PopAndDestroy(2); // view, buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)

	{
		// Read triplet file name
		eap_status_e status = type_configure_read(
			cf_str_EAP_GSMSIM_triplet_file.get_field(),
			&m_triplet_file);
		if (status != eap_status_ok
			&& status != eap_status_illegal_configure_field)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		// This is optional value. Don't care even if the configure fails.
	}

#endif //#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)

	{
		eap_status_e status = type_configure_read(
			cf_str_EAP_GSMSIM_manual_realm.get_field(),
			&m_nai_realm);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		if (m_nai_realm.get_is_valid_data() == false)
		{
			// We should really generate a NAI here but it's too much work.
			// So for testing purposes so we'll just use 3gppnetwork.org
			
			_LIT8(KDefaultRealm, "3gppnetwork.org");
			TBuf8<16> tmp(KDefaultRealm);
			status = m_nai_realm.set_copy_of_buffer(tmp.Ptr(), tmp.Length());			
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

#if !defined (USE_EAP_GSMSIM_INTERFACE)
// Needed only for test environment.

	{
		eap_variable_data_c simulator_sim_algorithm(m_am_tools);

		eap_status_e status = type_configure_read(
			cf_str_EAP_GSMSIM_simulator_sim_algorithm.get_field(),
			&simulator_sim_algorithm);
		if (status == eap_status_ok
			&& simulator_sim_algorithm.get_is_valid_data() == true
			&& simulator_sim_algorithm.get_data_length() > 0ul
			&& simulator_sim_algorithm.get_data(
				simulator_sim_algorithm.get_data_length()) != 0)
		{
			if (cf_str_EAP_GSMSIM_simulator_sim_algorithm_config_value_nokia_test_network_xor
				.get_field()->compare(
					m_am_tools,
					&simulator_sim_algorithm) == true)
			{
				m_simulator_sim_algorithm = sim_algorithm_nokia_test_network_xor;
			}
			else if (cf_str_EAP_GSMSIM_simulator_sim_algorithm_config_value_tls_prf_with_shared_secret
					 .get_field()->compare(
						 m_am_tools,
						 &simulator_sim_algorithm) == true)
			{
				m_simulator_sim_algorithm = sim_algorithm_tls_prf_with_shared_secret;
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: illegal configuration value %s\n"),
					 cf_str_EAP_GSMSIM_simulator_sim_algorithm.get_field()->get_field()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
			}
		}
	}
	
	{
		eap_status_e status = type_configure_read(
			cf_str_EAP_GSMSIM_simulator_sim_ki.get_field(),
			&m_simulator_sim_ki);
		if (status == eap_status_ok
			&& m_simulator_sim_ki.get_is_valid_data() == true
			&& m_simulator_sim_ki.get_data_length() > 0ul
			&& m_simulator_sim_ki.get_data(
				m_simulator_sim_ki.get_data_length()) != 0)
		{
			// OK.
			eap_status_e status = m_sim_algorithm.set_simulator_sim_ki(&m_simulator_sim_ki);
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}		
	}
#endif // #if !defined (USE_EAP_GSMSIM_INTERFACE)


#if defined(USE_EAP_SIM_RESET_RAND_DATABASES)
	{
		eap_variable_data_c do_rand_uniqueness_check(m_am_tools);

		eap_status_e status = type_configure_read(
			cf_str_EAP_GSMSIM_do_rand_uniqueness_check.get_field(),
			&do_rand_uniqueness_check);

		if (status == eap_status_ok
			&& do_rand_uniqueness_check.get_is_valid_data() == true
			&& do_rand_uniqueness_check.get_data_length() == sizeof(u32_t))
		{
			u32_t *flag = reinterpret_cast<u32_t *>(do_rand_uniqueness_check.get_data());
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_do_rand_uniqueness_check = false;
					(void) reset_rand_check();
				}
			}
		}
	}
#endif //#if defined(USE_EAP_SIM_RESET_RAND_DATABASES)

	{
		// Read Maximum Session Validity Time from the config file
		eap_variable_data_c sessionTimeFromFile(m_am_tools);
		
		eap_status_e status = type_configure_read(
			cf_str_EAP_GSMSIM_max_session_validity_time.get_field(),
			&sessionTimeFromFile);
		
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
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_rands_handled = 0ul;

#if defined(USE_EAP_SIM_RESET_RAND_DATABASES)
	if (m_do_rand_uniqueness_check == false)
	{
		(void) reset_rand_check();
	}
#endif //#if defined(USE_EAP_SIM_RESET_RAND_DATABASES)
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eap_am_type_gsmsim_symbian_c::shutdown(), m_shutdown_was_called=%d\n"),
		(m_is_client == true) ? "client": "server",
		m_shutdown_was_called));

	m_shutdown_was_called = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

#if defined(USE_EAP_SIM_RESET_RAND_DATABASES)

eap_status_e eap_am_type_gsmsim_symbian_c::reset_rand_check()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	RFs fs;

	TInt error = fs.Connect();
	if (error != KErrNone)
	{
		eap_status_e status(m_am_tools->convert_am_error_to_eapol_error(error));

		send_error_notification(status);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("RFs::Connect() failed %d.\n"),
			status));
		(void) EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		// Remove RAND check databases.
		_LIT(KRandDb,		"C:\\private\\101f7989\\rand_db.cur");
		_LIT(KRandDbPrev,	"C:\\private\\101f7989\\rand_db.prv");

		TInt err = fs.Delete(KRandDb);
		(void) EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));

		err = fs.Delete(KRandDbPrev);
		(void) EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));

		fs.Close();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

#endif //#if defined(USE_EAP_SIM_RESET_RAND_DATABASES)

//--------------------------------------------------

#if defined(__WINS__)

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::query_SIM_imsi(
	u8_t * const imsi, const u32_t max_length, u32_t * const imsi_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (imsi == 0 || imsi_length == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// This function returns Nokia test SIM IMSI.
	// It is used only when real ISA interface is not used.	

	*imsi_length = m_am_tools->strlen(TEST_IMSI);
	if (*imsi_length > max_length)
	{
		// ERROR, too short buffer.
		*imsi_length = 0u;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	m_am_tools->memmove(imsi, TEST_IMSI, m_am_tools->strlen(TEST_IMSI));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

#endif //#if defined(__WINS__)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::store_pseudonym_id(
	const eap_am_network_id_c * const network_id,
	const eap_variable_data_c * const pseudonym)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
		
	// Send error if the pseudonym is too long.
	if(pseudonym != NULL && pseudonym->get_data_length() > KMaxPseudonymIdLengthInDB)
	{
		// Pseudonym too long. Can't store this in DB.
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_gsmsim_symbian_c::store_pseudonym_id: ")
			 EAPL("Too long Pseudonym. Length=%d\n"),
			 pseudonym->get_data_length()));
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	eap_status_e status(eap_status_ok);
	
	TRAPD(err, store_pseudonym_idL(network_id, pseudonym));
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		send_error_notification(status);
	} 
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

void eap_am_type_gsmsim_symbian_c::store_pseudonym_idL(
	const eap_am_network_id_c * const /*network_id*/,
	const eap_variable_data_c * const pseudonym)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Form the insertion command
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLInsert, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLInsert,
		&KPseudonymId,
		&KSimTableName, 
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());

	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	
	// Update the columns in the database
	view.FirstL();
	view.UpdateL();	
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();		
	CleanupStack::PushL(colSet);
	
	// Create pointer to the data
	if ((pseudonym != NULL) 
		&& (pseudonym->get_is_valid_data() == true))
	{		
		TPtrC8 pseudonymId(
			pseudonym->get_data(pseudonym->get_data_length()),
			pseudonym->get_data_length());
		
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("pseudonymId to DB"),	pseudonymId.Ptr(), pseudonymId.Length()));
		
		view.SetColL(colSet->ColNo(KPseudonymId), pseudonymId);
	} 
	else 
	{
		// If passed pseudonym was 0 that means the field must be cleared.
		view.SetColNullL(colSet->ColNo(KPseudonymId));
	}
		
	CleanupStack::PopAndDestroy(colSet); // Delete colSet.	
		
	view.PutL();
	
	// Close database
	CleanupStack::PopAndDestroy(2); // view, buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::store_reauthentication_id(
	const eap_am_network_id_c * const network_id,
	const eap_variable_data_c * const reauthentication_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
	
	// Send error if the pseudonym is too long.
	if(reauthentication_id != NULL 
		&& reauthentication_id->get_data_length() > KMaxReauthIdLengthInDB)
	{
		// Reauth id too long. Can't store this in DB.
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_gsmsim_symbian_c::store_reauthentication_id: ")
			 EAPL("Too long reauth id. Length=%d\n"),
			 reauthentication_id->get_data_length()));
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	eap_status_e status(eap_status_ok);
	
	TRAPD(err, store_reauthentication_idL(network_id, reauthentication_id));
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		send_error_notification(status);
	} 
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

void eap_am_type_gsmsim_symbian_c::store_reauthentication_idL(
	const eap_am_network_id_c * const /*network_id*/,
	const eap_variable_data_c * const reauthentication_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Form the insertion command
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLInsert, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLInsert,
		&KReauthId,
		&KSimTableName, 
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());
		
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	
	view.FirstL();
	view.UpdateL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);		

	// Create pointer to the data
	if ((reauthentication_id != NULL) 
		&& (reauthentication_id->get_is_valid_data() == true))
	{
		TPtrC8 reauthId(
			reauthentication_id->get_data(reauthentication_id->get_data_length()), 
			reauthentication_id->get_data_length());
		
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("reauthId to DB"), reauthId.Ptr(), reauthId.Length()));
		
		view.SetColL(colSet->ColNo(KReauthId), reauthId);		
	} 
	else 
	{
		// If passed reauthentication_id was 0 that means the field must be cleared.
		view.SetColNullL(colSet->ColNo(KReauthId));
	}
	
	CleanupStack::PopAndDestroy(colSet); // Delete colSet.	
	
	view.PutL();	
	
	// Close database
	CleanupStack::PopAndDestroy(2); // view, buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}
//--------------------------------------------------

eap_status_e eap_am_type_gsmsim_symbian_c::store_imsi(
	const eap_variable_data_c * const imsi)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
	
	// Send error if the IMSI is too long.
	if(imsi != NULL && imsi->get_data_length() > KMaxIMSILengthInDB)
	{
		// IMSI too long. Can't store this in DB.
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_gsmsim_symbian_c::store_imsi: ")
			 EAPL("Too long IMSI. Length=%d\n"),
			 imsi->get_data_length()));
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	eap_status_e status(eap_status_ok);

	TRAPD(err, store_imsiL(imsi));
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		send_error_notification(status);
	} 
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

void eap_am_type_gsmsim_symbian_c::store_imsiL(
	const eap_variable_data_c * const imsi)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	// Form the insertion command
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLInsert, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLInsert,
		&KPreviousIMSI,
		&KSimTableName, 
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());

	// Evaluate view
	RDbView view;
	
	User::LeaveIfError(view.Prepare(m_database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	view.FirstL();

	view.UpdateL();

	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);	

	// Create pointer to the data
	if ((imsi != 0) 
		&& (imsi->get_is_valid_data() == true))
	{
		TPtrC8 tmp_imsi(
			imsi->get_data(imsi->get_data_length()), 
			imsi->get_data_length());	
	
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("IMSI to DB"), tmp_imsi.Ptr(), tmp_imsi.Length()));
		
		view.SetColL(colSet->ColNo(KPreviousIMSI), tmp_imsi); 
	} 
	else 
	{
		// If passed IMSI was 0 that means the field must be cleared.
		view.SetColNullL(colSet->ColNo(KPreviousIMSI));
	}
	
	CleanupStack::PopAndDestroy(colSet); // Delete colSet.	

	view.PutL();	
	
	// Close database
	CleanupStack::PopAndDestroy(2); // view, buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::query_SIM_IMSI_or_pseudonym_or_reauthentication_id(
	const bool must_be_synchronous,
	eap_variable_data_c * const IMSI,
	eap_variable_data_c * const pseudonym_identity,
	eap_variable_data_c * const reauthentication_identity,
	eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
	u32_t * const length_of_mnc,
	const gsmsim_payload_AT_type_e required_identity,
	const eap_type_gsmsim_complete_e required_completion,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	EAP_ASSERT((IMSI != 0) && (pseudonym_identity != 0) && (reauthentication_identity != 0));

	m_stored_required_completion = required_completion;
	m_stored_received_eap_identifier = received_eap_identifier;

	TRAPD(err, query_SIM_IMSI_or_pseudonym_or_reauthentication_idL(
		must_be_synchronous,
		IMSI,
		pseudonym_identity,
		reauthentication_identity,
		automatic_realm,
		length_of_mnc,
		required_identity,
		required_completion,
		received_eap_identifier));
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);

		if (status != eap_status_pending_request)
		{
			send_error_notification(status);
		}
	} 

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

void eap_am_type_gsmsim_symbian_c::query_SIM_IMSI_or_pseudonym_or_reauthentication_idL(
	const bool /*must_be_synchronous*/,
	eap_variable_data_c * const IMSI,
	eap_variable_data_c * const pseudonym_identity,
	eap_variable_data_c * const reauthentication_identity,
	eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
	u32_t * const /*length_of_mnc*/,
	const gsmsim_payload_AT_type_e required_identity,
	const eap_type_gsmsim_complete_e /*required_completion*/,
	const u8_t /*received_eap_identifier*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Reset everything
	IMSI->reset();
	pseudonym_identity->reset();
	reauthentication_identity->reset();
	automatic_realm->reset();
	m_stored_pseudonym.reset();
	m_stored_reauth_id.reset();
	m_previous_imsi.reset();

	// Query all the relevant parameters

	_LIT(KSQLQuery, "SELECT %S, %S, %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLQuery,
		&KReauthId,
		&KReauthCounter,
		&KPseudonymId,
		&KPreviousIMSI,
		&KSimTableName,
		&KServiceType,
		m_index_type, 
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());

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
	
	// Get the values from DB
	TUint reauthCount = view.ColUint32(colSet->ColNo(KReauthCounter));	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("query_SIM_IMSI_or_pseudonym_or_reauthentication_idL: ")
		 EAPL("required_identity=%d, reauthCount from DB %d\n"),
		 required_identity, reauthCount));
	
	// A stream is needed for LONG columns in DB.
	RDbColReadStream readStream;

	// Get pseudonym ID from DB.
	HBufC8* pseudonymIdBuf = HBufC8::NewLC(KMaxPseudonymIdLengthInDB); // Buffer for pseudonym id.
	TPtr8 pseudonymId = pseudonymIdBuf->Des();
	
	readStream.OpenLC(view, colSet->ColNo(KPseudonymId));
	readStream.ReadL(pseudonymId, view.ColLength(colSet->ColNo(KPseudonymId)));
	readStream.Close();
	CleanupStack::Pop(&readStream); // Pop readStream.
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("pseudonymId from DB"), pseudonymId.Ptr(), pseudonymId.Length()));

	// Get reauthentication ID from DB.
	HBufC8* reauthIdBuf = HBufC8::NewLC(KMaxReauthIdLengthInDB); // Buffer for reauthentication id.
	TPtr8 reauthId = reauthIdBuf->Des();
	
	readStream.OpenLC(view, colSet->ColNo(KReauthId));
	readStream.ReadL(reauthId, view.ColLength(colSet->ColNo(KReauthId)));
	readStream.Close();
	CleanupStack::Pop(&readStream); // Pop readStream.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("reauthId from DB"), reauthId.Ptr(), reauthId.Length()));

#if defined(USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)

	// Get the previous IMSI. Used for checking if SIM has been changed.
	// The checking is done in complete_SIM_imsi_L
	
	TPtrC8 tmp_imsi = view.ColDes8(colSet->ColNo(KPreviousIMSI));
	
	status = m_previous_imsi.set_copy_of_buffer(tmp_imsi.Ptr(), tmp_imsi.Length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		User::Leave(
			m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, status)));
	}
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("imsi from DB"), tmp_imsi.Ptr(), tmp_imsi.Size()));
#endif

	if (required_identity == gsmsim_payload_AT_ANY_ID_REQ)
	{
		if (is_session_valid())
		{
			if(reauthId.Length() > 0)
			{

#if defined(USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)

				// Store the reauth id in case we are using asynchronous processing (= ISA interface)
				status = m_stored_reauth_id.set_copy_of_buffer(reauthId.Ptr(), reauthId.Length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(
						m_am_tools->convert_eapol_error_to_am_error(
							EAP_STATUS_RETURN(m_am_tools, status)));
				}	
#endif

				status = reauthentication_identity->set_copy_of_buffer(reauthId.Ptr(), reauthId.Length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(
						m_am_tools->convert_eapol_error_to_am_error(
							EAP_STATUS_RETURN(m_am_tools, status)));
				}
			}
		}
	}
	
	CleanupStack::PopAndDestroy(reauthIdBuf); // Delete reauthIdBuf
	
	if (required_identity == gsmsim_payload_AT_ANY_ID_REQ
			|| required_identity == gsmsim_payload_AT_FULLAUTH_ID_REQ)
	{
		if (pseudonymId.Length() > 0)
		{

#if defined(USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)

			// Store the pseudonym in case we are using
			// asynchronous processing (= ISA interface)
			status = m_stored_pseudonym.set_copy_of_buffer(
				pseudonymId.Ptr(),
				pseudonymId.Length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(
					m_am_tools->convert_eapol_error_to_am_error(
						EAP_STATUS_RETURN(m_am_tools, status)));
			}
#endif

			status = pseudonym_identity->set_copy_of_buffer(
				pseudonymId.Ptr(),
				pseudonymId.Length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(
					m_am_tools->convert_eapol_error_to_am_error(
						EAP_STATUS_RETURN(m_am_tools, status)));
			}
		}
	}

	CleanupStack::PopAndDestroy(pseudonymIdBuf); // Delete pseudonymIdBuf

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.

	CleanupStack::PopAndDestroy( &view ); // Close view.

	CleanupStack::PopAndDestroy(buf); // Delete buf

	if (IMSI->get_is_valid_data() == false
		|| IMSI->get_buffer_length() < SIM_IMSI_LENGTH)
	{
		status = IMSI->init(SIM_IMSI_LENGTH);
		if (status != eap_status_ok)
		{
			User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
		}

		IMSI->set_is_valid();
	}

	{
	
#if defined (USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)

		// For real GSM SIM interface.
		// Use real GSM SIM interface active object.
		// This gets the IMSI from the real GSM SIM, using Custom API.
		
		m_isa_if->QueryIMSIL();
		
		// KErrCompletion means that the operation is pending.
		User::Leave(KErrCompletion);
		
#elif defined(__WINS__) // For plugin tester.

		// Here we get the Nokia test SIM IMSI since the SIM interface is disabled.
		u32_t imsi_length = 0u;
		
		status = query_SIM_imsi(
			IMSI->get_buffer(SIM_IMSI_LENGTH),
			SIM_IMSI_LENGTH,
			&imsi_length);

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			User::Leave(
				m_am_tools->convert_eapol_error_to_am_error(
					EAP_STATUS_RETURN(m_am_tools, status)));
		}
		else if (imsi_length != SIM_IMSI_LENGTH)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			User::Leave(KErrGeneral);
		}
		
		status = IMSI->set_data_length(imsi_length);
		
		if (status != eap_status_ok)
		{			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			User::Leave(KErrGeneral);
		}

#endif // End of #if defined (USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)
	
	}	
		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

eap_status_e eap_am_type_gsmsim_symbian_c::complete_SIM_imsi_L(
	const eap_variable_data_c * const IMSI,
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_process_general_error);

	if (completion_status != eap_status_ok)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("complete_SIM_imsi_L: failed status=%d\n"),
			completion_status));

		send_error_notification(eap_status_identity_query_failed);

		// Signal upper layer
		status = get_am_partner()->complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query(
			IMSI, 
			&m_stored_pseudonym, 
			&m_stored_reauth_id, 
			0,
			EAP_TYPE_GSMSIM_DEFAULT_MNC_LENGTH_3_BYTES,
			m_stored_required_completion, 
			m_stored_received_eap_identifier,
			completion_status);	

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);		
	}

	if (IMSI == 0
		|| IMSI->get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("complete_SIM_imsi_L: failed no IMSI retrieved.\n"),
			completion_status));

		send_error_notification(eap_status_identity_query_failed);

		// IMSI query failed
		status = get_am_partner()->complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query(
			IMSI, 
			&m_stored_pseudonym, 
			&m_stored_reauth_id, 
			0,
			EAP_TYPE_GSMSIM_DEFAULT_MNC_LENGTH_3_BYTES,
			m_stored_required_completion, 
			m_stored_received_eap_identifier,
			eap_status_hardware_not_ready);	
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	if (m_previous_imsi.get_data_length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Previous IMSI not valid. Storing new IMSI.\n")));

		// Store new IMSI
		status = store_imsi(IMSI);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}		
	}
	else if (IMSI->compare(&m_previous_imsi) != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIM has been changed since last authentication. ")
			 EAPL("Clear pseudonym & reauth IDs.\n")));

		// Different IMSI -> SIM has been changed.
		// Reset pseudonym and reauthentication ID. 
		status = store_reauthentication_id(0, 0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		status = store_pseudonym_id(0, 0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		// Store new IMSI
		status = store_imsi(IMSI);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		// Reset stored pseudonym & reauthentication ID
		m_stored_pseudonym.reset();
		m_stored_reauth_id.reset();
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIM has not been changed.\n")));
	}

	status = get_am_partner()->complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query(
		IMSI,
		&m_stored_pseudonym,
		&m_stored_reauth_id,
		0,
		0ul,
		m_stored_required_completion,
		m_stored_received_eap_identifier,
		eap_status_ok);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

//#endif

	return status;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::cancel_SIM_IMSI_or_pseudonym_or_reauthentication_id_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
#if defined (USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)
	if (m_is_client == true)
	{
		m_isa_if->Cancel();
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
#else
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_not_supported;
	
#endif //#if defined (USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)
	
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::query_SIM_kc_and_sres(	
	const u8_t * const rand,
	u8_t * const kc,
	u8_t * const sres)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_ok);

#if !defined (USE_EAP_GSMSIM_INTERFACE)
	if (rand == 0
		|| kc == 0
		|| sres == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u8_t tmp[SIM_KC_LENGTH + SIM_SRES_LENGTH];
	m_am_tools->memset(tmp, 0, sizeof(tmp));

	status = m_sim_algorithm.generate_kc_sres(
		m_simulator_sim_algorithm,
		rand,
		SIM_RAND_LENGTH,
		tmp,
		SIM_KC_LENGTH + SIM_SRES_LENGTH);

	m_am_tools->memmove(sres, tmp, SIM_SRES_LENGTH);
	m_am_tools->memmove(kc, tmp + SIM_SRES_LENGTH, SIM_KC_LENGTH);

#elif defined (USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)

	TBuf8<SIM_RAND_LENGTH> rand_buf;
	rand_buf.Copy(rand, SIM_RAND_LENGTH);
	TRAPD(err, m_isa_if->QueryKcAndSRESL(rand_buf));	
	if (err != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("m_isa_if->QueryKcAndSRESL(): %d"),
			err));

		status = m_am_tools->convert_am_error_to_eapol_error(err);
		if (status == eap_status_process_general_error)
		{
			status = eap_status_credential_query_failed;
		}
		send_error_notification(status);
	}
	else
	{
		status = eap_status_pending_request;
	}
#else

	EAP_UNREFERENCED_PARAMETER(rand);
	EAP_UNREFERENCED_PARAMETER(kc);
	EAP_UNREFERENCED_PARAMETER(sres);
	
#endif //#if !defined (USE_EAP_GSMSIM_INTERFACE)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_am_type_gsmsim_symbian_c::complete_SIM_kc_and_sres_L(
	TDesC8& aKc,
	TDesC8& aSRES,
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("complete_SIM_kc_and_sres\n")));
	
	eap_status_e status(eap_status_ok);
	
	if (completion_status != eap_status_ok)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("complete_SIM_kc_and_sres_L: failed status=%d\n"),
			completion_status));

		send_error_notification(eap_status_credential_query_failed);

		// Signal upper layer
		status = get_am_partner()->complete_SIM_kc_sres(
			&m_copy_of_n_rands,
			&m_n_kc,
			&m_n_sres,
			completion_status);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);		
	}	
	
#if !defined(USE_EAP_GSMSIM_INTERFACE) || defined(__WINS__)
	EAP_UNREFERENCED_PARAMETER(aKc);
	EAP_UNREFERENCED_PARAMETER(aSRES);
#else

	if (static_cast<u32_t>(aKc.Length()) != SIM_KC_LENGTH
		|| static_cast<u32_t>(aSRES.Length()) != SIM_SRES_LENGTH)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("complete_SIM_kc_and_sres_L: Illegal length Kc or SRES\n")));

		send_error_notification(eap_status_credential_query_failed);

		status = get_am_partner()->complete_SIM_kc_sres(
			&m_copy_of_n_rands,
			&m_n_kc,
			&m_n_sres,
			eap_status_hardware_not_ready);		

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);		
	}

	m_rands_handled++;

	TInt rand_count = m_copy_of_n_rands.get_data_length() / SIM_RAND_LENGTH;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("complete_SIM_kc_and_sres: m_rands_handled=%d, rand_count=%d\n"),
		m_rands_handled,
		rand_count));

	status = m_n_kc.add_data(aKc.Ptr(), aKc.Size());
	if (status != eap_status_ok)
	{		
		send_error_notification(eap_status_credential_query_failed);

		// Signal upper layer
		status = get_am_partner()->complete_SIM_kc_sres(
			&m_copy_of_n_rands,
			&m_n_kc,
			&m_n_sres,
			status);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);		
	}
	
	status = m_n_sres.add_data(aSRES.Ptr(), aSRES.Size());
	if (status != eap_status_ok)
	{
		send_error_notification(eap_status_credential_query_failed);

		// Signal upper layer
		status = get_am_partner()->complete_SIM_kc_sres(
			&m_copy_of_n_rands,
			&m_n_kc,
			&m_n_sres,
			status);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);		
	}
	
	if (m_rands_handled == rand_count)
	{
		// All rands handled. Complete request.
		status = get_am_partner()->complete_SIM_kc_sres(
			&m_copy_of_n_rands,
			&m_n_kc,
			&m_n_sres,
			eap_status_ok);		
	}
	else
	{
		// Handle next rand.		
		u8_t *rand = m_copy_of_n_rands.get_data_offset(
			m_rands_handled*SIM_RAND_LENGTH,
			SIM_RAND_LENGTH);
		if (rand == 0)
		{
			send_error_notification(eap_status_credential_query_failed);

			// ERROR: Signal upper layer bacause of allocation error.
			status = get_am_partner()->complete_SIM_kc_sres(
				&m_copy_of_n_rands,
				&m_n_kc,
				&m_n_sres,
				eap_status_allocation_error);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);		
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP-SIM next RAND"),
			 rand,
			 SIM_RAND_LENGTH));

		status = query_SIM_kc_and_sres(
			rand,
			0,		 // Kc and SRES are handled in the complete function and ignored here in this asynchronous case
			0);
		
		if (status != eap_status_ok
			&& status != eap_status_pending_request)
		{
			send_error_notification(eap_status_credential_query_failed);

			// Signal upper layer
			status = get_am_partner()->complete_SIM_kc_sres(
				&m_copy_of_n_rands,
				&m_n_kc,
				&m_n_sres,
				status);					
		}

	}
#endif // defined(USE_EAP_GSMSIM_INTERFACE) || defined(__WINS__)
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::query_SIM_kc_sres(
	const bool must_be_synchronous,
	const eap_variable_data_c * const p_n_rands,
	eap_variable_data_c * const n_kc,
	eap_variable_data_c * const n_sres)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(must_be_synchronous);

	eap_status_e status(eap_status_process_general_error);
	// NOTE if user needs to use state_selector or n_rands after return from query_SIM_kc_sres()
	// function those parameters MUST be copied using copy() member function of each parameter.
	// For example: saved_n_rands = n_rands->copy()
	//              saved_state_selector = state_selector->copy()

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (n_kc == 0
		|| n_sres == 0
		|| p_n_rands == 0)
	{
		// Something is really wrong.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	m_rands_handled = 0ul;

#if !defined(USE_EAP_GSMSIM_INTERFACE) || defined(__WINS__)
	
	eap_variable_data_c *copy_of_n_rands = p_n_rands->copy();

	if (copy_of_n_rands == 0)
	{
		return eap_status_allocation_error;
	}

	u32_t count = copy_of_n_rands->get_data_length() / SIM_RAND_LENGTH;

	if (n_kc->get_is_valid_data() == false
		|| n_kc->get_buffer_length() < count*SIM_KC_LENGTH)
	{
		n_kc->init(count*SIM_KC_LENGTH);
		n_kc->set_is_valid();
	}

	if (n_sres->get_is_valid_data() == false
		|| n_sres->get_buffer_length() < count*SIM_SRES_LENGTH)
	{
		n_sres->init(count*SIM_SRES_LENGTH);
		n_sres->set_is_valid();
	}

	u8_t *rand = copy_of_n_rands->get_data(copy_of_n_rands->get_data_length());
	u8_t *kc = n_kc->get_data(n_kc->get_data_length());
	u8_t *sres = n_sres->get_data(n_sres->get_data_length());

	for (u32_t ind = 0u; ind < count; ind++)
	{
		query_SIM_kc_and_sres(			
			rand+(ind*SIM_RAND_LENGTH),
			kc+(ind*SIM_KC_LENGTH),
			sres+(ind*SIM_SRES_LENGTH));
	}

	n_kc->set_data_length(count*SIM_KC_LENGTH);
	n_sres->set_data_length(count*SIM_SRES_LENGTH);

	status = get_am_partner()->complete_SIM_kc_sres(
		copy_of_n_rands,
		n_kc,
		n_sres,
		eap_status_ok);

	delete copy_of_n_rands;

	if (status == eap_status_ok)
	{
		status = eap_status_completed_request;
	}

#else

	// This is for ISA interface			
	status = m_copy_of_n_rands.set_copy_of_buffer(p_n_rands);
	if (status != eap_status_ok)
	{		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}		

	u8_t *rand = m_copy_of_n_rands.get_data(SIM_RAND_LENGTH);
	if (rand == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_n_kc.reset();
	m_n_sres.reset();
	
	status = query_SIM_kc_and_sres(
		rand,
		0,		 // Kc and SRES are handled in the complete function and ignored here in this asynchronous case
		0);

#endif // !defined(USE_EAP_GSMSIM_INTERFACE) || defined(__WINS__)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//-------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::cancel_SIM_kc_sres_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		
#if defined (USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)
	if (m_is_client == true)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_gsmsim_symbian_c::cancel_SIM_kc_sres_query() - cancelling IF query\n")));
	
		m_isa_if->Cancel();
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
#else
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
	
#endif //#if defined (USE_EAP_GSMSIM_INTERFACE) && !defined(__WINS__)
		
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::handle_gsmsim_notification(
	eap_gsmsim_notification_codes_e gsmsim_notification_code )
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	switch ((gsmsim_notification_code & gsmsim_notification_code_value))
	{
	case eap_gsmsim_notification_no_F_no_P_user_has_not_subscribed_to_the_requested_service:
		send_error_notification(eap_status_user_has_not_subscribed_to_the_requested_service);
		break;

	case eap_gsmsim_notification_no_F_no_P_users_calls_are_barred:
		send_error_notification(eap_status_users_calls_are_barred);
		break;

	default:
		// Do nothing
		break;
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_am_type_gsmsim_symbian_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_am_type_gsmsim_symbian_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::type_configure_read(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_ASSERT(data != 0);
	EAP_ASSERT(field != 0);

	eap_status_e status(eap_status_ok);

	m_am_tools->trace_configuration(
		status,
		field,
		data);

	// Trap must be set here because the OS independent portion of EAP SIM
	// that calls this function does not know anything about Symbian.	
	TRAPD(err, type_configure_readL(
		field->get_field(),
		field->get_field_length(),
		data));
	if (err != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_gsmsim_symbian_c::type_configure_read(): LEAVE from type_configure_readL, error=%d, Reads configuration from partner.\n"),
			err));

		status = m_partner->read_configure(
			field,
			data);
	}

	m_am_tools->trace_configuration(
		status,
		field,
		data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_type_gsmsim_symbian_c::type_configure_readL(
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
		
	// Buffer for unicode parameter
	HBufC* unicodebuf = HBufC::NewLC(KMaxDBFieldNameLength);
	TPtr unicodeString = unicodebuf->Des();
	
	// Convert to unicode 
	unicodeString.Copy(asciiString);
	
	// Now do the database query
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLQueryRow,
		&unicodeString,
		&KSimTableName, 
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());
	
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
						User::Leave(
							m_am_tools->convert_eapol_error_to_am_error(
								EAP_STATUS_RETURN(m_am_tools, status)));
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
					User::Leave(
						m_am_tools->convert_eapol_error_to_am_error(
							EAP_STATUS_RETURN(m_am_tools, status)));
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
	
	CleanupStack::PopAndDestroy(4); // Close view, & 3 strings

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void eap_am_type_gsmsim_symbian_c::send_error_notification(const eap_status_e error)
{
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
		eap_type_gsmsim,
		eap_state_none,
		eap_general_state_authentication_error,
		0,
		false);

	notification.set_authentication_error(error);

	m_partner->state_notification(&notification);
}


//--------------------------------------------------
//
// SERVER / TEST CODE BEGINS.
//
//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)
	#include "read_rand_and_triplets.h"
#endif //#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)


EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::query_SIM_triplets(
	const bool /*must_be_synchronous*/,
	const eap_variable_data_c * const /*p_username*/,
	eap_variable_data_c * const /* p_imsi */,
	eap_type_sim_triplet_array_c * const triplets,
	eap_type_gsmsim_identity_type * const /* type */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	// Only used in EAP SIM server.
	
	// NOTE if user needs to use state_selector or imsi after return from query_SIM_triplets()
	// function those parameters MUST be copied using copy() member function of each parameter.
	// For example: saved_imsi = p_imsi_or_pseudonym->copy()
	//              saved_state_selector = state_selector->copy()

	eap_status_e status = eap_status_process_general_error;

#if !defined (USE_EAP_GSMSIM_INTERFACE)

	if (triplets == 0)
	{
		// Something is really wrong.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_process_general_error;
	}

#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)
	if (m_triplet_file.get_is_valid() == true)
	{
		status = read_triplets_from_file(m_am_tools, &m_triplet_file, triplets);
	} else
#endif // defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)
	{
		const u32_t rand_length = 16u;
		u8_t test_rand[] = "0123456789abcdef";
		const u32_t triplet_count = 2u;
		u32_t ind;
		
		triplets->set_triplet_count(triplet_count);

		for (ind = 0u; ind < triplet_count; ind++)
		{
			eap_type_saesim_triplet_c *tripl = triplets->get_triplet(m_am_tools, ind);
			u8_t tmp[rand_length] = {0,};
	
			status = m_am_tools->get_crypto()->get_rand_bytes(
				test_rand,
				sizeof(test_rand)-1u);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return status;
			}

			status = tripl->get_rand()->set_copy_of_buffer(reinterpret_cast<u8_t *>(test_rand), rand_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return status;
			}
	
			status = tripl->get_kc()->init(SIM_KC_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return status;
			}

			tripl->get_kc()->set_is_valid();
			tripl->get_kc()->set_data_length(SIM_KC_LENGTH);

			status = tripl->get_sres()->init(SIM_SRES_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return status;
			}
	
			tripl->get_sres()->set_is_valid();
			tripl->get_sres()->set_data_length(SIM_SRES_LENGTH);
	
			m_sim_algorithm.generate_kc_sres(
				m_simulator_sim_algorithm,
				test_rand,
				rand_length,
				tmp,
				SIM_KC_LENGTH + SIM_SRES_LENGTH);
	
			status = tripl->get_sres()->set_copy_of_buffer(tmp, SIM_SRES_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			status = tripl->get_kc()->set_copy_of_buffer(tmp + SIM_SRES_LENGTH, SIM_KC_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

#else
	EAP_UNREFERENCED_PARAMETER(triplets);
#endif // #if !defined (USE_EAP_GSMSIM_INTERFACE)
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::cancel_SIM_triplets_query()
{
	EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: cancel_SIM_triplets_query() not supported here..\n")));
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::generate_encryption_IV(
	eap_variable_data_c * const encryption_IV,
		const u32_t IV_length)
{
	// EAP SIM server only.
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = encryption_IV->init(IV_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	encryption_IV->set_is_valid();
	encryption_IV->set_data_length(IV_length);

	m_am_tools->get_crypto()->add_rand_seed_hw_ticks();

	status = m_am_tools->get_crypto()->get_rand_bytes(
		encryption_IV->get_data(encryption_IV->get_data_length()),
		encryption_IV->get_data_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::query_imsi_from_username(
	const bool must_be_synchronous,
	const u8_t next_eap_identifier,
	const eap_am_network_id_c * const network_id,
	const eap_variable_data_c * const username,
	eap_variable_data_c * const imsi,
	eap_type_gsmsim_identity_type * const identity_type,
	const eap_type_gsmsim_complete_e /* completion_action */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(must_be_synchronous);
	EAP_UNREFERENCED_PARAMETER(next_eap_identifier);	
	EAP_UNREFERENCED_PARAMETER(network_id);	
	// Setup headers for comparison
	
	_LIT8(KReauthHeader, "RE");
	TBufC8<2> reauthHeader(KReauthHeader);	

	_LIT8(KPseudonymHeader, "PS");
	TBufC8<2> pseudonymHeader(KPseudonymHeader);

	if (username->get_data_length() >= 2)
	{
		TBuf8<2> head;
		head.Append(username->get_data(2), KIdentityHeaderLength);
		// Note this is syncronous call.

		const u8_t * const username_prefix = username->get_data_offset(0u, 1u);

		if (username->get_data_length() <= SIM_IMSI_LENGTH+1u
			&& username->get_data_length() > 1u
			&& username_prefix != 0
			&& *username_prefix == *GSMSIM_IMSI_PREFIX_CHARACTER)
		{
			// We have IMSI.
			eap_status_e status = imsi->set_copy_of_buffer(
				username->get_data_offset(1u, username->get_data_length()-1u),
				username->get_data_length()-1u);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			*identity_type = GSMSIM_IDENTITY_TYPE_IMSI_ID;

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("IMSI"),
				 imsi->get_data(imsi->get_data_length()),
				 imsi->get_data_length()));
			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("query_imsi_from_username(): Used EAP-Identity type %d.\n"),
				 *identity_type));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (head == reauthHeader) 
		{
			eap_status_e status = imsi->add_data(
				username->get_data_offset(KIdentityHeaderLength,
										  SIM_IMSI_LENGTH),
				SIM_IMSI_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			*identity_type = GSMSIM_IDENTITY_TYPE_RE_AUTH_ID;	
		}
		else if (head == pseudonymHeader) 
		{
			eap_status_e status = imsi->add_data(
				username->get_data_offset(
					KIdentityHeaderLength,
					SIM_IMSI_LENGTH),
				SIM_IMSI_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			*identity_type = GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID;
		}
		else
		{
			*identity_type = GSMSIM_IDENTITY_TYPE_NONE;		
		}
	}
	else
	{
		*identity_type = GSMSIM_IDENTITY_TYPE_NONE;		
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;

}

#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::cancel_imsi_from_username_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::check_is_rand_unused(
	const eap_variable_data_c * const /* n_rands */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::set_rand_is_used(
	const eap_variable_data_c * const /* n_rands */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::generate_reauthentication_id(
	const eap_am_network_id_c * const network_id,
	const eap_variable_data_c * const imsi,
	eap_variable_data_c * const reauthentication_identity,
	const u32_t maximum_reauthentication_identity_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_process_general_error);
	_LIT8(KTmp, "RE");
	TBufC8<KIdentityHeaderLength> header(KTmp);
	reauthentication_identity->reset();
	status = reauthentication_identity->add_data(header.Ptr(), KIdentityHeaderLength);
	if (status != eap_status_ok)
	{
		reauthentication_identity->reset();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	status = generate_identity(network_id, imsi, reauthentication_identity, 
							   maximum_reauthentication_identity_length);
	if (status != eap_status_ok)
	{
		reauthentication_identity->reset();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = reauthentication_identity->add_data(GSMSIM_AT_CHARACTER, GSMSIM_AT_CHARACTER_LENGTH);
	if (status != eap_status_ok)
	{
		reauthentication_identity->reset();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = reauthentication_identity->add_data(&m_nai_realm);
	if (status != eap_status_ok)
	{
		reauthentication_identity->reset();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::generate_pseudonym_id(
	const eap_am_network_id_c * const network_id,
	const eap_variable_data_c * const imsi,
	eap_variable_data_c * const pseudonym,
	const u32_t maximum_pseudonym_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_process_general_error);
	_LIT8(KTmp, "PS");
	TBufC8<KIdentityHeaderLength> header(KTmp);	
	status = pseudonym->add_data(header.Ptr(), KIdentityHeaderLength);
	if (status != eap_status_ok)
	{
		pseudonym->reset();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	status = generate_identity(network_id, imsi, pseudonym, maximum_pseudonym_length);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

eap_status_e eap_am_type_gsmsim_symbian_c::generate_identity(
	const eap_am_network_id_c * const /* network_id */,
	const eap_variable_data_c * const imsi,
	eap_variable_data_c * const identity,
	const u32_t /*maximum_identity_length*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = identity->add_data(imsi);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_symbian_c::type_configure_write(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	// NOTE: At the moment this is not called anywhere.
	// NOTE: This is really just for simulation.
	// Write is routed to partner object.
	eap_status_e status = m_partner->write_configure(
			field,
			data);
	return status;
}

//--------------------------------------------------

bool eap_am_type_gsmsim_symbian_c::is_session_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	bool sessionValidity(false);
	
	TRAPD(err, sessionValidity = is_session_validL());
	if (err != KErrNone) 
	{
		EAP_TRACE_ERROR(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("eap_am_type_gsmsim_symbian_c::is_session_valid - LEAVE - error=%d, Assuming session is invalid \n"),
			err));
			
		sessionValidity = false;
	}
	 		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	return sessionValidity;
}

//--------------------------------------------------

bool eap_am_type_gsmsim_symbian_c::is_session_validL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_gsmsim_symbian_c::is_session_validL - start \n")));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT(KSQLQuery, "SELECT %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLQuery,
		&cf_str_EAP_GSMSIM_max_session_validity_time_literal,
		&KGSMSIMLastFullAuthTime,
		&KSimTableName,
		&KServiceType,
		m_index_type, 
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());

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
		
	TInt64 maxSessionTime = view.ColInt64(colSet->ColNo(cf_str_EAP_GSMSIM_max_session_validity_time_literal));
	TInt64 fullAuthTime = view.ColInt64(colSet->ColNo(KGSMSIMLastFullAuthTime));

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
		
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("eap_am_type_gsmsim_symbian_c::is_session_validL:interval in microseconds:"),
			&(interval.Int64()),
			sizeof(interval.Int64()) ) );
			
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("eap_am_type_gsmsim_symbian_c::is_session_validL:max session time in microseconds:"),
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
			(EAPL("eap_am_type_gsmsim_symbian_c::is_session_validL()")
			 EAPL("interval in Minutes =%d\n"),
			 intervalMins.Int()));
	}
	
#endif


	if( maxSessionTime >= interval.Int64() )
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_gsmsim_symbian_c::is_session_validL - Session Valid \n")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			

		return true;	
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_gsmsim_symbian_c::is_session_validL - Session NOT Valid \n")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			
		
		return false;	
	}
}

//--------------------------------------------------

void eap_am_type_gsmsim_symbian_c::store_authentication_timeL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_gsmsim_symbian_c::store_authentication_timeL - start \n")));	

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT(KSQLQuery, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLQuery,
		&KGSMSIMLastFullAuthTime,
		&KSimTableName,
		&KServiceType,
		m_index_type, 
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());

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
	(EAPL("eap_am_type_gsmsim_symbian_c::store_authentication_time, %2d-%2d-%4d : %2d-%2d-%2d-%d\n"), 
	currentDateTime.Day()+1, currentDateTime.Month()+1,currentDateTime.Year(), currentDateTime.Hour(),
	currentDateTime.Minute(), currentDateTime.Second(), currentDateTime.MicroSecond()));

#endif

	TInt64 fullAuthTime = currentTime.Int64();
	
	view.SetColL(colSet->ColNo(KGSMSIMLastFullAuthTime), fullAuthTime);

	view.PutL();	

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	CleanupStack::PopAndDestroy(&view); // Close view.
	CleanupStack::PopAndDestroy(buf); // Delete buf.

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			
}

//--------------------------------------------------

//  End of File
