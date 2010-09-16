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
* %version: 95 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 151 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "eapol_am_wlan_authentication_symbian.h"
#include "abs_eapol_am_wlan_authentication.h"

#include "eap_header_string.h"
//#include "eap_type_all.h"
#include "eap_config.h"
#include "eap_file_config.h"
#include "eap_am_file_input_symbian.h"
#include "eap_type_selection.h"
#include "eapol_key_types.h"
#include "eap_timer_queue.h"
#include "eap_crypto_api.h"
#include "abs_eap_database_reference_if.h"
#include "abs_eap_state_notification.h"
#include "eap_state_notification.h"
#include "eap_automatic_variable.h"
#include "eap_base_type.h"
#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "eap_core_client_message_if.h"

#include "EapolDbDefaults.h"
#include "EapolDbParameterNames.h"
#include "EapConversion.h"
#include "EapConfigToolsSymbian.h"
#include "EapPluginTools.h"

#include <wdbifwlansettings.h>

const TUint KMaxSqlQueryLength = 2048;

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_am_wlan_authentication_symbian_c::~eapol_am_wlan_authentication_symbian_c()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::~eapol_am_wlan_authentication_symbian_c(): this = 0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::~eapol_am_wlan_authentication_symbian_c()");
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_am_wlan_authentication_symbian_c::eapol_am_wlan_authentication_symbian_c(
	abs_eap_am_tools_c * const tools,
	const bool is_client_when_true)
: m_am_partner(0)
#if defined(USE_EAP_SIMPLE_CONFIG)
, m_configuration_if(0)
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
, m_am_tools(tools)
, m_fileconfig(0)
, m_SSID(tools)
, m_wpa_preshared_key(tools)
, m_wpa_preshared_key_hash(tools)
, m_database_reference(tools)
, m_receive_network_id(tools)
, m_selected_eapol_key_authentication_type(eapol_key_authentication_type_none)
, m_WPA_override_enabled(false)
, m_is_client(is_client_when_true)
, m_is_valid(false)

{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::eapol_am_wlan_authentication_symbian_c(): this = 0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::eapol_am_wlan_authentication_symbian_c()");

	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eapol_am_wlan_authentication_symbian_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::get_is_valid(): this = 0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::get_is_valid()");

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

void eapol_am_wlan_authentication_symbian_c::TryInitDatabaseL()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_wlan_authentication_symbian_c::TryOpenDatabaseL()\n")));	
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::TryInitDatabaseL()");
		
	// 1. Open/create a database	
	RDbNamedDatabase db;

	// Create the secure shared database (if necessary) with the specified secure policy.
	// Database will be created in the data caging path for DBMS (C:\private\100012a5).

	TFileName aPrivateDatabasePathName;

	EapPluginTools::GetPrivatePathL(
		m_session,
		aPrivateDatabasePathName);

	aPrivateDatabasePathName.Append(KEapolDatabaseName);

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("aPrivateDatabasePathName",
		aPrivateDatabasePathName.Ptr(),
		aPrivateDatabasePathName.Size()));

	TInt error = db.Create(m_session, aPrivateDatabasePathName);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TryOpenDatabaseL() - Created Secure DB for eapol.dat. error=%d\n"), error ));	
		
	if(error == KErrNone)
	{	
		db.Close();
		
	} else if (error != KErrAlreadyExists) 
	{
		User::LeaveIfError(error);
	}
	
	User::LeaveIfError(db.Open(m_session, aPrivateDatabasePathName));	
		
	CleanupClosePushL(db);

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// 2. Create the table for pre-shared keys in database (ignore error if exists)

	//// NAME /////////////////////////////////////////////////// TYPE ////////////// Constant ///////
	//| ServiceType											  | UNSIGNED INTEGER | KServiceType    |//
	//| ServiceIndex										  | UNSIGNED INTEGER | KServiceIndex   |//
	//| SSID												  | VARBINARY(255)	 | KSSID		   |//	
	//| Password											  | VARBINARY(255)	 | KPassword	   |//	
	//| PSK												      | VARBINARY(255)   | KPSK			   |//	
	//////////////////////////////////////////////////////////////////////////////////////////////////	
	_LIT(KSQLCreateTable2, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S VARBINARY(255), \
											 %S VARBINARY(255), \
											 %S VARBINARY(255))");
	sqlStatement.Format(KSQLCreateTable2, &KEapolPSKTableName, 
		&KServiceType, &KServiceIndex, &KSSID, &KPassword, &KPSK);
	error = db.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}
	
	CleanupStack::PopAndDestroy(buf);
	
	// If compacting is not done the database will start growing
	db.Compact();
	
	CleanupStack::PopAndDestroy(&db);
}

//--------------------------------------------------

void eapol_am_wlan_authentication_symbian_c::InitDatabaseL()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_wlan_authentication_symbian_c::InitDatabaseL()\n")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::InitDatabaseL()");

	// Create the database (if necessary)
	TRAPD(error, TryInitDatabaseL());
	if (error != KErrNone)
	{
		// Because of error remove the database file.
		TFileName aPrivateDatabasePathName;

		EapPluginTools::GetPrivatePathL(
			m_session,
			aPrivateDatabasePathName);

		aPrivateDatabasePathName.Append(KEapolDatabaseName);

		EAP_TRACE_DATA_DEBUG_SYMBIAN(("aPrivateDatabasePathName",
			aPrivateDatabasePathName.Ptr(),
			aPrivateDatabasePathName.Size()));

		error = m_session.Delete(aPrivateDatabasePathName);
		if(error != KErrNone)
		{
			User::Leave(KErrCorrupt);
		}		

		// Try open database again. This will leave if fails second time.
		TryInitDatabaseL();
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::configure(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::configure()");

	TInt error(KErrNone);
	eap_status_e status(eap_status_process_general_error);

	// Open the database session
	error = m_session.Connect();
	if (error != KErrNone)
	{
		eap_status_e status(m_am_tools->convert_am_error_to_eapol_error(error));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: RDbs::Connect() failed %d=%s.\n"),
			status,
			eap_status_string_c::get_status_string(status)));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Database session initialized...\n")));

	// Initialize database
	TRAP(error, InitDatabaseL());
	if (error != KErrNone)
	{
		eap_status_e status(m_am_tools->convert_am_error_to_eapol_error(error));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: InitDatabaseL failed %d=%s.\n"),
			status,
			eap_status_string_c::get_status_string(status)));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Database initialized...\n")));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = EapConfigToolsSymbian::EapReadDefaultConfigFileSymbian(
		m_am_tools,
		&m_fileconfig);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_FILE_TRACE)
	{
		eap_variable_data_c trace_output_file(m_am_tools);

		status = read_configure(
			cf_str_EAP_TRACE_output_file_name.get_field(),
			&trace_output_file);
		if (status == eap_status_ok
			&& trace_output_file.get_is_valid_data() == true)
		{
			status = m_am_tools->set_trace_file_name(&trace_output_file);
			if (status == eap_status_ok)
			{
				// OK, set the default trace mask.
				m_am_tools->set_trace_mask(
					eap_am_tools_c::eap_trace_mask_debug
					| eap_am_tools_c::eap_trace_mask_always
					| eap_am_tools_c::eap_trace_mask_error
					| eap_am_tools_c::eap_trace_mask_message_data);
			}
		}
	}
#endif //#if defined(USE_EAP_FILE_TRACE)


	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		eap_variable_data_c EAP_TRACE_enable_timer_traces(m_am_tools);

		status = read_configure(
			cf_str_EAP_TRACE_enable_timer_traces.get_field(),
			&EAP_TRACE_enable_timer_traces);
		if (status == eap_status_ok
			&& EAP_TRACE_enable_timer_traces.get_is_valid_data() == true)
		{
			u32_t *enable_timer_traces = reinterpret_cast<u32_t *>(
				EAP_TRACE_enable_timer_traces.get_data(sizeof(u32_t)));
			if (enable_timer_traces != 0
				&& *enable_timer_traces != 0)
			{
				m_am_tools->set_trace_mask(
					m_am_tools->get_trace_mask()
					| TRACE_FLAGS_TIMER
					);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		eap_variable_data_c EAP_TRACE_enable_timer_queue_traces(m_am_tools);

		status = read_configure(
			cf_str_EAP_TRACE_enable_timer_queue_traces.get_field(),
			&EAP_TRACE_enable_timer_queue_traces);
		if (status == eap_status_ok
			&& EAP_TRACE_enable_timer_queue_traces.get_is_valid_data() == true)
		{
			u32_t *enable_timer_queue_traces = reinterpret_cast<u32_t *>(
				EAP_TRACE_enable_timer_queue_traces.get_data(sizeof(u32_t)));
			if (enable_timer_queue_traces != 0
				&& *enable_timer_queue_traces != 0)
			{
				m_am_tools->set_trace_mask(
					m_am_tools->get_trace_mask()
					| TRACE_FLAGS_TIMER_QUEUE
					);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		eap_variable_data_c EAP_TRACE_enable_function_traces(m_am_tools);

		status = read_configure(
			cf_str_EAP_TRACE_enable_function_traces.get_field(),
			&EAP_TRACE_enable_function_traces);
		if (status == eap_status_ok
			&& EAP_TRACE_enable_function_traces.get_is_valid_data() == true)
		{
			u32_t *enable_function_traces = reinterpret_cast<u32_t *>(
				EAP_TRACE_enable_function_traces.get_data(sizeof(u32_t)));
			if (enable_function_traces != 0
				&& *enable_function_traces != 0)
			{
				m_am_tools->set_trace_mask(
					m_am_tools->get_trace_mask()
					| eap_am_tools_c::eap_trace_mask_functions
					);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Created timer...\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::shutdown(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::shutdown()");

	m_session.Close();

	delete m_fileconfig;
	m_fileconfig = 0;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::set_am_partner(
	abs_eapol_am_wlan_authentication_c * am_partner
#if defined(USE_EAP_SIMPLE_CONFIG)
	, abs_eap_configuration_if_c * const configuration_if
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_simulator_c::set_am_partner(): %s, this = 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::set_am_partner()");

	m_am_partner = am_partner;

#if defined(USE_EAP_SIMPLE_CONFIG)
	m_configuration_if = configuration_if;
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::reset_wpa_configuration()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::reset_wpa_configuration(): %s, this = 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::reset_wpa_configuration()");

	TRAPD(error, ReadWPASettingsL());
	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP settings reading from CommDb failed or cancelled(error %d).\n"), error));

		eap_status_e status(m_am_tools->convert_am_error_to_eapol_error(error));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

void eapol_am_wlan_authentication_symbian_c::send_error_notification(const eap_status_e error)
{
	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::send_error_notification, error=%d\n"),
		error));	
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::send_error_notification()");

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
		eap_type_none,
		eap_state_none,
		general_state_variable,
		0,
		false);

	notification.set_authentication_error(error);

	m_am_partner->state_notification(&notification);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::set_wlan_parameters(
	const eap_variable_data_c * const SSID,
	const bool WPA_override_enabled,
	const eap_variable_data_c * const wpa_preshared_key,
	const eapol_key_authentication_type_e selected_eapol_key_authentication_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::set_wlan_parameters(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::set_wlan_parameters()");

	m_WPA_override_enabled = WPA_override_enabled;

	m_selected_eapol_key_authentication_type = selected_eapol_key_authentication_type;

	eap_status_e status = m_SSID.set_copy_of_buffer(SSID);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_wpa_preshared_key.set_copy_of_buffer(wpa_preshared_key);
	if (status != eap_status_ok)
	{
		send_error_notification(eap_status_key_error);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_selected_eapol_key_authentication_type == eapol_key_authentication_type_WPS)
	{
		// Normally here is HASH of WPA pre-shared key, but when connection is Wi-fi Protected setup here is PIN or push button (00000000) key.
		status = m_wpa_preshared_key_hash.set_copy_of_buffer(wpa_preshared_key);
		if (status != eap_status_ok)
		{
			send_error_notification(eap_status_key_error);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("new m_wpa_preshared_key_hash for WPS"),
			m_wpa_preshared_key_hash.get_data(),
			m_wpa_preshared_key_hash.get_data_length()));
	}

    EAP_TRACE_DATA_DEBUG(
        m_am_tools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("new m_SSID"),
        m_SSID.get_data(),
        m_SSID.get_data_length()));

    EAP_TRACE_DATA_DEBUG(
        m_am_tools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("new m_wpa_preshared_key"),
        m_wpa_preshared_key.get_data(),
        m_wpa_preshared_key.get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eapol_am_wlan_authentication_symbian_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::state_notification(): this = 0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::state_notification()");

	EAP_UNREFERENCED_PARAMETER(state);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::association(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::association(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::association()");

	eap_status_e status = m_receive_network_id.set_copy_of_network_id(receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::disassociation(
	const eap_am_network_id_c * const /* receive_network_id */ ///< source includes remote address, destination includes local address.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::disassociation(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::disassociation()");

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::get_wlan_configuration(
	eap_variable_data_c * const wpa_preshared_key_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::get_wlan_configuration(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::get_wlan_configuration()");

	// Normally here is HASH of WPA pre-shared key, but when connection is Wi-fi Protected setup here is PIN or push button (00000000) key.
	eap_status_e status = wpa_preshared_key_hash->set_copy_of_buffer(&m_wpa_preshared_key_hash);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::authentication_finished(
	const bool when_true_successfull,
	const eap_type_value_e /* eap_type */,
	const eapol_key_authentication_type_e authentication_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::authentication_finished(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::authentication_finished()");

	if (when_true_successfull == true)
	{
		if (authentication_type != eapol_key_authentication_type_RSNA_PSK
			&& authentication_type != eapol_key_authentication_type_WPA_PSK)
		{
			// Move the active eap type index to the first type
			m_am_partner->set_current_eap_index(0ul);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e eapol_am_wlan_authentication_symbian_c::read_database_reference_values(
	TIndexType * const type,
	TUint * const index)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::read_database_reference_values(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::read_database_reference_values()");

	const eapol_wlan_database_reference_values_s * const database_reference_values
		= reinterpret_cast<eapol_wlan_database_reference_values_s *>(
		m_database_reference.get_data(sizeof(eapol_wlan_database_reference_values_s)));
	if (database_reference_values == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	*type = static_cast<TIndexType>(database_reference_values->m_database_index_type);
	*index = database_reference_values->m_database_index;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_wlan_authentication_symbian_c::read_database_reference_values(): Type=%d, Index=%d.\n"),
		 *type,
		 *index));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_ASSERT_ALWAYS(data != NULL);
	
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::read_configure(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eapol_am_wlan_authentication_symbian_c::read_configure()");

	// Trap must be set here because the OS independent portion of EAPOL
	// that calls this function does not know anything about Symbian.	
	eap_status_e status(eap_status_ok);

	// Check if the wanted parameter is default type

	eap_variable_data_c wanted_field(m_am_tools);
	eap_variable_data_c type_field(m_am_tools);
	
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
		cf_str_EAP_default_type_hex_data.get_field()->get_field(),
		cf_str_EAP_default_type_hex_data.get_field()->get_field_length(),
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// It was something else than EAP type. Read it from eapol DB.
	_LIT( KEapolTableName, "eapol" );

	TFileName aPrivateDatabasePathName;

	TRAPD(err, EapPluginTools::GetPrivatePathL(
		m_session,
		aPrivateDatabasePathName));
		
	if (err)
		{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
		}

	aPrivateDatabasePathName.Append(KEapolDatabaseName);

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("aPrivateDatabasePathName",
		aPrivateDatabasePathName.Ptr(),
		aPrivateDatabasePathName.Size()));

	TRAPD( error, read_configureL(
		aPrivateDatabasePathName,
		KEapolTableName,
		field->get_field(),
		field->get_field_length(),
		data) );

	// Try to read it for eap fast DB	
	HBufC8* fieldBuf = HBufC8::New( field->get_field_length() );

	eap_automatic_variable_c<HBufC8> automatic_fieldBuf(
		m_am_tools,
		fieldBuf);

	if (fieldBuf == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	TPtr8 fieldPtr = fieldBuf->Des();
	fieldPtr.Copy( reinterpret_cast<const TUint8 *> ( field->get_field() ));

	if (error != KErrNone) 
	{
		status = m_am_tools->convert_am_error_to_eapol_error(error);

#if defined(USE_EAP_FILECONFIG)
		if (m_fileconfig != 0
			&& m_fileconfig->get_is_valid() == true)
		{
			// Here we could try the final configuration option.
			status = m_fileconfig->read_configure(
				field,
				data);
		}
#endif //#if defined(USE_EAP_FILECONFIG)
	}

	m_am_tools->trace_configuration(
		status,
		field,
		data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eapol_am_wlan_authentication_symbian_c::read_configureL(
	const TDesC& aDbName,
	const TDesC& aTableName,
	eap_config_string field,
	const u32_t /*field_length*/,
	eap_variable_data_c * const data)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::read_configureL(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
	EAP_TRACE_RETURN_STRING_FLAGS(m_am_tools, TRACE_FLAGS_DEFAULT, "returns: eapol_am_wlan_authentication_symbian_c::read_configureL()");

	// Open database
	RDbNamedDatabase db;

	TInt error = db.Open(m_session, aDbName);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::read_configureL(): db.Open(), error = %d\n"),
		 error));

	User::LeaveIfError(error);
	
	CleanupClosePushL(db);


	// Create a buffer for the ascii strings - initialised with the argument
	HBufC8* asciibuf = HBufC8::NewLC(128);
	TPtr8 asciiString = asciibuf->Des();
	asciiString.Copy(reinterpret_cast<const unsigned char *>(field));
		
	// Buffer for unicode parameter
	HBufC* unicodebuf = HBufC::NewLC(128);
	TPtr unicodeString = unicodebuf->Des();
	
	// Convert to unicode 
	unicodeString.Copy(asciiString);

	// Now do the database query
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	_LIT(KSQLQueryRow, "SELECT %S FROM %S");
	sqlStatement.Format( KSQLQueryRow, &unicodeString, &aTableName );
	
	RDbView view;
	User::LeaveIfError(view.Prepare(db, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());	
	if (view.FirstL())
	{
		eap_status_e status(eap_status_process_general_error);
		view.GetL();		
		switch (view.ColType(1))
		{
		case EDbColText:				
			{
				unicodeString = view.ColDes(1);
				// Convert to 8-bit
				asciiString.Copy(unicodeString);
				if (asciiString.Size() > 0)
				{
					status = data->set_copy_of_buffer(asciiString.Ptr(), asciiString.Size());
					if (status != eap_status_ok)
					{
						User::Leave(m_am_tools->convert_eapol_error_to_am_error(
							EAP_STATUS_RETURN(m_am_tools, status)));
					}
				} 
				else 
				{
					// Empty field. Do nothing...data remains invalid and the stack knows what to do hopefully.
					break;
				}
			}
			break;
		case EDbColUint32:
			{
				TUint value;
				value = view.ColUint32(1);
				status = data->set_copy_of_buffer((const unsigned char *) &value, sizeof(value));
				if (status != eap_status_ok)
				{
					User::Leave(m_am_tools->convert_eapol_error_to_am_error(
						EAP_STATUS_RETURN(m_am_tools, status)));
				}
			}
			break;
		default:
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: read_configureL: Unexpected column type.\n")));
			User::Panic(_L("EAPOL"), 1);			
		}
	} 
	else 
	{
		// Could not find parameter
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: read_configureL: Could not find configuration parameter.\n")));
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
							EAP_STATUS_RETURN(m_am_tools, eap_status_not_found)));
	}		
	
	// Close database
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);
	CleanupStack::PopAndDestroy(unicodebuf);
	CleanupStack::PopAndDestroy(asciibuf);
	CleanupStack::PopAndDestroy(&db);


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::write_configure(
	const eap_configuration_field_c * const /* field */,
	eap_variable_data_c * const /* data */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = eap_status_illegal_configure_field;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::set_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id, 
	void * const p_data,
	const u32_t p_time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::set_timer(): this = 0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::set_timer()");

	const eap_status_e status = m_am_tools->am_set_timer(
		p_initializer, 
		p_id, 
		p_data,
		p_time_ms);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::cancel_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::cancel_timer(): this = 0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::cancel_timer()");

	const eap_status_e status = m_am_tools->am_cancel_timer(
		p_initializer, 
		p_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::cancel_all_timers(): this = 0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::cancel_all_timers()");

	const eap_status_e status = m_am_tools->am_cancel_all_timers();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eapol_am_wlan_authentication_symbian_c::RetrievePSKL(TPSKEntry& entry)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::RetrievePSKL(): this = 0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::RetrievePSKL()");

	// Open database
	RDbNamedDatabase db;

	TFileName aPrivateDatabasePathName;

	EapPluginTools::GetPrivatePathL(
		m_session,
		aPrivateDatabasePathName);

	aPrivateDatabasePathName.Append(KEapolDatabaseName);

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("aPrivateDatabasePathName",
		aPrivateDatabasePathName.Ptr(),
		aPrivateDatabasePathName.Size()));

	TInt error = db.Open(m_session, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::RetrievePSKL(): db.Open(), error = %d\n"),
		 error));

	User::LeaveIfError(error);
	
	CleanupClosePushL(db);

	HBufC* sqlbuf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = sqlbuf->Des();

	RDbView view;

	CleanupClosePushL(view);

	_LIT(KSQL, "SELECT %S, %S, %S, %S, %S FROM %S WHERE %S=%d AND %S=%d");

	sqlStatement.Format(KSQL, &KServiceType, &KServiceIndex, &KSSID, &KPassword, &KPSK,
		&KEapolPSKTableName, &KServiceType, entry.indexType, &KServiceIndex, entry.index);
		
	User::LeaveIfError(view.Prepare(db, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	User::LeaveIfError(view.EvaluateAll());	

	TInt rows = view.CountL();
	
	if (rows == 0)
	{
		// No saved PSK
		User::Leave(KErrNotFound);
	}
	view.FirstL();
	view.GetL();

	entry.ssid.Copy(view.ColDes8(3));
	entry.password.Copy(view.ColDes8(4));
	entry.psk.Copy(view.ColDes8(5));

	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(sqlbuf);
	CleanupStack::PopAndDestroy(&db);
}

//--------------------------------------------------

void eapol_am_wlan_authentication_symbian_c::SavePSKL(TPSKEntry& entry)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::SavePSKL(): this = 0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::SavePSKL()");

	// Connect to CommDBif so that we can delete PSK entries that have no IAP associated anymore.
	CWLanSettings* wlan_settings = new(ELeave) CWLanSettings;
	CleanupStack::PushL(wlan_settings);
	
	SWLANSettings wlanSettings;

	if (wlan_settings->Connect() != KErrNone)
	{
		// Could not connect to CommDB			
		User::Leave(KErrCouldNotConnect);
	}

	// Open database
	RDbNamedDatabase db;

	TFileName aPrivateDatabasePathName;

	EapPluginTools::GetPrivatePathL(
		m_session,
		aPrivateDatabasePathName);

	aPrivateDatabasePathName.Append(KEapolDatabaseName);

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("aPrivateDatabasePathName",
		aPrivateDatabasePathName.Ptr(),
		aPrivateDatabasePathName.Size()));

	User::LeaveIfError(db.Open(m_session, aPrivateDatabasePathName));	
	
	CleanupClosePushL(db);

	HBufC* sqlbuf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = sqlbuf->Des();

	RDbView view;

	_LIT(KSQL, "SELECT %S, %S, %S, %S, %S FROM %S");
	
	sqlStatement.Format(KSQL, &KServiceType, &KServiceIndex, &KSSID, &KPassword, &KPSK,
		&KEapolPSKTableName);

	User::LeaveIfError(view.Prepare(db, TDbQuery(sqlStatement), TDbWindow::EUnlimited));	
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();		
	CleanupStack::PushL(colSet);
	
	// Delete old row and also rows that have no associated IAP settings.
	if (view.FirstL())
	{
		do {
			view.GetL();

			if ((wlan_settings->GetWlanSettingsForService(view.ColUint32(colSet->ColNo(KServiceIndex)), wlanSettings) != KErrNone)
				|| (view.ColUint32(colSet->ColNo(KServiceType)) == static_cast<TUint>(entry.indexType)
					&& view.ColUint32(colSet->ColNo(KServiceIndex)) == static_cast<TUint>(entry.index)))
			{	
				// Not found or current IAP
				view.DeleteL();	
			}
			
		} while (view.NextL() != EFalse);
	}

	wlan_settings->Disconnect();
	
	view.InsertL();
	
	view.SetColL(colSet->ColNo(KServiceType), (TUint)entry.indexType);
	view.SetColL(colSet->ColNo(KServiceIndex), (TUint)entry.index);
	view.SetColL(colSet->ColNo(KSSID), entry.ssid);
	view.SetColL(colSet->ColNo(KPassword), entry.password);
	view.SetColL(colSet->ColNo(KPSK), entry.psk);	
	
	view.PutL();
	
	CleanupStack::PopAndDestroy( colSet ); // Delete colSet.	

	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(sqlbuf);
	CleanupStack::PopAndDestroy(&db);
	CleanupStack::PopAndDestroy(wlan_settings);

}
														 
//--------------------------------------------------

//
void eapol_am_wlan_authentication_symbian_c::ReadWPASettingsL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::ReadWPASettingsL(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::ReadWPASettingsL()");

	eap_status_e status(eap_status_ok);

	if (m_selected_eapol_key_authentication_type == eapol_key_authentication_type_WPS)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT, (EAPL("WPS does not use CommDbIf anymore.\n")));
		return;
	}

	TIndexType index_type(ELan);
	TUint index(0UL);

	status = read_database_reference_values(
		&index_type,
		&index);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
	}

	if (index_type == ELan)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WLAN settings: m_WPA_override_enabled=%d\n"),
			m_WPA_override_enabled));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("m_wpa_preshared_key"),
			m_wpa_preshared_key.get_data(),
			m_wpa_preshared_key.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("m_SSID"),
			m_SSID.get_data(),
			m_SSID.get_data_length()));

		// Get WPA pre shared key & SSID
		if (m_is_client == true
			&& (m_selected_eapol_key_authentication_type == eapol_key_authentication_type_RSNA_PSK
				|| m_selected_eapol_key_authentication_type == eapol_key_authentication_type_WPA_PSK))
		{
			TPSKEntry pskEntry;
			pskEntry.indexType = index_type;
			pskEntry.index = index;
			pskEntry.ssid.Zero();
			pskEntry.password.Zero();
			pskEntry.psk.Zero();

            TInt error(KErrNone);

			// Retrieve saved PSK only when override is not in effect
			TRAP(error, RetrievePSKL(pskEntry));
			
			if (error != KErrNone
				|| m_SSID.compare(pskEntry.ssid.Ptr(), pskEntry.ssid.Size()) != 0
				|| m_wpa_preshared_key.compare(pskEntry.password.Ptr(), pskEntry.password.Size()) != 0)
			{
				// No previous PSK or parameters were changed.
				// We need to calculate PSK again
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("No previous PSK found...\n")));

				crypto_wpa_psk_password_hash_c password_hash(m_am_tools);

				if (m_wpa_preshared_key.get_data_length() == 2ul*EAPOL_WPA_PSK_LENGTH_BYTES)
				{
					// This is hex ascii 64-digit WWPA-PSK.
					// Convert it to 32 octets.
					u32_t target_length(EAPOL_WPA_PSK_LENGTH_BYTES);

					status = m_wpa_preshared_key_hash.set_buffer_length(EAPOL_WPA_PSK_LENGTH_BYTES);
					if (status != eap_status_ok)
					{
						send_error_notification(eap_status_key_error);
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
					}

					status = m_wpa_preshared_key_hash.set_data_length(EAPOL_WPA_PSK_LENGTH_BYTES);
					if (status != eap_status_ok)
					{
						send_error_notification(eap_status_key_error);
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
					}

					status = m_am_tools->convert_hex_ascii_to_bytes(
						m_wpa_preshared_key.get_data(m_wpa_preshared_key.get_data_length()),
						m_wpa_preshared_key.get_data_length(),
						m_wpa_preshared_key_hash.get_data(EAPOL_WPA_PSK_LENGTH_BYTES),
						&target_length);
					if (status != eap_status_ok
						|| target_length != EAPOL_WPA_PSK_LENGTH_BYTES)
					{
						send_error_notification(eap_status_key_error);
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
					}
				}
				else
				{
					status = password_hash.password_hash(
						&m_wpa_preshared_key,
						&m_SSID,	
						&m_wpa_preshared_key_hash,
						0,
						0);

					if (status != eap_status_ok)
					{
						send_error_notification(eap_status_key_error);
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
					}
				}

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("new WPA-PSK SSID"),
					m_SSID.get_data(),
					m_SSID.get_data_length()));
				
				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("new WPA-PSK preshared key"),
					m_wpa_preshared_key.get_data(),
					m_wpa_preshared_key.get_data_length()));
				
				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("new WPA-PSK hash"),
					m_wpa_preshared_key_hash.get_data(),
					m_wpa_preshared_key_hash.get_data_length()));
				
				// Save new PSK.
				pskEntry.ssid.Copy(
					m_SSID.get_data(),
					m_SSID.get_data_length()
					);
			
				pskEntry.password.Copy(
					m_wpa_preshared_key.get_data(),
					m_wpa_preshared_key.get_data_length()
					);
				
				pskEntry.psk.Copy(
					m_wpa_preshared_key_hash.get_data(),
					m_wpa_preshared_key_hash.get_data_length()
					);

				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Saving PSK.\n")));

				SavePSKL(pskEntry);
			}
			else
			{
				// Copy retrieved WPAPSK hash to member variable
				status = m_wpa_preshared_key_hash.set_copy_of_buffer(pskEntry.psk.Ptr(), pskEntry.psk.Size());
				if (status != eap_status_ok)
				{
					send_error_notification(eap_status_key_error);
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
				}

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("old WPA-PSK SSID"),
					m_SSID.get_data(),
					m_SSID.get_data_length()));
				
				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("old WPA-PSK preshared key"),
					m_wpa_preshared_key.get_data(),
					m_wpa_preshared_key.get_data_length()));
				
				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("old WPA-PSK hash"),
					m_wpa_preshared_key_hash.get_data(),
					m_wpa_preshared_key_hash.get_data_length()));
			}
		}
	} 
	else
	{
		// At the moment only LAN bearer is supported.
		User::Leave(KErrNotSupported);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::save_simple_config_session(
	const simple_config_state_e state,
	EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
	const eap_variable_data_c * const new_password,
	const simple_config_Device_Password_ID_e Device_Password_ID,
	const simple_config_payloads_c * const other_configuration)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eapol_am_wlan_authentication_simulator_c::save_simple_config_session()\n"),
		(m_is_client == true ? "client": "server")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::save_simple_config_session()");

	eap_status_e status(eap_status_ok);

	status = m_configuration_if->save_simple_config_session(
		state,
		credential_array,
		new_password,
		Device_Password_ID,
		other_configuration);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::set_eap_database_reference_values(
	const eap_variable_data_c * const reference)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eapol_am_wlan_authentication_symbian_c::set_eap_database_reference_values()\n"),
		(m_is_client == true ? "client": "server")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eapol_am_wlan_authentication_symbian_c::set_eap_database_reference_values()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::set_eap_database_reference_values(): reference"),
		 reference->get_data(),
		 reference->get_data_length()));

	eap_status_e status = m_database_reference.set_copy_of_buffer(reference);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eapol_am_wlan_authentication_c * eapol_am_wlan_authentication_c::new_eapol_am_wlan_authentication(
	abs_eap_am_tools_c * const tools,
	const bool is_client_when_true)
{
	EAP_TRACE_BEGIN(tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::new_eapol_am_wlan_authentication()\n")));
	EAP_TRACE_RETURN_STRING(tools, "returns: eapol_am_wlan_authentication_symbian_c::new_eapol_am_wlan_authentication()");

	eapol_am_wlan_authentication_c * const wauth = new eapol_am_wlan_authentication_symbian_c(
		tools,
		is_client_when_true);

	EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
	return wauth;
}


//--------------------------------------------------

//
eap_session_core_base_c * new_eap_core_client_message_if_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_session_core_c * const partner,
	const bool is_client_when_true,
	const u32_t MTU)
{
	EAP_TRACE_DEBUG(
		tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("new_eap_core_client_message_if_c()\n")));
	EAP_TRACE_RETURN_STRING(tools, "returns: new_eap_core_client_message_if_c()");

	eap_am_message_if_c *client_if = new_eap_am_client_message_if_c(
		tools,
		is_client_when_true,
		MTU);

	eap_automatic_variable_c<eap_am_message_if_c> automatic_server_if(
		tools,
		client_if);

	if (client_if == 0
		|| client_if->get_is_valid() == false)
	{
		// ERROR.
		if (client_if != 0)
		{
			EAP_TRACE_DEBUG(
				tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: calls: eap_session_core_base_c::new_eap_core_client_message_if_c(): client_if->shutdown(): %s.\n"),
				(is_client_when_true == true) ? "client": "server"));

			(void) client_if->shutdown();
		}

		return 0;
	}

	eap_core_client_message_if_c * new_session_core = new eap_core_client_message_if_c(tools, client_if, partner, is_client_when_true);

	eap_automatic_variable_c<eap_core_client_message_if_c> automatic_new_session_core(
		tools,
		new_session_core);

	if (new_session_core == 0
		|| new_session_core->get_is_valid() == false)
	{
		// ERROR.
		if (new_session_core != 0)
		{
			EAP_TRACE_DEBUG(
				tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: calls: eap_session_core_base_c::new_eap_core_client_message_if_c(): new_session_core->shutdown(): %s.\n"),
				(is_client_when_true == true) ? "client": "server"));

			new_session_core->shutdown();
		}

		(void) client_if->shutdown();

		return 0;
	}

	client_if->set_partner(new_session_core);

	automatic_server_if.do_not_free_variable();
	automatic_new_session_core.do_not_free_variable();

	return new_session_core;
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------
// End.
