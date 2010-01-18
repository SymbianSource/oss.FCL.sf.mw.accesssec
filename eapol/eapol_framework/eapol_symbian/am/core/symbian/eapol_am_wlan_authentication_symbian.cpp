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
* %version: 59.1.4 %
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
#include "abs_eapol_wlan_database_reference_if.h"
#include "abs_eap_state_notification.h"
#include "eap_state_notification.h"
#include "eap_automatic_variable.h"
#include "eap_base_type.h"

#include "EapolDbDefaults.h"
#include "EapolDbParameterNames.h"

const TUint KMaxSqlQueryLength = 2048;

#ifdef USE_EAP_EXPANDED_TYPES

const TUint KExpandedEAPSize = 8;

#else

const TUint KMaxEapCueLength = 3;

#endif //#ifdef USE_EAP_EXPANDED_TYPES

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_am_wlan_authentication_symbian_c::~eapol_am_wlan_authentication_symbian_c()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::~eapol_am_wlan_authentication_symbian_c(): this = 0x%08x\n"),
		this));
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eapol_am_wlan_authentication_symbian_c::eapol_am_wlan_authentication_symbian_c(
	abs_eap_am_tools_c * const tools,
	const bool is_client_when_true,
	const abs_eapol_wlan_database_reference_if_c * const wlan_database_reference)
: CActive(CActive::EPriorityStandard)
, m_am_partner(0)
#if defined(USE_EAP_SIMPLE_CONFIG)
, m_configuration_if(0)
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
, m_am_tools(tools)
, m_fileconfig(0)
, m_SSID(tools)
, m_wpa_preshared_key(tools)
, m_wpa_preshared_key_hash(tools)
, m_wlan_database_reference(wlan_database_reference)
#ifdef USE_EAP_EXPANDED_TYPES
, m_eap_type_array(tools)
#endif
, m_receive_network_id(tools)
, m_security_mode(Wpa)
, m_selected_eapol_key_authentication_type(eapol_key_authentication_type_none)
, m_WPA_override_enabled(false)
, m_is_client(is_client_when_true)
, m_is_valid(false)

{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eapol_am_wlan_authentication_symbian_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

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
		
	// 1. Open/create a database	
	RDbNamedDatabase db;

#ifdef SYMBIAN_SECURE_DBMS
	
	// Create the secure shared database (if necessary) with the specified secure policy.
	// Database will be created in the data caging path for DBMS (C:\private\100012a5).
	
	TInt err = db.Create(m_session, KDatabaseName, KSecureUIDFormat);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TryOpenDatabaseL() - Created Secure DB for eapol.dat. err=%d\n"), err ));	
		
	if(err == KErrNone)
	{	
		db.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	User::LeaveIfError(db.Open(m_session, KDatabaseName, KSecureUIDFormat));	
		
#else
	// For non-secured database. The database will be created in the old location (c:\system\data).
	
	// Create the database (if necessary)		
	TInt err = db.Create(m_fs, KDatabaseName);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TryOpenDatabaseL() - Created Non-Secure DB for eapol.dat. err=%d\n"), err ));	
	
	if(err == KErrNone)
	{
		db.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
		
	User::LeaveIfError(db.Open(m_session, KDatabaseName));
	    
#endif // #ifdef SYMBIAN_SECURE_DBMS		

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
	err = db.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}
	
	CleanupStack::PopAndDestroy(); // buf
	
	// If compacting is not done the database will start growing
	db.Compact();
	
	CleanupStack::PopAndDestroy(); // Close database
}

//--------------------------------------------------

void eapol_am_wlan_authentication_symbian_c::InitDatabaseL()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_wlan_authentication_symbian_c::OpenDatabaseL()\n")));

	// Create the database (if necessary)
	TRAPD(err, TryInitDatabaseL());
	if (err != KErrNone)
	{
		// Because of error remove the database file.
		err = m_fs.Delete(KDatabaseName);
		if(err != KErrNone)
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

	TInt error(KErrNone);

	// Open the database session
	error = m_session.Connect();
	if (error != KErrNone)
	{
		eap_status_e status(m_am_tools->convert_am_error_to_eapol_error(error));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("RDbs::Connect() failed %d.\n"),
			status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Database session initialized...\n")));

	// Connect to FS
	error = m_fs.Connect();
	if (error != KErrNone)
	{
		eap_status_e status(m_am_tools->convert_am_error_to_eapol_error(error));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("RFs::Connect() failed %d.\n"),
			status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Fileserver session initialized...\n")));

	// Initialize database
	TRAPD(err, InitDatabaseL());
	if (err != KErrNone)
	{
		eap_status_e status(m_am_tools->convert_am_error_to_eapol_error(error));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("InitDatabaseL failed %d.\n"),
			status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Database initialized...\n")));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_FILECONFIG)
	{
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

			eap_status_e status(eap_status_process_general_error);

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
	}
#endif //#if defined(USE_EAP_FILECONFIG)

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_FILE_TRACE)
	{
		eap_variable_data_c trace_output_file(m_am_tools);

		eap_status_e status = read_configure(
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
		eap_variable_data_c EAP_TRACE_enable_timer_queue_traces(m_am_tools);

		eap_status_e status = read_configure(
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
					| eap_am_tools_c::eap_trace_mask_timer_queue
					);
			}
		}
	}

	{
		eap_variable_data_c EAP_TRACE_enable_function_traces(m_am_tools);

		eap_status_e status = read_configure(
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

eap_status_e eapol_am_wlan_authentication_symbian_c::reset_eap_plugins()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::reset_eap_plugins(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

	// Unload all loaded plugins
	for(int ind = 0; ind < m_plugin_if_array.Count(); ind++)
	{
		delete m_plugin_if_array[ind];
	}

	m_plugin_if_array.Close();

#ifdef USE_EAP_EXPANDED_TYPES

	m_enabled_expanded_eap_array.ResetAndDestroy();

	m_disabled_expanded_eap_array.ResetAndDestroy();
	
	m_eap_type_array.reset();
	
#else

	// Delete the IAP EAP type info array
	m_iap_eap_array.ResetAndDestroy();
	
	m_eap_type_array.Close();	
	
#endif //#ifdef USE_EAP_EXPANDED_TYPES

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

	m_session.Close();
	m_fs.Close();

	delete m_fileconfig;
	m_fileconfig = 0;

	(void) reset_eap_plugins();

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

	m_am_partner = am_partner;

#if defined(USE_EAP_SIMPLE_CONFIG)
	m_configuration_if = configuration_if;
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::reset_eap_configuration()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::reset_eap_configuration(): %s, this = 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this));

	TRAPD(error, ReadEAPSettingsL());
	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP settings reading from CommDb failed or cancelled(err %d).\n"), error));

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

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
void eapol_am_wlan_authentication_symbian_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

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

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

#ifdef USE_EAP_EXPANDED_TYPES

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::get_selected_eap_types(
	eap_array_c<eap_type_selection_c> * const selected_eap_types)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::get_selected_eap_types(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

	eap_status_e status = selected_eap_types->reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_header_string_c eap_string;
	EAP_UNREFERENCED_PARAMETER(eap_string);

	// We need to return only the EAP types available as enabled types.
	// It means only the ones available in m_enabled_expanded_eap_array.
	
	for (TInt i = 0; i < m_enabled_expanded_eap_array.Count(); i++)
	{	
		TBuf8<KExpandedEAPSize> tmpExpEAP(m_enabled_expanded_eap_array[i]->EapExpandedType);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eapol_am_wlan_authentication_symbian_c::get_selected_eap_types:Enabled expanded EAP type at index=%d\n"),
			 i));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Enabled expanded EAP type"),
			tmpExpEAP.Ptr(),
			tmpExpEAP.Size()));

		// This is for one expanded EAP type (for the above one).
		eap_expanded_type_c expandedEAPType;
				
		// Read the expanded EAP type details from an item in m_enabled_expanded_eap_array.
		status = eap_expanded_type_c::read_type(m_am_tools,
												0,
												tmpExpEAP.Ptr(),
												tmpExpEAP.Size(),
												&expandedEAPType);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Add EAP-type to list.
		eap_type_selection_c * selection = new eap_type_selection_c(
			m_am_tools,
			expandedEAPType,
			true);
		if (selection != 0)
		{
			status = selected_eap_types->add_object(selection, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("get_selected_eap_types(): added EAP-type=0x%08x=%s\n"),
				expandedEAPType.get_vendor_type(),
				eap_string.get_eap_type_string(expandedEAPType)));			
		}
		else
		{
			// On error we ignore this EAP-type.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("Some problem with EAP type at index %d in m_enabled_expanded_eap_array\n"),
				 i));
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

#else // for non-expanded (normal EAP types)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::get_selected_eap_types(
	eap_array_c<eap_type_selection_c> * const selected_eap_types)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::get_selected_eap_types(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

	eap_status_e status = selected_eap_types->reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_header_string_c eap_string;
	EAP_UNREFERENCED_PARAMETER(eap_string);

	TEap *eapType = 0; 

	for (TInt i = 0; i < m_iap_eap_array.Count(); i++)
	{
		// Check if type is enabled
		eapType = m_iap_eap_array[i];
		if (eapType->Enabled == 1)
		{	
			TLex8 tmp(eapType->UID);
			TInt val(0);
			tmp.Val(val);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("get_selected_eap_types(): adds EAP-type=0x%08x=%s\n"),
				static_cast<eap_type_ietf_values_e>(val),
				eap_string.get_eap_type_string(
					static_cast<eap_type_value_e>(
						static_cast<eap_type_ietf_values_e>(val)))));

			// Add EAP-type to list.
			eap_type_selection_c * selection = new eap_type_selection_c(
				m_am_tools,
				static_cast<eap_type_value_e>(static_cast<eap_type_ietf_values_e>(val)),
				true);
			if (selection != 0)
			{
				status = selected_eap_types->add_object(selection, true);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				// On error we ignore this EAP-type.
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif //#ifdef USE_EAP_EXPANDED_TYPES

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

	eap_status_e status = wpa_preshared_key_hash->set_copy_of_buffer(&m_wpa_preshared_key_hash);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::authentication_finished(
	const bool when_true_successfull,
	const eap_type_value_e eap_type,
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

	if (when_true_successfull == true)
	{
		if (authentication_type != eapol_key_authentication_type_RSNA_PSK
			&& authentication_type != eapol_key_authentication_type_WPA_PSK)
		{

#ifdef USE_EAP_EXPANDED_TYPES

			// This moves the successful type to be the top priority type in IAP settings.
			TRAPD(err, SetToTopPriorityL(eap_type));
			if (err != KErrNone)
			{
				// Just log the error. 
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT, 
					(EAPL("state_notification: SetToTopPriorityL() Expanded EAP type - leave with error=%d!\n"),
					err));
			}

#else // For normal EAP types
					
			TEap eap;
			eap.Enabled = ETrue;
			eap.UID.Num(static_cast<TInt>(convert_eap_type_to_u32_t(eap_type)));
			
			// This moves the successful type to be the top priority type in IAP settings.
			TRAPD(err, SetToTopPriorityL(&eap));
			if (err != KErrNone)
			{
				// Just log the error. 
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT, 
					(EAPL("state_notification: SetToTopPriorityL leaved!\n")));
			}

#endif //#ifdef USE_EAP_EXPANDED_TYPES

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

	eap_variable_data_c database_reference(m_am_tools);

	eap_status_e status = m_wlan_database_reference->get_wlan_database_reference_values(&database_reference);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const eapol_wlan_database_reference_values_s * const database_reference_values
		= reinterpret_cast<eapol_wlan_database_reference_values_s *>(
		database_reference.get_data(sizeof(eapol_wlan_database_reference_values_s)));
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

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::load_module(
	const eap_type_value_e type,
	const eap_type_value_e tunneling_type,
	abs_eap_base_type_c * const partner,
	eap_base_type_c ** const eap_type_if,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id ///< source includes remote address, destination includes local address.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_wlan_authentication_symbian_c::load_module(type %d=%s, tunneling_type %d=%s)\n"),
		convert_eap_type_to_u32_t(type),
		eap_header_string_c::get_eap_type_string(type),
		convert_eap_type_to_u32_t(tunneling_type),
		eap_header_string_c::get_eap_type_string(tunneling_type)));

	eap_status_e status(eap_status_process_general_error);
	
#ifdef USE_EAP_EXPANDED_TYPES

	CEapType* eapType = 0;
	TInt error(KErrNone);

	// Check if this EAP type has already been loaded
	TInt eapArrayIndex = find<eap_type_value_e>(
		&m_eap_type_array,
		&type,
		m_am_tools);

	if (eapArrayIndex >= 0)
	{
		// We found the entry in the array.
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eapol_am_wlan_authentication_symbian_c::load_module(type %d=%s, tunneling_type %d=%s) already loaded.\n"),
			convert_eap_type_to_u32_t(type),
			eap_header_string_c::get_eap_type_string(type),
			convert_eap_type_to_u32_t(tunneling_type),
			eap_header_string_c::get_eap_type_string(tunneling_type)));

		// Yep. It was loaded already.
		eapType = m_plugin_if_array[eapArrayIndex];		
	}
	else 
	{
		TIndexType index_type(ELan);
		TUint index(0UL);

		status = read_database_reference_values(
			&index_type,
			&index);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eapol_am_wlan_authentication_symbian_c::load_module(type %d=%s, tunneling_type %d=%s) load new, index type=%d, index=%d.\n"),
			convert_eap_type_to_u32_t(type),
			eap_header_string_c::get_eap_type_string(type),
			convert_eap_type_to_u32_t(tunneling_type),
			eap_header_string_c::get_eap_type_string(tunneling_type),
			index_type,
			index));

		TBuf8<KExpandedEAPSize> ExpandedCue;
		
		// Some indirect way of forming the 8 byte string of an EAP type for the cue is needed here.		
		TUint8 tmpExpCue[KExpandedEAPSize];

		// This is to make the tmpExpCue in 8 byte string with correct vendor type and vendor id details.
		status = eap_expanded_type_c::write_type(m_am_tools,
												0, // index should be zero here.
												tmpExpCue,
												KExpandedEAPSize,
												true,
												type);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("load_module: eap_expanded_type_c::write_type failed \n")));
		
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		// Now copy the 8 byte string to the real expanded cue.
		ExpandedCue.Copy(tmpExpCue, KExpandedEAPSize);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL:eapol_am_wlan_authentication_symbian_c::load_module: Expanded CUE:"),
			ExpandedCue.Ptr(),
			ExpandedCue.Size()));


		// We must have a trap here since the EAPOL core knows nothing about Symbian.
		TRAP(error, (eapType = CEapType::NewL(
			ExpandedCue,
			index_type,
			index)));	
		if (error != KErrNone
			|| eapType == 0)
		{
			// Interface not found or implementation creation function failed
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ECom could not find/initiate implementation.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}

#else // For normal EAP types
	
	TBuf8<KMaxEapCueLength> cue;
	cue.Num(static_cast<TInt>(convert_eap_type_to_u32_t(type)));
	CEapType* eapType = 0;
	TInt error(KErrNone);

	// Check if this EAP type has already been loaded
	TInt eapArrayIndex = m_eap_type_array.Find(type);
	if (eapArrayIndex != KErrNotFound)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eapol_am_wlan_authentication_symbian_c::load_module(type %d=%s, tunneling_type %d=%s) already loaded.\n"),
			convert_eap_type_to_u32_t(type),
			eap_header_string_c::get_eap_type_string(type),
			convert_eap_type_to_u32_t(tunneling_type),
			eap_header_string_c::get_eap_type_string(tunneling_type)));

		// Yep. It was loaded already.
		eapType = m_plugin_if_array[eapArrayIndex];		
	}
	else 
	{
		TIndexType index_type(ELan);
		TUint index(0UL);

		status = read_database_reference_values(
			&index_type,
			&index);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eapol_am_wlan_authentication_symbian_c::load_module(type %d=%s, tunneling_type %d=%s) load new, index type=%d, index=%d.\n"),
			convert_eap_type_to_u32_t(type),
			eap_header_string_c::get_eap_type_string(type),
			convert_eap_type_to_u32_t(tunneling_type),
			eap_header_string_c::get_eap_type_string(tunneling_type),
			index_type,
			index));

		// We must have a trap here since the EAPOL core knows nothing about Symbian.
		TRAP(error, (eapType = CEapType::NewL(
			cue,
			index_type,
			index)));	
		if (error != KErrNone
			|| eapType == 0)
		{
			// Interface not found or implementation creation function failed
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ECom could not find/initiate implementation.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	// Set the tunneling type
	eapType->SetTunnelingType(convert_eap_type_to_u32_t(tunneling_type));

	// Create the EAP protocol interface implementation.
	
#ifdef USE_EAP_SIMPLE_CONFIG

	TRAP(error, (*eap_type_if = eapType->GetStackInterfaceL(m_am_tools, 
		partner, 
		is_client_when_true, 
		receive_network_id,
		this)));

#else

	TRAP(error, (*eap_type_if = eapType->GetStackInterfaceL(m_am_tools, 
		partner, 
		is_client_when_true, 
		receive_network_id)));

#endif // #ifdef USE_EAP_SIMPLE_CONFIG
	
		
	if (error != KErrNone 
		|| *eap_type_if == 0 
		|| (*eap_type_if)->get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Could not create EAP type interface instance. Error: %d\n"), error));

		status = eap_status_allocation_error;
		// Unload DLL (two ways, depending whether this type was already loaded...)
		if  (eapArrayIndex == KErrNotFound)
		{
			// No need to call shutdown here because GetStackInterfaceL has done it.
			delete eapType;
		}
		else
		{
			unload_module(type);
		}
		// Note: even in error cases eap_core_c deletes eap_type_if
	}
	else
	{
		status = eap_status_ok;
		if (eapArrayIndex  == KErrNotFound)
		{
			// Add plugin information to the member arrays. There is no need to store eap_type pointer because
			// the stack takes care of its deletion.
			if (m_plugin_if_array.Append(eapType) != KErrNone)
			{
				delete eapType;
				status = eap_status_allocation_error;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);				
			}
			
#ifdef USE_EAP_EXPANDED_TYPES

			eap_type_value_e * tmpEAPType = new eap_type_value_e();
			if(tmpEAPType == NULL)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("eapol_am_wlan_authentication_symbian_c::load_module() eap_type_value_e creation failed\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);				
			}
			
			*tmpEAPType = type;
			
			status = m_eap_type_array.add_object(tmpEAPType, true);
			
			if (status != eap_status_ok)			

#else // For normal EAP type.			
			
			if (m_eap_type_array.Append(type) != KErrNone)

#endif // #ifdef USE_EAP_EXPANDED_TYPES			
			{
				// Remove the eap type added just previously
				m_plugin_if_array.Remove(m_plugin_if_array.Count() - 1);
				delete eapType;
				status = eap_status_allocation_error;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);				
			}
		} 
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::unload_module(
	const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::unload_module(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

	eap_status_e status(eap_status_type_does_not_exists_error);

#ifdef USE_EAP_EXPANDED_TYPES

	// Check if this EAP type has already been loaded
	TInt index = find<eap_type_value_e>(
		&m_eap_type_array,
		&type,
		m_am_tools);
		
	if (index >= 0)
	{
		// EAP was loaded before.
		
		delete m_plugin_if_array[index];
		m_plugin_if_array.Remove(index);
		
		status = m_eap_type_array.remove_object(index);
	}

#else // For normal EAP types.

	TInt index = m_eap_type_array.Find(type);
	if (index != KErrNotFound)
	{
		delete m_plugin_if_array[index];
		m_plugin_if_array.Remove(index);
		m_eap_type_array.Remove(index);
		status = eap_status_ok;			
	}

#endif // #ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
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
		return status;
	}
	
	status = type_field.set_buffer(
		cf_str_EAP_default_type_hex_data.get_field()->get_field(),
		cf_str_EAP_default_type_hex_data.get_field()->get_field_length(),
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	eap_type_value_e aSelectedEapType;
	
#ifdef USE_EAP_EXPANDED_TYPES

	if (!wanted_field.compare(&type_field))
	{
		TInt ind; 

		// First check do we have read configuration from databases.
		if (m_enabled_expanded_eap_array.Count() == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP settings not read from CommsDat\n")));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		// Now we need to return here the next EAP type we should try		
		for (ind = m_am_partner->get_current_eap_index(); ind < m_enabled_expanded_eap_array.Count(); ind++)
		{
			// Find the highest priority EAP with index "ind".
			
			TBuf8<KExpandedEAPSize> tmpExpEAP(m_enabled_expanded_eap_array[ind]->EapExpandedType);
			
			status = data->set_copy_of_buffer(tmpExpEAP.Ptr(), tmpExpEAP.Size());			
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);			
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL:eapol_am_wlan_authentication_symbian_c::read_configure: Trying EAP type:"),
				tmpExpEAP.Ptr(),
				tmpExpEAP.Size()));
			status = eap_expanded_type_c::read_type(m_am_tools,
					0,
					tmpExpEAP.Ptr(),
					tmpExpEAP.Size(),
					&aSelectedEapType);
			if (status == eap_status_ok)
			{
				break;
			}
		}

		// Set the index of new EAP type we are trying now.
		m_am_partner->set_current_eap_index(ind);
		
		if (ind >= m_enabled_expanded_eap_array.Count())
		{
			// Not found any other EAP type as enabled.
			// Send WLM notification because there is no way that the authentication
			// can be successful if we don't have any EAP types to use...
			if (m_is_client)
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: read_configure: No configured EAP types or all tried unsuccessfully.\n")));
			}

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
		}
	
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);		
	}

#else // For normal non-expanded EAP

	if (!wanted_field.compare(&type_field))
	{
		TInt ind; 

		// First check do we have read configuration from databases.
		if (m_iap_eap_array.Count() == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP settings not read from CommDb\n")));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		// We need to return here the next EAP type we should try		
		for (ind = m_am_partner->get_current_eap_index(); ind < m_iap_eap_array.Count(); ind++)
		{
			// Find the first enabled EAP type (highest priority)
			TEap *eapType = m_iap_eap_array[ind];			
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

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAPOL: Trying EAP type: %d.\n"), val));
				aSelectedEapType = val;
				break;
			}
		}

		m_am_partner->set_current_eap_index(ind);
		if (ind >= m_iap_eap_array.Count())
		{
			// Not found
			// Send WLM notification because there is no way that the authentication
			// can be successful if we don't have any EAP types to use...
			if (m_is_client)
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: No configured EAP types or all tried unsuccessfully.\n")));
			}

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
		}
	
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);		
	}

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	// It was something else than EAP type. Read it from eapol DB.
	_LIT( KEapolTableName, "eapol" );
	TRAPD( err, read_configureL(
		KDatabaseName,
		KEapolTableName,
		field->get_field(),
		field->get_field_length(),
		data) );
	// Try to read it for eap fast DB	
	HBufC8* fieldBuf = HBufC8::NewLC( field->get_field_length() );
	TPtr8 fieldPtr = fieldBuf->Des();
	fieldPtr.Copy( reinterpret_cast<const TUint8 *> ( field->get_field() ));

	_LIT8(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal, "EAP_TLS_PEAP_use_identity_privacy");
	
	if ( err != KErrNone &&
		 fieldPtr.Compare( cf_str_EAP_TLS_PEAP_use_identity_privacy_literal() ) == 0 ) 
		{
		if (aSelectedEapType == eap_type_tls)
			{
			_LIT(KGeneralSettingsDBTableName, "KTlsDatabaseTableName");
			TRAP( err, read_configureL(
					KDatabaseName,
					KGeneralSettingsDBTableName,
					field->get_field(),
					field->get_field_length(),
					data) );		

			}
		if (aSelectedEapType == eap_type_peap)
			{
			_LIT(KGeneralSettingsDBTableName, "KPeapDatabaseTableName"); 
			TRAP( err, read_configureL(
					KDatabaseName,
					KGeneralSettingsDBTableName,
					field->get_field(),
					field->get_field_length(),
					data) );		
			}
		if (aSelectedEapType == eap_type_ttls)
			{
			_LIT(KGeneralSettingsDBTableName, "KTtlsDatabaseTableName"); 
			TRAP( err, read_configureL(
					KDatabaseName,
					KGeneralSettingsDBTableName,
					field->get_field(),
					field->get_field_length(),
					data) );		
			}
#if defined (USE_FAST_EAP_TYPE)
		if ( aSelectedEapType == eap_type_fast)
			{
			_LIT(KFastGeneralSettingsDBTableName, "eapfast_general_settings"); 
			TRAP( err, read_configureL(
			KFastDatabaseName,
			KFastGeneralSettingsDBTableName,
			field->get_field(),
			field->get_field_length(),
			data) );		
			}
#endif
		}
	CleanupStack::PopAndDestroy( fieldBuf );

	if (err != KErrNone) 
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);

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
	
	// Open database
	RDbNamedDatabase db;

#ifdef SYMBIAN_SECURE_DBMS
	User::LeaveIfError(db.Open(m_session, aDbName, KSecureUIDFormat));	
#else			
	User::LeaveIfError(db.Open(m_session, aDbName));
#endif // #ifdef SYMBIAN_SECURE_DBMS		
	
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
						User::Leave(KErrNoMemory);
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
					User::Leave(KErrNoMemory);
				}
			}
			break;
		default:
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("read_configureL: Unexpected column type.\n")));
			User::Panic(_L("EAPOL"), 1);			
		}
	} 
	else 
	{
		// Could not find parameter
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("read_configureL: Could not find configuration parameter.\n")));
		User::Leave(KErrNotFound);
	}		
	
	// Close database
	CleanupStack::PopAndDestroy(5); // view, 3 buffers and database


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

	const eap_status_e status = m_am_tools->am_cancel_all_timers();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::check_is_valid_eap_type(const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_header_string_c eap_string;
	EAP_UNREFERENCED_PARAMETER(eap_string);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_wlan_authentication_symbian_c::check_is_valid_eap_type():  %s, this = 0x%08x => 0x%08x, EAP-type=0x%08x=%s\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this),
		convert_eap_type_to_u32_t(eap_type),
		eap_string.get_eap_type_string(eap_type)));

#ifdef USE_EAP_EXPANDED_TYPES

	for (int i = 0; i < m_enabled_expanded_eap_array.Count(); i++)
	{
		TBuf8<KExpandedEAPSize> tmpExpEAP(m_enabled_expanded_eap_array[i]->EapExpandedType);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eapol_am_wlan_authentication_symbian_c::check_is_valid_eap_type:Enabled expanded EAP type at index=%d\n"),
			 i));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Enabled expanded EAP type:"),
			tmpExpEAP.Ptr(),
			tmpExpEAP.Size()));

		// This is for one expanded EAP type (for the above one).
		eap_expanded_type_c expandedEAPType;
				
		// Read the expanded EAP type details for this item in m_enabled_expanded_eap_array.
		eap_status_e status = eap_expanded_type_c::read_type(m_am_tools,
												0,
												tmpExpEAP.Ptr(),
												tmpExpEAP.Size(),
												&expandedEAPType);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (eap_type == expandedEAPType)
		{
			// This is Allowed and Valid.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
	}
		 
#else // For normal unexpanded EAP type

	TEap *eapType = 0; 
	
	for (int i = 0; i < m_iap_eap_array.Count(); i++)
	{
		// Try next EAP type
		eapType = m_iap_eap_array[i];
		if (eapType->Enabled == 1)
		{	
			// Convert the string to integer
			TLex8 tmp(eapType->UID);
			TInt val(0);
			tmp.Val(val);

			if (eap_type == static_cast<eap_type_ietf_values_e>(val))
			{
				// Allowed
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
		}
	}
	
#endif // #ifdef USE_EAP_EXPANDED_TYPES
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ERROR: %s: check_is_valid_eap_type(): not supported EAP-type=0x%08x=%s\n"),
		 (m_is_client == true ? "client": "server"),
		 convert_eap_type_to_u32_t(eap_type),
		 eap_string.get_eap_type_string(eap_type)));

	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_type);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eapol_am_wlan_authentication_symbian_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::get_eap_type_list(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));


	eap_status_e status(eap_status_illegal_eap_type);

	status = eap_type_list->reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_header_string_c eap_string;
	EAP_UNREFERENCED_PARAMETER(eap_string);

#ifdef USE_EAP_EXPANDED_TYPES

	// This function is same as get_selected_eap_types in behavior.

	// We need to return only the EAP types available as enabled types.
	// It means only the ones available in m_enabled_expanded_eap_array.
	
	for (TInt i = 0; i < m_enabled_expanded_eap_array.Count(); i++)
	{	
		TBuf8<KExpandedEAPSize> tmpExpEAP(m_enabled_expanded_eap_array[i]->EapExpandedType);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eapol_am_wlan_authentication_symbian_c::get_eap_type_list:Enabled expanded EAP type at index=%d\n"),
			 i));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Enabled expanded EAP type:"),
			tmpExpEAP.Ptr(),
			tmpExpEAP.Size()));

		// This is for one expanded EAP type (for the above one).
		eap_expanded_type_c * expandedEAPType = new eap_type_value_e();
				
		// Read the expanded EAP type details from an item in m_enabled_expanded_eap_array.
		status = eap_expanded_type_c::read_type(m_am_tools,
												0,
												tmpExpEAP.Ptr(),
												tmpExpEAP.Size(),
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
			
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("get_eap_type_list():added EAP-type=0x%08x=%s\n"),
			expandedEAPType->get_vendor_type(),
			eap_string.get_eap_type_string(*expandedEAPType)));			
	}

#else // for normal EAP types.

	TEap *eapType = 0; 

	for (TInt i = 0; i < m_iap_eap_array.Count(); i++)
	{
		// Check if type is enabled
		eapType = m_iap_eap_array[i];
		if (eapType->Enabled == 1)
		{	
			TLex8 tmp(eapType->UID);
			TInt val(0);
			tmp.Val(val);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("get_eap_type_list(): adds EAP-type=0x%08x=%s\n"),
				static_cast<eap_type_ietf_values_e>(val),
				eap_string.get_eap_type_string(
					static_cast<eap_type_value_e>(
						static_cast<eap_type_ietf_values_e>(val)))));

			eap_type_value_e * const eap_type = new eap_type_value_e(
				static_cast<eap_type_ietf_values_e>(val));
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
	}

#endif // #ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
void eapol_am_wlan_authentication_symbian_c::RunL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_wlan_authentication_symbian_c::RunL(): iStatus.Int() = %d\n"),
		iStatus.Int()));

	if (iStatus.Int() != KErrNone)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	// Authentication cancelled.
	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("Authentication cancelled.\n")));

	eap_status_e status = m_am_partner->disassociation(
		&m_receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("set_timer(EAPOL_AM_CORE_TIMER_DELETE_STACK_ID) failed in RunL().\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}
	
	// Reset index of current EAP-type.
	m_am_partner->set_current_eap_index(0ul);

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("Indication sent to WLM: EFailedCompletely.\n")));

	m_am_partner->eapol_indication(
		&m_receive_network_id,
		eapol_wlan_authentication_state_failed_completely);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

//
void eapol_am_wlan_authentication_symbian_c::DoCancel()
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_wlan_authentication_symbian_c::DoCancel()\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

void eapol_am_wlan_authentication_symbian_c::RetrievePSKL(TPSKEntry& entry)
{

	// Open database
	RDbNamedDatabase db;

#ifdef SYMBIAN_SECURE_DBMS
	User::LeaveIfError(db.Open(m_session, KDatabaseName, KSecureUIDFormat));	
#else			
	User::LeaveIfError(db.Open(m_session, KDatabaseName));
#endif // #ifdef SYMBIAN_SECURE_DBMS		
	
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

	CleanupStack::PopAndDestroy(3); // view, buf, database
}

//--------------------------------------------------

void eapol_am_wlan_authentication_symbian_c::SavePSKL(TPSKEntry& entry)
{
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

#ifdef SYMBIAN_SECURE_DBMS
	User::LeaveIfError(db.Open(m_session, KDatabaseName, KSecureUIDFormat));	
#else			
	User::LeaveIfError(db.Open(m_session, KDatabaseName));
#endif // #ifdef SYMBIAN_SECURE_DBMS		
	
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

	CleanupStack::PopAndDestroy(4); // CWLanSettings, database, buffer, view

}
														 
//--------------------------------------------------

//
void eapol_am_wlan_authentication_symbian_c::ReadEAPSettingsL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_am_wlan_authentication_symbian_c::ReadEAPSettingsL(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

	eap_status_e status(eap_status_ok);

	status = reset_eap_plugins();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
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
			(EAPL("Beginning to read IAP settings - Type: %d, Index: %d.\n"), index_type, index));

		CWLanSettings* wlan_settings = new(ELeave) CWLanSettings;
		CleanupStack::PushL(wlan_settings);
		SWLANSettings wlanSettings;
		if (wlan_settings->Connect() != KErrNone)
		{
			// Could not connect to CommDB			
			User::Leave(KErrCouldNotConnect);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT, (EAPL("Connected to CommDbIf.\n")));

		if (wlan_settings->GetWlanSettingsForService(index, wlanSettings) != KErrNone)
		{
			wlan_settings->Disconnect();
			User::Leave(KErrUnknown);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Got WLAN settings: wlanSettings.EnableWpaPsk=%d, m_WPA_override_enabled=%d\n"),
			wlanSettings.EnableWpaPsk,
			m_WPA_override_enabled));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WPA-PSK"),
			wlanSettings.WPAPreSharedKey.Ptr(),
			wlanSettings.WPAPreSharedKey.Size()));

#ifdef USE_EAP_EXPANDED_TYPES

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Beginning to read EAP Data using new Comm_DB_if for expanded eap type\n")));

		wlan_settings->GetEapDataL(m_enabled_expanded_eap_array, m_disabled_expanded_eap_array);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Enabled EAP count=%d, Disabled EAP count=%d\n"),
			m_enabled_expanded_eap_array.Count(), m_disabled_expanded_eap_array.Count()));

			
	
#else
		// Without expanded EAP type. Normal EAP type stuff.
		wlan_settings->GetEapDataL(m_iap_eap_array);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Got EAP data:\n")));

#ifdef USE_EAP_EXPANDED_TYPES

		// Reading enabled.
		for (TInt i = 0; i < m_enabled_expanded_eap_array.Count(); i++)
		{	
			TBuf8<KExpandedEAPSize> tmpExpEAP(m_enabled_expanded_eap_array[i]->EapExpandedType);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eapol_am_wlan_authentication_symbian_c::ReadEAPSettingsL:Enabled expanded EAP type at index=%d\n"),
				 i));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Enabled expanded EAP type:"),
				tmpExpEAP.Ptr(),
				tmpExpEAP.Size()));
		}

		// Now reading disabled.
		for (TInt i = 0; i < m_disabled_expanded_eap_array.Count(); i++)
		{	
			TBuf8<KExpandedEAPSize> tmpExpEAP(m_disabled_expanded_eap_array[i]->EapExpandedType);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eapol_am_wlan_authentication_symbian_c::ReadEAPSettingsL:Disabled expanded EAP type at index=%d\n"),
				 i));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Disabled expanded EAP type:"),
				tmpExpEAP.Ptr(),
				tmpExpEAP.Size()));
		}

#else // Normal EAP type.

		for (TInt i = 0; i < m_iap_eap_array.Count(); i++)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP type %d\n"),
				i));

			TLex8 tmp(m_iap_eap_array[i]->UID);
			TInt val(0);
			tmp.Val(val);
		
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("  UID: %d\n"), val));
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("  Enabled: %d\n"),
				m_iap_eap_array[i]->Enabled));
		}

#endif // #ifdef USE_EAP_EXPANDED_TYPES

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("End EAP data:\n")));


#ifndef USE_EAP_EXPANDED_TYPES

// There can not be a situation where all EAPs are disabled.

		if (m_iap_eap_array.Count() == 0)
		{

#if defined(USE_EAP_ALLOW_ALL_EAP_TYPES_WHEN_NONE_IS_ACTIVATED_IN_CONFIGURATION)

			// The EAP field was empty. Allow all types.

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Empty EAP field -> enable all types.\n")));

			RImplInfoPtrArray eapArray;
			
			REComSession::ListImplementationsL(KEapTypeInterfaceUid, eapArray);
		
			TEap *eap;
			for (TInt i = 0; i < eapArray.Count(); i++)
			{
				eap = new(ELeave) TEap;
				eap->UID.Copy(eapArray[i]->DataType());
				eap->Enabled = ETrue;
				m_iap_eap_array.Append(eap);
			}

			eapArray.ResetAndDestroy();

#else

			// The EAP field was empty. Allow EAP-SIM only.

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Empty EAP field -> enable EAP-SIM only.\n")));

			{
				TBuf8<3> eap_sim_uid = _L8("018");

				TEap *eap = new(ELeave) TEap;
				eap->UID.Copy(eap_sim_uid);
				eap->Enabled = ETrue;
				m_iap_eap_array.Append(eap);
			}

#endif //#if defined(USE_EAP_ALLOW_ALL_EAP_TYPES_WHEN_NONE_IS_ACTIVATED_IN_CONFIGURATION)

		}

#endif // #ifndef USE_EAP_EXPANDED_TYPES

		// Get security mode
		if (m_WPA_override_enabled == false)
		{
			m_security_mode = static_cast<EWlanSecurityMode>(wlanSettings.SecurityMode);
		}
		else
		{
			// WPA override is enabled
			m_security_mode = Wpa;
		}

		// Get WPA pre shared key & SSID
		if (m_is_client == true
			&& (wlanSettings.EnableWpaPsk
				|| m_WPA_override_enabled == true)
			&& (m_selected_eapol_key_authentication_type == eapol_key_authentication_type_RSNA_PSK
				|| m_selected_eapol_key_authentication_type == eapol_key_authentication_type_WPA_PSK))
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Uses WPAPSK: wlanSettings.EnableWpaPsk=%d\n"),
				wlanSettings.EnableWpaPsk));

			// When not using easy WLAN there is no WPA PSK override.
			if (m_WPA_override_enabled == false)
			{
				status = m_wpa_preshared_key.set_copy_of_buffer(
					wlanSettings.WPAPreSharedKey.Ptr(),
					wlanSettings.WPAPreSharedKey.Size());
				if (status != eap_status_ok)
				{
					send_error_notification(eap_status_key_error);
					wlan_settings->Disconnect();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
				}

				// Here we copy the SSID read from IAP.
				TBuf8<K_Max_SSID_Length> tmp;
				tmp.Copy(wlanSettings.SSID);
				status = m_SSID.set_copy_of_buffer(tmp.Ptr(), tmp.Size());
				if (status != eap_status_ok)
				{
					wlan_settings->Disconnect();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
				}
			}
			else
			{
				// In override mode SSID is stored to m_SSID
				// and password is stored to m_wpa_preshared_key.
			}

			TPSKEntry pskEntry;
			pskEntry.indexType = index_type;
			pskEntry.index = index;
			pskEntry.ssid.Zero();
			pskEntry.password.Zero();
			pskEntry.psk.Zero();

            TInt err(KErrNone);

			// Retrieve saved PSK only when override is not in effect
			TRAP(err, RetrievePSKL(pskEntry));
			
			if (err != KErrNone
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
						wlan_settings->Disconnect();							
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
					}

					status = m_wpa_preshared_key_hash.set_data_length(EAPOL_WPA_PSK_LENGTH_BYTES);
					if (status != eap_status_ok)
					{
						send_error_notification(eap_status_key_error);
						wlan_settings->Disconnect();							
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
						wlan_settings->Disconnect();							
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
						wlan_settings->Disconnect();							
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
					wlan_settings->Disconnect();
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
		
		wlan_settings->Disconnect();
		CleanupStack::PopAndDestroy(wlan_settings);

		if (m_security_mode != Wlan8021x
			&& m_security_mode != Wpa
			&& m_security_mode != Wpa2Only)
		{
			// Unsupported mode
			User::Leave(KErrNotSupported);
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

#ifdef USE_EAP_EXPANDED_TYPES

void eapol_am_wlan_authentication_symbian_c::SetToTopPriorityL(const eap_type_value_e aEapType)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_wlan_authentication_symbian_c::SetToTopPriorityL() - for EXP EAP types\n")));

	TIndexType index_type(ELan);
	TUint index(0UL);
	TInt priorityIndex (0);

	eap_status_e status = read_database_reference_values(
		&index_type,
		&index);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
	}

	if (index_type == ELan)
	{
		for (TInt i = 0; i < m_enabled_expanded_eap_array.Count(); i++)
		{
			TBuf8<KExpandedEAPSize> tmpExpEAP(m_enabled_expanded_eap_array[i]->EapExpandedType);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eapol_am_wlan_authentication_symbian_c::SetToTopPriorityL:Enabled expanded EAP type at index=%d\n"),
				 i));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Enabled expanded EAP type:"),
				tmpExpEAP.Ptr(),
				tmpExpEAP.Size()));

			// This is for one expanded EAP type (for the above one).
			eap_expanded_type_c expandedEAPType;
					
			// Read the expanded EAP type details for this item in m_enabled_expanded_eap_array.
			eap_status_e status = eap_expanded_type_c::read_type(m_am_tools,
													0,
													tmpExpEAP.Ptr(),
													tmpExpEAP.Size(),
													&expandedEAPType);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
			}

			if (aEapType == expandedEAPType)
			{
				// Found it. This is the EAP type which should be at top priority.
				priorityIndex = i;
				break;
			}
		}	
				
		if(priorityIndex == 0)
		{
			// This means this EAP type is already at the top priority.

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eapol_am_wlan_authentication_symbian_c::SetToTopPriorityL() - This is already at top\n")));
			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}

		if (priorityIndex >= m_enabled_expanded_eap_array.Count())
		{
			// No such EAP type in enabled list. This should never happen.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: eapol_am_wlan_authentication_symbian_c::SetToTopPriorityL() - No such EAP in the enabled list\n")));
			
			User::Leave(KErrNotFound);					
		}

		CWLanSettings* wlan = new(ELeave) CWLanSettings;
		CleanupStack::PushL(wlan);
		SWLANSettings wlanSettings;
		if (wlan->Connect() != KErrNone)
		{
			// Could not connect to CommDB			
			User::Leave(KErrCouldNotConnect);
		}
		
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("SetToTopPriorityL():Connected to CommDbIf.\n")));

		if (wlan->GetWlanSettingsForService(index, wlanSettings) != KErrNone)
		{
			wlan->Disconnect();
			User::Leave(KErrUnknown);
		}
		
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("SetToTopPriorityL():Got WLAN settings.\n")));
		
		// Change the order
		SEapExpandedType* TopPriorityEAP(m_enabled_expanded_eap_array[priorityIndex]);

		m_enabled_expanded_eap_array.Remove(priorityIndex); // This does not delete the object	
				
		m_enabled_expanded_eap_array.Insert(TopPriorityEAP, 0); // Insert in the beginning.

		wlan->SetEapDataL(m_enabled_expanded_eap_array, m_disabled_expanded_eap_array);
		
		wlan->Disconnect();

		CleanupStack::PopAndDestroy(wlan);		
	} 
	else
	{
		// At the moment only LAN bearer is supported.

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eapol_am_wlan_authentication_symbian_c::SetToTopPriorityL() - LEAVE - only LAN bearer is supported\n")));
		
		User::Leave(KErrNotSupported);
	}
		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

#else // For normal EAP types

void eapol_am_wlan_authentication_symbian_c::SetToTopPriorityL(const TEap* const aEapType)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_wlan_authentication_symbian_c::SetToTopPriorityL()\n")));

	TIndexType index_type(ELan);
	TUint index(0UL);

	eap_status_e status = read_database_reference_values(
		&index_type,
		&index);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
	}

	if (index_type == ELan)
	{
		TInt i(0);
		TBuf8<3> uid;
		for (i = 0; i < m_iap_eap_array.Count(); i++)
		{
			TEap* eap = m_iap_eap_array[i];
			if (eap->UID[0] == '0')
			{
				// Cut the leading zero
				uid.Copy(eap->UID.Right(eap->UID.Length()-1));				
			}
			else
			{
				uid.Copy(eap->UID);
			}
			if (eap->Enabled == aEapType->Enabled
				&& uid.Compare(aEapType->UID) == 0)
			{
				// Found
				break;
			}
		}
		if (i >= m_iap_eap_array.Count())
		{
			// This should never happen
			User::Leave(KErrNotFound);					
		}
	
		TLex8 tmp(aEapType->UID);
		TInt val(0);
		tmp.Val(val);

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Setting to top priority:\n")));
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Old index: %d\n"), i));
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("  UID: %d\n"), val));
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("  Enabled: %d\n"), aEapType->Enabled));
	
		if (i == 0)
		{
			// Already at the highest priority
			return;
		}

		CWLanSettings* wlan = new(ELeave) CWLanSettings;
		CleanupStack::PushL(wlan);
		SWLANSettings wlanSettings;
		if (wlan->Connect() != KErrNone)
		{
			// Could not connect to CommDB			
			User::Leave(KErrCouldNotConnect);
		}
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Connected to CommDbIf.\n")));

		if (wlan->GetWlanSettingsForService(index, wlanSettings) != KErrNone)
		{
			wlan->Disconnect();
			User::Leave(KErrUnknown);
		}
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Got WLAN settings.\n")));
		
		// Change the order
		TEap* eap = m_iap_eap_array[i];

		m_iap_eap_array.Remove(i); // This does not delete the object	
				
		m_iap_eap_array.Insert(eap, 0);

		wlan->SetEapDataL(m_iap_eap_array);
		
		wlan->Disconnect();

		CleanupStack::PopAndDestroy(wlan);		
	} 
	else
	{
		// At the moment only LAN bearer is supported.
		User::Leave(KErrNotSupported);
	}
		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

#endif // #ifdef USE_EAP_EXPANDED_TYPES 

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

EAP_FUNC_EXPORT eapol_am_wlan_authentication_c * eapol_am_wlan_authentication_c::new_eapol_am_wlan_authentication(
	abs_eap_am_tools_c * const tools,
	const bool is_client_when_true,
	const abs_eapol_wlan_database_reference_if_c * const wlan_database_reference)
{
	EAP_TRACE_BEGIN(tools, TRACE_FLAGS_DEFAULT);

	eapol_am_wlan_authentication_c * const wauth = new eapol_am_wlan_authentication_symbian_c(
		tools,
		is_client_when_true,
		wlan_database_reference);

	EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
	return wauth;
}


//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------
// End.
