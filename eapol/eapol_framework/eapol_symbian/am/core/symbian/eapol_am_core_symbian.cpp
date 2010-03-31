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
* %version: 17.1.2.1.1 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 148 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "eap_am_memory.h"

#include "eap_variable_data.h"
#include "eap_tools.h"
#include "eap_type_all.h"

#include "eapol_am_core_symbian.h"
#include "eapol_ethernet_header.h"
#include "ethernet_core.h"
#include "eap_am_tools_symbian.h"
#include <EapolToWlmIf.h>
#include "EapolDbDefaults.h"
#include "EapolDbParameterNames.h"
#include "eap_crypto_api.h"
#include "eap_header_string.h"
#include "eap_am_file_input_symbian.h"
#include "eap_rogue_ap_entry.h"
#include "abs_eap_state_notification.h"
#include "eapol_session_key.h"
#include "eap_buffer.h"
#include "eap_config.h"

#if defined(USE_EAP_FILECONFIG)
	#include "eap_file_config.h"
#endif //#if defined(USE_EAP_FILECONFIG)

#if defined (USE_EAPOL_KEY_STATE) 
	#include "eapol_key_state.h"	
#endif

// LOCAL CONSTANTS
const TUint KMaxSqlQueryLength = 2048;
const TUint KMaxConfigStringLength = 256;
const u32_t KMTU = 1500u;
const u32_t KTrailerLength = 0;
const u32_t KHeaderOffset = 0;
const TUint KMaxEapCueLength = 3;

enum eapol_am_core_timer_id_e
{
	EAPOL_AM_CORE_TIMER_RESTART_AUTHENTICATION_ID,
	EAPOL_AM_CORE_TIMER_DELETE_STACK_ID,
	EAPOL_AM_CORE_TIMER_FAILED_COMPLETELY_ID,
};


const TUint8 TEST_RSN_IE[] =
{
	0xdd, // information element id, 221 expressed as Hex value
	0x14, // length in octets, 20 expressed as Hex value
	0x01, 0x00, // Version 1
	0x00, 0x0f, 0xac, 0x04, // CCMP as group key cipher suite
	0x01, 0x00, // pairwise key cipher suite count
	0x00, 0x0f, 0xac, 0x04, // CCMP as pairwise key cipher suite
	0x01, 0x00, // authentication count
	0x00, 0x0f, 0xac, 0x01, // 802.1X authentication
	0x01, 0x00, // Pre-authentication capabilities
};

// ================= MEMBER FUNCTIONS =======================

eapol_am_core_symbian_c::eapol_am_core_symbian_c(MEapolToWlmIf * const aPartner,
												 const bool is_client_when_true,
												 const TUint aServerIndex)
: CActive(CActive::EPriorityStandard)
, m_partner(aPartner)
, m_ethernet_core(0)
, m_am_tools(0)
, m_enable_random_errors(false)
, m_error_probability(0u)
, m_generate_multiple_error_packets(0u)
, m_authentication_counter(0u)
, m_successful_authentications(0u)
, m_failed_authentications(0u)
, m_is_valid(false)
, m_is_client(is_client_when_true)
, m_eap_index(0u)
, m_index_type(ELan)
, m_index(aServerIndex)
//, m_timer(0)
, m_packet_index(0)
, m_manipulate_ethernet_header(false)
, m_send_original_packet_first(false)
, m_authentication_indication_sent(false)
, m_unicast_wep_key_received(false)
, m_broadcast_wep_key_received(false)
, m_block_packet_sends_and_notifications(false)
, m_success_indication_sent(false)
, m_first_authentication(true)
, m_self_disassociated(false)
, m_802_11_authentication_mode(EAuthModeOpen)
, m_receive_network_id(0)
, m_wpa_override_enabled(false)
, m_wpa_psk_mode_allowed(false)
, m_wpa_psk_mode_active(false)
, m_stack_marked_to_be_deleted(false)
, m_active_type_is_leap(false)
, m_fileconfig(0)
{
}	

//--------------------------------------------------

void eapol_am_core_symbian_c::ConstructL()
{
	if (m_partner == 0)
	{
		User::Leave(KErrGeneral);
	}

	// Create tools class
	m_am_tools = new(ELeave) eap_am_tools_symbian_c(EAP_DEFAULT_TRACE_FILE);
	if (m_am_tools->get_is_valid() != true)
	{
		// The real reason most likely is KErrNoMemory but since that is not sure we'll use KErrGeneral
		User::Leave(KErrGeneral);
	}
	if (m_am_tools->configure() != eap_status_ok)
	{
		User::Leave(KErrGeneral);
	}


	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL INITIALISATION\n")));	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("====================\n")));	

	m_wpa_preshared_key = new (ELeave) eap_variable_data_c(m_am_tools);

	m_ssid = new (ELeave) eap_variable_data_c(m_am_tools);

	m_wpa_psk_password_override = new (ELeave) eap_variable_data_c(m_am_tools);

	// Create/initialise the database
	OpenDatabaseL(m_database, m_session);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Database initialized...\n")));
	
#if defined(USE_EAP_FILECONFIG)

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Initialize file configuration.\n")));
			eap_am_file_input_symbian_c fileio(m_am_tools);

		eap_variable_data_c file_name_c_data(m_am_tools);

		eap_status_e status(eap_status_process_general_error);

		{
			eap_const_string const FILECONFIG_FILENAME_C
				= "c:\\system\\data\\eap.conf";

			status = file_name_c_data.set_copy_of_buffer(
				FILECONFIG_FILENAME_C,
				m_am_tools->strlen(FILECONFIG_FILENAME_C));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
			}

			status = file_name_c_data.add_end_null();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
			}
		}

		eap_variable_data_c file_name_z_data(m_am_tools);

		{
			eap_const_string const FILECONFIG_FILENAME_Z
				= "z:\\private\\101F8EC5\\eap.conf";

			status = file_name_z_data.set_copy_of_buffer(
				FILECONFIG_FILENAME_Z,
				m_am_tools->strlen(FILECONFIG_FILENAME_Z));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
			}

			status = file_name_z_data.add_end_null();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
			}
		}

		if (status == eap_status_ok)
		{
			// First try open from C: disk.
			status = fileio.file_open(
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
				status = fileio.file_open(
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
					status = m_fileconfig->configure(&fileio);
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

#endif //#if defined(USE_EAP_FILECONFIG)

#if !defined(USE_EAP_HARDWARE_TRACE)
	{
		// Disable traces.
		m_am_tools->set_trace_mask(eap_am_tools_c::eap_trace_mask_none);

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
					| eap_am_tools_c::eap_trace_mask_error);
			}
		}
	}
#endif //#if defined(USE_EAP_HARDWARE_TRACE)


	{
		eap_status_e status = configure();
		if (status != eap_status_ok)
		{
			User::Leave(KErrGeneral);
			User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
		}
	}
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Configured EAPOL AM...\n")));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Created timer...\n")));

	// SERVER TEST CODE
	if (m_is_client == false)
	{
		TRAPD(err, ReadEAPSettingsL());
		if (err != KErrNone)
		{
			// Setting reading from CommDB failed. Use default values instead (only EAP-SIM).
			
			// SIM
			_LIT(KSIM, "18");
			TEap* sim = new(ELeave) TEap;
			CleanupStack::PushL(sim);
			sim->Enabled = ETrue;
			sim->UID.Copy(KSIM);		
			User::LeaveIfError(m_iap_eap_array.Append(sim));
			CleanupStack::Pop(sim);
		}

	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("========================\n")));

	set_is_valid();

}


//--------------------------------------------------

eapol_am_core_symbian_c* eapol_am_core_symbian_c::NewL(MEapolToWlmIf * const aPartner,
												  const bool aIsClient,
												  const TUint aServerIndex)
{
	eapol_am_core_symbian_c* self = new(ELeave) eapol_am_core_symbian_c(aPartner, aIsClient, aServerIndex);
	CleanupStack::PushL(self);
	self->ConstructL();

	if (self->get_is_valid() != true)
	{
		User::Leave(KErrGeneral);
	}

	CleanupStack::Pop();
	return self;
}

//--------------------------------------------------

eapol_am_core_symbian_c::~eapol_am_core_symbian_c()
{

#if defined(USE_EAP_FILECONFIG)
	delete m_fileconfig;
	m_fileconfig = 0;
#endif //#if defined(USE_EAP_FILECONFIG)

	shutdown();
}

//--------------------------------------------------

//
eap_status_e eapol_am_core_symbian_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::shutdown()\n")));

	// Cancel timer	
	cancel_all_timers();

	// Delete upper stack if it still exists
	if (m_ethernet_core != 0)
	{
		m_ethernet_core->shutdown();
		delete m_ethernet_core;
	}
	
	delete m_wpa_preshared_key;
	
	delete m_ssid;

	delete m_wpa_psk_password_override;

	delete m_receive_network_id;

	m_database.Close();
	m_session.Close();

	// Print some statistics
	if (m_is_client)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_TEST_VECTORS,
			(EAPL("client authentication SUCCESS %d, FAILED %d, count %d\n"),
			m_successful_authentications,
			m_failed_authentications,
			m_authentication_counter));	
	}
	else
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_TEST_VECTORS,
			(EAPL("server authentication SUCCESS %d, FAILED %d, count %d\n"),
			m_successful_authentications,
			m_failed_authentications,
			m_authentication_counter));
	}	
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPOL EXITING.\n")));
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	

	// Finally delete tools. No logging is allowed after this.
	if (m_am_tools != 0)
	{
		m_am_tools->shutdown();
		delete m_am_tools;
	}


	// Unload all loaded plugins
	// NOTE this must be after the m_am_tools->shutdown() call.
	// m_am_tools->shutdown() will run virtual functions of some plugins.
	for(int i = 0; i < m_plugin_if_array.Count(); i++)
	{
		delete m_plugin_if_array[i];
	}

	m_plugin_if_array.Close();
	m_eap_type_array.Close();

	// Delete the IAP EAP type info array
	m_iap_eap_array.ResetAndDestroy();
	

	return eap_status_ok;
}

//--------------------------------------------------

//
void eapol_am_core_symbian_c::RunL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::RunL(): iStatus.Int() = %d\n"),
		iStatus.Int()));

	if (iStatus.Int() != KErrNone)
	{
		return;
	}

	// Authentication cancelled.
	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("Authentication cancelled.\n")));

	// Set block on.
	m_block_packet_sends_and_notifications = true;

	// Reset flags
	m_success_indication_sent = false;
	m_unicast_wep_key_received = false;
	m_broadcast_wep_key_received = false;
	m_authentication_indication_sent = false;

	m_stack_marked_to_be_deleted = true;
	set_timer(this, EAPOL_AM_CORE_TIMER_DELETE_STACK_ID, 0, 0);
	
	// reset index
	m_eap_index = 0;

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("Indication sent to WLM: EFailedCompletely.\n")));

	m_partner->EapIndication(EFailedCompletely);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

//
void eapol_am_core_symbian_c::DoCancel()
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::DoCancel()\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

//
TInt eapol_am_core_symbian_c::Start(const TIndexType aIndexType, 
									const TUint aIndex, 
									const TSSID& aSSID, 
									const TBool aWPAOverrideEnabled,
									const TUint8* aWPAPSK,
									const TUint aWPAPSKLength)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::Start()\n")));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("STARTING AUTHENTICATION.\n")));

	eap_status_e status(eap_status_ok);

	if (m_ethernet_core != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Deleting previously used stack.\n")));

		// It is an error to call start without calling disassociated
		if (m_stack_marked_to_be_deleted == false)
		{	
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eapol_am_core_symbian_c::Start called twice!\n")));
			return KErrAlreadyExists;
		}

		// The previously used stack is perhaps still waiting for deletion.
		cancel_timer(this, EAPOL_AM_CORE_TIMER_DELETE_STACK_ID);
	
		// Delete stack
		m_ethernet_core->shutdown();
		delete m_ethernet_core;
		m_ethernet_core = 0;				
		
		m_stack_marked_to_be_deleted = false;
	}

	// Clear packet send and notification blocking.
	m_block_packet_sends_and_notifications = false;

	// Store SSID. This is needed for WPA PSK calculation.
	if (aSSID.ssidLength > 0)
	{		
		status = m_ssid->set_copy_of_buffer(aSSID.ssid, aSSID.ssidLength);
		if (status != eap_status_ok)
		{
			return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));
		}
	}
	
	// Store WPAPSK. This is needed for WPA PSK mode in Easy WLAN.
	if (aWPAPSKLength > 0
		&& aWPAPSK != 0)
	{		
		status = m_wpa_psk_password_override->set_copy_of_buffer(aWPAPSK, aWPAPSKLength);
		if (status != eap_status_ok)
		{
			return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));
		}
	}		

	if (aWPAOverrideEnabled)
	{
		m_wpa_override_enabled = true;
	}
	else
	{
		m_wpa_override_enabled = false;
	}
	
	///////////////////////////////////
	// Get EAP parameters from CommDbIf
	///////////////////////////////////
	m_index_type = aIndexType;
	m_index = aIndex;

	TRAPD(err, ReadEAPSettingsL());
	if (err != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP settings reading from CommDb failed or cancelled(err %d).\n"), err));
		m_partner->EapIndication(EFailedCompletely);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return err;
	}

	// Start new authentication from scratch.
	m_unicast_wep_key_received = false;
	m_broadcast_wep_key_received = false;
	m_wpa_psk_mode_active = false;
	
	if (m_wpa_psk_mode_allowed == false
		|| m_wpa_preshared_key->get_data_length() == 0)
	{
		// Check the first enabled type
		TEap* eapType = 0;
		TInt i(0);
		for (i = 0; i < m_iap_eap_array.Count(); i++)
		{
			// Check if type is enabled
			eapType = m_iap_eap_array[i];
			if (eapType->Enabled == 1)
			{	
				break;
			}
		}
		if (i >= m_iap_eap_array.Count())
		{
			// No enabled EAP types.
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
				(EAPL("No enabled EAP types.\n")));
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
				(EAPL("Indication sent to WLM: EFailedCompletely.\n")));

			m_partner->EapIndication(EFailedCompletely);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return KErrNone; 
		}	

		// reset index (start from the first enabled EAP type)
		m_eap_index = i;

		// Check if the first enabled type is LEAP.
		TLex8 tmp(eapType->UID);
		TInt type(0);
		tmp.Val(type);
		
		switch (type)
		{
		case eap_type_leap:
			if (m_security_mode != Wpa
				&& m_security_mode != Wpa2Only)
			{
				m_802_11_authentication_mode = EAuthModeLeap;

				EAP_TRACE_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("Start: Trying auth mode LEAP.\n")));
			}
			else
			{
				// If security mode is WPA or WPA2 then even LEAP uses open authentication!
				m_802_11_authentication_mode = EAuthModeOpen;

				EAP_TRACE_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("Start: Trying auth mode OPEN (LEAP in WPA mode).\n")));
			}

			m_active_type_is_leap = true;
			break;
		default:
			m_802_11_authentication_mode = EAuthModeOpen;

			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("Start: Trying auth mode OPEN.\n")));

			m_active_type_is_leap = false;
			break;
		}
	}
	else
	{
		// WPA Pre-shared key mode
		m_active_type_is_leap = false;
		m_wpa_psk_mode_active = true;
		m_802_11_authentication_mode = EAuthModeOpen;

		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("Start: Trying auth mode OPEN.\n")));
	}
		
	// Ignore return value. Result comes with CompleteAssociation call.
	m_partner->Associate(m_802_11_authentication_mode);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));
}

//--------------------------------------------------

//
TInt eapol_am_core_symbian_c::CompleteAssociation(
		const TInt aResult,
		const TMacAddress& aLocalAddress, 
		const TMacAddress& aRemoteAddress,
		const TUint8* const aReceivedWPAIE, // WLM must give only the WPA IE to EAPOL									        
		const TUint aReceivedWPAIELength,
		const TUint8* const aSentWPAIE,
		const TUint aSentWPAIELength,
		const TWPACipherSuite aGroupKeyCipherSuite,
		const TWPACipherSuite aPairwiseKeyCipherSuite
		)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::CompleteAssociation(): aResult %d\n"),
		aResult));

	eap_status_e status(eap_status_ok);

	// ASSOCIATION UNSUCCESSFUL
	if (aResult != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CompleteAssociation: Unsuccessful.\n")));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("Got AP MAC address"),
			aRemoteAddress.iMacAddress,
			KMacAddressLength));

		// Report rogue AP if we tried LEAP and it failed
		if (m_802_11_authentication_mode == EAuthModeLeap)
		{
			// Only add rogue AP if the error code is correct
			if (aResult == E802Dot11StatusAuthAlgorithmNotSupported)
			{
				eap_rogue_ap_entry_c rogue_entry(m_am_tools);
			
				rogue_entry.set_mac_address(static_cast<const u8_t *>(aRemoteAddress.iMacAddress));
				rogue_entry.set_rogue_reason(rogue_ap_association_failed);

				eap_array_c<eap_rogue_ap_entry_c> rogue_list(m_am_tools);
				status = rogue_list.add_object(&rogue_entry, false);
				if (status == eap_status_ok)
				{	
					status = add_rogue_ap(rogue_list);
					// Ignore return value on purpose - it's not fatal if this fails
				}
			}			
		}

		if (m_wpa_psk_mode_active == false)
		{
			if (aResult == E802Dot11StatusAuthAlgorithmNotSupported
				&& m_security_mode != Wpa
				&& m_security_mode != Wpa2Only) // If security mode is WPA or WPA2 then only OPEN auth should be used
			{
				// Association failed because we had wrong authentication type. 
				// Try to find next allowed type that uses different authentication type
				m_eap_index++;

				TEap* eapType;
				TBool found(EFalse);
				TInt i(0);
				for (i = m_eap_index; i < m_iap_eap_array.Count(); i++)
				{
					// Check if type is enabled
					eapType = m_iap_eap_array[i];
					if (eapType->Enabled == 1)
					{	
						TLex8 tmp(eapType->UID);
						TInt type(0);
						tmp.Val(type);
						
						switch (type)
						{
						case eap_type_leap:
							if (m_802_11_authentication_mode != EAuthModeLeap)
							{
								// This type will do; it uses different authentication mode.
								EAP_TRACE_ALWAYS(
									m_am_tools,
									TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
									(EAPL("CompleteAssociation: Changed auth mode to LEAP.\n")));

								m_802_11_authentication_mode = EAuthModeLeap;
								m_active_type_is_leap = true;
								found = ETrue;
							}					
							break;
						default:
							if (m_802_11_authentication_mode != EAuthModeOpen)
							{
								// This type will do; it uses different authentication mode.
								EAP_TRACE_ALWAYS(
									m_am_tools,
									TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
									(EAPL("CompleteAssociation: Changed auth mode to OPEN.\n")));

								m_802_11_authentication_mode = EAuthModeOpen;	
								m_active_type_is_leap = false;
								found = ETrue;
							}
							break;
						}				
						if (found)
						{
							break;
						}
					}
				}

				m_eap_index = i;

				if (i >= m_iap_eap_array.Count())
				{
					// All the remaining allowed types had the same authentication mode.
					// Give up this AP.
					EAP_TRACE_ALWAYS(
						m_am_tools,
						TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
						(EAPL("Could not associate to the AP. Tried all types.\n")));

					EAP_TRACE_ALWAYS(
						m_am_tools,
						TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
						(EAPL("Indication sent to WLM: EThisAPFailed.\n")));

					m_partner->EapIndication(EThisAPFailed);
					return KErrNone;

				}

				// We found a type with different authentication mode. Try it.			
			
				// Ignore return value. Result comes with CompleteAssociation call.
				m_partner->Associate(m_802_11_authentication_mode);
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				return KErrNone;
			}
			else
			{
				EAP_TRACE_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("Could not associate to the AP (error %d).\n"), aResult));

				EAP_TRACE_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
					(EAPL("Indication sent to WLM: EThisAPFailed.\n")));

				m_partner->EapIndication(EThisAPFailed);
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				return KErrNone;
			}
		}
		else
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("Could not associate to the AP with WPA pre-shared-key.\n")));

			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
				(EAPL("Indication sent to WLM: EThisAPFailed.\n")));

			m_partner->EapIndication(EThisAPFailed);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return KErrNone;
		}					
	}
	
	// ASSOCIATION SUCCESSFUL
	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("CompleteAssociation: Successful.\n")));

	// Store parameters
	m_local_address = aLocalAddress;

	m_remote_address = aRemoteAddress;

	m_received_wpa_ie = aReceivedWPAIE;

	m_received_wpa_ie_length = aReceivedWPAIELength;

	m_sent_wpa_ie = aSentWPAIE;

	m_sent_wpa_ie_length = aSentWPAIELength;

	m_group_key_cipher_suite = aGroupKeyCipherSuite;

	m_pairwise_key_cipher_suite = aPairwiseKeyCipherSuite;

	// Create stack if it does not already exist. 
	status = create_upper_stack();
	if (status != eap_status_ok
		&& status != eap_status_already_exists)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("Indication sent to WLM: EFailedCompletely.\n")));

		m_partner->EapIndication(EFailedCompletely);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return KErrNone; 
	}

	// First create stack object and then copy it to heap object. This is because 
	// eap_am_network_id_c does not have a constructor that copies the buffers.
	eap_am_network_id_c receive_network_id(
			m_am_tools,
			&aRemoteAddress,
			sizeof(TMacAddress),
			&aLocalAddress,
			sizeof(TMacAddress),
			eapol_ethernet_type_pae,
			false,
			false);
	
	delete m_receive_network_id;
	m_receive_network_id = new eap_am_network_id_c(
		m_am_tools);

	if (m_receive_network_id == 0)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("Indication sent to WLM: EFailedCompletely.\n")));

		m_partner->EapIndication(EFailedCompletely);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return KErrNone; 
	}
	
	status = m_receive_network_id->set_copy_of_network_id(&receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("Indication sent to WLM: EFailedCompletely.\n")));

		m_partner->EapIndication(EFailedCompletely);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return KErrNone; 
	}

	
#if defined (USE_EAPOL_KEY_STATE) 

	// Initialise EAPOL key state

	eapol_key_authentication_type_e authentication_type(eapol_key_authentication_type_dynamic_WEP);
	
	if (aReceivedWPAIE !=0 
		&& aSentWPAIE != 0)
	{
		// WPA (in wpa or 802.1x security mode)
		if (m_wpa_psk_mode_allowed == false)
		{
			authentication_type = eapol_key_authentication_type_WPA_EAP;
		}
		else
		{
			m_wpa_psk_mode_active = true;
			authentication_type = eapol_key_authentication_type_WPA_PSK;
		}

	}
	else
	{
		// Non-wpa mode
		authentication_type = eapol_key_authentication_type_dynamic_WEP;
	}	

	eap_variable_data_c	authenticator_RSNA_IE(m_am_tools);
	eap_variable_data_c	supplicant_RSNA_IE(m_am_tools);

	// Note: the default values here are only for 802.1x mode. In that mode
	// we don't know the WEP key length beforehand so we will have to guess.
	// It does not matter in this case if we guess wrong - only thing that matters
	// is that it is WEP.
	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e 
		eapol_pairwise_cipher(eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_40);
	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e 
		eapol_group_cipher(eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_40);	
	
	// WPA mode is active if information elements are valid
	if (aReceivedWPAIE != 0
		&& aSentWPAIE != 0)
	{
		status = authenticator_RSNA_IE.set_copy_of_buffer(aReceivedWPAIE, aReceivedWPAIELength);
		if (status != eap_status_ok)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
				(EAPL("Indication sent to WLM: EFailedCompletely.\n")));

			m_partner->EapIndication(EFailedCompletely);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return KErrNoMemory;
		}
		status = supplicant_RSNA_IE.set_copy_of_buffer(aSentWPAIE, aSentWPAIELength);
		if (status != eap_status_ok)
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
				(EAPL("Indication sent to WLM: EFailedCompletely.\n")));

			m_partner->EapIndication(EFailedCompletely);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return KErrNoMemory;
		}
		
		switch (aGroupKeyCipherSuite)
		{
		case ENoCipherSuite:
			eapol_group_cipher = eapol_RSNA_key_header_c::eapol_RSNA_cipher_none;
			break;
		case EWEP40:
			eapol_group_cipher = eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_40;							 
			break;
		case EWEP104:
			eapol_group_cipher = eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_104;
			break;
		case ETKIP:
			eapol_group_cipher = eapol_RSNA_key_header_c::eapol_RSNA_cipher_TKIP;
			break;
		case ECCMP:
			eapol_group_cipher = eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP;
			break;
		case EWRAP:
		default:
			User::Panic(_L("EAPOL"), KErrNotSupported);							
		}

		switch (aPairwiseKeyCipherSuite)
		{
		case ENoCipherSuite:
			eapol_pairwise_cipher = eapol_RSNA_key_header_c::eapol_RSNA_cipher_none;
			break;
		case EWEP40:
			eapol_pairwise_cipher = eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_40;							 
			break;
		case EWEP104:
			eapol_pairwise_cipher = eapol_RSNA_key_header_c::eapol_RSNA_cipher_WEP_104;
			break;
		case ETKIP:
			eapol_pairwise_cipher = eapol_RSNA_key_header_c::eapol_RSNA_cipher_TKIP;
			break;
		case ECCMP:
			eapol_pairwise_cipher = eapol_RSNA_key_header_c::eapol_RSNA_cipher_CCMP;
			break;
		case EWRAP:
		default:
			User::Panic(_L("EAPOL"), KErrNotSupported);							
		}
	} 

	if (authentication_type == eapol_key_authentication_type_WPA_PSK)
	{
		status = m_ethernet_core->association(
			m_receive_network_id,
			authentication_type,
			&authenticator_RSNA_IE,
			&supplicant_RSNA_IE,
			eapol_pairwise_cipher,
			eapol_group_cipher,
			m_wpa_preshared_key);
	}
	else
	{
		status = m_ethernet_core->association(
			m_receive_network_id,
			authentication_type,
			&authenticator_RSNA_IE,
			&supplicant_RSNA_IE,
			eapol_pairwise_cipher,
			eapol_group_cipher,
			0);
	}
	if (status != eap_status_ok)
	{

		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("m_ethernet_core->association call failed.\n")));

		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("Indication sent to WLM: EFailedCompletely.\n")));

		m_partner->EapIndication(EFailedCompletely);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return KErrGeneral;
	}

#endif // USE_EAPOL_KEY_STATE

	if (m_wpa_psk_mode_active == false)
	{
		// Start authentication if mode is not pre-shared key. If mode is pre-shared key then
		// just wait for EAPOL-Key frames.
		status = m_ethernet_core->start_authentication(m_receive_network_id, m_is_client);		
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));
}

//--------------------------------------------------

//
TInt eapol_am_core_symbian_c::ReceivePacket(const TUint aLength, const TUint8* const aPacket)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
		
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::ReceivePacket()\n")));

	if (aLength < eapol_ethernet_header_wr_c::get_header_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message));
	}

	eapol_ethernet_header_wr_c eth_header(m_am_tools, aPacket, aLength);
	eap_am_network_id_c receive_network_id(
			m_am_tools,
			eth_header.get_source(),
			eth_header.get_source_length(),
			eth_header.get_destination(),
			eth_header.get_destination_length(),
			eth_header.get_type(),
			false,
			false);
	eap_status_e status(eap_status_process_general_error);
	if (eth_header.get_type() == eapol_ethernet_type_pae)
	{
		status = create_upper_stack();
		if (status != eap_status_ok 
			&& status != eap_status_already_exists)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Indication sent to WLM: EFailedCompletely.\n")));
			m_partner->EapIndication(EFailedCompletely);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return KErrNone; 
		} 

#if defined (USE_EAPOL_KEY_STATE) 
		if (m_is_client == false
			&& status != eap_status_already_exists)
		{
			// If we are server we need to do associate here.
			eapol_key_authentication_type_e authentication_type(
				eapol_key_authentication_type_WPA_EAP);

			eap_variable_data_c authenticator_RSNA_IE(m_am_tools);
			eap_variable_data_c supplicant_RSNA_IE(m_am_tools);

			status = authenticator_RSNA_IE.set_buffer(TEST_RSN_IE, sizeof(TEST_RSN_IE), false, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
			}

			status = supplicant_RSNA_IE.set_buffer(TEST_RSN_IE, sizeof(TEST_RSN_IE), false, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
			}
						
			eapol_RSNA_key_header_c::eapol_RSNA_cipher_e 
				eapol_pairwise_cipher(eapol_RSNA_key_header_c::eapol_RSNA_cipher_TKIP);	
			eapol_RSNA_key_header_c::eapol_RSNA_cipher_e 
				eapol_group_cipher(eapol_RSNA_key_header_c::eapol_RSNA_cipher_TKIP);	
			
				
			if (authentication_type == eapol_key_authentication_type_WPA_PSK)
			{
				status = m_ethernet_core->association(
					&receive_network_id,
					authentication_type,
					&authenticator_RSNA_IE,
					&supplicant_RSNA_IE,
					eapol_pairwise_cipher,
					eapol_group_cipher,
					m_wpa_preshared_key);
			}
			else
			{
				status = m_ethernet_core->association(
					&receive_network_id,
					authentication_type,
					&authenticator_RSNA_IE,
					&supplicant_RSNA_IE,
					eapol_pairwise_cipher,
					eapol_group_cipher,
					0);
			}

		}
#endif // USE_EAPOL_KEY_STATE

		// Forward the packet to the Ethernet layer of the EAPOL stack. Ignore return value. Failure is signalled using state_notification.
		status = m_ethernet_core->packet_process(
			&receive_network_id,
			&eth_header,
			aLength);
		
	} 
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Not supported ethernet type 0x%04x\n"), eth_header.get_type()));
		status = eap_status_ethernet_type_not_supported;
	}
	
	status = eap_status_ok;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));
}

//--------------------------------------------------

void eapol_am_core_symbian_c::set_is_valid()
{
	m_is_valid = true;
}

bool eapol_am_core_symbian_c::get_is_valid()
{
	return m_is_valid;
}

void eapol_am_core_symbian_c::increment_authentication_counter()
{
	++m_authentication_counter;
}

u32_t eapol_am_core_symbian_c::get_authentication_counter()
{
	return m_authentication_counter;
}

bool eapol_am_core_symbian_c::get_is_client()
{
	return m_is_client;
}
	

//--------------------------------------------------

//
eap_status_e eapol_am_core_symbian_c::packet_data_crypto_keys(
	const eap_am_network_id_c * const /*send_network_id*/,
	const eap_variable_data_c * const /*master_session_key*/)
{
	// Not needed in Symbian version
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

eap_status_e eapol_am_core_symbian_c::packet_data_session_key(
	const eap_am_network_id_c * const /*send_network_id*/,
	const eapol_session_key_c * const key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	TInt status(KErrNone);

	const eap_variable_data_c * const key_data = key->get_key();
	if (key_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_key_error;
	}

	EAP_TRACE_DEBUG(m_am_tools,
		TRACE_FLAGS_DEFAULT, 
		(EAPL("packet_data_session_key: index: %d, type %d\n"),
		key->get_key_index(),
		key->get_key_type()));
	
	EAP_TRACE_DATA_DEBUG(m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("packet_data_session_key:"),
		key_data->get_data(key_data->get_data_length()),
		key_data->get_data_length()));
	
	switch (key->get_key_type())
	{
	case eapol_key_type_broadcast:
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eapol_am_core_symbian_c::packet_data_session_key: Got rc4_broadcast key.\n")));

		status = m_partner->SetCipherKey(
			ERC4Broadcast,
			static_cast<TUint8> (key->get_key_index()),
			key_data->get_data(key_data->get_data_length()),
			key_data->get_data_length());
		m_broadcast_wep_key_received = true;
		break;
	case eapol_key_type_unicast:
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eapol_am_core_symbian_c::packet_data_session_key: Got rc4_unicast key.\n")));

		status = m_partner->SetCipherKey(
			ERC4Unicast,
			static_cast<TUint8> (key->get_key_index()),
			key_data->get_data(key_data->get_data_length()),
			key_data->get_data_length());
		m_unicast_wep_key_received = true;
		break;
	default:
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eapol_am_core_symbian_c::packet_data_session_key: Got unsupported key, type %d.\n"),
			key->get_key_type()));
		status = KErrNotSupported;
		break;
	}

	if (m_unicast_wep_key_received == true 
		&& m_broadcast_wep_key_received == true
		&& m_success_indication_sent == false)
	{
		// Signal success because we have received one unicast (pairwise) key and one broadcast (group) key.
		// If there are more keys coming later they are saved also.
		if (m_active_type_is_leap == true)
		{
			// Leap was successful
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Indication sent to WLM: ELeapSuccess.\n")));
			m_partner->EapIndication(ELeapSuccess);
		}
		else
		{
			// some other type was successful
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Indication sent to WLM: ESuccess.\n")));
			m_partner->EapIndication(ESuccess);
		}
		
		m_success_indication_sent = true;
		m_first_authentication = false;
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(status));
}

//--------------------------------------------------

//

eap_status_e eapol_am_core_symbian_c::packet_send(
	const eap_am_network_id_c * const /*send_network_id*/,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t /*buffer_length*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::packet_send(data_length=%d).\n"),
		data_length));

	if (header_offset != 0u)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_process_general_error;
	}
	else if (header_offset+data_length != sent_packet->get_data_length())
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: packet_send: packet buffer corrupted (data_length != sent_packet->get_data_length()).\n")));
		EAP_ASSERT(data_length == sent_packet->get_buffer_length());
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_process_general_error;
	}	

	if (m_block_packet_sends_and_notifications == true)
	{
		// Packet sending block is active. This happens when disassociated has been called.  
		// start_authentication clears the block.
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet ignored because Disassociated() was called.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_ok;
	}

	TInt status(KErrNone);
	if (m_send_original_packet_first == true)
	{
		if (m_enable_random_errors == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TEST: random_error(): packet_index 0x%08x:%lu, Send original packet\n"),
				this,
				m_packet_index));
		}

		u8_t * const packet_data = sent_packet->get_data_offset(header_offset, data_length);
		if (packet_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return eap_status_buffer_too_short;
		}

		// Here we send the original packet.
		status = m_partner->EapPacketSend(
			data_length, 
			static_cast<TUint8*>(packet_data));
		++m_packet_index;
	}

	if (m_enable_random_errors == true
		&& status == KErrNone)
	{
		if (m_generate_multiple_error_packets > 0ul)
		{
			// First create a copy of sent packet. Original correct packet will will be sent last.
			for (u32_t ind = 0ul; ind < m_generate_multiple_error_packets; ind++)
			{
				eap_buf_chain_wr_c *copy_packet = sent_packet->copy();

				if (copy_packet != 0
					&& copy_packet->get_is_valid_data() == true)
				{
					// Make a random error to the copy message.
					random_error(copy_packet, true, m_packet_index);

					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("TEST: random_error(): packet_index 0x%08x:%lu, Send error packet\n"),
						this,
						m_packet_index));
					
					u8_t * const packet_data = copy_packet->get_data_offset(header_offset, data_length);
					if (packet_data == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return eap_status_buffer_too_short;
					}

					// Here we send the copied and manipulated packet.
					status = m_partner->EapPacketSend(
						data_length, 
						static_cast<TUint8*>(packet_data));
					
					++m_packet_index;
				}
				delete copy_packet;
			}
		}
		else
		{
			// Make a random error to the original message.
			random_error(sent_packet, false, m_packet_index);

			if (sent_packet->get_is_manipulated() == true)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TEST: random_error(): packet_index 0x%08x:%lu, Send error packet\n"),
					this,
					m_packet_index));
			}
		}
	}


	if (m_send_original_packet_first == false
		&& status == KErrNone)
	{
		if (m_enable_random_errors == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TEST: random_error(): packet_index 0x%08x:%lu, Send original packet\n"),
				this,
				m_packet_index));
		}

		u8_t * const packet_data = sent_packet->get_data_offset(header_offset, data_length);
		if (packet_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return eap_status_buffer_too_short;
		}

		// Here we send the original packet.
		status = m_partner->EapPacketSend(
			data_length,
			static_cast<TUint8*>(packet_data));
		++m_packet_index;
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(status));
}

//--------------------------------------------------

//
eap_status_e eapol_am_core_symbian_c::reassociate(
		const eap_am_network_id_c * const /* send_network_id */,
		const eapol_key_authentication_type_e /* authentication_type */,
		const eap_variable_data_c * const /* PMKID */,
		const eap_variable_data_c * const /* WPXM_WPXK1 */,
		const eap_variable_data_c * const /* WPXM_WPXK2 */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
void eapol_am_core_symbian_c::state_notification(const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if(state->get_protocol_layer() == eap_protocol_layer_general)
	{
		if (state->get_current_state() == eap_general_state_authentication_cancelled)
		{
			// Authentication was cancelled. Cannot continue.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Authentication was cancelled. Sets timer EAPOL_AM_CORE_TIMER_FAILED_COMPLETELY_ID.\n")));

			set_timer(this, EAPOL_AM_CORE_TIMER_FAILED_COMPLETELY_ID, 0, 0);
		}
		else if (state->get_current_state() == eap_general_state_configuration_error)
		{
			// Configuration error. Cannot continue.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Configuration error. Sets timer EAPOL_AM_CORE_TIMER_FAILED_COMPLETELY_ID.\n")));

			set_timer(this, EAPOL_AM_CORE_TIMER_FAILED_COMPLETELY_ID, 0, 0);
		}
	}


	if (m_block_packet_sends_and_notifications == true)
	{
		// Notification block is active.		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("state_notification: notification ignored because Disassociated() was called.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}


	// Check if this is EAP layer notification
	if(state->get_protocol_layer() == eap_protocol_layer_eap)
	{
		switch (state->get_current_state())
		{
		case eap_state_none:
			break;
		case eap_state_identity_request_sent:
			// This is for server only so no need to notify WLM.
			break;
		case eap_state_identity_request_received:
			if (m_authentication_indication_sent == false) 
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Indication sent to WLM: EAuthenticating.\n")));
				m_partner->EapIndication(EAuthenticating);
				m_authentication_indication_sent = true;
			}
			break;
		case eap_state_identity_response_received:
			// This is for server only so no need to notify WLM.
			break;
		case eap_state_authentication_finished_successfully:
			{

			increment_authentication_counter();
			m_successful_authentications++;	
			
			if (m_wpa_psk_mode_active == false)
			{				
				TEap eap;
				eap.Enabled = ETrue;
				eap.UID.Num(static_cast<TInt>(state->get_eap_type()));
				
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

				// Move the active eap type index to the first type
				m_eap_index = 0; 
			}
						

			}
			break;
		case eap_state_authentication_terminated_unsuccessfully:
			{
				if (m_wpa_psk_mode_active == false)
				{
					// Set index to next type.
					m_eap_index++;
				}
		
				increment_authentication_counter();
				m_failed_authentications++;

				// Restart authentication
				eap_am_network_id_c* send_network_id = new eap_am_network_id_c(m_am_tools, state->get_send_network_id());
				if (send_network_id == 0 
					|| send_network_id->get_is_valid_data() == false)
				{
					delete send_network_id;
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("Indication sent to WLM: EFailedCompletely.\n")));
					m_partner->EapIndication(EFailedCompletely);
					break;
				}
				set_timer(this, EAPOL_AM_CORE_TIMER_RESTART_AUTHENTICATION_ID, send_network_id, 0);

			}
			break;
		default:
			break;
		}
	}
	else 
	{
		if(state->get_protocol_layer() == eap_protocol_layer_eapol)
		{
			switch (state->get_current_state())
			{
			case eapol_state_no_start_response:
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Indication sent to WLM: ENoResponse.\n")));
				m_partner->EapIndication(ENoResponse);
				break;
			default:
				break;
			}
		}
		else if(state->get_protocol_layer() == eap_protocol_layer_eapol_key)
		{
			switch (state->get_current_state())
			{
			case eapol_key_state_802_11i_authentication_terminated_unsuccessfull:
				{					
					increment_authentication_counter();
					m_failed_authentications++;

					// Consider EAPOL layer failures fatal.
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: Unsuccessful authentication on EAPOL level.\n")));
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("Indication sent to WLM: EThisAPFailed.\n")));
					m_partner->EapIndication(EThisAPFailed);
				}
				break;
			case eapol_key_state_802_11i_authentication_finished_successfull:
				{					
					EAP_TRACE_ALWAYS(
						m_am_tools,
						TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
						(EAPL("EAPOL_KEY: %s: Authentication SUCCESS\n"),
						(m_is_client == true ? "client": "server")));
				}
				break;
			default:
				break;
			}
		}	
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//

eap_status_e eapol_am_core_symbian_c::timer_expired(
	const u32_t id, void * /* data */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::TimerExpired id = %d.\n"),
		id));

	switch (id)
	{
	case EAPOL_AM_CORE_TIMER_RESTART_AUTHENTICATION_ID:
		{			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_AM_CORE_TIMER_RESTART_AUTHENTICATION_ID elapsed: Stopping stack.\n")));
			
			// Stop stack. Do this only if Ethernet core still exists.
			if (m_ethernet_core != 0)
			{
				m_ethernet_core->shutdown();
				delete m_ethernet_core;
				m_ethernet_core = 0;
			}
			if (m_wpa_psk_mode_active == true)
			{
				// PSK mode active - cannot restart. Just fail.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WPA PSK mode failed.\n")));
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Indication sent to WLM: EThisAPFailed.\n")));
				m_partner->EapIndication(EThisAPFailed);			
				break;

			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Checking if more types.\n")));

			TInt i;
			TEap *eapType = 0;  
			// Search for more EAP types to try
			for (i = m_eap_index; i < m_iap_eap_array.Count(); i++)
			{
				// Find the next enabled EAP type (highest priority)
				eapType = m_iap_eap_array[i];			
				if (eapType->Enabled == 1)
				{
					break;
				}
			}
			// Update index to point to next type to be tried
			m_eap_index = i;

			if (i >= m_iap_eap_array.Count())
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("No more configured EAP types to try.\n")));

				// No point in trying to restart authentication because there isn't any more
				// EAP types left to try...
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Indication sent to WLM: EThisAPFailed.\n")));
				m_partner->EapIndication(EThisAPFailed);			
				break;
			}

			// Check if authentication mode must be changed
			TLex8 tmp(eapType->UID);
			TInt type(0);
			tmp.Val(type);

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Found new type to try: %d.\n"), type));

			switch (type)
			{
			case eap_type_leap:
				m_active_type_is_leap = true;
				if (m_802_11_authentication_mode != EAuthModeLeap
					&& m_security_mode != Wpa
					&& m_security_mode != Wpa2Only) // In WPA or WPA2 even LEAP uses open authentication
				{
					// New type is LEAP and the old was something else:
					// must reassociate with correct authentication mode.					
					m_self_disassociated = true;
					TInt result = m_partner->Disassociate();
					if (result != KErrNone)
					{
						// Probably unrecoverable error
						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("Indication sent to WLM: EFailedCompletely.\n")));				
						m_partner->EapIndication(EFailedCompletely);
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
						return eap_status_ok;
					}
					
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("TimerExpired: Changing auth type to LEAP.\n")));

					m_802_11_authentication_mode = EAuthModeLeap;
					
					m_partner->Associate(EAuthModeLeap);
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
					return eap_status_ok;
				}
				break;
			default:
				m_active_type_is_leap = false;
				if (m_802_11_authentication_mode != EAuthModeOpen
					&& m_security_mode != Wpa
					&& m_security_mode != Wpa2Only) // In WPA or WPA2 even LEAP uses open authentication)
				{
					// New type is non-LEAP and the old was LEAP:
					// must reassociate with correct authentication mode
					m_self_disassociated = true;
					TInt result = m_partner->Disassociate();
					if (result != KErrNone)
					{
						// Probably unrecoverable error	
						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("Indication sent to WLM: EFailedCompletely.\n")));

						m_partner->EapIndication(EFailedCompletely);
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
						return eap_status_ok;
					}

					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("TimerExpired: Changing auth type to OPEN.\n")));				

					m_802_11_authentication_mode = EAuthModeOpen;
					
					m_partner->Associate(EAuthModeOpen);
					
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
					return eap_status_ok;
				}
				break;
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TimerExpired: No need to change auth type.\n")));				

			if (CompleteAssociation(
					KErrNone,
					m_local_address, 
					m_remote_address,
					m_received_wpa_ie, 
					m_received_wpa_ie_length,
					m_sent_wpa_ie,
					m_sent_wpa_ie_length,
					m_group_key_cipher_suite,
					m_pairwise_key_cipher_suite) != KErrNone)
			{
				// Probably unrecoverable error	
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Indication sent to WLM: EFailedCompletely.\n")));				
				m_partner->EapIndication(EFailedCompletely);
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				return eap_status_ok;
			}			
		}
		break;
				
	case EAPOL_AM_CORE_TIMER_DELETE_STACK_ID:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_AM_CORE_TIMER_DELETE_STACK_ID elapsed: Delete stack.\n")));

			cancel_all_timers();

			// Delete stack
			if (m_ethernet_core != 0)
			{
				m_ethernet_core->shutdown();
				delete m_ethernet_core;
				m_ethernet_core = 0;				
			}
			m_stack_marked_to_be_deleted = false;

			// Re-activates timer queue.
			eap_status_e status = m_am_tools->re_activate_timer_queue();
			if (status != eap_status_ok)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: re_activate_timer_queue() failed, status = %d\n")));
			}
		}
		break;
	
	case EAPOL_AM_CORE_TIMER_FAILED_COMPLETELY_ID:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_AM_CORE_TIMER_FAILED_COMPLETELY_ID elapsed: Indication sent to WLM: EFailedCompletely.\n")));

			m_partner->EapIndication(EFailedCompletely);
		}
		break;
	
	default:
		break;
	}
	return eap_status_ok;
}

eap_status_e eapol_am_core_symbian_c::timer_delete_data(
	const u32_t id, void *data)
{
	switch (id)
	{
	case EAPOL_AM_CORE_TIMER_RESTART_AUTHENTICATION_ID:
		{
			eap_am_network_id_c* tmp = static_cast<eap_am_network_id_c*>(data);
			delete tmp;
		}
		break;
	case EAPOL_AM_CORE_TIMER_DELETE_STACK_ID:
		break;
	case EAPOL_AM_CORE_TIMER_FAILED_COMPLETELY_ID:
		break;

	default:
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eapol_am_core_symbian_c::timer_delete_data: deleted unknown timer.\n")));
			(void)EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
		}
	}	
	return eap_status_ok;
}
//--------------------------------------------------

//
u32_t eapol_am_core_symbian_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	*MTU = KMTU;
	*trailer_length = KTrailerLength;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return KHeaderOffset;
}

//--------------------------------------------------

//
eap_status_e eapol_am_core_symbian_c::unload_module(const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_type_does_not_exists_error);
	TInt index = m_eap_type_array.Find(type);
	if (index != KErrNotFound)
	{
		delete m_plugin_if_array[index];
		m_plugin_if_array.Remove(index);
		m_eap_type_array.Remove(index);
		status = eap_status_ok;			
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eapol_am_core_symbian_c::eap_acknowledge(const eap_am_network_id_c * const receive_network_id)
{
	// Any Network Protocol packet is accepted as a success indication.
	// This is described in RFC 2284 "PPP Extensible Authentication Protocol (EAP)".

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_ethernet_core->eap_acknowledge(receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e eapol_am_core_symbian_c::load_module(
		const eap_type_value_e type,
		const eap_type_value_e tunneling_type,
		abs_eap_base_type_c * const partner,
		eap_base_type_c ** const eap_type_if,
		const bool is_client_when_true,
		const eap_am_network_id_c * const receive_network_id)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::load_module(type %d=%s, tunneling_type %d=%s)\n"),
		static_cast<TInt>(type),
		eap_header_string_c::get_eap_type_string(type),
		static_cast<TInt>(tunneling_type),
		eap_header_string_c::get_eap_type_string(tunneling_type)));

	eap_status_e status = eap_status_process_general_error;
	TBuf8<KMaxEapCueLength> cue;
	cue.Num(static_cast<TInt>(convert_eap_type_to_u32_t(type)));
	CEapType* eapType = 0;
	TInt error(KErrNone);

	// Check if this EAP type has already been loaded
	TInt eapArrayIndex = m_eap_type_array.Find(type);
	if (eapArrayIndex != KErrNotFound)
	{
		// Yep. It was loaded already.
		eapType = m_plugin_if_array[eapArrayIndex];		
	}
	else 
	{
		// We must have a trap here since the EAPOL core knows nothing about Symbian.
		TRAP(error, (eapType = CEapType::NewL(cue, m_index_type, m_index)));	
		if (error != KErrNone
			|| eapType == 0)
		{
			// Interface not found or implementation creation function failed
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ECom could not find/initiate implementation.\n")));
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
	}
	// Set the tunneling type
	eapType->SetTunnelingType(convert_eap_type_to_u32_t(tunneling_type));

	// Create the EAP protocol interface implementation.
	TRAP(error, (*eap_type_if = eapType->GetStackInterfaceL(m_am_tools, partner, is_client_when_true, receive_network_id)));
		
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
			if (m_eap_type_array.Append(type) != KErrNone)
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

//
TInt eapol_am_core_symbian_c::Disassociated()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::Disassociated()\n")));

	if (m_self_disassociated == true)
	{
		// We were expecting this. No need to reset state.
		m_self_disassociated = false;
		return KErrNone;
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::Disassociated.\n")));

	eap_status_e status(eap_status_ok);

	// Set block on.
	m_block_packet_sends_and_notifications = true;

	// Reset flags
	m_success_indication_sent = false;
	m_unicast_wep_key_received = false;
	m_broadcast_wep_key_received = false;
	m_authentication_indication_sent = false;

	if (m_ethernet_core != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Stack exists. Set EAPOL_AM_CORE_TIMER_DELETE_STACK_ID timer.\n")));

		m_stack_marked_to_be_deleted = true;
		set_timer(this, EAPOL_AM_CORE_TIMER_DELETE_STACK_ID, 0, 0);
	} 
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Stack did not exists. EAPOL_AM_CORE_TIMER_DELETE_STACK_ID timer not set.\n")));
	}

	// reset index
	m_eap_index = 0;


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));	
}

//--------------------------------------------------

//
TInt eapol_am_core_symbian_c::SendWPAMICFailureReport(
		TBool aFatalMICFailure,
		const TMICFailureType aMICFailureType)
{
	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::SendWPAMICFailureReport(%d, %d).\n"),
		aFatalMICFailure,
		aMICFailureType));

	bool fatal_failure_when_true = true;

	if (!aFatalMICFailure)
	{
		fatal_failure_when_true = false;
	}

	eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e tkip_mic_failure_type
		= eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_pairwise_key;

	if (aMICFailureType == EGroupKey)
	{
		tkip_mic_failure_type
			= eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_group_key;
	}

	const eap_status_e status = m_ethernet_core->tkip_mic_failure(
		m_receive_network_id,
		fatal_failure_when_true,
		tkip_mic_failure_type);

	return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));	
}


//--------------------------------------------------

//
void eapol_am_core_symbian_c::ReadEAPSettingsL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::ReadEAPSettingsL()\n")));

	eap_status_e status(eap_status_ok);

	// Delete old IAP settings
	m_iap_eap_array.ResetAndDestroy();
	if (m_index_type == ELan)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Beginning to read IAP settings - Type: %d, Index: %d.\n"), m_index_type, m_index));

		CWLanSettings* wlan = new(ELeave) CWLanSettings;
		CleanupStack::PushL(wlan);
		SWLANSettings wlanSettings;
		if (wlan->Connect() != KErrNone)
		{
			// Could not connect to CommDB			
			User::Leave(KErrCouldNotConnect);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT, (EAPL("Connected to CommDbIf.\n")));

		if (wlan->GetWlanSettingsForService(m_index, wlanSettings) != KErrNone)
		{
			wlan->Disconnect();
			User::Leave(KErrUnknown);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Got WLAN settings.\n")));
		
		wlan->GetEapDataL(m_iap_eap_array);
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Got EAP data:\n")));

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

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("End EAP data:\n")));

		if (m_iap_eap_array.Count() == 0)
		{
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
		}

		// Get security mode
		if (m_wpa_override_enabled == false)
		{
			m_security_mode = static_cast<EWlanSecurityMode>(wlanSettings.SecurityMode);		
	
			if (wlanSettings.EnableWpaPsk)
			{
				m_wpa_psk_mode_allowed = true;
			}
			else
			{
				m_wpa_psk_mode_allowed = false;
			}
		}
		else
		{
			// WPA override is enabled
			m_security_mode = Wpa;
			if (m_wpa_psk_password_override->get_is_valid_data() == true
				&& m_wpa_psk_password_override->get_data_length() > 0)
			{
				m_wpa_psk_mode_allowed = true;
			}			
			else
			{
				m_wpa_psk_mode_allowed = false;
			}
		}
		
		
		// Get WPA or WPA2 pre shared key & SSID
		if ((m_security_mode == Wlan8021x
			|| m_security_mode == Wpa
			|| m_security_mode == Wpa2Only)
			&& m_wpa_psk_mode_allowed == true
			&& m_is_client == true)
		{
			eap_variable_data_c * password = new eap_variable_data_c(m_am_tools);
			if (password == 0)
			{
				wlan->Disconnect();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(KErrNoMemory);
			}
			eap_variable_data_c * ssid = new eap_variable_data_c(m_am_tools);
			if (ssid == 0)
			{
				delete password;
				wlan->Disconnect();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(KErrNoMemory);
			}

			// When using easy WLAN there might be WPA PSK override
			if (m_wpa_psk_password_override->get_is_valid_data() == true
				&& m_wpa_psk_password_override->get_data_length() > 0)
			{
				// Use WPA PSK override
				status = password->set_copy_of_buffer(
					m_wpa_psk_password_override->get_data(m_wpa_psk_password_override->get_data_length()), 
					m_wpa_psk_password_override->get_data_length());
				if (status != eap_status_ok)
				{
					delete password;
					delete ssid;
					wlan->Disconnect();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
				}
			}
			else
			{
				status = password->set_copy_of_buffer(wlanSettings.WPAPreSharedKey.Ptr(), wlanSettings.WPAPreSharedKey.Size());
				if (status != eap_status_ok)
				{
					delete password;
					delete ssid;
					wlan->Disconnect();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
				}
			}

			TBuf8<KMaxSSIDLength> tmp;
			tmp.Copy(wlanSettings.SSID);
			status = ssid->set_copy_of_buffer(tmp.Ptr(), tmp.Size());
			if (status != eap_status_ok)
			{
				delete password;
				delete ssid;
				wlan->Disconnect();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
			}

			crypto_wpa_psk_password_hash_c password_hash(m_am_tools);

			if (ssid->get_data_length() == 0)
			{
				status = ssid->set_copy_of_buffer(m_ssid);
				if (status != eap_status_ok)
				{
					delete password;
					delete ssid;
					wlan->Disconnect();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
				}
			}	

			TPSKEntry pskEntry;

			pskEntry.indexType = m_index_type;
			pskEntry.index = m_index;

			TPtr8 ssidPtr(
					ssid->get_data(ssid->get_data_length()),
					ssid->get_data_length(),
					ssid->get_data_length()
				);			

            TInt err(KErrNone);

			if (m_wpa_psk_password_override->get_is_valid_data() == false
				|| m_wpa_psk_password_override->get_data_length() == 0)
			{
				// Retrieve saved PSK only when override is not in effect
				TRAP(err, RetrievePSKL(pskEntry));
			} 
			
			if (err != KErrNone
				|| pskEntry.ssid.Compare(ssidPtr) != 0
				|| pskEntry.password.Compare(wlanSettings.WPAPreSharedKey) != 0)
			{
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("No previous PSK found...\n")));
				// No previous PSK or parameters were changed. We need to calculate
				// PSK again

				status = password_hash.password_hash(
					password,
					ssid,	
					m_wpa_preshared_key,
					0,
					0);

				if (status != eap_status_ok)
				{			
					delete password;
					delete ssid;
					wlan->Disconnect();							
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
				//	return;
				}
				
				if (m_wpa_psk_password_override->get_is_valid_data() == false
					|| m_wpa_psk_password_override->get_data_length() == 0)
				{
					// Save new PSK (only if psk override is not in effect)
					pskEntry.ssid.Copy(ssidPtr);
				
					pskEntry.password.Copy(wlanSettings.WPAPreSharedKey);
					
					pskEntry.psk.Copy(
						m_wpa_preshared_key->get_data(m_wpa_preshared_key->get_data_length()),
						m_wpa_preshared_key->get_data_length()
						);

					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Saving PSK.\n")));
					SavePSKL(pskEntry);																
				}
			}			
			else
			{
				// Copy retrieved psk to member variable
				status = m_wpa_preshared_key->set_copy_of_buffer(pskEntry.psk.Ptr(), pskEntry.psk.Size());
				if (status != eap_status_ok)
				{
					delete password;
					delete ssid;
					wlan->Disconnect();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
				}
			}
			delete password;
			delete ssid;
		}
		
		wlan->Disconnect();
		CleanupStack::PopAndDestroy(wlan);		
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

void eapol_am_core_symbian_c::SetToTopPriorityL(const TEap* const aEapType)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::SetToTopPriorityL()\n")));

	if (m_index_type == ELan)
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

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Beginning to write IAP EAP settings - Type: %d, Index: %d.\n"), m_index_type, m_index));
		
		CWLanSettings* wlan = new(ELeave) CWLanSettings;
		CleanupStack::PushL(wlan);
		SWLANSettings wlanSettings;
		if (wlan->Connect() != KErrNone)
		{
			// Could not connect to CommDB			
			User::Leave(KErrCouldNotConnect);
		}
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Connected to CommDbIf.\n")));		
		if (wlan->GetWlanSettingsForService(m_index, wlanSettings) != KErrNone)
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

//--------------------------------------------------

eap_status_e eapol_am_core_symbian_c::configure()
{	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::configure()\n")));


	//----------------------------------------------------------

#if defined(USE_EAP_ERROR_TESTS)

	{
		eap_variable_data_c EAP_ERROR_TEST_enable_random_errors(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_ERROR_TEST_enable_random_errors.get_field(),
			&EAP_ERROR_TEST_enable_random_errors);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_enable_random_errors.get_is_valid_data() == true)
		{
			u32_t *enable_random_errors = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_enable_random_errors.get_data(sizeof(u32_t));
			if (enable_random_errors != 0
				&& *enable_random_errors != 0)
			{
				m_enable_random_errors = true;
			}
		}
	}

	{
		eap_variable_data_c EAP_ERROR_TEST_send_original_packet_first(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_ERROR_TEST_send_original_packet_first.get_field(),
			&EAP_ERROR_TEST_send_original_packet_first);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_send_original_packet_first.get_is_valid_data() == true)
		{
			u32_t *send_original_packet_first = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_send_original_packet_first.get_data(sizeof(u32_t));
			if (send_original_packet_first != 0
				&& *send_original_packet_first != 0)
			{
				m_send_original_packet_first = true;
			}
		}
	}

	{
		eap_variable_data_c EAP_ERROR_TEST_generate_multiple_error_packets(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_ERROR_TEST_generate_multiple_error_packets.get_field(),
			&EAP_ERROR_TEST_generate_multiple_error_packets);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_generate_multiple_error_packets.get_is_valid_data() == true)
		{
			u32_t *generate_multiple_error_packets = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_generate_multiple_error_packets.get_data(sizeof(u32_t));
			if (generate_multiple_error_packets != 0
				&& *generate_multiple_error_packets != 0)
			{
				m_generate_multiple_error_packets = *generate_multiple_error_packets;
			}
		}
	}


	{
		eap_variable_data_c EAP_ERROR_TEST_manipulate_ethernet_header(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_ERROR_TEST_manipulate_ethernet_header.get_field(),
			&EAP_ERROR_TEST_manipulate_ethernet_header);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_manipulate_ethernet_header.get_is_valid_data() == true)
		{
			u32_t *manipulate_ethernet_header = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_manipulate_ethernet_header.get_data(sizeof(u32_t));
			if (manipulate_ethernet_header != 0
				&& *manipulate_ethernet_header != 0)
			{
				m_manipulate_ethernet_header = true;
			}
		}
	}

	{
		eap_variable_data_c EAP_ERROR_TEST_error_probability(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_ERROR_TEST_error_probability.get_field(),
			&EAP_ERROR_TEST_error_probability);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_error_probability.get_is_valid_data() == true)
		{
			u32_t *error_probability = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_error_probability.get_data(sizeof(u32_t));
			if (error_probability != 0)
			{
				m_error_probability = *error_probability;
			}
		}
	}	

	{
		eap_variable_data_c EAP_disable_function_traces(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_enable_function_traces.get_field(),
			&EAP_disable_function_traces);
		if (status == eap_status_ok
			&& EAP_disable_function_traces.get_is_valid_data() == true)
		{
			u32_t *disable_function_traces = reinterpret_cast<u32_t *>(
				EAP_disable_function_traces.get_data(sizeof(u32_t));
			if (disable_function_traces != 0
				&& *disable_function_traces != 0)
			{
				m_am_tools->set_trace_mask(
					m_am_tools->get_trace_mask()
					| eap_am_tools_c::eap_trace_mask_functions
					);
			}
		}
	}

#endif //#if defined(USE_EAP_ERROR_TESTS)


	//----------------------------------------------------------

	{		
		eap_variable_data_c EAP_TRACE_disable_traces(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_disable_traces.get_field(),
			&EAP_TRACE_disable_traces);
		if (status == eap_status_ok
			&& EAP_TRACE_disable_traces.get_is_valid_data() == true)
		{
			u32_t *disable_traces = reinterpret_cast<u32_t *>(
				EAP_TRACE_disable_traces.get_data(sizeof(u32_t)));
			if (disable_traces != 0
				&& *disable_traces != 0)
			{
				m_am_tools->set_trace_mask(eap_am_tools_c::eap_trace_mask_none);
			}
			else
			{
				// OK, set the default trace mask.
				m_am_tools->set_trace_mask(
					eap_am_tools_c::eap_trace_mask_debug
					| eap_am_tools_c::eap_trace_mask_always
					| eap_am_tools_c::eap_trace_mask_error);
			}
		}
	}

	//----------------------------------------------------------

	{		
		eap_variable_data_c EAP_TRACE_activate_only_trace_masks_always_and_error(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_activate_only_trace_masks_always_and_error.get_field(),
			&EAP_TRACE_activate_only_trace_masks_always_and_error);
		if (status == eap_status_ok
			&& EAP_TRACE_activate_only_trace_masks_always_and_error.get_is_valid_data() == true)
		{
			u32_t *activate_trace_mask_always
				= reinterpret_cast<u32_t *>(
					EAP_TRACE_activate_only_trace_masks_always_and_error.get_data(
						sizeof(u32_t)));
			if (activate_trace_mask_always != 0
				&& *activate_trace_mask_always != 0)
			{
				m_am_tools->set_trace_mask(
					eap_am_tools_c::eap_trace_mask_always
					| eap_am_tools_c::eap_trace_mask_error
					);
			}
		}
	}

	//----------------------------------------------------------

	{		
		eap_variable_data_c EAP_TRACE_activate_trace_on_error(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_activate_trace_on_error.get_field(),
			&EAP_TRACE_activate_trace_on_error);
		if (status == eap_status_ok
			&& EAP_TRACE_activate_trace_on_error.get_is_valid_data() == true)
		{
			u32_t *activate_trace_on_error = reinterpret_cast<u32_t *>(
				EAP_TRACE_activate_trace_on_error.get_data(sizeof(u32_t)));
			if (activate_trace_on_error != 0
				&& *activate_trace_on_error != 0)
			{
				m_am_tools->set_activate_trace_on_error();
			}
		}
	}

	//----------------------------------------------------------

	// All of the configuration options are optional.
	// So we return OK.
	return eap_status_ok;
}

//--------------------------------------------------

eap_status_e eapol_am_core_symbian_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_ASSERT_ALWAYS(data != NULL);
	
	// To remove compilation warning in UREL due to KMaxConfigStringLength.
	if(field->get_field_length() > KMaxConfigStringLength)
	{
		return eap_status_process_general_error;
	}
	
	// Trap must be set here because the OS independent portion of EAPOL
	// that calls this function does not know anything about Symbian.	
	eap_status_e status(eap_status_ok);
	
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
		return status;
	}
	
	status = type_field.set_buffer(
		cf_str_EAP_default_type_u32_t.get_field()->get_field(),
		cf_str_EAP_default_type_u32_t.get_field()->get_field_length(),
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}
	
	status = type_field_server.set_buffer(
		cf_str_EAP_server_default_type_u32_t.get_field()->get_field(),
		cf_str_EAP_server_default_type_u32_t.get_field()->get_field_length(),
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	if (!wanted_field.compare(&type_field)
		|| !wanted_field.compare(&type_field_server))
	{
		TInt i; 
		// We need to return here the next EAP type we should try		
		for (i = m_eap_index; i < m_iap_eap_array.Count(); i++)
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

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EAPOL: Trying EAP type: %d.\n"), val));
				break;
			}
		}	
		m_eap_index = i;
		if (i >= m_iap_eap_array.Count())
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

	// It was something else than EAP type. Read it from DB.
	TRAPD(err, read_configureL(
		field->get_field(),
		field->get_field_length(),
		data));
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

void eapol_am_core_symbian_c::read_configureL(
	eap_config_string field,
	const u32_t /*field_length*/,
	eap_variable_data_c * const data)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

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
	_LIT(KSQLQueryRow, "SELECT %S FROM eapol");
	sqlStatement.Format(KSQLQueryRow, &unicodeString);
	
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
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
					// Empty field. Do nothing...data remains invalid
					// and the stack knows what to do hopefully.
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
	CleanupStack::PopAndDestroy(4); // session & 3 buffers


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

eap_status_e eapol_am_core_symbian_c::write_configure(
	const eap_configuration_field_c * const /*field*/,
	eap_variable_data_c * const /*data*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_not_supported;
}

//--------------------------------------------------

//
eap_status_e eapol_am_core_symbian_c::set_timer(
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
	return status;
}

//--------------------------------------------------

//
eap_status_e eapol_am_core_symbian_c::cancel_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	const eap_status_e status = m_am_tools->am_cancel_timer(
		p_initializer, 
		p_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

//
eap_status_e eapol_am_core_symbian_c::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = m_am_tools->am_cancel_all_timers();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

eap_status_e eapol_am_core_symbian_c::check_is_valid_eap_type(const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	TEap *eapType = 0; 
	
	eap_status_e status(eap_status_illegal_eap_type);
	
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
				status = eap_status_ok;
				break;
			}	
		}
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eapol_am_core_symbian_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	TEap *eapType = 0; 

	eap_status_e status(eap_status_illegal_eap_type);

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
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

void eapol_am_core_symbian_c::TryOpenDatabaseL(RDbNamedDatabase& aDatabase, RDbs& aSession)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::TryOpenDatabaseL()\n")));

	// 1. Open/create a database	
	
	// Connect to the DBMS server.
	User::LeaveIfError(aSession.Connect());		
	CleanupClosePushL(aSession);	
	// aSession and aDatabase are pushed to the cleanup stack even though they may be member
	// variables of the calling class and would be closed in the destructor anyway. This ensures
	// that if they are not member variables they will be closed. Closing the handle twice
	// does no harm.	
	
#ifdef SYMBIAN_SECURE_DBMS
	
	// Create the secure shared database (if necessary) with the specified secure policy.
	// Database will be created in the data caging path for DBMS (C:\private\100012a5).
	
	TInt err = aDatabase.Create(aSession, KDatabaseName, KSecureUIDFormat);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TryOpenDatabaseL() - Created Secure DB for eapol.dat. err=%d\n"), err ));	
		
	if(err == KErrNone)
	{	
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	User::LeaveIfError(aDatabase.Open(aSession, KDatabaseName, KSecureUIDFormat));
	CleanupClosePushL(aDatabase);		
		
#else
	// For non-secured database. The database will be created in the old location (c:\system\data).
	
	RFs fsSession;		
	User::LeaveIfError(fsSession.Connect());
	CleanupClosePushL(fsSession);
	
	// Create the database (if necessary)		
	TInt err = aDatabase.Create(fsSession, KDatabaseName);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TryOpenDatabaseL() - Created Non-Secure DB for eapol.dat. err=%d\n"), err ));	
	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	CleanupStack::PopAndDestroy(); // close fsSession
	
	User::LeaveIfError(aDatabase.Open(aSession, KDatabaseName));
	CleanupClosePushL(aDatabase);		
	    
#endif // #ifdef SYMBIAN_SECURE_DBMS

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
		
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}
	
	CleanupStack::PopAndDestroy(); // buf
	CleanupStack::Pop(2); // database, session
	
	// If compacting is not done the database will start growing
	aDatabase.Compact();
}

//--------------------------------------------------

void eapol_am_core_symbian_c::OpenDatabaseL(RDbNamedDatabase& aDatabase, RDbs& aSession)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::OpenDatabaseL()\n")));

	// Create the database (if necessary)
	TRAPD(err, TryOpenDatabaseL(aDatabase, aSession));
	if (err != KErrNone)
	{
		// Because of error remove the database file.
		RFs fsDataBaseFile;
		User::LeaveIfError(fsDataBaseFile.Connect());
		CleanupClosePushL(fsDataBaseFile);
		err = fsDataBaseFile.Delete(KDatabaseName);
		if(err != KErrNone)
		{
			User::Leave(KErrCorrupt);
		}
		CleanupStack::PopAndDestroy(); // close fsDataBaseFile

		// Try open database again. This will leave if fails second time.
		TryOpenDatabaseL(aDatabase, aSession);
	}
}

//--------------------------------------------------

eap_status_e eapol_am_core_symbian_c::random_error(
	eap_buf_chain_wr_c * const sent_packet,
	const bool forse_error,
	const u32_t packet_index)
{	
	EAP_UNREFERENCED_PARAMETER(packet_index);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::random_error()\n")));

	eap_status_e status(eap_status_ok);
	u8_t *data = sent_packet->get_data(sent_packet->get_data_length());

	crypto_random_c rand(m_am_tools);
	u32_t random_guard(0);
	bool error_generated(false);
	u32_t minimum_index(0);

	if (m_manipulate_ethernet_header == false)
	{
		minimum_index = eapol_ethernet_header_wr_c::get_header_length();
	}

	for (u32_t ind = minimum_index; ind < sent_packet->get_data_length(); ind++)
	{
		status = rand.get_rand_bytes(
			reinterpret_cast<u8_t *>(&random_guard),
			sizeof(random_guard));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// This is simple limiter to the probability of an error.
		// probability = m_error_probability / (2^32)
		if (random_guard < m_error_probability)
		{
			u8_t rnd(0);
			u8_t previous_data(0);
			// Create an error.
			status = rand.get_rand_bytes(
				&rnd,
				sizeof(rnd));
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			previous_data = data[ind];
			data[ind] ^= rnd;

			if (previous_data != data[ind])
			{
				error_generated = true;
				sent_packet->set_random_error_type(eap_random_error_type_manipulate_byte);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TEST: random_error(): packet_index 0x%08x:%lu, data[0x%04x] changed from 0x%02x to 0x%02x.\n"),
					this,
					packet_index,
					ind,
					previous_data,
					data[ind]));
			}
		}
	}

	if (error_generated == false
		&& forse_error == true
		&& sent_packet->get_data_length() > 0ul)
	{
		// Generate one error.

		// Random error type.
		eap_random_error_type error_type = eap_random_error_type_none_keep_this_last_case;
		status = rand.get_rand_bytes(
			reinterpret_cast<u8_t *>(&error_type),
			sizeof(error_type));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		error_type = static_cast<eap_random_error_type>(
			static_cast<u32_t>(error_type % static_cast<u32_t>(
								   eap_random_error_type_none_keep_this_last_case)));

		sent_packet->set_random_error_type(error_type);

		switch(error_type)
		{
		case eap_random_error_type_manipulate_byte:
			{
				u32_t rnd_index(0);
				u8_t previous_data(0);
				u32_t index(0);

				do
				{
					do
					{
						// Create an error index.
						status = rand.get_rand_bytes(
							reinterpret_cast<u8_t *>(&rnd_index),
							sizeof(rnd_index));
						if (status != eap_status_ok)
						{
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						index = (rnd_index % (sent_packet->get_data_length() - minimum_index))
							+ minimum_index;
					}
					while(index < minimum_index
						|| index > sent_packet->get_buffer_length());

					u8_t rnd(0);
					// Create an error.
					status = rand.get_rand_bytes(
						&rnd,
						sizeof(rnd));
					if (status != eap_status_ok)
					{
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					previous_data = data[index];
					data[index] ^= rnd;
				}
				while(previous_data == data[index]);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TEST: random_error(): packet_index 0x%08x:%lu, data[0x%04x] changed from 0x%02x to 0x%02x.\n"),
					this,
					packet_index,
					index,
					previous_data,
					data[index]));

				error_generated = true;
			}
			break;
		case eap_random_error_type_change_packet_length_longer:
			{
				u8_t delta_length(0);
				i32_t new_length(0);

				do
				{
					status = rand.get_rand_bytes(
						reinterpret_cast<u8_t *>(&delta_length),
						sizeof(delta_length));
					if (status != eap_status_ok)
					{
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					new_length = static_cast<i32_t>(sent_packet->get_data_length()
													+ static_cast<i32_t>(delta_length));
				}
				while (new_length < static_cast<i32_t>(
						   eapol_ethernet_header_wr_c::get_header_length())
					|| new_length > static_cast<i32_t>(sent_packet->get_buffer_length()));

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TEST: random_error(): packet_index 0x%08x:%lu, packet length changed from %lu to %lu.\n"),
					this,
					packet_index,
					sent_packet->get_data_length(),
					new_length));

				sent_packet->set_data_length(new_length);

				error_generated = true;
			}
			break;
		case eap_random_error_type_change_packet_length_shorter:
			{
				u8_t delta_length(0);
				i32_t new_length(0);

				do
				{
					status = rand.get_rand_bytes(
						reinterpret_cast<u8_t *>(&delta_length),
						sizeof(delta_length));
					if (status != eap_status_ok)
					{
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					delta_length %= static_cast<i32_t>(
						sent_packet->get_data_length()
						- static_cast<i32_t>(eapol_ethernet_header_wr_c::get_header_length()));

					if (delta_length == 0)
					{
						continue;
					}

					new_length = static_cast<i32_t>(
						sent_packet->get_data_length() - static_cast<i32_t>(delta_length));
				}
				while (new_length < static_cast<i32_t>(
						   eapol_ethernet_header_wr_c::get_header_length())
					|| new_length > static_cast<i32_t>(sent_packet->get_buffer_length()));

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TEST: random_error(): packet_index 0x%08x:%lu, packet length changed from %lu to %lu.\n"),
					this,
					packet_index,
					sent_packet->get_data_length(),
					new_length));

				sent_packet->set_data_length(new_length);

				error_generated = true;
			}
			break;
		default:
			User::Panic(_L("EAPOL"), 1);
			break;
		}
	}

	if (error_generated == true)
	{
		sent_packet->set_is_manipulated();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

eap_status_e eapol_am_core_symbian_c::create_upper_stack()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::create_upper_stack()\n")));

	eap_status_e status(eap_status_ok);

	if (m_ethernet_core == 0)
	{        
		m_ethernet_core = new ethernet_core_c(m_am_tools, this, m_is_client);
		if (m_ethernet_core == 0
			|| m_ethernet_core->get_is_valid() != true)
		{
			if (m_ethernet_core != 0)
			{
				m_ethernet_core->shutdown();
				delete m_ethernet_core;
				m_ethernet_core = 0;							
			}			
			EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Stack creation failed.\n")));			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);	
		}

		// Initialise upper stack
		status = m_ethernet_core->configure();
		
		if (status != eap_status_ok)
		{
			m_ethernet_core->shutdown();
			delete m_ethernet_core;
			m_ethernet_core = 0;							

			EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Stack creation failed.\n")));			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);	
		}
	}
	else
	{			
		status = eap_status_already_exists;
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;	
}

//--------------------------------------------------

eap_status_e eapol_am_core_symbian_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol_am_core_symbian_c::add_rogue_ap()\n")));

	TInt err(KErrNone);
	eap_rogue_ap_entry_c* entry = 0;

	TMacAddress mac;

	TRogueType type;

	for (u32_t i = 0; i < rogue_ap_list.get_object_count(); i++)
	{
		entry = rogue_ap_list.get_object(i);

		entry->get_mac_address(mac.iMacAddress);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Adding rogue AP - type: %d\n"),
			entry->get_rogue_reason()));
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("Rogue MAC address"),
			mac.iMacAddress,
			KMacAddressLength));

		switch (entry->get_rogue_reason())
		{
		case rogue_ap_none:
			// Ignore this
			continue;
		case rogue_ap_association_failed:
			type = EInvalidAuthenticationType;
			break;
		case rogue_ap_timeout:
			type = EAuthenticationTimeout;
			break;
		case rogue_ap_challenge_to_client_failed:
			type = EChallengeFromAPFailed;
			break;
		case rogue_ap_challenge_to_ap_failed:
			type = EChallengeToAPFailed;
			break;
		default:
			// ignore others
			continue;
		}

		err = m_partner->AddRogueAP(mac, type);
		if (err != KErrNone)
		{
			break;
		}
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
}

//--------------------------------------------------

void eapol_am_core_symbian_c::RetrievePSKL(TPSKEntry& entry)
{
	HBufC* sqlbuf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = sqlbuf->Des();

	RDbView view;

	_LIT(KSQL, "SELECT %S, %S, %S, %S, %S FROM %S WHERE %S=%d AND %S=%d");

	sqlStatement.Format(KSQL, &KServiceType, &KServiceIndex, &KSSID, &KPassword, &KPSK,
		&KEapolPSKTableName, &KServiceType, entry.indexType, &KServiceIndex, entry.index);
		
	User::LeaveIfError(view.Prepare(m_database, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
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

	CleanupStack::PopAndDestroy(2); // view, buf
}

//--------------------------------------------------

void eapol_am_core_symbian_c::SavePSKL(TPSKEntry& entry)
{
	// Connect to CommDBif so that we can delete PSK entries that have no IAP associated anymore.
	CWLanSettings* wlan = new(ELeave) CWLanSettings;
	CleanupStack::PushL(wlan);
	
	SWLANSettings wlanSettings;

	if (wlan->Connect() != KErrNone)
	{
		// Could not connect to CommDB			
		User::Leave(KErrCouldNotConnect);
	}

	HBufC* sqlbuf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = sqlbuf->Des();

	RDbView view;

	_LIT(KSQL, "SELECT %S, %S, %S, %S, %S FROM %S");
	
	sqlStatement.Format(KSQL, &KServiceType, &KServiceIndex, &KSSID, &KPassword, &KPSK,
		&KEapolPSKTableName);

	User::LeaveIfError(view.Prepare(m_database, TDbQuery(sqlStatement), TDbWindow::EUnlimited));	
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

			if ((wlan->GetWlanSettingsForService(view.ColUint32(colSet->ColNo(KServiceIndex)), wlanSettings) != KErrNone)
				|| (view.ColUint32(colSet->ColNo(KServiceType)) == static_cast<TUint>(entry.indexType)
					&& view.ColUint32(colSet->ColNo(KServiceIndex)) == static_cast<TUint>(entry.index)))
			{	
				// Not found or current IAP
				view.DeleteL();	
			}
			
		} while (view.NextL() != EFalse);
	}

	wlan->Disconnect();
		
	view.InsertL();
	
	view.SetColL(colSet->ColNo(KServiceType), (TUint)entry.indexType);
	view.SetColL(colSet->ColNo(KServiceIndex), (TUint)entry.index);
	view.SetColL(colSet->ColNo(KSSID), entry.ssid);
	view.SetColL(colSet->ColNo(KPassword), entry.password);
	view.SetColL(colSet->ColNo(KPSK), entry.psk);	
		
	view.PutL();
	
	CleanupStack::PopAndDestroy( colSet ); // Delete colSet.	

	CleanupStack::PopAndDestroy(3); // CWLanSettings, session, database

}

														 
//--------------------------------------------------				


// End of file
