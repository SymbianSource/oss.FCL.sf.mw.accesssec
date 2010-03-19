/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_symbian/wapi_core/symbian/wapi_am_wlan_authentication_symbian.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 22.1.1 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.1.1
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 151 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "wapi_am_wlan_authentication_symbian.h"
#include "abs_wapi_am_wlan_authentication.h"

#include "eap_header_string.h"
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
#include "wapi_core.h"
#include "WapiDbDefaults.h"
#include "certificate_store_db_parameters.h"

//--------------------------------------------------

EAP_FUNC_EXPORT wapi_am_wlan_authentication_symbian_c::~wapi_am_wlan_authentication_symbian_c()
    {
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_am_wlan_authentication_symbian_c::~wapi_am_wlan_authentication_symbian_c(): this = 0x%08x\n"),
		this));
    }

//--------------------------------------------------

EAP_FUNC_EXPORT wapi_am_wlan_authentication_symbian_c::wapi_am_wlan_authentication_symbian_c(
	abs_eap_am_tools_c * const tools,
	const bool is_client_when_true,
	const abs_eapol_wlan_database_reference_if_c * const wlan_database_reference)
: CActive(CActive::EPriorityStandard)
, m_am_partner(0)
, m_am_tools(tools)
, m_fileconfig(0)
, m_SSID(tools)
, m_wlan_database_reference(wlan_database_reference)
, m_receive_network_id(tools)
, m_selected_eapol_key_authentication_type(eapol_key_authentication_type_none)
, m_is_client(is_client_when_true)
, m_is_valid(false)
, m_wapi_preshared_key(tools)
, m_wapi_psk(tools)
, iIapIndex(0)
    {
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    }

//--------------------------------------------------

EAP_FUNC_EXPORT bool wapi_am_wlan_authentication_symbian_c::get_is_valid()
    {
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
    }

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::reset_wapi_configuration()
	{
	
	return eap_status_ok;
	}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::configure()
    {
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_am_wlan_authentication_symbian_c::configure(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

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
						= "c:\\system\\data\\wapi.conf";
				#else
					eap_const_string const FILECONFIG_FILENAME_C
						= "c:\\private\\101F8EC5\\wapi.conf";
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
						= "z:\\system\\data\\wapi.conf";
				#else
					eap_const_string const FILECONFIG_FILENAME_Z
						= "z:\\private\\101F8EC5\\wapi.conf";
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

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
    }

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::shutdown()
    {
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_am_wlan_authentication_symbian_c::shutdown(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

	delete m_fileconfig;
    m_fileconfig = 0;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
    }

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::set_am_partner(
	abs_wapi_am_wlan_authentication_c * am_partner
	)
    {
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_am_wlan_authentication_simulator_c::set_am_partner(): %s, this = 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this));

	m_am_partner = am_partner;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
    }

//--------------------------------------------------
//--------------------------------------------------

void wapi_am_wlan_authentication_symbian_c::send_error_notification(const eap_status_e error)
    {
	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_am_wlan_authentication_symbian_c::send_error_notification, error=%d\n"),
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

EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::set_wlan_parameters(
	const eap_variable_data_c * const SSID,
	const bool WPA_override_enabled,
	const eap_variable_data_c * const wapi_preshared_key,
	const eapol_key_authentication_type_e selected_eapol_key_authentication_type)
    {
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_am_wlan_authentication_symbian_c::set_wlan_parameters(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

	m_selected_eapol_key_authentication_type = selected_eapol_key_authentication_type;

	eap_status_e status = m_SSID.set_copy_of_buffer(SSID);
	if (status != eap_status_ok)
	    {
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	   }

	status = m_wapi_preshared_key.set_copy_of_buffer(&m_wapi_psk);
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
void wapi_am_wlan_authentication_symbian_c::state_notification(
	const abs_eap_state_notification_c * const state)
    {
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(state);
	
	// nothing to show to user, so do nothing
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    }

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::association(
	const eap_am_network_id_c * const receive_network_id)
    {
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_am_wlan_authentication_symbian_c::association(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

	eap_status_e status = m_receive_network_id.set_copy_of_network_id(receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
    }

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::disassociation(
	const eap_am_network_id_c * const /* receive_network_id */ ///< source includes remote address, destination includes local address.
	)
    {
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_am_wlan_authentication_symbian_c::disassociation(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
    }

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::get_wlan_configuration(
	eap_variable_data_c * const wapi_psk)
    {
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok;
	
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_am_wlan_authentication_symbian_c::get_wlan_configuration(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));


	TRAPD(err, status = GetWlanConfigurationL(wapi_psk ));
	if (err)
	    {
	    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	    return m_am_tools->convert_am_error_to_eapol_error(err);
	    }
	  
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
    }

eap_status_e wapi_am_wlan_authentication_symbian_c::GetWlanConfigurationL(eap_variable_data_c * const wapi_psk )
    {

    EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
    
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
        EAP_TRACE_DEBUG(
            m_am_tools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("Beginning to read IAP settings - Type: %d, Index: %d.\n"), index_type, index));
        
        iIapIndex = index;
        
        CWLanSettings* wlan_settings = new(ELeave) CWLanSettings;
        CleanupStack::PushL(wlan_settings);
        SWLANSettings wlanSettings;
        if (wlan_settings->Connect() != KErrNone)
            {
            // Could not connect to CommDB          
            CleanupStack::PopAndDestroy(wlan_settings);
            User::Leave(KErrCouldNotConnect);
            }

        EAP_TRACE_DEBUG(
                m_am_tools,
                TRACE_FLAGS_DEFAULT, (EAPL("Connected to CommDbIf.\n")));

        if (wlan_settings->GetWlanSettingsForService(index, wlanSettings) != KErrNone)
            {
            wlan_settings->Disconnect();
            CleanupStack::PopAndDestroy(wlan_settings);
            User::Leave(KErrUnknown);
            }

        status = m_wapi_preshared_key.set_copy_of_buffer(
                wlanSettings.WPAPreSharedKey.Ptr(),
                wlanSettings.WPAPreSharedKey.Size());
        if (status != eap_status_ok)
            {
            send_error_notification(eap_status_key_error);
            wlan_settings->Disconnect();
            CleanupStack::PopAndDestroy(wlan_settings);
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
           }

       // Here we copy the SSID read from IAP.
       TBuf8<32> tmp;
       tmp.Copy(wlanSettings.SSID);
       status = m_SSID.set_copy_of_buffer(tmp.Ptr(), tmp.Size());
        if (status != eap_status_ok)
           {
           wlan_settings->Disconnect();
           CleanupStack::PopAndDestroy(wlan_settings);
           EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
           User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
           }
 
        EAP_TRACE_DATA_DEBUG(
               m_am_tools,
               TRACE_FLAGS_DEFAULT,
               (EAPL("m_wapi_preshared_key"),
                       m_wapi_preshared_key.get_data(),
                       m_wapi_preshared_key.get_data_length()));

        TInt aPskType = wlanSettings.PresharedKeyFormat;
 
        if (aPskType == EWlanPresharedKeyFormatHex)
            {
            EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("PSK HEX\n")));
    
            m_wapi_psk.reset();
            wapi_psk->reset();
    
            u32_t target_length(m_wapi_preshared_key.get_data_length() / 2);
                 
            status = m_wapi_psk.set_buffer_length(target_length);
        
            if (status != eap_status_ok)
                {
                EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("set_buffer_length NOT OK \n")));
                send_error_notification(eap_status_key_error);
                wlan_settings->Disconnect();                            
                CleanupStack::PopAndDestroy(wlan_settings); 
                EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                return eap_status_key_error;
                }
            
            status = m_wapi_psk.set_data_length(target_length);
            if (status != eap_status_ok)
                {
                EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("set_data_length NOT OK \n")));
                send_error_notification(eap_status_key_error);
                wlan_settings->Disconnect();                            
                CleanupStack::PopAndDestroy(wlan_settings); 
                EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                return eap_status_key_error;
                }
    
            status = m_am_tools->convert_hex_ascii_to_bytes(
                    m_wapi_preshared_key.get_data(m_wapi_preshared_key.get_data_length()),
                    m_wapi_preshared_key.get_data_length(),
                    m_wapi_psk.get_data(target_length),
                    &target_length);
            
            if (status != eap_status_ok
                    || target_length != (m_wapi_preshared_key.get_data_length()/2))
                    {
                    EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("convert_hex_ascii_to_bytes NOT OK \n")));
                    send_error_notification(eap_status_key_error);
                    wlan_settings->Disconnect();                            
                    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                    CleanupStack::PopAndDestroy(wlan_settings);
                   return eap_status_key_error;
                    }
                
            status = wapi_psk->set_copy_of_buffer(&m_wapi_psk);
            if (status != eap_status_ok)
                {
                EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("set_copy_of_buffer NOT OK \n")));
                send_error_notification(eap_status_key_error);
                wlan_settings->Disconnect();                            
                EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                CleanupStack::PopAndDestroy(wlan_settings); 
                return eap_status_key_error;
                }
            }
        else
            {
            EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("PSK ASCII\n")));
            m_wapi_psk.reset();
            wapi_psk->reset();

            status = m_wapi_psk.set_copy_of_buffer(&m_wapi_preshared_key);
            if (status != eap_status_ok)
                {
                EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("set_copy_of_buffer NOT OK \n")));
                send_error_notification(eap_status_key_error);
                wlan_settings->Disconnect();                            
                EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                CleanupStack::PopAndDestroy(wlan_settings); 
                return eap_status_key_error;
                }
            
            status = wapi_psk->set_copy_of_buffer(&m_wapi_psk); 
            if (status != eap_status_ok)
                {
                EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("set_copy_of_buffer NOT OK \n")));
                send_error_notification(eap_status_key_error);
                wlan_settings->Disconnect();                            
                EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                CleanupStack::PopAndDestroy(wlan_settings); 
               return eap_status_key_error;
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
                m_wapi_preshared_key.get_data(),
                m_wapi_preshared_key.get_data_length()));
            
        EAP_TRACE_DATA_DEBUG(
                m_am_tools,
                TRACE_FLAGS_DEFAULT,
                (EAPL("new WPA-PSK hash"),
                m_wapi_psk.get_data(),
                m_wapi_psk.get_data_length()));
    
        CleanupStack::PopAndDestroy(wlan_settings);
        }
    
    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    return status;

    }
                                                         
//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::authentication_finished(
	const bool when_true_successfull,
	const eapol_key_authentication_type_e authentication_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_am_wlan_authentication_symbian_c::authentication_finished(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

eap_status_e wapi_am_wlan_authentication_symbian_c::read_database_reference_values(
	TIndexType * const type,
	TUint * const index)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_am_wlan_authentication_symbian_c::read_database_reference_values(): %s, this = 0x%08x => 0x%08x\n"),
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
		(EAPL("wapi_am_wlan_authentication_symbian_c::read_database_reference_values(): Type=%d, Index=%d.\n"),
		 *type,
		 *index));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_ASSERT_ALWAYS(data != NULL);
	
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_am_wlan_authentication_symbian_c::read_configure(): %s, this = 0x%08x => 0x%08x\n"),
		 (m_is_client == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));
	
	eap_status_e status(eap_status_ok);

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
	
	TInt err = KErrNone;
	HBufC8* asciibuf = NULL;
	TRAP( err, asciibuf = HBufC8::NewL(128));
    if (err != KErrNone) 
        {
        EAP_TRACE_DEBUG(
            m_am_tools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("wapi_am_wlan_authentication_symbian_c::read_configure HBufC8::NewL LEAVE(): Type=%d.\n"),
                    err));
            status = m_am_tools->convert_am_error_to_eapol_error(err);
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            return status;
        }
   
    if((cf_str_WAPI_database_reference_index.get_field()->compare((m_am_tools), field)) == true)
        {
        if (iIapIndex == 0)
            {
            TIndexType index_type(ELan);

            eap_status_e status = read_database_reference_values(
                &index_type,
                &iIapIndex);
            if (status != eap_status_ok)
                {
                EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
                }
            else
                {
                status = data->set_copy_of_buffer(&iIapIndex, sizeof(iIapIndex));
                if (status != eap_status_ok)
                    {
                    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                    User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
                    }
                
                 }
            }
        else
            {
            status = data->set_copy_of_buffer(&iIapIndex, sizeof(iIapIndex));
            if (status != eap_status_ok)
                {
                EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
                }
            }
        EAP_TRACE_DEBUG(
              m_am_tools,
              TRACE_FLAGS_DEFAULT,
              (EAPL("wapi_am_wlan_authentication_symbian_c::read_configure(): index = %d\n"), iIapIndex));
 
        }

    TPtr8 asciiString = asciibuf->Des();
    asciiString.Copy(reinterpret_cast<const unsigned char *>(field));

    eap_variable_data_c aConfigField(m_am_tools);
    aConfigField.set_copy_of_buffer(asciiString.Ptr(), asciiString.Size());

    if ((cf_str_WAPI_CORE_PSK.get_field()->compare((m_am_tools), field)) == true)
        {
        TRAP( err, ReadConfigureL(
            field->get_field(),
            field,
            field->get_field_length(),
            data) );
        }
    delete asciibuf; 
   
	if (err != KErrNone) 
        {
        EAP_TRACE_DEBUG(
            m_am_tools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("wapi_am_wlan_authentication_symbian_c::read_configure ReadConfigureL LEAVE(): Type=%d.\n"),
                    err));
            status = m_am_tools->convert_am_error_to_eapol_error(err);


#if defined(USE_EAP_FILECONFIG)
		if (m_fileconfig != 0
			&& m_fileconfig->get_is_valid() == true)
		    {
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

void wapi_am_wlan_authentication_symbian_c::ReadConfigureL(
	eap_config_string fieldx,
	const eap_configuration_field_c * const field,
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

    eap_variable_data_c aConfigField(m_am_tools);

    if ((cf_str_WAPI_CORE_PSK.get_field()->compare((m_am_tools), field)) == true )
        {
        if(m_wapi_psk.get_data_length()>0)
            {
            data->set_copy_of_buffer(&m_wapi_psk);
            }
        else
            {
            GetWlanConfigurationL(&aConfigField);
            data->set_copy_of_buffer(&aConfigField);
            }
        CleanupStack::PopAndDestroy(2); // 2 buffers
        return;
        }

	CleanupStack::PopAndDestroy(2); // 2 buffers


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::write_configure(
	const eap_configuration_field_c * const /* field */,
	eap_variable_data_c * const /* data */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = eap_status_illegal_configure_field;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::set_timer(
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

EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::cancel_timer(
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

EAP_FUNC_EXPORT eap_status_e wapi_am_wlan_authentication_symbian_c::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = m_am_tools->am_cancel_all_timers();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void wapi_am_wlan_authentication_symbian_c::RunL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_am_wlan_authentication_symbian_c::RunL(): iStatus.Int() = %d\n"),
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
            (EAPL("Disassociation failed in RunL().\n")));
        EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
        return;
    }

    EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("Indication sent to WLM: EFailedCompletely.\n")));

	   m_am_partner->wapi_indication(
	        &m_receive_network_id,
	        eapol_wlan_authentication_state_failed_completely);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

void wapi_am_wlan_authentication_symbian_c::DoCancel()
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_am_wlan_authentication_symbian_c::DoCancel()\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

EAP_FUNC_EXPORT wapi_am_wlan_authentication_c * wapi_am_wlan_authentication_c::new_wapi_am_wlan_authentication(
	abs_eap_am_tools_c * const tools,
	const bool is_client_when_true,
	const abs_eapol_wlan_database_reference_if_c * const wlan_database_reference)
{
	EAP_TRACE_BEGIN(tools, TRACE_FLAGS_DEFAULT);

	wapi_am_wlan_authentication_c * const wauth = new wapi_am_wlan_authentication_symbian_c(
		tools,
		is_client_when_true,
		wlan_database_reference);

	EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
	return wauth;
}


//--------------------------------------------------
// End.
