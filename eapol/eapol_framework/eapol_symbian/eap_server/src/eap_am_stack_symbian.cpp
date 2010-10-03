/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* %version: 52 %
*/

#include "eap_am_stack_symbian.h"
#include "eap_array_algorithms.h"
#include "eap_base_type.h"
#include "eap_header_string.h"
#include "EapConversion.h"
#include "eapol_key_state_string.h"
#include "eap_type_tls_peap_types.h"
#include "EapPluginDbDefaults.h"
#include "EapConfigToolsSymbian.h"
#include "eap_am_general_settings_symbian.h"

class CEapTypePlugin;

// LOCAL CONSTANTS
const TUint KMaxSqlQueryLength = 2048;

const TUint KExpandedEAPSize = 8;

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_stack_symbian_c::eap_am_stack_symbian_c(class abs_eap_am_tools_c * tools, bool is_client_when_true)
	: CActive(0)
	, iTools (tools)
	, iIsClient(is_client_when_true)
	, iPartner(0)
	, m_client_config(tools)
	, iFileconfig(0)
	, iEnabledEapMethodsArray(tools)
	, iDisabledEapMethodsArray(tools)
	, m_eap_type_array(tools)
	, iConfigurationIf(0)
	, iIndexType(ELan)
	, iIndex(0UL)
	, iCurrentEapIndex(0)
	, m_selected_eapol_key_authentication_type(eapol_key_authentication_type_none)
{
    EAP_TRACE_DEBUG(
        tools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("eap_am_stack_symbian_c::eap_am_stack_symbian_c()\n")));

    EAP_TRACE_RETURN_STRING(tools, "returns: eap_am_stack_symbian_c::eap_am_stack_symbian_c()");

    iIsValid = ETrue;
    
    return;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_stack_symbian_c::~eap_am_stack_symbian_c()
    {
    EAP_TRACE_DEBUG(
        iTools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("eap_am_stack_symbian_c::~eap_am_stack_symbian_c()\n")));

	Cancel();

    EAP_TRACE_RETURN_STRING(iTools, "returns: eap_am_stack_symbian_c::~eap_am_stack_symbian_c()");
    }

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_am_stack_symbian_c::get_is_valid()
    {
    return iIsValid;
    }

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_stack_symbian_c::set_partner(abs_eap_am_stack_c * partner, abs_eap_configuration_if_c * configuration_if)
    {
    eap_status_e aStatus(eap_status_ok);
    iPartner = partner;
    iConfigurationIf = configuration_if;
    return aStatus;
    }

//--------------------------------------------------

eap_status_e eap_am_stack_symbian_c::reset_eap_configuration()
{
	EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_stack_symbian_c::reset_eap_configuration(): %s, this = 0x%08x\n"),
		 (iIsClient == true) ? "client": "server",
		 this));

    EAP_TRACE_RETURN_STRING(iTools, "returns: eap_am_stack_symbian_c::reset_eap_configuration()");

	eap_status_e status(eap_status_ok);

	TRAPD(error, ReadEAPSettingsL());
	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP settings reading from CommDb failed or cancelled(error %d).\n"), error));

		status = iTools->convert_am_error_to_eapol_error(error);
	}

	EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(iTools, status);
}

//--------------------------------------------------

// This is documented in abs_eap_stack_interface_c::configure().
EAP_FUNC_EXPORT eap_status_e eap_am_stack_symbian_c::configure(
	const eap_variable_data_c * const client_configuration)
    {
    EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);

    EAP_TRACE_DEBUG(
        iTools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("eap_am_stack_symbian_c::configure(): %s, this = 0x%08x => 0x%08x\n"),
         (iIsClient == true) ? "client": "server",
         this,
         dynamic_cast<abs_eap_base_timer_c *>(this)));

    EAP_TRACE_RETURN_STRING(iTools, "returns: eap_am_stack_symbian_c::configure()");

    TInt error(KErrNone);
	eap_status_e status(eap_status_ok);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (client_configuration != 0
		&& client_configuration->get_is_valid_data() == true)
	{
		status = m_client_config.read_configuration_message(client_configuration);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(iTools, status);
		}
	}
	
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    // Open the database session
    error = iSession.Connect();
    if (error != KErrNone)
    {
        status = EAP_STATUS_RETURN(iTools, iTools->convert_am_error_to_eapol_error(error));

        EAP_TRACE_DEBUG(
            iTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("RDbs::Connect() failed %d.\n"),
            status));
        EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
        return EAP_STATUS_RETURN(iTools, status);
    }

    EAP_TRACE_DEBUG(
        iTools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("Database session initialized...\n")));

    // Connect to FS
    error = iFs.Connect();
    if (error != KErrNone)
    {
        status = EAP_STATUS_RETURN(iTools, iTools->convert_am_error_to_eapol_error(error));

        EAP_TRACE_DEBUG(
            iTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("RFs::Connect() failed %d.\n"),
            status));
        EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
        return EAP_STATUS_RETURN(iTools, status);
    }

    EAP_TRACE_DEBUG(
        iTools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("Fileserver session initialized...\n")));

    // - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = EapConfigToolsSymbian::EapReadDefaultConfigFileSymbian(
		iTools,
		&iFileconfig);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(iTools, status);
	}

    // - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(USE_EAP_FILE_TRACE)
    {
        eap_variable_data_c trace_output_file(iTools);

        status = read_configure(
            cf_str_EAP_TRACE_output_file_name.get_field(),
            &trace_output_file);
        if (status == eap_status_ok
            && trace_output_file.get_is_valid_data() == true)
        {
            status = iTools->set_trace_file_name(&trace_output_file);
            if (status == eap_status_ok)
            {
                // OK, set the default trace mask.
                iTools->set_trace_mask(
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
		eap_variable_data_c EAP_TRACE_enable_timer_traces(iTools);

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
				iTools->set_trace_mask(
					iTools->get_trace_mask()
					| TRACE_FLAGS_TIMER
					);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		eap_variable_data_c EAP_TRACE_enable_timer_queue_traces(iTools);

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
				iTools->set_trace_mask(
					iTools->get_trace_mask()
					| TRACE_FLAGS_TIMER_QUEUE
					);
			}
		}
	}

    {
        eap_variable_data_c EAP_TRACE_enable_function_traces(iTools);

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
                iTools->set_trace_mask(
                    iTools->get_trace_mask()
                    | eap_am_tools_c::eap_trace_mask_functions
                    );
            }
        }
    }

    // - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    EAP_TRACE_DEBUG(
        iTools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("Created timer...\n")));

    EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
    return EAP_STATUS_RETURN(iTools, eap_status_ok);
  
    }

//--------------------------------------------------

eap_status_e eap_am_stack_symbian_c::reset_eap_plugins()
{
	EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_stack_symbian_c::reset_eap_plugins(): %s, this = 0x%08x => 0x%08x\n"),
		 (iIsClient == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

	iEnabledEapMethodsArray.reset();
	iDisabledEapMethodsArray.reset();
	
	m_eap_type_array.reset();
	
	EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(iTools, eap_status_ok);
}

//--------------------------------------------------

// This is documented in abs_eap_stack_interface_c::shutdown().
EAP_FUNC_EXPORT eap_status_e eap_am_stack_symbian_c::shutdown()
{
	EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_ALWAYS(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_stack_symbian_c::shutdown(): %s, this = 0x%08x => 0x%08x\n"),
		 (iIsClient == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

	delete iFileconfig;
	iFileconfig = 0;

	// Unload all loaded plugins
	for(int ind = 0; ind < m_plugin_if_array.Count(); ind++)
	{
		delete m_plugin_if_array[ind];
	}

	m_plugin_if_array.Close();

	(void) reset_eap_plugins();

	EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(iTools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_stack_symbian_c::read_configure(
    const eap_configuration_field_c * const field,
    eap_variable_data_c * const data) 
{
    EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);
    EAP_ASSERT_ALWAYS_TOOLS(iTools, data != NULL);
    
    EAP_TRACE_DEBUG(
        iTools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("eap_am_stack_symbian_c::read_configure(): %s, %d=%s, this = 0x%08x => 0x%08x\n"),
         (iIsClient == true) ? "client": "server",
		 m_selected_eapol_key_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_selected_eapol_key_authentication_type),
         this,
         dynamic_cast<abs_eap_base_timer_c *>(this)));
    
	EAP_TRACE_DATA_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_stack_symbian_c::read_configure()"),
		 field->get_field(),
		 field->get_field_length()));

    EAP_TRACE_RETURN_STRING(iTools, "returns: eap_am_stack_symbian_c::read_configure()");

    // Trap must be set here because the OS independent portion of EAPOL
    // that calls this function does not know anything about Symbian.   
    eap_status_e status(eap_status_ok);

    // Check if the wanted parameter is default type
	if (field->compare(iTools, cf_str_EAP_default_type_hex_data.get_field()) == true)
	{
		// First check do we have read configuration from databases.
		if (m_selected_eapol_key_authentication_type == eapol_key_authentication_type_WPS)
		{
			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("m_selected_eapol_key_authentication_type = eapol_key_authentication_type_WPS\n")));

			status = eap_expanded_type_simple_config.get_type().get_expanded_type_data(
				iTools,
				data);

			if (status == eap_status_ok)
			{
				set_current_eap_index(0);
			}

			EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(iTools, status);
		}
		else if (iEnabledEapMethodsArray.get_object_count() == 0ul)
		{
			EAP_TRACE_ERROR(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: No activated EAP-methods.\n")));

			EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);	
			return EAP_STATUS_RETURN(iTools, eap_status_process_general_error);
		}

		// Now we need to return here the next EAP type we should try

		TInt ind = get_current_eap_index(); 


		if (get_current_eap_index() < iEnabledEapMethodsArray.get_object_count())
		{
			eap_type_value_e * const next_eap_method = iEnabledEapMethodsArray.get_object(get_current_eap_index());
			if (next_eap_method != 0
				&& next_eap_method->get_is_valid() == true)
			{
				status = data->set_buffer_length(eap_expanded_type_c::get_eap_expanded_type_size());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(iTools, eap_status_allocation_error);
				}

				status = data->set_data_length(eap_expanded_type_c::get_eap_expanded_type_size());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(iTools, status);
				}

				status = eap_expanded_type_c::write_type(
					iTools,
					0ul,
					data->get_data(),
					data->get_data_length(),
					true,
					*next_eap_method);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(iTools, status);
				}
			}
		}



		if (ind >= iEnabledEapMethodsArray.get_object_count())
		{
			// Not found any other EAP type as enabled.
			// Send WLM notification because there is no way that the authentication
			// can be successful if we don't have any EAP types to use...
			if (iIsClient)
			{
				EAP_TRACE_ERROR(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: read_configure: No configured EAP types or all tried unsuccessfully.\n")));
			}

			EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(iTools, eap_status_illegal_configure_field);
		}

		EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(iTools, status);

	} // if ()


#if defined(USE_EAP_FILECONFIG)
    {
		status = m_client_config.read_configure(field, data);
		if (status != eap_status_ok)
		{
			if (iFileconfig != 0
				&& iFileconfig->get_is_valid() == true)
			{
				// Here we could try the final configuration option.
				status = iFileconfig->read_configure(
					field,
					data);
			}
		}
    }
#endif //#if defined(USE_EAP_FILECONFIG)


    iTools->trace_configuration(
        status,
        field,
        data);

    EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
    return EAP_STATUS_RETURN(iTools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_stack_symbian_c::set_timer(
    abs_eap_base_timer_c * const p_initializer, 
    const u32_t p_id, 
    void * const p_data,
    const u32_t p_time_ms) 
{
	EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = iTools->am_set_timer(
		p_initializer, 
		p_id, 
		p_data,
		p_time_ms);

	EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(iTools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_stack_symbian_c::cancel_timer(
    abs_eap_base_timer_c * const p_initializer, 
    const u32_t p_id) 
{
	EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = iTools->am_cancel_timer(
		p_initializer, 
		p_id);

	EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(iTools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_stack_symbian_c::check_is_valid_eap_type(
    const eap_type_value_e eap_type) 
{
	EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_stack_symbian_c::check_is_valid_eap_type():  %s, %d=%s, this = 0x%08x => 0x%08x, EAP-type=0xfe%06x%08x=%s\n"),
		(iIsClient == true) ? "client": "server",
		m_selected_eapol_key_authentication_type,
		eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_selected_eapol_key_authentication_type),
		this,
		dynamic_cast<abs_eap_base_timer_c *>(this),
		eap_type.get_vendor_id(),
		eap_type.get_vendor_type(),
		eap_header_string_c::get_eap_type_string(eap_type)));

    EAP_TRACE_RETURN_STRING(iTools, "returns: eap_am_stack_symbian_c::check_is_valid_eap_type()");

	if (m_selected_eapol_key_authentication_type == eapol_key_authentication_type_WPS
		&& eap_type == eap_expanded_type_simple_config.get_type())
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT, (EAPL("eap_am_stack_symbian_c::check_is_valid_eap_type(): WPS does not use CommDbIf anymore.\n")));

		return EAP_STATUS_RETURN(iTools, eap_status_ok);
	}


	for (int ind = 0; ind < iEnabledEapMethodsArray.get_object_count(); ++ind)
	{
		const eap_type_value_e * const allowed_eap_method = iEnabledEapMethodsArray.get_object(ind);

		if (allowed_eap_method != 0
			&& eap_type == *allowed_eap_method)
		{
			// This is Allowed and Valid.
			EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(iTools, eap_status_ok);
		}
	} // for()


	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ERROR: %s: check_is_valid_eap_type(): not supported EAP-type=0xfe%06x%08x=%s\n"),
		 (iIsClient == true ? "client": "server"),
		 eap_type.get_vendor_id(),
		 eap_type.get_vendor_type(),
		 eap_header_string_c::get_eap_type_string(eap_type)));


	EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(iTools, eap_status_illegal_eap_type);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_stack_symbian_c::get_eap_type_list(
    eap_array_c<eap_type_value_e> * const eap_type_list) 
{
	EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_stack_symbian_c::get_eap_type_list(): %s, %d=%s, this = 0x%08x => 0x%08x\n"),
		 (iIsClient == true) ? "client": "server",
		 m_selected_eapol_key_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_selected_eapol_key_authentication_type),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

    EAP_TRACE_RETURN_STRING(iTools, "returns: eap_am_stack_symbian_c::get_eap_type_list()");

	eap_status_e status(eap_status_illegal_eap_type);

	status = eap_type_list->reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(iTools, status);
	}

	if (m_selected_eapol_key_authentication_type == eapol_key_authentication_type_WPS)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT, (EAPL("eap_am_stack_symbian_c::get_eap_type_list(): WPS does not use CommDbIf anymore.\n")));

		// This is for one expanded EAP type (for the above one).
		eap_expanded_type_c * expandedEAPType = new eap_type_value_e(eap_expanded_type_simple_config.get_type());

		// Add WPS EAP-type to list.		
		status = eap_type_list->add_object(expandedEAPType, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(iTools, status);
		}

		return EAP_STATUS_RETURN(iTools, eap_status_ok);
	}

	// This function is same as get_selected_eap_types in behavior.

	// We need to return only the EAP types available as enabled types.
	// It means only the ones available in m_enabled_expanded_eap_array.
	

	for (TInt ind = 0; ind < iEnabledEapMethodsArray.get_object_count(); ++ind)
	{	
		const eap_type_value_e * const allowed_eap_method = iEnabledEapMethodsArray.get_object(ind);

		if (allowed_eap_method != 0
			&& allowed_eap_method->get_is_valid() == true)
		{
			EAP_TRACE_DEBUG(
				iTools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_am_stack_symbian_c::get_eap_type_list(): Enabled expanded EAP type at index=%d, EAP-type=0xfe%06x%08x\n"),
				 ind,
				 allowed_eap_method->get_vendor_id(),
				 allowed_eap_method->get_vendor_type()));

			status = eap_type_list->add_object(allowed_eap_method->copy(), true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(iTools, status);
			}
		}
	} // for()


	EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(iTools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_stack_symbian_c::load_module(
    const eap_type_value_e type,
    const eap_type_value_e tunneling_type,
    abs_eap_base_type_c * const partner,
    eap_base_type_c ** const eap_type,
    const bool is_client_when_true,
    const eap_am_network_id_c * const receive_network_id) 
{
	EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_stack_symbian_c::load_module(type %d=%s, tunneling_type %d=%s)\n"),
		convert_eap_type_to_u32_t(type),
		eap_header_string_c::get_eap_type_string(type),
		convert_eap_type_to_u32_t(tunneling_type),
		eap_header_string_c::get_eap_type_string(tunneling_type)));

	EAP_TRACE_RETURN_STRING(iTools, "returns: eap_am_stack_symbian_c::load_module()");

	eap_status_e status(eap_status_process_general_error);

	CEapTypePlugin* eapType = 0;
	TInt error(KErrNone);

	// Check if this EAP type has already been loaded
	TInt eapArrayIndex = find<eap_type_value_e>(
		&m_eap_type_array,
		&type,
		iTools);

	if (eapArrayIndex >= 0)
	{
		// We found the entry in the array.
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_stack_symbian_c::load_module(type %d=%s, tunneling_type %d=%s) already loaded.\n"),
			convert_eap_type_to_u32_t(type),
			eap_header_string_c::get_eap_type_string(type),
			convert_eap_type_to_u32_t(tunneling_type),
			eap_header_string_c::get_eap_type_string(tunneling_type)));

		// Yep. It was loaded already.
		eapType = m_plugin_if_array[eapArrayIndex];     
	}
	else 
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_stack_symbian_c::load_module(type %d=%s, tunneling_type %d=%s) load new, iIndexType=%d, iIndex=%d.\n"),
			convert_eap_type_to_u32_t(type),
			eap_header_string_c::get_eap_type_string(type),
			convert_eap_type_to_u32_t(tunneling_type),
			eap_header_string_c::get_eap_type_string(tunneling_type),
			iIndexType,
			iIndex));

		TBuf8<KExpandedEAPSize> expanded_type;
    
		// Some indirect way of forming the 8 byte string of an EAP type for the cue is needed here.        
		TUint8 tmp_expanded_type[KExpandedEAPSize];

		// This is to make the tmp_expanded_type in 8 byte string with correct vendor type and vendor id details.
		status = eap_expanded_type_c::write_type(iTools,
												0, // index should be zero here.
												tmp_expanded_type,
												KExpandedEAPSize,
												true,
												type);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("load_module: eap_expanded_type_c::write_type(): failed status=%d=%s\n"),
				status,
				eap_status_string_c::get_status_string(status)));
    
			EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(iTools, status);
		}
    
		// Now copy the 8 byte string to the real expanded cue.
		expanded_type.Copy(tmp_expanded_type, KExpandedEAPSize);

		EAP_TRACE_DATA_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAPOL:eap_am_stack_symbian_c::load_module(): expanded_type:"),
			expanded_type.Ptr(),
			expanded_type.Size()));


		// We must have a trap here since the EAPOL core knows nothing about Symbian.
		TRAP(error, (eapType = CEapTypePlugin::NewL(
			expanded_type,
			iIndexType,
			iIndex,
			iTools)));   
		if (error != KErrNone
			|| eapType == 0)
		{
			// Interface not found or implementation creation function failed
			status = iTools->convert_am_error_to_eapol_error(error);
			if (status == eap_status_ok)
			{
				status = eap_status_allocation_error;
			}

			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: ECom could not find/initiate implementation, error=%d, status=%d=%s.\n"),
				error,
				status,
				eap_status_string_c::get_status_string(status)));

			EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(iTools, status);
		}
	}


	{
		TEapExpandedType expanded_type;
    
		error = CEapConversion::ConvertInternalTypeToExpandedEAPType(
				&tunneling_type,
				&expanded_type);
		if (error != KErrNone)
		{
			status = iTools->convert_am_error_to_eapol_error(error);
			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: CEapConversion::ConvertInternalTypeToExpandedEAPType(): failed error=%d, status=%d=%s\n"),
				error,
				status,
				eap_status_string_c::get_status_string(status)));
			EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(iTools, status);
		}

		eapType->SetTunnelingType(expanded_type);
	}

	// Create the EAP protocol interface implementation.

	TRAP(error, (*eap_type = eapType->GetStackInterfaceL(iTools, 
		partner, 
		is_client_when_true, 
		receive_network_id,
		this)));

	if (error != KErrNone 
		|| *eap_type == 0 
		|| (*eap_type)->get_is_valid() == false)
	{
		status = iTools->convert_am_error_to_eapol_error(error);
		if (status == eap_status_ok)
		{
			status = eap_status_allocation_error;
		}

		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: Could not create EAP type interface instance. error=%d, status=%d=%s\n"),
			error,
			status,
			eap_status_string_c::get_status_string(status)));

		if  (eapArrayIndex == KErrNotFound)
		{
			// No need to call shutdown here because GetStackInterfaceL has done it.
			delete eapType;
		}
		// Note: even in error cases eap_core_c deletes eap_type
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
				EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(iTools, status);               
			}

			eap_type_value_e * tmpEAPType = new eap_type_value_e();
			if(tmpEAPType == NULL)
			{
				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: eap_am_stack_symbian_c::load_module() eap_type_value_e creation failed\n")));
				EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(iTools, eap_status_allocation_error);              
			}
        
			*tmpEAPType = type;
        
			status = m_eap_type_array.add_object(tmpEAPType, true);
        
			if (status != eap_status_ok)            
			{
				// Remove the eap type added just previously
				m_plugin_if_array.Remove(m_plugin_if_array.Count() - 1);
				delete eapType;
				status = eap_status_allocation_error;
				EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(iTools, status);               
			}
		} 
	}

	EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(iTools, status);
}

//--------------------------------------------------

void eap_am_stack_symbian_c::RunL()
{
    EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);   
    EAP_TRACE_DEBUG(
        iTools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("eap_am_stack_symbian_c::RunL(): iStatus.Int() = %d\n"),
        iStatus.Int()));

    if (iStatus.Int() != KErrNone)
    {
        EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
        return;
    }

    // Authentication cancelled.
    EAP_TRACE_ALWAYS(
        iTools,
        TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
        (EAPL("Authentication cancelled.\n")));

    // Reset index of current EAP-type.
    set_current_eap_index(0ul);

    EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT); 
}

//--------------------------------------------------

void eap_am_stack_symbian_c::read_configureL(
    const TDesC& aDbName,
    const TDesC& aTableName,
    eap_config_string field,
    const u32_t /*field_length*/,
    eap_variable_data_c * const data)
{   
    EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);
    
    EAP_TRACE_DEBUG(
        iTools, 
        TRACE_FLAGS_DEFAULT, 
        (EAPL("eap_am_stack_symbian_c::read_configureL(): %s, %d=%s, this = 0x%08x => 0x%08x\n"),
         (iIsClient == true) ? "client": "server",
		 m_selected_eapol_key_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_selected_eapol_key_authentication_type),
         this,
         dynamic_cast<abs_eap_base_timer_c *>(this)));
    
    EAP_TRACE_RETURN_STRING(iTools, "returns: eap_am_stack_symbian_c::read_configureL()");

	if (m_selected_eapol_key_authentication_type == eapol_key_authentication_type_WPS)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT, (EAPL("eap_am_stack_symbian_c::read_configureL(): WPS does not use CommDbIf anymore.\n")));
		User::Leave(KErrNotSupported);
	}

    // Open database
    RDbNamedDatabase db;

    User::LeaveIfError(db.Open(iSession, aDbName, KEapSecureUIDFormat));  
    
    CleanupClosePushL(db);

	const TUint BUFFER_SIZE = 128ul;

    // Create a buffer for the ascii strings - initialised with the argument
    HBufC8* asciibuf = HBufC8::NewLC(BUFFER_SIZE);
    TPtr8 asciiString = asciibuf->Des();
    asciiString.Copy(reinterpret_cast<const unsigned char *>(field));
        
    // Buffer for unicode parameter
    HBufC* unicodebuf = HBufC::NewLC(BUFFER_SIZE);
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
		const TDbColNo FIRST_COLUMN = 1ul;
        view.GetL();        
        switch (view.ColType(FIRST_COLUMN))
        {
        case EDbColText:                
            {
                unicodeString = view.ColDes(FIRST_COLUMN);
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
            }
            break;
        case EDbColUint32:
            {
                TUint value;
                value = view.ColUint32(FIRST_COLUMN);
                status = data->set_copy_of_buffer((const unsigned char *) &value, sizeof(value));
                if (status != eap_status_ok)
                {
                    User::Leave(KErrNoMemory);
                }
            }
            break;
        default:
            EAP_TRACE_DEBUG(
                iTools,
                TRACE_FLAGS_DEFAULT,
                (EAPL("read_configureL: Unexpected column type.\n")));
            User::Panic(_L("EAPOL"), 1);            
        }
    } 
    else 
    {
        // Could not find parameter
        EAP_TRACE_DEBUG(
            iTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("read_configureL: Could not find configuration parameter.\n")));
        User::Leave(KErrNotFound);
    }       
    
    // Close database
    CleanupStack::PopAndDestroy(&view);
    CleanupStack::PopAndDestroy(buf);
    CleanupStack::PopAndDestroy(unicodebuf);
    CleanupStack::PopAndDestroy(asciibuf);
    CleanupStack::PopAndDestroy(&db);


    EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

//
void eap_am_stack_symbian_c::DoCancel()
{   
    EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);

    EAP_TRACE_DEBUG(
        iTools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("eap_am_stack_symbian_c::DoCancel()\n")));

    EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT); 
}

//----------------------------------------------------------------------------

TInt eap_am_stack_symbian_c::RunError(TInt aError)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_stack_symbian_c::RunError(): aError=%d, this=0x%08x\n"),
		aError,
		this));

	return aError;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_stack_symbian_c::save_simple_config_session(
    const simple_config_state_e state,
    EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
    const eap_variable_data_c * const new_password,
    const simple_config_Device_Password_ID_e Device_Password_ID,
    const simple_config_payloads_c * const other_configuration)
{
    EAP_TRACE_DEBUG(
        iTools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("%s: eap_am_stack_symbian_c::save_simple_config_session()\n"),
        (iIsClient == true ? "client": "server")));

    eap_status_e status(eap_status_ok);

    status = iConfigurationIf->save_simple_config_session(
        state,
        credential_array,
        new_password,
        Device_Password_ID,
        other_configuration);

    EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
    return EAP_STATUS_RETURN(iTools, status);
}

//--------------------------------------------------

//
void eap_am_stack_symbian_c::ReadEAPSettingsL()
{
	EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_stack_symbian_c::ReadEAPSettingsL(): %s, %d=%s, this = 0x%08x => 0x%08x\n"),
		 (iIsClient == true) ? "client": "server",
		 m_selected_eapol_key_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_selected_eapol_key_authentication_type),
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

    EAP_TRACE_RETURN_STRING(iTools, "returns: eap_am_stack_symbian_c::ReadEAPSettingsL()");

	eap_status_e status(eap_status_ok);

	if (m_selected_eapol_key_authentication_type == eapol_key_authentication_type_WPS
		|| iIndex == 0)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT, (EAPL("eap_am_stack_symbian_c::ReadEAPSettingsL(): WPS does not use CommDbIf anymore.\n")));
		return;
	}

	status = reset_eap_plugins();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
		User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, status)));
	}

	if (iIndexType == ELan
		|| iIndexType == EVpn)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_stack_symbian_c::ReadEAPSettingsL(): Beginning to read IAP settings - Type: %d, Index: %d.\n"), iIndexType, iIndex));


		{
			{
				eap_am_general_settings_symbian_c * const general_setting = new eap_am_general_settings_symbian_c(iTools);

				if (general_setting == 0)
				{
					User::Leave(KErrNoMemory);
				}
				if (general_setting->get_is_valid() == false)
				{
					general_setting->shutdown();
					delete general_setting;
					User::Leave(KErrNoMemory);
				}

				status = general_setting->configure();
				if (status != eap_status_ok)
				{
					general_setting->shutdown();
					delete general_setting;
					User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, status)));
				}

				status = general_setting->read_eap_methods_synchronously(
					iIndexType,
					iIndex,
					&iEnabledEapMethodsArray,
					&iDisabledEapMethodsArray);

				general_setting->shutdown();
				delete general_setting;
			}

			if (status != eap_status_ok)
			{
				User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, status)));
			}

			// Trace enabled.
			for (TInt ind = 0; ind < iEnabledEapMethodsArray.get_object_count(); ++ind)
			{	
				const eap_type_value_e * const allowed_eap_method = iEnabledEapMethodsArray.get_object(ind);

				if (allowed_eap_method != 0
					&& allowed_eap_method->get_is_valid() == true)
				{
					EAP_TRACE_DEBUG(
						iTools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_am_stack_symbian_c::ReadEAPSettingsL(): Enabled expanded EAP type at index=%d, EAP-type=0xfe%06x%08x\n"),
						 ind,
						 allowed_eap_method->get_vendor_id(),
						 allowed_eap_method->get_vendor_type()));
				}
			} // for()

			// Trace disabled.
			for (TInt ind = 0; ind < iDisabledEapMethodsArray.get_object_count(); ++ind)
			{	
				const eap_type_value_e * const allowed_eap_method = iDisabledEapMethodsArray.get_object(ind);

				if (allowed_eap_method != 0
					&& allowed_eap_method->get_is_valid() == true)
				{
					EAP_TRACE_DEBUG(
						iTools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_am_stack_symbian_c::ReadEAPSettingsL(): Disabled expanded EAP type at index=%d, EAP-type=0xfe%06x%08x\n"),
						 ind,
						 allowed_eap_method->get_vendor_id(),
						 allowed_eap_method->get_vendor_type()));
				}
			} // for()
		}


	} 
	else
	{
		// Unsupported bearer.

		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: eap_am_stack_symbian_c::ReadEAPSettingsL() - LEAVE - unsupported bearer\n")));

		User::Leave(KErrNotSupported);
	}

	EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void eap_am_stack_symbian_c::SetToTopPriorityL(const eap_type_value_e /* aEapType */)
{
	EAP_TRACE_BEGIN(iTools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_stack_symbian_c::SetToTopPriorityL() - for EXP EAP types, %d=%s\n"),
		 m_selected_eapol_key_authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(m_selected_eapol_key_authentication_type)));

    EAP_TRACE_RETURN_STRING(iTools, "returns: eap_am_stack_symbian_c::SetToTopPriorityL()");

	if (m_selected_eapol_key_authentication_type == eapol_key_authentication_type_WPS)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT, (EAPL("eap_am_stack_symbian_c::SetToTopPriorityL(): WPS does not use CommDbIf anymore.\n")));
		return;
	}

	if (iIndexType == ELan
		|| iIndexType == EVpn)
	{



	} 
	else
	{
		// Unsupported bearer.

		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: eap_am_stack_symbian_c::SetToTopPriorityL() - LEAVE - unsupported bearer\n")));
		
		User::Leave(KErrNotSupported);
	}
		
	EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_stack_symbian_c::set_eap_database_reference_values(
                const eap_variable_data_c * const reference)
{
    eap_status_e status(eap_status_ok);

	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_stack_symbian_c::set_eap_database_reference_values(): %s, this = 0x%08x => 0x%08x\n"),
		 (iIsClient == true) ? "client": "server",
		 this,
		 dynamic_cast<abs_eap_base_timer_c *>(this)));

    EAP_TRACE_RETURN_STRING(iTools, "returns: eap_am_stack_symbian_c::set_eap_database_reference_values()");

	const eapol_wlan_database_reference_values_s * const database_reference_values
		= reinterpret_cast<eapol_wlan_database_reference_values_s *>(
		reference->get_data(sizeof(eapol_wlan_database_reference_values_s)));
	if (database_reference_values == 0)
	{
		EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(iTools, eap_status_allocation_error);
	}

	iIndexType = static_cast<TIndexType>(database_reference_values->m_database_index_type);
	iIndex = database_reference_values->m_database_index;

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_stack_symbian_c::set_eap_database_reference_values(): iIndexType=%d, iIndex=%d.\n"),
		 iIndexType,
		 iIndex));

    // - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    return EAP_STATUS_RETURN(iTools, status);
}

//--------------------------------------------------

TInt eap_am_stack_symbian_c::get_current_eap_index()
{
	return iCurrentEapIndex;
}

//--------------------------------------------------

void eap_am_stack_symbian_c::set_current_eap_index(const TInt ind)
{
	iCurrentEapIndex = ind;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_stack_symbian_c::get_802_11_authentication_mode(
	const eap_am_network_id_c * const receive_network_id,
	const eapol_key_authentication_type_e authentication_type)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eap_am_stack_symbian_c::get_802_11_authentication_mode(): %d=%s\n"),
		("client"),
		 authentication_type,
		 eapol_key_state_string_c::get_eapol_key_authentication_type_string(authentication_type)));

    EAP_TRACE_RETURN_STRING(iTools, "returns: eap_am_stack_symbian_c::get_802_11_authentication_mode()");

	eap_status_e status(eap_status_ok);
	eap_expanded_type_c expandedEAPType(eap_type_none);
	u32_t ind_type = 0ul;

	m_selected_eapol_key_authentication_type = authentication_type;

    // - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = reset_eap_configuration();
    if (status != eap_status_ok)
    {
        EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
        return EAP_STATUS_RETURN(iTools, status);
    }

    // - - - - - - - - - - - - - - - - - - - - - - - - - - - -


	for (ind_type = 0; ind_type < iEnabledEapMethodsArray.get_object_count(); ++ind_type)
	{	
		const eap_type_value_e * const allowed_eap_method = iEnabledEapMethodsArray.get_object(ind_type);

		if (allowed_eap_method != 0
			&& allowed_eap_method->get_is_valid() == true)
		{
			EAP_TRACE_DEBUG(
				iTools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_am_stack_symbian_c::get_802_11_authentication_mode(): Enabled expanded EAP type at index=%d, EAP-type=0xfe%06x%08x\n"),
				 ind_type,
				 allowed_eap_method->get_vendor_id(),
				 allowed_eap_method->get_vendor_type()));

			if (*allowed_eap_method != eap_type_none)
			{
				expandedEAPType = *allowed_eap_method;
				break;
			}
		}
	} // for()


	if (m_selected_eapol_key_authentication_type == eapol_key_authentication_type_WPS)
	{
		expandedEAPType = eap_expanded_type_simple_config.get_type();
	}
	else if (ind_type >= iEnabledEapMethodsArray.get_object_count())
	{
		// No enabled EAP types.
		EAP_TRACE_ALWAYS(
			iTools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: No enabled EAP types.\n")));
		EAP_TRACE_ALWAYS(
			iTools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: Indication sent to WLM: eap_status_failed_completely.\n")));

		status = iPartner->complete_get_802_11_authentication_mode(
			eap_status_illegal_eap_type,
			receive_network_id,
			eapol_key_802_11_authentication_mode_none);

		EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);	
		return EAP_STATUS_RETURN(iTools, status);
	}	

	eapol_key_802_11_authentication_mode_e a802_11_authentication_mode(eapol_key_802_11_authentication_mode_none);

	if (expandedEAPType == eap_type_leap)
	{
		if (authentication_type == eapol_key_authentication_type_dynamic_WEP)
		{
			// LEAP uses it's own 802.11 authentication mode when 802.1X (dynamic WEP) is used.
			a802_11_authentication_mode = eapol_key_802_11_authentication_mode_leap;

			EAP_TRACE_ALWAYS(
				iTools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("start_authentication(): Trying auth mode LEAP (802.1x mode).\n")));
		}
		else
		{
			// If security mode is WPA or RSNA then even LEAP uses open authentication!
			a802_11_authentication_mode = eapol_key_802_11_authentication_mode_open;

			EAP_TRACE_ALWAYS(
				iTools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("start_authentication(): Trying auth mode OPEN (LEAP in WPA mode).\n")));
		}

	}
	else
	{
		a802_11_authentication_mode = eapol_key_802_11_authentication_mode_open;

		EAP_TRACE_ALWAYS(
			iTools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("start_authentication(): Trying auth mode OPEN.\n")));
	}

	status = iPartner->complete_get_802_11_authentication_mode(
		status,
		receive_network_id,
		a802_11_authentication_mode);

	EAP_TRACE_END(iTools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(iTools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_stack_c * new_eap_am_stack_c(class abs_eap_am_tools_c * tools, bool is_client_when_true)
{
    eap_am_stack_symbian_c * am_stack = new eap_am_stack_symbian_c(tools, is_client_when_true);

	eap_automatic_variable_c<eap_am_stack_c> automatic_am_stack(
		tools,
		am_stack);

	if (am_stack == 0
		|| am_stack->get_is_valid() == false)
	{
		// ERROR.
		if (am_stack != 0)
		{
			EAP_TRACE_DEBUG(
				tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("calls: new_eap_am_stack_c(): am_stack->shutdown(): %s.\n"),
				(is_client_when_true == true) ? "client": "server"));

			am_stack->shutdown();
		}
		return 0;
	}

	automatic_am_stack.do_not_free_variable();

    return am_stack;
}

//--------------------------------------------------
// end

