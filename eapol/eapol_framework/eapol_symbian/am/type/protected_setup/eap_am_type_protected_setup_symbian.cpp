/*
* Copyright (c) 2007 Nokia Corporation and/or its subsidiary(-ies).
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
* %version: 18.1.4.1.13 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 175 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

// INCLUDE FILES

#include "eap_am_type_protected_setup_symbian.h"

#include "eap_am_tools.h"
#include "eap_state_notification.h"
#include "eap_config.h"

#include "eap_type_simple_config_types.h"
#include "eap_tlv_message_data.h"
#include "abs_simple_config_am_services.h"
#include "simple_config_credential.h"
#include "abs_eap_configuration_if.h"
#include "eap_network_id_selector.h"

#include "EapTraceSymbian.h"
#include <mmtsy_names.h>

static const char EAP_AM_TYPE_SIMPLE_CONFIG_MEMORY_STORE_KEY[] = "eap_am_type_simple_config_simulator_c credential_store";

// ================= MEMBER FUNCTIONS =======================


// 
EAP_FUNC_EXPORT CEapAmProtectedSetupSymbian::CEapAmProtectedSetupSymbian(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	const TIndexType /* aIndexType */,
	const TInt aIndex,
	const eap_type_value_e /* aTunnelingType */,
	const eap_type_value_e eap_type,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id,
	abs_eap_configuration_if_c * const configuration_if)
: m_partner(partner)
, m_index(aIndex)
, m_am_tools(tools)
, m_am_partner(0)
, m_simple_config_am_partner(0)
, m_configuration_if(configuration_if)
, m_device_parameters_valid(false)
, m_network_and_device_parameters(tools)
, m_UUID_E(tools)
, m_Device_Password_ID(simple_config_Device_Password_ID_Default_PIN)
, m_receive_network_id(tools)
, m_eap_identifier(0)
, m_eap_type(eap_type)
, m_simple_config_state(simple_config_state_none)
, m_is_valid(false)
, m_is_client(is_client_when_true)
, m_shutdown_was_called(false)
, m_manual_username(tools)
, m_manual_realm(tools)
, m_use_manual_username(false)
, m_use_manual_realm(false)
, m_configured(false)
, m_prot_setup_if(0)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: function: CEapAmProtectedSetupSymbian(): this = 0x%08x\n"),
		(m_is_client == true ? "client": "server"),
		this));

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		// No need to delete anything here because it is done in destructor.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	eap_status_e status = m_receive_network_id.set_copy_of_network_id(
		receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void CEapAmProtectedSetupSymbian::ConstructL()
{
	if (m_is_client == true)
	{
		m_prot_setup_if = CEapProtectedSetupInterface::NewL(m_am_tools, this);
		if(m_prot_setup_if == NULL)
		{
			EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: EAP-WSC No interface to MMETEL\n")));
			User::Leave(KErrNoMemory);
		}
	} 
	else
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: EAP-WSC server does not work at the moment\n")));
		User::Leave(KErrNotSupported);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT CEapAmProtectedSetupSymbian* CEapAmProtectedSetupSymbian::NewL(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,	
	const eap_type_value_e eap_type,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id,
	abs_eap_configuration_if_c * const configuration_if)
{
	CEapAmProtectedSetupSymbian* self = new (ELeave) CEapAmProtectedSetupSymbian(
		tools,
		partner,
		aIndexType, 
		aIndex, 
		aTunnelingType,		
		eap_type,
		is_client_when_true,
		receive_network_id,
		configuration_if);
		
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

// 
EAP_FUNC_EXPORT CEapAmProtectedSetupSymbian::~CEapAmProtectedSetupSymbian()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: function: ~CEapAmProtectedSetupSymbian(): this = 0x%08x\n"),
		(m_is_client == true ? "client": "server"),
		this));

	EAP_ASSERT(m_shutdown_was_called == true);

	if (m_is_client == true)
	{
		delete m_prot_setup_if;
	}	

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

abs_simple_config_am_services_c * CEapAmProtectedSetupSymbian::get_simple_config_am_partner()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_ASSERT_ALWAYS(m_simple_config_am_partner != 0);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_simple_config_am_partner;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void CEapAmProtectedSetupSymbian::set_simple_config_am_partner(abs_simple_config_am_services_c * const simple_config_am_partner)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_simple_config_am_partner = simple_config_am_partner;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void CEapAmProtectedSetupSymbian::set_am_partner(abs_eap_am_type_simple_config_c * const partner)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_am_partner = partner;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::configure()
{

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: function: CEapAmProtectedSetupSymbian::configure()\n"),
		 (m_is_client == true ? "client": "server")));

	if (m_configured == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: %s: function: CEapAmProtectedSetupSymbian::configure(): Already configured.\n"),
			 (m_is_client == true ? "client": "server")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c use_manual_username(m_am_tools);

		eap_status_e status = type_configure_read(
			cf_str_EAP_SIMPLE_CONFIG_use_manual_username.get_field(),
			&use_manual_username);
		if (status == eap_status_ok
			&& use_manual_username.get_is_valid_data() == true)
		{
			u32_t *use_manual_username_flag = reinterpret_cast<u32_t *>(
				use_manual_username.get_data(sizeof(u32_t)));
			if (use_manual_username_flag != 0
				&& *use_manual_username_flag != 0)
			{
				m_use_manual_username = true;
			}
		}
	}

	//----------------------------------------------------------

	if (m_use_manual_username == true)
	{
		eap_status_e status = type_configure_read(
			cf_str_EAP_SIMPLE_CONFIG_manual_username.get_field(),
			&m_manual_username);
		if (status == eap_status_ok
			&& m_manual_username.get_is_valid_data() == true)
		{
			// This is optional value.
		}
		else
		{
			// No username defined.
			m_use_manual_username = false;
		}
	}

	//----------------------------------------------------------

	// create UUID using create_uuid_v5_from_mac_address, mac address from receive_nw_id.
	// Copy the UUID to m_UUID_E
	{	
		eap_status_e status = m_am_tools->create_uuid_v5_from_mac_address(
			m_receive_network_id.get_destination(), 
			m_receive_network_id.get_destination_length(),
			&m_UUID_E);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: EAP_type_SIMPLE_CONFIG: function: configure(): cannot get UUID-E from MAC address\n")));
		}
		else
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("SIMPLE_CONFIG: UUID-E from MAC address"),
				m_UUID_E.get_data(),
				m_UUID_E.get_data_length()));			
		}
	
	}

	m_configured = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_device_parameters_valid = false;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: function: CEapAmProtectedSetupSymbian::shutdown(): ")
		 EAPL("this = 0x%08x\n"),
		(m_is_client == true ? "client": "server"),
		this));

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	
	m_shutdown_was_called = true;

	{
		eap_variable_data_c key(m_am_tools);

		eap_status_e status = key.set_copy_of_buffer(
			EAP_AM_TYPE_SIMPLE_CONFIG_MEMORY_STORE_KEY,
			sizeof(EAP_AM_TYPE_SIMPLE_CONFIG_MEMORY_STORE_KEY));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = key.add_data(&m_is_client, sizeof(m_is_client));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = key.add_data(&m_eap_type, sizeof(m_eap_type));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		(void) m_am_tools->memory_store_remove_data(&key);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EAP_type_SIMPLE_CONFIG: CEapAmProtectedSetupSymbian::shutdown():")
			 EAPL("credentials removed from eapol\n")));
		
		eap_tlv_message_data_c tlv_data(m_am_tools);


		status = m_am_tools->memory_store_add_data(
			&key,
			&tlv_data,
			eap_type_default_credential_timeout);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAP_type_SIMPLE_CONFIG: function: shutdown(): cannot store credentials\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}

	reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

void CEapAmProtectedSetupSymbian::send_error_notification(const eap_status_e error)
{
	{
		eap_general_state_variable_e general_state_variable(eap_general_state_authentication_error);
	
		if (error == eap_status_user_cancel_authentication)
		{
			general_state_variable = eap_general_state_authentication_cancelled;
		}
		
		// Notifies the lower level of an authentication error.
		eap_state_notification_c notification(
			m_am_tools,
			&m_receive_network_id,
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_general,
			m_eap_type,
			eap_state_none,
			general_state_variable,
			0,
			false);

		notification.set_authentication_error(error);

		m_partner->state_notification(&notification);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::authentication_finished(
	const bool true_when_successfull,
	const bool true_when_session_resumed)
{
	EAP_UNREFERENCED_PARAMETER(true_when_successfull);  // for release
	EAP_UNREFERENCED_PARAMETER(true_when_session_resumed); // for release

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: function: authentication_finished()\n"),
		(m_is_client == true ? "client": "server")));

	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::query_eap_identity(
	const eap_am_network_id_c * const /* receive_network_id */,
	const u8_t eap_identifier,
	bool * const /* use_manual_username */,
	eap_variable_data_c * const manual_username,
	bool *const /* use_manual_realm */,
	eap_variable_data_c * const /* manual_realm */
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: function: query_eap_identity()\n"),
		 (m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_process_general_error);

	if (m_use_manual_username == true
		&& m_manual_username.get_is_valid_data() == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: %s: function: query_eap_identity(): manual username\n"),
			 (m_is_client == true ? "client": "server")));

		status = manual_username->set_copy_of_buffer(&m_manual_username);
	}

	m_eap_identifier = eap_identifier;
	
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: %s: direct_complete_function: complete_eap_identity_query()\n"),
			(m_is_client == true ? "client": "server")));

		status = get_am_partner()->complete_eap_identity_query(
			&m_receive_network_id,
			m_eap_identifier,
			status,
			m_use_manual_username,
			&m_manual_username,
			m_use_manual_realm,
			&m_manual_realm);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else //if (status == eap_status_ok)
		{
			status = eap_status_completed_request;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::cancel_identity_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: function: cancel_identity_query()\n"),
		 (m_is_client == true ? "client": "server")));

	if (m_is_client == true)
	{
		m_prot_setup_if->Cancel();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void CEapAmProtectedSetupSymbian::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool CEapAmProtectedSetupSymbian::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::type_configure_read(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
		// Here configuration data must be read from type spesific database (CommsDat).

		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_ASSERT(data != NULL);
		
		// Trap must be set here because the OS independent portion of EAP protected setup
		// that calls this function does not know anything about Symbian.
		
		eap_status_e status(eap_status_ok);

		if (cf_str_EAP_SIMPLE_CONFIG_device_password.get_field()->compare(
			m_am_tools,
			field) == true)
		{
			// We have to get the device password here. It is nothing but the PIN code in PIN based protected setup.

			status = read_memory_store(
				eap_type_protected_setup_stored_preshared_key,														
				data);
			
			m_am_tools->trace_configuration(
				status,
				field,
				data);				
			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


	// Read is routed to partner object.
	status = m_partner->read_configure(
			field,
			data);

	m_am_tools->trace_configuration(
		status,
		field,
		data);

	return status;
}

//--------------------------------------------------

//
eap_status_e CEapAmProtectedSetupSymbian::read_memory_store(
	const eap_type_protected_setup_stored_e data_type,														
	eap_variable_data_c * const data)
{
	// Read data from memory store.

	eap_variable_data_c memory_store_key(m_am_tools);

	eap_status_e status = memory_store_key.set_copy_of_buffer(
		EAP_WPS_CONFIGURATION_MEMORY_STORE_KEY,
		sizeof(EAP_WPS_CONFIGURATION_MEMORY_STORE_KEY));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = memory_store_key.add_data(
		&m_is_client,
		sizeof(m_is_client));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_network_id_selector_c state_selector(
		m_am_tools,
		&m_receive_network_id);

	status = memory_store_key.add_data(
		&state_selector);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_tlv_message_data_c tlv_data(m_am_tools);

	status = m_am_tools->memory_store_get_data(
		&memory_store_key,
		&tlv_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("simple_config_record_c::complete_query_network_and_device_parameters(): cannot get WPS credentials\n")));
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("simple_config_record_c::complete_query_network_and_device_parameters(): WPS credentials found\n")));

		// Parse read data.
		eap_array_c<eap_tlv_header_c> tlv_blocks(m_am_tools);
			
		status = tlv_data.parse_message_data(&tlv_blocks);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		for (u32_t ind = 0ul; ind < tlv_blocks.get_object_count(); ind++)
		{
			eap_tlv_header_c * const tlv = tlv_blocks.get_object(ind);
			if (tlv != 0)
			{
				if (tlv->get_type() == data_type)
				{
					status = data->set_copy_of_buffer(
						tlv->get_value(tlv->get_value_length()),
						tlv->get_value_length());
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
		} // for()

		if (data->get_is_valid_data() == false)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_ERROR,
				(EAPL("simple_config_record_c::complete_query_network_and_device_parameters(): cannot get data %d\n"),
				data_type));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if 0

//
void CEapAmProtectedSetupSymbian::read_device_passwordL(
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Get the things from commsdat here.

#if 1

	// Read PIN from memory store.

	eap_status_e status = read_memory_store(
		eap_type_protected_setup_stored_preshared_key,														
		data);

#elif 0

	{
		eap_variable_data_c memory_store_key(m_am_tools);

		eap_status_e status = memory_store_key.set_copy_of_buffer(
			EAP_WPS_CONFIGURATION_MEMORY_STORE_KEY,
			sizeof(EAP_WPS_CONFIGURATION_MEMORY_STORE_KEY));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return;
		}

		status = memory_store_key.add_data(
			&m_is_client,
			sizeof(m_is_client));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return;
		}

		eap_network_id_selector_c state_selector(
			m_am_tools,
			&m_receive_network_id);

		status = memory_store_key.add_data(
			&state_selector);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return;
		}

		eap_tlv_message_data_c tlv_data(m_am_tools);

		status = m_am_tools->memory_store_get_data(
			&memory_store_key,
			&tlv_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("simple_config_record_c::complete_query_network_and_device_parameters(): cannot get WPS credentials\n")));
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("simple_config_record_c::complete_query_network_and_device_parameters(): WPS credentials found\n")));

			// Parse read data.
			eap_array_c<eap_tlv_header_c> tlv_blocks(m_am_tools);
				
			status = tlv_data.parse_message_data(&tlv_blocks);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				(void) EAP_STATUS_RETURN(m_am_tools, status);
				return;
			}

			for (u32_t ind = 0ul; ind < tlv_blocks.get_object_count(); ind++)
			{
				eap_tlv_header_c * const tlv = tlv_blocks.get_object(ind);
				if (tlv != 0)
				{
					if (tlv->get_type() == eap_type_protected_setup_stored_preshared_key)
					{
						status = data->set_copy_of_buffer(
							tlv->get_value(tlv->get_value_length()),
							tlv->get_value_length());
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							(void) EAP_STATUS_RETURN(m_am_tools, status);
							return;
						}
					}
					else if (tlv->get_type() == eap_type_protected_setup_stored_ssid)
					{
						status = m_SSID.set_copy_of_buffer(
							tlv->get_value(tlv->get_value_length()),
							tlv->get_value_length());
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							(void) EAP_STATUS_RETURN(m_am_tools, status);
							return;
						}
					}
				}
			} // for()

			if (data->get_is_valid_data() == false)
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_ERROR,
					(EAPL("simple_config_record_c::complete_query_network_and_device_parameters(): cannot get WPS PIN\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				(void) EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
				return;
			}
		}


		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG m_device_password"),
			 m_device_password.get_data(),
			 m_device_password.get_data_length()));

		if (m_device_password.get_data_length() == SIMPLE_CONFIG_PBC_DEVICE_PASSWORD_PIN_SIZE
			&& m_am_tools->memcmp(m_device_password.get_data(), SIMPLE_CONFIG_PBC_DEVICE_PASSWORD_PIN, SIMPLE_CONFIG_PBC_DEVICE_PASSWORD_PIN_SIZE) == 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapAmProtectedSetupSymbian::read_device_passwordL(): WPS push button\n")));

			m_Device_Password_ID = simple_config_Device_Password_ID_PushButton;
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapAmProtectedSetupSymbian::read_device_passwordL(): WPS PIN\n")));

			m_Device_Password_ID = simple_config_Device_Password_ID_Default_PIN;
		}
	}

#else

	// We need PSK (PIN code for protected setup) from the CommsDat.
	// CommDbIf is used to get the PSK.

	CWLanSettings* wlan_settings = new(ELeave) CWLanSettings;
	CleanupStack::PushL(wlan_settings);
	SWLANSettings wlanSettings;
	TInt error(KErrNone);
	
	// Connect to CommsDat using CommDbIf
	error = wlan_settings->Connect();	
	if (error != KErrNone)
	{
		// Could not connect to CommsDat	
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT, (
			EAPL("ERROR: CEapAmProtectedSetupSymbian::read_device_passwordL() Connecting to CommsDat failed!\n")));
				
		User::Leave(KErrCouldNotConnect);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT, (
		EAPL("CEapAmProtectedSetupSymbian::read_device_passwordL() Connected to CommDbIf.\n")));

	error = wlan_settings->GetWlanSettingsForService(m_index, wlanSettings);
	if ( error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT, (
			EAPL("ERROR: CEapAmProtectedSetupSymbian::read_device_passwordL() GetWlanSettingsForService failed, error=%d\n"),
			error));
	
		wlan_settings->Disconnect();
		
		User::Leave(error);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Protected Setup: Got WLAN settings: wlanSettings.EnableWpaPsk=%d\n"),
		wlanSettings.EnableWpaPsk));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WPA-PSK or PIN"),
		wlanSettings.WPAPreSharedKey.Ptr(),
		wlanSettings.WPAPreSharedKey.Size()));	
	
	if(wlanSettings.WPAPreSharedKey.Size() != 0)
	{
		// Copy the PSK (PIN for us here) to the data
		eap_status_e status = data->set_copy_of_buffer(
			wlanSettings.WPAPreSharedKey.Ptr(),
			wlanSettings.WPAPreSharedKey.Size());
		
		if (status != eap_status_ok)
		{
			wlan_settings->Disconnect();
			
			User::Leave(KErrNoMemory);
		}
	}
	else	
	{
		// NO PIN -> means this is for the PUSH-BUTTON.
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT, (
			EAPL("WARNING: ############ NO PIN (WPA-PSK) FOR PROTECTED SETUP -> PUSH-BUTTON ############\n")));
		
		m_Device_Password_ID = simple_config_Device_Password_ID_PushButton;
	
		// This ("00000000") is a temporary password. This is not used since we will try push-button.
		// Some value has to be set for this password so that that calling function doesn't return error.
		// If nothing is set for the password the calling function takes it as wrong password and 
		// stops the authentication.
		TBuf8<16> asciiString(_L8("00000000"));
		eap_status_e status = data->set_copy_of_buffer(asciiString.Ptr(), asciiString.Size());
		if (status != eap_status_ok)
		{
			wlan_settings->Disconnect();
			
			User::Leave(KErrNoMemory);
		}
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT, (
			EAPL("WARNING: ############ WE WILL TRY PUSH-BUTTON ############\n")));
	}

	wlan_settings->Disconnect();
	CleanupStack::PopAndDestroy(wlan_settings);

#endif

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

#endif

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::type_configure_write(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	// Here configuration data must be read from type spesific database.

	// NOTE: This is for simulation.
	// Write is routed to partner object.
	eap_status_e status = m_partner->write_configure(
			field,
			data);
	return status;
}

//--------------------------------------------------

abs_eap_am_type_simple_config_c * CEapAmProtectedSetupSymbian::get_am_partner()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_am_partner;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::query_network_and_device_parameters(
	const simple_config_state_e state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: CEapAmProtectedSetupSymbian::query_network_and_device_parameters()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status = eap_status_process_general_error;

	m_simple_config_state = state;
	
	// check if we already have done the query
	if( m_device_parameters_valid == true )
	{
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapAmProtectedSetupSymbian::query_network_and_device_parameters: Parameters exist, completing query immediately.")));

		// pass the parameters
		status = get_simple_config_am_partner()->complete_query_network_and_device_parameters(
			m_simple_config_state,
			&m_network_and_device_parameters,
			eap_status_ok);
								
		if (status == eap_status_ok || 
				status == eap_status_pending_request)
		{
			// we completed the request successfully
			status = eap_status_completed_request;
		}
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);		
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	m_network_and_device_parameters.reset();

	if (m_simple_config_state == simple_config_state_process_simple_config_start)
	{
		status = m_network_and_device_parameters.copy_attribute_data(
			simple_config_Attribute_Type_UUID_E,
			true,
			m_UUID_E.get_data(),
			m_UUID_E.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		 u16_t Authentication_Type(
			simple_config_Authentication_Type_Open
			| simple_config_Authentication_Type_WPAPSK
			| simple_config_Authentication_Type_Shared
			| simple_config_Authentication_Type_WPA2PSK);

		u16_t network_order_Authentication_Type(eap_htons(Authentication_Type));

		status = m_network_and_device_parameters.copy_attribute_data(
			simple_config_Attribute_Type_Authentication_Type_Flags,
			true,
			&network_order_Authentication_Type,
			sizeof(network_order_Authentication_Type));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		u16_t Encryption_Type(
			simple_config_Encryption_Type_None
			| simple_config_Encryption_Type_WEP
			| simple_config_Encryption_Type_TKIP
			| simple_config_Encryption_Type_AES);

		u16_t network_order_Encryption_Type(eap_htons(Encryption_Type));

		status = m_network_and_device_parameters.copy_attribute_data(
			simple_config_Attribute_Type_Encryption_Type_Flags,
			true,
			&network_order_Encryption_Type,
			sizeof(network_order_Encryption_Type));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	
	{
		// We support ESS only.
		simple_config_Connection_Type_e Connection_Type(simple_config_Connection_Type_ESS);

		u8_t network_order_Encryption_Type(static_cast<u8_t>(Connection_Type));

		status = m_network_and_device_parameters.copy_attribute_data(
			simple_config_Attribute_Type_Connection_Type_Flags,
			true,
			&network_order_Encryption_Type,
			sizeof(network_order_Encryption_Type));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		eap_variable_data_c device_password(m_am_tools);

		status = read_memory_store(
			eap_type_protected_setup_stored_preshared_key,														
			&device_password);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG device_password"),
			 device_password.get_data(),
			 device_password.get_data_length()));

		if (device_password.get_data_length() == SIMPLE_CONFIG_PBC_DEVICE_PASSWORD_PIN_SIZE
			&& m_am_tools->memcmp(device_password.get_data(), SIMPLE_CONFIG_PBC_DEVICE_PASSWORD_PIN, SIMPLE_CONFIG_PBC_DEVICE_PASSWORD_PIN_SIZE) == 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapAmProtectedSetupSymbian::read_device_passwordL(): WPS push button\n")));

			m_Device_Password_ID = simple_config_Device_Password_ID_PushButton;
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapAmProtectedSetupSymbian::read_device_passwordL(): WPS PIN\n")));

			m_Device_Password_ID = simple_config_Device_Password_ID_Default_PIN;
		}
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapAmProtectedSetupSymbian::query_network_and_device_parameters() m_Device_Password_ID=%d\n"),
		m_Device_Password_ID));

	{
		// This may be changed in future if more methods need to be supported.
		simple_config_Config_Methods_e Config_Methods(simple_config_Config_Methods_Display);

		// At the moment only PIN and PUSH-BUTTON. Default method is PIN.
		if(m_Device_Password_ID == simple_config_Device_Password_ID_PushButton)
		{
			Config_Methods = simple_config_Config_Methods_PushButton;	
		}

		u16_t network_order_Config_Methods(eap_htons(static_cast<u16_t>(Config_Methods)));

		status = m_network_and_device_parameters.copy_attribute_data(
			simple_config_Attribute_Type_Config_Methods,
			true,
			&network_order_Config_Methods,
			sizeof(network_order_Config_Methods));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		simple_config_State_e State(simple_config_State_Not_Configured);

		u8_t network_order_State(static_cast<u8_t>(State));

		status = m_network_and_device_parameters.copy_attribute_data(
			simple_config_Attribute_Type_Simple_Config_State,
			true,
			&network_order_State,
			sizeof(network_order_State));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		// See WPS spec for this.
		u8_t Primary_Device_Type[]
			= { 0x00, 0x0a,
				0x00, 0x50, 0xf2, 0x04,
				0x00, 0x02 };

		status = m_network_and_device_parameters.copy_attribute_data(
			simple_config_Attribute_Type_Primary_Device_Type,
			true,
			Primary_Device_Type,
			sizeof(Primary_Device_Type));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		// 2.4 GHz band support only.
		u8_t RF_Band(simple_config_RF_Bands_2_4_GHz);

		status = m_network_and_device_parameters.copy_attribute_data(
			simple_config_Attribute_Type_RF_Band,
			true,
			&RF_Band,
			sizeof(RF_Band));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		simple_config_Association_State_e Association_State(simple_config_Association_State_Not_Associated);

		u16_t network_order_Association_State(eap_htons(static_cast<u16_t>(Association_State)));

		status = m_network_and_device_parameters.copy_attribute_data(
			simple_config_Attribute_Type_Association_State,
			true,
			&network_order_Association_State,
			sizeof(network_order_Association_State));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		// This is for authentication based on PIN method or PUSH-BUTTON method.
		u16_t network_order_Device_Password_ID(eap_htons(static_cast<u16_t>(m_Device_Password_ID)));

		status = m_network_and_device_parameters.copy_attribute_data(
			simple_config_Attribute_Type_Device_Password_ID,
			true,
			&network_order_Device_Password_ID,
			sizeof(network_order_Device_Password_ID));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		// No need for anything specific here.
		u8_t OS_Version[]
			= { 0xf0, 0x00, 0x00, 0x01 };

		status = m_network_and_device_parameters.copy_attribute_data(
			simple_config_Attribute_Type_OS_Version,
			true,
			OS_Version,
			sizeof(OS_Version));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


	{
		eap_variable_data_c SSID(m_am_tools);

		status = read_memory_store(
			eap_type_protected_setup_stored_ssid,														
			&SSID);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_network_and_device_parameters.copy_attribute_data(
			simple_config_Attribute_Type_SSID,
			true,
			SSID.get_data(),
			SSID.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	
	// Query the device details from the MMETEL connection.
	TRAPD(error, m_prot_setup_if->QueryDeviceParametersL());	
	if (error != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(error);
		if (status == eap_status_process_general_error)
		{
			status = eap_status_credential_query_failed;
		}
		
		send_error_notification(status);
		
		// Query failed.
		get_simple_config_am_partner()->complete_query_network_and_device_parameters(
			m_simple_config_state,
			&m_network_and_device_parameters,
			status);		
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_pending_request); // Request is always pending here.
}

//--------------------------------------------------

// This is always synchronous call.
EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::save_simple_config_session(
	const simple_config_state_e state,
	EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
	const eap_variable_data_c * const new_password,
	const simple_config_Device_Password_ID_e Device_Password_ID,
	const simple_config_payloads_c * const other_configuration)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: save_simple_config_session()\n"),
		(m_is_client == true ? "client": "server")));

	for (u32_t ind = 0ul; ind < credential_array->get_object_count(); ind++)
	{
		simple_config_credential_c * const credential = credential_array->get_object(ind);

		if (credential != 0
			&& credential->get_is_valid() == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("SIMPLE_CONFIG: network_index=%d\n"),
				credential->get_network_index()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("SIMPLE_CONFIG: SSID"),
				credential->get_SSID()->get_data(),
				credential->get_SSID()->get_data_length()));

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("SIMPLE_CONFIG: Authentication_Type=%d\n"),
				credential->get_Authentication_Type()));

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("SIMPLE_CONFIG: Encryption_Type=%d\n"),
				credential->get_Encryption_Type()));

			for (u32_t ind = 0ul; ind < credential->get_network_keys()->get_object_count(); ++ind)
			{
				network_key_and_index_c * const key = credential->get_network_keys()->get_object(ind);
				if (key != 0)
				{

					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("SIMPLE_CONFIG: network_key_index=%d\n"),
						key->get_network_key_index()));

					EAP_TRACE_DATA_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("SIMPLE_CONFIG: Key"),
						key->get_network_key()->get_data(),
						key->get_network_key()->get_data_length()));
				}
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("SIMPLE_CONFIG: MAC_address"),
				credential->get_MAC_address()->get_data(),
				credential->get_MAC_address()->get_data_length()));
		}
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("SIMPLE_CONFIG: new_password"),
		new_password->get_data(),
		new_password->get_data_length()));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: Device_Password_ID=%d\n"),
		Device_Password_ID));

	eap_status_e status = m_configuration_if->save_simple_config_session(
		state,
		credential_array,
		new_password,
		Device_Password_ID,
		other_configuration);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::received_registrar_information(
	EAP_TEMPLATE_CONST eap_array_c<simple_config_payloads_c> * const M2D_payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: received_registrar_information()\n"),
		(m_is_client == true ? "client": "server")));

	eap_simple_config_trace_string_c debug_string;

	for (u32_t ind = 0ul; ind < M2D_payloads->get_object_count(); ind++)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("---------------------------------------------------------------\n")));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("M2D %d\n"),
			ind));

		simple_config_payloads_c * const payloads = M2D_payloads->get_object(ind);
		if (payloads == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		const u32_t attribute_count(payloads->get_attribute_count());
		u32_t attribute_index(0ul);

		while (attribute_index < attribute_count)
		{
			simple_config_variable_data_c * attribute = payloads->get_attribute(attribute_index);
			if (attribute == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("\n")));

			EAP_TRACE_DEBUG(
				m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
				(EAPL("%s (0x%08x): TLV type 0x%08x=%s, data length 0x%04x.\n"),
				"M2D", (attribute)->get_data((attribute)->get_data_length()),
				(attribute)->get_attribute_type(),
				debug_string.get_attribute_type_string((attribute)->get_attribute_type()),
				(attribute)->get_data_length()));

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,
				(EAPL("M2D"), (attribute)->get_data((attribute)->get_data_length()),
				(attribute)->get_data_length()));

			++attribute_index;
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("\n")));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::cancel_query_network_and_device_parameters()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: cancel_query_dh_parameters()\n"),
		(m_is_client == true ? "client": "server")));

	if (m_is_client == true)
	{
		m_prot_setup_if->Cancel();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::load_module(
		const eap_type_value_e eap_type,
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
		(EAPL("CEapAmProtectedSetupSymbian::load_module(0x%08x)\n"),
		 convert_eap_type_to_u32_t(eap_type)));

	eap_status_e status = m_partner->load_module(
		eap_type,
		tunneling_type,
		partner,
		eap_type_if,
		is_client_when_true,
		receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::check_is_valid_eap_type(const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapAmProtectedSetupSymbian::check_is_valid_eap_type(0x%08x)\n"),
		 convert_eap_type_to_u32_t(eap_type)));

	eap_status_e status = m_partner->check_is_valid_eap_type(
		eap_type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_partner->get_eap_type_list(eap_type_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::unload_module(const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapAmProtectedSetupSymbian::unload_module(0x%08x)\n"),
		convert_eap_type_to_u32_t(eap_type)));

	eap_status_e status = m_partner->unload_module(
		eap_type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e CEapAmProtectedSetupSymbian::complete_protected_setup_device_paramsL(
	const RMobilePhone::TMobilePhoneIdentityV1 &phone_identity,
	const eap_status_e completion_status )
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_process_general_error);
	
	if (completion_status != eap_status_ok)
	{
		// Query failed
		status = get_simple_config_am_partner()->complete_query_network_and_device_parameters(
			m_simple_config_state,
			&m_network_and_device_parameters,
			completion_status);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	if(phone_identity.iManufacturer.Size() == 0
		|| phone_identity.iModel.Size() == 0
		|| phone_identity.iRevision.Size() == 0
		|| phone_identity.iSerialNumber.Size() == 0 )
	{
		// Some identies are missing.
		status = get_simple_config_am_partner()->complete_query_network_and_device_parameters(
			m_simple_config_state,
			&m_network_and_device_parameters,
			eap_status_process_general_error);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;		
	}

	// Copy device details to m_network_and_device_parameters	
	
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		HBufC8* attribute_data = HBufC8::NewLC(phone_identity.iManufacturer.Size());
	
		TPtr8 attribute_data_Ptr = attribute_data->Des();
	
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
				("Attribute data to convert:",
						phone_identity.iManufacturer.Ptr(), 
						phone_identity.iManufacturer.Size()));
	
		ConvertUnicodeToAsciiL(phone_identity.iManufacturer, attribute_data_Ptr);

		status = m_network_and_device_parameters.copy_attribute_data(
				simple_config_Attribute_Type_Manufacturer,
				true,
				attribute_data_Ptr.Ptr(),
				attribute_data_Ptr.Size());

		CleanupStack::PopAndDestroy(attribute_data);
		
		if (status != eap_status_ok)
		{
			status = get_simple_config_am_partner()->complete_query_network_and_device_parameters(
				m_simple_config_state,
				&m_network_and_device_parameters,
				eap_status_process_general_error);
			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		HBufC8* attribute_data = HBufC8::NewLC(phone_identity.iModel.Size());
		
		TPtr8 attribute_data_Ptr = attribute_data->Des();
	
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
				("Attribute data to convert:",
						phone_identity.iModel.Ptr(), 
						phone_identity.iModel.Size()));
	
		ConvertUnicodeToAsciiL(phone_identity.iModel, attribute_data_Ptr);
	
		status = m_network_and_device_parameters.copy_attribute_data(
				simple_config_Attribute_Type_Model_Name,
				true,
				attribute_data_Ptr.Ptr(),
				attribute_data_Ptr.Size());
			
		if (status != eap_status_ok)
		{
			CleanupStack::PopAndDestroy(attribute_data);
			
			status = get_simple_config_am_partner()->complete_query_network_and_device_parameters(
				m_simple_config_state,
				&m_network_and_device_parameters,
				eap_status_process_general_error);
			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
			
		// Use model as the device name as well 
		// since there is nothing better for the purpose.
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapAmProtectedSetupSymbian::complete_protected_setup_device_paramsL: Uses model as device name.")));

		status = m_network_and_device_parameters.copy_attribute_data(
				simple_config_Attribute_Type_Device_Name,
				true,
				attribute_data_Ptr.Ptr(),
				attribute_data_Ptr.Size());
			
		CleanupStack::PopAndDestroy(attribute_data);

		if (status != eap_status_ok)
		{
			status = get_simple_config_am_partner()->complete_query_network_and_device_parameters(
				m_simple_config_state,
				&m_network_and_device_parameters,
				eap_status_process_general_error);
			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		HBufC8* attribute_data = HBufC8::NewLC(phone_identity.iRevision.Size());
		
		TPtr8 attribute_data_Ptr = attribute_data->Des();
	
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
				("Attribute data to convert:",
						phone_identity.iRevision.Ptr(), 
						phone_identity.iRevision.Size()));
	
		ConvertUnicodeToAsciiL(phone_identity.iRevision, attribute_data_Ptr);
	
		status = m_network_and_device_parameters.copy_attribute_data(
				simple_config_Attribute_Type_Model_Number,
				true,
				attribute_data_Ptr.Ptr(),
				attribute_data_Ptr.Size());
	
		CleanupStack::PopAndDestroy(attribute_data);

		if (status != eap_status_ok)
		{
			status = get_simple_config_am_partner()->complete_query_network_and_device_parameters(
				m_simple_config_state,
				&m_network_and_device_parameters,
				eap_status_process_general_error);
			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		HBufC8* attribute_data = HBufC8::NewLC(phone_identity.iSerialNumber.Size());
		
		TPtr8 attribute_data_Ptr = attribute_data->Des();
	
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
				("Attribute data to convert:",
						phone_identity.iSerialNumber.Ptr(), 
						phone_identity.iSerialNumber.Size()));
	
		ConvertUnicodeToAsciiL(phone_identity.iSerialNumber, attribute_data_Ptr);
	
		status = m_network_and_device_parameters.copy_attribute_data(
				simple_config_Attribute_Type_Serial_Number,
			true,
			attribute_data_Ptr.Ptr(),
			attribute_data_Ptr.Size());
	
		CleanupStack::PopAndDestroy(attribute_data);

		if (status != eap_status_ok)
		{
			status = get_simple_config_am_partner()->complete_query_network_and_device_parameters(
				m_simple_config_state,
				&m_network_and_device_parameters,
				eap_status_process_general_error);
			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}	
	
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Ok So far. Complete the request succesfully.
	
	status = get_simple_config_am_partner()->complete_query_network_and_device_parameters(
		m_simple_config_state,
	 &m_network_and_device_parameters,
		completion_status);
		
	if( status == eap_status_ok )
	{
		// save the state
		// no need to fetch the parameters again
		m_device_parameters_valid = true;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

void CEapAmProtectedSetupSymbian::ConvertUnicodeToAsciiL(const TDesC16& aFromUnicode, TDes8& aToAscii)
{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
			("CEapAmProtectedSetupSymbian::ConvertUnicodeToAsciiL:From TEXT",
			aFromUnicode.Ptr(), 
			aFromUnicode.Size()));	
		
		if(aFromUnicode.Length() <= 0)
		{
			EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapAmProtectedSetupSymbian::ConvertUnicodeToAsciiL: Return: NOTHING TO CONVERT")));
			
			return;
		}	
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapAmProtectedSetupSymbian::ConvertUnicodeToAsciiL, aFromUnicode.Length=%d, aFromUnicode.Size=%d"),
			aFromUnicode.Length(), aFromUnicode.Size()));	
		
		// Convert from Unicode to ascii.
		HBufC8* aFromUnicodeBuf8 = HBufC8::NewLC(aFromUnicode.Length()); // Half times size of source (or length) is enough here.
		TPtr8 aFromUnicodePtr8 = aFromUnicodeBuf8->Des();
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapAmProtectedSetupSymbian::ConvertUnicodeToAsciiL, aFromUnicodePtr8.Length=%d, aFromUnicodePtr8.Size=%d, aFromUnicodePtr8.MaxLength=%d, aFromUnicodePtr8.MaxSize=%d"),
			aFromUnicodePtr8.Length(), aFromUnicodePtr8.Size(), aFromUnicodePtr8.MaxLength(), aFromUnicodePtr8.MaxSize()));				
		
		aFromUnicodePtr8.Copy(aFromUnicode); // Unicode -> ascii.
		
		aToAscii = aFromUnicodePtr8;	

		CleanupStack::PopAndDestroy(aFromUnicodeBuf8); // Delete aFromUnicodeBuf8.	

		EAP_TRACE_DATA_DEBUG_SYMBIAN(
			("CEapAmProtectedSetupSymbian::ConvertUnicodeToAsciiL:To ASCII",
			aToAscii.Ptr(), 
			aToAscii.Size()));	
}

//--------------------------------------------------

// End of file.
