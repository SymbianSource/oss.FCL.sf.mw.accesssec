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
* %version: 69.1.7 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 601 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#if defined(USE_EAP_SIMPLE_CONFIG)

#include "eap_am_memory.h"
#include "eap_am_export.h"
#include "eap_am_tools.h"
#include "eap_tools.h"
#include "eap_crypto_api.h"
#include "abs_simple_config_base_record.h"
#include "simple_config_base_record.h"
#include "simple_config_record.h"
#include "simple_config_am_services.h"
#include "simple_config_types.h"
#include "simple_config_message.h"
#include "eap_automatic_variable.h"
#include "eap_state_notification.h"
#include "eap_type_simple_config_types.h"
#include "eap_header_string.h"
#include "abs_eap_am_mutex.h"
#include "simple_config_credential.h"
#include "eapol_key_types.h"
#include "eap_config.h"
#include "eap_network_id_selector.h"
#include "eap_tlv_message_data.h"

//--------------------------------------------------


EAP_FUNC_EXPORT simple_config_record_c::~simple_config_record_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("%s: function: simple_config_record_c::~simple_config_record_c(): this = 0x%08x, m_am_simple_config_services")
					 EAPL(" = 0x%08x (validity %d).\n"),
					 (m_is_client == true ? "client": "server"),
					 this,
					 m_am_simple_config_services,
					 m_am_simple_config_services->get_is_valid()));

	EAP_ASSERT(m_shutdown_was_called == true);

	completion_action_clenup();

	if (m_free_am_simple_config_services == true)
	{
		delete m_am_simple_config_services;
	}
	m_am_simple_config_services = 0;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

EAP_FUNC_EXPORT simple_config_record_c::simple_config_record_c(
	abs_eap_am_tools_c * const tools, ///< tools is pointer to the tools class. @see abs_eap_am_tools_c.
	simple_config_am_services_c * const am_simple_config_services, ///< This is pointer to adaptation module of SIMPLE_CONFIG.
	const bool free_am_simple_config_services,
	const bool is_client_when_true, ///< Indicates whether this is client (true) or server (false).
	const eap_am_network_id_c * const receive_network_id)
	: simple_config_base_record_c(tools /*, partner */)
	, m_am_tools(tools)
	, m_am_simple_config_services(am_simple_config_services)
	, m_free_am_simple_config_services(free_am_simple_config_services)
	, m_completion_queue(tools)
	, m_M2D_payloads(tools)
	, m_received_simple_config_message(tools, is_client_when_true)
	, m_received_payloads(tools)
	, m_previous_simple_config_message(tools, is_client_when_true)
	, m_new_simple_config_message(tools, is_client_when_true)
	, m_current_simple_config_message_type(simple_config_Message_Type_None)
	, m_enrollee_nonce(tools)
	, m_enrollee_mac(tools)
	, m_registrar_nonce(tools)
	, m_device_password(tools)
	, m_PSK1(tools)
	, m_PSK2(tools)
	, m_E_SNonce1(tools)
	, m_E_SNonce2(tools)
	, m_EHash1(tools)
	, m_EHash2(tools)
	, m_R_SNonce1(tools)
	, m_R_SNonce2(tools)
	, m_RHash1(tools)
	, m_RHash2(tools)
	, m_own_private_dhe_key(tools)
	, m_own_public_dhe_key(tools)
	, m_peer_public_dhe_key(tools)
	, m_shared_dh_key(tools)
	, m_dhe_prime(tools)
	, m_dhe_group_generator(tools)
	, m_kdk(tools)
	, m_auth_key(tools)
	, m_key_wrap_key(tools)
	, m_EMSK(tools)
	, m_SSID(tools)
	, m_signed_message_hash(tools)
	, m_NAI(tools)
	, m_NAI_realm(tools)
	, m_send_network_id(tools)
#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)
	, m_network_key(tools)
	, m_authentication_type(simple_config_Authentication_Type_None)
#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)
	, m_simple_config_state(simple_config_state_wait_simple_config_start)
	, m_handshake_error(eap_status_ok)
	, m_UUID_E(tools)
	, m_UUID_R(tools)
	, m_Rf_Bands(simple_config_RF_Bands_2_4_GHz)
	, m_MAC_address(tools)
	, m_local_Device_Password_ID(simple_config_Device_Password_ID_Default_PIN)
	, m_received_Device_Password_ID(simple_config_Device_Password_ID_Default_PIN)
	, m_new_password(tools)
	, m_new_Device_Password_ID(simple_config_Device_Password_ID_Default_PIN)
	, m_error_message_received_timeout(SIMPLE_CONFIG_RECORD_ERROR_MESSAGE_RECEIVED_TIMEOUT)
	, m_is_valid(false)
	, m_is_client(is_client_when_true)
	, m_allow_message_send(true)
	, m_already_in_completion_action_check(false)
	, m_pending_query_network_and_device_parameters(false)
	, m_simple_config_test_version(false)
	, m_key_material_generated(false)
	, m_force_simple_config_message_send(false)
	, m_shutdown_was_called(false)
	, m_M2D_received_timeout_active(false)
{
	if (m_am_tools == 0
		|| m_am_tools->get_is_valid() == false)
	{
		// No need to delete anything here because it is done in destructor.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: function: simple_config_record_c::simple_config_record_c(): ")
		 EAPL("this = 0x%08x\n"),
		(m_is_client == true ? "client": "server"),
		this));

	if (receive_network_id == 0
		|| receive_network_id->get_is_valid_data() == false)
	{
		// No need to delete anything here because it is done in destructor.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	if (m_am_simple_config_services == 0
		|| m_am_simple_config_services->get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_SIMPLE_CONFIG_ERROR,
						(EAPL("ERROR: %s: function: simple_config_record_c::simple_config_record_c() failed,")
						 EAPL(" m_am_simple_config_services = 0x%08x (validity %d) is invalid.\n"),
						 (m_is_client == true ? "client": "server"),
						 m_am_simple_config_services, (m_am_simple_config_services != 0) ? m_am_simple_config_services->get_is_valid(): false));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}
	m_am_simple_config_services->set_simple_config_am_partner(this);

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(
		m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());

	if (send_network_id.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	if (m_send_network_id.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	eap_status_e status = m_send_network_id.set_copy_of_network_id(&send_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	if (m_send_network_id.get_is_valid() == false
		|| m_received_simple_config_message.get_is_valid() == false
		|| m_received_payloads.get_is_valid() == false
		|| m_previous_simple_config_message.get_is_valid() == false
		|| m_new_simple_config_message.get_is_valid() == false
		|| m_enrollee_nonce.get_is_valid() == false
		|| m_enrollee_mac.get_is_valid() == false
		|| m_registrar_nonce.get_is_valid() == false
		|| m_device_password.get_is_valid() == false
		|| m_PSK1.get_is_valid() == false
		|| m_PSK2.get_is_valid() == false
		|| m_E_SNonce1.get_is_valid() == false
		|| m_E_SNonce2.get_is_valid() == false
		|| m_EHash1.get_is_valid() == false
		|| m_EHash2.get_is_valid() == false
		|| m_R_SNonce1.get_is_valid() == false
		|| m_R_SNonce2.get_is_valid() == false
		|| m_RHash1.get_is_valid() == false
		|| m_RHash2.get_is_valid() == false
		|| m_own_private_dhe_key.get_is_valid() == false
		|| m_own_public_dhe_key.get_is_valid() == false
		|| m_peer_public_dhe_key.get_is_valid() == false
		|| m_shared_dh_key.get_is_valid() == false
		|| m_dhe_prime.get_is_valid() == false
		|| m_dhe_group_generator.get_is_valid() == false
		|| m_kdk.get_is_valid() == false
		|| m_auth_key.get_is_valid() == false
		|| m_key_wrap_key.get_is_valid() == false
		|| m_EMSK.get_is_valid() == false
		|| m_SSID.get_is_valid() == false
		|| m_signed_message_hash.get_is_valid() == false
		|| m_NAI.get_is_valid() == false
		|| m_NAI_realm.get_is_valid() == false
		|| m_send_network_id.get_is_valid() == false
		|| m_UUID_E.get_is_valid() == false
		|| m_UUID_R.get_is_valid() == false
		|| m_MAC_address.get_is_valid() == false
		|| m_new_password.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)
	if (m_is_client == false)
	{
		set_state(simple_config_state_wait_M1);
	}
#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void simple_config_record_c::set_state(const simple_config_state_e state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_simple_config_trace_string_c state_string;
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: state_function: set_state() from %s to %s\n"),
		(m_is_client == true ? "client": "server"),
		state_string.get_state_string(m_simple_config_state),
		state_string.get_state_string(state)));

	if (m_simple_config_state != simple_config_state_failure)
	{
		m_simple_config_state = state;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT simple_config_state_e simple_config_record_c::get_state() const
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_simple_config_state;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool simple_config_record_c::verify_state(const simple_config_state_e state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_simple_config_trace_string_c state_string;

	if (m_simple_config_state == state)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: %s: state_function: verify_state(): current state %s == %s\n"),
			 (m_is_client == true ? "client": "server"),
			 state_string.get_state_string(m_simple_config_state),
			 state_string.get_state_string(state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return true;
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: SIMPLE_CONFIG: %s: state_function: verify_state(): current state %s != %s\n"),
			 (m_is_client == true ? "client": "server"),
			 state_string.get_state_string(m_simple_config_state),
			 state_string.get_state_string(state)));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return false;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT void simple_config_record_c::set_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: function: simple_config_record_c::configure(): ")
		 EAPL("this = 0x%08x\n"),
		(m_is_client == true ? "client": "server"),
		this));

	eap_status_e status = m_am_simple_config_services->configure();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (get_type_partner() == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_is_client == true)
	{
		// Creates Enrollee Nonce.
		status = generate_nonce(
			&m_enrollee_nonce,
			SIMPLE_CONFIG_ENROLLEE_NONCE_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		// Creates Registrar Nonce.
		status = generate_nonce(
			&m_registrar_nonce,
			SIMPLE_CONFIG_REGISTRAR_NONCE_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = generate_dhe_keys();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	//----------------------------------------------------------

	if (m_is_client == false)
	{
		status = get_type_partner()->read_configure(
			cf_str_EAP_SIMPLE_CONFIG_device_password.get_field(),
			&m_device_password);
		if (status != eap_status_ok
			|| m_device_password.get_is_valid_data() == false)
		{
			// This is mandatory value.
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: SIMPLE_CONFIG: %s: simple_config_record_c::configure(): Missing device password.\n"),
				 (m_is_client == true ? "client": "server")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_password);
		}

		(void) get_type_partner()->read_configure(
			cf_str_EAP_SIMPLE_CONFIG_server_device_password.get_field(),
			&m_device_password);
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c test_version(m_am_tools);

		if (test_version.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = get_type_partner()->read_configure(
			cf_str_EAP_SIMPLE_CONFIG_test_version.get_field(),
			&test_version);
		if (status == eap_status_ok
			&& test_version.get_is_valid_data() == true
			&& test_version.get_data_length() == sizeof(u32_t)
			&& test_version.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(test_version.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_simple_config_test_version = false;
				}
				else
				{
					m_simple_config_test_version = true;
				}
			}
		}

		status = eap_status_ok;
	}

	//----------------------------------------------------------

	{
		eap_variable_data_c error_message_received_timeout(m_am_tools);

		if (error_message_received_timeout.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_status_e status = read_configure(
			cf_str_SIMPLE_CONFIG_error_message_received_timeout.get_field(),
			&error_message_received_timeout);
		if (status == eap_status_ok
			&& error_message_received_timeout.get_is_valid_data() == true)
		{
			u32_t *error_message_received_timeout_value = reinterpret_cast<u32_t *>(
				error_message_received_timeout.get_data(sizeof(u32_t)));
			if (error_message_received_timeout_value != 0)
			{
				m_error_message_received_timeout = *error_message_received_timeout_value;
			}
		}
	}

	//----------------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)
	if (m_is_client == false)
	{
		{
			// This is optional.
			(void) read_configure(
				cf_str_SIMPLE_CONFIG_new_password.get_field(),
				&m_new_password);
		}

		{
			// This is optional.
			(void) read_configure(
				cf_str_SIMPLE_CONFIG_network_key.get_field(),
				&m_network_key);
		}

		{
			eap_variable_data_c authentication_type(m_am_tools);

			eap_status_e status = read_configure(
				cf_str_SIMPLE_CONFIG_authentication_type.get_field(),
				&authentication_type);
			if (status == eap_status_ok
				&& authentication_type.get_is_valid() == true
				&& authentication_type.get_data_length() > 0ul
				&& authentication_type.get_data(
					authentication_type.get_data_length()) != 0)
			{

				if (cf_str_SIMPLE_CONFIG_authentication_type_None.get_field()
					->compare(
						m_am_tools,
						&authentication_type) == true)
				{
					m_authentication_type
						= simple_config_Authentication_Type_None;
				}
				else if (cf_str_SIMPLE_CONFIG_authentication_type_Open.get_field()
						 ->compare(
							 m_am_tools,
							 &authentication_type) == true)
				{
					m_authentication_type
						= simple_config_Authentication_Type_Open;
				}
				else if (cf_str_SIMPLE_CONFIG_authentication_type_WPAPSK.get_field()
						 ->compare(
							 m_am_tools,
							 &authentication_type) == true)
				{
					m_authentication_type
						= simple_config_Authentication_Type_WPAPSK;
				}
				else if (cf_str_SIMPLE_CONFIG_authentication_type_Shared.get_field()
						 ->compare(
							 m_am_tools,
							 &authentication_type) == true)
				{
					m_authentication_type
						= simple_config_Authentication_Type_Shared;
				}
				else if (cf_str_SIMPLE_CONFIG_authentication_type_WPA.get_field()
						 ->compare(
							 m_am_tools,
							 &authentication_type) == true)
				{
					m_authentication_type
						= simple_config_Authentication_Type_WPA;
				}
				else if (cf_str_SIMPLE_CONFIG_authentication_type_WPA2.get_field()
						 ->compare(
							 m_am_tools,
							 &authentication_type) == true)
				{
					m_authentication_type
						= simple_config_Authentication_Type_WPA2;
				}
				else if (cf_str_SIMPLE_CONFIG_authentication_type_WPA2PSK.get_field()
						 ->compare(
							 m_am_tools,
							 &authentication_type) == true)
				{
					m_authentication_type
						= simple_config_Authentication_Type_WPA2PSK;
				}
			}
		}
	}
#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

	//----------------------------------------------------------

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: function: simple_config_record_c::shutdown(): ")
		 EAPL("this = 0x%08x\n"),
		(m_is_client == true ? "client": "server"),
		this));

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;


	// Cancel all timers.
	cancel_error_message_timeout();
	cancel_M2D_received_timeout();


	if (get_state() != simple_config_state_simple_config_success)
	{
		set_state(simple_config_state_failure);
	}

	eap_status_e status = eap_status_ok;

	if (m_pending_query_network_and_device_parameters == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: function: simple_config_record_c::shutdown(): calls cancel_query_dh_parameters()\n")));

		m_am_simple_config_services->cancel_query_network_and_device_parameters();
		m_pending_query_network_and_device_parameters = false;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::set_nai_realm(
	const eap_variable_data_c * const NAI_realm)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_NAI_realm.set_copy_of_buffer(NAI_realm);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e simple_config_record_c::completion_action_add(
	simple_config_completion_action_e action)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	simple_config_completion_c *completion_action = new simple_config_completion_c(
		m_am_tools,
		action);

	if (completion_action == 0
		|| completion_action->get_is_valid() == false)
	{
		delete completion_action;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// add_object() will delete completion_action if operation fails.
	eap_status_e status = m_completion_queue.add_object(completion_action, true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("SIMPLE_CONFIG: %s: send_function: completion_action_add(): action %s\n"),
					 (m_is_client == true ? "client": "server"),
					 completion_action->get_completion_action_string()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e simple_config_record_c::completion_action_clenup()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("SIMPLE_CONFIG: %s: send_function: completion_action_clenup()\n"),
					 (m_is_client == true ? "client": "server")));

	eap_status_e final_status = eap_status_ok;
	u32_t counter(0ul);

	while(m_completion_queue.get_object_count() > 0ul)
	{
		simple_config_completion_c * const completion_action = m_completion_queue.get_object(0ul);
		EAP_UNREFERENCED_PARAMETER(completion_action); // Not referenced without trace.

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: SIMPLE_CONFIG: %s: send_function: completion_action_clenup(): ")
			 EAPL("action[%u] %s not completed.\n"),
			 (m_is_client == true ? "client": "server"),
			 counter,
			 completion_action->get_completion_action_string()));

		final_status = m_completion_queue.remove_object(0ul);
		if (final_status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, final_status);
		}

		++counter;

	} // while()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, final_status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e simple_config_record_c::completion_action_check()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("SIMPLE_CONFIG: %s: send_function: completion_action_check()\n"),
					 (m_is_client == true ? "client": "server")));

	if (m_already_in_completion_action_check == true)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		// This is recursive call of completion_action_check().
		// This MUST return eap_status_ok. Other return values will skip
		// further prosessing of completion action list.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_already_in_completion_action_check = true;

	eap_automatic_simple_value_c<bool> restore_already_in_completion_action_check(
		m_am_tools,
		&m_already_in_completion_action_check,
		false);

	eap_status_e status = eap_status_ok;
	bool continue_with_next_action = true;
	u32_t counter = 0ul;

	while(continue_with_next_action == true
		&& m_completion_queue.get_object_count() > 0ul)
	{
		simple_config_completion_c * const completion_action = m_completion_queue.get_object(0ul);
		EAP_UNREFERENCED_PARAMETER(completion_action); // Not referenced without trace.

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
						(EAPL("SIMPLE_CONFIG: %s: send_function: completion_action_check(): action[%u] %s\n"),
						 (m_is_client == true ? "client": "server"),
						 counter,
						 completion_action->get_completion_action_string()));

		if (continue_with_next_action == true)
		{
			status = m_completion_queue.remove_object(0ul);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		++counter;

	} // while()

	if (continue_with_next_action == false)
	{
		status = eap_status_pending_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// This is commented in abs_simple_config_base_application_c.
EAP_FUNC_EXPORT eap_status_e simple_config_record_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return get_type_partner()->read_configure(
			field,
			data);
}

//--------------------------------------------------

// This is commented in abs_simple_config_base_application_c.
EAP_FUNC_EXPORT eap_status_e simple_config_record_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return get_type_partner()->write_configure(
			field,
			data);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::add_common_attributes(
	simple_config_payloads_c * const payloads,
	const simple_config_Message_Type_e message_type,
	const bool add_enrollee_nonce,
	const bool add_registrar_nonce)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::add_common_attributes()\n"),
		(m_is_client == true ? "client": "server")));

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (message_type > simple_config_Message_keep_this_last)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);

	{
		u8_t Version[]
			= { SIMPLE_CONFIG_VERSION };

		status = payloads->copy_attribute_data(
			simple_config_Attribute_Type_Version,
			true,
			Version,
			sizeof(Version));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		u8_t Message_type(static_cast<u8_t>(message_type));

		status = payloads->copy_attribute_data(
			simple_config_Attribute_Type_Message_Type,
			true,
			&Message_type,
			sizeof(Message_type));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		// Save the type for indicating it to the lower layer in transmission
		m_current_simple_config_message_type = message_type;
	}

	if (add_enrollee_nonce == true)
	{
		if (m_enrollee_nonce.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = payloads->copy_attribute_data(
			simple_config_Attribute_Type_Enrollee_Nonce,
			true,
			m_enrollee_nonce.get_data(),
			m_enrollee_nonce.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (add_registrar_nonce == true)
	{
		if (m_registrar_nonce.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = payloads->copy_attribute_data(
			simple_config_Attribute_Type_Registrar_Nonce,
			true,
			m_registrar_nonce.get_data(),
			m_registrar_nonce.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::send_M1(
	const simple_config_payloads_c * const network_and_device_parameters)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M1()\n"),
		(m_is_client == true ? "client": "server")));

	if (network_and_device_parameters == 0
		|| network_and_device_parameters->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);


	{
		// Save Enrollee MAC.
		status = m_enrollee_mac.set_copy_of_buffer(
			m_send_network_id.get_source_id());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	
	simple_config_payloads_c * payloads = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = add_common_attributes(
		payloads,
		simple_config_Message_Type_M1,
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_UUID_E);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		if (m_enrollee_mac.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = payloads->copy_attribute_data(
			simple_config_Attribute_Type_MAC_Address,
			true,
			m_enrollee_mac.get_data(),
			m_enrollee_mac.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	{
		if (m_enrollee_nonce.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = payloads->copy_attribute_data(
			simple_config_Attribute_Type_Enrollee_Nonce,
			true,
			m_enrollee_nonce.get_data(),
			m_enrollee_nonce.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		if (m_own_public_dhe_key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = payloads->copy_attribute_data(
			simple_config_Attribute_Type_Public_Key,
			true,
			m_own_public_dhe_key.get_data(),
			m_own_public_dhe_key.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Authentication_Type_Flags);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Encryption_Type_Flags);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Connection_Type_Flags);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Config_Methods);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Simple_Config_State);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Manufacturer);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Model_Name);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Model_Number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Serial_Number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Primary_Device_Type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Device_Name);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_RF_Band);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Association_State);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Device_Password_ID);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (payloads->get_attribute_pointer(
		simple_config_Attribute_Type_Configuration_Error) != 0)
	{
		status = payloads->copy_attribute(
			network_and_device_parameters,
			simple_config_Attribute_Type_Configuration_Error);
	}
	else
	{
		status = eap_status_not_found;
	}

	if (status != eap_status_ok)
	{
		simple_config_Configuration_Error_e Configuration_Error(simple_config_Configuration_Error_No_Error);
		u16_t network_order_Configuration_Error(eap_htons(static_cast<u16_t>(Configuration_Error)));

		status = payloads->copy_attribute_data(
			simple_config_Attribute_Type_Configuration_Error,
			true,
			&network_order_Configuration_Error,
			sizeof(network_order_Configuration_Error));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_OS_Version);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	if (m_new_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->create_simple_config_message(
		&m_new_simple_config_message,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	set_state(simple_config_state_wait_M2);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::send_M2(
	const simple_config_payloads_c * const network_and_device_parameters)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M2()\n"),
		(m_is_client == true ? "client": "server")));

	if (network_and_device_parameters == 0
		|| network_and_device_parameters->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);
	

	simple_config_payloads_c * payloads = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = add_common_attributes(
		payloads,
		simple_config_Message_Type_M2,
		true,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_UUID_R);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		status = payloads->copy_attribute_data(
			simple_config_Attribute_Type_Public_Key,
			true,
			m_own_public_dhe_key.get_data(),
			m_own_public_dhe_key.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Authentication_Type_Flags);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Encryption_Type_Flags);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Connection_Type_Flags);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Config_Methods);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Manufacturer);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Model_Name);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Model_Number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Serial_Number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Primary_Device_Type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Device_Name);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_RF_Band);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Association_State);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (payloads->get_attribute_pointer(
		simple_config_Attribute_Type_Configuration_Error) != 0)
	{
		status = payloads->copy_attribute(
			network_and_device_parameters,
			simple_config_Attribute_Type_Configuration_Error);
	}
	else
	{
		status = eap_status_missing_payload;
	}

	if (status != eap_status_ok)
	{
		// Because the Configuration_Error is missing there is no error.
		simple_config_Configuration_Error_e Configuration_Error(simple_config_Configuration_Error_No_Error);
		u16_t network_order_Configuration_Error(eap_htons(static_cast<u16_t>(Configuration_Error)));

		status = payloads->copy_attribute_data(
			simple_config_Attribute_Type_Configuration_Error,
			true,
			&network_order_Configuration_Error,
			sizeof(network_order_Configuration_Error));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Device_Password_ID);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_OS_Version);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	if (m_new_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->create_simple_config_message(
		&m_new_simple_config_message,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_authenticator_attribute(
		&m_received_simple_config_message,
		&m_new_simple_config_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_state(simple_config_state_wait_M3);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::send_M2D(
	const simple_config_payloads_c * const network_and_device_parameters)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M2D()\n"),
		(m_is_client == true ? "client": "server")));

	if (network_and_device_parameters == 0
		|| network_and_device_parameters->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);
	

	simple_config_payloads_c * payloads = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	status = add_common_attributes(
		payloads,
		simple_config_Message_Type_M2D,
		true,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_UUID_R);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Authentication_Type_Flags);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Encryption_Type_Flags);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Connection_Type_Flags);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Config_Methods);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Manufacturer);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Model_Name);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Model_Number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Serial_Number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Primary_Device_Type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Device_Name);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_RF_Band);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_Association_State);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (network_and_device_parameters->get_attribute_pointer(
		simple_config_Attribute_Type_Configuration_Error) != 0)
	{
		status = payloads->copy_attribute(
			network_and_device_parameters,
			simple_config_Attribute_Type_Configuration_Error);
	}
	else
	{
		status = eap_status_missing_payload;
	}

	if (status != eap_status_ok)
	{
		simple_config_Configuration_Error_e Configuration_Error(simple_config_Configuration_Error_No_Error);
		u16_t network_order_Configuration_Error(eap_htons(static_cast<u16_t>(Configuration_Error)));

		status = payloads->copy_attribute_data(
			simple_config_Attribute_Type_Configuration_Error,
			true,
			&network_order_Configuration_Error,
			sizeof(network_order_Configuration_Error));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = payloads->copy_attribute(
		network_and_device_parameters,
		simple_config_Attribute_Type_OS_Version);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	if (m_new_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->create_simple_config_message(
		&m_new_simple_config_message,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_state(simple_config_state_wait_WSC_ACK);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::send_M3()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M3()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Create HASHs
	status = generate_er_hashs(
		false,
		&m_device_password,
		&m_own_public_dhe_key,
		&m_peer_public_dhe_key,
		&m_PSK1,
		&m_E_SNonce1,
		&m_EHash1,
		&m_PSK2,
		&m_E_SNonce2,
		&m_EHash2);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	simple_config_payloads_c * payloads = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	status = add_common_attributes(
		payloads,
		simple_config_Message_Type_M3,
		false,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute_data(
		simple_config_Attribute_Type_E_Hash1,
		true,
		m_EHash1.get_data(),
		m_EHash1.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute_data(
		simple_config_Attribute_Type_E_Hash2,
		true,
		m_EHash2.get_data(),
		m_EHash2.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_new_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->create_simple_config_message(
		&m_new_simple_config_message,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_authenticator_attribute(
		&m_received_simple_config_message,
		&m_new_simple_config_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_state(simple_config_state_wait_M4);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::send_M4()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M4()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Create HASHs
	status = generate_er_hashs(
		false,
		&m_device_password,
		&m_peer_public_dhe_key,
		&m_own_public_dhe_key,
		&m_PSK1,
		&m_R_SNonce1,
		&m_RHash1,
		&m_PSK2,
		&m_R_SNonce2,
		&m_RHash2);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	simple_config_payloads_c * payloads = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	status = add_common_attributes(
		payloads,
		simple_config_Message_Type_M4,
		true,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute_data(
		simple_config_Attribute_Type_R_Hash1,
		true,
		m_RHash1.get_data(),
		m_RHash1.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->copy_attribute_data(
		simple_config_Attribute_Type_R_Hash2,
		true,
		m_RHash2.get_data(),
		m_RHash2.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	simple_config_variable_data_c * encrypted_settings = new simple_config_variable_data_c(m_am_tools);
	eap_automatic_variable_c<simple_config_variable_data_c> automatic_encrypted_settings(m_am_tools, encrypted_settings);

	if (encrypted_settings == 0
		|| encrypted_settings->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		// Create Encrypted Settings.
		// This one includes R-SNonce1 (R-S1).
		simple_config_payloads_c * plaintext_payloads = new simple_config_payloads_c(m_am_tools);
		eap_automatic_variable_c<simple_config_payloads_c> automatic_plaintext_payloads(m_am_tools, plaintext_payloads);

		if (plaintext_payloads == 0
			|| plaintext_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = plaintext_payloads->copy_attribute_data(
			simple_config_Attribute_Type_R_SNonce1,
			true,
			m_R_SNonce1.get_data(),
			m_R_SNonce1.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = encrypt_payloads(
			&m_auth_key,
			&m_key_wrap_key,
			plaintext_payloads,
			encrypted_settings);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	automatic_encrypted_settings.do_not_free_variable();

	status = payloads->add_attribute(
		encrypted_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_new_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->create_simple_config_message(
		&m_new_simple_config_message,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_authenticator_attribute(
		&m_received_simple_config_message,
		&m_new_simple_config_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_state(simple_config_state_wait_M5);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::send_M5()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M5()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	simple_config_payloads_c * payloads = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M5(): calls add_common_attributes()\n"),
		(m_is_client == true ? "client": "server")));

	status = add_common_attributes(
		payloads,
		simple_config_Message_Type_M5,
		false,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	simple_config_variable_data_c * encrypted_settings = new simple_config_variable_data_c(m_am_tools);
	eap_automatic_variable_c<simple_config_variable_data_c> automatic_encrypted_settings(m_am_tools, encrypted_settings);

	if (encrypted_settings == 0
		|| encrypted_settings->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		// Create Encrypted Settings.
		// This one includes E-SNonce1 (E-S1).
		simple_config_payloads_c * plaintext_payloads = new simple_config_payloads_c(m_am_tools);
		eap_automatic_variable_c<simple_config_payloads_c> automatic_plaintext_payloads(m_am_tools, plaintext_payloads);

		if (plaintext_payloads == 0
			|| plaintext_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M5(): calls copy_attribute_data()\n"),
			(m_is_client == true ? "client": "server")));

		status = plaintext_payloads->copy_attribute_data(
			simple_config_Attribute_Type_E_SNonce1,
			true,
			m_E_SNonce1.get_data(),
			m_E_SNonce1.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M5(): calls encrypt_payloads()\n"),
			(m_is_client == true ? "client": "server")));

		status = encrypt_payloads(
			&m_auth_key,
			&m_key_wrap_key,
			plaintext_payloads,
			encrypted_settings);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M5(): calls payloads.add_attribute()\n"),
		(m_is_client == true ? "client": "server")));

	automatic_encrypted_settings.do_not_free_variable();

	status = payloads->add_attribute(
		encrypted_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_new_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M5(): calls payloads.create_simple_config_message()\n"),
		(m_is_client == true ? "client": "server")));

	status = payloads->create_simple_config_message(
		&m_new_simple_config_message,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M5(): calls m_received_simple_config_message.get_is_valid()\n"),
		(m_is_client == true ? "client": "server")));

	if (m_received_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M5(): calls m_new_simple_config_message.get_is_valid()\n"),
		(m_is_client == true ? "client": "server")));

	if (m_new_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M5(): calls add_authenticator_attribute()\n"),
		(m_is_client == true ? "client": "server")));

	status = add_authenticator_attribute(
		&m_received_simple_config_message,
		&m_new_simple_config_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_state(simple_config_state_wait_M6);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M5(): returns\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::send_M6()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M6()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	simple_config_payloads_c * payloads = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = add_common_attributes(
		payloads,
		simple_config_Message_Type_M6,
		true,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	simple_config_variable_data_c * encrypted_settings = new simple_config_variable_data_c(m_am_tools);
	eap_automatic_variable_c<simple_config_variable_data_c> automatic_encrypted_settings(m_am_tools, encrypted_settings);

	if (encrypted_settings == 0
		|| encrypted_settings->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		// Create Encrypted Settings.
		// This one includes R-SNonce2 (R-S2).
		simple_config_payloads_c * plaintext_payloads = new simple_config_payloads_c(m_am_tools);
		eap_automatic_variable_c<simple_config_payloads_c> automatic_plaintext_payloads(m_am_tools, plaintext_payloads);

		if (plaintext_payloads == 0
			|| plaintext_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = plaintext_payloads->copy_attribute_data(
			simple_config_Attribute_Type_R_SNonce2,
			true,
			m_R_SNonce2.get_data(),
			m_R_SNonce2.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = encrypt_payloads(
			&m_auth_key,
			&m_key_wrap_key,
			plaintext_payloads,
			encrypted_settings);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	automatic_encrypted_settings.do_not_free_variable();

	status = payloads->add_attribute(
		encrypted_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_new_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->create_simple_config_message(
		&m_new_simple_config_message,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_authenticator_attribute(
		&m_received_simple_config_message,
		&m_new_simple_config_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_state(simple_config_state_wait_M7);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::send_M7()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M7()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	simple_config_payloads_c * payloads = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = add_common_attributes(
		payloads,
		simple_config_Message_Type_M7,
		false,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	simple_config_variable_data_c * encrypted_settings = new simple_config_variable_data_c(m_am_tools);
	eap_automatic_variable_c<simple_config_variable_data_c> automatic_encrypted_settings(m_am_tools, encrypted_settings);

	if (encrypted_settings == 0
		|| encrypted_settings->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	{
		// Create Encrypted Settings.
		// This one includes E-SNonce2 (E-S2).
		simple_config_payloads_c * plaintext_payloads = new simple_config_payloads_c(m_am_tools);
		eap_automatic_variable_c<simple_config_payloads_c> automatic_plaintext_payloads(m_am_tools, plaintext_payloads);

		if (plaintext_payloads == 0
			|| plaintext_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = plaintext_payloads->copy_attribute_data(
			simple_config_Attribute_Type_E_SNonce2,
			true,
			m_E_SNonce2.get_data(),
			m_E_SNonce2.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = encrypt_payloads(
			&m_auth_key,
			&m_key_wrap_key,
			plaintext_payloads,
			encrypted_settings);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	automatic_encrypted_settings.do_not_free_variable();

	status = payloads->add_attribute(
		encrypted_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_new_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->create_simple_config_message(
		&m_new_simple_config_message,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_authenticator_attribute(
		&m_received_simple_config_message,
		&m_new_simple_config_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_state(simple_config_state_wait_M8);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::send_M8()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_M8()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	simple_config_payloads_c * payloads = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	status = add_common_attributes(
		payloads,
		simple_config_Message_Type_M8,
		true,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	simple_config_variable_data_c * encrypted_settings = new simple_config_variable_data_c(m_am_tools);
	eap_automatic_variable_c<simple_config_variable_data_c> automatic_encrypted_settings(m_am_tools, encrypted_settings);

	if (encrypted_settings == 0
		|| encrypted_settings->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// Create Encrypted Settings.
	{
		simple_config_payloads_c * plaintext_payloads = new simple_config_payloads_c(m_am_tools);
		eap_automatic_variable_c<simple_config_payloads_c> automatic_plaintext_payloads(m_am_tools, plaintext_payloads);

		if (plaintext_payloads == 0
			|| plaintext_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Create Credential attribute
		{
			u32_t SIMPLE_CONFIG_TEST_CREDENTIAL_COUNT = 2ul;

			for (u32_t ind = 0ul; ind < SIMPLE_CONFIG_TEST_CREDENTIAL_COUNT; ind++)
			{
				simple_config_payloads_c * credential_payloads = new simple_config_payloads_c(m_am_tools);
				eap_automatic_variable_c<simple_config_payloads_c> automatic_credential_payloads(m_am_tools, credential_payloads);

				if (credential_payloads == 0
					|| credential_payloads->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}


				{
					u8_t network_index(static_cast<u8_t>(ind+SIMPLE_CONFIG_DEFAULT_NETWORK_KEY_INDEX));

					status = credential_payloads->copy_attribute_data(
						simple_config_Attribute_Type_Network_Index,
						true,
						&network_index,
						sizeof(network_index));
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = credential_payloads->copy_attribute_data(
						simple_config_Attribute_Type_SSID,
						true,
						m_SSID.get_data(),
						m_SSID.get_data_length());
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					{
						u16_t network_order_Authentication_Type(eap_htons(static_cast<u16_t>(m_authentication_type)));

						status = credential_payloads->copy_attribute_data(
							simple_config_Attribute_Type_Authentication_Type,
							true,
							&network_order_Authentication_Type,
							sizeof(network_order_Authentication_Type));
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}

					{
						u16_t network_order_Encryption_Type(eap_htons(static_cast<u16_t>(simple_config_Encryption_Type_AES)));

						status = credential_payloads->copy_attribute_data(
							simple_config_Attribute_Type_Encryption_Type,
							true,
							&network_order_Encryption_Type,
							sizeof(network_order_Encryption_Type));
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}


					// Creates some test data.
					eap_array_c<network_key_and_index_c> * network_keys = new eap_array_c<network_key_and_index_c>(m_am_tools);
					eap_automatic_variable_c<eap_array_c<network_key_and_index_c> > automatic_network_keys(m_am_tools, network_keys);
					
					if (network_keys == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					{
						const u32_t MAX_COUNT_OF_KEYS = 3ul;

						for (u32_t ind = 0ul; ind < MAX_COUNT_OF_KEYS; ++ind)
						{
							network_key_and_index_c * const obj = new network_key_and_index_c(m_am_tools);

							if (obj != 0)
							{
								u8_t network_key_index(static_cast<u8_t>(ind));

								obj->set_network_key_index(network_key_index);

								status = obj->get_network_key()->set_copy_of_buffer(
									&m_network_key);
								if (status != eap_status_ok)
								{
									EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
									return EAP_STATUS_RETURN(m_am_tools, status);
								}

								status = network_keys->add_object(obj, true);
								if (status != eap_status_ok)
								{
									EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
									return EAP_STATUS_RETURN(m_am_tools, status);
								}
							}
						}
					}

					{
						for (u32_t ind = 0ul; ind < network_keys->get_object_count(); ++ind)
						{
							network_key_and_index_c * const obj = network_keys->get_object(ind);

							if (obj != 0)
							{
								u8_t network_key_index(obj->get_network_key_index());

								status = credential_payloads->copy_attribute_data(
									simple_config_Attribute_Type_Network_Key_Index,
									true,
									&network_key_index,
									sizeof(network_key_index));
								if (status != eap_status_ok)
								{
									EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
									return EAP_STATUS_RETURN(m_am_tools, status);
								}

								status = credential_payloads->copy_attribute_data(
									simple_config_Attribute_Type_Network_Key,
									true,
									obj->get_network_key()->get_data(),
									obj->get_network_key()->get_data_length());
								if (status != eap_status_ok)
								{
									EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
									return EAP_STATUS_RETURN(m_am_tools, status);
								}
							}
						}
					}

					status = credential_payloads->copy_attribute_data(
						simple_config_Attribute_Type_MAC_Address,
						true,
						m_MAC_address.get_data(),
						m_MAC_address.get_data_length());
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

				}

				simple_config_message_c * credential_data = new simple_config_message_c(m_am_tools, m_is_client);
				eap_automatic_variable_c<simple_config_message_c> automatic_credential_data(m_am_tools, credential_data);

				if (credential_data == 0
					|| credential_data->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}


				status = credential_payloads->create_simple_config_message(
					credential_data,
					false);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = plaintext_payloads->copy_attribute_data(
					simple_config_Attribute_Type_Credential,
					true,
					credential_data->get_simple_config_message_data()->get_data(),
					credential_data->get_simple_config_message_data()->get_data_length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
			// Add other optional encrypted attributes.

			if (m_new_password.get_is_valid_data() == true)
			{
				status = plaintext_payloads->copy_attribute_data(
					simple_config_Attribute_Type_New_Password,
					true,
					m_new_password.get_data(),
					m_new_password.get_data_length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				{
					u16_t device_password_id(static_cast<u16_t>(simple_config_Device_Password_ID_Default_PIN));
					u16_t network_order_device_password_id(eap_htons(device_password_id));

					status = plaintext_payloads->copy_attribute_data(
						simple_config_Attribute_Type_Device_Password_ID,
						true,
						&network_order_device_password_id,
						sizeof(network_order_device_password_id));
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}

		}

		status = encrypt_payloads(
			&m_auth_key,
			&m_key_wrap_key,
			plaintext_payloads,
			encrypted_settings);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	automatic_encrypted_settings.do_not_free_variable();

	status = payloads->add_attribute(
		encrypted_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_new_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->create_simple_config_message(
		&m_new_simple_config_message,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_authenticator_attribute(
		&m_received_simple_config_message,
		&m_new_simple_config_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_state(simple_config_state_wait_WSC_DONE);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::send_WSC_ACK()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_WSC_ACK()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	simple_config_payloads_c * payloads = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	status = add_common_attributes(
		payloads,
		simple_config_Message_Type_WSC_ACK,
		true,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_new_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->create_simple_config_message(
		&m_new_simple_config_message,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_state(simple_config_state_failure);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::send_WSC_NACK()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_WSC_NACK()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	simple_config_payloads_c * payloads = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = add_common_attributes(
		payloads,
		simple_config_Message_Type_WSC_NACK,
		true,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_new_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->create_simple_config_message(
		&m_new_simple_config_message,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_state(simple_config_state_failure);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::send_WSC_Done()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: simple_config_record_c::send_WSC_Done()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	simple_config_payloads_c * payloads = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_payloads(m_am_tools, payloads);

	if (payloads == 0
		|| payloads->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	status = add_common_attributes(
		payloads,
		simple_config_Message_Type_WSC_DONE,
		true,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_new_simple_config_message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->create_simple_config_message(
		&m_new_simple_config_message,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	set_state(simple_config_state_simple_config_success);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void simple_config_record_c::send_error_notification(const eap_status_e error)
{
	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("simple_config_record_c::send_error_notification, error=%d\n"),
		error));	

	// Notifies the lower level of an authentication error.
	eap_state_notification_c notification(
		m_am_tools,
		&m_send_network_id,
		m_is_client,
		eap_state_notification_generic,
		eap_protocol_layer_general,
		eap_type_none,
		eap_state_none,
		eap_general_state_authentication_error,
		0,
		false);

	notification.set_authentication_error(error);

	get_type_partner()->state_notification(&notification);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e simple_config_record_c::initalize_error_message_timeout()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	cancel_error_message_timeout();

	eap_status_e status = get_type_partner()->set_timer(
		this,
		SIMPLE_CONFIG_RECORD_ERROR_MESSAGE_RECEIVED_ID,
		0,
		m_error_message_received_timeout);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s: SIMPLE_CONFIG_RECORD_ERROR_MESSAGE_RECEIVED_ID set %d ms, this = 0x%08x.\n"),
		 (m_is_client == true) ? "client": "server",
		 m_error_message_received_timeout,
		 this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e simple_config_record_c::cancel_error_message_timeout()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_type_partner()->cancel_timer(
		this,
		SIMPLE_CONFIG_RECORD_ERROR_MESSAGE_RECEIVED_ID);

	EAP_UNREFERENCED_PARAMETER(status); // in release
	
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s, SIMPLE_CONFIG_RECORD_ERROR_MESSAGE_RECEIVED_ID cancelled status %d, this = 0x%08x.\n"),
		 (m_is_client == true ? "client": "server"),
		 status,
		 this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e simple_config_record_c::initialize_M2D_received_timeout()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	if (m_M2D_received_timeout_active == false)
	{
		cancel_M2D_received_timeout();

		status = get_type_partner()->set_timer(
			this,
			SIMPLE_CONFIG_RECORD_M2D_RECEIVED_ID,
			0,
			m_error_message_received_timeout);

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: SIMPLE_CONFIG_RECORD_M2D_RECEIVED_ID set %d ms, this = 0x%08x.\n"),
			 (m_is_client == true) ? "client": "server",
			 m_error_message_received_timeout,
			 this));
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: SIMPLE_CONFIG_RECORD_M2D_RECEIVED_ID already set.\n"),
			 (m_is_client == true) ? "client": "server"));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e simple_config_record_c::cancel_M2D_received_timeout()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_type_partner()->cancel_timer(
		this,
		SIMPLE_CONFIG_RECORD_M2D_RECEIVED_ID);

	m_M2D_received_timeout_active = false;

	EAP_UNREFERENCED_PARAMETER(status); // in release
	
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("TIMER: %s, SIMPLE_CONFIG_RECORD_M2D_RECEIVED_ID cancelled status %d, this = 0x%08x.\n"),
		 (m_is_client == true ? "client": "server"),
		 status,
		 this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e simple_config_record_c::timer_expired(
	const u32_t id,
	void * data
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(data); // Only trace uses this.
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: [0x%08x]->simple_config_record_c::timer_expired(id 0x%02x, data 0x%08x)\n"),
		 this,
		 id,
		 data));

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	if (id == SIMPLE_CONFIG_RECORD_ERROR_MESSAGE_RECEIVED_ID)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("TIMER: %s: SIMPLE_CONFIG_RECORD_ERROR_MESSAGE_RECEIVED_ID elapsed.\n"),
			 (m_is_client == true ? "client": "server")
			 ));

		status = send_WSC_NACK();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = check_sent_simple_config_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		(void) send_error_notification(m_handshake_error);

	}
	else if (id == SIMPLE_CONFIG_RECORD_M2D_RECEIVED_ID)
	{
		(void) m_am_simple_config_services->received_registrar_information(&m_M2D_payloads);

		(void) send_error_notification(m_handshake_error);

		m_M2D_received_timeout_active = false;
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: TIMER: %s: unknown timer elapsed.\n"),
			 (m_is_client == true ? "client": "server")
			 ));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e simple_config_record_c::timer_delete_data(
	const u32_t /*id*/,
	void * /*data*/
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e simple_config_record_c::verify_nonces_and_authenticator(
	const eap_variable_data_c * const auth_key,
	const eap_variable_data_c * const enrollee_nonce,
	const eap_variable_data_c * const registrar_nonce,
	const simple_config_payloads_c * const payloads,
	const bool check_enrollee_nonce,
	const bool check_registrar_nonce,
	const bool check_authenticator)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::verify_authenticator()\n"),
		 (m_is_client == true ? "client": "server")));

	if (check_enrollee_nonce == true)
	{
		// Verify Enrollee Nonce.

		simple_config_variable_data_c * const enrollee_nonce_attribute
			= payloads->get_attribute_pointer(simple_config_Attribute_Type_Enrollee_Nonce);
		if (enrollee_nonce_attribute == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
		}

		if (enrollee_nonce->compare(
				enrollee_nonce_attribute->get_data(enrollee_nonce_attribute->get_data_length()),
				enrollee_nonce_attribute->get_data_length()) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	if (check_registrar_nonce == true)
	{
		// Verify Registrar Nonce.

		simple_config_variable_data_c * const registrar_nonce_attribute
			= payloads->get_attribute_pointer(simple_config_Attribute_Type_Registrar_Nonce);
		if (registrar_nonce_attribute == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
		}

		if (registrar_nonce->compare(
				registrar_nonce_attribute->get_data(registrar_nonce_attribute->get_data_length()),
				registrar_nonce_attribute->get_data_length()) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}

	if (check_authenticator == true)
	{
		// Verify Authenticator.
		crypto_sha_256_c sha_256(m_am_tools);
		if (sha_256.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		crypto_hmac_c hmac_sha_256(
			m_am_tools,
			&sha_256,
			false);
		if (hmac_sha_256.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG authenticator auth_key"),
			 auth_key->get_data(),
			 auth_key->get_data_length()));

		eap_status_e status = hmac_sha_256.hmac_set_key(auth_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG authenticator data"),
			 m_previous_simple_config_message.get_simple_config_message_data()->get_data(),
			 m_previous_simple_config_message.get_simple_config_message_data()->get_data_length()));

		status = hmac_sha_256.hmac_update(
			m_previous_simple_config_message.get_simple_config_message_data()->get_data(),
			m_previous_simple_config_message.get_simple_config_message_data()->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = payloads->add_payloads_to_simple_config_authenticator(
			&hmac_sha_256,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		{
			eap_variable_data_c authenticator(m_am_tools);

			if (authenticator.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = authenticator.set_buffer_length(hmac_sha_256.get_digest_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = authenticator.set_data_length(hmac_sha_256.get_digest_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			u32_t md_length(hmac_sha_256.get_digest_length());
			
			status = hmac_sha_256.hmac_final(
				authenticator.get_data(hmac_sha_256.get_digest_length()),
				&md_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("SIMPLE_CONFIG authenticator"),
				 authenticator.get_data(),
				 authenticator.get_data_length()));
			
			status = authenticator.set_data_length(SIMPLE_CONFIG_AUTHENTICATOR_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			simple_config_variable_data_c * const received_authenticator
				= payloads->get_attribute_pointer(simple_config_Attribute_Type_Authenticator);
			if (received_authenticator == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
			}

			if (authenticator.compare(
					received_authenticator->get_data(received_authenticator->get_data_length()),
					received_authenticator->get_data_length()) != 0)
			{
				EAP_TRACE_DATA_ERROR(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("SIMPLE_CONFIG    local authenticator"),
					 authenticator.get_data(),
					 authenticator.get_data_length()));

				EAP_TRACE_DATA_ERROR(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("SIMPLE_CONFIG received authenticator"),
					 received_authenticator->get_data(received_authenticator->get_data_length()),
					 received_authenticator->get_data_length()));
				
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::verify_authenticator(): Authenticator OK\n"),
					 (m_is_client == true ? "client": "server")));
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e simple_config_record_c::start_simple_config_authentication(
	const eap_variable_data_c * const NAI ///< This is the full NAI of the client.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: start_simple_config_authentication()\n"),
		(m_is_client == true ? "client": "server")));

	if (verify_state(simple_config_state_wait_simple_config_start) == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	set_state(simple_config_state_process_simple_config_start);

	if (NAI == 0
		|| NAI->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
	}

	eap_status_e status = m_NAI.set_copy_of_buffer(NAI);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_allow_message_send = false;

	status = m_am_simple_config_services->query_network_and_device_parameters(get_state());

	m_allow_message_send = true;

	if (status == eap_status_pending_request)
	{
		// This is pending query, that will be completed by
		// complete_query_network_and_device_parameters() call.
		m_pending_query_network_and_device_parameters = true;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status == eap_status_completed_request)
	{
		// This is already completed by complete_query_network_and_device_parameters() call.

		status = check_sent_simple_config_message();

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status == eap_status_ok)
	{
		// This is also an error case, because this call is always completed on success. 
		status = eap_status_process_general_error;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else // All other status values means error, because this call is always completed on success.
	{
		// This is an error case.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
}

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

static const simple_config_Attribute_Type_e needed_payloads_of_M1[]
	= {
		simple_config_Attribute_Type_Version,
		simple_config_Attribute_Type_Message_Type,
		simple_config_Attribute_Type_UUID_E,
		simple_config_Attribute_Type_MAC_Address,
		simple_config_Attribute_Type_Enrollee_Nonce,
		simple_config_Attribute_Type_Public_Key,
		simple_config_Attribute_Type_Authentication_Type_Flags,
		simple_config_Attribute_Type_Encryption_Type_Flags,
		simple_config_Attribute_Type_Connection_Type_Flags,
		simple_config_Attribute_Type_Config_Methods,
		simple_config_Attribute_Type_Simple_Config_State,
		simple_config_Attribute_Type_Manufacturer,
		simple_config_Attribute_Type_Model_Name,
		simple_config_Attribute_Type_Model_Number,
		simple_config_Attribute_Type_Serial_Number,
		simple_config_Attribute_Type_Primary_Device_Type,
		simple_config_Attribute_Type_Device_Name,
		simple_config_Attribute_Type_RF_Band,
		simple_config_Attribute_Type_Association_State,
		simple_config_Attribute_Type_Device_Password_ID,
		simple_config_Attribute_Type_Configuration_Error,
		simple_config_Attribute_Type_OS_Version,
	};

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_M1(
	const simple_config_payloads_c * const payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_M1()\n"),
		 (m_is_client == true ? "client": "server")));

	if (verify_state(simple_config_state_wait_M1) == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	set_state(simple_config_state_process_M1);

	eap_status_e status = payloads->check_payloads_existense(
		needed_payloads_of_M1, // const simple_config_Attribute_Type_e * const needed_payloads,
		sizeof(needed_payloads_of_M1)/sizeof(needed_payloads_of_M1[0]));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Save Enrollee Nonce.
	status = payloads->get_attribute_data(
		simple_config_Attribute_Type_Enrollee_Nonce,
		&m_enrollee_nonce);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Save Enrollee MAC.
	status = payloads->get_attribute_data(
		simple_config_Attribute_Type_MAC_Address,
		&m_enrollee_mac);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Save Public Key.
	status = payloads->get_attribute_data(
		simple_config_Attribute_Type_Public_Key,
		&m_peer_public_dhe_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		u16_t data(0ul);

		status = payloads->get_attribute_data(
			simple_config_Attribute_Type_Device_Password_ID,
			&data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_received_Device_Password_ID = static_cast<simple_config_Device_Password_ID_e>(data);
	}

	eap_variable_data_c dhe_shared_secret(m_am_tools);

	if (dhe_shared_secret.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = generate_dhe_shared_secret(&m_peer_public_dhe_key, &dhe_shared_secret);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = generate_kdk(
		&dhe_shared_secret,
		&m_enrollee_nonce,
		&m_enrollee_mac,
		&m_registrar_nonce,
		&m_kdk);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = derive_additional_keys(
		&m_kdk,
		&m_auth_key,
		&m_key_wrap_key,
		&m_EMSK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_allow_message_send = false;

	status = m_am_simple_config_services->query_network_and_device_parameters(get_state());

	m_allow_message_send = true;

	if (status == eap_status_pending_request)
	{
		// This is pending query, that will be completed by
		// complete_query_network_and_device_parameters() call.
		m_pending_query_network_and_device_parameters = true;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status == eap_status_completed_request)
	{
		// This is already completed by complete_query_network_and_device_parameters() call.

		status = check_sent_simple_config_message();

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status == eap_status_ok)
	{
		// This is also an error case, because this call is always completed on success. 
		status = eap_status_process_general_error;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else // All other status values means error, because this call is always completed on success.
	{
		// This is an error case.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

//--------------------------------------------------

static const simple_config_Attribute_Type_e needed_payloads_of_M2[]
	= {
		simple_config_Attribute_Type_Version,
		simple_config_Attribute_Type_Message_Type,
		simple_config_Attribute_Type_Enrollee_Nonce,
		simple_config_Attribute_Type_Registrar_Nonce,
		simple_config_Attribute_Type_UUID_R,
		simple_config_Attribute_Type_Public_Key,
		simple_config_Attribute_Type_Authentication_Type_Flags,
		simple_config_Attribute_Type_Encryption_Type_Flags,
		simple_config_Attribute_Type_Connection_Type_Flags,
		simple_config_Attribute_Type_Config_Methods,
		simple_config_Attribute_Type_Manufacturer,
		simple_config_Attribute_Type_Model_Name,
		simple_config_Attribute_Type_Model_Number,
		simple_config_Attribute_Type_Serial_Number,
		simple_config_Attribute_Type_Primary_Device_Type,
		simple_config_Attribute_Type_Device_Name,
		simple_config_Attribute_Type_RF_Band,
		simple_config_Attribute_Type_Association_State,
		simple_config_Attribute_Type_Configuration_Error,
		simple_config_Attribute_Type_Device_Password_ID,
		simple_config_Attribute_Type_OS_Version,
		simple_config_Attribute_Type_Authenticator,
	};

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_M2(
	const simple_config_payloads_c * const payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_M2()\n"),
		 (m_is_client == true ? "client": "server")));

	if (verify_state(simple_config_state_wait_M2) == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	eap_status_e status = payloads->check_payloads_existense(
		needed_payloads_of_M2, // const simple_config_Attribute_Type_e * const needed_payloads,
		sizeof(needed_payloads_of_M2)/sizeof(needed_payloads_of_M2[0]));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		// Verify Enrollee Nonce.
		simple_config_variable_data_c * const enrollee_nonce
			= payloads->get_attribute_pointer(simple_config_Attribute_Type_Enrollee_Nonce);
		if (enrollee_nonce == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
		}

		if (m_enrollee_nonce.compare(
				enrollee_nonce->get_data(enrollee_nonce->get_data_length()),
				enrollee_nonce->get_data_length()) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
		}
	}


	eap_variable_data_c registrar_nonce_data(m_am_tools);

	if (registrar_nonce_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = payloads->get_attribute_data(
		simple_config_Attribute_Type_Registrar_Nonce,
		&registrar_nonce_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	eap_variable_data_c registrar_public_key_data(m_am_tools);

	if (registrar_public_key_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c auth_key(m_am_tools);

	if (auth_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c key_wrap_key(m_am_tools);

	if (key_wrap_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c EMSK(m_am_tools);

	if (EMSK.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		// Save Registrar Public Key.
		status = payloads->get_attribute_data(
			simple_config_Attribute_Type_Public_Key,
			&registrar_public_key_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		eap_variable_data_c dhe_shared_secret(m_am_tools);

		if (dhe_shared_secret.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = generate_dhe_shared_secret(&registrar_public_key_data, &dhe_shared_secret);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_variable_data_c kdk(m_am_tools);

		if (kdk.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = generate_kdk(
			&dhe_shared_secret,
			&m_enrollee_nonce,
			&m_enrollee_mac,
			&registrar_nonce_data,
			&kdk);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = derive_additional_keys(
			&kdk,
			&auth_key,
			&key_wrap_key,
			&EMSK);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = verify_nonces_and_authenticator(
		&auth_key,
		&m_enrollee_nonce,
		&registrar_nonce_data,
		payloads,
		false, // No Enrolle Nonce
		true, // Check Registrar Nonce
		true); // Check Authenticator
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Check Device Password ID.

	{
		u16_t data(0ul);

		status = payloads->get_attribute_data(
			simple_config_Attribute_Type_Device_Password_ID,
			&data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_received_Device_Password_ID = static_cast<simple_config_Device_Password_ID_e>(data);

#if 0 // This is done to bypass some external registrar. We do not test Device Password ID.
		if (m_received_Device_Password_ID != m_local_Device_Password_ID)
		{
			// No matching Device Password ID.
			if (m_local_Device_Password_ID == simple_config_Device_Password_ID_Default_PIN)
			{
				m_handshake_error = eap_status_pin_code_authentication_not_supported;
			}
			else if (m_local_Device_Password_ID == simple_config_Device_Password_ID_PushButton)
			{
				m_handshake_error = eap_status_push_button_authentication_not_supported;
			}
			else
			{
				m_handshake_error = eap_status_network_authentication_failure;
			}

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, m_handshake_error);
		}
#endif
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Save Registrar Nonce.
	status = m_registrar_nonce.set_copy_of_buffer(&registrar_nonce_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Save Registrar Public Key.
	status = m_peer_public_dhe_key.set_copy_of_buffer(&registrar_public_key_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Save Authentication Key.
	status = m_auth_key.set_copy_of_buffer(&auth_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Save Key Wrap Key.
	status = m_key_wrap_key.set_copy_of_buffer(&key_wrap_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Save EMSK.
	status = m_EMSK.set_copy_of_buffer(&EMSK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = cancel_M2D_received_timeout();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = send_M3();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

static const simple_config_Attribute_Type_e needed_payloads_of_M2D[]
	= {
		simple_config_Attribute_Type_Version,
		simple_config_Attribute_Type_Message_Type,
		simple_config_Attribute_Type_Enrollee_Nonce,
		simple_config_Attribute_Type_Registrar_Nonce,
		simple_config_Attribute_Type_UUID_R,
		simple_config_Attribute_Type_Authentication_Type_Flags,
		simple_config_Attribute_Type_Encryption_Type_Flags,
		simple_config_Attribute_Type_Connection_Type_Flags,
		simple_config_Attribute_Type_Config_Methods,
		simple_config_Attribute_Type_Manufacturer,
		simple_config_Attribute_Type_Model_Name,
		simple_config_Attribute_Type_Model_Number,
		simple_config_Attribute_Type_Serial_Number,
		simple_config_Attribute_Type_Primary_Device_Type,
		simple_config_Attribute_Type_Device_Name,
		simple_config_Attribute_Type_RF_Band,
		simple_config_Attribute_Type_Association_State,
		simple_config_Attribute_Type_Configuration_Error,
		simple_config_Attribute_Type_OS_Version,
	};

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_M2D(
	const simple_config_payloads_c * const payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_M2D()\n"),
		 (m_is_client == true ? "client": "server")));

	if (verify_state(simple_config_state_wait_M2) == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	eap_status_e status = payloads->check_payloads_existense(
		needed_payloads_of_M2D, // const simple_config_Attribute_Type_e * const needed_payloads,
		sizeof(needed_payloads_of_M2D)/sizeof(needed_payloads_of_M2D[0]));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Save Registrar Nonce.
	status = payloads->get_attribute_data(
		simple_config_Attribute_Type_Registrar_Nonce,
		&m_registrar_nonce);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_handshake_error == eap_status_ok
		|| m_handshake_error == eap_status_authentication_failure)
	{
		u8_t RF_Band(simple_config_RF_Bands_2_4_GHz);

		status = payloads->get_attribute_data(
			simple_config_Attribute_Type_RF_Band,
			&RF_Band);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		simple_config_RF_Bands_e received_bands = static_cast<simple_config_RF_Bands_e>(RF_Band);

		if ((received_bands & m_Rf_Bands) == 0)
		{
			// No matching RF Band.
			if ((m_Rf_Bands & simple_config_RF_Bands_2_4_GHz) != 0)
			{
				m_handshake_error = eap_status_rf_band_2_4_ghz_not_supported;
			}
			else if ((m_Rf_Bands & simple_config_RF_Bands_5_0_GHz) != 0)
			{
				m_handshake_error = eap_status_rf_band_5_0_ghz_not_supported;
			}
		}

	}

	if (m_handshake_error == eap_status_ok
		|| m_handshake_error == eap_status_authentication_failure)
	{
		u16_t error(0ul);

		status = payloads->get_attribute_data(
			simple_config_Attribute_Type_Configuration_Error,
			&error);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		simple_config_Configuration_Error_e received_error = static_cast<simple_config_Configuration_Error_e>(error);

		if (received_error != simple_config_Configuration_Error_No_Error)
		{
			if (received_error == simple_config_Configuration_Error_OOB_Interface_Read_Error)
			{
				m_handshake_error = eap_status_oob_interface_read_error;
			}
			else if (received_error == simple_config_Configuration_Error_Decryption_CRC_Failure)
			{
				m_handshake_error = eap_status_decryption_crc_failure;
			}
			else if (received_error == simple_config_Configuration_Error_2_4_channel_not_supported)
			{
				m_handshake_error = eap_status_rf_band_2_4_ghz_not_supported;
			}
			else if (received_error == simple_config_Configuration_Error_5_0_channel_not_supported)
			{
				m_handshake_error = eap_status_rf_band_5_0_ghz_not_supported;
			}
			else if (received_error == simple_config_Configuration_Error_Signal_too_weak)
			{
				m_handshake_error = eap_status_signal_too_weak;
			}
			else if (received_error == simple_config_Configuration_Error_Network_auth_failure)
			{
				m_handshake_error = eap_status_network_authentication_failure;
			}
			else if (received_error == simple_config_Configuration_Error_Network_association_failure)
			{
				m_handshake_error = eap_status_network_association_failure;
			}
			else if (received_error == simple_config_Configuration_Error_No_DHCP_response)
			{
				m_handshake_error = eap_status_no_dhcp_response;
			}
			else if (received_error == simple_config_Configuration_Error_Failed_DHCP_config)
			{
				m_handshake_error = eap_status_failed_dhcp_configure;
			}
			else if (received_error == simple_config_Configuration_Error_IP_address_conflict)
			{
				m_handshake_error = eap_status_ip_address_conflict;
			}
			else if (received_error == simple_config_Configuration_Error_Couldnt_connect_to_Registrar)
			{
				m_handshake_error = eap_status_could_not_connect_to_registrar;
			}
			else if (received_error == simple_config_Configuration_Error_Multiple_PBC_sessions_detected)
			{
				m_handshake_error = eap_status_multiple_pbc_sessions_detected;
			}
			else if (received_error == simple_config_Configuration_Error_Rogue_activity_suspected)
			{
				m_handshake_error = eap_status_rogue_activity_suspected;
			}
			else if (received_error == simple_config_Configuration_Error_Device_busy)
			{
				m_handshake_error = eap_status_device_busy;
			}
			else if (received_error == simple_config_Configuration_Error_Setup_locked)
			{
				m_handshake_error = eap_status_setup_locked;
			}
			else if (received_error == simple_config_Configuration_Error_Message_Timeout)
			{
				m_handshake_error = eap_status_message_timeout;
			}
			else if (received_error == simple_config_Configuration_Error_Registration_Session_Timeout)
			{
				m_handshake_error = eap_status_registration_session_timeout;
			}
			else if (received_error == simple_config_Configuration_Error_Device_Password_Auth_Failure)
			{
				m_handshake_error = eap_status_device_password_authentication_failure;
			}
		}

	}

	if (m_handshake_error == eap_status_ok)
	{
		m_handshake_error = eap_status_authentication_failure;
	}

	status = initialize_M2D_received_timeout();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		simple_config_payloads_c * const copied_payloads = payloads->copy();

		if (copied_payloads == 0
			|| copied_payloads->get_is_valid() == false)
		{
			delete copied_payloads;

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = m_M2D_payloads.add_object(copied_payloads, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = send_WSC_ACK();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

static const simple_config_Attribute_Type_e needed_payloads_of_M3[]
	= {
		simple_config_Attribute_Type_Version,
		simple_config_Attribute_Type_Message_Type,
		simple_config_Attribute_Type_Registrar_Nonce,
		simple_config_Attribute_Type_E_Hash1,
		simple_config_Attribute_Type_E_Hash2,
		simple_config_Attribute_Type_Authenticator,
	};

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_M3(
	const simple_config_payloads_c * const payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_M3()\n"),
		 (m_is_client == true ? "client": "server")));

	if (verify_state(simple_config_state_wait_M3) == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	eap_status_e status = payloads->check_payloads_existense(
		needed_payloads_of_M3, // const simple_config_Attribute_Type_e * const needed_payloads,
		sizeof(needed_payloads_of_M3)/sizeof(needed_payloads_of_M3[0]));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Save E-Hash1 and E-Hash2

	status = payloads->get_attribute_data(
		simple_config_Attribute_Type_E_Hash1,
		&m_EHash1);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->get_attribute_data(
		simple_config_Attribute_Type_E_Hash2,
		&m_EHash2);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = send_M4();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

//--------------------------------------------------

static const simple_config_Attribute_Type_e needed_payloads_of_M4[]
	= {
		simple_config_Attribute_Type_Version,
		simple_config_Attribute_Type_Message_Type,
		simple_config_Attribute_Type_Enrollee_Nonce,
		simple_config_Attribute_Type_R_Hash1,
		simple_config_Attribute_Type_R_Hash2,
		simple_config_Attribute_Type_Encrypted_Settings,
		simple_config_Attribute_Type_Authenticator,
	};

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_M4(
	const simple_config_payloads_c * const payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_M4()\n"),
		 (m_is_client == true ? "client": "server")));

	if (verify_state(simple_config_state_wait_M4) == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	eap_status_e status = payloads->check_payloads_existense(
		needed_payloads_of_M4, // const simple_config_Attribute_Type_e * const needed_payloads,
		sizeof(needed_payloads_of_M4)/sizeof(needed_payloads_of_M4[0]));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Save R-Hash1 and R-Hash2

	status = payloads->get_attribute_data(
		simple_config_Attribute_Type_R_Hash1,
		&m_RHash1);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = payloads->get_attribute_data(
		simple_config_Attribute_Type_R_Hash2,
		&m_RHash2);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		// Decrypt Encrypted Settings.
		simple_config_variable_data_c * const Encrypted_Settings
			= payloads->get_attribute_pointer(simple_config_Attribute_Type_Encrypted_Settings);
		if (Encrypted_Settings == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
		}

		simple_config_payloads_c * plaintext_payloads = new simple_config_payloads_c(m_am_tools);
		eap_automatic_variable_c<simple_config_payloads_c> automatic_plaintext_payloads(m_am_tools, plaintext_payloads);

		if (plaintext_payloads == 0
			|| plaintext_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = decrypt_payloads(
			&m_auth_key,
			&m_key_wrap_key,
			Encrypted_Settings,
			plaintext_payloads);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		status = plaintext_payloads->get_attribute_data(
			simple_config_Attribute_Type_R_SNonce1,
			&m_R_SNonce1);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		eap_variable_data_c local_RHash1(m_am_tools);

		if (local_RHash1.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Verify m_R_SNonce1 and m_RHash1.
		status = generate_er_hashs(
			true,
			&m_device_password,
			&m_own_public_dhe_key,
			&m_peer_public_dhe_key,
			&m_PSK1,
			&m_R_SNonce1,
			&local_RHash1,
			0,
			0,
			0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Compare RHash1.
		if (local_RHash1.compare(&m_RHash1) != 0)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("local_RHash1"),
				 local_RHash1.get_data(),
				 local_RHash1.get_data_length()));
			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("m_RHash1"),
				 m_RHash1.get_data(),
				 m_RHash1.get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_device_password_authentication_failure);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = send_M5();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

static const simple_config_Attribute_Type_e needed_payloads_of_M5[]
	= {
		simple_config_Attribute_Type_Version,
		simple_config_Attribute_Type_Message_Type,
		simple_config_Attribute_Type_Registrar_Nonce,
		simple_config_Attribute_Type_Encrypted_Settings,
		simple_config_Attribute_Type_Authenticator,
	};

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_M5(
	const simple_config_payloads_c * const payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_M5()\n"),
		 (m_is_client == true ? "client": "server")));

	if (verify_state(simple_config_state_wait_M5) == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	eap_status_e status = payloads->check_payloads_existense(
		needed_payloads_of_M5, // const simple_config_Attribute_Type_e * const needed_payloads,
		sizeof(needed_payloads_of_M5)/sizeof(needed_payloads_of_M5[0]));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		// Decrypt Encrypted Settings.
		simple_config_variable_data_c * const Encrypted_Settings
			= payloads->get_attribute_pointer(simple_config_Attribute_Type_Encrypted_Settings);
		if (Encrypted_Settings == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
		}

		simple_config_payloads_c * plaintext_payloads = new simple_config_payloads_c(m_am_tools);
		eap_automatic_variable_c<simple_config_payloads_c> automatic_plaintext_payloads(m_am_tools, plaintext_payloads);

		if (plaintext_payloads == 0
			|| plaintext_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = decrypt_payloads(
			&m_auth_key,
			&m_key_wrap_key,
			Encrypted_Settings,
			plaintext_payloads);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		status = plaintext_payloads->get_attribute_data(
			simple_config_Attribute_Type_E_SNonce1,
			&m_E_SNonce1);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		eap_variable_data_c local_EHash1(m_am_tools);

		if (local_EHash1.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Verify m_E_SNonce1 and m_EHash1.
		status = generate_er_hashs(
			true,
			&m_device_password,
			&m_peer_public_dhe_key,
			&m_own_public_dhe_key,
			&m_PSK1,
			&m_E_SNonce1,
			&local_EHash1,
			0,
			0,
			0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Compare EHash1.
		if (local_EHash1.compare(&m_EHash1) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_device_password_authentication_failure);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = send_M6();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

//--------------------------------------------------

static const simple_config_Attribute_Type_e needed_payloads_of_M6[]
	= {
		simple_config_Attribute_Type_Version,
		simple_config_Attribute_Type_Message_Type,
		simple_config_Attribute_Type_Enrollee_Nonce,
		simple_config_Attribute_Type_Encrypted_Settings,
		simple_config_Attribute_Type_Authenticator,
	};

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_M6(
	const simple_config_payloads_c * const payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_M6()\n"),
		 (m_is_client == true ? "client": "server")));

	if (verify_state(simple_config_state_wait_M6) == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	eap_status_e status = payloads->check_payloads_existense(
		needed_payloads_of_M6, // const simple_config_Attribute_Type_e * const needed_payloads,
		sizeof(needed_payloads_of_M6)/sizeof(needed_payloads_of_M6[0]));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		// Decrypt Encrypted Settings.
		simple_config_variable_data_c * const Encrypted_Settings
			= payloads->get_attribute_pointer(simple_config_Attribute_Type_Encrypted_Settings);
		if (Encrypted_Settings == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
		}

		simple_config_payloads_c * plaintext_payloads = new simple_config_payloads_c(m_am_tools);
		eap_automatic_variable_c<simple_config_payloads_c> automatic_plaintext_payloads(m_am_tools, plaintext_payloads);

		if (plaintext_payloads == 0
			|| plaintext_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = decrypt_payloads(
			&m_auth_key,
			&m_key_wrap_key,
			Encrypted_Settings,
			plaintext_payloads);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		status = plaintext_payloads->get_attribute_data(
			simple_config_Attribute_Type_R_SNonce2,
			&m_R_SNonce2);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		eap_variable_data_c local_RHash2(m_am_tools);

		if (local_RHash2.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Verify m_R_SNonce2 and m_RHash2.
		status = generate_er_hashs(
			true,
			&m_device_password,
			&m_own_public_dhe_key,
			&m_peer_public_dhe_key,
			0,
			0,
			0,
			&m_PSK2,
			&m_R_SNonce2,
			&local_RHash2);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Compare RHash2.
		if (local_RHash2.compare(&m_RHash2) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_device_password_authentication_failure);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = send_M7();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

static const simple_config_Attribute_Type_e needed_payloads_of_M7[]
	= {
		simple_config_Attribute_Type_Version,
		simple_config_Attribute_Type_Message_Type,
		simple_config_Attribute_Type_Registrar_Nonce,
		simple_config_Attribute_Type_Encrypted_Settings,
		simple_config_Attribute_Type_Authenticator,
	};

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_M7(
	const simple_config_payloads_c * const payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_M7()\n"),
		 (m_is_client == true ? "client": "server")));

	if (verify_state(simple_config_state_wait_M7) == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	eap_status_e status = payloads->check_payloads_existense(
		needed_payloads_of_M7, // const simple_config_Attribute_Type_e * const needed_payloads,
		sizeof(needed_payloads_of_M7)/sizeof(needed_payloads_of_M7[0]));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		// Decrypt Encrypted Settings.
		simple_config_variable_data_c * const Encrypted_Settings
			= payloads->get_attribute_pointer(simple_config_Attribute_Type_Encrypted_Settings);
		if (Encrypted_Settings == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
		}

		simple_config_payloads_c * plaintext_payloads = new simple_config_payloads_c(m_am_tools);
		eap_automatic_variable_c<simple_config_payloads_c> automatic_plaintext_payloads(m_am_tools, plaintext_payloads);

		if (plaintext_payloads == 0
			|| plaintext_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = decrypt_payloads(
			&m_auth_key,
			&m_key_wrap_key,
			Encrypted_Settings,
			plaintext_payloads);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		status = plaintext_payloads->get_attribute_data(
			simple_config_Attribute_Type_E_SNonce2,
			&m_E_SNonce2);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		eap_variable_data_c local_EHash2(m_am_tools);

		if (local_EHash2.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Verify m_E_SNonce2 and m_EHash2.
		status = generate_er_hashs(
			true,
			&m_device_password,
			&m_peer_public_dhe_key,
			&m_own_public_dhe_key,
			0,
			0,
			0,
			&m_PSK2,
			&m_E_SNonce2,
			&local_EHash2);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Compare RHash2.
		if (local_EHash2.compare(&m_EHash2) != 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_device_password_authentication_failure);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = send_M8();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

//--------------------------------------------------

eap_status_e simple_config_record_c::fix_incorrect_network_key(
	eap_variable_data_c * const network_key, 
	const simple_config_Authentication_Type_e authentication_type)
{
	if (authentication_type == simple_config_Authentication_Type_WPAPSK
		|| authentication_type == simple_config_Authentication_Type_WPA2PSK)
	{
		// For example, Vista External Registar sends incorrect WPA(2)PSK that includes terminating NULL.
		// Check the PSK is passphrase <= 64 bytes in length and the last byte is 0x00.
		const u32_t ONE_CHARACTER_LENGTH = 1ul;
		const u8_t STRING_TERMINATING_NULL = 0x00;

		if (network_key->get_data_length() > 0ul)
		{
			if (network_key->get_data_offset(network_key->get_data_length()-1ul, ONE_CHARACTER_LENGTH) != 0
			&& *(network_key->get_data_offset(network_key->get_data_length()-1ul, ONE_CHARACTER_LENGTH)) == STRING_TERMINATING_NULL)
			{
				// Check for passphrase characters. If it includes only passphrase characters and the last byte is NULL
				// we assume it is broken passphrase.

				bool remove_terminating_null = true;

				if (network_key->get_data_length() == 2ul*EAPOL_WPA_PSK_LENGTH_BYTES)
				{
					for (u32_t ind = 0; ind < network_key->get_data_length()-1ul; ind++)
					{
						u8_t * const character = network_key->get_data_offset(ind, 1);
						if (character == 0)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
						}

						if((*character < 32) || (126 < *character))
						{
							// This is not passphrase.
							remove_terminating_null = false;
							break;
						}
					}
				}
				else
				{
					// Because the length is less than 64 bytes, this is passprase, and we remove the terminating NULL.
				}

				if (remove_terminating_null == true)
				{
					network_key->set_data_length(network_key->get_data_length()-1ul);
				}
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

static const simple_config_Attribute_Type_e needed_payloads_of_M8[]
	= {
		simple_config_Attribute_Type_Version,
		simple_config_Attribute_Type_Message_Type,
	};

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_M8(
	const simple_config_payloads_c * const payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_M8()\n"),
		 (m_is_client == true ? "client": "server")));

	if (verify_state(simple_config_state_wait_M8) == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	eap_status_e status = payloads->check_payloads_existense(
		needed_payloads_of_M8, // const simple_config_Attribute_Type_e * const needed_payloads,
		sizeof(needed_payloads_of_M8)/sizeof(needed_payloads_of_M8[0]));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	simple_config_payloads_c * other_configuration = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_other_configuration(m_am_tools, other_configuration);
	
	if (other_configuration == 0
		|| other_configuration->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_array_c<simple_config_credential_c> * credential_array = new eap_array_c<simple_config_credential_c>(m_am_tools);
	eap_automatic_variable_c<eap_array_c<simple_config_credential_c> > automatic_credential_array(m_am_tools, credential_array);

	if (credential_array == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		// Decrypt Encrypted Settings.
		simple_config_variable_data_c * const Encrypted_Settings
			= payloads->get_attribute_pointer(simple_config_Attribute_Type_Encrypted_Settings);
		if (Encrypted_Settings == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
		}

		simple_config_payloads_c * plaintext_payloads = new simple_config_payloads_c(m_am_tools);
		eap_automatic_variable_c<simple_config_payloads_c> automatic_plaintext_payloads(m_am_tools, plaintext_payloads);

		if (plaintext_payloads == 0
			|| plaintext_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = decrypt_payloads(
			&m_auth_key,
			&m_key_wrap_key,
			Encrypted_Settings,
			plaintext_payloads);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		simple_config_variable_data_c * Credential_Attribute
			= plaintext_payloads->get_attribute_pointer(simple_config_Attribute_Type_Credential);
		if (Credential_Attribute == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
		}

		do
		{
			simple_config_credential_c * credential = new simple_config_credential_c(m_am_tools);

			eap_automatic_variable_c<simple_config_credential_c> automatic_credential(m_am_tools, credential);

			if (credential == 0
				|| credential->get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			simple_config_payloads_c * Credential_payloads = new simple_config_payloads_c(m_am_tools);
			eap_automatic_variable_c<simple_config_payloads_c> automatic_Credential_payloads(m_am_tools, Credential_payloads);
	
			if (Credential_payloads == 0
				|| Credential_payloads->get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u32_t payload_length(Credential_Attribute->get_data_length());
			u32_t padding_length(0ul);

			status = Credential_payloads->parse_simple_config_payloads(
				Credential_Attribute->get_data(Credential_Attribute->get_data_length()),
				&payload_length,
				&padding_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			{
				u8_t network_index(0ul);

				status = Credential_payloads->get_attribute_data(
					simple_config_Attribute_Type_Network_Index,
					&network_index);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				credential->set_network_index(network_index);
			}

			status = Credential_payloads->get_attribute_data(
				simple_config_Attribute_Type_SSID,
				credential->get_SSID());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			{
				u16_t data(0ul);

				status = Credential_payloads->get_attribute_data(
					simple_config_Attribute_Type_Authentication_Type,
					&data);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				credential->set_Authentication_Type(static_cast<simple_config_Authentication_Type_e>(data));
			}

			{
				u16_t data(0ul);

				status = Credential_payloads->get_attribute_data(
					simple_config_Attribute_Type_Encryption_Type,
					&data);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				credential->set_Encryption_Type(static_cast<simple_config_Encryption_Type_e>(data));
			}

			{
				simple_config_variable_data_c * Network_Key_Index
					= Credential_payloads->get_attribute_pointer(simple_config_Attribute_Type_Network_Key_Index);
				// NOTE, this is optional. Omitted Network_Key_Index defaults to 1.

				simple_config_variable_data_c * Network_Key
					= Credential_payloads->get_attribute_pointer(simple_config_Attribute_Type_Network_Key);

				
				if ( Network_Key == 0 
				        && (credential->get_Authentication_Type() != simple_config_Authentication_Type_Open 
				            || credential->get_Encryption_Type() != simple_config_Encryption_Type_None) )
				{
					// We fail since the required Network Key TLV is missing in a non-open mode.
				    EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
				} 
				else if ( Network_Key == 0 )
				{
                    // This is implemented for IOP reasons. The AP does not send the 
                    // Network Key TLV (required TLV in the spec) in the Open security mode so we do not 
                    // require it. The TLV in Open mode would be empty anyway (length would be zero).
				
		            EAP_TRACE_DEBUG(
		                    m_am_tools,
		                    TRACE_FLAGS_DEFAULT,
		                    (EAPL("simple_config_record_c::process_M8(): Network Key TLV missing but Open network. This is ok.\n")));
				
				    // Just add empty parameters
				    network_key_and_index_c * const obj = new network_key_and_index_c(m_am_tools);
				    if(obj != 0)
				    {                        
                        status = credential->get_network_keys()->add_object(obj, true);
                        if (status != eap_status_ok)
                        {
                            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
                            return EAP_STATUS_RETURN(m_am_tools, status);
                        }
				    }

                }
				else
				{
				    // Normal case, i.e Network Key TLV exists
                    do
    				{
    					network_key_and_index_c * const obj = new network_key_and_index_c(m_am_tools);
    
    					if (obj != 0)
    					{
    						if (Network_Key_Index != 0)
    						{
    							const u8_t * const network_key_index = Network_Key_Index->get_header()->get_data(sizeof(u8_t));
    							if (network_key_index == 0)
    							{
    								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    								return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
    							}
    
    							obj->set_network_key_index(*network_key_index);
    						}
    						else
    						{
    							obj->set_network_key_index(SIMPLE_CONFIG_DEFAULT_NETWORK_KEY_INDEX);
    						}
    
    						status = obj->get_network_key()->set_copy_of_buffer(
    							Network_Key->get_header()->get_data(
    								Network_Key->get_header()->get_data_length()),
    							Network_Key->get_header()->get_data_length());
    						if (status != eap_status_ok)
    						{
    							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    							return EAP_STATUS_RETURN(m_am_tools, status);
    						}
    
    						// For example, Vista External Registar sends incorrect WPA(2)PSK that includes terminating NULL.
    						status = fix_incorrect_network_key(obj->get_network_key(), credential->get_Authentication_Type());
    						if (status != eap_status_ok)
    						{
    							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    							return EAP_STATUS_RETURN(m_am_tools, status);
    						}
    
    
    						status = credential->get_network_keys()->add_object(obj, true);
    						if (status != eap_status_ok)
    						{
    							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    							return EAP_STATUS_RETURN(m_am_tools, status);
    						}
    					}
    
    					if (Network_Key_Index != 0)
    					{
    						Network_Key_Index = Network_Key_Index->get_next_payload_with_same_attribute_type();
    					}
    
    					Network_Key = Network_Key->get_next_payload_with_same_attribute_type();
    				}
    				while(Network_Key != 0);
    			}
			}

			status = Credential_payloads->get_attribute_data(
				simple_config_Attribute_Type_MAC_Address,
				credential->get_MAC_address());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			automatic_credential.do_not_free_variable();

			status = credential_array->add_object(credential, true);

			Credential_Attribute = Credential_Attribute->get_next_payload_with_same_attribute_type();
		}
		while (Credential_Attribute != 0);

		// This is optional attribute.
		if (plaintext_payloads->get_attribute_pointer(
			simple_config_Attribute_Type_New_Password) != 0)
		{
			status = plaintext_payloads->get_attribute_data(
				simple_config_Attribute_Type_New_Password,
				&m_new_password);
			if (status != eap_status_ok
				&& status != eap_status_missing_payload)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (plaintext_payloads->get_attribute_pointer(
			simple_config_Attribute_Type_Device_Password_ID) != 0)
		{
			u16_t data(0ul);

			// This is optional attribute.
			status = plaintext_payloads->get_attribute_data(
				simple_config_Attribute_Type_Device_Password_ID,
				&data);
			if (status != eap_status_ok
				&& status != eap_status_missing_payload)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (status == eap_status_ok)
			{
				m_new_Device_Password_ID = static_cast<simple_config_Device_Password_ID_e>(data);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_am_simple_config_services->save_simple_config_session(
		simple_config_state_simple_config_success,
		credential_array,
		&m_new_password,
		m_new_Device_Password_ID,
		other_configuration);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = send_WSC_Done();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

static const simple_config_Attribute_Type_e needed_payloads_of_WSC_ACK[]
	= {
		simple_config_Attribute_Type_Version,
		simple_config_Attribute_Type_Message_Type,
	};

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_WSC_ACK(
	const simple_config_payloads_c * const payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_WSC_ACK()\n"),
		 (m_is_client == true ? "client": "server")));

	if (verify_state(simple_config_state_wait_WSC_ACK) == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	eap_status_e status = payloads->check_payloads_existense(
		needed_payloads_of_WSC_ACK, // const simple_config_Attribute_Type_e * const needed_payloads,
		sizeof(needed_payloads_of_WSC_ACK)/sizeof(needed_payloads_of_WSC_ACK[0]));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

static const simple_config_Attribute_Type_e needed_payloads_of_WSC_NACK[]
	= {
		simple_config_Attribute_Type_Version,
		simple_config_Attribute_Type_Message_Type,
	};

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_WSC_NACK(
	const simple_config_payloads_c * const payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_WSC_NACK()\n"),
		 (m_is_client == true ? "client": "server")));

	eap_status_e status = payloads->check_payloads_existense(
		needed_payloads_of_WSC_NACK, // const simple_config_Attribute_Type_e * const needed_payloads,
		sizeof(needed_payloads_of_WSC_NACK)/sizeof(needed_payloads_of_WSC_NACK[0]));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_handshake_error != eap_status_ok)
	{
		(void) send_error_notification(m_handshake_error);
	}

	set_state(simple_config_state_failure);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

static const simple_config_Attribute_Type_e needed_payloads_of_WSC_DONE[]
	= {
		simple_config_Attribute_Type_Version,
		simple_config_Attribute_Type_Message_Type,
	};

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_WSC_DONE(
	const simple_config_payloads_c * const payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_WSC_DONE()\n"),
		 (m_is_client == true ? "client": "server")));

	if (verify_state(simple_config_state_wait_WSC_DONE) == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
	}

	eap_status_e status = payloads->check_payloads_existense(
		needed_payloads_of_WSC_DONE, // const simple_config_Attribute_Type_e * const needed_payloads,
		sizeof(needed_payloads_of_WSC_DONE)/sizeof(needed_payloads_of_WSC_DONE[0]));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_state(simple_config_state_simple_config_success);

	{
		// Send state notification to lower layer.
		eap_state_notification_c notification(
			m_am_tools,
			&m_send_network_id,
			m_is_client,
			eap_state_notification_generic,
			eap_protocol_layer_eap,
			eap_type_none,
			eap_state_none,
			eap_state_authentication_finished_successfully,
			0ul,
			false);
		get_type_partner()->state_notification(&notification);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_simple_config_attributes(
	const simple_config_payloads_c * const payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_simple_config_attributes()\n"),
		 (m_is_client == true ? "client": "server")));

	simple_config_variable_data_c * const message_type_payload
		= payloads->get_attribute_pointer(simple_config_Attribute_Type_Message_Type);
	if (message_type_payload == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
	}

	u8_t * const Message_type_data = message_type_payload->get_header()->get_data(sizeof(u8_t));
	if (Message_type_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
	}

	const simple_config_Message_Type_e Message_type(static_cast<simple_config_Message_Type_e>(*Message_type_data));

	eap_status_e status(eap_status_process_general_error);


	{
		eap_simple_config_trace_string_c trace_string;
		EAP_UNREFERENCED_PARAMETER(trace_string);			

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_simple_config_attributes(): Received message %s=%d\n"),
			 (m_is_client == true ? "client": "server"),
			 trace_string.get_message_type_string(Message_type),
			 Message_type));
	}


	switch(Message_type)
	{
	case simple_config_Message_Type_M1:
	case simple_config_Message_Type_M2:
	case simple_config_Message_Type_M2D:
		// Check is done later inside correcponding function.
		break;
	case simple_config_Message_Type_M3:
	case simple_config_Message_Type_M5:
	case simple_config_Message_Type_M7:

		status = verify_nonces_and_authenticator(
			&m_auth_key,
			&m_enrollee_nonce,
			&m_registrar_nonce,
			payloads,
			false, // No Enrolle Nonce
			true, // Check Registrar Nonce
			true); // Check Authenticator
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		break;
	case simple_config_Message_Type_M4:
	case simple_config_Message_Type_M6:
	case simple_config_Message_Type_M8:
		status = verify_nonces_and_authenticator(
			&m_auth_key,
			&m_enrollee_nonce,
			&m_registrar_nonce,
			payloads,
			true, // Check Enrolle Nonce
			false, // No Registrar Nonce
			true); // Check Authenticator
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		break;
	case simple_config_Message_Type_WSC_ACK:
	case simple_config_Message_Type_WSC_NACK:
	case simple_config_Message_Type_WSC_DONE:
		{
			bool check_enrollee_nonce(true);
			bool check_registrar_nonce(true);

			if (get_state() == simple_config_state_wait_M1)
			{
				check_enrollee_nonce = false;
				check_registrar_nonce = false;
			}

			if (get_state() == simple_config_state_wait_M2)
			{
				check_registrar_nonce = false;
			}

			status = verify_nonces_and_authenticator(
				&m_auth_key,
				&m_enrollee_nonce,
				&m_registrar_nonce,
				payloads,
				check_enrollee_nonce,
				check_registrar_nonce,
				false); // No Authenticator
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		break;
	default:
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	};


	switch(Message_type)
	{

	case simple_config_Message_Type_M2:
		status = process_M2(payloads);
		break;
	case simple_config_Message_Type_M2D:
		status = process_M2D(payloads);
		break;
	case simple_config_Message_Type_M4:
		status = process_M4(payloads);
		break;
	case simple_config_Message_Type_M6:
		status = process_M6(payloads);
		break;
	case simple_config_Message_Type_M8:
		status = process_M8(payloads);
		break;
	case simple_config_Message_Type_WSC_ACK:
		status = process_WSC_ACK(payloads);
		break;
	case simple_config_Message_Type_WSC_NACK:
		status = process_WSC_NACK(payloads);
		break;

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

	case simple_config_Message_Type_M1:
		status = process_M1(payloads);
		break;
	case simple_config_Message_Type_M3:
		status = process_M3(payloads);
		break;
	case simple_config_Message_Type_M5:
		status = process_M5(payloads);
		break;
	case simple_config_Message_Type_M7:
		status = process_M7(payloads);
		break;
	case simple_config_Message_Type_WSC_DONE:
		status = process_WSC_DONE(payloads);
		break;

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

	default:
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: SIMPLE_CONFIG: %s: parse_function: process_simple_config_attributes(): Unknown message 0x%08x\n"),
			 (m_is_client == true ? "client": "server"),
			 Message_type));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_unexpected_message);
	};

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::process_simple_config_message()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("SIMPLE_CONFIG: %s: parse_function: simple_config_record_c::process_simple_config_message()\n"),
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("SIMPLE_CONFIG-message"),
		m_received_simple_config_message.get_simple_config_message_data()->get_data(
			m_received_simple_config_message.get_simple_config_message_data()->get_data_length()),
		m_received_simple_config_message.get_simple_config_message_data()->get_data_length()));

	u32_t next_start_offset = 0ul;
	u32_t simple_config_packet_length = m_received_simple_config_message.get_simple_config_message_data()->get_data_length();

	m_received_payloads.reset();

	u32_t padding_length(0ul);

	eap_status_e status = m_received_payloads.parse_simple_config_payloads(
		m_received_simple_config_message.get_simple_config_message_data()->get_data(
			m_received_simple_config_message.get_simple_config_message_data()->get_data_length()),
		&simple_config_packet_length,
		&padding_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (next_start_offset != simple_config_packet_length)
	{
		// Parsed packet length does not match with received packet length.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(
			m_am_tools,
			eap_status_process_illegal_packet_error);
	}


	status = process_simple_config_attributes(&m_received_payloads);

	if (status == eap_status_ok)
	{
		status = cancel_error_message_timeout();
	}
	else
	{
		if (m_handshake_error == eap_status_ok)
		{
			// Save the first error.
			m_handshake_error = status;
		}

		status = initalize_error_message_timeout();
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::are_pending_queries_completed()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_pending_request;

	if (m_pending_query_network_and_device_parameters == false)
	{
		status = eap_status_ok;
	}

	eap_status_string_c status_string;
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: pending_function: are_pending_queries_completed(): %s\n"),
		(m_is_client == true ? "client": "server"),
		status_string.get_status_string(status)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::indicate_state_to_lower_layer(
	const simple_config_state_e indicated_state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Notify lower layer the state of SIMPLE_CONFIG.

	eap_simple_config_trace_string_c state_string;
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: state_function: indicate_state_to_lower_layer(): %s\n"),
		(m_is_client == true ? "client": "server"),
		state_string.get_state_string(indicated_state)));

	eap_state_notification_c notification(
		m_am_tools,
		&m_send_network_id,
		m_is_client,
		eap_state_notification_generic,
		eap_protocol_layer_internal_type,
		eap_type_none,
		simple_config_state_none,
		indicated_state,
		0,
		false);
	get_type_partner()->state_notification(&notification);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::indicate_messages_processed()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Notify lower layer that SIMPLE_CONFIG-messages are processed.

	eap_simple_config_trace_string_c state_string;
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: state_function: indicate_messages_processed(): %s\n"),
		(m_is_client == true ? "client": "server"),
		state_string.get_state_string(m_simple_config_state)));

	eap_state_notification_c notification(
		m_am_tools,
		&m_send_network_id,
		m_is_client,
		eap_state_notification_generic,
		eap_protocol_layer_internal_type,
		eap_type_none,
		simple_config_state_none,
		simple_config_state_pending_simple_config_messages_processed,
		0,
		false);
	get_type_partner()->state_notification(&notification);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::send_simple_config_message()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: send_function: simple_config_record_c::send_simple_config_message()\n"),
		 (m_is_client == true ? "client": "server")));

	eap_variable_data_c simple_config_message_buffer(m_am_tools);

	if (simple_config_message_buffer.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// --------------------------------------------------------------------

	eap_buf_chain_wr_c sent_packet(
		eap_write_buffer,
		m_am_tools,
		m_new_simple_config_message.get_simple_config_message_data()->get_data(simple_config_message_buffer.get_data_length()),
		m_new_simple_config_message.get_simple_config_message_data()->get_data_length(),
		false,
		false,
		0ul);
	if (sent_packet.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send SIMPLE_CONFIG-message"),
		 sent_packet.get_data(sent_packet.get_data_length()),
		 sent_packet.get_data_length()));

	// --------------------------------------------------------------------
	
    // Send message
	eap_status_e status = get_type_partner()->simple_config_packet_send(
		&sent_packet,
		m_current_simple_config_message_type);
	
	if (status != eap_status_ok)
    {
        EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
        return EAP_STATUS_RETURN(m_am_tools, status);
    }

	status = m_previous_simple_config_message.get_simple_config_message_data()->set_copy_of_buffer(
		m_new_simple_config_message.get_simple_config_message_data());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_new_simple_config_message.reset();
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::check_sent_simple_config_message()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: send_function: simple_config_record_c::check_sent_simple_config_message()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e msg_status = eap_status_authentication_failure;

	if (m_already_in_completion_action_check == true)
	{
		// This is recursive call. Do not process yet.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	if (m_force_simple_config_message_send == true)
	{
		// There may be an alert message pending.
		msg_status = send_simple_config_message();
	}
	else
	{
		msg_status = are_pending_queries_completed();
		if (msg_status == eap_status_ok)
		{
			eap_status_e compl_status = completion_action_check();

			if (compl_status == eap_status_pending_request)
			{
				// Some asyncronous query is still pending.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, compl_status);
			}
			else if (compl_status != eap_status_ok)
			{
				// There may be Alert message to be sent.
				msg_status = compl_status;
			}


			if (m_allow_message_send == true)
			{
				if (msg_status == eap_status_ok
					&& m_new_simple_config_message.get_simple_config_message_data()->get_is_valid_data() == true)
				{
					// We could send the pending SIMPLE_CONFIG-messages.
					msg_status = send_simple_config_message();
				}
				else if (m_force_simple_config_message_send == true // There may be Alert message to be sent.
					&& m_new_simple_config_message.get_simple_config_message_data()->get_is_valid_data() == true)
				{
					// We could send the pending SIMPLE_CONFIG-messages.
					send_simple_config_message();
				}
				else
				{
					// No message to sent.
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("SIMPLE_CONFIG: %s: send_function: simple_config_record_c::check_sent_simple_config_message(), ")
						 EAPL("No message to sent.\n"),
						(m_is_client == true ? "client": "server")));
				}
			}

			if (msg_status == eap_status_ok
				&& m_allow_message_send == true)
			{
				eap_status_e indication_status = indicate_messages_processed();
				if (indication_status != eap_status_ok)
				{
					// This is an error case.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, indication_status);
				}
			}
		}
	}

	if (get_state() == simple_config_state_simple_config_success)
	{
		// Notify lower layer that SIMPLE_CONFIG/PEAP ended successfully

		eap_simple_config_trace_string_c simple_config_trace;

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s: SIMPLE_CONFIG/PEAP authentication ")
			 EAPL("SUCCESS: EAP-type %s\n"),
			 (m_is_client == true ? "client": "server"),
			 eap_header_string_c::get_eap_type_string(eap_expanded_type_simple_config.get_type())));

		eap_status_e notification_status = indicate_state_to_lower_layer(get_state());
		if (notification_status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, notification_status);
		}
	}
	else if (get_state() == simple_config_state_failure)
	{
		eap_simple_config_trace_string_c simple_config_trace;

		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("%s: SIMPLE_CONFIG/PEAP authentication ")
			 EAPL("FAILED: EAP-type %s\n"),
			 (m_is_client == true ? "client": "server"),
			 eap_header_string_c::get_eap_type_string(eap_expanded_type_simple_config.get_type())));

		eap_status_e notification_status = indicate_state_to_lower_layer(get_state());
		if (notification_status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, notification_status);
		}
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, msg_status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::packet_process(
	eap_variable_data_c * const simple_config_packet,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_simple_config_trace_string_c state_trace;
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: message_function: packet_process(): state %s\n"),
		(m_is_client == true ? "client": "server"),
		state_trace.get_state_string(get_state())));

	m_received_simple_config_message.reset();

	eap_status_e status = m_received_simple_config_message.set_simple_config_message_data(
		simple_config_packet,
		received_eap_identifier);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_automatic_simple_value_c<bool> restore_allow_message_send(
		m_am_tools,
		&m_allow_message_send,
		true);

	// Packet send is delayed until after the process_simple_config_message() function returns.
	m_allow_message_send = false;

	status = process_simple_config_message();

	m_allow_message_send = true;


	if (status != eap_status_pending_request)
	{
		// Note this call will return eap_status_pending_request if any asyncronous call is pending.
		eap_status_e send_status = check_sent_simple_config_message();
		if (send_status != eap_status_ok)
		{
			status = send_status;
		}
	}

	if (get_state() == simple_config_state_simple_config_success)
	{
		// Send state notification to lower layer.
		eap_state_notification_c notification(
			m_am_tools,
			&m_send_network_id,
			m_is_client,
			eap_state_notification_generic,
			eap_protocol_layer_eap,
			eap_type_none,
			eap_state_none,
			eap_state_authentication_finished_successfully,
			0ul,
			false);
		get_type_partner()->state_notification(&notification);
	}


	if (status == eap_status_success
		&& get_state() != simple_config_state_simple_config_success)
	{
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool simple_config_record_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: function: simple_config_record_c::reset(): this = 0x%08x\n"),
		(m_is_client == true ? "client": "server"),
		this));

	completion_action_clenup();

	m_M2D_payloads.reset();

	m_handshake_error = eap_status_ok;
	m_Rf_Bands = simple_config_RF_Bands_2_4_GHz;

	m_received_simple_config_message.reset();
	m_new_simple_config_message.reset();
	m_own_private_dhe_key.reset();
	m_own_public_dhe_key.reset();
	m_peer_public_dhe_key.reset();
	m_shared_dh_key.reset();
	m_dhe_prime.reset();
	m_dhe_group_generator.reset();
	m_signed_message_hash.reset();
	m_NAI.reset();
	m_NAI_realm.reset();

	m_completion_queue.reset();

	m_key_material_generated = false;

	m_force_simple_config_message_send = false;

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)
	if (m_is_client == false)
	{
		// Server
		// NOTE: set_state() function cannot reset state.
		m_simple_config_state = simple_config_state_wait_M1;
	}
	else
#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)
	{
		// Client
		// NOTE: set_state() function cannot reset state.
		m_simple_config_state = simple_config_state_wait_simple_config_start;
	}

	eap_status_e status = generate_dhe_keys();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::generate_dhe_keys()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s:     key_function: generate_dhe_keys()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status = eap_status_not_supported;

	{
		m_dhe_prime.reset();

		status = m_dhe_prime.add_data(SIMPLE_CONFIG_DIFFIE_HELLMAN_PRIME, sizeof(SIMPLE_CONFIG_DIFFIE_HELLMAN_PRIME));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_dhe_group_generator.reset();

		status = m_dhe_group_generator.add_data(SIMPLE_CONFIG_DIFFIE_HELLMAN_GROUP_GENERATOR, sizeof(SIMPLE_CONFIG_DIFFIE_HELLMAN_GROUP_GENERATOR));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		crypto_ephemeral_diffie_hellman_c dhe(m_am_tools);

		if (dhe.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: %s:     key_function: dhe.generate_diffie_hellman_keys()\n"),
			(m_is_client == true ? "client": "server")));

		status = dhe.generate_diffie_hellman_keys(
			&m_own_private_dhe_key,
			&m_own_public_dhe_key,
			m_dhe_prime.get_data(m_dhe_prime.get_data_length()),
			m_dhe_prime.get_data_length(),
			m_dhe_group_generator.get_data(m_dhe_group_generator.get_data_length()),
			m_dhe_group_generator.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::generate_dhe_shared_secret(
	const eap_variable_data_c * const peer_public_key_data,
	eap_variable_data_c * const dhe_shared_secret)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s:     key_function: generate_dhe_shared_secret()\n"),
		(m_is_client == true ? "client": "server")));


	if (m_dhe_prime.get_is_valid_data() == false
		|| m_dhe_group_generator.get_is_valid_data() == false
		|| m_own_private_dhe_key.get_is_valid_data() == false
		|| peer_public_key_data->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	crypto_ephemeral_diffie_hellman_c dhe(m_am_tools);

	if (dhe.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s:     key_function: dhe.generate_g_power_to_xy()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status = dhe.generate_g_power_to_xy(
		&m_own_private_dhe_key,
		peer_public_key_data,
		dhe_shared_secret,
		m_dhe_prime.get_data(),
		m_dhe_prime.get_data_length(),
		m_dhe_group_generator.get_data(),
		m_dhe_group_generator.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("SIMPLE_CONFIG: dhe_shared_secret"),
		dhe_shared_secret->get_data(dhe_shared_secret->get_data_length()),
		dhe_shared_secret->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::generate_nonce(
	eap_variable_data_c * const nonce,
	const u32_t nonce_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s:     key_function: generate_nonce()\n"),
		(m_is_client == true ? "client": "server")));

	// Creates a Nonce.
	crypto_random_c rand(m_am_tools);

	eap_status_e status = nonce->set_buffer_length(nonce_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = nonce->set_data_length(nonce->get_buffer_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = rand.get_rand_bytes(nonce->get_data(), nonce->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::generate_erhash(
	const bool verify,
	const eap_variable_data_c * const half_of_device_password,
	const eap_variable_data_c * const PKE,
	const eap_variable_data_c * const PKR,
	eap_variable_data_c * const PSKn,
	eap_variable_data_c * const ERSn,
	eap_variable_data_c * const ERHash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s:     key_function: generate_erhash()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: PKE"),
		PKE->get_data(),
		PKE->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: PKR"),
		PKR->get_data(),
		PKR->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: half_of_device_password"),
		half_of_device_password->get_data(),
		half_of_device_password->get_data_length()));

	eap_status_e status = keyed_hmac(&m_auth_key, half_of_device_password, PSKn);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = PSKn->set_data_length(SIMPLE_CONFIG_PSKn_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: PSKn"),
		PSKn->get_data(),
		PSKn->get_data_length()));

	if (verify == false)
	{
		status = generate_nonce(
			ERSn,
			SIMPLE_CONFIG_ESn_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: %s:     key_function: generate_erhash(): No new nonce is generated,\n"),
			(m_is_client == true ? "client": "server")));
		EAP_ASSERT(ERSn != 0 && ERSn->get_is_valid_data() == true);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: ERSn"),
		ERSn->get_data(),
		ERSn->get_data_length()));

	{
		eap_variable_data_c hmac_input(m_am_tools);

		if (hmac_input.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = hmac_input.add_data(ERSn);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = hmac_input.add_data(PSKn);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = hmac_input.add_data(PKE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = hmac_input.add_data(PKR);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = keyed_hmac(&m_auth_key, &hmac_input, ERHash);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: ERHash"),
		ERHash->get_data(),
		ERHash->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::generate_er_hashs(
	const bool verify,
	const eap_variable_data_c * const device_password,
	const eap_variable_data_c * const PKE,
	const eap_variable_data_c * const PKR,
	eap_variable_data_c * const PSK1,
	eap_variable_data_c * const ER_S1,
	eap_variable_data_c * const ER_Hash1,
	eap_variable_data_c * const PSK2,
	eap_variable_data_c * const ER_S2,
	eap_variable_data_c * const ER_Hash2)
{
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: generate_er_hashs(): device_password"),
		device_password->get_data(),
		device_password->get_data_length()));

	eap_variable_data_c first_half_of_device_password(m_am_tools);

	if (first_half_of_device_password.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = first_half_of_device_password.set_buffer(device_password);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = first_half_of_device_password.set_data_length((device_password->get_data_length() + 1ul) / 2ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (ER_Hash1 != 0)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Create E/R-Hash1.

		status = generate_erhash(
			verify,
			&first_half_of_device_password,
			PKE,
			PKR,
			PSK1,
			ER_S1,
			ER_Hash1);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: ER_Hash1"),
			ER_Hash1->get_data(),
			ER_Hash1->get_data_length()));
	}

	if (ER_Hash2 != 0)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// Create E/R-Hash2.

		eap_variable_data_c second_half_of_device_password(m_am_tools);

		if (second_half_of_device_password.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t second_half_length(device_password->get_data_length() / 2ul);

		eap_status_e status = second_half_of_device_password.set_buffer(
			device_password->get_data_offset(first_half_of_device_password.get_data_length(), second_half_length),
			second_half_length,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = generate_erhash(
			verify,
			&second_half_of_device_password,
			PKE,
			PKR,
			PSK2,
			ER_S2,
			ER_Hash2);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: ER_Hash2"),
			ER_Hash2->get_data(),
			ER_Hash2->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::keyed_hmac(
	const eap_variable_data_c * const key,
	const eap_variable_data_c * const input,
	eap_variable_data_c * const output)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s:     key_function: keyed_hmac()\n"),
		(m_is_client == true ? "client": "server")));

	crypto_sha_256_c sha_256(m_am_tools);
	if (sha_256.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	crypto_hmac_c hmac_sha_256(
		m_am_tools,
		&sha_256,
		false);
	if (hmac_sha_256.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: key"),
		key->get_data(),
		key->get_data_length()));

	eap_status_e status = hmac_sha_256.hmac_set_key(key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = hmac_sha_256.hmac_update(
		input->get_data(),
		input->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = output->set_buffer_length(hmac_sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = output->set_data_length(hmac_sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t md_length(hmac_sha_256.get_digest_length());

	status = hmac_sha_256.hmac_final(
		output->get_data(hmac_sha_256.get_digest_length()),
		&md_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::generate_kdk(
	const eap_variable_data_c * const dhe_shared_secret,
	const eap_variable_data_c * const nonce_1,
	const eap_variable_data_c * const enrollee_mac,
	const eap_variable_data_c * const nonce_2,
	eap_variable_data_c * const kdk
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s:     key_function: generate_kdk()\n"),
		(m_is_client == true ? "client": "server")));

	crypto_sha_256_c sha_256(m_am_tools);
	if (sha_256.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = sha_256.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: simple_config_record_c::generate_kdk(): dhe_shared_secret"),
		dhe_shared_secret->get_data(),
		dhe_shared_secret->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: simple_config_record_c::generate_kdk(): nonce_1"),
		 nonce_1->get_data(),
		 nonce_1->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: simple_config_record_c::generate_kdk(): enrollee_mac"),
		 enrollee_mac->get_data(),
		 enrollee_mac->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: simple_config_record_c::generate_kdk(): nonce_2"),
		 nonce_2->get_data(),
		 nonce_2->get_data_length()));

	status = sha_256.hash_update(
		dhe_shared_secret->get_data(),
		dhe_shared_secret->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c dh_key(m_am_tools);
	if (dh_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = dh_key.set_buffer_length(sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = dh_key.set_data_length(sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		u32_t md_length(sha_256.get_digest_length());

		status = sha_256.hash_final(
			dh_key.get_data(sha_256.get_digest_length()),
			&md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: dh_key"),
		dh_key.get_data(),
		dh_key.get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - -

	sha_256.hash_cleanup();
	if (sha_256.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	crypto_hmac_c hmac_sha_256(
		m_am_tools,
		&sha_256,
		false);
	if (hmac_sha_256.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = hmac_sha_256.hmac_set_key(&dh_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = hmac_sha_256.hmac_update(
		nonce_1->get_data(),
		nonce_1->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = hmac_sha_256.hmac_update(
		enrollee_mac->get_data(),
		enrollee_mac->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = hmac_sha_256.hmac_update(
		nonce_2->get_data(),
		nonce_2->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = kdk->set_buffer_length(hmac_sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = kdk->set_data_length(hmac_sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		u32_t md_length(hmac_sha_256.get_digest_length());

		status = hmac_sha_256.hmac_final(
			kdk->get_data(hmac_sha_256.get_digest_length()),
			&md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIMPLE_CONFIG: simple_config_record_c::generate_kdk(): kdk"),
			 kdk->get_data(),
			 kdk->get_data_length()));
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::key_derivation_function(
	const eap_variable_data_c * const key,
	const eap_variable_data_c * const personalization_string,
	const u32_t total_key_bits,
	eap_variable_data_c * const result
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s:     key_function: key_derivation_function()\n"),
		(m_is_client == true ? "client": "server")));

	result->reset();

	crypto_sha_256_c sha_256(m_am_tools);
	if (sha_256.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	crypto_hmac_c hmac_sha_256(
		m_am_tools,
		&sha_256,
		false);
	if (hmac_sha_256.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: key"),
		key->get_data(),
		key->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: personalization_string"),
		personalization_string->get_data(),
		personalization_string->get_data_length()));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: total_key_bits %d\n"),
		total_key_bits));

	u32_t prf_digest_size(hmac_sha_256.get_digest_length()*8ul);
	u32_t iterations((total_key_bits + prf_digest_size - 1) / prf_digest_size);

	eap_status_e status = result->set_buffer_length(iterations * hmac_sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = result->set_data_length(iterations * hmac_sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	for (u32_t ind = 0ul; ind != iterations; ++ind)
	{
		status = hmac_sha_256.hmac_set_key(key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		{
			u32_t ind_network_order(eap_htonl(ind+1ul));
			status = hmac_sha_256.hmac_update(
				&ind_network_order,
				sizeof(ind_network_order));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		status = hmac_sha_256.hmac_update(
			personalization_string->get_data(),
			personalization_string->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		{
			u32_t total_key_bits_network_order(eap_htonl(total_key_bits));
			status = hmac_sha_256.hmac_update(
				&total_key_bits_network_order,
				sizeof(total_key_bits_network_order));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		u32_t md_length(hmac_sha_256.get_digest_length());

		status = hmac_sha_256.hmac_final(
			result->get_data_offset(ind*hmac_sha_256.get_digest_length(), hmac_sha_256.get_digest_length()),
			&md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	} // for()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::derive_additional_keys(
	const eap_variable_data_c * const kdk,
	eap_variable_data_c * const auth_key,
	eap_variable_data_c * const key_wrap_key,
	eap_variable_data_c * const EMSK
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s:     key_function: derive_additional_keys()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("SIMPLE_CONFIG simple_config_record_c::derive_additional_keys(): kdk"),
		 kdk->get_data(),
		 kdk->get_data_length()));


	eap_variable_data_c personalization_string(m_am_tools);

	if (personalization_string.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = personalization_string.set_buffer(
		SIMPLE_CONFIG_SECURE_KEY_DERIVATION_LABEL,
		SIMPLE_CONFIG_SECURE_KEY_DERIVATION_LABEL_LENGTH,
		false,
		false);
	if (personalization_string.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c key_expansion(m_am_tools);

	if (key_expansion.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t key_bits(SIMPLE_CONFIG_AUTH_KEY_BITS + SIMPLE_CONFIG_KEY_WRAP_KEY_BITS + SIMPLE_CONFIG_EMSK_BITS);
	u32_t key_bytes((key_bits+7)/8);

	status = key_derivation_function(
		kdk,
		&personalization_string,
		key_bits,
		&key_expansion);

	if (key_expansion.get_is_valid_data() == false
		|| key_expansion.get_data_length() < key_bytes)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	u32_t key_offset(0ul);

	u32_t key_length(SIMPLE_CONFIG_AUTH_KEY_BITS/8ul);

	status = auth_key->set_copy_of_buffer(
		key_expansion.get_data_offset(key_offset, key_length),
		key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	key_offset += key_length;

	key_length = SIMPLE_CONFIG_KEY_WRAP_KEY_BITS/8ul;

	status = key_wrap_key->set_copy_of_buffer(
		key_expansion.get_data_offset(key_offset, key_length),
		key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	key_offset += key_length;

	key_length = SIMPLE_CONFIG_EMSK_BITS/8ul;

	status = EMSK->set_copy_of_buffer(
		key_expansion.get_data_offset(key_offset, key_length),
		key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	key_offset += key_length;


	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: simple_config_record_c::derive_additional_keys():     auth_key"),
		 auth_key->get_data(),
		 auth_key->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: simple_config_record_c::derive_additional_keys(): key_wrap_key"),
		 key_wrap_key->get_data(),
		 key_wrap_key->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: simple_config_record_c::derive_additional_keys():         EMSK"),
		 EMSK->get_data(),
		 EMSK->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::generate_authenticator(
	const eap_variable_data_c * const received_simple_config_message,
	const eap_variable_data_c * const new_simple_config_message_data_without_authenticator,
	eap_variable_data_c * const authenticator)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s:     key_function: generate_authenticator()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status = eap_status_not_supported;

	crypto_sha_256_c sha_256(m_am_tools);
	if (sha_256.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	crypto_hmac_c hmac_sha_256(
		m_am_tools,
		&sha_256,
		false);
	if (hmac_sha_256.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("SIMPLE_CONFIG authenticator m_auth_key"),
		 m_auth_key.get_data(),
		 m_auth_key.get_data_length()));

	status = hmac_sha_256.hmac_set_key(&m_auth_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("SIMPLE_CONFIG authenticator data"),
		 received_simple_config_message->get_data(),
		 received_simple_config_message->get_data_length()));

	status = hmac_sha_256.hmac_update(
		received_simple_config_message->get_data(),
		received_simple_config_message->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("SIMPLE_CONFIG authenticator data"),
		 new_simple_config_message_data_without_authenticator->get_data(),
		 new_simple_config_message_data_without_authenticator->get_data_length()));

	status = hmac_sha_256.hmac_update(
		new_simple_config_message_data_without_authenticator->get_data(),
		new_simple_config_message_data_without_authenticator->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = authenticator->set_buffer_length(hmac_sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = authenticator->set_data_length(hmac_sha_256.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		u32_t md_length(hmac_sha_256.get_digest_length());

		status = hmac_sha_256.hmac_final(
			authenticator->get_data(hmac_sha_256.get_digest_length()),
			&md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG authenticator"),
			 authenticator->get_data(),
			 authenticator->get_data_length()));

		status = authenticator->set_data_length(SIMPLE_CONFIG_AUTHENTICATOR_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s:     key_function: generate_authenticator(): returns\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::add_authenticator_attribute(
	simple_config_message_c * const received_simple_config_message,
	simple_config_message_c * const new_simple_config_message)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s:     message_function: add_authenticator_attribute()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_process_general_error);

	simple_config_payloads_c * authenticator_payload = new simple_config_payloads_c(m_am_tools);
	eap_automatic_variable_c<simple_config_payloads_c> automatic_payloads(m_am_tools, authenticator_payload);

	if (authenticator_payload == 0
		|| authenticator_payload->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		eap_variable_data_c authenticator(m_am_tools);

		if (authenticator.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = generate_authenticator(
			received_simple_config_message->get_simple_config_message_data(),
			new_simple_config_message->get_simple_config_message_data(),
			&authenticator);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = authenticator_payload->copy_attribute_data(
			simple_config_Attribute_Type_Authenticator,
			true,
			authenticator.get_data(),
			authenticator.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// Adds Authenticator attribute to the end of the message.
	status = authenticator_payload->create_simple_config_message(
		new_simple_config_message,
		true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s:     message_function: add_authenticator_attribute(): returns\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::encrypt_payloads(
	const eap_variable_data_c * const auth_key,
	const eap_variable_data_c * const key_wrap_key,
	simple_config_payloads_c * const plaintext_payloads,
	simple_config_variable_data_c * const encrypted_settings)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: pki_function: encrypt_payloads()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_process_general_error);

	simple_config_message_c plaintext_data(
		m_am_tools,
		m_is_client);

	status = plaintext_payloads->create_simple_config_message(
		&plaintext_data,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	eap_variable_data_c KWA(m_am_tools);

	if (KWA.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		crypto_sha_256_c sha_256(m_am_tools);
		if (sha_256.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		crypto_hmac_c hmac_sha_256(
			m_am_tools,
			&sha_256,
			false);
		if (hmac_sha_256.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG auth_key"),
			auth_key->get_data(),
			auth_key->get_data_length()));

		status = hmac_sha_256.hmac_set_key(auth_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG plaintext_data"),
			plaintext_data.get_simple_config_message_data()->get_data(),
			plaintext_data.get_simple_config_message_data()->get_data_length()));

		status = hmac_sha_256.hmac_update(
			plaintext_data.get_simple_config_message_data()->get_data(),
			plaintext_data.get_simple_config_message_data()->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = KWA.set_buffer_length(hmac_sha_256.get_digest_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = KWA.set_data_length(hmac_sha_256.get_digest_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		{
			u32_t md_length(hmac_sha_256.get_digest_length());

			status = hmac_sha_256.hmac_final(
				KWA.get_data(hmac_sha_256.get_digest_length()),
				&md_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("SIMPLE_CONFIG KWA"),
				 KWA.get_data(),
				 KWA.get_data_length()));

			status = KWA.set_data_length(SIMPLE_CONFIG_AUTHENTICATOR_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		status = plaintext_payloads->copy_attribute_data(
			simple_config_Attribute_Type_Key_Wrap_Authenticator,
			true,
			KWA.get_data(),
			KWA.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = plaintext_payloads->create_simple_config_message(
			&plaintext_data,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	eap_variable_data_c IV(m_am_tools);

	if (IV.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		// Creates Enrollee Nonce.
		status = generate_nonce(
			&IV,
			SIMPLE_CONFIG_KEY_WRAP_IV_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	{
		crypto_aes_c aes(m_am_tools);

		crypto_cbc_c aes_cbc(
			m_am_tools,
			&aes,
			false);

		if (aes_cbc.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG key_wrap_key"),
			key_wrap_key->get_data(),
			key_wrap_key->get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG IV"),
			IV.get_data(),
			IV.get_data_length()));

		status = aes_cbc.set_encryption_key(
			IV.get_data(),
			IV.get_data_length(),
			key_wrap_key->get_data(),
			key_wrap_key->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = plaintext_data.add_padding(aes_cbc.get_block_size());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG plaintext data"),
			 plaintext_data.get_simple_config_message_data()->get_data(),
			 plaintext_data.get_simple_config_message_data()->get_data_length()));

		status = aes_cbc.update_non_aligned(
			plaintext_data.get_simple_config_message_data()->get_data(),
			plaintext_data.get_simple_config_message_data()->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = aes_cbc.finalize_non_aligned();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG encrypted data"),
			 plaintext_data.get_simple_config_message_data()->get_data(),
			 plaintext_data.get_simple_config_message_data()->get_data_length()));


		status = encrypted_settings->set_copy_of_buffer(
			simple_config_Attribute_Type_Encrypted_Settings,
			true,
			IV.get_data(),
			IV.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = encrypted_settings->add_data(
			plaintext_data.get_simple_config_message_data()->get_data(),
			plaintext_data.get_simple_config_message_data()->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: pki_function: encrypt_payloads(): returns\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::decrypt_payloads(
	const eap_variable_data_c * const auth_key,
	const eap_variable_data_c * const key_wrap_key,
	simple_config_variable_data_c * const encrypted_settings,
	simple_config_payloads_c * const plaintext_payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: pki_function: decrypt_payloads()\n"),
		(m_is_client == true ? "client": "server")));

	eap_status_e status(eap_status_process_general_error);

	eap_variable_data_c data_payload(m_am_tools);

	if (data_payload.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = data_payload.set_buffer(
		encrypted_settings->get_data(encrypted_settings->get_data_length()),
		encrypted_settings->get_data_length(),
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (data_payload.get_data_length() <= SIMPLE_CONFIG_KEY_WRAP_IV_SIZE)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}


	eap_variable_data_c IV(m_am_tools);

	if (IV.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = IV.set_buffer(
		data_payload.get_data(SIMPLE_CONFIG_KEY_WRAP_IV_SIZE),
		SIMPLE_CONFIG_KEY_WRAP_IV_SIZE,
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	eap_variable_data_c decrypted_data(m_am_tools);

	if (decrypted_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	const u32_t encrypted_data_length(
		data_payload.get_data_length()
		- SIMPLE_CONFIG_KEY_WRAP_IV_SIZE);

	status = decrypted_data.set_buffer(
		data_payload.get_data_offset(
			SIMPLE_CONFIG_KEY_WRAP_IV_SIZE,
			encrypted_data_length),
		encrypted_data_length,
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("SIMPLE_CONFIG key_wrap_key"),
		key_wrap_key->get_data(),
		key_wrap_key->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("SIMPLE_CONFIG IV"),
		IV.get_data(),
		IV.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("SIMPLE_CONFIG encrypted data"),
		decrypted_data.get_data(),
		decrypted_data.get_data_length()));

	{
		crypto_aes_c aes(m_am_tools);

		crypto_cbc_c aes_cbc(
			m_am_tools,
			&aes,
			false);

		if (aes_cbc.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = aes_cbc.set_decryption_key(
			IV.get_data(),
			IV.get_data_length(),
			key_wrap_key->get_data(),
			key_wrap_key->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = aes_cbc.update_non_aligned(
			decrypted_data.get_data(),
			decrypted_data.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = aes_cbc.finalize_non_aligned();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG plaintext data"),
			decrypted_data.get_data(),
			decrypted_data.get_data_length()));
	}


	u32_t data_length(decrypted_data.get_data_length());
	u32_t padding_length(0ul);

	status = plaintext_payloads->parse_simple_config_payloads(
		decrypted_data.get_data(),
		&data_length,
		&padding_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	simple_config_variable_data_c * const received_KWA
		= plaintext_payloads->get_attribute_pointer(simple_config_Attribute_Type_Key_Wrap_Authenticator);
	if (received_KWA == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("SIMPLE_CONFIG received_KWA"),
		 received_KWA->get_data(received_KWA->get_data_length()),
		 received_KWA->get_data_length()));


	eap_variable_data_c plaintext_data(m_am_tools);

	if (plaintext_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (decrypted_data.get_data_length() < (received_KWA->get_header()->get_length()+padding_length))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	const u32_t plaintext_data_length(
		decrypted_data.get_data_length()
		- (received_KWA->get_header()->get_length()+padding_length));

	status = plaintext_data.set_buffer(
		decrypted_data.get_data(plaintext_data_length),
		plaintext_data_length,
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("SIMPLE_CONFIG plaintext_data"),
		 plaintext_data.get_data(),
		 plaintext_data.get_data_length()));


	{
		crypto_sha_256_c sha_256(m_am_tools);
		if (sha_256.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		crypto_hmac_c hmac_sha_256(
			m_am_tools,
			&sha_256,
			false);
		if (hmac_sha_256.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("SIMPLE_CONFIG authenticator auth_key"),
			 auth_key->get_data(),
			 auth_key->get_data_length()));

		status = hmac_sha_256.hmac_set_key(auth_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = hmac_sha_256.hmac_update(
			plaintext_data.get_data(),
			plaintext_data.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_variable_data_c local_KWA(m_am_tools);

		if (local_KWA.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = local_KWA.set_buffer_length(hmac_sha_256.get_digest_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = local_KWA.set_data_length(hmac_sha_256.get_digest_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		{
			u32_t md_length(hmac_sha_256.get_digest_length());

			status = hmac_sha_256.hmac_final(
				local_KWA.get_data(hmac_sha_256.get_digest_length()),
				&md_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("SIMPLE_CONFIG local_KWA"),
				 local_KWA.get_data(),
				 local_KWA.get_data_length()));

			status = local_KWA.set_data_length(SIMPLE_CONFIG_AUTHENTICATOR_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (local_KWA.compare(
				received_KWA->get_data(received_KWA->get_data_length()),
				received_KWA->get_data_length()) != 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e simple_config_record_c::complete_query_network_and_device_parameters(
	const simple_config_state_e state,
	simple_config_payloads_c * const network_and_device_parameters,
	const eap_status_e p_completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("SIMPLE_CONFIG: %s: pki_function: complete_query_network_and_device_parameters()\n"),
		(m_is_client == true ? "client": "server")));

	m_pending_query_network_and_device_parameters = false;

	if (network_and_device_parameters == 0
		|| network_and_device_parameters->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e local_completion_status(p_completion_status);
	eap_status_e status(eap_status_process_general_error);

	if (m_is_client == true)
	{
		status = get_type_partner()->read_configure(
			cf_str_EAP_SIMPLE_CONFIG_device_password.get_field(),
			&m_device_password);
		if (status != eap_status_ok
			|| m_device_password.get_is_valid_data() == false)
		{
			// This is mandatory value.
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: SIMPLE_CONFIG: %s: simple_config_record_c::configure(): Missing device password.\n"),
				 (m_is_client == true ? "client": "server")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_password);
		}
	}

	
	{
		if (m_simple_config_state == simple_config_state_process_simple_config_start)
		{
			status = network_and_device_parameters->get_attribute_data(
				simple_config_Attribute_Type_UUID_E,
				&m_UUID_E);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			{
				u16_t data(0ul);

				status = network_and_device_parameters->get_attribute_data(
					simple_config_Attribute_Type_Device_Password_ID,
					&data);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				m_local_Device_Password_ID = static_cast<simple_config_Device_Password_ID_e>(data);
			}

			{
				u8_t RF_Band(simple_config_RF_Bands_2_4_GHz);

				status = network_and_device_parameters->get_attribute_data(
					simple_config_Attribute_Type_RF_Band,
					&RF_Band);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				m_Rf_Bands = static_cast<simple_config_RF_Bands_e>(RF_Band);
			}
		}
		else if (m_simple_config_state == simple_config_state_process_M1)
		{
			status = network_and_device_parameters->get_attribute_data(
				simple_config_Attribute_Type_UUID_R,
				&m_UUID_R);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = network_and_device_parameters->get_attribute_data(
				simple_config_Attribute_Type_SSID,
				&m_SSID);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = network_and_device_parameters->get_attribute_data(
				simple_config_Attribute_Type_MAC_Address,
				&m_MAC_address);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			{
				u16_t data(0ul);

				status = network_and_device_parameters->get_attribute_data(
					simple_config_Attribute_Type_Device_Password_ID,
					&data);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				if (status == eap_status_ok)
				{
					m_local_Device_Password_ID = static_cast<simple_config_Device_Password_ID_e>(data);
				}

				if (m_received_Device_Password_ID != m_local_Device_Password_ID)
				{
					// Registrar requires different Device_Password_ID.
					local_completion_status = eap_status_user_has_not_subscribed_to_the_requested_service;

					bool add_new_attribute(false);

					// Change the error attribute to simple_config_Configuration_Error_Network_auth_failure.
					simple_config_variable_data_c * Configuration_Error
						= network_and_device_parameters->get_attribute_pointer(simple_config_Attribute_Type_Configuration_Error);
					if (Configuration_Error == 0)
					{
						// Add a new simple_config_Attribute_Type_Configuration_Error attribute.
						Configuration_Error = new simple_config_variable_data_c(m_am_tools);

						if (Configuration_Error != 0)
						{
							add_new_attribute = true;
						}
						else
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
						}
					}

					if (Configuration_Error != 0)
					{
						u16_t error(simple_config_Configuration_Error_Network_auth_failure);
						u16_t network_order_error(eap_htons(error));

						status = Configuration_Error->set_copy_of_buffer(
							simple_config_Attribute_Type_Configuration_Error,
							true,
							&network_order_error,
							sizeof(network_order_error));
						if (status != eap_status_ok)
						{
							if (add_new_attribute == true)
							{
								delete Configuration_Error;
								Configuration_Error = 0;
							}
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						if (add_new_attribute == true)
						{
							// Only the new object is added.
							status = network_and_device_parameters->add_attribute(Configuration_Error);
							if (status != eap_status_ok)
							{
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}
						}
					}
					else
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_missing_payload);
					}
				}
			}
		}
	}


	if (local_completion_status == eap_status_ok)
	{
		switch (state)
		{

		case simple_config_state_process_simple_config_start:
			status = send_M1(network_and_device_parameters);
			break;

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

		case simple_config_state_process_M1:
			status = send_M2(network_and_device_parameters);
			break;

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

		default:
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);

		} // switch (state)
	}
	else if (local_completion_status == eap_status_user_has_not_subscribed_to_the_requested_service)
	{
		switch (state)
		{

		case simple_config_state_process_simple_config_start:
			status = send_WSC_NACK();
			break;

#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

		case simple_config_state_process_M1:
			status = send_M2D(network_and_device_parameters);
			break;

#endif //#if defined(USE_EAP_TYPE_SERVER_SIMPLE_CONFIG)

		default:
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);

		} // switch(state)
	}

	if (status == eap_status_ok)
	{
		status = check_sent_simple_config_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_status_completed_request;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#endif //#if defined(USE_EAP_SIMPLE_CONFIG)


// End.
