/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/ec_certificate_store.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 109 % << Don't touch! Updated by Synergy at check-out.
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

// This is enumeration of WAPI source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 701 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#if defined(USE_WAPI_CORE)

#include "eap_automatic_variable.h"
#include "ec_certificate_store.h"
#include "ec_cs_types.h"
#include "ec_cs_strings.h"
#include "abs_ec_certificate_store.h"
#include "abs_eap_am_file_input.h"
#include "asn1_der_type.h"
#include "ec_am_base_algorithms.h"
#include "wapi_asn1_der_parser.h"
#include "ec_am_base_certificate_store.h"
#include "ec_cs_tlv.h"
#include "ec_cs_tlv_payloads.h"
#include "eap_protocol_layer.h"
#include "eap_state_notification.h"
#include "ec_cs_compare_certificate_id.h"
#include "wapi_certificate_asn1_der_parser.h"
#include "ec_cs_compare_certificate_issuer_name.h"
#include "ec_cs_compare_certificate_reference.h"
#include "ec_cs_compare_reference_id.h"
#include "ec_cs_compare_reference.h"
#include "ec_cs_compare_reference_issuer_name.h"
#include "eap_tlv_message_data.h"
#include "eap_crypto_api.h"

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_certificate_store_c::~ec_certificate_store_c()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::~ec_certificate_store_c():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::~ec_certificate_store_c()");

	delete m_ec_algorithms;
	m_ec_algorithms = 0;

}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_certificate_store_c::ec_certificate_store_c(
	abs_eap_am_tools_c * const tools,
	abs_ec_certificate_store_c * const partner,
	ec_am_base_certificate_store_c * const am_certificate_store,
	const bool is_client_when_true)
	: m_am_tools(tools)
	, m_partner(partner)
	, m_ec_algorithms(0)
	, m_am_certificate_store(am_certificate_store)
	, m_receive_network_id(tools)
	, m_master_key_changed(false)
	, m_PAC_store_master_key(tools)
	, m_PAC_store_password(tools)
	, m_PAC_store_device_seed(tools)
	, m_completion_queue(tools)
	, m_pending_operation(ec_cs_pending_operation_none)
	, m_queried_issuer_ID(tools)
	, m_imported_certificate_wapi_id(tools)
	, m_imported_certificate_file_data(tools)
	, m_imported_certificate_filename(tools)
	, m_imported_certificate_data(tools)
	, m_imported_private_key_data(tools)
	, m_ec_cs_completion_status(eap_status_process_general_error)
	, m_ae_certificate(tools)

	, m_selected_ca_id(tools)
	, m_selected_client_id(tools)

	, m_broken_cs_data_list(tools)
	, m_ca_asu_id_list(tools)
	, m_read_ca_asu_id_list(false)
	, m_client_asu_id_list(tools)
	, m_read_client_asu_id_list(false)
	, m_ca_certificates(tools)
	, m_client_certificates(tools)
	, m_client_private_keys(tools)

	, m_peer_identity(tools)
	, m_signature(tools)

	, m_hash_of_message(tools)
	, m_id_of_own_certificate(tools)

	, m_dummy_test_asu_certificate(tools)
	, m_dummy_test_asu_private_key(tools)
	, m_dummy_test_peer_certificate(tools)
	, m_dummy_test_own_certificate(tools)
	, m_dummy_test_own_private_key(tools)

	, m_is_client(is_client_when_true)
	, m_is_valid(false)
	, m_shutdown_was_called(false)
	, m_reference_counter_read(false)
	, m_reference_counter_changed(false)
	, m_reference_counter(0ul)
	, m_PAC_store_key_timeout_ms(EAP_FAST_PAC_STORE_DEFAULT_KEY_CACHE_TIMEOUT)
	, m_already_in_completion_action_check(false)
	, m_pending_read_ec_cs_data(false)
	, m_complete_start_certificate_import(false)
	, m_certificate_store_initialized(false)
	, m_allow_use_of_ae_certificate(false)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::ec_certificate_store_c():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::ec_certificate_store_c()");

	if (partner == 0
		|| am_certificate_store == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		return;
	}

	m_ec_algorithms = ec_am_base_algorithms_c::new_ec_base_algorithms_c(
		tools,
		this,
		is_client_when_true);
	if (m_ec_algorithms == 0
		|| m_ec_algorithms->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return;
	}

	am_certificate_store->set_am_certificate_store_partner(this);

	m_is_valid = true;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT bool ec_certificate_store_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = m_partner->read_configure(field, data);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

#if defined(USE_WAPI_CORE_SERVER) || !defined(WAPI_USE_CERTIFICATE_STORE)

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::read_test_certificate(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::read_test_certificate():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::read_test_certificate()");

	eap_status_e status(eap_status_not_supported);

	{
		eap_variable_data_c name(m_am_tools);
		if (name.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = m_partner->read_configure(
			field,
			&name);
		if (status == eap_status_ok
			&& name.get_is_valid_data() == true)
		{
			// OK test certificate configured.

			abs_eap_am_file_input_c * const file_input = abs_eap_am_file_input_c::new_abs_eap_am_file_input_c(m_am_tools);

			eap_automatic_variable_c<abs_eap_am_file_input_c> automatic_file_input(m_am_tools, file_input);

			if (file_input == 0
				|| file_input->get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = file_input->file_open(&name, eap_file_io_direction_read);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			u32_t file_size = file_input->file_size();

			status = data->set_buffer_length(file_size);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = file_input->file_read(data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			// Here we ignore missing configuration data.
			status = eap_status_ok;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif //#if defined(USE_WAPI_CORE_SERVER) || !defined(WAPI_USE_CERTIFICATE_STORE)

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::configure():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::configure()");

	eap_status_e status(eap_status_not_supported);


	{
		eap_variable_data_c EAP_FAST_PAC_store_key_timeout_ms(m_am_tools);

		eap_status_e status = m_partner->read_configure(
			cf_str_EAP_FAST_PAC_store_key_timeout_ms.get_field(),
			&EAP_FAST_PAC_store_key_timeout_ms);
		if (status == eap_status_ok
			&& EAP_FAST_PAC_store_key_timeout_ms.get_is_valid_data() == true)
		{
			u32_t *timeout_ms = reinterpret_cast<u32_t *>(
				EAP_FAST_PAC_store_key_timeout_ms.get_data(sizeof(u32_t)));
			if (timeout_ms != 0)
			{
				m_PAC_store_key_timeout_ms = *timeout_ms;
			}
		}
	}


	{
		// Read CS store password from memory store if such exists.
		eap_variable_data_c key(m_am_tools);

		status = key.set_copy_of_buffer(
			WAPI_CS_MEMORY_STORE_KEY,
			sizeof(WAPI_CS_MEMORY_STORE_KEY));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_tlv_message_data_c tlv_data(m_am_tools);

		status = m_am_tools->memory_store_get_data(
			&key,
			&tlv_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ec_certificate_store_c::configure(): cannot get credentials\n")));

			// Ignore the error.
			status = eap_status_ok;
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ec_certificate_store_c::configure(): credentials found\n")));

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
					if (tlv->get_type() == ec_cs_data_type_password)
					{
						status = m_PAC_store_password.set_copy_of_buffer(
							tlv->get_value(tlv->get_value_length()),
							tlv->get_value_length());
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						EAP_TRACE_DATA_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("CS store password"),
							 m_PAC_store_password.get_data(),
							 m_PAC_store_password.get_data_length()));
					}
					else if (tlv->get_type() == ec_cs_data_type_device_seed)
					{
						status = m_PAC_store_device_seed.set_copy_of_buffer(
							tlv->get_value(tlv->get_value_length()),
							tlv->get_value_length());
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						EAP_TRACE_DATA_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("CS store device seed"),
							 m_PAC_store_device_seed.get_data(),
							 m_PAC_store_device_seed.get_data_length()));
					}
					else if (tlv->get_type() == ec_cs_data_type_master_key)
					{
						status = m_PAC_store_master_key.set_copy_of_buffer(
							tlv->get_value(tlv->get_value_length()),
							tlv->get_value_length());
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						EAP_TRACE_DATA_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("CS store master key"),
							 m_PAC_store_master_key.get_data(),
							 m_PAC_store_master_key.get_data_length()));
					}
					else if (tlv->get_type() == ec_cs_data_type_reference_counter)
					{
						u32_t * data = reinterpret_cast<u32_t *>(tlv->get_value(sizeof(m_reference_counter)));
						if (data != 0)
						{
							m_reference_counter = eap_read_u32_t_network_order(
								data,
								sizeof(m_reference_counter));
						}
					}
					else
					{
						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ec_certificate_store_c::configure(): unknown credential type %d, length %d\n"),
							 tlv->get_type(),
							 tlv->get_value_length()));
					}
				}
			} // for()

			status = m_am_tools->memory_store_remove_data(&key);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ec_certificate_store_c::configure(): credentials removed from eapol\n")));
		}
	}


#if !defined(WAPI_USE_CERTIFICATE_STORE)
	if (m_is_client == true)
	{
		status = read_test_certificate(
			cf_str_WAPI_ASU_certificate_file.get_field(),
			&m_dummy_test_asu_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = read_test_certificate(
			cf_str_WAPI_ASUE_certificate_file.get_field(),
			&m_dummy_test_own_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = read_test_certificate(
			cf_str_WAPI_ASUE_private_key_file.get_field(),
			&m_dummy_test_own_private_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = read_test_certificate(
			cf_str_WAPI_AE_certificate_file.get_field(),
			&m_dummy_test_peer_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
#endif //#if !defined(WAPI_USE_CERTIFICATE_STORE)
#if defined(USE_WAPI_CORE_SERVER)

	if (m_is_client == false)
	{
		status = read_test_certificate(
			cf_str_WAPI_ASU_certificate_file.get_field(),
			&m_dummy_test_asu_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = read_test_certificate(
			cf_str_WAPI_AE_certificate_file.get_field(),
			&m_dummy_test_own_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = read_test_certificate(
			cf_str_WAPI_AE_private_key_file.get_field(),
			&m_dummy_test_own_private_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = read_test_certificate(
			cf_str_WAPI_ASU_private_key_file.get_field(),
			&m_dummy_test_asu_private_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = read_test_certificate(
			cf_str_WAPI_ASUE_certificate_file.get_field(),
			&m_dummy_test_peer_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
#endif //#if defined(USE_WAPI_CORE_SERVER)
	{
		status = eap_status_ok;
	}

	{
		// Adds timer to delete CS store Key from member variable.

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ec_certificate_store_c::configure(): am_set_timer(): WAPI_CS_KEY_TIMER_ID\n")));

		status = m_am_tools->am_set_timer(
			this,
			WAPI_CS_KEY_TIMER_ID,
			0,
			m_PAC_store_key_timeout_ms);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//------------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::cancel_operations()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: ec_certificate_store_c::cancel_operations()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::cancel_operations()");

	eap_status_e status(eap_status_ok);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_am_certificate_store->cancel_certificate_store_store_operations();

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

eap_status_e ec_certificate_store_c::save_data_to_permanent_store()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s, ec_certificate_store_c::save_data_to_permanent_store()\n"),
		this,
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::save_data_to_permanent_store()");

	eap_status_e status(eap_status_ok);

	if (m_is_client == true)
	{
		if (m_certificate_store_initialized == true)
		{
			// Save all data to permanent store.

			eap_array_c<ec_cs_data_c> data_references(m_am_tools);

			if (m_reference_counter_changed == true)
			{
				/*
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
				 * | Type=Referene counter TLV     |           Length=4            |  |
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
				 * |                    reference counter (4 octets)               |  |
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
				 * | Type=CS-MAC TLV               |           Length=32           |  |
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
				 * |                              MAC (32 octets)                  |  |
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
				 */

				ec_cs_data_c * const refence_counter = new ec_cs_data_c(m_am_tools);

				eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, refence_counter);

				if (refence_counter == 0
					|| refence_counter->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Wrote reference counter = 0x%08x\n"),
					 m_reference_counter));

				refence_counter->set_type(ec_cs_data_type_reference_counter);

				status = refence_counter->get_writable_reference()->set_copy_of_buffer(
					EC_CS_ZERO_REFERENCE,
					sizeof(EC_CS_ZERO_REFERENCE));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				eap_variable_data_c reference_counter_MAC_key(m_am_tools);
				if (reference_counter_MAC_key.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				ec_cs_tlv_c pac_tlv_handler(m_am_tools, true);
				if (pac_tlv_handler.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = pac_tlv_handler.generate_data_key(
					false,
					ec_cs_data_type_reference_counter,
					&reference_counter_MAC_key,
					&m_PAC_store_master_key,
					refence_counter->get_reference(),
					&m_PAC_store_device_seed);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				ec_cs_variable_data_c reference_counter_tlv(m_am_tools);
				if (reference_counter_tlv.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = pac_tlv_handler.create_u32_t_tlv(
					&reference_counter_tlv,
					ec_cs_tlv_type_CS_reference_counter,
					m_reference_counter);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = pac_tlv_handler.create_data_with_MAC(
					&reference_counter_MAC_key,
					reference_counter_tlv.get_full_tlv_buffer(),
					refence_counter->get_writable_data());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("New reference counter data"),
					 refence_counter->get_data()->get_data(),
					 refence_counter->get_data()->get_data_length()));

				refence_counter->set_change_status(ec_cs_data_change_status_new);

				status = data_references.add_object(refence_counter->copy(), true);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

			}

			if (m_master_key_changed == true)
			{
				// Create encrypted Master key data block.
				// NOTE this is the only data encrypted with CS store password.

				/*
				 * Master key data
				 *
 				 * 0                   1                   2                   3   
				 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    -+ -+
				 * | Type=CS-Encrypted block TLV   |     Length=4+16+4+n+4+m       |     |  |
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+  |  |
				 * | Type=CS-Encryption IV TLV     |           Length=16           |  |  |  | plain text
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  |
				 * |                              IV (16 octets)                   |  |  |  |
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+  |  |
				 * | Type=CS-Encrypted data TLV    |           Length=n+4+m        |  |  |  |
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  | -+
				 * |                          Master key TLV (n octets)            |  |  |  |
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  | encrypted
				 * | Type=CS-padding TLV           |           Length=m            |  |  |  | multiple of
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  | 16 octets
				 * |                           padding (m octets)                  |  |  |  |
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+ -+ -+
				 * | Type=CS-MAC TLV               |           Length=32           |  |
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
				 * |                              MAC (32 octets)                  |  |
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
				 */

				ec_cs_data_c * const master_key = new ec_cs_data_c(m_am_tools);

				eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, master_key);

				if (master_key == 0
					|| master_key->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				master_key->set_type(ec_cs_data_type_master_key);

				status = master_key->get_writable_reference()->set_copy_of_buffer(
					EC_CS_ZERO_REFERENCE,
					sizeof(EC_CS_ZERO_REFERENCE));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				ec_cs_tlv_c pac_tlv_handler(m_am_tools, true);
				if (pac_tlv_handler.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = pac_tlv_handler.create_master_key_data(
					&m_PAC_store_password,
					&m_PAC_store_device_seed,
					&m_PAC_store_master_key,
					master_key->get_reference(),
					master_key->get_writable_data());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				master_key->set_change_status(ec_cs_data_change_status_new);

				status = data_references.add_object(master_key->copy(), true);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			status = copy<ec_cs_data_c>(
				&m_ca_certificates,
				&data_references,
				m_am_tools,
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = copy<ec_cs_data_c>(
				&m_client_certificates,
				&data_references,
				m_am_tools,
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = copy<ec_cs_data_c>(
				&m_client_private_keys,
				&data_references,
				m_am_tools,
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			status = add_asu_id_list(
				&m_ca_asu_id_list,
				&data_references);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = add_asu_id_list(
				&m_client_asu_id_list,
				&data_references);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			status = copy<ec_cs_data_c>(
				&m_broken_cs_data_list,
				&data_references,
				m_am_tools,
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("calls: ec_certificate_store_c::save_data_to_permanent_store(): m_am_pac_store_services->write_PAC_store_data(): %d.\n"),
				__LINE__));

			status = m_am_certificate_store->write_certificate_store_data(
				true,
				ec_cs_pending_operation_none,
				&data_references);
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
				(EAPL("ERROR: WAPI_Core: this = 0x%08x, %s, ec_certificate_store_c::save_data_to_permanent_store(): Certificate store NOT initialized. Do not save data.\n"),
				this,
				(m_is_client == true ? "client": "server")));
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s, ec_certificate_store_c::shutdown()\n"),
		this,
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::shutdown()");

	eap_status_e status(eap_status_process_general_error);

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	(void) m_am_tools->am_cancel_timer(
			this,
			WAPI_CS_KEY_TIMER_ID);

	(void) cancel_operations();

	(void) save_data_to_permanent_store();

	(void) completion_action_clenup();

	{
		// Save the CS store password.
		eap_variable_data_c key(m_am_tools);

		status = key.set_copy_of_buffer(
			WAPI_CS_MEMORY_STORE_KEY,
			sizeof(WAPI_CS_MEMORY_STORE_KEY));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		(void) m_am_tools->memory_store_remove_data(&key);

		eap_tlv_message_data_c tlv_data(m_am_tools);

		if (m_PAC_store_password.get_is_valid_data() == true)
		{
			status = tlv_data.add_message_data(
				ec_cs_data_type_password,
				m_PAC_store_password.get_data_length(),
				m_PAC_store_password.get_data());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (m_PAC_store_device_seed.get_is_valid_data() == true)
		{
			status = tlv_data.add_message_data(
				ec_cs_data_type_device_seed,
				m_PAC_store_device_seed.get_data_length(),
				m_PAC_store_device_seed.get_data());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (m_PAC_store_master_key.get_is_valid_data() == true)
		{
			status = tlv_data.add_message_data(
				ec_cs_data_type_master_key,
				m_PAC_store_master_key.get_data_length(),
				m_PAC_store_master_key.get_data());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		{
			u32_t network_order_reference_counter = eap_htonl(m_reference_counter);

			status = tlv_data.add_message_data(
				ec_cs_data_type_reference_counter,
				sizeof(network_order_reference_counter),
				&network_order_reference_counter);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		status = m_am_tools->memory_store_add_data(
			&key,
			&tlv_data,
			m_PAC_store_key_timeout_ms);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ec_certificate_store_c::shutdown(): cannot store credentials\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e ec_certificate_store_c::add_asu_id_list(
	EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const asu_id_list,
	eap_array_c<ec_cs_data_c> * const data_references)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: ec_certificate_store_c::add_asu_id_list()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::add_asu_id_list()");

	eap_status_e status(eap_status_ok);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	for (u32_t index = 0ul; index < asu_id_list->get_object_count(); ++index)
	{
		const ec_cs_data_c * const data = asu_id_list->get_object(index);
		if (data != 0)
		{
			ec_cs_data_c * const new_ec_cd_data = data->copy();
			if (new_ec_cd_data != 0)
			{
				status = data_references->add_object(new_ec_cd_data, true);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e ec_certificate_store_c::create_unique_reference(
	ec_cs_data_c * const out_reference)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: ec_certificate_store_c::create_unique_reference()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::create_unique_reference()");

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	++m_reference_counter;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Increased reference counter = 0x%08x\n"),
		 m_reference_counter));

	m_reference_counter_changed = true;

	u32_t network_order_counter = eap_htonl(m_reference_counter);

	status = out_reference->get_writable_reference()->set_copy_of_buffer(
		&network_order_counter,
		sizeof(network_order_counter));

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::initialize_certificate_store()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::initialize_certificate_store():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::initialize_certificate_store()");

	eap_status_e status(eap_status_not_supported);

	status = m_am_certificate_store->initialize_certificate_store(wapi_completion_operation_continue_certificate_authentication);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::query_asu_id()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::query_asu_id():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::query_asu_id()");

	eap_variable_data_c asn1_der_subject_name(m_am_tools);
	eap_variable_data_c asn1_der_issuer_name(m_am_tools);
	eap_variable_data_c asn1_der_sequence_number(m_am_tools);

	wapi_certificate_asn1_der_parser_c parser(m_am_tools);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status(eap_status_ok);

	if (m_selected_ca_id.get_is_valid_data() == true)
	{
		wapi_asn1_der_parser_c asn1_der_parser(m_am_tools);
		if (asn1_der_parser.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = asn1_der_parser.decode(&m_selected_ca_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = asn1_der_parser.get_wapi_identity(
			&asn1_der_subject_name,
			&asn1_der_issuer_name,
			&asn1_der_sequence_number);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = parser.decode(&m_dummy_test_asu_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = parser.read_certificate_id(
			&asn1_der_subject_name,
			&asn1_der_issuer_name,
			&asn1_der_sequence_number);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = m_partner->complete_query_asu_id(
		&asn1_der_subject_name,
		&asn1_der_issuer_name,
		&asn1_der_sequence_number,
		status);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::compare_id_and_certificate(
	const eap_variable_data_c * const ID,
	const eap_variable_data_c * const certificate)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::compare_id_and_certificate():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::compare_id_and_certificate()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	wapi_certificate_asn1_der_parser_c parser(m_am_tools);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = parser.decode(certificate);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c certificate_id(m_am_tools);
	if (certificate_id.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = parser.read_certificate_id(
		&certificate_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (certificate_id.compare(ID) == 0)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("OK: compare_id_and_certificate(): match certificate_id"),
			certificate_id.get_data(),
			certificate_id.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("OK: compare_id_and_certificate(): match ID"),
			ID->get_data(),
			ID->get_data_length()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("INFO: compare_id_and_certificate(): mismatch certificate_id"),
			certificate_id.get_data(),
			certificate_id.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("INFO: compare_id_and_certificate(): mismatch ID"),
			ID->get_data(),
			ID->get_data_length()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_match);
	}
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::compare_issuer_name_of_id_and_certificate(
	const eap_variable_data_c * const issuer_ID,
	const eap_variable_data_c * const certificate)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::compare_issuer_name_of_id_and_certificate():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::compare_issuer_name_of_id_and_certificate()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c issuer_ID_subject_name(m_am_tools);
	eap_variable_data_c issuer_ID_issuer_name(m_am_tools);
	eap_variable_data_c issuer_ID_sequence_number(m_am_tools);

	wapi_asn1_der_parser_c asn1_der_parser(m_am_tools);
	if (asn1_der_parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = asn1_der_parser.decode(issuer_ID);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = asn1_der_parser.get_wapi_identity(
		&issuer_ID_subject_name,
		&issuer_ID_issuer_name,
		&issuer_ID_sequence_number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c certificate_subject_name(m_am_tools);
	eap_variable_data_c certificate_issuer_name(m_am_tools);
	eap_variable_data_c certificate_sequence_number(m_am_tools);

	wapi_certificate_asn1_der_parser_c parser(m_am_tools);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = parser.decode(certificate);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = parser.read_certificate_id(
		&certificate_subject_name,
		&certificate_issuer_name,
		&certificate_sequence_number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (certificate_issuer_name.compare(&issuer_ID_issuer_name) == 0)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("OK: compare_issuer_name_of_id_and_certificate(): match certificate_issuer_name"),
			certificate_issuer_name.get_data(),
			certificate_issuer_name.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("OK: compare_issuer_name_of_id_and_certificate(): match issuer_ID_issuer_name"),
			issuer_ID_issuer_name.get_data(),
			issuer_ID_issuer_name.get_data_length()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("INFO: compare_issuer_name_of_id_and_certificate(): mismatch certificate_issuer_name"),
			certificate_issuer_name.get_data(),
			certificate_issuer_name.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("INFO: compare_issuer_name_of_id_and_certificate(): mismatch issuer_ID_issuer_name"),
			issuer_ID_issuer_name.get_data(),
			issuer_ID_issuer_name.get_data_length()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_match);
	}
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::compare_issuer_common_name_and_certificate(
	const eap_variable_data_c * const certificate,
	const eap_variable_data_c * const subject_common_name)
{
	eap_variable_data_c certificate_subject_name(m_am_tools);
	eap_variable_data_c certificate_issuer_name(m_am_tools);
	eap_variable_data_c certificate_sequence_number(m_am_tools);

	wapi_certificate_asn1_der_parser_c parser(m_am_tools);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = parser.decode(certificate);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = parser.read_certificate_id(
		&certificate_subject_name,
		&certificate_issuer_name,
		&certificate_sequence_number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	wapi_asn1_der_parser_c parse_subject_name(m_am_tools);
	if (parse_subject_name.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c subject_name(m_am_tools);

	status = parse_subject_name.get_decoded_subject_name(
		&certificate_subject_name,
		&subject_name);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (subject_common_name->compare(&subject_name) == 0)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("OK: compare_issuer_common_name_and_certificate(): match subject_common_name"),
			subject_common_name->get_data(),
			subject_common_name->get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("OK: compare_issuer_common_name_and_certificate(): match subject_name"),
			subject_name.get_data(),
			subject_name.get_data_length()));
	}
	else
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("INFO: compare_issuer_common_name_and_certificate(): mismatch subject_common_name"),
			subject_common_name->get_data(),
			subject_common_name->get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("INFO: compare_issuer_common_name_and_certificate(): mismatch subject_name"),
			subject_name.get_data(),
			subject_name.get_data_length()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_user_certificate_unknown);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::get_own_certificate()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::get_own_certificate():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::get_own_certificate()");

	eap_status_e status = m_partner->complete_get_own_certificate(&m_dummy_test_own_certificate);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::set_ae_certificate(
	const eap_variable_data_c * const ae_certificate)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::set_ae_certificate():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::set_ae_certificate()");

	eap_status_e status = m_ae_certificate.set_copy_of_buffer(ae_certificate);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::select_certificate(
	const eap_variable_data_c * const issuer_ID)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::select_certificate():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::select_certificate()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("issuer_ID"),
		 issuer_ID->get_data(),
		 issuer_ID->get_data_length()));

	if (m_pending_operation != ec_cs_pending_operation_none)
	{
		// Some operation is already pending. Try again later.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_device_busy);
	}

#if defined(WAPI_USE_CERTIFICATE_STORE)

	eap_status_e status = m_queried_issuer_ID.set_copy_of_buffer(issuer_ID);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = completion_action_push(ec_cs_completion_internal_select_certificate);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = completion_action_push(ec_cs_completion_internal_select_certificate_with_identity);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = completion_action_push(ec_cs_completion_query_PAC_store_password);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = initialize_certificate_store();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = completion_action_check();

#else

	(void) EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);

	eap_variable_data_c * selected_certificate = 0;

	eap_variable_data_c certificate_id(m_am_tools);
	if (certificate_id.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = compare_issuer_name_of_id_and_certificate(issuer_ID, &m_dummy_test_own_certificate);
	if (status == eap_status_ok)
	{
		selected_certificate = &m_dummy_test_own_certificate;

		wapi_certificate_asn1_der_parser_c parser(m_am_tools);
		if (parser.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_status_e status = parser.decode(&m_dummy_test_asu_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = parser.read_certificate_id(
			&certificate_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = m_partner->complete_select_certificate(
		issuer_ID,
		&certificate_id,
		selected_certificate);

#endif

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::internal_select_certificate_with_identity(
	const eap_variable_data_c * const user_certificate_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::internal_select_certificate_with_identity():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::internal_select_certificate_with_identity()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("user_certificate_id"),
		 user_certificate_id->get_data(),
		 user_certificate_id->get_data_length()));

	ec_cs_data_c search_id(m_am_tools);

	eap_status_e status = search_id.get_writable_data()->set_buffer(
		user_certificate_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c certificate_reference(m_am_tools);

	ec_cs_data_type_e certificate_type(ec_cs_data_type_none);

	const ec_cs_data_c * reference_tlv = 0;

	if (reference_tlv == 0
		&& m_read_client_asu_id_list == true)
	{
		// Search client certificate that is selected by UI.

		ec_cs_compare_reference_id_c compare_certificate_id(m_am_tools);

		ec_cs_data_c search_user_certificate_id(m_am_tools);

		status = search_user_certificate_id.get_writable_data()->set_buffer(
			user_certificate_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_select_certificate_with_identity(): count of m_client_asu_id_list = %d.\n"),
			 this,
			 (m_is_client == true ? "client": "server"),
			 m_client_asu_id_list.get_object_count()));

		// Search Certificate-reference with the issuer ID.
		i32_t index = find_with_compare<ec_cs_data_c>(
			&compare_certificate_id,
			&m_client_asu_id_list,
			&search_user_certificate_id,
			m_am_tools);
		if (index >= 0)
		{
			// Match.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_select_certificate_with_identity(): Certificate match.\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			reference_tlv = m_client_asu_id_list.get_object(index);
			certificate_type = ec_cs_data_type_client_certificate_data;
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_select_certificate_with_identity(): No certificate match.\n"),
				 this,
				 (m_is_client == true ? "client": "server")));
		}
	}


	if (reference_tlv != 0)
	{
		status = read_certificate_reference(reference_tlv, &certificate_reference);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Read the certificate from database.
		status = read_certificate(
			ec_cs_pending_operation_select_client_certificate,
			certificate_type,
			&certificate_reference);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::internal_select_own_certificate_with_issuer_name()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::internal_select_own_certificate_with_issuer_name():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::internal_select_own_certificate_with_issuer_name()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("m_id_of_own_certificate"),
		 m_id_of_own_certificate.get_data(),
		 m_id_of_own_certificate.get_data_length()));

	eap_status_e status(eap_status_process_general_error);

	ec_cs_data_c search_id(m_am_tools);

	{
		wapi_asn1_der_parser_c parser(m_am_tools);
		if (parser.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = parser.decode(&m_id_of_own_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_variable_data_c subject_name(m_am_tools);
		eap_variable_data_c issuer_name(m_am_tools);
		eap_variable_data_c sequence_number(m_am_tools);

		status = parser.get_wapi_identity(
			&subject_name,
			&issuer_name,
			&sequence_number);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = search_id.get_writable_data()->set_copy_of_buffer(
			&issuer_name);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	eap_variable_data_c certificate_reference(m_am_tools);

	ec_cs_compare_reference_issuer_name_c compare_reference_issuer_name(m_am_tools);

	ec_cs_data_type_e certificate_type(ec_cs_data_type_none);

	const ec_cs_data_c * reference_tlv = 0;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_select_own_certificate_with_issuer_name(): count of m_client_asu_id_list = %d.\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_client_asu_id_list.get_object_count()));

	if (reference_tlv == 0
		&& m_read_client_asu_id_list == true)
	{
		// Search Certificate-reference with the issuer ID.
		i32_t index = find_with_compare<ec_cs_data_c>(
			&compare_reference_issuer_name,
			&m_client_asu_id_list,
			&search_id,
			m_am_tools);
		if (index >= 0)
		{
			// Match.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_select_own_certificate_with_issuer_name(): Certificate match.\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			reference_tlv = m_client_asu_id_list.get_object(index);
			certificate_type = ec_cs_data_type_client_certificate_data;
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_select_own_certificate_with_issuer_name(): No certificate match.\n"),
				 this,
				 (m_is_client == true ? "client": "server")));
		}
	}


	if (reference_tlv != 0)
	{
		status = read_certificate_reference(reference_tlv, &certificate_reference);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Read the certificate from database.
		status = read_certificate(
			ec_cs_pending_operation_select_client_certificate,
			certificate_type,
			&certificate_reference);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::internal_select_certificate()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::internal_select_certificate():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::internal_select_certificate()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("m_queried_issuer_ID"),
		 m_queried_issuer_ID.get_data(),
		 m_queried_issuer_ID.get_data_length()));

	if (m_pending_operation != ec_cs_pending_operation_none)
	{
		// Some operation is already pending. Try again later.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_device_busy);
	}

	eap_status_e status(eap_status_not_supported);

	ec_cs_compare_certificate_id_c compare_certificate_id(
		m_am_tools,
		&m_PAC_store_master_key,
		&m_PAC_store_device_seed);

	const ec_cs_data_c * match_certificate_data = 0;

	ec_cs_data_c search_id(m_am_tools);

	status = search_id.get_writable_data()->set_buffer(
		&m_queried_issuer_ID);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	i32_t index(-1);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_select_certificate(): count of m_ca_certificates = %d.\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 m_ca_certificates.get_object_count()));

	if (m_is_client == false)
	{
		// Search certificate with the issuer ID from CA-certificates.
		index = find_with_compare<ec_cs_data_c>(
			&compare_certificate_id,
			&m_ca_certificates,
			&search_id,
			m_am_tools);
	}

	if (index >= 0)
	{
		// Match.
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_select_certificate(): CA certificate match.\n"),
			 this,
			 (m_is_client == true ? "client": "server")));

		match_certificate_data = m_ca_certificates.get_object(index);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_select_certificate(): No CA certificate match.\n"),
			 this,
			 (m_is_client == true ? "client": "server")));

		eap_variable_data_c issuer_name(m_am_tools);

		{
			wapi_asn1_der_parser_c parser(m_am_tools);
			if (parser.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_status_e status = parser.decode(&m_queried_issuer_ID);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			eap_variable_data_c subject_name(m_am_tools);
			eap_variable_data_c sequence_number(m_am_tools);

			status = parser.get_wapi_identity(
				&subject_name,
				&issuer_name,
				&sequence_number);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		ec_cs_compare_certificate_id_c compare_certificate_id(
			m_am_tools,
			&m_PAC_store_master_key,
			&m_PAC_store_device_seed);

		ec_cs_data_c search_certificate_id(m_am_tools);

		status = search_certificate_id.get_writable_data()->set_buffer(
			&m_selected_client_id);

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_select_certificate(): count of m_client_certificates = %d.\n"),
			 this,
			 (m_is_client == true ? "client": "server"),
			 m_client_certificates.get_object_count()));

		// Search certificate with the issuer ID from client certificates.
		index = find_with_compare<ec_cs_data_c>(
			&compare_certificate_id,
			&m_client_certificates,
			&search_certificate_id,
			m_am_tools);
		if (index >= 0)
		{
			// Match.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_select_certificate(): Client certificate match.\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			match_certificate_data = m_client_certificates.get_object(index);
		}
		else if (m_read_ca_asu_id_list == true
				 && m_read_client_asu_id_list == true)
		{
			// Both certificate lists are already read, cannot continue.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_select_certificate(): No client certificate match.\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			(void) m_partner->set_session_timeout(0ul);

			if (m_is_client == false)
			{
				status = eap_status_ca_certificate_unknown;
			}
			else
			{
				status = eap_status_user_certificate_unknown;
			}

			(void) send_error_notification(status);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_no_match);
		}
		else
		{
			status = completion_action_push(ec_cs_completion_internal_select_certificate);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = completion_action_push(ec_cs_completion_internal_select_certificate_with_identity);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// This function call must be asyncronous.
			status = read_both_certificate_lists(ec_cs_pending_operation_select_client_certificate);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	const eap_variable_data_c * certificate_data = 0;

	eap_variable_data_c certificate_data_buffer(m_am_tools);
	eap_variable_data_c certificate_ID(m_am_tools);

	if (certificate_data_buffer.get_is_valid() == false
		|| certificate_ID.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (match_certificate_data != 0)
	{
		ec_cs_tlv_c handler(m_am_tools, true);
		if (handler.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c certificate_reference(m_am_tools);
		if (certificate_reference.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = handler.parse_encrypted_certificate(
			match_certificate_data->get_type(),
			&m_PAC_store_master_key,
			match_certificate_data->get_reference(),
			&m_PAC_store_device_seed,
			match_certificate_data->get_data(),
			&certificate_reference);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		const ec_cs_variable_data_c * const certificate_data_tlv = handler.get_payloads()->get_tlv_pointer(ec_cs_tlv_type_CS_certificate_data);
		if (certificate_data_tlv == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = certificate_data_buffer.set_copy_of_buffer(
			certificate_data_tlv->get_data(certificate_data_tlv->get_data_length()),
			certificate_data_tlv->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		certificate_data = &certificate_data_buffer;

		// Read the certificate ID.
		{
			wapi_certificate_asn1_der_parser_c parser(m_am_tools);
			if (parser.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_status_e status = parser.decode(certificate_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = parser.read_certificate_id(
				&certificate_ID);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	status = m_partner->complete_select_certificate(
		&m_queried_issuer_ID,
		&certificate_ID,
		certificate_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::internal_create_signature_with_private_key()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::internal_create_signature_with_private_key():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::internal_create_signature_with_private_key()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_id_of_own_certificate"),
		m_id_of_own_certificate.get_data(),
		m_id_of_own_certificate.get_data_length()));

	const ec_cs_data_c * selected_private_key = 0;
	const eap_variable_data_c * selected_private_key_data = 0;

	eap_variable_data_c private_key_buffer(m_am_tools);

	eap_status_e status(eap_status_not_supported);


	if (m_is_client == true)
	{

#if defined(WAPI_USE_CERTIFICATE_STORE)

		// Search client certificate that is issued by id_of_certificate,
		// then read the private key with Certificate-Reference.

		eap_variable_data_c issuer_name(m_am_tools);

		{
			wapi_asn1_der_parser_c parser(m_am_tools);
			if (parser.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_status_e status = parser.decode(&m_id_of_own_certificate);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			eap_variable_data_c subject_name(m_am_tools);
			eap_variable_data_c sequence_number(m_am_tools);

			status = parser.get_wapi_identity(
				&subject_name,
				&issuer_name,
				&sequence_number);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		ec_cs_compare_certificate_id_c compare_user_certificate_id(
			m_am_tools,
			&m_PAC_store_master_key,
			&m_PAC_store_device_seed);

		ec_cs_data_c search_user_certificate_id(m_am_tools);

		status = search_user_certificate_id.get_writable_data()->set_buffer(
			&m_id_of_own_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_create_signature_with_private_key(): count of m_client_certificates = %d.\n"),
			 this,
			 (m_is_client == true ? "client": "server"),
			 m_client_certificates.get_object_count()));

		// Search certificate with the issuer name from client-certificates.
		i32_t index = find_with_compare<ec_cs_data_c>(
			&compare_user_certificate_id,
			&m_client_certificates,
			&search_user_certificate_id,
			m_am_tools);

		if (index >= 0)
		{
			// Match.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_create_signature_with_private_key(): Client certificate match.\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			const ec_cs_data_c * const selected_certificate = m_client_certificates.get_object(index);

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			// Read the Certificate-Reference.

			ec_cs_tlv_c handler(m_am_tools, true);
			if (handler.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_variable_data_c certificate_reference(m_am_tools);
			if (certificate_reference.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = handler.parse_encrypted_certificate(
				selected_certificate->get_type(),
				&m_PAC_store_master_key,
				selected_certificate->get_reference(),
				&m_PAC_store_device_seed,
				selected_certificate->get_data(),
				&certificate_reference);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (certificate_reference.get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			const ec_cs_variable_data_c * const certificate_data_tlv = handler.get_payloads()->get_tlv_pointer(ec_cs_tlv_type_CS_certificate_data);
			if (certificate_data_tlv == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			{
				eap_variable_data_c certificate(
					m_am_tools,
					certificate_data_tlv->get_data(certificate_data_tlv->get_data_length()),
					certificate_data_tlv->get_data_length(),
					false,
					false);
				if (certificate.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = compare_id_and_certificate(
					&m_selected_client_id,
					&certificate);
				if (status != eap_status_ok)
				{
					// Certificate selected by host does not match the certificate peer uses.
					(void) m_partner->set_session_timeout(0ul);

					if (m_is_client == false)
					{
						status = eap_status_ca_certificate_unknown;
					}
					else
					{
						status = eap_status_user_certificate_unknown;
					}

					(void) send_error_notification(status);

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			ec_cs_compare_certificate_reference_c compare_certificate_reference(m_am_tools);

			ec_cs_data_c search_reference(m_am_tools);

			status = search_reference.get_writable_data()->set_buffer(
				&certificate_reference);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_create_signature_with_private_key(): count of m_client_private_keys = %d.\n"),
				 this,
				 (m_is_client == true ? "client": "server"),
				 m_client_private_keys.get_object_count()));

			// Search private key with the Certificate-Reference.
			i32_t index = find_with_compare<ec_cs_data_c>(
				&compare_certificate_reference,
				&m_client_private_keys,
				&search_reference,
				m_am_tools);

			if (index >= 0)
			{
				// Match.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_create_signature_with_private_key(): Client certificate match.\n"),
					 this,
					 (m_is_client == true ? "client": "server")));

				selected_private_key = m_client_private_keys.get_object(index);

				if (selected_private_key == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_index);
				}

				ec_cs_tlv_c handler(m_am_tools, true);
				if (handler.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				eap_variable_data_c certificate_reference(m_am_tools);
				if (certificate_reference.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = handler.parse_encrypted_certificate(
					selected_private_key->get_type(),
					&m_PAC_store_master_key,
					selected_private_key->get_reference(),
					&m_PAC_store_device_seed,
					selected_private_key->get_data(),
					&certificate_reference);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				const ec_cs_variable_data_c * const private_key_data = handler.get_payloads()->get_tlv_pointer(ec_cs_tlv_type_CS_private_key_data);
				if (private_key_data == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
				}

				status = private_key_buffer.set_copy_of_buffer(
					private_key_data->get_data(private_key_data->get_data_length()),
					private_key_data->get_data_length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				selected_private_key_data = &private_key_buffer;
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WARNING: WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_create_signature_with_private_key(): No client certificate match.\n"),
					 this,
					 (m_is_client == true ? "client": "server")));
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::internal_create_signature_with_private_key(): No client certificate match.\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			status = completion_action_push(ec_cs_completion_internal_create_signature_with_private_key);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = internal_select_own_certificate_with_issuer_name();
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

#else

		if (selected_private_key_data == 0)
		{
			status = compare_id_and_certificate(&m_id_of_own_certificate, &m_dummy_test_own_certificate);
			if (status == eap_status_ok)
			{
				selected_private_key_data = &m_dummy_test_own_private_key;
			}
		}

#endif //#if defined(WAPI_USE_CERTIFICATE_STORE)

	}

	if (m_is_client == false)
	{
		if (selected_private_key_data == 0)
		{
			status = compare_id_and_certificate(&m_id_of_own_certificate, &m_dummy_test_asu_certificate);
			if (status == eap_status_ok)
			{
				selected_private_key_data = &m_dummy_test_asu_private_key;
			}
		}

		if (selected_private_key_data == 0)
		{
			status = compare_id_and_certificate(&m_id_of_own_certificate, &m_dummy_test_own_certificate);
			if (status == eap_status_ok)
			{
				selected_private_key_data = &m_dummy_test_own_private_key;
			}
		}
	}

	status = m_ec_algorithms->create_signature_with_private_key(&m_hash_of_message, selected_private_key_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::create_signature_with_private_key(
	const eap_variable_data_c * const hash_of_message,
	const eap_variable_data_c * const id_of_certificate)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::create_signature_with_private_key():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::create_signature_with_private_key()");

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("id_of_certificate"),
		id_of_certificate->get_data(),
		id_of_certificate->get_data_length()));

	eap_variable_data_c private_key_buffer(m_am_tools);

	eap_status_e status(eap_status_not_supported);

	status = m_hash_of_message.set_copy_of_buffer(hash_of_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_id_of_own_certificate.set_copy_of_buffer(id_of_certificate);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = internal_create_signature_with_private_key();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::verify_signature_with_public_key(
	const eap_variable_data_c * const peer_identity,
	const eap_variable_data_c * const hash_of_message,
	const eap_variable_data_c * const signature,
	const bool allow_use_of_ae_certificate)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::verify_signature_with_public_key():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::verify_signature_with_public_key()");

	eap_status_e status(eap_status_not_supported);

	eap_variable_data_c used_certificate_id(m_am_tools);

	if (allow_use_of_ae_certificate == false
		&& m_selected_ca_id.get_is_valid_data() == true)
	{
		status = used_certificate_id.set_copy_of_buffer(&m_selected_ca_id);
	}
	else
	{
		status = used_certificate_id.set_copy_of_buffer(peer_identity);
	}

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("used_certificate_id"),
		used_certificate_id.get_data(),
		used_certificate_id.get_data_length()));

	eap_variable_data_c * selected_certificate = 0;
	eap_variable_data_c selected_certificate_buffer(m_am_tools);


	if (selected_certificate == 0
		&& m_ae_certificate.get_is_valid_data() == true
		&& allow_use_of_ae_certificate == true)
	{
		status = compare_id_and_certificate(&used_certificate_id, &m_ae_certificate);
		if (status == eap_status_ok)
		{
			selected_certificate = &m_ae_certificate;
		}
	}

	if (m_is_client == true
		&& selected_certificate == 0)
	{

#if defined(WAPI_USE_CERTIFICATE_STORE)

		ec_cs_compare_certificate_id_c compare_certificate_id(
			m_am_tools,
			&m_PAC_store_master_key,
			&m_PAC_store_device_seed);

		const ec_cs_data_c * match_certificate_data = 0;

		ec_cs_data_c search_peer_identity(m_am_tools);

		status = search_peer_identity.get_writable_data()->set_buffer(
			&used_certificate_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::verify_signature_with_public_key(): count of m_ca_certificates = %d.\n"),
			 this,
			 (m_is_client == true ? "client": "server"),
			 m_ca_certificates.get_object_count()));

		// Search certificate with the issuer ID from CA-certificates.
		i32_t index = find_with_compare<ec_cs_data_c>(
			&compare_certificate_id,
			&m_ca_certificates,
			&search_peer_identity,
			m_am_tools);

		if (index >= 0)
		{
			// Match.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::verify_signature_with_public_key(): CA certificate match.\n"),
				 this,
				 (m_is_client == true ? "client": "server")));

			match_certificate_data = m_ca_certificates.get_object(index);
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::verify_signature_with_public_key(): count of m_client_certificates = %d.\n"),
				 this,
				 (m_is_client == true ? "client": "server"),
				 m_client_certificates.get_object_count()));

			// Search certificate with the issuer ID from client certificates.
			index = find_with_compare<ec_cs_data_c>(
				&compare_certificate_id,
				&m_client_certificates,
				&search_peer_identity,
				m_am_tools);
			if (index >= 0)
			{
				// Match.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::verify_signature_with_public_key(): Client certificate match.\n"),
					 this,
					 (m_is_client == true ? "client": "server")));

				match_certificate_data = m_client_certificates.get_object(index);
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::verify_signature_with_public_key(): No CA neither client certificate match.\n"),
					 this,
					 (m_is_client == true ? "client": "server")));
			}
		}

		if (match_certificate_data != 0)
		{
			ec_cs_tlv_c handler(m_am_tools, true);
			if (handler.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_variable_data_c certificate_reference(m_am_tools);
			if (certificate_reference.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = handler.parse_encrypted_certificate(
				match_certificate_data->get_type(),
				&m_PAC_store_master_key,
				match_certificate_data->get_reference(),
				&m_PAC_store_device_seed,
				match_certificate_data->get_data(),
				&certificate_reference);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			const ec_cs_variable_data_c * const certificate_data_tlv = handler.get_payloads()->get_tlv_pointer(ec_cs_tlv_type_CS_certificate_data);
			if (certificate_data_tlv == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			{
				eap_variable_data_c certificate(
					m_am_tools,
					certificate_data_tlv->get_data(certificate_data_tlv->get_data_length()),
					certificate_data_tlv->get_data_length(),
					false,
					false);
				if (certificate.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = compare_id_and_certificate(
					&m_selected_ca_id,
					&certificate);
				if (status != eap_status_ok)
				{
					// Certificate selected by host does not match the certificate peer uses.
					(void) m_partner->set_session_timeout(0ul);

					if (m_is_client == false)
					{
						status = eap_status_ca_certificate_unknown;
					}
					else
					{
						status = eap_status_user_certificate_unknown;
					}

					(void) send_error_notification(status);

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			status = selected_certificate_buffer.set_copy_of_buffer(
				certificate_data_tlv->get_data(certificate_data_tlv->get_data_length()),
				certificate_data_tlv->get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			selected_certificate = &selected_certificate_buffer;
		}
		else
		{
			if (m_ca_certificates.get_object_count() == 0)
			{
				ec_cs_data_c search_id(m_am_tools);

				eap_status_e status = search_id.get_writable_data()->set_buffer(
					&used_certificate_id);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				eap_variable_data_c certificate_reference(m_am_tools);

				ec_cs_compare_reference_id_c compare_reference_id(m_am_tools);

				ec_cs_data_type_e certificate_type(ec_cs_data_type_none);

				const ec_cs_data_c * reference_tlv = 0;

				if (m_read_ca_asu_id_list == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::verify_signature_with_public_key(): count of m_ca_asu_id_list = %d.\n"),
						 this,
						 (m_is_client == true ? "client": "server"),
						 m_ca_asu_id_list.get_object_count()));

					// Search Certificate-reference with the issuer ID.
					i32_t index = find_with_compare<ec_cs_data_c>(
						&compare_reference_id,
						&m_ca_asu_id_list,
						&search_id,
						m_am_tools);
					if (index >= 0)
					{
						// Match.
						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::verify_signature_with_public_key(): CA certificate ID list match.\n"),
							 this,
							 (m_is_client == true ? "client": "server")));

						reference_tlv = m_ca_asu_id_list.get_object(index);
						certificate_type = ec_cs_data_type_ca_certificate_data;
					}
					else
					{
						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("WARNING: WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::verify_signature_with_public_key(): NO CA certificate ID list match.\n"),
							 this,
							 (m_is_client == true ? "client": "server")));
					}

					if (reference_tlv != 0)
					{
						status = read_certificate_reference(reference_tlv, &certificate_reference);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						status = m_peer_identity.set_copy_of_buffer(&used_certificate_id);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						status = m_hash_of_message.set_copy_of_buffer(hash_of_message);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						status = m_signature.set_copy_of_buffer(signature);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						m_allow_use_of_ae_certificate = allow_use_of_ae_certificate;

						status = completion_action_push(ec_cs_completion_internal_verify_signature_with_public_key);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						// Read the certificate from database.
						status = read_certificate(
							ec_cs_pending_operation_verify_signature_with_public_key,
							certificate_type,
							&certificate_reference);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
				}
			}
			else
			{
				// No certificate found. Cannot continue.
				(void) m_partner->set_session_timeout(0ul);

				if (m_is_client == false)
				{
					status = eap_status_ca_certificate_unknown;
				}
				else
				{
					status = eap_status_user_certificate_unknown;
				}

				(void) send_error_notification(status);

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

#else

		if (selected_certificate == 0)
		{
			status = compare_id_and_certificate(&used_certificate_id, &m_dummy_test_asu_certificate);
			if (status == eap_status_ok)
			{
				selected_certificate = &m_dummy_test_asu_certificate;
			}
		}

		if (selected_certificate == 0)
		{
			status = compare_id_and_certificate(&used_certificate_id, &m_dummy_test_own_certificate);
			if (status == eap_status_ok)
			{
				selected_certificate = &m_dummy_test_own_certificate;
			}
		}

#endif //#if defined(WAPI_USE_CERTIFICATE_STORE)

	}


	if (m_is_client == false)
	{
		if (selected_certificate == 0)
		{
			status = compare_id_and_certificate(&used_certificate_id, &m_dummy_test_asu_certificate);
			if (status == eap_status_ok)
			{
				selected_certificate = &m_dummy_test_asu_certificate;
			}
		}

		if (selected_certificate == 0)
		{
			status = compare_id_and_certificate(&used_certificate_id, &m_dummy_test_own_certificate);
			if (status == eap_status_ok)
			{
				selected_certificate = &m_dummy_test_own_certificate;
			}
		}

		if (m_is_client == false // Only test server could have this certificate.
			&& selected_certificate == 0)
		{
			status = compare_id_and_certificate(&used_certificate_id, &m_dummy_test_peer_certificate);
			if (status == eap_status_ok)
			{
				selected_certificate = &m_dummy_test_peer_certificate;
			}
		}
	}

	status = m_ec_algorithms->verify_signature_with_public_key(
		selected_certificate,
		hash_of_message,
		signature);


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::read_certificate_wapi_identity(
	const eap_variable_data_c * const certificate,
	eap_variable_data_c * const certificate_wapi_identity)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::read_certificate_wapi_identity():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::read_certificate_wapi_identity()");

	if (certificate_wapi_identity == 0
		|| certificate_wapi_identity->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	wapi_certificate_asn1_der_parser_c parser(m_am_tools);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = parser.decode(certificate);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = parser.read_certificate_id(
		certificate_wapi_identity);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::copy_certificate_wapi_identities(
	EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const certificates_id_list,
	eap_array_c<eap_variable_data_c> * const wapi_identities_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::copy_certificate_wapi_identities():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::copy_certificate_wapi_identities()");

	eap_status_e status(eap_status_ok);

	if (certificates_id_list == 0
		|| wapi_identities_list == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	ec_cs_tlv_c master_key_handler(m_am_tools, true);
	if (master_key_handler.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	for (u32_t ind = 0; ind < certificates_id_list->get_object_count(); ++ind)
	{
		eap_variable_data_c * const certificate_wapi_identity = new eap_variable_data_c(m_am_tools);

		eap_automatic_variable_c<eap_variable_data_c> automatic_certificate_wapi_identity(m_am_tools, certificate_wapi_identity);

		if (certificate_wapi_identity == 0
			|| certificate_wapi_identity->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		const ec_cs_data_c * const id_reference = certificates_id_list->get_object(ind);

		if (id_reference != 0
			&& id_reference->get_is_valid() == true)
		{
			ec_cs_tlv_payloads_c parser(
				m_am_tools,
				true);
			if (parser.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_variable_data_c id_reference_MAC_key(m_am_tools);
			if (id_reference_MAC_key.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = master_key_handler.generate_data_key(
				false,
				id_reference->get_type(),
				&id_reference_MAC_key,
				&m_PAC_store_master_key,
				id_reference->get_reference(),
				&m_PAC_store_device_seed);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = master_key_handler.parse_data_with_MAC(
				&id_reference_MAC_key,
				id_reference->get_data() ///< This is the start of the message buffer.
				);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			const ec_cs_variable_data_c * const ID_reference_data_tlv = master_key_handler.get_payloads()->get_tlv_pointer(ec_cs_tlv_type_CS_ID_reference);
			if (ID_reference_data_tlv == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			ec_cs_tlv_payloads_c id_parser(
				m_am_tools,
				true);
			if (id_parser.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			{
				u32_t length(ID_reference_data_tlv->get_header()->get_data_length());
				u32_t padding_length(0ul);

				status = id_parser.parse_ec_cs_payloads(
					ID_reference_data_tlv->get_header()->get_data(ID_reference_data_tlv->get_data_length()), ///< This is the start of the message buffer.
					&length, ///< This is the length of the buffer. This must match with the length of all payloads.
					&padding_length ///< Length of possible padding is set to this variable.
					);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}


			const ec_cs_variable_data_c * const asu_id_data_tlv = id_parser.get_tlv_pointer(ec_cs_tlv_type_CS_ASU_ID);
			if (asu_id_data_tlv == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			status = certificate_wapi_identity->set_copy_of_buffer(
				asu_id_data_tlv->get_data(asu_id_data_tlv->get_data_length()),
				asu_id_data_tlv->get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("certificate_wapi_identity"),
				certificate_wapi_identity->get_data(),
				certificate_wapi_identity->get_data_length()));

			automatic_certificate_wapi_identity.do_not_free_variable();

			status = wapi_identities_list->add_object(certificate_wapi_identity, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::read_id_of_certificate(
	const eap_variable_data_c * const certificate)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::read_id_of_certificate():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::read_id_of_certificate()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c certificate_wapi_id(m_am_tools);
	if (certificate_wapi_id.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = read_certificate_wapi_identity(
		certificate,
		&certificate_wapi_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_partner->complete_read_id_of_certificate(&certificate_wapi_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::create_ecdh_temporary_keys()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::create_ecdh_temporary_keys():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::create_ecdh_temporary_keys()");

	eap_status_e status = m_ec_algorithms->create_ecdh_temporary_keys();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::create_ecdh(
	const eap_variable_data_c * const own_private_key_d,
	const eap_variable_data_c * const peer_public_key_x,
	const eap_variable_data_c * const peer_public_key_y)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::create_ecdh():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::create_ecdh()");

	eap_status_e status = m_ec_algorithms->create_ecdh(
		own_private_key_d,
		peer_public_key_x,
		peer_public_key_y);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::complete_create_signature_with_private_key(
	const eap_variable_data_c * const signature,
	const eap_status_e signature_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::complete_create_signature_with_private_key():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::complete_create_signature_with_private_key()");

	eap_status_e status = m_partner->complete_create_signature_with_private_key(signature, signature_status);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::complete_verify_signature_with_public_key(
	const eap_status_e verification_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::complete_verify_signature_with_public_key():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::complete_verify_signature_with_public_key()");

	eap_status_e status = m_partner->complete_verify_signature_with_public_key(verification_status);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::complete_create_ecdh_temporary_keys(
	const eap_variable_data_c * const private_key_d,
	const eap_variable_data_c * const public_key_x,
	const eap_variable_data_c * const public_key_y)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::complete_create_ecdh_temporary_keys():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::complete_create_ecdh_temporary_keys()");

	eap_status_e status = m_partner->complete_create_ecdh_temporary_keys(private_key_d, public_key_x, public_key_y);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::complete_create_ecdh(
	const eap_variable_data_c * const K_AB_x4,
	const eap_variable_data_c * const K_AB_y4)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::complete_create_ecdh():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::complete_create_ecdh()");

	eap_status_e status = m_partner->complete_create_ecdh(K_AB_x4, K_AB_y4);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::complete_initialize_certificate_store(
	const wapi_completion_operation_e completion_operation)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::complete_initialize_certificate_store():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::complete_initialize_certificate_store()");

	eap_status_e status(eap_status_ok);

	m_certificate_store_initialized = true;

	if (m_complete_start_certificate_import == true)
	{
		set_pending_operation(ec_cs_pending_operation_none);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls: ec_certificate_store_c::complete_initialize_certificate_store(): %d.\n"),
			__LINE__));

		status = m_am_certificate_store->complete_start_certificate_import();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = completion_action_check();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::remove_cached_certificate_store_data()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::remove_cached_certificate_store_data():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::remove_cached_certificate_store_data()");

	eap_status_e status(eap_status_ok);

	save_data_to_permanent_store();

	m_certificate_store_initialized = false;

	m_master_key_changed = false;

	m_PAC_store_master_key.reset();

	m_PAC_store_password.reset();

	m_PAC_store_device_seed.reset();

	eap_variable_data_c key(m_am_tools);

	status = key.set_copy_of_buffer(
		WAPI_CS_MEMORY_STORE_KEY,
		sizeof(WAPI_CS_MEMORY_STORE_KEY));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	(void) m_am_tools->memory_store_remove_data(&key);

	status = m_imported_certificate_wapi_id.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_imported_certificate_data.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_imported_certificate_file_data.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_imported_certificate_filename.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = m_imported_private_key_data.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = m_ae_certificate.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = m_selected_ca_id.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_selected_client_id.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = m_ca_asu_id_list.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_read_ca_asu_id_list = false;

	status = m_client_asu_id_list.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_read_client_asu_id_list = false;

	status = m_ca_certificates.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_client_certificates.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_client_private_keys.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_broken_cs_data_list.reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::read_PEM_data_line(
	const eap_variable_data_c * const in_imported_certificate_file_data,
	u32_t * const offset,
	eap_variable_data_c * const line)
{
	if (in_imported_certificate_file_data == 0
		|| offset == 0
		|| in_imported_certificate_file_data->get_data_length() < *offset)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (*offset >= in_imported_certificate_file_data->get_data_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_end_of_file);
	}

	u32_t remain_data_size(in_imported_certificate_file_data->get_data_length() - *offset);

	const u8_t * const start = in_imported_certificate_file_data->get_data_offset(*offset, remain_data_size);
	if (start == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u8_t * data = start;
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	const u8_t * const end = start + remain_data_size;
	if (end == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	while (data < end && *data != '\n' && *data != '\r')
	{
		++data;
	}

	eap_status_e status = line->set_buffer(start, (data - start), false, false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (data < end)
	{
		if (*data == '\r')
		{
			++data;
		}

		if (*data == '\n')
		{
			++data;
		}
	}

	*offset += (data - start);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::convert_PEM_to_DER(
	const wapi_pem_data_type_e key_type,
	const eap_variable_data_c * const pem_data,
	eap_array_c<ec_cs_data_c> * const der_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::convert_PEM_to_DER():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::convert_PEM_to_DER()");

	ec_cs_data_c data(m_am_tools);
	if (data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = data.get_writable_data()->set_buffer_length(pem_data->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = data.get_writable_data()->set_data_length(data.get_writable_data()->get_buffer_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t der_data_length(data.get_writable_data()->get_data_length());

	status = m_am_tools->restore_bytes_from_ascii_armor(
		pem_data->get_data(),
		pem_data->get_data_length(),
		data.get_writable_data()->get_data(der_data_length),
		&der_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = data.get_writable_data()->set_data_length(der_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("data"),
		data.get_writable_data()->get_data(),
		data.get_writable_data()->get_data_length()));

	if (key_type == wapi_pem_data_type_certificate)
	{
		eap_variable_data_c certificate_wapi_id(m_am_tools);
		if (certificate_wapi_id.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = read_certificate_wapi_identity(
			data.get_data(),
			&certificate_wapi_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("certificate_wapi_id"),
			certificate_wapi_id.get_data(),
			certificate_wapi_id.get_data_length()));

		ec_cs_data_type_e data_type(ec_cs_data_type_none);

		status = read_certificate_type(&certificate_wapi_id, &data_type);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data.set_type(data_type);
	}
	else if (key_type == wapi_pem_data_type_private_key)
	{
		data.set_type(ec_cs_data_type_private_key_data);
	}
	else
	{
		EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);
	}

	status = der_data->add_object(data.copy(), true);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


#if defined(USE_WAPI_PEM_TO_DER_TEST)

	{
		// This is test code for PEM decode/encode.

		eap_variable_data_c pem_data_2(m_am_tools);
		if (pem_data_2.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = pem_data_2.set_buffer_length(3ul + data.get_data()->get_data_length() * 8 / 6);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = pem_data_2.set_data_length(pem_data_2.get_buffer_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u32_t pem_data_length(pem_data->get_data_length());

		status = m_am_tools->convert_bytes_to_ascii_armor(
			data.get_data()->get_data(),
			data.get_data()->get_data_length(),
			pem_data_2.get_data(der_data_length),
			&pem_data_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = pem_data_2.set_data_length(pem_data_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("pem_data_2"),
			pem_data_2.get_data(),
			pem_data_2.get_data_length()));

		if (pem_data->compare(&pem_data_2) != 0)
		{
			EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
		}
	}

#endif //#if defined(USE_WAPI_PEM_TO_DER_TEST)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::parse_PEM_file_data(
	const eap_variable_data_c * const in_imported_certificate_file_data,
	eap_array_c<ec_cs_data_c> * const der_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::parse_PEM_file_data():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::parse_PEM_file_data()");

	eap_status_e status(eap_status_not_supported);

	u32_t offset(0ul);

	eap_variable_data_c line(m_am_tools);
	if (line.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c pem_data(m_am_tools);
	if (pem_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	wapi_pem_data_type_e data_type(wapi_pem_data_type_none);
	wapi_pem_read_state_e state(wapi_pem_read_state_header);

	do
	{
		status = read_PEM_data_line(in_imported_certificate_file_data, &offset, &line);
		if (status == eap_status_end_of_file)
		{
			// In the end of file status is eap_status_end_of_file. We change that to OK status.
			status = eap_status_ok;
			break;
		}
		else if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (state == wapi_pem_read_state_header)
		{
			if (wapi_pem_certificate_begin.get_field()->compare(
					m_am_tools,
					&line) == true)
			{
				state = wapi_pem_read_state_data;
				data_type = wapi_pem_data_type_certificate;
			}
			else if (wapi_pem_ec_private_key_begin.get_field()->compare(
					m_am_tools,
					&line) == true)
			{
				state = wapi_pem_read_state_data;
				data_type = wapi_pem_data_type_private_key;
			}
		}
		else if (state == wapi_pem_read_state_data)
		{
			if (data_type == wapi_pem_data_type_certificate
				&& wapi_pem_certificate_end.get_field()->compare(
					m_am_tools,
					&line) == true)
			{
				status = convert_PEM_to_DER(
					data_type,
					&pem_data,
					der_data);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				pem_data.reset_start_offset_and_data_length();

				state = wapi_pem_read_state_header;
			}
			else if (data_type == wapi_pem_data_type_private_key
				&& wapi_pem_ec_private_key_end.get_field()->compare(
					m_am_tools,
					&line) == true)
			{
				status = convert_PEM_to_DER(
					data_type,
					&pem_data,
					der_data);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				pem_data.reset_start_offset_and_data_length();

				state = wapi_pem_read_state_header;
			}
			else
			{
				status = pem_data.add_data(&line);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
	}
	while(status == eap_status_ok);


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::read_certificate_type(
	const eap_variable_data_c * const imported_certificate_wapi_id,
	ec_cs_data_type_e * const data_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::read_certificate_type():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::read_certificate_type()");

	eap_status_e status(eap_status_not_supported);


	wapi_asn1_der_parser_c wapi_asn1_der_parser(m_am_tools);

	if (wapi_asn1_der_parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = wapi_asn1_der_parser.decode(imported_certificate_wapi_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c asn1_der_subject_name(m_am_tools);
	eap_variable_data_c asn1_der_issuer_name(m_am_tools);
	eap_variable_data_c asn1_der_sequence_number(m_am_tools);

	status = wapi_asn1_der_parser.get_wapi_identity(
		&asn1_der_subject_name,
		&asn1_der_issuer_name,
		&asn1_der_sequence_number);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (asn1_der_subject_name.compare(&asn1_der_issuer_name) == 0)
	{
		*data_type = ec_cs_data_type_ca_certificate_data;
	}
	else
	{
		*data_type = ec_cs_data_type_client_certificate_data;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::read_certificate_reference(
	const ec_cs_data_c * const reference_tlv,
	eap_variable_data_c * const certificate_reference)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::read_certificate_reference():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::read_certificate_reference()");

	eap_status_e status(eap_status_not_supported);

	ec_cs_tlv_header_c id_reference_tlv(
		m_am_tools,
		reference_tlv->get_data()->get_data(),
		reference_tlv->get_data()->get_data_length());
	if (id_reference_tlv.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	ec_cs_tlv_payloads_c parser(
		m_am_tools,
		true);
	if (parser.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t length(id_reference_tlv.get_data_length());
	u32_t padding_length(0ul);

	status = parser.parse_ec_cs_payloads(
		id_reference_tlv.get_data(length), ///< This is the start of the message buffer.
		&length, ///< This is the length of the buffer. This must match with the length of all payloads.
		&padding_length ///< Length of possible padding is set to this variable.
		);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const ec_cs_variable_data_c * const certificate_reference_tlv = parser.get_tlv_pointer(ec_cs_tlv_type_CS_certificate_reference);
	if (certificate_reference_tlv == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	status = certificate_reference->set_copy_of_buffer(
		certificate_reference_tlv->get_data(certificate_reference_tlv->get_data_length()),
		certificate_reference_tlv->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::read_certificate(
	const ec_cs_pending_operation_e pending_operation,
	const ec_cs_data_type_e certificate_type,
	const eap_variable_data_c * certificate_reference)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::read_certificate():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::read_certificate()");

	eap_status_e status(eap_status_not_supported);

	eap_array_c<ec_cs_data_c> in_references(m_am_tools);

	{
		ec_cs_data_c * const data = new ec_cs_data_c(m_am_tools);

		eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, data);

		if (data == 0
			|| data->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = data->get_writable_reference()->set_copy_of_buffer(certificate_reference);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data->set_type(certificate_type);

		automatic_data.do_not_free_variable();

		status = in_references.add_object(data, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	if (certificate_type == ec_cs_data_type_client_certificate_data)
	{
		ec_cs_data_c * const data = new ec_cs_data_c(m_am_tools);

		eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, data);

		if (data == 0
			|| data->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = data->get_writable_reference()->set_copy_of_buffer(certificate_reference);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data->set_type(ec_cs_data_type_private_key_data);

		automatic_data.do_not_free_variable();

		status = in_references.add_object(data, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = m_am_certificate_store->read_certificate_store_data(
		pending_operation,
		&in_references);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::read_both_certificate_lists(
	const ec_cs_pending_operation_e pending_operation)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::read_both_certificate_lists():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::read_both_certificate_lists()");

	eap_status_e status(eap_status_not_supported);

	eap_array_c<ec_cs_data_c> in_references(m_am_tools);

	status = add_password_qyery(&in_references);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_read_ca_asu_id_list == false)
	{
		ec_cs_data_c * const data = new ec_cs_data_c(m_am_tools);

		eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, data);

		if (data == 0
			|| data->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data->set_type(ec_cs_data_type_ca_asu_id_list);

		automatic_data.do_not_free_variable();

		status = in_references.add_object(data, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}
	else
	{
		status = eap_status_ok;
	}

	if (m_read_client_asu_id_list == false)
	{
		ec_cs_data_c * const data = new ec_cs_data_c(m_am_tools);

		eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, data);

		if (data == 0
			|| data->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data->set_type(ec_cs_data_type_client_asu_id_list);

		automatic_data.do_not_free_variable();

		status = in_references.add_object(data, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = eap_status_ok;
	}

	if (in_references.get_object_count() > 0ul)
	{
		m_read_ca_asu_id_list = true;
		m_read_client_asu_id_list = true;

		status = m_am_certificate_store->read_certificate_store_data(
			pending_operation,
			&in_references);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::read_ca_certificate_list(
	const ec_cs_pending_operation_e pending_operation)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::read_ca_certificate_list():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::read_ca_certificate_list()");

	eap_status_e status(eap_status_not_supported);

	eap_array_c<ec_cs_data_c> in_references(m_am_tools);

	status = add_password_qyery(&in_references);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_read_ca_asu_id_list == false)
	{
		ec_cs_data_c * const data = new ec_cs_data_c(m_am_tools);

		eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, data);

		if (data == 0
			|| data->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data->set_type(ec_cs_data_type_ca_asu_id_list);

		automatic_data.do_not_free_variable();

		status = in_references.add_object(data, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = eap_status_ok;
	}

	if (in_references.get_object_count() > 0ul)
	{
		status = m_am_certificate_store->read_certificate_store_data(
			pending_operation,
			&in_references);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

eap_status_e ec_certificate_store_c::read_client_certificate_list(
	const ec_cs_pending_operation_e pending_operation)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::read_client_certificate_list():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::read_client_certificate_list()");

	eap_status_e status(eap_status_not_supported);

	eap_array_c<ec_cs_data_c> in_references(m_am_tools);

	status = add_password_qyery(&in_references);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_read_client_asu_id_list == false)
	{
		ec_cs_data_c * const data = new ec_cs_data_c(m_am_tools);

		eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, data);

		if (data == 0
			|| data->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data->set_type(ec_cs_data_type_client_asu_id_list);

		automatic_data.do_not_free_variable();

		status = in_references.add_object(data, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = eap_status_ok;
	}


	if (in_references.get_object_count() > 0ul)
	{
		status = m_am_certificate_store->read_certificate_store_data(
			pending_operation,
			&in_references);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::add_imported_certificate_file(
	const eap_variable_data_c * const in_imported_certificate_file_data,
	const eap_variable_data_c * const in_imported_certificate_filename)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::add_imported_certificate_file():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::add_imported_certificate_file()");

	eap_status_e status(eap_status_not_supported);

	if (in_imported_certificate_file_data == 0
		|| in_imported_certificate_file_data->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (in_imported_certificate_filename == 0
		|| in_imported_certificate_filename->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("in_imported_certificate_filename"),
		in_imported_certificate_filename->get_data(),
		in_imported_certificate_filename->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("in_imported_certificate_file_data"),
		in_imported_certificate_file_data->get_data(),
		in_imported_certificate_file_data->get_data_length()));

	eap_array_c<ec_cs_data_c> der_data(m_am_tools);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_imported_certificate_file_data.set_copy_of_buffer(in_imported_certificate_file_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_imported_certificate_filename.set_copy_of_buffer(in_imported_certificate_filename);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_imported_certificate_data.reset_start_offset_and_data_length();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_imported_private_key_data.reset_start_offset_and_data_length();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = completion_action_push(ec_cs_completion_complete_add_imported_certificate_file);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_PAC_store_master_key.get_is_valid_data() == true
		&& m_PAC_store_password.get_is_valid_data() == true
		&& m_PAC_store_device_seed.get_is_valid_data() == true)
	{
		status = internal_complete_add_imported_certificate_file();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		status = completion_action_push(ec_cs_completion_internal_complete_add_imported_certificate_file);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = completion_action_push(ec_cs_completion_query_PAC_store_password);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// If there were no asyncronous calls operations continue here.
	status = completion_action_check();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::internal_complete_add_imported_certificate_file()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::internal_complete_add_imported_certificate_file():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::internal_complete_add_imported_certificate_file()");

	eap_status_e status(eap_status_not_supported);

	if (m_imported_certificate_file_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_imported_certificate_filename.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_imported_certificate_filename"),
		m_imported_certificate_filename.get_data(),
		m_imported_certificate_filename.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_imported_certificate_file_data"),
		m_imported_certificate_file_data.get_data(),
		m_imported_certificate_file_data.get_data_length()));

	eap_array_c<ec_cs_data_c> der_data(m_am_tools);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = parse_PEM_file_data(&m_imported_certificate_file_data, &der_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	ec_cs_data_type_e data_type(ec_cs_data_type_none);

	for (u32_t index = 0ul; index < der_data.get_object_count(); ++index)
	{
		ec_cs_data_c * const data = der_data.get_object(index);
		if (data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_index);
		}

		if (data->get_type() == ec_cs_data_type_ca_certificate_data
			|| data->get_type() == ec_cs_data_type_client_certificate_data)
		{
			data_type = data->get_type();

			status = read_certificate_wapi_identity(
				data->get_data(),
				&m_imported_certificate_wapi_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("m_imported_certificate_wapi_id"),
				m_imported_certificate_wapi_id.get_data(),
				m_imported_certificate_wapi_id.get_data_length()));

			status = m_imported_certificate_data.set_copy_of_buffer(data->get_data());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (data->get_type() == ec_cs_data_type_private_key_data)
		{
			status = m_imported_private_key_data.set_copy_of_buffer(data->get_data());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

	} // for()


	if (data_type == ec_cs_data_type_ca_certificate_data)
	{
		status = completion_action_push(ec_cs_completion_add_imported_ca_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = read_ca_certificate_list(ec_cs_pending_operation_import_ca_certificate_file);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else //if (data_type == ec_cs_data_type_client_certificate_data)
	{
		status = completion_action_push(ec_cs_completion_add_imported_client_certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = read_client_certificate_list(ec_cs_pending_operation_import_client_certificate_file);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// If there were no asyncronous calls operations continue here.
	status = completion_action_check();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e ec_certificate_store_c::save_to_broken_cs_data_list(
	const ec_cs_data_c * const ref_and_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: ec_certificate_store_c::save_to_broken_cs_data_list():\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::save_to_broken_cs_data_list()");

	eap_status_e status(eap_status_ok);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (ref_and_data != 0)
	{
		ec_cs_data_c * const new_ec_cd_data = ref_and_data->copy();
		if (new_ec_cd_data != 0)
		{
			new_ec_cd_data->set_change_status(ec_cs_data_change_status_delete);

			status = m_broken_cs_data_list.add_object(new_ec_cd_data, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (ref_and_data->get_type() == ec_cs_data_type_ca_certificate_data)
		{
			// We must remove the broken ID-Reference too.
			ec_cs_data_c search_id(m_am_tools);

			eap_status_e status = search_id.get_writable_data()->set_buffer(
				ref_and_data->get_reference());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			eap_variable_data_c certificate_reference(m_am_tools);

			ec_cs_compare_reference_c compare_reference(m_am_tools);

			const ec_cs_data_c * identity_reference_tlv = 0;

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::save_to_broken_cs_data_list(): count of m_ca_asu_id_list = %d.\n"),
				 this,
				 (m_is_client == true ? "client": "server"),
				 m_ca_asu_id_list.get_object_count()));

			// Search CA-Certificate identity.
			i32_t index = find_with_compare<ec_cs_data_c>(
				&compare_reference,
				&m_ca_asu_id_list,
				&search_id,
				m_am_tools);
			if (index >= 0)
			{
				// Match.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::save_to_broken_cs_data_list(): CA certificate ID list match.\n"),
					 this,
					 (m_is_client == true ? "client": "server")));

				identity_reference_tlv = m_ca_asu_id_list.get_object(index);

				if (identity_reference_tlv != 0)
				{
					ec_cs_data_c * const new_ec_cd_data = identity_reference_tlv->copy();
					if (new_ec_cd_data != 0)
					{
						new_ec_cd_data->set_change_status(ec_cs_data_change_status_delete);

						status = m_broken_cs_data_list.add_object(new_ec_cd_data, true);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
				}
			}
		}
		else if (ref_and_data->get_type() == ec_cs_data_type_client_certificate_data
			|| ref_and_data->get_type() == ec_cs_data_type_private_key_data)
		{
			// We must remove the broken ID-Reference too.
			ec_cs_data_c search_id(m_am_tools);

			eap_status_e status = search_id.get_writable_data()->set_buffer(
				ref_and_data->get_reference());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			eap_variable_data_c certificate_reference(m_am_tools);

			ec_cs_compare_reference_c compare_reference(m_am_tools);

			const ec_cs_data_c * identity_reference_tlv = 0;

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::save_to_broken_cs_data_list(): count of m_client_asu_id_list = %d.\n"),
				 this,
				 (m_is_client == true ? "client": "server"),
				 m_client_asu_id_list.get_object_count()));

			// Search CA-Certificate identity.
			i32_t index = find_with_compare<ec_cs_data_c>(
				&compare_reference,
				&m_client_asu_id_list,
				&search_id,
				m_am_tools);
			if (index >= 0)
			{
				// Match.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::save_to_broken_cs_data_list(): CA certificate ID list match.\n"),
					 this,
					 (m_is_client == true ? "client": "server")));

				identity_reference_tlv = m_client_asu_id_list.get_object(index);

				if (identity_reference_tlv != 0)
				{
					ec_cs_data_c * const new_ec_cd_data = identity_reference_tlv->copy();
					if (new_ec_cd_data != 0)
					{
						new_ec_cd_data->set_change_status(ec_cs_data_change_status_delete);

						status = m_broken_cs_data_list.add_object(new_ec_cd_data, true);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
				}
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e ec_certificate_store_c::save_to_ec_cs_list(
	eap_array_c<ec_cs_data_c> * const ec_cs_list,
	const ec_cs_data_c * const ref_and_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: ec_certificate_store_c::save_to_ec_cs_list():\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::save_to_ec_cs_list()");

	eap_status_e status(eap_status_ok);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (ref_and_data != 0)
	{
		ec_cs_data_c * const new_ec_cd_data = ref_and_data->copy();
		if (new_ec_cd_data != 0)
		{
			status = ec_cs_list->add_object(new_ec_cd_data, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e ec_certificate_store_c::save_ec_cs_data(
	EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const in_references_and_data_blocks)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: ec_certificate_store_c::save_ec_cs_data(): data_block_count %d\n"),
		in_references_and_data_blocks->get_object_count()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::save_ec_cs_data()");

	eap_status_e status(eap_status_ok);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	ec_cs_tlv_c handler(m_am_tools, true);

	for (u32_t ind = 0ul; ind < in_references_and_data_blocks->get_object_count(); ++ind)
	{
		const ec_cs_data_c * const ref_and_data = in_references_and_data_blocks->get_object(ind);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WAPI_Core: ec_certificate_store_c::save_ec_cs_data(): ref_and_data=0x%08x\n"),
			ref_and_data));

		if (ref_and_data != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("reference 0x%08x: type %d=%s, change status %d=%s\n"),
				ref_and_data,
				ref_and_data->get_type(),
				ec_cs_strings_c::get_ec_cs_store_data_string(ref_and_data->get_type()),
				ref_and_data->get_change_status(),
				ec_cs_strings_c::get_ec_cs_store_data_change_status_string(ref_and_data->get_change_status())));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("reference"),
				 ref_and_data->get_reference()->get_data(),
				 ref_and_data->get_reference()->get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("data"),
				 ref_and_data->get_data()->get_data(),
				 ref_and_data->get_data()->get_data_length()));
		}

		if (ref_and_data != 0
			&& ref_and_data->get_is_valid() == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("reference 0x%08x: type %d=%s, change status %d=%s\n"),
				ref_and_data,
				ref_and_data->get_type(),
				ec_cs_strings_c::get_ec_cs_store_data_string(ref_and_data->get_type()),
				ref_and_data->get_change_status(),
				ec_cs_strings_c::get_ec_cs_store_data_change_status_string(ref_and_data->get_change_status())));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("reference"),
				 ref_and_data->get_reference()->get_data(),
				 ref_and_data->get_reference()->get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("data"),
				 ref_and_data->get_data()->get_data(),
				 ref_and_data->get_data()->get_data_length()));

			if (ref_and_data->get_type() == ec_cs_data_type_ca_asu_id)
			{
				if (ref_and_data->get_data() != 0
					&& ref_and_data->get_data()->get_is_valid_data() == true
					&& ref_and_data->get_data()->get_data_length() > 0ul)
				{
					status = handler.verify_data_with_MAC(
						&m_PAC_store_master_key,
						&m_PAC_store_device_seed,
						ref_and_data);
					if (status != eap_status_ok)
					{
						status = save_to_broken_cs_data_list(ref_and_data);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						continue;
					}

					status = save_to_ec_cs_list(&m_ca_asu_id_list, ref_and_data);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}

				m_read_ca_asu_id_list = true;
			}
			else if (ref_and_data->get_type() == ec_cs_data_type_client_asu_id)
			{
				if (ref_and_data->get_data() != 0
					&& ref_and_data->get_data()->get_is_valid_data() == true
					&& ref_and_data->get_data()->get_data_length() > 0ul)
				{
					status = handler.verify_data_with_MAC(
						&m_PAC_store_master_key,
						&m_PAC_store_device_seed,
						ref_and_data);
					if (status != eap_status_ok)
					{
						status = save_to_broken_cs_data_list(ref_and_data);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						continue;
					}

					status = save_to_ec_cs_list(&m_client_asu_id_list, ref_and_data);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}

				m_read_client_asu_id_list = true;
			}

			else if (ref_and_data->get_type() == ec_cs_data_type_reference_counter)
			{
				if (ref_and_data->get_data() != 0
					&& ref_and_data->get_data()->get_is_valid_data() == true
					&& ref_and_data->get_reference()->get_is_valid_data() == true
					&& ref_and_data->get_data()->get_data_length() > 0ul
					&& ref_and_data->get_reference()->get_data_length() > 0ul)
				{
					/*
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
					 * | Type=Referene counter TLV     |           Length=4            |  |
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
					 * |                    reference counter (4 octets)               |  |
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
					 * | Type=CS-MAC TLV               |           Length=32           |  |
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
					 * |                              MAC (32 octets)                  |  |
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
					 */

					ec_cs_tlv_c master_key_handler(m_am_tools, true);
					if (master_key_handler.get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					eap_variable_data_c MAC_key(m_am_tools);
					if (MAC_key.get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					status = master_key_handler.generate_data_key(
						false,
						ec_cs_data_type_reference_counter,
						&MAC_key,
						&m_PAC_store_master_key,
						ref_and_data->get_reference(),
						&m_PAC_store_device_seed);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = master_key_handler.parse_data_with_MAC(
						&MAC_key,
						ref_and_data->get_data());
					if (status != eap_status_ok)
					{
						// Cannot continue, terminate authentication.
						(void) m_partner->set_session_timeout(0ul);
						(void) send_error_notification(eap_status_pac_store_corrupted);

						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					const ec_cs_variable_data_c * const master_key_encrypted_block_tlv
						= master_key_handler.get_payloads()->get_tlv_pointer(ec_cs_tlv_type_CS_reference_counter);
					if (master_key_encrypted_block_tlv == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
					}

					void * const network_order_counter = master_key_encrypted_block_tlv->get_data(sizeof(m_reference_counter));

					if (network_order_counter != 0)
					{
						m_reference_counter = eap_read_u32_t_network_order(
							network_order_counter,
							sizeof(m_reference_counter));

						status = eap_status_ok;
					}
				}
				else
				{
					// No data.
					status = eap_status_ok;
				}

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Read reference counter = 0x%08x\n"),
					 m_reference_counter));

				m_reference_counter_read = true;
			}
			else if (ref_and_data->get_type() == ec_cs_data_type_master_key)
			{
				if (ref_and_data->get_data() != 0
					&& ref_and_data->get_data()->get_is_valid_data() == true
					&& ref_and_data->get_reference()->get_is_valid_data() == true
					&& ref_and_data->get_data()->get_data_length() > 0ul
					&& ref_and_data->get_reference()->get_data_length() > 0ul)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ec_certificate_store_c::save_ec_cs_data(): Read master key from database.\n")));

					/*
					 * Master key data
					 *
 					 * 0                   1                   2                   3   
					 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    -+ -+
					 * | Type=CS-Encrypted block TLV   |     Length=4+16+4+n+4+m       |     |  |
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+  |  |
					 * | Type=CS-Encryption IV TLV     |           Length=16           |  |  |  | plain text
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  |
					 * |                              IV (16 octets)                   |  |  |  |
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+  |  |
					 * | Type=CS-Encrypted data TLV    |           Length=n+4+m        |  |  |  |
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  | -+
					 * |                          Master key TLV (n octets)            |  |  |  |
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  | encrypted
					 * | Type=CS-padding TLV           |           Length=m            |  |  |  | multiple of
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |  |  | 16 octets
					 * |                           padding (m octets)                  |  |  |  |
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+ -+ -+
					 * | Type=CS-MAC TLV               |           Length=32           |  |
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
					 * |                              MAC (32 octets)                  |  |
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
					 */

					ec_cs_tlv_c master_key_handler(m_am_tools, true);
					if (master_key_handler.get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					eap_variable_data_c MAC_key(m_am_tools);
					if (MAC_key.get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					status = master_key_handler.generate_data_key(
						false,
						ec_cs_data_type_master_key,
						&MAC_key,
						&m_PAC_store_password,
						ref_and_data->get_reference(),
						&m_PAC_store_device_seed);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = master_key_handler.parse_data_with_MAC(
						&MAC_key,
						ref_and_data->get_data());
					if (status == eap_status_authentication_failure)
					{
						// Ask password again.
						(void) m_PAC_store_password.reset();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
					}
					else if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					const ec_cs_variable_data_c * const master_key_encrypted_block_tlv
						= master_key_handler.get_payloads()->get_tlv_pointer(ec_cs_tlv_type_CS_encrypted_block);
					if (master_key_encrypted_block_tlv == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
					}

					ec_cs_variable_data_c master_key_plain_data_tlv(m_am_tools);
					if (master_key_plain_data_tlv.get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					eap_variable_data_c master_key_decryption_key(m_am_tools);
					if (master_key_decryption_key.get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					status = master_key_handler.generate_data_key(
						true,
						ec_cs_data_type_master_key,
						&master_key_decryption_key,
						&m_PAC_store_password,
						ref_and_data->get_reference(),
						&m_PAC_store_device_seed);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					ec_cs_tlv_c decrypt_handler(m_am_tools, true);
					if (decrypt_handler.get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					status = decrypt_handler.parse_encrypted_tlv(
						&master_key_decryption_key,
						master_key_encrypted_block_tlv,
						&master_key_plain_data_tlv);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = decrypt_handler.parse_cs_tlv(
						&master_key_plain_data_tlv);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					const ec_cs_variable_data_c * const master_key_tlv
						= decrypt_handler.get_payloads()->get_tlv_pointer(ec_cs_tlv_type_CS_master_key);
					if (master_key_tlv == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
					}

					status = m_PAC_store_master_key.set_copy_of_buffer(
						master_key_tlv->get_data(master_key_tlv->get_data_length()),
						master_key_tlv->get_data_length());
				}
				else
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ec_certificate_store_c::save_ec_cs_data(): Creates new master key.\n")));

					// Create a new master key.
					crypto_random_c rand(m_am_tools);

					if (rand.get_is_valid() == false)
					{
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = m_PAC_store_master_key.set_buffer_length(EAP_FAST_PAC_STORE_MASTER_KEY_SIZE);
					if (status != eap_status_ok)
					{
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = m_PAC_store_master_key.set_data_length(EAP_FAST_PAC_STORE_MASTER_KEY_SIZE);
					if (status != eap_status_ok)
					{
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = rand.get_rand_bytes(
						m_PAC_store_master_key.get_data(
							m_PAC_store_master_key.get_data_length()),
						m_PAC_store_master_key.get_data_length());
					if (status != eap_status_ok)
					{
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					m_master_key_changed = true;
				}

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CS store master key"),
					 m_PAC_store_master_key.get_data(),
					 m_PAC_store_master_key.get_data_length()));
			}
			else if (ref_and_data->get_type() == ec_cs_data_type_password)
			{
				if (ref_and_data->get_data() != 0
					&& ref_and_data->get_data()->get_is_valid_data() == true
					&& ref_and_data->get_data()->get_data_length() > 0ul)
				{
					status = m_PAC_store_password.set_copy_of_buffer(ref_and_data->get_data());
				}

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Read CS store password"),
					 m_PAC_store_password.get_data(),
					 m_PAC_store_password.get_data_length()));
			}
			else if (ref_and_data->get_type() == ec_cs_data_type_device_seed)
			{
				if (ref_and_data->get_data() != 0
					&& ref_and_data->get_data()->get_is_valid_data() == true
					&& ref_and_data->get_data()->get_data_length() > 0ul)
				{
					status = m_PAC_store_device_seed.set_copy_of_buffer(ref_and_data->get_data());
				}

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Read CS store device seed"),
					 m_PAC_store_device_seed.get_data(),
					 m_PAC_store_device_seed.get_data_length()));
			}
			else if (ref_and_data->get_type() == ec_cs_data_type_ca_certificate_data)
			{
				if (ref_and_data->get_data() != 0
					&& ref_and_data->get_data()->get_is_valid_data() == true
					&& ref_and_data->get_data()->get_data_length() > 0ul)
				{
					status = handler.verify_data_with_MAC(
						&m_PAC_store_master_key,
						&m_PAC_store_device_seed,
						ref_and_data);
					if (status != eap_status_ok)
					{
						status = save_to_broken_cs_data_list(ref_and_data);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						continue;
					}

					status = m_ca_certificates.add_object(ref_and_data->copy(), true);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
			else if (ref_and_data->get_type() == ec_cs_data_type_client_certificate_data)
			{
				if (ref_and_data->get_data() != 0
					&& ref_and_data->get_data()->get_is_valid_data() == true
					&& ref_and_data->get_data()->get_data_length() > 0ul)
				{
					status = handler.verify_data_with_MAC(
						&m_PAC_store_master_key,
						&m_PAC_store_device_seed,
						ref_and_data);
					if (status != eap_status_ok)
					{
						status = save_to_broken_cs_data_list(ref_and_data);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						continue;
					}

					status = m_client_certificates.add_object(ref_and_data->copy(), true);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
			else if (ref_and_data->get_type() == ec_cs_data_type_private_key_data)
			{
				if (ref_and_data->get_data() != 0
					&& ref_and_data->get_data()->get_is_valid_data() == true
					&& ref_and_data->get_data()->get_data_length() > 0ul)
				{
					status = handler.verify_data_with_MAC(
						&m_PAC_store_master_key,
						&m_PAC_store_device_seed,
						ref_and_data);
					if (status != eap_status_ok)
					{
						status = save_to_broken_cs_data_list(ref_and_data);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						continue;
					}

					status = m_client_private_keys.add_object(ref_and_data->copy(), true);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
			else if (ref_and_data->get_type() == ec_cs_data_type_selected_ca_id)
			{
				status = m_selected_ca_id.set_copy_of_buffer(ref_and_data->get_data());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("m_selected_ca_id"),
					 m_selected_ca_id.get_data(),
					 m_selected_ca_id.get_data_length()));
			}
			else if (ref_and_data->get_type() == ec_cs_data_type_selected_client_id)
			{
				status = m_selected_client_id.set_copy_of_buffer(ref_and_data->get_data());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("m_selected_client_id"),
					 m_selected_client_id.get_data(),
					 m_selected_client_id.get_data_length()));
			}
			else
			{
				status = eap_status_illegal_data_payload;
				(void) EAP_STATUS_RETURN(m_am_tools, status);
				EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);
			}

			if (status != eap_status_ok)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WARNING: WAPI_Core: ec_certificate_store_c::save_ec_cs_data(): ignored broken data.\n")));
				status = eap_status_ok;
			}

		}
	} // for()

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = completion_action_check();

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::complete_read_certificate_store_data(
	const eap_status_e in_completion_status,
	const ec_cs_pending_operation_e in_pending_operation,
	EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const in_references_and_data_blocks)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::complete_read_certificate_store_data():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::complete_read_certificate_store_data()");

	eap_status_e status(eap_status_not_supported);

	m_pending_read_ec_cs_data = false;

	if (in_completion_status == eap_status_ok
		&& in_references_and_data_blocks != 0)
	{
		status = save_ec_cs_data(in_references_and_data_blocks);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (in_completion_status != eap_status_ok)
	{
		// Cannot continue, terminate authentication.
		(void) m_partner->set_session_timeout(0ul);

		(void) send_error_notification(in_completion_status);

		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	status = completion_action_check();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::complete_write_certificate_store_data(
	const eap_status_e in_completion_status,
	const ec_cs_pending_operation_e in_pending_operation)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::complete_write_certificate_store_data():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::complete_write_certificate_store_data()");

	// Here we do nothing. Return still OK status that caller does not disturb.
	eap_status_e status(eap_status_ok);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::query_certificate_list()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::query_certificate_list():\n"),
		 this,
		 (m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::query_certificate_list()");

	eap_status_e status(eap_status_not_supported);

	status = completion_action_push(ec_cs_completion_complete_query_certificate_list);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = read_both_certificate_lists(ec_cs_pending_operation_query_certificate_list);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e ec_certificate_store_c::query_PAC_store_password(
	const ec_cs_pending_operation_e in_pending_operation)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: ec_certificate_store_c::query_PAC_store_password()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::query_PAC_store_password()");

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_array_c<ec_cs_data_c> in_references(m_am_tools);

	status = add_password_qyery(&in_references);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (in_references.get_object_count() > 0ul)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("calls: ec_certificate_store_c::query_PAC_store_password(): m_am_pac_store_services->read_PAC_store_data(): %d.\n"),
			__LINE__));

		m_pending_read_ec_cs_data = true;

		status = m_am_certificate_store->read_certificate_store_data(
			in_pending_operation,
			&in_references);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: ec_certificate_store_c::query_PAC_store_password(): Skips m_am_pac_store_services->read_PAC_store_data(): %d.\n"),
			__LINE__));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e ec_certificate_store_c::add_password_qyery(
	eap_array_c<ec_cs_data_c> * const in_references)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP-FAST: ec_certificate_store_c::add_password_qyery()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::add_password_qyery()");

	eap_status_e status(eap_status_ok);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_PAC_store_password.get_is_valid_data() == false)
	{
		ec_cs_data_c * const data = new ec_cs_data_c(m_am_tools);

		eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, data);

		if (data == 0
			|| data->get_is_valid() == false)
		{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data->set_type(ec_cs_data_type_password);

		status = data->get_writable_reference()->set_copy_of_buffer(
			EC_CS_ZERO_REFERENCE,
			sizeof(EC_CS_ZERO_REFERENCE));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		automatic_data.do_not_free_variable();

		status = in_references->add_object(data, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (m_PAC_store_device_seed.get_is_valid_data() == false)
	{
		ec_cs_data_c * const data = new ec_cs_data_c(m_am_tools);

		eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, data);

		if (data == 0
			|| data->get_is_valid() == false)
		{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data->set_type(ec_cs_data_type_device_seed);

		status = data->get_writable_reference()->set_copy_of_buffer(
			EC_CS_ZERO_REFERENCE,
			sizeof(EC_CS_ZERO_REFERENCE));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		automatic_data.do_not_free_variable();

		status = in_references->add_object(data, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (m_PAC_store_master_key.get_is_valid_data() == false)
	{
		ec_cs_data_c * const data = new ec_cs_data_c(m_am_tools);

		eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, data);

		if (data == 0
			|| data->get_is_valid() == false)
		{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = data->get_writable_reference()->set_copy_of_buffer(
			EC_CS_ZERO_REFERENCE,
			sizeof(EC_CS_ZERO_REFERENCE));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data->set_type(ec_cs_data_type_master_key);

		automatic_data.do_not_free_variable();

		status = in_references->add_object(data, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	if (m_reference_counter_read == false)
	{
		ec_cs_data_c * const data = new ec_cs_data_c(m_am_tools);

		eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, data);

		if (data == 0
			|| data->get_is_valid() == false)
		{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data->set_type(ec_cs_data_type_reference_counter);

		status = data->get_writable_reference()->set_copy_of_buffer(
			EC_CS_ZERO_REFERENCE,
			sizeof(EC_CS_ZERO_REFERENCE));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		automatic_data.do_not_free_variable();

		status = in_references->add_object(data, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (m_selected_client_id.get_is_valid_data() == false)
	{
		ec_cs_data_c * const data = new ec_cs_data_c(m_am_tools);

		eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, data);

		if (data == 0
			|| data->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data->set_type(ec_cs_data_type_selected_client_id);

		automatic_data.do_not_free_variable();

		status = in_references->add_object(data, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}

	if (m_selected_ca_id.get_is_valid_data() == false)
	{
		ec_cs_data_c * const data = new ec_cs_data_c(m_am_tools);

		eap_automatic_variable_c<ec_cs_data_c> automatic_data(m_am_tools, data);

		if (data == 0
			|| data->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		data->set_type(ec_cs_data_type_selected_ca_id);

		automatic_data.do_not_free_variable();

		status = in_references->add_object(data, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::start_certificate_import()
{
    EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

     EAP_TRACE_DEBUG(
         m_am_tools,
         TRACE_FLAGS_DEFAULT,
         (EAPL("WAPI_Core: this = 0x%08x, %s: ec_certificate_store_c::start_certificate_import():\n"),
          this,
          (m_is_client == true ? "client": "server")));

     EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::start_certificate_import()");

     eap_status_e status(eap_status_not_supported);

	if (m_pending_operation != ec_cs_pending_operation_none)
	{
		// Some operation is already pending. Try again later.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_device_busy);
	}

#if defined(WAPI_USE_CERTIFICATE_STORE)

	m_complete_start_certificate_import = true;

	status = initialize_certificate_store();

#endif //#if defined(WAPI_USE_CERTIFICATE_STORE)

     EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
     return EAP_STATUS_RETURN(m_am_tools, status);
   
}

//------------------------------------------------------------------------------

EAP_FUNC_EXPORT void ec_certificate_store_c::set_pending_operation(const ec_cs_pending_operation_e operation)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: ec_certificate_store_c::set_pending_operation(): %s => %s\n"),
		ec_cs_strings_c::get_ec_cs_store_data_string(m_pending_operation),
		ec_cs_strings_c::get_ec_cs_store_data_string(operation)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::set_pending_operation()");


	m_pending_operation = operation;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::are_pending_queries_completed()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_pending_request;

	eap_status_string_c status_string;
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: pending_function: starts: ec_certificate_store_c::are_pending_queries_completed(): %s\n"),
		status_string.get_status_string(status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::are_pending_queries_completed()");

	if (m_pending_read_ec_cs_data == false)
	{
		status = eap_status_ok;
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: pending_function: are_pending_queries_completed(): %s\n"),
		status_string.get_status_string(status)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::completion_action_pop()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("WAPI EC CS DB: ec_certificate_store_c::completion_action_pop()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::completion_action_pop()");

	const ec_cs_completion_c * const removed_completion_action = m_completion_queue.get_object(0ul);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: encrypt_function: starts: ec_certificate_store_c::completion_action_pop(): removes action[%d] %s=%d\n"),
		0ul,
		removed_completion_action->get_completion_action_string(removed_completion_action->get_completion_action()),
		removed_completion_action->get_completion_action()));

	eap_status_e remove_status = m_completion_queue.remove_object(0ul);
	if (remove_status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, remove_status);
	}

	completion_action_trace();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, remove_status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::completion_action_push(
	ec_cs_completion_e action)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("WAPI EC CS DB: ec_certificate_store_c::completion_action_push()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::completion_action_push()");

	ec_cs_completion_c *completion_action = new ec_cs_completion_c(
		m_am_tools,
		action);

	if (completion_action == 0
		|| completion_action->get_is_valid() == false)
	{
		delete completion_action;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// add_object_to_begin() will delete completion_action if operation fails.
	eap_status_e status = m_completion_queue.add_object_to_begin(completion_action, true);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("WAPI EC CS DB: send_function: completion_action_push(): action %s\n"),
					 completion_action->get_completion_action_string(completion_action->get_completion_action())));

	completion_action_trace();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::completion_action_add(
	ec_cs_completion_e action)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("WAPI EC CS DB: ec_certificate_store_c::completion_action_add()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::completion_action_add()");

	ec_cs_completion_c *completion_action = new ec_cs_completion_c(
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

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("WAPI EC CS DB: send_function: completion_action_add(): action %s\n"),
					 completion_action->get_completion_action_string(completion_action->get_completion_action())));

	completion_action_trace();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::completion_action_clenup()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("WAPI EC CS DB: ec_certificate_store_c::completion_action_clenup()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::completion_action_clenup()");

	eap_status_e final_status = eap_status_ok;
	u32_t counter = 0ul;

	while(m_completion_queue.get_object_count() > 0ul)
	{
		ec_cs_completion_c * const completion_action = m_completion_queue.get_object(0ul);
		EAP_UNREFERENCED_PARAMETER(completion_action); // Not referenced without trace.

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: WAPI EC CS DB: send_function: completion_action_clenup(): ")
			 EAPL("action[%u] %s not completed.\n"),
			 counter,
			 completion_action->get_completion_action_string(completion_action->get_completion_action())));

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
EAP_FUNC_EXPORT void ec_certificate_store_c::completion_action_trace()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
					(EAPL("WAPI EC CS DB: ec_certificate_store_c::completion_action_trace()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::completion_action_trace()");

	for (u32_t trace_ind = 0ul; trace_ind < m_completion_queue.get_object_count(); ++trace_ind)
	{
		ec_cs_completion_c * const completion_action = m_completion_queue.get_object(trace_ind);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WAPI EC CS DB: send_function: completion_action_trace(): pending action[%d] %s=%d\n"),
			 trace_ind,
			 completion_action->get_completion_action_string(completion_action->get_completion_action()),
			 completion_action->get_completion_action()));
	} // for()
}

//--------------------------------------------------

//
eap_status_e ec_certificate_store_c::add_imported_certificate(
	const ec_cs_data_type_e certificate_type,
	const eap_variable_data_c * const in_imported_certificate_wapi_id,
	const eap_variable_data_c * const in_imported_certificate_file_data,
	const eap_variable_data_c * const in_imported_certificate_filename,
	eap_array_c<ec_cs_data_c> * const out_asu_id_list,
	eap_array_c<ec_cs_data_c> * const out_certificates,
	ec_cs_variable_data_c * const out_certificate_reference)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools, TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: send_function: starts: ec_certificate_store_c::add_imported_certificate()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::add_imported_certificate()");

	eap_status_e status(eap_status_not_supported);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (in_imported_certificate_filename->get_is_valid_data() == true)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("filename"),
			 in_imported_certificate_filename->get_data(),
			 in_imported_certificate_filename->get_data_length()));
	}

	if (in_imported_certificate_file_data->get_is_valid_data() == false
		|| in_imported_certificate_file_data->get_data_length() == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
	}

	// First check this is unique certificate.

	ec_cs_compare_reference_id_c compare_reference_id(m_am_tools);

	ec_cs_data_c search_id(m_am_tools);

	status = search_id.get_writable_data()->set_buffer(
		in_imported_certificate_wapi_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: CERTIFICATE SELECTION: this = 0x%08x, %s: ec_certificate_store_c::add_imported_certificate(): count of out_certificates = %d.\n"),
		 this,
		 (m_is_client == true ? "client": "server"),
		 out_asu_id_list->get_object_count()));

	// Search certificate with the issuer ID from CA-certificates.
	i32_t index = find_with_compare<ec_cs_data_c>(
		&compare_reference_id,
		out_asu_id_list,
		&search_id,
		m_am_tools);

	if (index >= 0)
	{
		// Match, do not add a copy.
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WARNING: WAPI_Core: CERTIFICATE IMPORT: this = 0x%08x, %s: ec_certificate_store_c::add_imported_certificate(): Certificate alredy installed.\n"),
			 this,
			 (m_is_client == true ? "client": "server")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_already_exists);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	ec_cs_data_type_e id_reference_type(ec_cs_data_type_none);

	if (certificate_type == ec_cs_data_type_ca_certificate_data)
	{
		id_reference_type = ec_cs_data_type_ca_asu_id;
	}
	else if (certificate_type == ec_cs_data_type_client_certificate_data)
	{
		id_reference_type = ec_cs_data_type_client_asu_id;
	}
	else
	{
		EAP_ASSERT_ANYWAY_TOOLS(m_am_tools);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	ec_cs_data_c certificate_reference(m_am_tools);
	if (certificate_reference.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		status = create_unique_reference(&certificate_reference);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		certificate_reference.set_type(ec_cs_data_type_certificate_reference);

		status = out_certificate_reference->set_copy_of_buffer(
			ec_cs_tlv_type_CS_certificate_reference,
			certificate_reference.get_reference()->get_data(),
			certificate_reference.get_reference()->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("out_certificate_reference"),
			 out_certificate_reference->get_full_tlv_buffer()->get_data(),
			 out_certificate_reference->get_full_tlv_buffer()->get_data_length()));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		ec_cs_variable_data_c * const id_reference = new ec_cs_variable_data_c(m_am_tools);

		eap_automatic_variable_c<ec_cs_variable_data_c> automatic_id_reference(m_am_tools, id_reference);

		if (id_reference == 0
			|| id_reference->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = id_reference->init_header(
			ec_cs_tlv_type_CS_ID_reference,
			0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		{
			ec_cs_variable_data_c asu_id(m_am_tools);

			if (asu_id.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = asu_id.set_copy_of_buffer(
				ec_cs_tlv_type_CS_ASU_ID,
				in_imported_certificate_wapi_id->get_data(),
				in_imported_certificate_wapi_id->get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = id_reference->add_data(&asu_id);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EC_CS_TLV_TRACE_PAYLOAD("add_imported_certificate()", id_reference->get_header(), m_is_client);
		}

		{
			status = id_reference->add_data(out_certificate_reference);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EC_CS_TLV_TRACE_PAYLOAD("add_imported_certificate()", id_reference->get_header(), m_is_client);
		}

		ec_cs_data_c reference_data(m_am_tools);

		status = reference_data.get_writable_data()->set_copy_of_buffer(id_reference->get_full_tlv_buffer());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = reference_data.get_writable_reference()->set_copy_of_buffer(certificate_reference.get_reference());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		reference_data.set_type(id_reference_type);

		{
			eap_variable_data_c id_reference_MAC_key(m_am_tools);
			if (id_reference_MAC_key.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			ec_cs_tlv_c pac_tlv_handler(m_am_tools, true);
			if (pac_tlv_handler.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = pac_tlv_handler.generate_data_key(
				false,
				id_reference_type,
				&id_reference_MAC_key,
				&m_PAC_store_master_key,
				certificate_reference.get_reference(),
				&m_PAC_store_device_seed);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = pac_tlv_handler.create_data_with_MAC(
				&id_reference_MAC_key,
				id_reference->get_full_tlv_buffer(),
				reference_data.get_writable_data());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("New reference data"),
				 reference_data.get_data()->get_data(),
				 reference_data.get_data()->get_data_length()));
		}

		reference_data.set_change_status(ec_cs_data_change_status_new);

		status = out_asu_id_list->add_object(reference_data.copy(), true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		eap_variable_data_c certificate(m_am_tools);

		if (certificate.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		ec_cs_tlv_c handler(m_am_tools, true);
		if (handler.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = handler.create_encrypted_certificate(
			certificate_type,
			&m_PAC_store_master_key,
			certificate_reference.get_reference(),
			&m_PAC_store_device_seed,
			certificate_reference.get_reference(),
			ec_cs_tlv_type_CS_certificate_data,
			in_imported_certificate_file_data,
			&certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		ec_cs_data_c certificate_data(m_am_tools);

		status = certificate_data.get_writable_data()->set_copy_of_buffer(&certificate);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = certificate_data.get_writable_reference()->set_copy_of_buffer(certificate_reference.get_reference());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		certificate_data.set_type(certificate_type);

		certificate_data.set_change_status(ec_cs_data_change_status_new);

		status = out_certificates->add_object(certificate_data.copy(), true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
eap_status_e ec_certificate_store_c::add_imported_private_key(
	const ec_cs_data_type_e private_key_type,
	const eap_variable_data_c * const in_imported_private_key_file_data,
	const eap_variable_data_c * const in_imported_private_key_filename,
	const ec_cs_variable_data_c * const in_certificate_reference,
	eap_array_c<ec_cs_data_c> * const out_private_keys)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools, TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: send_function: starts: ec_certificate_store_c::add_imported_private_key()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::add_imported_private_key()");

	eap_status_e status(eap_status_not_supported);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	ec_cs_data_c certificate_reference(m_am_tools);
	if (certificate_reference.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		status = certificate_reference.get_writable_reference()->set_copy_of_buffer(
			in_certificate_reference->get_data(in_certificate_reference->get_data_length()),
			in_certificate_reference->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		eap_variable_data_c private_key(m_am_tools);

		if (private_key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		ec_cs_tlv_c handler(m_am_tools, true);
		if (handler.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = handler.create_encrypted_certificate(
			private_key_type,
			&m_PAC_store_master_key,
			certificate_reference.get_reference(),
			&m_PAC_store_device_seed,
			certificate_reference.get_reference(),
			ec_cs_tlv_type_CS_private_key_data,
			in_imported_private_key_file_data,
			&private_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		ec_cs_data_c private_key_data(m_am_tools);

		status = private_key_data.get_writable_data()->set_copy_of_buffer(&private_key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = private_key_data.get_writable_reference()->set_copy_of_buffer(certificate_reference.get_reference());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		private_key_data.set_type(private_key_type);

		private_key_data.set_change_status(ec_cs_data_change_status_new);

		status = out_private_keys->add_object(private_key_data.copy(), true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::completion_action_check()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools, TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: send_function: starts: ec_certificate_store_c::completion_action_check()\n")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::completion_action_check()");

	if (m_already_in_completion_action_check == true)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		// This is recursive call of completion_action_check().
		// This MUST return eap_status_ok. Other return values will skip
		// further prosessing of completion action list.
		EAP_TRACE_DEBUG(
			m_am_tools, TRACE_FLAGS_DEFAULT,
			(EAPL("WAPI EC CS DB: send_function: completion_action_check(): skip recursion\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_already_in_completion_action_check = true;

	eap_automatic_simple_value_c<bool> restore_already_in_completion_action_check(
		m_am_tools,
		&m_already_in_completion_action_check,
		false);


	eap_status_e status = are_pending_queries_completed();

	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, TRACE_FLAGS_DEFAULT,
			(EAPL("WAPI_Core: are_pending_queries_completed(): still pending\n")));
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	bool continue_with_next_action = true;
	u32_t counter = 0ul;

	completion_action_trace();

	while(continue_with_next_action == true
		&& m_completion_queue.get_object_count() > 0ul)
	{
		status = eap_status_ok;

		ec_cs_completion_c * const completion_action = m_completion_queue.get_object(0ul);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("WAPI EC CS DB: send_function: completion_action_check(): action[%d] %s=%d\n"),
			 counter,
			 completion_action->get_completion_action_string(completion_action->get_completion_action()),
			 completion_action->get_completion_action()));

		ec_cs_completion_e current_action = completion_action->get_completion_action();

		// This will remove the current completion action.
		status = completion_action_pop();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		switch(current_action)
		{
		case ec_cs_completion_none:
			break;
		case ec_cs_completion_complete_add_imported_certificate_file:
			{
				set_pending_operation(ec_cs_pending_operation_none);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls: ec_certificate_store_c::completion_action_check(): m_am_pac_store_services->complete_add_imported_certificate_file(): %d.\n"),
					__LINE__));

				status = m_am_certificate_store->complete_add_imported_certificate_file(
					m_ec_cs_completion_status,
					&m_imported_certificate_filename);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			break;
		case ec_cs_completion_add_imported_ca_certificate:
			{
				set_pending_operation(ec_cs_pending_operation_none);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls: ec_certificate_store_c::completion_action_check(): add_imported_ca_certificate_file(): %d.\n"),
					__LINE__));

				ec_cs_variable_data_c certificate_reference(m_am_tools);
				if (certificate_reference.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = add_imported_certificate(
					ec_cs_data_type_ca_certificate_data,
					&m_imported_certificate_wapi_id,
					&m_imported_certificate_data,
					&m_imported_certificate_filename,
					&m_ca_asu_id_list,
					&m_ca_certificates,
					&certificate_reference);

				m_ec_cs_completion_status = status;

				if (status != eap_status_ok)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
						(EAPL("ERROR: ec_certificate_store_c::completion_action_check(): add_imported_ca_certificate_file(): Failed status = %d.\n"),
						status));
					status = eap_status_ok;
				}
			}
			break;
		case ec_cs_completion_add_imported_client_certificate:
			{
				set_pending_operation(ec_cs_pending_operation_none);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls: ec_certificate_store_c::completion_action_check(): add_imported_ca_certificate_file(): %d.\n"),
					__LINE__));

				ec_cs_variable_data_c certificate_reference(m_am_tools);
				if (certificate_reference.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = add_imported_certificate(
					ec_cs_data_type_client_certificate_data,
					&m_imported_certificate_wapi_id,
					&m_imported_certificate_data,
					&m_imported_certificate_filename,
					&m_client_asu_id_list,
					&m_client_certificates,
					&certificate_reference);

				m_ec_cs_completion_status = status;

				if (status != eap_status_ok)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
						(EAPL("ERROR: ec_certificate_store_c::completion_action_check(): add_imported_certificate(): Failed status = %d.\n"),
						status));
					status = eap_status_ok;
				}
				else 
				{
					status = add_imported_private_key(
						ec_cs_data_type_private_key_data,
						&m_imported_private_key_data,
						&m_imported_certificate_filename,
						&certificate_reference,
						&m_client_private_keys);
					if (status != eap_status_ok)
					{
						EAP_TRACE_DEBUG(
							m_am_tools,
							TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
							(EAPL("ERROR: ec_certificate_store_c::completion_action_check(): add_imported_private_key(): Failed status = %d.\n"),
							status));
						status = eap_status_ok;
					}
				}
			}
			break;
		case ec_cs_completion_internal_select_certificate:
			{
				set_pending_operation(ec_cs_pending_operation_none);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls: ec_certificate_store_c::completion_action_check(): internal_select_certificate(): %d.\n"),
					__LINE__));

				status = internal_select_certificate();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			break;
		case ec_cs_completion_internal_select_certificate_with_identity:
			{
				set_pending_operation(ec_cs_pending_operation_none);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls: ec_certificate_store_c::completion_action_check(): internal_select_certificate_with_identity(): %d.\n"),
					__LINE__));

				status = internal_select_certificate_with_identity(&m_selected_client_id);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			break;
		case ec_cs_completion_internal_create_signature_with_private_key:
			{
				set_pending_operation(ec_cs_pending_operation_none);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls: ec_certificate_store_c::completion_action_check(): internal_create_signature_with_private_key(): %d.\n"),
					__LINE__));

				status = internal_create_signature_with_private_key();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			break;
		case ec_cs_completion_complete_query_certificate_list:
			{
				set_pending_operation(ec_cs_pending_operation_none);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls: ec_certificate_store_c::completion_action_check(): complete_query_certificate_list(): %d.\n"),
					__LINE__));

				eap_array_c<eap_variable_data_c> ca_certificates_identities(m_am_tools);
				eap_array_c<eap_variable_data_c> user_certificates_identities(m_am_tools);

				status = copy_certificate_wapi_identities(
					&m_ca_asu_id_list,
					&ca_certificates_identities);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = copy_certificate_wapi_identities(
					&m_client_asu_id_list,
					&user_certificates_identities);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = m_am_certificate_store->complete_query_certificate_list(
					&ca_certificates_identities,
					&user_certificates_identities);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			break;

		case ec_cs_completion_internal_verify_signature_with_public_key:
			{
				set_pending_operation(ec_cs_pending_operation_none);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls: ec_certificate_store_c::completion_action_check(): verify_signature_with_public_key(): %d.\n"),
					__LINE__));

				status = verify_signature_with_public_key(
					&m_peer_identity,
					&m_hash_of_message,
					&m_signature,
					m_allow_use_of_ae_certificate);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			break;

		case ec_cs_completion_internal_complete_add_imported_certificate_file:
			{
				set_pending_operation(ec_cs_pending_operation_none);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls: ec_certificate_store_c::completion_action_check(): internal_complete_add_imported_certificate_file(): %d.\n"),
					__LINE__));

				status = internal_complete_add_imported_certificate_file();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			break;

		case ec_cs_completion_query_PAC_store_password:
			{
				set_pending_operation(ec_cs_pending_operation_none);

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
					(EAPL("calls: ec_certificate_store_c::completion_action_check(): query_PAC_store_password(): %d.\n"),
					__LINE__));

				status = query_PAC_store_password(m_pending_operation);
				if (status == eap_status_pending_request)
				{
					// Cannot continue yet.
					continue_with_next_action = false;
				}
			}
			break;

		default:
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("EROR: WAPI EC CS DB: send_function: completion_action_check(): unknown action[%d] %s=%d\n"),
					 counter,
					 ec_cs_completion_c::get_completion_action_string(current_action),
					 current_action));
			}
			break;
		} // switch()

		if (status == eap_status_user_cancel_authentication)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		++counter;

	} // while()

	if (continue_with_next_action == false)
	{
		status = eap_status_pending_request;
	}

	completion_action_trace();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::timer_expired(
	const u32_t id,
	void * data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: ec_certificate_store_c::timer_expired(): id = %d, data = 0x%08x.\n"),
		id,
		data));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::timer_expired()");

	switch (id)
	{
	case WAPI_CS_KEY_TIMER_ID:
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WAPI_CS_KEY_TIMER_ID elapsed\n")));

			m_PAC_store_password.reset();
			m_PAC_store_device_seed.reset();
			m_PAC_store_master_key.reset();
		}
		break;
	
	default:
		break;
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::timer_delete_data(
	const u32_t id,
	void *data)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eapol calls: ec_certificate_store_c::timer_delete_data(): id = %d, data = 0x%08x.\n"),
		id,
		data));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: ec_certificate_store_c::timer_delete_data()");

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

void ec_certificate_store_c::send_error_notification(const eap_status_e error)
{
	// Notifies the lower level of an authentication error.

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

	eap_state_notification_c notification(
		m_am_tools,
		&send_network_id,
		true,
		eap_state_notification_eap,
		eap_protocol_layer_general,
		eap_type_none,
		eap_state_none,
		general_state_variable,
		0,
		false);

	notification.set_authentication_error(error);

	m_partner->state_notification(&notification);
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e ec_certificate_store_c::set_receive_network_id(const eap_am_network_id_c * const receive_network_id)
{
	return m_receive_network_id.set_copy_of_network_id(receive_network_id);
}

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_base_certificate_store_c * ec_base_certificate_store_c::new_ec_base_certificate_store_c(
	abs_eap_am_tools_c * const tools,
	abs_ec_certificate_store_c * const partner,
	ec_am_base_certificate_store_c * const am_certificate_store,
	const bool is_client_when_true)
{
	ec_base_certificate_store_c * store = new ec_certificate_store_c(
		tools,
		partner,
		am_certificate_store,
		is_client_when_true);

	if (store == 0)
	{
		return 0;
	}

	eap_status_e status(store->configure());

	if (status != eap_status_ok)
	{
		delete store;
		return 0;
	}

	return store;
}

//----------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
