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
* %version: 99 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 124 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_tools.h"
#include "eap_core.h"
#include "eap_type_tls_peap_types.h"
#include "tls_record_header.h"
#include "abs_tls_base_application.h"
#include "tls_application_eap_core.h"
#include "tls_peap_types.h"
#include "tls_peap_tlv_header.h"
#include "eap_diameter_avp_header.h"
#include "eap_state_notification.h"
#include "eap_crypto_api.h"
#include "eap_header_string.h"
#include "abs_eap_am_mutex.h"
#include "eap_config.h"
#include "eapol_header.h"
#include "eap_network_id_selector.h"
#include "eap_tlv_message_data.h"
#include "eap_array_algorithms.h"
#include "eap_automatic_variable.h"
#include "eap_base_type.h"

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	#include "eap_type_mschapv2_types.h"
	#include "eap_type_mschapv2_header.h"
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

const u32_t TLV_NONCE_LENGTH = 32ul;
const u32_t TLV_MAC_LENGTH = 16ul;

const u32_t TLV_NONCE_OFFSET = 4ul;
const u32_t TLV_MAC_OFFSET = TLV_NONCE_OFFSET + TLV_NONCE_LENGTH;

const u32_t TLS_PEAP_V2_TK_OFFSET = 32ul;
const u32_t TLS_PEAP_V2_TK_LENGTH = 32ul;

const u32_t TLS_PEAP_V2_COMPOUND_MAC_KEY_LENGTH = 20ul;

const u32_t TLS_PEAP_V2_COMPOUND_SESSION_KEY_LENGTH = 128ul;

//-----------------------------------------------------------------------------------------

/// This is pseudo Ethernet and EAPOL header.
/// This is used in trace of tunneled EAP-packet.
const u8_t EAP_PSEUDO_ETHERNET_HEADER[] =
{
	0x50, 0x73, 0x65, 0x75, 0x64, 0x6f, 0x68, 0x65,
	0x61, 0x64, 0x65, 0x72, 0x88, 0x8e, 0x01, 0x00,
	0x00, 0x00
};

const u32_t EAP_PSEUDO_EAPOL_HEADER_OFFSET = 14ul;

//--------------------------------------------------

EAP_FUNC_EXPORT tls_application_eap_core_c::~tls_application_eap_core_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: function: tls_application_eap_core_c::~tls_application_eap_core_c(): ")
		 EAPL("this = 0x%08x, m_eap_core")
		 EAPL(" = 0x%08x (validity %d).\n"),
		 (m_is_client == true ? "client": "server"),
		 this,
		 m_eap_core,
		 ((m_eap_core != 0) ? m_eap_core->get_is_valid(): true)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::~tls_application_eap_core_c()");

	EAP_ASSERT(m_shutdown_was_called == true);

	if (m_free_eap_core == true)
	{
		delete m_eap_core;
	}
	m_eap_core = 0;

	m_application_partner = 0;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT tls_application_eap_core_c::tls_application_eap_core_c(
	abs_eap_am_tools_c * const tools,
	eap_core_c * const eap_core,
	const bool free_eap_core,
	const bool is_client_when_true,
	const eap_type_value_e eap_type,
	const eap_am_network_id_c * const receive_network_id)
	: m_am_tools(tools)
	, m_eap_core(eap_core)
	, m_free_eap_core(free_eap_core)
	, m_application_partner(0)
	, m_receive_network_id(tools)
	, m_eap_type(eap_type)
	, m_peap_version(peap_version_none)
	, m_peap_tunneled_eap_type(eap_type_none)
	, m_tunneled_eap_type_authentication_state(eap_state_none)
	, m_peapv2_tlv_payloads(tools)
	, m_peap_v2_client_nonce(tools)
	, m_peap_v2_server_nonce(tools)
	, m_peap_v2_IPMKn(tools)
	, m_peap_v2_ISKn(tools)
	, m_peap_v2_CMK_B1_server(tools)
	, m_peap_v2_CMK_B2_client(tools)
	, m_peap_v2_CSK(tools, eap_type)
	, m_accepted_tunneled_eap_types(tools)
	, m_pseudo_ethernet_header(tools)
	, m_ttls_received_payloads(tools)
	, m_ttls_message_type(eap_ttls_tunneled_message_type_none)
	, m_ttls_sent_eap_packet(tools)
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	, m_ttls_user_name(tools)
	, m_ttls_implicit_challenge(tools)
	, m_ttls_tunneled_message_state(eap_ttls_tunneled_message_state_none)
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	, m_error_probability(0UL)
	, m_received_eap_identifier(0u)
	, m_enable_random_errors(false)
	, m_manipulate_only_tunneled_messages(false)
	, m_is_valid(false)
	, m_is_client(is_client_when_true)
	, m_shutdown_was_called(false)
	, m_tls_session_type(tls_session_type_none)
	, m_peap_allow_tunneled_session_resumption(true)
	, m_use_tppd_tls_peap(true)
	, m_use_tppd_peapv1_acknowledge_hack(false)
#if defined(USE_EAP_PEAPV1_EXTENSIONS)
	, m_server_use_peapv1_extensions_request(false)
	, m_client_send_peapv1_extensions_response(false)
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	, m_tunneled_eap_in_ttls(true)
	, m_ttls_plain_ms_chap_v2_eap_identifier(0ul)
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	, m_use_eap_expanded_type(false)
	, m_wait_plain_eap_success(true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: function: tls_application_eap_core_c::tls_application_eap_core_c(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::tls_application_eap_core_c()");

	if (m_eap_core == 0
		|| m_eap_core->get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_TLS_PEAP_ERROR,
			(EAPL("ERROR: %s: function: tls_application_eap_core_c() failed, ")
			 EAPL("m_eap_core is invalid.\n"),
						 (m_is_client == true ? "client": "server")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	m_eap_core->set_partner(this);

	eap_status_e status = m_receive_network_id.set_copy_of_network_id(receive_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}


	status = m_pseudo_ethernet_header.set_copy_of_buffer(
		EAP_PSEUDO_ETHERNET_HEADER,
		sizeof(EAP_PSEUDO_ETHERNET_HEADER));
	if (status != eap_status_ok)
	{
		// Do not care of this error.
		// User will check the validity of m_pseudo_ethernet_header.
	}

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_application_eap_core_c::set_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_is_valid = true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_application_eap_core_c::set_peap_version(
	const peap_version_e peap_version,
	const bool use_tppd_tls_peap,
	const bool use_tppd_peapv1_acknowledge_hack)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::set_peap_version()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::set_peap_version()");

	m_peap_version = peap_version;

	m_use_tppd_tls_peap = use_tppd_tls_peap;

	m_use_tppd_peapv1_acknowledge_hack = use_tppd_peapv1_acknowledge_hack;


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: function: tls_application_eap_core_c::configure(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::configure()");

	eap_status_e status = eap_status_process_general_error;

	//----------------------------------------------------------

	{
		eap_variable_data_c tunneled_eap_type(m_am_tools);

		if (m_is_client == true)
		{
			status = get_application_partner()->read_configure(
				cf_str_PEAP_tunneled_eap_type_hex_data.get_field(),
				&tunneled_eap_type);
			if (status == eap_status_illegal_configure_type)
			{
				status = get_application_partner()->read_configure(
					cf_str_PEAP_tunneled_eap_type_u32_t.get_field(),
					&tunneled_eap_type);
			}
		}
#if defined(USE_EAP_CORE_SERVER)
		else
		{
			status = get_application_partner()->read_configure(
				cf_str_PEAP_server_tunneled_eap_type_hex_data.get_field(),
				&tunneled_eap_type);
			if (status == eap_status_illegal_configure_type)
			{
				status = get_application_partner()->read_configure(
					cf_str_PEAP_server_tunneled_eap_type_u32_t.get_field(),
					&tunneled_eap_type);
			}
		}
#endif //#if defined(USE_EAP_CORE_SERVER)

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (tunneled_eap_type.get_data_length() == sizeof(u32_t)
			&& tunneled_eap_type.get_data(sizeof(u32_t)) != 0)
		{
			u32_t *p_eap_type = reinterpret_cast<u32_t *>(
				tunneled_eap_type.get_data(sizeof(u32_t)));
			if (p_eap_type != 0)
			{
				m_peap_tunneled_eap_type = static_cast<eap_type_ietf_values_e>(*p_eap_type);
			}
			else
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
			}
		}
		else if (tunneled_eap_type.get_data_length()
				 == eap_expanded_type_c::get_eap_expanded_type_size()
			&& tunneled_eap_type.get_data(tunneled_eap_type.get_data_length()) != 0)
		{
			eap_expanded_type_c eap_type(eap_type_none);

			status = eap_type.set_expanded_type_data(
				m_am_tools,
				&tunneled_eap_type);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = eap_type.get_type_data(
				m_am_tools,
				&m_peap_tunneled_eap_type);
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
				(EAPL("ERROR: %s: No tunneled EAP-type configured, %s.\n"),
				 (m_is_client == true ? "client": "server"),
				 cf_str_EAP_default_type_hex_data.get_field()->get_field()));
			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
		}


#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		if (m_peap_tunneled_eap_type == eap_expanded_type_ttls_plain_mschapv2.get_type())
		{
			// This is special case.
			// We must tell to inner EAP-stack to use EAP-MsChapv2.
			m_tunneled_eap_in_ttls = false;
		}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	}

	//----------------------------------------------------------

	{
		eap_variable_data_c allowed_eap_types(m_am_tools);

		const eap_configuration_field_c * field
			= cf_str_PEAP_accepted_tunneled_client_types_hex_data.get_field();
		if (m_is_client == false)
		{
			field = cf_str_PEAP_accepted_tunneled_server_types_hex_data.get_field();
		}

		eap_status_e status = read_configure(
			field,
			&allowed_eap_types);
		if (status == eap_status_ok
			&& allowed_eap_types.get_is_valid_data() == true)
		{
			// OK read.
			u32_t type_count = allowed_eap_types.get_data_length()
				/eap_expanded_type_c::get_eap_expanded_type_size();
			
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("%s: tls_application_eap_core_c::configure(): Tunneled EAP-type count %d, hex data.\n"),
				 (m_is_client == true ? "client": "server"),
				 type_count));

			for (u32_t ind = 0ul; ind < type_count; ind++)
			{
				eap_type_value_e * const eap_type = new eap_type_value_e(eap_type_none);
				if (eap_type == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = eap_expanded_type_c::read_type(
					m_am_tools,
					ind,
					allowed_eap_types.get_data(allowed_eap_types.get_data_length()),
					allowed_eap_types.get_data_length(),
					eap_type);
				if (status != eap_status_ok)
				{
					delete eap_type;
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("%s: tls_application_eap_core_c::configure(): allowed EAP-type %d.\n"),
					 (m_is_client == true ? "client": "server"),
					 convert_eap_type_to_u32_t(*eap_type)));

				status = m_accepted_tunneled_eap_types.add_object(eap_type, true);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			} // for()
		}
		else
		{
			// Try different configuration type.

			const eap_configuration_field_c * field
				= cf_str_PEAP_accepted_tunneled_client_types_u32array.get_field();
			if (m_is_client == false)
			{
				field = cf_str_PEAP_accepted_tunneled_server_types_u32array.get_field();
			}

			status = read_configure(
				field,
				&allowed_eap_types);
			if (status == eap_status_ok
				&& allowed_eap_types.get_is_valid_data() == true)
			{
				// OK read.
				u32_t type_count = allowed_eap_types.get_data_length()
					/ sizeof(u32_t);

				u32_t * const array = reinterpret_cast<u32_t *>(
					allowed_eap_types.get_data(type_count*sizeof(u32_t)));
				
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("%s: tls_application_eap_core_c::configure(): Tunneled EAP-type count %d, u32array.\n"),
					 (m_is_client == true ? "client": "server"),
					 type_count));

				for (u32_t ind = 0ul; ind < type_count; ind++)
				{
					eap_type_value_e * const eap_type = new eap_type_value_e(eap_type_none);
					if (eap_type == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					*eap_type = static_cast<eap_type_ietf_values_e>(array[ind]);

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("%s: tls_application_eap_core_c::configure(): allowed EAP-type %d.\n"),
						 (m_is_client == true ? "client": "server"),
						 convert_eap_type_to_u32_t(*eap_type)));

					status = m_accepted_tunneled_eap_types.add_object(eap_type, true);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				} // for()
			}
		}
	}

	//----------------------------------------------------------

	{
		// Client and server configuration.
		eap_variable_data_c allow_tunneled_session_resumption(m_am_tools);

		status = read_configure(
			cf_str_PEAP_allow_tunneled_session_resumption.get_field(),
			&allow_tunneled_session_resumption);
		if (status == eap_status_ok
			&& allow_tunneled_session_resumption.get_is_valid_data() == true
			&& allow_tunneled_session_resumption.get_data_length() == sizeof(u32_t)
			&& allow_tunneled_session_resumption.get_data(sizeof(u32_t)) != 0)
		{
			// This is optional value.
			u32_t *flag = reinterpret_cast<u32_t *>(
				allow_tunneled_session_resumption.get_data(sizeof(u32_t)));
			if (flag != 0)
			{
				if (*flag == 0)
				{
					m_peap_allow_tunneled_session_resumption = false;
				}
				else
				{
					m_peap_allow_tunneled_session_resumption = true;
				}
			}
		}

		status = eap_status_ok;
	}


	if (m_is_client == false)
	{
		{
			// Server only configuration.
			// This configuration allows different actions to server and client.
			eap_variable_data_c allow_tunneled_session_resumption(m_am_tools);

			status = read_configure(
				cf_str_PEAP_server_allow_tunneled_session_resumption.get_field(),
				&allow_tunneled_session_resumption);
			if (status == eap_status_ok
				&& allow_tunneled_session_resumption.get_is_valid_data() == true
				&& allow_tunneled_session_resumption.get_data_length() == sizeof(u32_t)
				&& allow_tunneled_session_resumption.get_data(sizeof(u32_t)) != 0)
			{
				// This is optional value.
				u32_t *flag = reinterpret_cast<u32_t *>(
					allow_tunneled_session_resumption.get_data(sizeof(u32_t)));
				if (flag != 0)
				{
					if (*flag == 0)
					{
						m_peap_allow_tunneled_session_resumption = false;
					}
					else
					{
						m_peap_allow_tunneled_session_resumption = true;
					}
				}
			}

			status = eap_status_ok;
		}

#if defined(USE_EAP_PEAPV1_EXTENSIONS)
		{
			// Server only configuration.
			eap_variable_data_c server_use_peapv1_extensions_request(m_am_tools);

			status = read_configure(
				cf_str_PEAPv1_server_use_extensions_request.get_field(),
				&server_use_peapv1_extensions_request);
			if (status == eap_status_ok
				&& server_use_peapv1_extensions_request.get_is_valid_data() == true
				&& server_use_peapv1_extensions_request.get_data_length() == sizeof(u32_t)
				&& server_use_peapv1_extensions_request.get_data(sizeof(u32_t)) != 0)
			{
				// This is optional value.
				u32_t *flag = reinterpret_cast<u32_t *>(
					server_use_peapv1_extensions_request.get_data(sizeof(u32_t)));
				if (flag != 0)
				{
					if (*flag == 0)
					{
						m_server_use_peapv1_extensions_request = false;
					}
					else
					{
						m_server_use_peapv1_extensions_request = true;
					}
				}
			}

			status = eap_status_ok;

		}
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)

	}


	//----------------------------------------------------------

#if defined(USE_EAP_ERROR_TESTS)

	{
		eap_variable_data_c EAP_ERROR_TEST_enable_random_errors(m_am_tools);
			
		status = read_configure(
			cf_str_EAP_ERROR_TEST_enable_random_errors.get_field(),
			&EAP_ERROR_TEST_enable_random_errors);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_enable_random_errors.get_is_valid_data() == true)
		{
			u32_t *enable_random_errors = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_enable_random_errors.get_data(sizeof(u32_t)));
			if (enable_random_errors != 0
				&& *enable_random_errors != 0)
			{
				m_enable_random_errors = true;
			}
		}
	}
	
	if (m_enable_random_errors == true)
	{
		eap_variable_data_c manipulate_only_tunneled_messages(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_ERROR_TEST_manipulate_only_tunneled_messages.get_field(),
			&manipulate_only_tunneled_messages);
		if (status == eap_status_ok
			&& manipulate_only_tunneled_messages.get_is_valid_data() == true)
		{
			// NOTE this is optional.
			u32_t * const flag = reinterpret_cast<u32_t *>(
				manipulate_only_tunneled_messages.get_data(sizeof(u32_t)));
			if (flag != 0
				&& *flag != 0)
			{
				m_manipulate_only_tunneled_messages = true;
			}
		}
	}

	{
		eap_variable_data_c EAP_ERROR_TEST_error_probability(m_am_tools);

		status = read_configure(
			cf_str_EAP_ERROR_TEST_error_probability.get_field(),
			&EAP_ERROR_TEST_error_probability);
		if (status == eap_status_ok
			&& EAP_ERROR_TEST_error_probability.get_is_valid_data() == true)
		{
			u32_t *error_probability = reinterpret_cast<u32_t *>(
				EAP_ERROR_TEST_error_probability.get_data(sizeof(u32_t)));
			if (error_probability != 0)
			{
				m_error_probability = *error_probability;
			}
		}
	}

#endif //#if defined(USE_EAP_ERROR_TESTS)

	//----------------------------------------------------------

	status = m_eap_core->configure();

	if (m_peap_tunneled_eap_type == eap_expanded_type_ttls_plain_pap.get_type())
	{
		if (m_free_eap_core == true)
		{
			m_eap_core->ignore_notifications();

			(void) m_eap_core->shutdown();

			delete m_eap_core;
		}
		m_eap_core = 0;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: tls_application_eap_core_c::shutdown(), m_shutdown_was_called=%d\n"),
		(m_is_client == true) ? "client": "server",
		m_shutdown_was_called));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::shutdown()");

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;

	eap_status_e status(eap_status_ok);

	if (m_eap_core != 0)
	{
		status = m_eap_core->shutdown();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_application_eap_core_c::trace_tunneled_packet(
	eap_const_string prefix,
	const eap_header_wr_c * const eap_packet)
{
	if (eap_packet == 0
		|| eap_packet->get_is_valid() == false)
	{
		EAP_UNREFERENCED_PARAMETER(prefix);
		// ERROR: Cannot trace invalid packet.
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: %s: %s: Cannot trace invalid packet.\n"),
			 prefix,
			 (m_is_client == true) ? "client": "server"));
		return;
	}

	if ((m_am_tools->get_trace_mask() & TRACE_FLAGS_DEFAULT)
		&& m_pseudo_ethernet_header.get_is_valid_data() == true
		&& m_pseudo_ethernet_header.get_data_length() >= sizeof(EAP_PSEUDO_ETHERNET_HEADER))
	{
		m_pseudo_ethernet_header.set_data_length(sizeof(EAP_PSEUDO_ETHERNET_HEADER));

		u32_t eap_packet_length = eap_packet->get_length();
		if (eap_packet->get_header_buffer_length() < eap_packet_length)
		{
			eap_packet_length = eap_packet->get_header_buffer_length();
		}

		eap_status_e status = m_pseudo_ethernet_header.add_data_to_offset(
			sizeof(EAP_PSEUDO_ETHERNET_HEADER),
			eap_packet->get_header_buffer(eap_packet_length),
			eap_packet_length);

		if (status == eap_status_ok)
		{
			m_pseudo_ethernet_header.set_data_length(
				sizeof(EAP_PSEUDO_ETHERNET_HEADER) + eap_packet_length);

			// Sets the EAPOL packet data length.
			eapol_header_wr_c eapol(
				m_am_tools,
				m_pseudo_ethernet_header.get_data_offset(
					EAP_PSEUDO_EAPOL_HEADER_OFFSET,
					m_pseudo_ethernet_header.get_data_length()-EAP_PSEUDO_EAPOL_HEADER_OFFSET),
				m_pseudo_ethernet_header.get_data_length()-EAP_PSEUDO_EAPOL_HEADER_OFFSET);

			if (eapol.get_is_valid() == true)
			{
				eapol.set_data_length(static_cast<u16_t>(eap_packet_length));

				EAP_TRACE_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("%s: %s: type=0x%08x, eap_length 0x%04x\n"),
					 prefix,
					 (m_is_client == true) ? "client": "server",
					 convert_eap_type_to_u32_t(eap_packet->get_type()),
					 eap_packet->get_length())); // NOTE, this will trace the values from the header of the EAP-packet.

				EAP_TRACE_DATA_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
					(prefix,
					m_pseudo_ethernet_header.get_data(m_pseudo_ethernet_header.get_data_length()),
					m_pseudo_ethernet_header.get_data_length()));
			}
		}
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::parse_generic_payload(
	const tls_peap_tlv_type_e current_payload,
	const tls_peap_tlv_header_c * const payload,
	peap_tlv_payloads_c * const p_peap_tlv_payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::parse_generic_payload()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::parse_generic_payload()");

	EAP_TLS_PEAP_TRACE_PAYLOAD("Parsing payload", payload, m_is_client);

	if (payload->get_data_length() == 0)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_TLS_PEAP_ERROR,
			(EAPL("ERROR: tls_application_eap_core_c::parse_generic_payload(0x%08x): ")
			 EAPL("current payload 0x%04x=%s, length is 0x%04x.\n"),
			payload, current_payload, payload->get_tlv_type_string(), payload->get_data_length()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);		
	}


	if (current_payload == tls_peap_tlv_type_result)
	{
		/*  Result TLV:
		 *  0                   1                   2                   3   
		 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |M|R|  TLV Type (AVP Type)      |            Length             |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |            Status             |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		const u32_t PEAP_TLV_STATUS_LENGTH = sizeof(u16_t);

		if (payload->get_data_length() != PEAP_TLV_STATUS_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_TLS_PEAP_ERROR,
				(EAPL("ERROR: tls_application_eap_core_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, data length incorrect 0x%04x.\n"),
				 payload, current_payload, payload->get_tlv_type_string(),
				 payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * buffer
			= static_cast<u8_t *>(payload->get_data(PEAP_TLV_STATUS_LENGTH));

		if (buffer == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_TLS_PEAP_ERROR, 
				(EAPL("ERROR: tls_application_eap_core_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				 payload,
				 current_payload,
				 payload->get_tlv_type_string(),
				 payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// Note here we get a reference to the data bytes of the received packet.
		eap_status_e status = p_peap_tlv_payloads->get_result_tlv()->set_copy_of_buffer(
			payload);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == tls_peap_tlv_type_nak)
	{
		/*  NAK TLV:
		 * 0                   1                   2                   3    
		 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |M|R|         TLV Type          |            Length             |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |                          Vendor-Id                            |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |      TLV Type number      | TLVs                              |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		const u32_t PEAP_TLV_NAK_MINIMUM_LENGTH = 6ul*sizeof(u8_t);

		if (payload->get_data_length() < PEAP_TLV_NAK_MINIMUM_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_TLS_PEAP_ERROR,
				(EAPL("ERROR: tls_application_eap_core_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, data length incorrect 0x%04x.\n"),
				 payload, current_payload, payload->get_tlv_type_string(),
				 payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * buffer
			= static_cast<u8_t *>(payload->get_data(payload->get_data_length()));

		if (buffer == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_TLS_PEAP_ERROR, 
				(EAPL("ERROR: tls_application_eap_core_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				 payload,
				 current_payload,
				 payload->get_tlv_type_string(),
				 payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// Note here we get a reference to the data bytes of the received packet.
		eap_status_e status = p_peap_tlv_payloads->get_nak_tlv()->set_copy_of_buffer(
			payload);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == tls_peap_tlv_type_crypto_binding)
	{
		/*  Crypto binding TLV:
		 * 0                   1                   2                   3    
		 * 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7  
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |M|R|         TLV Type          |            Length             |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * | Version       |Received Ver.  |           SubType             |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |                                                               |
		 * +                           NONCE                               +
		 * |                                                               |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |                                                               |
		 * +                          Compound MAC                         +
		 * |                                                               |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		const u32_t PEAP_TLV_CRYPTO_BINDING_LENGTH = sizeof(u16_t)+sizeof(u16_t)+32ul+16ul;

		if (payload->get_data_length() != PEAP_TLV_CRYPTO_BINDING_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_TLS_PEAP_ERROR,
				(EAPL("ERROR: tls_application_eap_core_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, data length incorrect 0x%04x.\n"),
				 payload, current_payload, payload->get_tlv_type_string(),
				 payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * buffer
			= static_cast<u8_t *>(payload->get_data(PEAP_TLV_CRYPTO_BINDING_LENGTH));

		if (buffer == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_TLS_PEAP_ERROR, 
				(EAPL("ERROR: tls_application_eap_core_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				 payload,
				 current_payload,
				 payload->get_tlv_type_string(),
				 payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// Note here we get a reference to the data bytes of the received packet.
		eap_status_e status = p_peap_tlv_payloads->get_crypto_binding_tlv()->set_copy_of_buffer(
			payload);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == tls_peap_tlv_eap_payload)
	{
		/*  EAP-Payload TLV:
		 *  0                   1                   2                   3
		 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |M|R|         TLV Type          |            Length             |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |                          EAP packet...
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |                             TLVs...
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		const u32_t PEAP_TLV_EAP_PAYLOAD_MINIMUM_LENGTH = 4ul*sizeof(u8_t);

		if (payload->get_data_length() < PEAP_TLV_EAP_PAYLOAD_MINIMUM_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_TLS_PEAP_ERROR,
				(EAPL("ERROR: tls_application_eap_core_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, data length incorrect 0x%04x.\n"),
				 payload, current_payload, payload->get_tlv_type_string(),
				 payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * buffer
			= static_cast<u8_t *>(payload->get_data(payload->get_data_length()));

		if (buffer == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_TLS_PEAP_ERROR, 
				(EAPL("ERROR: tls_application_eap_core_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				 payload,
				 current_payload,
				 payload->get_tlv_type_string(),
				 payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// Note here we get a reference to the data bytes of the received packet.
		eap_status_e status = p_peap_tlv_payloads->get_eap_payload_tlv()->set_copy_of_buffer(
			payload);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (current_payload == tls_peap_tlv_type_intermediate_result)
	{
		/*  Intermediate Result TLV:
		 *  0                   1                   2                   3   
		 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |M|R|  TLV Type (AVP Type)      |            Length             |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |            Status             |        TLVs...
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		const u32_t PEAP_TLV_INTERMEDIATE_RESULTMINIMUM_LENGTH = 2ul*sizeof(u8_t);

		if (payload->get_data_length() < PEAP_TLV_INTERMEDIATE_RESULTMINIMUM_LENGTH)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_TLS_PEAP_ERROR,
				(EAPL("ERROR: tls_application_eap_core_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, data length incorrect 0x%04x.\n"),
				 payload, current_payload, payload->get_tlv_type_string(),
				 payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * buffer
			= static_cast<u8_t *>(payload->get_data(payload->get_data_length()));

		if (buffer == 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_TLS_PEAP_ERROR, 
				(EAPL("ERROR: tls_application_eap_core_c::parse_generic_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, length 0x%04x, data buffer incorrect.\n"),
				 payload,
				 current_payload,
				 payload->get_tlv_type_string(),
				 payload->get_data_length()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// Note here we get a reference to the data bytes of the received packet.
		eap_status_e status = p_peap_tlv_payloads->get_intermediate_result_tlv()
			->set_copy_of_buffer(payload);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (payload->get_flag_mandatory_tlv() == false)
	{
		// Silently ignore this optional payload.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("IGNORED: tls_application_eap_core_c::parse_generic_payload(): ")
			 EAPL("Ignored PEAP_TLV-payload %d=0x%04x.\n"),
			current_payload,
			current_payload));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		/**
		 * @{ Add creation and sending of message with NAK TLV. }
		 */
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_TLS_PEAP_ERROR, 
			(EAPL("ERROR: tls_application_eap_core_c::parse_generic_payload(): ")
			 EAPL("Unknown PEAP_TLV-payload %d.\n"),
			current_payload));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::parse_peap_tlv_payload(
	u8_t * const buffer,
	u32_t * const buffer_length,
	peap_tlv_payloads_c * const p_peap_tlv_payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::parse_peap_tlv_payload()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::parse_peap_tlv_payload()");

	u32_t buffer_offset = 0ul;

	tls_peap_tlv_header_c payload(
		m_am_tools,
		buffer+buffer_offset,
		*buffer_length); // Const correctness is gone.

	tls_peap_tlv_type_e current_payload = payload.get_flag_tlv_type();

	eap_status_e status = eap_status_header_corrupted;

	if (payload.get_is_valid() == true
		&& current_payload != tls_peap_tlv_type_none)
	{
		status = payload.check_header();
		if (status != eap_status_ok)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_TLS_PEAP_ERROR, 
				(EAPL("ERROR: TLV header corrupted.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (*buffer_length < payload.get_header_length()+payload.get_data_length())
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_TLS_PEAP_ERROR,
				(EAPL("ERROR: tls_application_eap_core_c::parse_peap_tlv_payload(0x%08x): ")
				 EAPL("current payload 0x%04x=%s, data length 0x%04x, buffer length 0x%04x.\n"),
				 payload.get_header_buffer(0ul),
				 current_payload,
				 payload.get_tlv_type_string(),
				 payload.get_data_length(),
				 *buffer_length));
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_TLS_PEAP_ERROR,
				(EAPL("ERROR: tls_application_eap_core_c::parse_peap_tlv_payload(): ")
				 EAPL("PEAP_TLV-payload header is corrupted.\n")));
			EAP_TRACE_DATA_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("payload"),
				payload.get_header_buffer(*buffer_length),
				*buffer_length));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = parse_generic_payload(current_payload, &payload, p_peap_tlv_payloads);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (*buffer_length < payload.get_header_length()+payload.get_data_length())
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
		}

		buffer_offset += payload.get_header_length()+payload.get_data_length();
		*buffer_length -= payload.get_header_length()+payload.get_data_length();

		while(*buffer_length >= payload.get_header_length()
			&& payload.get_is_valid() == true)
		{
			// Sets payload point to the next TLV header.
			payload.set_header_buffer(
					buffer+buffer_offset,
					*buffer_length);
			if (payload.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			current_payload = payload.get_flag_tlv_type();

			if (*buffer_length < payload.get_header_length()+payload.get_data_length())
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_TLS_PEAP_ERROR,
					(EAPL("ERROR: tls_application_eap_core_c::parse_peap_tlv_payload(0x%08x): ")
					 EAPL("current payload 0x%04x=%s, data length 0x%04x, buffer length 0x%04x.\n"),
					 payload.get_header_buffer(0ul),
					 current_payload,
					 payload.get_tlv_type_string(),
					 payload.get_data_length(),
					 *buffer_length));
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_TLS_PEAP_ERROR,
					(EAPL("ERROR: tls_application_eap_core_c::parse_peap_tlv_payload(): ")
					 EAPL("PEAP_TLV-payload header is corrupted.\n")));
				EAP_TRACE_DATA_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("payload"),
					payload.get_header_buffer(*buffer_length),
					*buffer_length));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			status = parse_generic_payload(current_payload, &payload, p_peap_tlv_payloads);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (*buffer_length < payload.get_header_length()+payload.get_data_length())
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
			}

			buffer_offset += payload.get_header_length()+payload.get_data_length();
			*buffer_length -= payload.get_header_length()+payload.get_data_length();
		}
	}

	if (*buffer_length != 0u)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_TLS_PEAP_ERROR,
			(EAPL("ERROR: tls_application_eap_core_c::parse_peap_tlv_payload(): ")
			 EAPL("PEAP_TLV-header is corrupted. Buffer length and payload ")
			 EAPL("length does not match. %lu illegal bytes.\n"),
			 *buffer_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::start_ttls_tunneled_authentication(
	const eap_am_network_id_c * const /*receive_network_id*/,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::start_ttls_tunneled_authentication()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::start_ttls_tunneled_authentication()");

	if (m_eap_type != eap_type_ttls)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_type);
	}

	eap_status_e status(eap_status_process_general_error);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_peap_tunneled_eap_type == eap_expanded_type_ttls_plain_pap.get_type())
	{
		// Query PAP username and password.
		status = m_application_partner->query_ttls_pap_username_and_password(0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		eap_variable_data_c forwarded_packet_buffer(m_am_tools);

		status = forwarded_packet_buffer.set_buffer_length(EAP_CORE_PACKET_BUFFER_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		forwarded_packet_buffer.set_data_length(
			forwarded_packet_buffer.get_buffer_length());

		eap_header_wr_c forwarded_eap_packet(m_am_tools, 0, 0ul);

		forwarded_eap_packet.set_header_buffer(
			forwarded_packet_buffer.get_data(),
			forwarded_packet_buffer.get_buffer_length());
		if (forwarded_eap_packet.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u32_t packet_length = eap_header_wr_c::get_header_length() + 1ul;

		forwarded_eap_packet.reset_header(
			static_cast<u16_t>(packet_length),
			m_use_eap_expanded_type);
		forwarded_eap_packet.set_identifier(received_eap_identifier);
		forwarded_eap_packet.set_code(eap_code_request);
		forwarded_eap_packet.set_length(
			static_cast<u16_t>(packet_length),
			m_use_eap_expanded_type);
		forwarded_eap_packet.set_type(
			eap_type_identity,
			m_use_eap_expanded_type);

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		if (m_tunneled_eap_in_ttls == false)
		{
			set_ttls_tunneled_message_state(eap_ttls_tunneled_message_state_process_identity_request);
		}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

		status = packet_forward_to_tunnel(
			&m_receive_network_id,
			&forwarded_eap_packet,
			forwarded_eap_packet.get_length());

		{
			eap_status_string_c status_string;
			EAP_UNREFERENCED_PARAMETER(status_string);

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
				bool tmp_tunneled_eap_in_ttls(m_tunneled_eap_in_ttls);
#else
				bool tmp_tunneled_eap_in_ttls(false);
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

			EAP_UNREFERENCED_PARAMETER(tmp_tunneled_eap_in_ttls);
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("TTLS: %s: tls_application_eap_core_c::start_ttls_tunneled_authentication() returns status=%d=%s, m_tunneled_eap_in_ttls=%d\n"),
				(m_is_client == true ? "client": "server"),
				status,
				status_string.get_status_string(status),
				tmp_tunneled_eap_in_ttls));
		}

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		if (m_tunneled_eap_in_ttls == false
			&& status == eap_status_pending_request)
		{
			set_ttls_tunneled_message_state(eap_ttls_tunneled_message_state_process_identity_request_pending);
		}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		// NOTE, here we process client send packets separately to 
		// reduce stack consumption.

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		if (m_eap_type == eap_type_ttls
			&& m_peap_tunneled_eap_type == eap_expanded_type_ttls_plain_mschapv2.get_type())
		{
			eap_header_wr_c sent_eap_packet(
				m_am_tools,
				m_ttls_sent_eap_packet.get_data(),
				m_ttls_sent_eap_packet.get_data_length());

			if (m_ttls_sent_eap_packet.get_data_length() > 0ul
				&& sent_eap_packet.get_data_length() > 0ul
				&& sent_eap_packet.get_type() == eap_type_identity
				&& get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_process_identity_request)
			{
				// Client sent EAP-Response/Identity.
				// This message should include username.

				status = ttls_tunneled_message_state_process_identity_request(&sent_eap_packet);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
			}
		}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		if (m_eap_type == eap_type_ttls
			&& m_peap_tunneled_eap_type == eap_expanded_type_ttls_plain_mschapv2.get_type())
		{
			eap_header_wr_c sent_eap_packet(
				m_am_tools,
				m_ttls_sent_eap_packet.get_data(),
				m_ttls_sent_eap_packet.get_data_length());

			if (m_ttls_sent_eap_packet.get_data_length() > 0ul
				&& sent_eap_packet.get_data_length() > 0ul
				&& sent_eap_packet.get_type() == eap_type_mschapv2
				&& get_ttls_tunneled_message_state() == eap_ttls_tunneled_message_state_process_challenge_request)
			{
				// This message shoud include MS-CHAP-V2 Response.
				status = ttls_tunneled_message_state_process_challenge_request(&sent_eap_packet);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state);
			}
		}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::create_eap_success_failure_in_forward_to_tunnel(
	const eap_am_network_id_c * const /*receive_network_id*/,
	const eap_code_value_e forwarded_eap_code,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_variable_data_c forwarded_packet_buffer(m_am_tools);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::create_eap_success_failure_in_forward_to_tunnel()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::create_eap_success_failure_in_forward_to_tunnel()");

	eap_status_e status = forwarded_packet_buffer.set_buffer_length(EAP_CORE_PACKET_BUFFER_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	forwarded_packet_buffer.set_data_length(
		forwarded_packet_buffer.get_buffer_length());

	eap_header_wr_c forwarded_eap_packet(m_am_tools, 0, 0ul);

	forwarded_eap_packet.set_header_buffer(
		forwarded_packet_buffer.get_data(),
		forwarded_packet_buffer.get_buffer_length());
	if (forwarded_eap_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	forwarded_eap_packet.reset_header(
		static_cast<u16_t>(eap_header_wr_c::get_header_length()),
		m_use_eap_expanded_type);
	forwarded_eap_packet.set_identifier(received_eap_identifier);
	forwarded_eap_packet.set_code(forwarded_eap_code);
	forwarded_eap_packet.set_length(
		static_cast<u16_t>(eap_header_wr_c::get_header_length()),
		m_use_eap_expanded_type);

	status = packet_forward_to_tunnel(
		&m_receive_network_id,
		&forwarded_eap_packet,
		forwarded_eap_packet.get_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::check_ttls_eap_payloads(
	eap_diameter_payloads_c * const payloads,
	eap_ttls_tunneled_message_type_e * const message_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::check_ttls_eap_payloads()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::check_ttls_eap_payloads()");

	*message_type = eap_ttls_tunneled_message_type_none;

	eap_array_c<eap_diameter_avp_code_c> needed_payloads(m_am_tools);

	eap_diameter_avp_code_c code_eap_message(eap_diameter_avp_code_eap_message);

	eap_status_e status = needed_payloads.add_object(&code_eap_message, false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
		
	// Test the required attribute.
	status = payloads->check_payloads_existense(
		&needed_payloads);
	if (status != eap_status_ok)
	{
		// No required payloads.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// This packet includes EAP-Message AVP.

	status = payloads->check_mandatory_payloads(
		&needed_payloads);
	if (status != eap_status_ok)
	{
		// Some mandatory payload is not used here.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	*message_type = eap_ttls_tunneled_message_type_eap;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::packet_process_ttls(
	eap_variable_data_c * const received_eap_message,
	const u8_t received_eap_identifier,
	u32_t * const eap_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::packet_process_ttls()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::packet_process_ttls()");

	eap_status_e status = eap_status_process_general_error;


	u32_t payload_length = received_eap_message->get_data_length();

	if (payload_length == 0u)
	{
		// No payload in this packet.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	m_ttls_received_payloads.reset();

	{
		eap_diameter_avp_header_c received_avp(
			m_am_tools,
			received_eap_message->get_data(received_eap_message->get_data_length()),
			received_eap_message->get_data_length());
		if (received_avp.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		
		status = m_ttls_received_payloads.parse_diameter_payloads(
			&received_avp,
			&payload_length);
	}

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (payload_length != 0u)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DIAMETER_ERROR,
			(EAPL("ERROR: eap_radius_payloads_c::parse_radius_packet(): ")
			 EAPL("RADIUS-header is corrupted. Buffer length and payload ")
			 EAPL("length does not match. Illegal byte count %lu\n"),
			 payload_length));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	m_ttls_message_type = eap_ttls_tunneled_message_type_none;
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)


	if (check_ttls_eap_payloads(&m_ttls_received_payloads, &m_ttls_message_type)
		== eap_status_ok)
	{
		// This packet includes EAP-Message AVP.

		eap_diameter_variable_data_c * const eap_message_payload
			= m_ttls_received_payloads.get_payload(eap_diameter_avp_code_eap_message);

		if (eap_message_payload == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		eap_variable_data_c * const eap_message
			= eap_message_payload->get_payload_buffer();

		if (eap_message == 0
			|| eap_message->get_is_valid_data() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		if (eap_message->get_data_length() < eap_header_base_c::get_header_length())
		{
			// Not enough payload in this packet.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		*eap_packet_length = eap_message->get_data_length();
		
		u8_t * const eap_payload
			= eap_message->get_data(*eap_packet_length);
		if (eap_payload == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_header_wr_c forwarded_eap_packet(m_am_tools, 0, 0ul);

		// We must forward this EAP-packet to tunneled EAP-type.
		forwarded_eap_packet.set_header_buffer(
			eap_payload,
			*eap_packet_length);
		if (forwarded_eap_packet.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = packet_forward_to_tunnel(
			&m_receive_network_id,
			&forwarded_eap_packet,
			*eap_packet_length);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	else if (check_ttls_plain_mschapv2_payloads(&m_ttls_received_payloads, &m_ttls_message_type)
		== eap_status_ok)
	{
		status = handle_ttls_plain_mschapv2_payloads(
			&m_ttls_received_payloads,
			m_ttls_message_type,
			received_eap_identifier);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	else if (check_ttls_plain_pap_payloads(&m_ttls_received_payloads, &m_ttls_message_type)
		== eap_status_ok)
	{
		status = handle_ttls_plain_pap_payloads(
			&m_ttls_received_payloads,
			m_ttls_message_type,
			received_eap_identifier);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	else
	{
		// Not correct AVP-payloads are included.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_TLS_PEAP_ERROR, 
			(EAPL("ERROR: tls_application_eap_core_c::packet_process_ttls(): ")
			 EAPL("Not correct AVP-payloads are included in eap_state_variable_e %d.\n"),
			 m_tunneled_eap_type_authentication_state));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::packet_process_xp_peap_v0(
	eap_variable_data_c * const packet,
	const u8_t received_eap_identifier,
	u32_t * const eap_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::packet_process_xp_peap_v0()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::packet_process_xp_peap_v0()");

	// XP PEAPv0 does not include EAP-header (code, identifier and length).
	// Here we must create those attributes.
	// Exception to this rule is, EAP-success and EAP-failure are sent in "Extensions Request Packet"
	// or "Extensions Response Packet".
	// The whole EAP-header is included
	// to "Extensions Request Packet" and "Extensions Response Packet".
	// See draft-kamath-pppext-peapv0-00.txt.
	// 
	// EAP-packet without code, identifier and length:
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |  EAP-type     |  EAP-data ...                                                                  
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// EAP-packet with "Extensions Request Packet" or "Extensions Response Packet":
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |  EAP-code     |EAP-identifier | EAP-length                    | EAP-type      |  EAP-data ...  
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// 
	// EAP-code of "Extensions Request Packet" is 1 which is same as EAP-type of EAP-identity.
	// EAP-code of "Extensions Response Packet" is 2 which is same as EAP-type of EAP-notification.

	eap_status_e status = eap_status_process_general_error;

	u32_t received_eap_packet_length = packet->get_data_length();
	if (received_eap_packet_length == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	
	eap_type_value_e received_eap_type_or_code(eap_type_none);

	const u8_t * const p_received_eap_type_or_code
		= static_cast<const u8_t *>(packet->get_data(sizeof(u8_t)));

	if (p_received_eap_type_or_code == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	else if (*p_received_eap_type_or_code == eap_type_expanded_type)
	{
		status = eap_expanded_type_c::read_type(
			m_am_tools,
			0ul,
			p_received_eap_type_or_code,
			received_eap_packet_length,
			&received_eap_type_or_code);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		received_eap_type_or_code = static_cast<eap_type_ietf_values_e>(*p_received_eap_type_or_code);
	}

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("packet_process_xp_peap_v0(): XP-PEAPv0 %s, tunneled eap_type_or_code %d, ")
		 EAPL("eap_packet_length %d, m_tunneled_eap_type_authentication_state %d, ")
		 EAPL("m_tls_session_type %d.\n"),
		 (m_is_client == true ? "client": "server"),
		 convert_eap_type_to_u32_t(received_eap_type_or_code),
		 received_eap_packet_length,
		 m_tunneled_eap_type_authentication_state,
		 m_tls_session_type));

	bool probably_is_extensions_packet = false;

	const u32_t EAP_PEAP_V0_RESULT_AVP_STATUS_LENGTH = sizeof(u16_t);
	const u32_t EAP_PEAP_V0_EXTENSIONS_PACKET_LENGTH
		= eap_header_wr_c::get_header_length()
		+ eap_header_wr_c::get_ietf_type_field_length()
		+ tls_peap_tlv_header_c::get_header_length()
		+ EAP_PEAP_V0_RESULT_AVP_STATUS_LENGTH;

	if (received_eap_packet_length >= EAP_PEAP_V0_EXTENSIONS_PACKET_LENGTH)
	{
		eap_header_wr_c possible_extensions_eap_packet(
			m_am_tools,
			packet->get_data(packet->get_data_length()),
			packet->get_data_length());

		if (possible_extensions_eap_packet.get_is_valid() == true
			&& possible_extensions_eap_packet.check_header() == eap_status_ok)
		{
			if (m_is_client == true
				&& possible_extensions_eap_packet.get_code() == eap_code_request
				&& possible_extensions_eap_packet.get_type() == eap_type_tlv_extensions)
			{
				// This is "Extensions Request Packet".
				probably_is_extensions_packet = true;
			}
			else if (m_is_client == false
				&& possible_extensions_eap_packet.get_code() == eap_code_response
				&& possible_extensions_eap_packet.get_type() == eap_type_tlv_extensions)
			{
				// This is "Extensions Response Packet".
				probably_is_extensions_packet = true;
			}
		}
	}


	eap_code_value_e forwarded_eap_code = eap_code_none;
	eap_variable_data_c forwarded_packet_buffer(m_am_tools);

	// In the first phase we will check first byte as a EAP-type field.
	if (probably_is_extensions_packet == false
		&& ((m_tunneled_eap_type_authentication_state == eap_state_none
			&& received_eap_type_or_code == eap_type_identity)
		|| (m_tunneled_eap_type_authentication_state == eap_state_identity_request_received
			&& (received_eap_type_or_code != eap_type_none
				&& received_eap_type_or_code != eap_type_identity)
			)))
	{
		EAP_TRACE_ALWAYS(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_process_xp_peap_v0(): XP-PEAPv0 tunneled eap_type %d, ")
			 EAPL("m_tunneled_eap_type_authentication_state %d.\n"),
			 convert_eap_type_to_u32_t(received_eap_type_or_code),
			 m_tunneled_eap_type_authentication_state));
		
		if (m_tunneled_eap_type_authentication_state == eap_state_none
			&& received_eap_type_or_code == eap_type_identity)
		{
			m_tunneled_eap_type_authentication_state = eap_state_identity_request_received;
		}

		*eap_packet_length = eap_header_base_c::get_header_length()+packet->get_data_length();

		status = forwarded_packet_buffer.set_buffer_length(*eap_packet_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		forwarded_packet_buffer.set_data_length(*eap_packet_length);

		status = forwarded_packet_buffer.add_data_to_offset(
			eap_header_base_c::get_header_length(),
			packet->get_data(packet->get_data_length()),
			packet->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (m_is_client == true)
		{
			forwarded_eap_code = eap_code_request;
		}
		else
		{
			forwarded_eap_code = eap_code_response;
		}
	}
	else if (probably_is_extensions_packet == true
			  // The first case will allow sessions resumption without tunneled EAP-authentication
			 && ((m_tunneled_eap_type_authentication_state
				  == eap_state_none && m_peap_allow_tunneled_session_resumption == true)
				 || m_tunneled_eap_type_authentication_state == eap_state_identity_request_received
				 || m_tunneled_eap_type_authentication_state
				 == eap_state_authentication_finished_successfully
				 || m_tunneled_eap_type_authentication_state
				 == eap_state_authentication_terminated_unsuccessfully))
	{
		// In the second phase we will check first byte as a EAP-code field

		EAP_TRACE_ALWAYS(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_process_xp_peap_v0(): XP-PEAPv0 tunneled eap_code %d, ")
			 EAPL("m_tunneled_eap_type_authentication_state %d.\n"),
			 convert_eap_type_to_u32_t(received_eap_type_or_code),
			 m_tunneled_eap_type_authentication_state));
		
		eap_header_wr_c final_eap_packet(
			m_am_tools,
			packet->get_data(packet->get_data_length()),
			packet->get_data_length());
		if (final_eap_packet.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = final_eap_packet.check_header();
		if (status != eap_status_ok)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_TLS_PEAP_ERROR, 
				(EAPL("ERROR: EAP-header corrupted.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u32_t parsed_eap_data_length = final_eap_packet.get_type_data_length();

		if (parsed_eap_data_length == 0u)
		{
			// No payload in this packet.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}

		if (final_eap_packet.get_header_length()+parsed_eap_data_length > packet->get_data_length())
		{
			// Corrupted length in EAP-header.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_TLS_PEAP_ERROR, 
				(EAPL("ERROR: EAP-header corrupted.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}


		if (m_is_client == true)
		{
			trace_tunneled_packet(EAPL("-> TUNNELED packet client"), &final_eap_packet);
		}
		else
		{
			trace_tunneled_packet(EAPL("-> TUNNELED packet server"), &final_eap_packet);
		}


		peap_tlv_payloads_c * peap_tlv_payloads = new peap_tlv_payloads_c(m_am_tools);
		eap_automatic_variable_c<peap_tlv_payloads_c> automatic_peap_tlv_payloads(m_am_tools, peap_tlv_payloads);

		if (peap_tlv_payloads == 0
			|| peap_tlv_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		tls_peap_tlv_header_c tlv(
			m_am_tools,
			final_eap_packet.get_type_data(final_eap_packet.get_type_data_length()),
			parsed_eap_data_length);
		if (tlv.get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_TLS_PEAP_ERROR, 
				(EAPL("ERROR: No peap_tlv_payloads_c.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = tlv.check_header();
		if (status != eap_status_ok)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_TLS_PEAP_ERROR, 
				(EAPL("ERROR: TLV header corrupted.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = parse_peap_tlv_payload(
			final_eap_packet.get_type_data(final_eap_packet.get_type_data_length()),
			&parsed_eap_data_length,
			peap_tlv_payloads);

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (parsed_eap_data_length != 0u)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_TLS_PEAP_ERROR,
				(EAPL("ERROR: tls_application_eap_core_c::packet_process_xp_peap_v0(): ")
				 EAPL("PEAP-header is corrupted. Buffer length and payload ")
				 EAPL("length does not match. Illegal byte count %lu\n"),
				 parsed_eap_data_length));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		// Checks the payloads existence.
		if (peap_tlv_payloads->check_payloads(
				peap_tlv_payloads_c::peap_tlv_payload_status_must_be, // result_tlv
				peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be, // nak_tlv
				peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be, // crypto_binding_tlv
				peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be, // eap_payload_tlv
				peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be  // intermediate_result_tlv
				) == true
			)
		{
			// OK.

			if (peap_tlv_payloads->get_result_tlv()->get_data_length()
				< EAP_PEAP_V0_RESULT_AVP_STATUS_LENGTH)
			{
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_TLS_PEAP_ERROR, 
					(EAPL("ERROR: TLV-result payload too short.\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			u8_t * const tlv_status_network_order
				= reinterpret_cast<u8_t *>(
					peap_tlv_payloads->get_result_tlv()->get_data(
						EAP_PEAP_V0_RESULT_AVP_STATUS_LENGTH));
			if (tlv_status_network_order == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_ASSERT(EAP_PEAP_V0_RESULT_AVP_STATUS_LENGTH == sizeof(u16_t));

			u16_t tlv_status_host_order
				= eap_read_u16_t_network_order(
					tlv_status_network_order,
					EAP_PEAP_V0_RESULT_AVP_STATUS_LENGTH);

			if (tlv_status_host_order == tls_peap_tlv_status_success)
			{
				forwarded_eap_code = eap_code_success;
			}
			else
			{
				// All other EAP-codes are assumed EAP-Failure.
				forwarded_eap_code = eap_code_failure;
			}

			eap_header_string_c eap_string;
			EAP_UNREFERENCED_PARAMETER(eap_string);

			EAP_TRACE_ALWAYS(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("packet_process_xp_peap_v0(): XP-PEAPv0 tunneled %s received.\n"),
				 eap_string.get_eap_code_string(forwarded_eap_code)));

			// Here we swap the addresses.
			eap_am_network_id_c send_network_id(
				m_am_tools,
				m_receive_network_id.get_destination_id(),
				m_receive_network_id.get_source_id(),
				m_receive_network_id.get_type());


			if (m_is_client == true)
			{
				if ((m_tls_session_type == tls_session_type_original_session_resumption
						|| m_tls_session_type == tls_session_type_stateless_session_resumption)
					&& m_tunneled_eap_type_authentication_state == eap_state_none
					&& forwarded_eap_code == eap_code_success)
				{
					// Send tunneled EAP-Success acknowledge.
					eap_status_e status = send_tunneled_acknowledge_xp_peap_v0(
						eap_code_success,
						received_eap_identifier);
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
					}
					else
					{
						// Send state notification to lower layer.

						eap_state_notification_c * const notification = new eap_state_notification_c(
							m_am_tools,
							&send_network_id,
							m_is_client,
							eap_state_notification_eap,
							eap_protocol_layer_eap,
							m_peap_tunneled_eap_type,
							eap_state_none,
							eap_state_authentication_finished_successfully,
							received_eap_identifier,
							false);

						eap_automatic_variable_c<eap_state_notification_c> automatic_notification(m_am_tools, notification);

						if (notification == 0)
						{
							m_tunneled_eap_type_authentication_state
								= eap_state_authentication_terminated_unsuccessfully;
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
						}

						get_application_partner()->state_notification(notification);

						status = eap_status_success;
					}

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else if ((m_tls_session_type == tls_session_type_original_session_resumption
							|| m_tls_session_type == tls_session_type_stateless_session_resumption)
					&& m_tunneled_eap_type_authentication_state == eap_state_none
					&& forwarded_eap_code == eap_code_failure)
				{
					// Send tunneled EAP-Failure acknowledge.
					eap_status_e status = send_tunneled_acknowledge_xp_peap_v0(
						eap_code_failure,
						received_eap_identifier);

					m_tunneled_eap_type_authentication_state
						= eap_state_authentication_terminated_unsuccessfully;

						// Send state notification to lower layer.
					eap_state_notification_c * const notification = new eap_state_notification_c(
						m_am_tools,
						&send_network_id,
						m_is_client,
						eap_state_notification_eap,
						eap_protocol_layer_eap,
						m_peap_tunneled_eap_type,
						eap_state_none,
						eap_state_authentication_terminated_unsuccessfully,
						received_eap_identifier,
						false);

					eap_automatic_variable_c<eap_state_notification_c> automatic_notification(m_am_tools, notification);

					if (notification == 0)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					notification->set_authentication_error(eap_status_authentication_failure);

					get_application_partner()->state_notification(notification);
					
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else
				{
					// Client must forward this EAP-packet to tunneled EAP-type.
					*eap_packet_length = eap_header_base_c::get_header_length();

					status = forwarded_packet_buffer.set_buffer_length(*eap_packet_length);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
					forwarded_packet_buffer.set_data_length(*eap_packet_length);
				}
			}
			else
			{
				status = eap_status_authentication_failure;

				// This is server.
				// Client sent a acknowledge.
				if (forwarded_eap_code == eap_code_success
					&& (m_tunneled_eap_type_authentication_state
						== eap_state_authentication_finished_successfully
						|| ((m_tls_session_type == tls_session_type_original_session_resumption
								|| m_tls_session_type == tls_session_type_stateless_session_resumption)
							&& m_tunneled_eap_type_authentication_state == eap_state_none)))
				{
					// XP-PEAP Authentication OK.

					eap_state_notification_c * const notification = new eap_state_notification_c(
						m_am_tools,
						&send_network_id,
						m_is_client,
						eap_state_notification_eap,
						eap_protocol_layer_eap,
						m_peap_tunneled_eap_type,
						eap_state_none,
						eap_state_authentication_finished_successfully,
						received_eap_identifier,
						false);

					eap_automatic_variable_c<eap_state_notification_c> automatic_notification(m_am_tools, notification);

					if (notification == 0)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					get_application_partner()->state_notification(notification);

					status = eap_status_success;
				}
				else
				{
					// Authentication failed.
					eap_state_notification_c * const notification = new eap_state_notification_c(
						m_am_tools,
						&send_network_id,
						m_is_client,
						eap_state_notification_eap,
						eap_protocol_layer_eap,
						m_peap_tunneled_eap_type,
						eap_state_none,
						eap_state_authentication_terminated_unsuccessfully,
						received_eap_identifier,
						false);

					eap_automatic_variable_c<eap_state_notification_c> automatic_notification(m_am_tools, notification);

					if (notification == 0)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					notification->set_authentication_error(eap_status_authentication_failure);

					get_application_partner()->state_notification(notification);

					status = eap_status_authentication_failure;
				}

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			// Not correct PEAP_TLV-payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_TLS_PEAP_ERROR, 
				(EAPL("ERROR: tls_application_eap_core_c::packet_process_xp_peap_v0(): ")
				 EAPL("Not correct PEAP_TLV-payloads are included in eap_state_variable_e %d.\n"),
				 m_tunneled_eap_type_authentication_state));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

	}
	else
	{
		status = eap_status_unexpected_message;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_header_wr_c forwarded_eap_packet(m_am_tools, 0, 0ul);

	forwarded_eap_packet.set_header_buffer(
		forwarded_packet_buffer.get_data(*eap_packet_length),
		*eap_packet_length);
	if (forwarded_eap_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	forwarded_eap_packet.reset_header(
		static_cast<u16_t>(*eap_packet_length),
		m_use_eap_expanded_type);
	forwarded_eap_packet.set_identifier(received_eap_identifier);
	forwarded_eap_packet.set_code(forwarded_eap_code);
	forwarded_eap_packet.set_length(
		static_cast<u16_t>(*eap_packet_length),
		m_use_eap_expanded_type);

	status = packet_forward_to_tunnel(
		&m_receive_network_id,
		&forwarded_eap_packet,
		*eap_packet_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::packet_process_peap_v1(
	eap_variable_data_c * const received_eap_message,
	const u8_t received_eap_identifier,
	u32_t * const eap_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::packet_process_peap_v1()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::packet_process_peap_v1()");

	eap_status_e status = eap_status_process_general_error;


	eap_header_wr_c received_eap_header(
		m_am_tools,
		received_eap_message->get_data(received_eap_message->get_data_length()),
		received_eap_message->get_data_length());
	if (received_eap_header.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = received_eap_header.check_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_TLS_PEAP_ERROR, 
			(EAPL("ERROR: EAP-header corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t parsed_eap_data_length = received_eap_header.get_type_data_length();

	if (received_eap_header.get_header_length()+parsed_eap_data_length
		> received_eap_message->get_data_length())
	{
		// Corrupted length in EAP-header.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_TLS_PEAP_ERROR, 
			(EAPL("ERROR: EAP-header corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}


	// This is plain EAP-packet.
	*eap_packet_length = received_eap_message->get_data_length();

	eap_header_wr_c forwarded_eap_packet(m_am_tools, 0, 0ul);

	forwarded_eap_packet.set_header_buffer(
		received_eap_message->get_data(*eap_packet_length),
		*eap_packet_length);

	eap_code_value_e received_eap_code = received_eap_header.get_code();

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(
		m_am_tools,
		m_receive_network_id.get_destination_id(),
		m_receive_network_id.get_source_id(),
		m_receive_network_id.get_type());

	if (
#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
		m_is_client == false
#if defined(USE_EAP_PEAPV1_EXTENSIONS)
		&& m_server_use_peapv1_extensions_request == false
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)
		&&
#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
		m_use_tppd_tls_peap == true
		&& (m_tunneled_eap_type_authentication_state
			== eap_state_authentication_finished_successfully
		|| m_tunneled_eap_type_authentication_state
			== eap_state_authentication_terminated_unsuccessfully))
	{
		status = eap_status_authentication_failure;

		// This is server.
		// Client sent a acknowledge.
		if (m_tunneled_eap_type_authentication_state
			== eap_state_authentication_finished_successfully
			&& forwarded_eap_packet.get_type() == eap_type_peap
			&& forwarded_eap_packet.get_type_data_length() == sizeof(u8_t) // There is only flags and version
			&& forwarded_eap_packet.get_type_data(sizeof(u8_t)) != 0
			&& *(forwarded_eap_packet.get_type_data(sizeof(u8_t))) == peap_version_1)
		{
			// PEAPv1 Authentication OK.

			eap_state_notification_c notification(
				m_am_tools,
				&send_network_id,
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_eap,
				m_peap_tunneled_eap_type,
				eap_state_none,
				eap_state_authentication_finished_successfully,
				received_eap_identifier,
				false);
			get_application_partner()->state_notification(&notification);

			status = eap_status_success;
		}
		else
		{
			// PEAPv1 Authentication failed.
			eap_state_notification_c notification(
				m_am_tools,
				&send_network_id,
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_eap,
				m_peap_tunneled_eap_type,
				eap_state_none,
				eap_state_authentication_terminated_unsuccessfully,
				received_eap_identifier,
				false);

			notification.set_authentication_error(eap_status_authentication_failure);

			get_application_partner()->state_notification(&notification);

			status = eap_status_authentication_failure;
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
	else if (m_is_client == true
		&& m_use_tppd_tls_peap == true
		&& (m_tls_session_type == tls_session_type_original_session_resumption
			|| m_tls_session_type == tls_session_type_stateless_session_resumption)
		&& m_tunneled_eap_type_authentication_state == eap_state_none
		&& received_eap_code == eap_code_success)
	{
		// Received tunneled EAP-Success.
		// This will tell client the tunneled
		// EAP-session was also restored.

		if (m_is_client == true)
		{
			trace_tunneled_packet(EAPL("-> TUNNELED packet client"), &forwarded_eap_packet);
		}
		else
		{
			trace_tunneled_packet(EAPL("-> TUNNELED packet server"), &forwarded_eap_packet);
		}

		m_tunneled_eap_type_authentication_state = eap_state_authentication_finished_successfully;

		eap_state_notification_c notification(
			m_am_tools,
			&send_network_id,
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_eap,
			m_peap_tunneled_eap_type,
			eap_state_none,
			eap_state_tppd_peapv1_authentication_finished_successfully_with_tunneled_eap_success,
			received_eap_identifier,
			false);
		get_application_partner()->state_notification(&notification);

		status = eap_status_success;
	}
#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
	else
	{

#if defined(USE_EAP_PEAPV1_EXTENSIONS)
		if ((m_is_client == true
				&& forwarded_eap_packet.get_code() == eap_code_request
				&& forwarded_eap_packet.get_type() == eap_type_tlv_extensions)
#if defined(USE_EAP_CORE_SERVER)
			|| (m_is_client == false
				&& forwarded_eap_packet.get_code() == eap_code_response
				&& forwarded_eap_packet.get_type() == eap_type_tlv_extensions)
#endif //#if defined(USE_EAP_CORE_SERVER)
			)
		{
			if (m_is_client == true)
			{
				trace_tunneled_packet(EAPL("-> TUNNELED packet client"), &forwarded_eap_packet);
			}
			else
			{
				trace_tunneled_packet(EAPL("-> TUNNELED packet server"), &forwarded_eap_packet);
			}


			peap_tlv_payloads_c * peap_tlv_payloads = new peap_tlv_payloads_c(m_am_tools);
			eap_automatic_variable_c<peap_tlv_payloads_c> automatic_peap_tlv_payloads(m_am_tools, peap_tlv_payloads);

			if (peap_tlv_payloads == 0
				|| peap_tlv_payloads->get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			tls_peap_tlv_header_c tlv(
				m_am_tools,
				forwarded_eap_packet.get_type_data(forwarded_eap_packet.get_type_data_length()),
				parsed_eap_data_length);
			if (tlv.get_is_valid() == false)
			{
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_TLS_PEAP_ERROR, 
					(EAPL("ERROR: No peap_tlv_payloads_c.\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = tlv.check_header();
			if (status != eap_status_ok)
			{
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_TLS_PEAP_ERROR, 
					(EAPL("ERROR: TLV header corrupted.\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = parse_peap_tlv_payload(
				forwarded_eap_packet.get_type_data(forwarded_eap_packet.get_type_data_length()),
				&parsed_eap_data_length,
				peap_tlv_payloads);

			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else if (parsed_eap_data_length != 0u)
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_TLS_PEAP_ERROR,
					(EAPL("ERROR: tls_application_eap_core_c::packet_process_peap_v1(): ")
					 EAPL("PEAP-header is corrupted. Buffer length and payload ")
					 EAPL("length does not match. Illegal byte count %lu\n"),
					 parsed_eap_data_length));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			// Checks the payloads existence.
			if (peap_tlv_payloads->check_payloads(
					peap_tlv_payloads_c::peap_tlv_payload_status_must_be, // result_tlv
					peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be, // nak_tlv
					peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be, // crypto_binding_tlv
					peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be, // eap_payload_tlv
					peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be  // intermediate_result_tlv
					) == true
				)
			{
				// OK.

				const u32_t EAP_PEAP_V1_RESULT_AVP_STATUS_LENGTH = sizeof(u16_t);

				if (peap_tlv_payloads->get_result_tlv()->get_data_length()
					< EAP_PEAP_V1_RESULT_AVP_STATUS_LENGTH)
				{
					EAP_TRACE_ERROR(
						m_am_tools, 
						TRACE_FLAGS_TLS_PEAP_ERROR, 
						(EAPL("ERROR: TLV-result payload too short.\n")));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}

				u8_t * const tlv_status_network_order
					= reinterpret_cast<u8_t *>(
						peap_tlv_payloads->get_result_tlv()->get_data(
							EAP_PEAP_V1_RESULT_AVP_STATUS_LENGTH));
				if (tlv_status_network_order == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				EAP_ASSERT(EAP_PEAP_V1_RESULT_AVP_STATUS_LENGTH == sizeof(u16_t));

				u16_t tlv_status_host_order
					= eap_read_u16_t_network_order(
						tlv_status_network_order,
						EAP_PEAP_V1_RESULT_AVP_STATUS_LENGTH);

				eap_code_value_e forwarded_eap_code(eap_code_none);

				if (tlv_status_host_order == tls_peap_tlv_status_success)
				{
					forwarded_eap_code = eap_code_success;
				}
				else
				{
					// All other EAP-codes are assumed EAP-Failure.
					forwarded_eap_code = eap_code_failure;
				}

				eap_header_string_c eap_string;
				EAP_UNREFERENCED_PARAMETER(eap_string);

				EAP_TRACE_ALWAYS(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("tls_application_eap_core_c::packet_process_peap_v1(): PEAPv1 tunneled %s received.\n"),
					 eap_string.get_eap_code_string(forwarded_eap_code)));

				// Here we swap the addresses.
				eap_am_network_id_c send_network_id(
					m_am_tools,
					m_receive_network_id.get_destination_id(),
					m_receive_network_id.get_source_id(),
					m_receive_network_id.get_type());


				if (m_is_client == true)
				{
					if ((m_tls_session_type == tls_session_type_original_session_resumption
							|| m_tls_session_type == tls_session_type_stateless_session_resumption)
						&& m_tunneled_eap_type_authentication_state == eap_state_none
						&& forwarded_eap_code == eap_code_success)
					{
						// Send tunneled EAP-Success acknowledge.
						status = send_tunneled_acknowledge_xp_peap_v0(
							eap_code_success,
							received_eap_identifier);
						if (status != eap_status_ok)
						{
							m_tunneled_eap_type_authentication_state
								= eap_state_authentication_terminated_unsuccessfully;
						}
						else
						{
							// Send state notification to lower layer.

							eap_state_notification_c * const notification = new eap_state_notification_c(
								m_am_tools,
								&send_network_id,
								m_is_client,
								eap_state_notification_eap,
								eap_protocol_layer_eap,
								m_peap_tunneled_eap_type,
								eap_state_none,
								eap_state_authentication_finished_successfully,
								received_eap_identifier,
								false);

							eap_automatic_variable_c<eap_state_notification_c> automatic_notification(m_am_tools, notification);

							if (notification == 0)
							{
								m_tunneled_eap_type_authentication_state
									= eap_state_authentication_terminated_unsuccessfully;
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
							}

							get_application_partner()->state_notification(notification);

							status = eap_status_success;
						}

						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
					else if ((m_tls_session_type == tls_session_type_original_session_resumption
								|| m_tls_session_type == tls_session_type_stateless_session_resumption)
						&& m_tunneled_eap_type_authentication_state == eap_state_none
						&& forwarded_eap_code == eap_code_failure)
					{
						// Send tunneled EAP-Failure acknowledge.
						eap_status_e status = send_tunneled_acknowledge_xp_peap_v0(
							eap_code_failure,
							received_eap_identifier);

						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;

							// Send state notification to lower layer.
						eap_state_notification_c * const notification = new eap_state_notification_c(
							m_am_tools,
							&send_network_id,
							m_is_client,
							eap_state_notification_eap,
							eap_protocol_layer_eap,
							m_peap_tunneled_eap_type,
							eap_state_none,
							eap_state_authentication_terminated_unsuccessfully,
							received_eap_identifier,
							false);

						eap_automatic_variable_c<eap_state_notification_c> automatic_notification(m_am_tools, notification);

						if (notification == 0)
						{
							m_tunneled_eap_type_authentication_state
								= eap_state_authentication_terminated_unsuccessfully;
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
						}

						notification->set_authentication_error(eap_status_authentication_failure);

						get_application_partner()->state_notification(notification);
						
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
					else
					{
						// Client must forward this EAP-packet to tunneled EAP-type.

						m_client_send_peapv1_extensions_response = true;

						eap_variable_data_c forwarded_packet_buffer(m_am_tools);
						if (forwarded_packet_buffer.get_is_valid() == false)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
						}

						*eap_packet_length = eap_header_base_c::get_header_length();

						status = forwarded_packet_buffer.set_buffer_length(*eap_packet_length);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						status = forwarded_packet_buffer.set_data_length(*eap_packet_length);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						{
							eap_header_wr_c forwarded_eap_packet(m_am_tools, 0, 0ul);

							forwarded_eap_packet.set_header_buffer(
								forwarded_packet_buffer.get_data(*eap_packet_length),
								*eap_packet_length);
							if (forwarded_eap_packet.get_is_valid() == false)
							{
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
							}

							forwarded_eap_packet.reset_header(
								static_cast<u16_t>(*eap_packet_length),
								m_use_eap_expanded_type);
							forwarded_eap_packet.set_identifier(received_eap_identifier);
							forwarded_eap_packet.set_code(forwarded_eap_code);
							forwarded_eap_packet.set_length(
								static_cast<u16_t>(*eap_packet_length),
								m_use_eap_expanded_type);

							// Forward packet to upper layer.
							status = packet_forward_to_tunnel(
								&m_receive_network_id,
								&forwarded_eap_packet,
								*eap_packet_length);
						}
					}
				}
				else
				{
					status = eap_status_authentication_failure;

					// This is server.
					// Client sent a acknowledge.
					if (forwarded_eap_code == eap_code_success
						&& (m_tunneled_eap_type_authentication_state
							== eap_state_authentication_finished_successfully
							|| ((m_tls_session_type == tls_session_type_original_session_resumption
									|| m_tls_session_type == tls_session_type_stateless_session_resumption)
								&& m_tunneled_eap_type_authentication_state == eap_state_none)))
					{
						// PEAPv1 Authentication OK.

						eap_state_notification_c * const notification = new eap_state_notification_c(
							m_am_tools,
							&send_network_id,
							m_is_client,
							eap_state_notification_eap,
							eap_protocol_layer_eap,
							m_peap_tunneled_eap_type,
							eap_state_none,
							eap_state_authentication_finished_successfully_peapv1_extension,
							received_eap_identifier,
							false);

						eap_automatic_variable_c<eap_state_notification_c> automatic_notification(m_am_tools, notification);

						if (notification == 0)
						{
							m_tunneled_eap_type_authentication_state
								= eap_state_authentication_terminated_unsuccessfully;
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
						}

						get_application_partner()->state_notification(notification);

						status = eap_status_success;
					}
					else
					{
						// Authentication failed.
						eap_state_notification_c * const notification = new eap_state_notification_c(
							m_am_tools,
							&send_network_id,
							m_is_client,
							eap_state_notification_eap,
							eap_protocol_layer_eap,
							m_peap_tunneled_eap_type,
							eap_state_none,
							eap_state_authentication_terminated_unsuccessfully_peapv1_extension,
							received_eap_identifier,
							false);

						eap_automatic_variable_c<eap_state_notification_c> automatic_notification(m_am_tools, notification);

						if (notification == 0)
						{
							m_tunneled_eap_type_authentication_state
								= eap_state_authentication_terminated_unsuccessfully;
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
						}

						notification->set_authentication_error(eap_status_authentication_failure);

						get_application_partner()->state_notification(notification);

						status = eap_status_authentication_failure;
					}

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				// Not correct PEAP_TLV-payloads are included.
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_TLS_PEAP_ERROR, 
					(EAPL("ERROR: tls_application_eap_core_c::packet_process_peap_v1(): ")
					 EAPL("Not correct PEAP_TLV-payloads are included in eap_state_variable_e %d.\n"),
					 m_tunneled_eap_type_authentication_state));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}
		}
		else
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)
		{
			// Forward packet to upper layer.
			status = packet_forward_to_tunnel(
				&m_receive_network_id,
				&forwarded_eap_packet,
				*eap_packet_length);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::finish_successfull_authentication_peap_v2(
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::finish_successfull_authentication_peap_v2()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::finish_successfull_authentication_peap_v2()");

	eap_status_e status = eap_status_process_general_error;

	if (m_tunneled_eap_type_authentication_state == eap_state_authentication_finished_successfully)
	{
		// PEAPv2 Authentication OK.

		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(m_am_tools,
			m_receive_network_id.get_destination_id(),
			m_receive_network_id.get_source_id(),
			m_receive_network_id.get_type());

		status = create_compound_session_key_peap_v2();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = get_application_partner()->packet_data_crypto_keys(
			&send_network_id,
			&m_peap_v2_CSK
			);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_state_notification_c notification(
			m_am_tools,
			&send_network_id,
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_eap,
			m_peap_tunneled_eap_type,
			eap_state_none,
			eap_state_authentication_finished_successfully,
			received_eap_identifier,
			false);
		get_application_partner()->state_notification(&notification);

		status = eap_status_success;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::store_nonce_peap_v2(
	const bool is_client_when_true,
	peap_tlv_payloads_c * const peapv2_tlv_payloads)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::store_nonce_peap_v2()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::store_nonce_peap_v2()");

	eap_status_e status = eap_status_process_general_error;

	u8_t * const nonce = reinterpret_cast<u8_t *>(
		peapv2_tlv_payloads->get_crypto_binding_tlv()->get_data_offset(
			TLV_NONCE_OFFSET,
			TLV_NONCE_LENGTH));
	if (nonce == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (is_client_when_true == true)
	{
		status = m_peap_v2_server_nonce.set_copy_of_buffer(
			nonce,
			TLV_NONCE_LENGTH);
	}
	else
	{
		status = m_peap_v2_client_nonce.set_copy_of_buffer(
			nonce,
			TLV_NONCE_LENGTH);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::packet_process_peap_v2(
	eap_variable_data_c * const received_eap_message,
	const u8_t received_eap_identifier,
	u32_t * const eap_packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::packet_process_peap_v2()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::packet_process_peap_v2()");

	eap_status_e status = eap_status_process_general_error;
	eap_code_value_e forwarded_eap_code = eap_code_none;


	eap_header_wr_c received_eap_header(
		m_am_tools,
		received_eap_message->get_data(received_eap_message->get_data_length()),
		received_eap_message->get_data_length());
	if (received_eap_header.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = received_eap_header.check_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_TLS_PEAP_ERROR, 
			(EAPL("ERROR: EAP-header corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t parsed_eap_data_length = received_eap_header.get_type_data_length();

	if (parsed_eap_data_length < sizeof(u8_t))
	{
		// Not enough payload in this packet.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	if (received_eap_header.get_header_length()+parsed_eap_data_length
		> received_eap_message->get_data_length())
	{
		// Corrupted length in EAP-header.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_TLS_PEAP_ERROR, 
			(EAPL("ERROR: EAP-header corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	if (received_eap_header.get_type() != eap_type_tlv_extensions)
	{
		// Not enough payload in this packet.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}


	tls_peap_tlv_header_c tlv(
		m_am_tools,
		received_eap_header.get_type_data(received_eap_header.get_type_data_length()),
		parsed_eap_data_length);
	if (tlv.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_TLS_PEAP_ERROR, 
			(EAPL("ERROR: No peap_tlv_payloads_c.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = tlv.check_header();
	if (status != eap_status_ok)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_TLS_PEAP_ERROR, 
			(EAPL("ERROR: TLV header corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_peapv2_tlv_payloads.reset();

	status = parse_peap_tlv_payload(
		received_eap_header.get_type_data(received_eap_header.get_type_data_length()),
		&parsed_eap_data_length,
		&m_peapv2_tlv_payloads);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (parsed_eap_data_length != 0u)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_TLS_PEAP_ERROR,
			(EAPL("ERROR: tls_application_eap_core_c::packet_process_peap_v2(): ")
			 EAPL("PEAP-header is corrupted. Buffer length and payload ")
			 EAPL("length does not match. Illegal byte count %lu\n"),
			 parsed_eap_data_length));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}


	// EAP-Identifier is used later in verify_tunneled_acknowledge_peap_v2().
	m_received_eap_identifier = received_eap_identifier;

	// Checks the payloads existence.
	if (m_peapv2_tlv_payloads.check_payloads(
			peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be, // result_tlv
			peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be, // nak_tlv
			peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be, // crypto_binding_tlv
			peap_tlv_payloads_c::peap_tlv_payload_status_must_be, // eap_payload_tlv
			peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be  // intermediate_result_tlv
			) == true
		)
	{
		// This packet includes EAP-Payload TLV.

		*eap_packet_length = m_peapv2_tlv_payloads.get_eap_payload_tlv()->get_data_length();
		
		u8_t * const eap_payload
			= reinterpret_cast<u8_t *>(
				m_peapv2_tlv_payloads.get_eap_payload_tlv()->get_data(
					*eap_packet_length));
		if (eap_payload == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_header_wr_c forwarded_eap_packet(m_am_tools, 0, 0ul);

		// We must forward this EAP-packet to tunneled EAP-type.
		forwarded_eap_packet.set_header_buffer(
			eap_payload,
			*eap_packet_length);
		if (forwarded_eap_packet.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = packet_forward_to_tunnel(
			&m_receive_network_id,
			&forwarded_eap_packet,
			*eap_packet_length);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (m_peapv2_tlv_payloads.check_payloads(
			peap_tlv_payloads_c::peap_tlv_payload_status_must_be, // result_tlv
			peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be, // nak_tlv
			peap_tlv_payloads_c::peap_tlv_payload_status_must_be, // crypto_binding_tlv
			peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be, // eap_payload_tlv
			peap_tlv_payloads_c::peap_tlv_payload_status_must_be  // intermediate_result_tlv
			) == true
		)
	{
		// This is Protected termination.

		{
			u8_t * const tlv_status_network_order = reinterpret_cast<u8_t *>(
				m_peapv2_tlv_payloads.get_result_tlv()->get_data(sizeof(u16_t)));
			if (tlv_status_network_order == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u16_t tlv_status_host_order
				= eap_read_u16_t_network_order(tlv_status_network_order, sizeof(u16_t));

			if (tlv_status_host_order == tls_peap_tlv_status_success)
			{
				forwarded_eap_code = eap_code_success;
			}
			else
			{
				// All other EAP-codes are assumed EAP-Failure.
				forwarded_eap_code = eap_code_failure;
			}

			eap_header_string_c eap_string;
			EAP_UNREFERENCED_PARAMETER(eap_string);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("packet_process_peap_v2(): PEAPv2 tunneled %s received.\n"),
				 eap_string.get_eap_code_string(forwarded_eap_code)));
		}


		if (m_is_client == true)
		{
			// Client must forward created EAP-Success or EAP-Failure to tunneled EAP-type.
			// Result TLV, Crypto Binding TLV and Intermediate Result TLV
			// are checked within the state_notification() function
			// by the verify_tunneled_acknowledge_peap_v2() function
			// when eap_state_authentication_finished_successfully or
			// eap_state_authentication_terminated_unsuccessfully indication
			// is received.

			// Client stores the received server nonce. This is used later in key generation.
			status = store_nonce_peap_v2(m_is_client, &m_peapv2_tlv_payloads);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = create_eap_success_failure_in_forward_to_tunnel(
				&m_receive_network_id,
				forwarded_eap_code,
				received_eap_identifier);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			// Server checks the received TLVs immediately.

			status = store_nonce_peap_v2(m_is_client, &m_peapv2_tlv_payloads);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			eap_variable_data_c saved_mac(m_am_tools);

			{
				u8_t * const mac = reinterpret_cast<u8_t *>(
					m_peapv2_tlv_payloads.get_crypto_binding_tlv()->get_data_offset(
						TLV_MAC_OFFSET,
						TLV_MAC_LENGTH));
				if (mac == 0)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = saved_mac.set_copy_of_buffer(
					mac,
					TLV_MAC_LENGTH);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				m_am_tools->memset(mac, 0, TLV_MAC_LENGTH);
			}

			// Intermediate Combined Key is stored to m_peap_v2_IPMKn.
			// Compound MAC Key is stored to m_peap_v2_CMK_Bn.
			status = create_compound_mac_key_peap_v2(true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Client uses server CMK B1 key
			// to check the message server sent.
			eap_variable_data_c * mac_key = &m_peap_v2_CMK_B1_server;
			if (m_is_client == false)
			{
				// Server uses Client CMK B2 key
				// to check the message client sent.
				mac_key = &m_peap_v2_CMK_B2_client;
			}

			eap_variable_data_c mac_data(m_am_tools);

			status = create_crypto_binding_compound_mac(
				mac_key,
				m_peapv2_tlv_payloads.get_crypto_binding_tlv()->get_original_header(),
				&mac_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("verify TLV MAC"),
				 saved_mac.get_data(saved_mac.get_data_length()),
				 saved_mac.get_data_length()));

			// Here we check only saved_mac.get_data_length() bytes.
			// HMAC-SHA1 generates more than 128 bits used MAC.
			if (saved_mac.get_data_length() > mac_data.get_data_length()
 				|| m_am_tools->memcmp(
					saved_mac.get_data(saved_mac.get_data_length()),
					mac_data.get_data(mac_data.get_data_length()),
					saved_mac.get_data_length()) != 0)
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("PEAPv2: ERROR: %s: receive_function: ")
					 EAPL("packet_process_peap_v2(): MAC failed\n"),
					 (m_is_client == true ? "client": "server")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("PEAPv2: %s: MAC OK\n"),
					 (m_is_client == true ? "client": "server")));
			}


			/**
			 * @{ Check Intermediate Result TLV. }
			 */

			status = eap_status_authentication_failure;

			// This is server.
			// Client sent an acknowledge.
			if (forwarded_eap_code == eap_code_success
				&& m_tunneled_eap_type_authentication_state
				== eap_state_authentication_finished_successfully)
			{
				// PEAPv2 Authentication OK.

				status = finish_successfull_authentication_peap_v2(
					received_eap_identifier);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				// Authentication failed.
				status = eap_status_authentication_failure;
			}

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		// Not correct PEAP_TLV-payloads are included.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_TLS_PEAP_ERROR, 
			(EAPL("ERROR: tls_application_eap_core_c::packet_process_peap_v2(): ")
			 EAPL("Not correct PEAP_TLV-payloads are included in eap_state_variable_e %d.\n"),
			 m_tunneled_eap_type_authentication_state));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::verify_tunneled_acknowledge_peap_v2()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::verify_tunneled_acknowledge_peap_v2(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::verify_tunneled_acknowledge_peap_v2()");

	eap_status_e status = eap_status_process_general_error;
	eap_code_value_e forwarded_eap_code = eap_code_none;


	// Checks the payloads existence.
	if (m_peapv2_tlv_payloads.check_payloads(
			peap_tlv_payloads_c::peap_tlv_payload_status_must_be, // result_tlv
			peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be, // nak_tlv
			peap_tlv_payloads_c::peap_tlv_payload_status_must_be, // crypto_binding_tlv
			peap_tlv_payloads_c::peap_tlv_payload_status_must_not_be, // eap_payload_tlv
			peap_tlv_payloads_c::peap_tlv_payload_status_must_be  // intermediate_result_tlv
			) == true
		)
	{
		// This is Protected termination.

		{
			u8_t * const tlv_status_network_order = reinterpret_cast<u8_t *>(
				m_peapv2_tlv_payloads.get_result_tlv()->get_data(sizeof(u16_t)));
			if (tlv_status_network_order == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u16_t tlv_status_host_order
				= eap_read_u16_t_network_order(tlv_status_network_order, sizeof(u16_t));

			if (tlv_status_host_order == tls_peap_tlv_status_success)
			{
				forwarded_eap_code = eap_code_success;
			}
			else
			{
				// All other EAP-codes are assumed EAP-Failure.
				forwarded_eap_code = eap_code_failure;
			}
		}


		// Client and server checks the received TLVs.

		status = store_nonce_peap_v2(m_is_client, &m_peapv2_tlv_payloads);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_variable_data_c saved_mac(m_am_tools);

		{
			u8_t * const mac = reinterpret_cast<u8_t *>(
				m_peapv2_tlv_payloads.get_crypto_binding_tlv()->get_data_offset(
					TLV_MAC_OFFSET,
					TLV_MAC_LENGTH));
			if (mac == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = saved_mac.set_copy_of_buffer(
				mac,
				TLV_MAC_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			m_am_tools->memset(mac, 0, TLV_MAC_LENGTH);
		}

		// Client uses server CMK B1 key
		// to check the message server sent.
		eap_variable_data_c * mac_key = &m_peap_v2_CMK_B1_server;
		if (m_is_client == false)
		{
			// Server uses Client CMK B2 key
			// to check the message client sent.
			mac_key = &m_peap_v2_CMK_B2_client;
		}

		eap_variable_data_c mac_data(m_am_tools);

		status = create_crypto_binding_compound_mac(
			mac_key,
			m_peapv2_tlv_payloads.get_crypto_binding_tlv()->get_original_header(),
			&mac_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("verify TLV MAC"),
			 saved_mac.get_data(saved_mac.get_data_length()),
			 saved_mac.get_data_length()));

		// Here we check only saved_mac.get_data_length() bytes.
		// HMAC-SHA1 generates more than 128 bits used MAC.
		if (saved_mac.get_data_length() > mac_data.get_data_length()
			|| m_am_tools->memcmp(
				saved_mac.get_data(saved_mac.get_data_length()),
				mac_data.get_data(mac_data.get_data_length()),
				saved_mac.get_data_length()) != 0)
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("PEAPv2: ERROR: %s: receive_function: ")
				 EAPL("packet_process_peap_v2(): MAC failed\n"),
				 (m_is_client == true ? "client": "server")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("PEAPv2: %s: MAC OK\n"),
				 (m_is_client == true ? "client": "server")));
		}


		/**
		 * @{ Check Intermediate Result TLV. }
		 */

		status = eap_status_authentication_failure;

		// This is server.
		// Client sent a acknowledge.
		if (forwarded_eap_code == eap_code_success
			&& m_tunneled_eap_type_authentication_state
			== eap_state_authentication_finished_successfully)
		{
			// PEAPv2 Authentication OK.

			if (m_is_client == false)
			{
				status = finish_successfull_authentication_peap_v2(
					m_received_eap_identifier);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				// Server does nothing here.
				status = eap_status_success;
			}

		}
		else
		{
			// Authentication failed.
			status = eap_status_authentication_failure;
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		// Not correct PEAP_TLV-payloads are included.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_TLS_PEAP_ERROR, 
			(EAPL("ERROR: tls_application_eap_core_c::verify_tunneled_acknowledge_peap_v2(): ")
			 EAPL("Not correct PEAP_TLV-payloads are included in eap_state_variable_e %d.\n"),
			 m_tunneled_eap_type_authentication_state));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::packet_forward_to_tunnel(
	const eap_am_network_id_c * const /*receive_network_id*/,
	eap_header_wr_c * const forwarded_eap_packet,
	const u32_t eap_packet_length)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::packet_forward_to_tunnel(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::packet_forward_to_tunnel()");

	if (m_is_client == true)
	{
		trace_tunneled_packet(EAPL("-> TUNNELED packet client"), forwarded_eap_packet);
	}
	else
	{
		trace_tunneled_packet(EAPL("-> TUNNELED packet server"), forwarded_eap_packet);
	}

	eap_status_e status(eap_status_drop_packet_quietly);

	if (m_eap_core != 0)
	{
		status = m_eap_core->packet_process(
			&m_receive_network_id,
			forwarded_eap_packet,
			eap_packet_length);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::packet_process(
	eap_variable_data_c * const received_eap_message,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	u32_t eap_packet_length = 0ul;

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("tls_application_eap_core_c::packet_process(): received tunneled data:"),
		 received_eap_message->get_data(received_eap_message->get_data_length()),
		 received_eap_message->get_data_length()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::packet_process()");

	// At least EAP-type or EAP-code field is needed.
	if (received_eap_message->get_data_length() < sizeof(u8_t))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message);
	}

	if (received_eap_message->get_data_length() > received_eap_message->get_buffer_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
	}

	if (m_eap_type == eap_type_peap)
	{
		if (m_peap_version == peap_version_0_xp)
		{
			status = packet_process_xp_peap_v0(
				received_eap_message,
				received_eap_identifier,
				&eap_packet_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if ((m_tls_session_type == tls_session_type_original_session_resumption
					|| m_tls_session_type == tls_session_type_stateless_session_resumption)
				&& m_tunneled_eap_type_authentication_state
				== eap_state_authentication_finished_successfully)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
		}
		else if (m_peap_version == peap_version_1)
		{
			status = packet_process_peap_v1(
				received_eap_message,
				received_eap_identifier,
				&eap_packet_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (m_peap_version == peap_version_2)
		{
			status = packet_process_peap_v2(
				received_eap_message,
				received_eap_identifier,
				&eap_packet_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
		}
	}
	else if (m_eap_type == eap_type_ttls)
	{
		status = packet_process_ttls(
			received_eap_message,
			received_eap_identifier,
			&eap_packet_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::plain_eap_success_failure_packet_received(
	const eap_am_network_id_c * const receive_network_id,
	const eap_code_value_e received_eap_code,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_tls_trace_string_c state_trace;
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: plain_eap_success_failure_packet_received(): m_wait_plain_eap_success=%d, EAP-Code=%d, m_tls_session_type=%s, m_eap_core=0x%08x\n"),
		(m_is_client == true ? "client": "server"),
		m_wait_plain_eap_success,
		received_eap_code,
		eap_tls_trace_string_c::get_tls_session_type_string(m_tls_session_type),
		m_eap_core));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::plain_eap_success_failure_packet_received()");

	eap_status_e status(eap_status_ok);

	if (m_eap_core != 0
		&& m_tls_session_type != tls_session_type_original_session_resumption
		&& m_tls_session_type != tls_session_type_stateless_session_resumption)
	{
		status = create_eap_success_failure_in_forward_to_tunnel(
			receive_network_id,
			received_eap_code,
			received_eap_identifier);
		if (status != eap_status_ok
			&& status != eap_status_drop_packet_quietly)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// This object might wait EAP-Success, too.
	if (m_wait_plain_eap_success == true
		&& received_eap_code == eap_code_success)
	{
		// Here we swap the addresses.
		eap_am_network_id_c send_network_id(
			m_am_tools,
			m_receive_network_id.get_destination_id(),
			m_receive_network_id.get_source_id(),
			m_receive_network_id.get_type());

		eap_state_notification_c notification(
			m_am_tools,
			&send_network_id,
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_eap,
			m_eap_type,
			eap_state_none,
			eap_state_authentication_finished_successfully,
			m_received_eap_identifier,
			true);
		m_application_partner->state_notification(&notification);

		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::empty_ack_packet_received(
	const eap_am_network_id_c * const /* receive_network_id */,
	const u8_t /* received_eap_identifier */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: empty_ack_packet_received()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::empty_ack_packet_received()");

	eap_status_e status(eap_status_not_found);

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	if (m_is_client == false
		&& m_tunneled_eap_in_ttls == false
		&& m_eap_type == eap_type_ttls)
	{
		u32_t eap_length
			= EAP_MSCHAPV2_OPCODE_SIZE // OpCode is the only payload
			+ eap_header_base_c::get_type_data_start_offset(m_use_eap_expanded_type);

		eap_buf_chain_wr_c eap_packet_buffer(
			eap_write_buffer,
			m_am_tools,
			eap_length);
		if (eap_packet_buffer.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_header_wr_c forwarded_eap_packet(
			m_am_tools,
			eap_packet_buffer.get_data(eap_length),
			eap_length);

		if (forwarded_eap_packet.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		forwarded_eap_packet.reset_header(
			static_cast<u16_t>(eap_length),
			m_use_eap_expanded_type);
		forwarded_eap_packet.set_identifier(m_ttls_plain_ms_chap_v2_eap_identifier);
		forwarded_eap_packet.set_code(eap_code_response);
		forwarded_eap_packet.set_length(
			static_cast<u16_t>(eap_length),
			m_use_eap_expanded_type);
		forwarded_eap_packet.set_type(
			eap_type_mschapv2,
			m_use_eap_expanded_type);

		mschapv2_header_c mschapv2_header(
			m_am_tools,
			forwarded_eap_packet.get_type_data_offset(
				0,
				forwarded_eap_packet.get_type_data_length()),
			forwarded_eap_packet.get_type_data_length());

		mschapv2_header.set_opcode(mschapv2_opcode_success);

		status = packet_forward_to_tunnel(
			&m_receive_network_id,
			&forwarded_eap_packet,
			eap_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool tls_application_eap_core_c::get_is_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: function: tls_application_eap_core_c::reset(): this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::reset()");

	m_tunneled_eap_type_authentication_state = eap_state_none;
	m_tls_session_type = tls_session_type_none;
	m_use_tppd_tls_peap = false;
	m_use_tppd_peapv1_acknowledge_hack = false;

	eap_status_e status(eap_status_ok);

	if (m_eap_core != 0)
	{
		status = m_eap_core->reset();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::create_result_tlv_message(
	eap_buf_chain_wr_c * const packet,
	const eap_code_value_e result_eap_code,
	const u8_t eap_identifier,
	const tls_peap_tlv_type_e tlv_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: create_result_tlv_message()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::create_result_tlv_message()");

	if (packet->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t final_packet_length
		= eap_header_wr_c::get_header_length()
		+ sizeof(u8_t) // EAP-type field
		+tls_peap_tlv_header_c::get_header_length()
		+sizeof(u16_t);

	eap_status_e status = packet->set_buffer_length(final_packet_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (packet->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = packet->set_data_length(final_packet_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_header_wr_c final_eap_packet(
		m_am_tools,
		packet->get_data(packet->get_data_length()),
		packet->get_data_length());
	if (final_eap_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	final_eap_packet.reset_header(
		static_cast<u16_t>(final_packet_length),
		m_use_eap_expanded_type);
	final_eap_packet.set_identifier(eap_identifier);
	if (m_is_client == true)
	{
		final_eap_packet.set_code(eap_code_response);
	}
	else
	{
		final_eap_packet.set_code(eap_code_request);
	}
	final_eap_packet.set_length(
		static_cast<u16_t>(final_packet_length),
		m_use_eap_expanded_type);
	final_eap_packet.set_type(
		eap_type_tlv_extensions,
		m_use_eap_expanded_type);

	tls_peap_tlv_header_c tlv(
		m_am_tools,
		final_eap_packet.get_type_data(final_eap_packet.get_type_data_length()),
		final_eap_packet.get_type_data_length());
	if (tlv.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	/*  Result TLV:
	 *  0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |M|R|  TLV Type (AVP Type)      |            Length             |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |            Status             |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	tlv.reset_header(static_cast<u16_t>(sizeof(u16_t)));
	tlv.set_flag_tlv_type(tlv_type);
	tlv.set_flag_mandatory_tlv(true);

	u16_t * const tlv_status = reinterpret_cast<u16_t *>(tlv.get_data(sizeof(u16_t)));
	if (tlv_status == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u16_t tlv_status_network_order = 0ul;

	if (result_eap_code == eap_code_success)
	{
		tlv_status_network_order = eap_htons(static_cast<u16_t>(tls_peap_tlv_status_success));
	}
	else
	{
		tlv_status_network_order = eap_htons(static_cast<u16_t>(tls_peap_tlv_status_failure));
	}

	m_am_tools->memmove(tlv_status, &tlv_status_network_order, sizeof(tlv_status_network_order));

	EAP_TLS_PEAP_TRACE_PAYLOAD("Add TLV payload", &tlv, m_is_client);


	if (m_is_client == true)
	{
		trace_tunneled_packet(EAPL("<- TUNNELED packet client"), &final_eap_packet);
	}
	else
	{
		trace_tunneled_packet(EAPL("<- TUNNELED packet client"), &final_eap_packet);
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::create_intermediate_result_tlv_message(
	eap_buf_chain_wr_c * const packet,
	const eap_code_value_e result_eap_code,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: create_intermediate_result_tlv_message()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::create_intermediate_result_tlv_message()");

	/*  Intermediate Result TLV:
	 *  0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |M|R|  TLV Type (AVP Type)      |            Length             |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |            Status             |        TLVs...
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 * Now we do not support any included TLVs.
	 * This means Intermediate Result TLV is the same as Result TLV.
	 */

	eap_status_e status = create_result_tlv_message(
		packet,
		result_eap_code,
		eap_identifier,
		tls_peap_tlv_type_intermediate_result);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::create_eap_payload_tlv_message(
	eap_buf_chain_wr_c * const packet,
	const eap_header_wr_c * const sent_eap_packet,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::create_eap_payload_tlv_message()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::create_eap_payload_tlv_message()");

	if (packet->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	const u32_t tlv_payload_length
		= sent_eap_packet->get_length();

	const u32_t final_packet_length
		= eap_header_wr_c::get_header_length()
		+ sizeof(u8_t) // EAP-type field
		+ tls_peap_tlv_header_c::get_header_length()
		+ tlv_payload_length;

	eap_status_e status = packet->set_buffer_length(final_packet_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (packet->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = packet->set_data_length(final_packet_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_header_wr_c final_eap_packet(
		m_am_tools,
		packet->get_data(packet->get_data_length()),
		packet->get_data_length());
	if (final_eap_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	final_eap_packet.reset_header(
		static_cast<u16_t>(final_packet_length),
		m_use_eap_expanded_type);
	final_eap_packet.set_identifier(eap_identifier);
	if (m_is_client == true)
	{
		final_eap_packet.set_code(eap_code_response);
	}
	else
	{
		final_eap_packet.set_code(eap_code_request);
	}
	final_eap_packet.set_length(
		static_cast<u16_t>(final_packet_length),
		m_use_eap_expanded_type);
	final_eap_packet.set_type(
		eap_type_tlv_extensions,
		m_use_eap_expanded_type);

	tls_peap_tlv_header_c tlv(
		m_am_tools,
		final_eap_packet.get_type_data(final_eap_packet.get_type_data_length()),
		final_eap_packet.get_type_data_length());
	if (tlv.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// EAP-Payload TLV:
	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |M|R|         TLV Type          |            Length             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                          EAP packet...
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                             TLVs...
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//
	// We do not support any included TLVs.
	//
	tlv.reset_header(static_cast<u16_t>(tlv_payload_length));
	tlv.set_flag_tlv_type(tls_peap_tlv_eap_payload);
	tlv.set_flag_mandatory_tlv(true);


	{
		// Adds EAP-Packet as a payload to EAP-Payload TLV.
		u16_t * const eap_packet_payload = reinterpret_cast<u16_t *>(
			tlv.get_data_offset(0ul, sent_eap_packet->get_length()));
		if (eap_packet_payload == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_am_tools->memmove(
			eap_packet_payload,
			sent_eap_packet->get_header_buffer(sent_eap_packet->get_length()),
			sent_eap_packet->get_length());
	}

	EAP_TLS_PEAP_TRACE_PAYLOAD("Add TLV payload", &tlv, m_is_client);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::create_crypto_binding_tlv_message(
	eap_buf_chain_wr_c * const packet,
	const eap_code_value_e result_eap_code,
	const u8_t eap_identifier,
	const eap_variable_data_c * const nonce,
	const u8_t received_version)
{
	EAP_UNREFERENCED_PARAMETER(result_eap_code);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::create_crypto_binding_tlv_message()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::create_crypto_binding_tlv_message()");

	if (packet->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	const u32_t result_tlv_payload_length
		= sizeof(u16_t);

	const u32_t result_tlv_length
		= tls_peap_tlv_header_c::get_header_length()
		+ result_tlv_payload_length;

	const u32_t crypto_binding_tlv_payload_length
		= sizeof(u8_t)
		+ sizeof(u8_t)
		+ sizeof(u16_t)
		+ TLV_NONCE_LENGTH
		+ TLV_MAC_LENGTH;

	const u32_t crypto_binding_tlv_length
		= tls_peap_tlv_header_c::get_header_length()
		+ crypto_binding_tlv_payload_length;

	const u32_t intermediate_result_tlv_payload_length
		= sizeof(u16_t);

	const u32_t intermediate_result_tlv_length
		= tls_peap_tlv_header_c::get_header_length()
		+ intermediate_result_tlv_payload_length;

	const u32_t final_packet_length
		= eap_header_wr_c::get_header_length()
		+ sizeof(u8_t) // EAP-type field
		+ result_tlv_length
		+ crypto_binding_tlv_length
		+ intermediate_result_tlv_length;

	eap_status_e status = packet->set_buffer_length(final_packet_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (packet->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = packet->set_data_length(final_packet_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_header_wr_c final_eap_packet(
		m_am_tools,
		packet->get_data(packet->get_data_length()),
		packet->get_data_length());
	if (final_eap_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	final_eap_packet.reset_header(
		static_cast<u16_t>(final_packet_length),
		m_use_eap_expanded_type);
	final_eap_packet.set_identifier(eap_identifier);
	if (m_is_client == true)
	{
		final_eap_packet.set_code(eap_code_response);
	}
	else
	{
		final_eap_packet.set_code(eap_code_request);
	}
	final_eap_packet.set_length(
		static_cast<u16_t>(final_packet_length),
		m_use_eap_expanded_type);
	final_eap_packet.set_type(
		eap_type_tlv_extensions,
		m_use_eap_expanded_type);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t tlv_offset = 0ul;

	{
		// Data includes Result TLV:
		//  0                   1                   2                   3
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |M|R|         TLV Type          |            Length             |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |             Status            |        TLVs...
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//
		// We do not support included TLVs.
		// 

		tls_peap_tlv_header_c result_tlv(
			m_am_tools,
			final_eap_packet.get_type_data_offset(tlv_offset, result_tlv_length),
			final_eap_packet.get_type_data_length());
		if (result_tlv.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		tlv_offset += result_tlv_length;

		result_tlv.reset_header(static_cast<u16_t>(result_tlv_payload_length));
		result_tlv.set_flag_tlv_type(tls_peap_tlv_type_result);
		result_tlv.set_flag_mandatory_tlv(true);
		

		{
			u16_t * const tlv_status = reinterpret_cast<u16_t *>(
				result_tlv.get_data_offset(0ul, sizeof(u16_t)));
			if (tlv_status == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u16_t tlv_status_value = 0ul;
			if (result_eap_code == eap_code_success)
			{
				tlv_status_value = static_cast<u16_t>(tls_peap_tlv_status_success);
			}
			else
			{
				tlv_status_value = static_cast<u16_t>(tls_peap_tlv_status_failure);
			}

			status = eap_write_u16_t_network_order(
				tlv_status,
				sizeof(*tlv_status),
				tlv_status_value);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		EAP_TLS_PEAP_TRACE_PAYLOAD("Add TLV payload", &result_tlv, m_is_client);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		// Data includes Crypto Binding TLV:
		//  0                   1                   2                   3
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |M|R|         TLV Type          |            Length             |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |    Version    |Received Ver.  |         Sub-Type              |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// ~                             Nonce                             ~
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// ~                          Compound MAC                         ~
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// 

		tls_peap_tlv_header_c crypto_binding_tlv(
			m_am_tools,
			final_eap_packet.get_type_data_offset(tlv_offset, crypto_binding_tlv_length),
			final_eap_packet.get_type_data_length());
		if (crypto_binding_tlv.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		tlv_offset += crypto_binding_tlv_length;

		crypto_binding_tlv.reset_header(static_cast<u16_t>(crypto_binding_tlv_payload_length));
		crypto_binding_tlv.set_flag_tlv_type(tls_peap_tlv_type_crypto_binding);
		crypto_binding_tlv.set_flag_mandatory_tlv(true);

		u32_t tlv_data_offset = 0ul;

		{
			u8_t * const tlv_version = reinterpret_cast<u8_t *>(
				crypto_binding_tlv.get_data_offset(tlv_data_offset, sizeof(u8_t)));
			if (tlv_version == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			
			*tlv_version = static_cast<u8_t>(0ul);

			tlv_data_offset += sizeof(u8_t);
		}


		{
			u8_t * const tlv_received_version = reinterpret_cast<u8_t *>(
				crypto_binding_tlv.get_data_offset(tlv_data_offset, sizeof(u8_t)));
			if (tlv_received_version == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			
			*tlv_received_version = static_cast<u8_t>(received_version);

			tlv_data_offset += sizeof(u8_t);
		}


		{
			u16_t * const tlv_sub_type = reinterpret_cast<u16_t *>(
				crypto_binding_tlv.get_data_offset(tlv_data_offset, sizeof(u16_t)));
			if (tlv_sub_type == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u16_t tlv_sub_type_network_order = 0ul;
			if (m_is_client == true)
			{
				tlv_sub_type_network_order = eap_htons(
					static_cast<u16_t>(tls_peap_tlv_type_crypto_binding_request));
			}
			else
			{
				tlv_sub_type_network_order = eap_htons(
					static_cast<u16_t>(tls_peap_tlv_type_crypto_binding_response));
			}
			
			m_am_tools->memmove(
				tlv_sub_type,
				&tlv_sub_type_network_order,
				sizeof(tlv_sub_type_network_order));

			tlv_data_offset += sizeof(u16_t);
		}


		if (nonce->get_data_length() == TLV_NONCE_LENGTH)
		{
			u16_t * const tlv_nonce = reinterpret_cast<u16_t *>(
				crypto_binding_tlv.get_data_offset(tlv_data_offset, TLV_NONCE_LENGTH));
			if (tlv_nonce == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			
			m_am_tools->memmove(tlv_nonce, nonce->get_data(TLV_NONCE_LENGTH), TLV_NONCE_LENGTH);

			tlv_data_offset += TLV_NONCE_LENGTH;
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}


		{
			u8_t * const tlv_mac = reinterpret_cast<u8_t *>(
				crypto_binding_tlv.get_data_offset(tlv_data_offset, TLV_MAC_LENGTH));
			if (tlv_mac == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			
			m_am_tools->memset(tlv_mac, 0, TLV_MAC_LENGTH);

			eap_variable_data_c * mac_key = &m_peap_v2_CMK_B1_server;
			if (m_is_client == true)
			{
				mac_key = &m_peap_v2_CMK_B2_client;
			}

			eap_variable_data_c mac_data(m_am_tools);

			status = create_crypto_binding_compound_mac(
				mac_key,
				&crypto_binding_tlv,
				&mac_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			m_am_tools->memmove(
				tlv_mac,
				mac_data.get_data(mac_data.get_data_length()),
				TLV_MAC_LENGTH);

			tlv_data_offset += TLV_MAC_LENGTH;
		}

		EAP_TLS_PEAP_TRACE_PAYLOAD("Add TLV payload", &crypto_binding_tlv, m_is_client);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		// Data includes Intermediate Result TLV:
		//  0                   1                   2                   3
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |M|R|         TLV Type          |            Length             |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |             Status            |        TLVs...
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// 
		// We do not support included TLVs.
		// 

		tls_peap_tlv_header_c intermediate_result_tlv(
			m_am_tools,
			final_eap_packet.get_type_data_offset(tlv_offset, intermediate_result_tlv_length),
			final_eap_packet.get_type_data_length());
		if (intermediate_result_tlv.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		tlv_offset += intermediate_result_tlv_length;

		intermediate_result_tlv.reset_header(
			static_cast<u16_t>(intermediate_result_tlv_payload_length));
		intermediate_result_tlv.set_flag_tlv_type(tls_peap_tlv_type_intermediate_result);
		intermediate_result_tlv.set_flag_mandatory_tlv(true);
		

		{
			u16_t * const tlv_intermediate_status
				= reinterpret_cast<u16_t *>(
					intermediate_result_tlv.get_data_offset(0ul, sizeof(u16_t)));
			if (tlv_intermediate_status == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u16_t tlv_intermediate_status_value = 0ul;
			if (result_eap_code == eap_code_success)
			{
				tlv_intermediate_status_value = static_cast<u16_t>(tls_peap_tlv_status_success);
			}
			else
			{
				tlv_intermediate_status_value = static_cast<u16_t>(tls_peap_tlv_status_failure);
			}

			status = eap_write_u16_t_network_order(
				tlv_intermediate_status,
				sizeof(*tlv_intermediate_status),
				tlv_intermediate_status_value);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		EAP_TLS_PEAP_TRACE_PAYLOAD("Add TLV payload", &intermediate_result_tlv, m_is_client);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::create_eap_diameter_avp_message(
	eap_buf_chain_wr_c * const packet,
	const eap_header_wr_c * const sent_eap_packet,
	const u8_t /* eap_identifier */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::create_eap_diameter_avp_message()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::create_eap_diameter_avp_message()");

	if (packet->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	const u32_t tlv_payload_length
		= sent_eap_packet->get_length();

	const u32_t final_packet_length
		= eap_diameter_avp_header_c::get_header_length(false)
		+ tlv_payload_length;

	eap_status_e status = packet->set_buffer_length(final_packet_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (packet->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = packet->set_data_length(final_packet_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_diameter_avp_header_c avp(
		m_am_tools,
		packet->get_data(packet->get_data_length()),
		packet->get_data_length());
	if (avp.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// These packets are encapsulated to AVP.
	//  0                   1                   2                   3   
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                           AVP Code                            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |V|M|r r r r r r|                  AVP Length                   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                      Vendor-ID (optional)                     |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                   Data includes EAP-packet ...
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	status = avp.reset_header(static_cast<u16_t>(final_packet_length));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = avp.set_avp_code(eap_diameter_avp_code_eap_message);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = avp.set_avp_flag_mandatory_avp(false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	{
		// Adds EAP-Packet as a payload to AVP.
		u16_t * const eap_packet_payload = reinterpret_cast<u16_t *>(
			avp.get_data_offset(0ul, sent_eap_packet->get_length()));
		if (eap_packet_payload == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_am_tools->memmove(
			eap_packet_payload,
			sent_eap_packet->get_header_buffer(sent_eap_packet->get_length()),
			sent_eap_packet->get_length());
	}

	EAP_TLS_PEAP_TRACE_TTLS_PAYLOAD("Send TTLS AVP payload", &avp, m_is_client);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::create_nonce(
	eap_variable_data_c * const nonce)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::create_nonce(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::create_nonce()");

	eap_status_e status = nonce->set_buffer_length(TLV_NONCE_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	nonce->set_data_length(nonce->get_buffer_length());

	crypto_random_c rand(m_am_tools);
	if (rand.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = rand.get_rand_bytes(
		nonce->get_data(nonce->get_data_length()),
		nonce->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::create_nonce_peap_v2(
	const bool create_client_nonce_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::create_nonce_peap_v2(%s): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 (create_client_nonce_when_true == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::create_nonce_peap_v2()");

	eap_status_e status = eap_status_process_general_error;

	eap_variable_data_c * nonce = 0;

	if (create_client_nonce_when_true == true)
	{
		nonce = &m_peap_v2_client_nonce;
	}
	else
	{
		nonce = &m_peap_v2_server_nonce;
	}

	status = create_nonce(nonce);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::create_compound_mac_key_peap_v2(
	const bool create_client_CMK_when_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::create_compound_mac_key_peap_v2(%s): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 (create_client_CMK_when_true == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::create_compound_mac_key_peap_v2()");

	eap_status_e status = eap_status_process_general_error;

	if (m_peap_v2_IPMKn.get_is_valid_data() == false
		|| m_peap_v2_IPMKn.get_data_length() != TLS_PEAP_V2_TK_LENGTH)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_peap_v2_ISKn.get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_peap_v2_IPMKn"),
		 m_peap_v2_IPMKn.get_data(m_peap_v2_IPMKn.get_data_length()),
		 m_peap_v2_IPMKn.get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("m_peap_v2_ISKn"),
		 m_peap_v2_ISKn.get_data(m_peap_v2_ISKn.get_data_length()),
		 m_peap_v2_ISKn.get_data_length()));

	{
		eap_variable_data_c label(m_am_tools);

		status = label.set_copy_of_buffer(
			TLS_INTERMEDIATE_COMBINED_KEY_LABEL,
			TLS_INTERMEDIATE_COMBINED_KEY_LABEL_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		crypto_tls_sha1_prf_c tls_sha1_prf(m_am_tools);

		status = tls_sha1_prf.tls_prf_init(
			&m_peap_v2_IPMKn,
			&label,
			&m_peap_v2_ISKn);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (tls_sha1_prf.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = tls_sha1_prf.tls_prf_output(
			m_peap_v2_IPMKn.get_data(m_peap_v2_IPMKn.get_data_length()),
			m_peap_v2_IPMKn.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("m_peap_v2_IPMKn"),
			 m_peap_v2_IPMKn.get_data(m_peap_v2_IPMKn.get_data_length()),
			 m_peap_v2_IPMKn.get_data_length()));
	}

	{
		eap_variable_data_c label(m_am_tools);

		if (create_client_CMK_when_true == true)
		{
			status = label.set_copy_of_buffer(
				TLS_INTERMEDIATE_COMPOUND_CLIENT_MAC_KEY_LABEL,
				TLS_INTERMEDIATE_COMPOUND_CLIENT_MAC_KEY_LABEL_LENGTH);
		}
		else
		{
			status = label.set_copy_of_buffer(
				TLS_INTERMEDIATE_COMPOUND_SERVER_MAC_KEY_LABEL,
				TLS_INTERMEDIATE_COMPOUND_SERVER_MAC_KEY_LABEL_LENGTH);
		}

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		crypto_tls_sha1_prf_c tls_sha1_prf(m_am_tools);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("m_peap_v2_server_nonce"),
			 m_peap_v2_server_nonce.get_data(m_peap_v2_server_nonce.get_data_length()),
			 m_peap_v2_server_nonce.get_data_length()));

		if (create_client_CMK_when_true == true)
		{
			eap_variable_data_c client_server_nonce(m_am_tools);

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("m_peap_v2_client_nonce"),
				 m_peap_v2_client_nonce.get_data(m_peap_v2_client_nonce.get_data_length()),
				 m_peap_v2_client_nonce.get_data_length()));

			status = client_server_nonce.set_copy_of_buffer(
				&m_peap_v2_client_nonce);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = client_server_nonce.add_data(
				&m_peap_v2_server_nonce);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = tls_sha1_prf.tls_prf_init(
				&m_peap_v2_IPMKn,
				&label,
				&client_server_nonce);
		}
		else
		{
			status = tls_sha1_prf.tls_prf_init(
				&m_peap_v2_IPMKn,
				&label,
				&m_peap_v2_server_nonce);
		}

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (tls_sha1_prf.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_variable_data_c * cmk = &m_peap_v2_CMK_B1_server;

		if (create_client_CMK_when_true == true)
		{
			cmk = &m_peap_v2_CMK_B2_client;
		}

		status = cmk->set_buffer_length(TLS_PEAP_V2_COMPOUND_MAC_KEY_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		cmk->set_data_length(TLS_PEAP_V2_COMPOUND_MAC_KEY_LENGTH);

		status = tls_sha1_prf.tls_prf_output(
			cmk->get_data(cmk->get_data_length()),
			cmk->get_data_length());

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLV MAC key CMK"),
			 cmk->get_data(cmk->get_data_length()),
			 cmk->get_data_length()));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::create_compound_session_key_peap_v2()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::create_compound_session_key_peap_v2(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::create_compound_session_key_peap_v2()");

	eap_status_e status = eap_status_process_general_error;

	if (m_peap_v2_IPMKn.get_is_valid_data() == false
		|| m_peap_v2_IPMKn.get_data_length() != TLS_PEAP_V2_TK_LENGTH)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	{
		eap_variable_data_c label(m_am_tools);

		status = label.set_copy_of_buffer(
			TLS_INTERMEDIATE_COMPOUND_SESSION_KEY_LABEL,
			TLS_INTERMEDIATE_COMPOUND_SESSION_KEY_LABEL_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		crypto_tls_sha1_prf_c tls_sha1_prf(m_am_tools);

		eap_variable_data_c client_server_nonce_outputlength(m_am_tools);

		status = client_server_nonce_outputlength.set_copy_of_buffer(
			&m_peap_v2_client_nonce);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = client_server_nonce_outputlength.add_data(
			&m_peap_v2_server_nonce);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		/* @{ What is the sizeof the OutputLength? } */
		
		u8_t OutputLength = TLS_PEAP_V2_COMPOUND_SESSION_KEY_LENGTH;

		status = client_server_nonce_outputlength.add_data(
			&OutputLength,
			sizeof(OutputLength));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = tls_sha1_prf.tls_prf_init(
			&m_peap_v2_IPMKn,
			&label,
			&client_server_nonce_outputlength);

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (tls_sha1_prf.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = m_peap_v2_CSK.set_buffer_length(TLS_PEAP_V2_COMPOUND_SESSION_KEY_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		m_peap_v2_CSK.set_data_length(TLS_PEAP_V2_COMPOUND_SESSION_KEY_LENGTH);

		status = tls_sha1_prf.tls_prf_output(
			m_peap_v2_CSK.get_data(m_peap_v2_CSK.get_data_length()),
			m_peap_v2_CSK.get_data_length());

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

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::create_crypto_binding_compound_mac(
	const eap_variable_data_c * const peap_v2_CMK,
	const tls_peap_tlv_header_c * const crypto_binding_tlv,
	eap_variable_data_c * const mac_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::create_crypto_binding_compound_mac(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::create_crypto_binding_compound_mac()");

	EAP_TLS_PEAP_TRACE_PAYLOAD("Create TLV MAC", crypto_binding_tlv, m_is_client);

	crypto_sha1_c sha1(m_am_tools);
	crypto_hmac_c hmac(m_am_tools, &sha1, false);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLV MAC key CMK"),
		 peap_v2_CMK->get_data(peap_v2_CMK->get_data_length()),
		 peap_v2_CMK->get_data_length()));

	status = hmac.hmac_set_key(peap_v2_CMK);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (hmac.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLV MAC data"),
		crypto_binding_tlv->get_header_buffer(
			crypto_binding_tlv->get_header_length()
			+ crypto_binding_tlv->get_data_length()),
		crypto_binding_tlv->get_header_length()
		+ crypto_binding_tlv->get_data_length()));

	status = hmac.hmac_update(
		crypto_binding_tlv->get_header_buffer(
			crypto_binding_tlv->get_header_length()
			+ crypto_binding_tlv->get_data_length()),
		crypto_binding_tlv->get_header_length()
		+ crypto_binding_tlv->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = mac_data->set_buffer_length(hmac.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	mac_data->set_data_length(hmac.get_digest_length());
		
	u32_t mac_length = hmac.get_digest_length();

	status = hmac.hmac_final(
		mac_data->get_data(mac_data->get_data_length()),
		&mac_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (mac_length != hmac.get_digest_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAPv2 Compound MAC"),
		 mac_data->get_data(mac_data->get_data_length()),
		 mac_data->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::packet_send(
	const eap_am_network_id_c * const /*network_id*/,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::packet_send(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::packet_send()");

	eap_buf_chain_wr_c * forwarded_packet = sent_packet;
	u32_t forwarded_data_length = data_length;
	u32_t forwarded_buffer_length = buffer_length;
	u32_t forwaded_header_offset = header_offset;

	eap_status_e status = eap_status_process_general_error;

	eap_buf_chain_wr_c tmp_packet(
		eap_write_buffer,
		m_am_tools);
	if (tmp_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	const u32_t eap_packet_length = sent_packet->get_data_length();

	eap_header_wr_c sent_eap_packet(
		m_am_tools,
		sent_packet->get_data(eap_packet_length),
		eap_packet_length);
	if (sent_eap_packet.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	if (m_is_client == true)
	{
		trace_tunneled_packet(EAPL("<- TUNNELED packet client"), &sent_eap_packet);
	}
	else
	{
		trace_tunneled_packet(EAPL("<- TUNNELED packet server"), &sent_eap_packet);
	}


	if (m_eap_type == eap_type_peap)
	{
		if (m_peap_version == peap_version_0_xp)
		{
			// XP PEAP does not include EAP-header (code, identifier and length).
			// Here we must remove those attributes.
			// See draft-kamath-pppext-peapv0-00.txt.

			if (sent_eap_packet.get_code() == eap_code_request
				|| sent_eap_packet.get_code() == eap_code_response)
			{
				forwaded_header_offset += eap_header_base_c::get_header_length();
			}
			else if (sent_eap_packet.get_code() == eap_code_success
				|| sent_eap_packet.get_code() == eap_code_failure)
			{
				if (m_is_client == true)
				{
					// Client does not send these packets.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
				}

				// XP PEAPv0 does not include EAP-header (code, identifier and length).
				// Here we must create those attributes.
				// Exception to this rule is, EAP-success and EAP-failure are sent in "Extensions Request Packet"
				// or "Extensions Response Packet".
				// The whole EAP-header is included
				// to "Extensions Request Packet" and "Extensions Response Packet".
				// See draft-kamath-pppext-peapv0-00.txt.
				// 
				// EAP-packet without code, identifier and length:
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// |  EAP-type     |  EAP-data ...                                                                  
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// EAP-packet with "Extensions Request Packet" or "Extensions Response Packet":
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// |  EAP-code     |EAP-identifier | EAP-length                    | EAP-type      |  EAP-data ...  
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// 
				// EAP-code of "Extensions Request Packet" is 1 which is same as EAP-type of EAP-identity.
				// EAP-code of "Extensions Response Packet" is 2 which is same as EAP-type of EAP-notification.

				u8_t send_eap_identifier = sent_eap_packet.get_identifier();
				if (m_is_client == false)
				{
					++send_eap_identifier;
				}

				status = create_result_tlv_message(
					&tmp_packet,
					sent_eap_packet.get_code(),
					send_eap_identifier,
					tls_peap_tlv_type_result);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				forwarded_packet = &tmp_packet;

				forwarded_data_length = tmp_packet.get_data_length();
				forwarded_buffer_length = tmp_packet.get_buffer_length();
				forwaded_header_offset = 0;

				eap_header_string_c eap_string;
				EAP_UNREFERENCED_PARAMETER(eap_string);

				EAP_TRACE_ALWAYS(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("packet_send(): XP-PEAPv0 tunneled %s send.\n"),
					 eap_string.get_eap_code_string(sent_eap_packet.get_code())));
			}
		}
		else if (m_peap_version == peap_version_1)
		{
			// This version does not change packet.

#if defined(USE_EAP_PEAPV1_EXTENSIONS)
			if (m_is_client == false
				&& m_server_use_peapv1_extensions_request == true
				&& (sent_eap_packet.get_code() == eap_code_success
					|| sent_eap_packet.get_code() == eap_code_failure))
			{
				u8_t send_eap_identifier = sent_eap_packet.get_identifier();
				if (m_is_client == false)
				{
					++send_eap_identifier;
				}

				status = create_result_tlv_message(
					&tmp_packet,
					sent_eap_packet.get_code(),
					send_eap_identifier,
					tls_peap_tlv_type_result);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				forwarded_packet = &tmp_packet;

				forwarded_data_length = tmp_packet.get_data_length();
				forwarded_buffer_length = tmp_packet.get_buffer_length();
				forwaded_header_offset = 0;

				eap_header_string_c eap_string;
				EAP_UNREFERENCED_PARAMETER(eap_string);

				EAP_TRACE_ALWAYS(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("packet_send(): PEAPv1 tunneled %s send.\n"),
					 eap_string.get_eap_code_string(sent_eap_packet.get_code())));
			}
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)

		}
		else if (m_peap_version == peap_version_2)
		{
			if (sent_eap_packet.get_code() == eap_code_request
				|| sent_eap_packet.get_code() == eap_code_response)
			{
				// These packets are encapsulated to EAP-TLV packet.
				//  0                   1                   2                   3
				//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// |     Code      |   Identifier  |            Length             |
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// |     Type      |                  Data....
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// 
				// Data includes EAP-Payload TLV:
				//  0                   1                   2                   3
				//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// |M|R|         TLV Type          |            Length             |
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// |                          EAP packet...
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// |                             TLVs...
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

				status = create_eap_payload_tlv_message(
					&tmp_packet,
					&sent_eap_packet,
					sent_eap_packet.get_identifier());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				forwarded_packet = &tmp_packet;

				forwarded_data_length = tmp_packet.get_data_length();
				forwarded_buffer_length = tmp_packet.get_buffer_length();
				forwaded_header_offset = 0;
			}
			else if (sent_eap_packet.get_code() == eap_code_success
				|| sent_eap_packet.get_code() == eap_code_failure)
			{
				if (m_is_client == true)
				{
					// Client does not send these packets.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
				}

				// Server blocks the EAP-Success packet.
				// Result TLV, Crypto Binding TLV and Intermediate Result TLV
				// are created and sent within the state_notification() function
				// by the send_tunneled_acknowledge_peap_v2() function
				// when eap_state_authentication_finished_successfully or
				// eap_state_authentication_terminated_unsuccessfully indication
				// is received.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: %s: message_function: tls_application_eap_core_c::")
					 EAPL("packet_send(), server blocks tunneled EAP-Success and EAP-Failure\n"),
					(m_is_client == true ? "client": "server")));

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);

			}
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
		}
	}
	else if (m_eap_type == eap_type_ttls)
	{

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		if (m_tunneled_eap_in_ttls == true)
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		{
			// These packets are encapsulated to AVP.
			//  0                   1                   2                   3   
			//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |                           AVP Code                            |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |V|M|r r r r r r|                  AVP Length                   |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |                      Vendor-ID (optional)                     |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |                   Data includes EAP-packet ...
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

			if (sent_eap_packet.get_code() == eap_code_success
				|| sent_eap_packet.get_code() == eap_code_failure)
			{
				if (m_is_client == true)
				{
					// Client does not send these packets.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
				}

				// Server blocks the tunneled EAP-Success packet.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("TLS: %s: message_function: tls_application_eap_core_c::")
					 EAPL("packet_send(), server blocks tunneled EAP-Success and EAP-Failure\n"),
					(m_is_client == true ? "client": "server")));

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);

			}
			else
			{
				status = create_eap_diameter_avp_message(
					&tmp_packet,
					&sent_eap_packet,
					sent_eap_packet.get_identifier());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				
				forwarded_packet = &tmp_packet;
				
				forwarded_data_length = tmp_packet.get_data_length();
				forwarded_buffer_length = tmp_packet.get_buffer_length();
				forwaded_header_offset = 0;
			}
		}
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		else
		{
			// This is plain MsChapv2 tunneled in EAP-TTLS.
			status = send_ttls_ms_chapv2_packet(&sent_eap_packet);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
	}


	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("sent tunneled data:"),
		 forwarded_packet->get_data_offset(
			 forwaded_header_offset,
			 forwarded_packet->get_data_length()-forwaded_header_offset),
		 forwarded_packet->get_data_length()-forwaded_header_offset));


#if defined(USE_EAP_ERROR_TESTS)
	if (m_enable_random_errors == true
		&& m_manipulate_only_tunneled_messages == true)
	{
		status = m_am_tools->generate_random_error(
			forwarded_packet,
			false,
			m_am_tools->get_packet_index(),
			0UL,
			m_error_probability,
			0UL);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#endif //#if defined(USE_EAP_ERROR_TESTS)


	status = get_application_partner()->packet_send(
		forwarded_packet,
		forwaded_header_offset,
		forwarded_data_length,
		forwarded_buffer_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::send_tunneled_acknowledge_xp_peap_v0(
	const eap_code_value_e result_eap_code,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::send_tunneled_acknowledge_xp_peap_v0(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::send_tunneled_acknowledge_xp_peap_v0()");

	eap_buf_chain_wr_c eap_ack_packet(
		eap_write_buffer, 
		m_am_tools);

	if (eap_ack_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("tls_application_eap_core_c::send_tunneled_acknowledge_xp_peap_v0(): ")
			 EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = create_result_tlv_message(
		&eap_ack_packet,
		result_eap_code,
		eap_identifier,
		tls_peap_tlv_type_result);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_header_string_c eap_string;
	EAP_UNREFERENCED_PARAMETER(eap_string);

	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send_tunneled_acknowledge_xp_peap_v0(): XP-PEAPv0 tunneled %s acknowledge send.\n"),
		 eap_string.get_eap_code_string(result_eap_code)));

	EAP_TRACE_DATA_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("    send: XP-PEAPv0 EAP acknowledge packet"),
		eap_ack_packet.get_data(eap_ack_packet.get_data_length()),
		eap_ack_packet.get_data_length()));


#if defined(USE_EAP_ERROR_TESTS)
	if (m_enable_random_errors == true
		&& m_manipulate_only_tunneled_messages == true)
	{
		status = m_am_tools->generate_random_error(
			&eap_ack_packet,
			false,
			m_am_tools->get_packet_index(),
			0UL,
			m_error_probability,
			0UL);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#endif //#if defined(USE_EAP_ERROR_TESTS)

	status = get_application_partner()->packet_send(
		&eap_ack_packet,
		0ul,
		eap_ack_packet.get_data_length(),
		EAP_CORE_PACKET_BUFFER_LENGTH
		);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::send_tunneled_acknowledge_peap_v2(
	const eap_code_value_e result_eap_code,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::send_tunneled_acknowledge_peap_v2()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::send_tunneled_acknowledge_peap_v2()");

	eap_variable_data_c *peap_v2_nonce = &m_peap_v2_client_nonce;
	if (m_is_client == false)
	{
		peap_v2_nonce = &m_peap_v2_server_nonce;
	}

	if (peap_v2_nonce->get_is_valid_data() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("tls_application_eap_core_c::send_tunneled_acknowledge_peap_v2(): ")
			 EAPL("peap_v2_nonce invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_buf_chain_wr_c eap_ack_packet(
		eap_write_buffer, 
		m_am_tools);

	if (eap_ack_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("tls_application_eap_core_c::send_tunneled_acknowledge_peap_v2(): ")
			 EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = create_crypto_binding_tlv_message(
		&eap_ack_packet,
		result_eap_code,
		eap_identifier,
		peap_v2_nonce,
		static_cast<u8_t>(m_peap_version));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_header_string_c eap_string;
	EAP_UNREFERENCED_PARAMETER(eap_string);

	EAP_TRACE_ALWAYS(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send_tunneled_acknowledge_peap_v2(): PEAPv2 tunneled %s acknowledge send.\n"),
		 eap_string.get_eap_code_string(result_eap_code)));

	EAP_TRACE_DATA_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("    send: PEAPv2 EAP acknowledge packet"),
		eap_ack_packet.get_data(eap_ack_packet.get_data_length()),
		eap_ack_packet.get_data_length()));

#if defined(USE_EAP_ERROR_TESTS)
	if (m_enable_random_errors == true
		&& m_manipulate_only_tunneled_messages == true)
	{
		status = m_am_tools->generate_random_error(
			&eap_ack_packet,
			false,
			m_am_tools->get_packet_index(),
			0UL,
			m_error_probability,
			0UL);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#endif //#if defined(USE_EAP_ERROR_TESTS)

	status = get_application_partner()->packet_send(
		&eap_ack_packet,
		0ul,
		eap_ack_packet.get_data_length(),
		EAP_CORE_PACKET_BUFFER_LENGTH
		);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t tls_application_eap_core_c::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	u32_t offset = get_application_partner()->get_header_offset(
		MTU,
		trailer_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return offset;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::load_module(
	const eap_type_value_e type,
	const eap_type_value_e tunneling_type,
	abs_eap_base_type_c * const partner,
	eap_base_type_c ** const eap_type,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (tunneling_type != eap_type_none)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("TLS: %s: message_function: tls_application_eap_core_c::load_module(), ")
			 EAPL("tunneling_type is not eap_type_none, it is 0x%08x=%s\n"),
			(m_is_client == true ? "client": "server"),
			convert_eap_type_to_u32_t(tunneling_type),
			eap_header_string_c::get_eap_type_string(tunneling_type)));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_status_e status = get_application_partner()->load_module(
		type,
		m_eap_type, // This is the tunneling EAP-type.
		partner,
		eap_type,
		is_client_when_true,
		receive_network_id);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::unload_module(
	const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_application_partner()->unload_module(
		type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::peap_tunnel_ready()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::peap_tunnel_ready()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::peap_tunnel_ready()");

	eap_status_e status = eap_status_ok;

	if (m_peap_version == peap_version_2)
	{
		eap_variable_data_c eap_tls_master_session_key(m_am_tools);

		status = get_application_partner()->get_eap_tls_master_session_key(
			&eap_tls_master_session_key,
			0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (eap_tls_master_session_key.get_data_length()
			< TLS_PEAP_V2_TK_OFFSET + TLS_PEAP_V2_TK_LENGTH)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_encryption_parameter_size);
		}

		status = m_peap_v2_IPMKn.set_copy_of_buffer(
			eap_tls_master_session_key.get_data_offset(
				TLS_PEAP_V2_TK_OFFSET, TLS_PEAP_V2_TK_LENGTH),
			TLS_PEAP_V2_TK_LENGTH);
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

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::start_peap_tunneled_authentication(
	const eap_am_network_id_c * const receive_network_id,
	const bool is_client_when_true,
	const u8_t received_eap_identifier,
	const tls_session_type_e tls_session_type,
	const bool /* tls_peap_server_authenticates_client_action */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::start_peap_tunneled_authentication(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::start_peap_tunneled_authentication()");

	eap_status_e status = eap_status_process_general_error;


#if defined(USE_EAP_CORE_SERVER)

	if (m_is_client == false)
	{
		// Server

		if (m_eap_type == eap_type_peap
			&& (tls_session_type == tls_session_type_original_session_resumption
				|| tls_session_type == tls_session_type_stateless_session_resumption)
			&& m_peap_allow_tunneled_session_resumption == true
#if !defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
			&& m_peap_version == peap_version_0_xp
#endif //#if !defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
			)
		{
			if (m_peap_version == peap_version_0_xp)
			{
				if (is_client_when_true == false)
				{
					// Server sends tunneled EAP-Success.

					eap_buf_chain_wr_c forwarded_packet(
						eap_write_buffer,
						m_am_tools);
					if (forwarded_packet.get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					status = create_result_tlv_message(
						&forwarded_packet,
						eap_code_success,
						static_cast<u8_t>(received_eap_identifier+1ul),
						tls_peap_tlv_type_result);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					u32_t forwarded_data_length = forwarded_packet.get_data_length();
					u32_t forwarded_buffer_length = forwarded_packet.get_buffer_length();
					u32_t forwaded_header_offset = 0;

					eap_header_string_c eap_string;
					EAP_UNREFERENCED_PARAMETER(eap_string);

					EAP_TRACE_ALWAYS(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("packet_send(): XP-PEAPv0 tunneled %s send.\n"),
						 eap_string.get_eap_code_string(eap_code_success)));

#if defined(USE_EAP_ERROR_TESTS)
					if (m_enable_random_errors == true
						&& m_manipulate_only_tunneled_messages == true)
					{
						status = m_am_tools->generate_random_error(
							&forwarded_packet,
							false,
							m_am_tools->get_packet_index(),
							0UL,
							m_error_probability,
							0UL);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
#endif //#if defined(USE_EAP_ERROR_TESTS)


					status = get_application_partner()->packet_send(
						&forwarded_packet,
						forwaded_header_offset,
						forwarded_data_length,
						forwarded_buffer_length);
#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)
				}
			}
			else if (m_peap_version == peap_version_1)
			{

#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)

				// Send tunneled EAP-Success.
				// This will tell client the tunneled
				// EAP-session was also restored.

				// Here we swap the addresses.
				eap_am_network_id_c send_network_id(
					m_am_tools,
					receive_network_id->get_destination_id(),
					receive_network_id->get_source_id(),
					receive_network_id->get_type());

				if (m_use_tppd_tls_peap == true
					&& m_use_tppd_peapv1_acknowledge_hack == true)
				{
					// This case does not send tunneled EAP-Success
					// instead it sends plain EAP-Success.

					m_tunneled_eap_type_authentication_state
						= eap_state_authentication_wait_tppd_peapv1_empty_acknowledge;

					eap_state_notification_c notification(
						m_am_tools,
						&send_network_id,
						m_is_client,
						eap_state_notification_eap,
						eap_protocol_layer_eap,
						m_eap_type,
						eap_state_none,
						m_tunneled_eap_type_authentication_state,
						received_eap_identifier,
						true);
					get_application_partner()->state_notification(&notification);

					status = eap_status_ok;
				}
				else
				{
					if (m_eap_core == 0)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
					}

					status = m_eap_core->send_eap_success(
						&send_network_id,
						received_eap_identifier);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					m_tunneled_eap_type_authentication_state
						= eap_state_authentication_finished_successfully;

					eap_state_notification_c notification(
						m_am_tools,
						&send_network_id,
						m_is_client,
						eap_state_notification_eap,
						eap_protocol_layer_eap,
						m_peap_tunneled_eap_type,
						eap_state_none,
						m_tunneled_eap_type_authentication_state,
						received_eap_identifier,
						false);
					get_application_partner()->state_notification(&notification);

					status = eap_status_success;
				}

#else

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);

#endif //#if defined(USE_EAP_TLS_PEAP_TPPD_PEAP_V1_NEW_FIXES)

			}
			else if (m_peap_version == peap_version_2)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
			}
		}
		else
		{
			if (m_eap_core == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
			}

			status = m_eap_core->send_eap_identity_request(
				receive_network_id);
		}
	}
	else
#endif //#if defined(USE_EAP_CORE_SERVER)
	{
		// Client

		status = eap_status_ok;
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::restart_authentication(
	const eap_am_network_id_c * const /*receive_network_id*/,
	const bool /*is_client_when_true*/,
	const bool /*force_clean_restart*/,
	const bool /*from_timer*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// NOTE, we do not allow tunneled EAP-type restart authentication.
	eap_status_e status = eap_status_ok;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::packet_data_crypto_keys(
	const eap_am_network_id_c * const /*send_network_id*/,
	const eap_master_session_key_c * const master_session_key
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TLS: %s: message_function: tls_application_eap_core_c::packet_data_crypto_keys()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::packet_data_crypto_keys()");

	eap_status_e status = eap_status_process_general_error;

	if (m_peap_version == peap_version_2)
	{
		status = m_peap_v2_ISKn.set_copy_of_buffer(
			master_session_key);
	}
	else
	{
		// Note older PEAP version does not use keys generated by tunneled EAP-type.
		// This is sad but true.
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	if (field == 0
		|| data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (cf_str_EAP_default_type_hex_data.get_field()->compare(
			m_am_tools,
			field) == true
		|| cf_str_EAP_server_default_type_hex_data.get_field()->compare(
			m_am_tools,
			field) == true)
	{
		eap_type_value_e tunneled_type = m_peap_tunneled_eap_type;

#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
		if (m_tunneled_eap_in_ttls == false
			&& m_peap_tunneled_eap_type == eap_expanded_type_ttls_plain_mschapv2.get_type())
		{
			tunneled_type = eap_type_mschapv2;
		}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)

		if (field->get_type() == eap_configure_type_u32_t)
		{
			u32_t tunneled_eap_type = convert_eap_type_to_u32_t(tunneled_type);
			status = data->set_copy_of_buffer(&tunneled_eap_type, sizeof(tunneled_eap_type));
		}
		else if (field->get_type() == eap_configure_type_hex_data)
		{
			eap_expanded_type_c default_type(tunneled_type);
			status = default_type.get_expanded_type_data(m_am_tools, data);
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_type);
		}

	}
	else if (cf_str_EAP_CORE_retransmission_counter.get_field()->compare(
				 m_am_tools,
				 field) == true)
	{
		// We do not allow inner EAP Core to re-transmit packets.
		u32_t retransmission_counter = 0ul;
		status = data->set_copy_of_buffer(&retransmission_counter, sizeof(retransmission_counter));
	}
	else if (cf_str_EAP_CORE_process_EAP_Nak_immediately.get_field()->compare(
				 m_am_tools,
				 field) == true)
	{
		// We do not allow inner EAP Core to delay EAP-Nak processing.
		u32_t EAP_CORE_process_EAP_Nak_immediately = 1ul; // This is true value.
		status = data->set_copy_of_buffer(
			&EAP_CORE_process_EAP_Nak_immediately,
			sizeof(EAP_CORE_process_EAP_Nak_immediately));
	}
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	else if (m_tunneled_eap_in_ttls == false
		&& cf_str_EAP_MSCHAPV2_use_implicit_challenge.get_field()->compare(
				 m_am_tools,
				 field) == true)
	{
		u32_t use_implicit_challenge = 1ul;
		status = data->set_copy_of_buffer(&use_implicit_challenge, sizeof(use_implicit_challenge));
	}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
	else if (m_is_client == false
		&& m_eap_type == eap_type_peap
		&& m_peap_version == peap_version_0_xp
		&& cf_str_EAP_TLS_PEAP_check_identifier_of_eap_identity_response.get_field()->compare(
				 m_am_tools,
				 field) == true)
	{
		// Tunneled type on PEAPv0 server cannot check EAP-Identity exactly.
		u32_t check_identifier_of_eap_identity_response = 0ul;
		status = data->set_copy_of_buffer(&check_identifier_of_eap_identity_response, sizeof(check_identifier_of_eap_identity_response));
	}
	else
	{
		status = get_application_partner()->read_configure(
			field,
			data);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::write_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_application_partner()->write_configure(
		field,
		data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_application_eap_core_c::set_tunneled_state(
	const tls_session_type_e tls_session_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::set_tunneled_state(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::set_tunneled_state()");

	m_tls_session_type = tls_session_type;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void tls_application_eap_core_c::state_notification(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::state_notification(): notification state=%s")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 eap_state_notification_c::get_state_string(state->get_protocol_layer(), state->get_current_state()),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::state_notification()");


	const abs_eap_state_notification_c * notification = state;
	eap_automatic_variable_c<const abs_eap_state_notification_c> automatic_notification(m_am_tools, 0);

	if (state->get_protocol_layer() == eap_protocol_layer_eap)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::state_notification(): eap_protocol_layer_eap: state = %s")
			 EAPL("this = 0x%08x\n"),
			 (m_is_client == true ? "client": "server"),
			 eap_state_notification_c::get_state_string(state->get_protocol_layer(), state->get_current_state()),
			 this));

		if (state->get_current_state() == eap_state_authentication_terminated_unsuccessfully)
		{
			// Tunneled EAP-type terminated unsuccessfully.
			m_tunneled_eap_type_authentication_state = static_cast<eap_state_variable_e>(
				state->get_current_state());
			if (m_is_client == true
				&& m_eap_type == eap_type_peap)
			{
				if (m_peap_version == peap_version_0_xp)
				{
					// Send tunneled EAP-Success acknowledge.
					eap_status_e status = send_tunneled_acknowledge_xp_peap_v0(
						eap_code_failure,
						state->get_eap_identifier());
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
					}
					// XP-PEAPv0 Authentication FAILED.
				}
#if defined(USE_EAP_PEAPV1_EXTENSIONS)
				else if (m_peap_version == peap_version_1
					&& m_client_send_peapv1_extensions_response == true)
				{
					// Send tunneled EAP-Success acknowledge.
					eap_status_e status = send_tunneled_acknowledge_xp_peap_v0(
						eap_code_failure,
						state->get_eap_identifier());
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
					}
					// PEAPv1 Authentication FAILED.

					notification = new eap_state_notification_c(
						m_am_tools,
						state->get_send_network_id(),
						state->get_is_client(),
						eap_state_notification_eap,
						state->get_protocol_layer(),
						state->get_eap_type(),
						state->get_previous_state(),
						eap_state_authentication_terminated_unsuccessfully_peapv1_extension,
						state->get_eap_identifier(),
						state->get_allow_send_eap_success());

					automatic_notification.set_variable(notification);

					if (notification == 0)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
						return;
					}
				}
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)
				else if (m_peap_version == peap_version_2)
				{
					// Send tunneled EAP-Success acknowledge.
					eap_status_e status = send_tunneled_acknowledge_peap_v2(
						eap_code_failure,
						state->get_eap_identifier());
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
					}
					// PEAPv2 Authentication FAILED.
				}
			}
			else if (m_eap_type == eap_type_peap)
			{
				// Server
				if (m_peap_version == peap_version_0_xp)
				{
					// Does nothing special.
					// Server waits the EAP Response of Type=Extensions
					// acknowled packet from client.
					return;
				}
				else if (m_peap_version == peap_version_2)
				{
					// Does nothing special.
					// Server waits the EAP Response of Type=Extensions
					// acknowled packet from client.
					return;
				}
			}
		}
		else if (state->get_current_state() == eap_state_authentication_finished_successfully)
		{
			// Tunneled EAP-type finished successfully.
			m_tunneled_eap_type_authentication_state = static_cast<eap_state_variable_e>(
				state->get_current_state());

			if (m_is_client == true
				&& m_eap_type == eap_type_peap)
			{
				if (m_peap_version == peap_version_0_xp)
				{
					// Send tunneled EAP-Success acknowledge.
					eap_status_e status = send_tunneled_acknowledge_xp_peap_v0(
						eap_code_success,
						state->get_eap_identifier());
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
					}

					// XP-PEAPv0 Authentication OK.
				}
#if defined(USE_EAP_PEAPV1_EXTENSIONS)
				else if (m_peap_version == peap_version_1
					&& m_client_send_peapv1_extensions_response == true)
				{
					// Send tunneled EAP-Success acknowledge.
					eap_status_e status = send_tunneled_acknowledge_xp_peap_v0(
						eap_code_success,
						state->get_eap_identifier());
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
					}
					// PEAPv1 Authentication OK.

					notification = new eap_state_notification_c(
						m_am_tools,
						state->get_send_network_id(),
						state->get_is_client(),
						eap_state_notification_eap,
						state->get_protocol_layer(),
						state->get_eap_type(),
						state->get_previous_state(),
						eap_state_authentication_finished_successfully_peapv1_extension,
						state->get_eap_identifier(),
						state->get_allow_send_eap_success());

					automatic_notification.set_variable(notification);

					if (notification == 0)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
						return;
					}
				}
#endif //#if defined(USE_EAP_PEAPV1_EXTENSIONS)
				else if (m_peap_version == peap_version_2)
				{
					// Send tunneled EAP-Success acknowledge.

					eap_status_e status = create_nonce_peap_v2(m_is_client);
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return;
					}

					// Intermediate Combined Key is stored to m_peap_v2_IPMKn.
					// Compound MAC Key is stored to m_peap_v2_CMK_Bn.
					status = create_compound_mac_key_peap_v2(false);
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return;
					}

					status = create_compound_mac_key_peap_v2(true);
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return;
					}

					// First we must verify the received TLVs and B1 MAC.
					status = verify_tunneled_acknowledge_peap_v2();
					if (status != eap_status_success)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return;
					}

					status = send_tunneled_acknowledge_peap_v2(
						eap_code_success,
						state->get_eap_identifier());
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return;
					}

					status = finish_successfull_authentication_peap_v2(
						m_received_eap_identifier);
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_terminated_unsuccessfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return;
					}

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return;

					// PEAPv2 Authentication OK.
				}
			}
			else if (m_eap_type == eap_type_peap)
			{
				// Server
				if (m_peap_version == peap_version_0_xp)
				{
					// Does nothing special.
					// Server waits the EAP Response of Type=Extensions acknowled packet from client.
					return;
				}
				else if (m_peap_version == peap_version_2)
				{
					eap_status_e status = create_nonce_peap_v2(m_is_client);
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_finished_successfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return;
					}

					// Intermediate Combined Key is stored to m_peap_v2_IPMKn.
					// Compound MAC Key is stored to m_peap_v2_CMK_Bn.
					status = create_compound_mac_key_peap_v2(m_is_client);
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_finished_successfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return;
					}

					status = send_tunneled_acknowledge_peap_v2(
						eap_code_success,
						state->get_eap_identifier());
					if (status != eap_status_ok)
					{
						m_tunneled_eap_type_authentication_state
							= eap_state_authentication_finished_successfully;
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return;
					}

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return;
				}
			}
			else if (m_eap_type == eap_type_ttls)
			{
#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
				if (m_tunneled_eap_in_ttls == true)
				{
					// TTLS with tunneled EAP.
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::state_notification(): notification state=%s")
						 EAPL("this = 0x%08x, TTLS with tunneled EAP.\n"),
						 (m_is_client == true ? "client": "server"),
						 eap_state_notification_c::get_state_string(state->get_protocol_layer(), state->get_current_state()),
						 this));
				}
				else if (m_tunneled_eap_in_ttls == false)
				{
					// TTLS with plain MsChapv2.
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::state_notification(): notification state=%s")
						 EAPL("this = 0x%08x, TTLS with plain MsChapv2.\n"),
						 (m_is_client == true ? "client": "server"),
						 eap_state_notification_c::get_state_string(state->get_protocol_layer(), state->get_current_state()),
						 this));
				}
#endif //#if defined(EAP_USE_TTLS_PLAIN_MS_CHAP_V2_HACK)
			}
		}
	}

	get_application_partner()->state_notification(notification);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::asynchronous_init_remove_eap_session(
	const eap_am_network_id_c * const /* send_network_id */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Here we do not want to remove the session yet. It is removed after PEAP session finishes.
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::set_timer(
	abs_eap_base_timer_c * const initializer, 
	const u32_t id, 
	void * const data,
	const u32_t p_time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_application_partner()->set_timer(
		initializer, 
		id, 
		data,
		p_time_ms);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::cancel_timer(
	abs_eap_base_timer_c * const initializer, 
	const u32_t id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_process_general_error;
	abs_tls_base_application_c * partner = get_application_partner();
	if (partner != 0)
	{
		status = partner->cancel_timer(
			initializer, 
			id);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::check_is_valid_eap_type(
	const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("tls_application_eap_core_c::check_is_valid_eap_type(): EAP-type=0xfe%06x%08x=%s\n"),
		eap_type.get_vendor_id(),
		eap_type.get_vendor_type(),
		eap_header_string_c::get_eap_type_string(eap_type)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::check_is_valid_eap_type()");

	if (m_accepted_tunneled_eap_types.get_object_count() > 0ul)
	{
		bool allow_this_eap_type = false;

		eap_type_value_e * type = 0;

		for (u32_t ind = 0ul; ind < m_accepted_tunneled_eap_types.get_object_count(); ind++)
		{
			type = m_accepted_tunneled_eap_types.get_object(ind);

			if (type != 0)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("%s: tls_application_eap_core_c::check_is_valid_eap_type(): allowed EAP-type %d.\n"),
					 (m_is_client == true ? "client": "server"),
					 convert_eap_type_to_u32_t(*type)));
			}

			if (type != 0
				&& eap_type == *type)
			{
				allow_this_eap_type = true;
				break;
			}
		} // for()

		if (allow_this_eap_type == false)
		{
			// Not allowed EAP-type inside PEAP.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: tls_application_eap_core_c::check_is_valid_eap_type(): No allowed EAP-type=0xfe%06x%08x=%s\n"),
				eap_type.get_vendor_id(),
				eap_type.get_vendor_type(),
				eap_header_string_c::get_eap_type_string(eap_type)));

			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_type);
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_type);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::get_eap_type_list(
	eap_array_c<eap_type_value_e> * const eap_type_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::get_eap_type_list(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::get_eap_type_list()");

	for (u32_t ind = 0ul; ind < m_accepted_tunneled_eap_types.get_object_count(); ind++)
	{
		const eap_type_value_e * const type = m_accepted_tunneled_eap_types.get_object(ind);

		if (type != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("%s: tls_application_eap_core_c::get_eap_type_list(): allowed EAP-type %d.\n"),
				 (m_is_client == true ? "client": "server"),
				 convert_eap_type_to_u32_t(*type)));
		}
	}

	eap_status_e status = copy_simple<eap_type_value_e>(
		&m_accepted_tunneled_eap_types,
		eap_type_list,
		m_am_tools,
		false);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT abs_tls_base_application_c * tls_application_eap_core_c::get_application_partner()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_application_partner;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::set_application_partner(
	abs_tls_base_application_c * const partner)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::set_application_partner(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::set_application_partner()");

	m_application_partner = partner;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::add_rogue_ap(
	eap_array_c<eap_rogue_ap_entry_c> & rogue_ap_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = get_application_partner()->add_rogue_ap(rogue_ap_list);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::set_session_timeout(
	const u32_t session_timeout_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("PEAP: %s: crypto_function: tls_application_eap_core_c::set_session_timeout(): ")
		 EAPL("this = 0x%08x\n"),
		 (m_is_client == true ? "client": "server"),
		 this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::set_session_timeout()");

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = get_application_partner()->set_session_timeout(session_timeout_ms);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::read_authority_identity(eap_variable_data_c * const /* authority_identity_payload*/)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::save_user_authorization_pac_opaque(const tls_extension_c * const /* extension */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

// This is commented in tls_base_record_c::query_tunnel_PAC().
EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::query_tunnel_PAC(
	const eap_fast_variable_data_c * const /* in_A_ID_TLV */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

// This is commented in tls_base_record_c::cancel_query_tunnel_PAC().
EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::cancel_query_tunnel_PAC()
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::complete_query_ttls_pap_username_and_password(
	const eap_variable_data_c * const ttls_pap_username,
	const eap_variable_data_c * const ttls_pap_password,
	const eap_status_e query_result)
{
	eap_status_e status(eap_status_process_general_error);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::complete_query_ttls_pap_username_and_password()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::complete_query_ttls_pap_username_and_password()");

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(
		m_am_tools,
		m_receive_network_id.get_destination_id(),
		m_receive_network_id.get_source_id(),
		m_receive_network_id.get_type());

	if (query_result != eap_status_ok)
	{
		{
			eap_general_state_variable_e general_state_variable(eap_general_state_authentication_error);

			if (query_result == eap_status_user_cancel_authentication)
			{
				general_state_variable = eap_general_state_authentication_cancelled;
			}

			eap_state_notification_c notification(
				m_am_tools,
				&send_network_id,
				true,
				eap_state_notification_eap,
				eap_protocol_layer_general,
				m_peap_tunneled_eap_type,
				eap_state_none,
				general_state_variable,
				m_received_eap_identifier,
				false);

			notification.set_authentication_error(query_result);

			m_application_partner->state_notification(&notification);
		}

		{
			eap_state_notification_c notification(
				m_am_tools,
				&send_network_id,
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_eap,
				m_peap_tunneled_eap_type,
				eap_state_none,
				eap_state_authentication_terminated_unsuccessfully,
				m_received_eap_identifier,
				true);
			m_application_partner->state_notification(&notification);
		}
	}
	else
	{
		if (ttls_pap_username == 0
			|| ttls_pap_username->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		if (ttls_pap_password == 0
			|| ttls_pap_password->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eap_variable_data_c tunneled_data(m_am_tools);
		eap_variable_data_c avp(m_am_tools);

		{
			status = create_ttls_diameter_avp(
				&avp,
				ttls_pap_username,
				eap_diameter_avp_code_user_name,
				false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = tunneled_data.add_data(&avp);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		{
			eap_variable_data_c padded_password(m_am_tools);

			status = padded_password.set_copy_of_buffer(ttls_pap_password);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			const u32_t PADDING_LENGTH_MULTIPLIER(16ul);

			const u32_t padding_length((PADDING_LENGTH_MULTIPLIER - (padded_password.get_data_length() % PADDING_LENGTH_MULTIPLIER)) % PADDING_LENGTH_MULTIPLIER);

			if (padding_length > 0ul)
			{
				const u8_t PADDING[] = {
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };

				status = padded_password.add_data_to_offset(padded_password.get_data_length(), PADDING, padding_length);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			status = create_ttls_diameter_avp(
				&avp,
				&padded_password,
				eap_diameter_avp_code_user_password,
				false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = tunneled_data.add_data(&avp);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		eap_buf_chain_wr_c forwarded_packet(
			eap_write_buffer,
			m_am_tools,
			tunneled_data.get_data(),
			tunneled_data.get_data_length(),
			false,
			false,
			0ul);
		if (forwarded_packet.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = get_application_partner()->packet_send(
			&forwarded_packet,
			0ul,
			forwarded_packet.get_data_length(),
			forwarded_packet.get_buffer_length());
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------


EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::check_ttls_plain_pap_payloads(
	eap_diameter_payloads_c * const payloads,
	eap_ttls_tunneled_message_type_e * const message_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::check_ttls_plain_pap_payloads()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::check_ttls_plain_pap_payloads()");

	*message_type = eap_ttls_tunneled_message_type_none;

	eap_status_e status(eap_status_not_found);

	eap_array_c<eap_diameter_avp_code_c> needed_payloads(m_am_tools);

	needed_payloads.reset();

	if (m_is_client == false)
	{
		// First check are there User-Name and User-Password AVPs.

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		eap_diameter_avp_code_c code_user_name(
			eap_diameter_avp_code_user_name);

		status = needed_payloads.add_object(&code_user_name, false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		eap_diameter_avp_code_c code_user_password(
			eap_diameter_avp_code_user_password);

		status = needed_payloads.add_object(&code_user_password, false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		// Test the required attribute.
		status = payloads->check_payloads_existense(
			&needed_payloads);
		if (status == eap_status_ok)
		{
			// This packet includes required AVPs.

			status = payloads->check_mandatory_payloads(
				&needed_payloads);
			if (status == eap_status_ok)
			{
				// All mandatory AVPs are included.

				*message_type = eap_ttls_tunneled_message_type_pap_response;

				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("Match User-Name and User-Password AVPs.\n")));

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else //if (m_is_client == true)
	{
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		// First check is there Reply-Message AVP.
		
		eap_diameter_avp_code_c code_reply_message(
			eap_diameter_avp_code_reply_message);

		status = needed_payloads.add_object(&code_reply_message, false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		// Test the required attribute.
		status = payloads->check_payloads_existense(
			&needed_payloads);
		if (status == eap_status_ok)
		{
			// This packet includes required AVPs.

			status = payloads->check_mandatory_payloads(
				&needed_payloads);
			if (status == eap_status_ok)
			{
				// All mandatory AVPs are included.

				*message_type = eap_ttls_tunneled_message_type_pap_reply_message;

				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("Match Reply-Message AVP.\n")));

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------


EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_server_handles_pap_response(
	eap_diameter_payloads_c * const /* payloads */,
	const u8_t /* received_eap_identifier */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::ttls_server_handles_pap_response()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_server_handles_pap_response()");

	eap_status_e status(eap_status_not_found);

	eap_diameter_variable_data_c * const user_name_payload
		= m_ttls_received_payloads.get_payload(eap_diameter_avp_code_user_name);

	if (user_name_payload == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_diameter_variable_data_c * const user_password_payload
		= m_ttls_received_payloads.get_payload(eap_diameter_avp_code_user_password);

	if (user_password_payload == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_variable_data_c * const password = user_password_payload->get_payload_buffer();

	// Remove possible padding of user_password_payload.
	while(true)
	{
		if (password->get_data_length() < 1ul)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		u8_t * last_char = password->get_data_offset(password->get_data_length()-1ul, 1ul) ;

		if (last_char != 0
			&& *last_char == 0x00)
		{
			status = password->set_data_length(password->get_data_length()-1ul);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			break;
		}
	}

	status = m_application_partner->verify_ttls_pap_username_and_password(
		user_name_payload->get_payload_buffer(),
		password);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------


EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::ttls_server_handles_pap_reply_message(
	eap_diameter_payloads_c * const /* payloads */,
	const u8_t /* received_eap_identifier */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::ttls_server_handles_pap_reply_message()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::ttls_server_handles_pap_reply_message()");

	eap_status_e status(eap_status_not_found);

	eap_diameter_variable_data_c * const reply_message_payload
		= m_ttls_received_payloads.get_payload(eap_diameter_avp_code_reply_message);

	if (reply_message_payload == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	status = m_application_partner->query_ttls_pap_username_and_password(
		reply_message_payload->get_payload_buffer());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------


EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::handle_ttls_plain_pap_payloads(
	eap_diameter_payloads_c * const payloads,
	const eap_ttls_tunneled_message_type_e message_type,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::handle_ttls_plain_pap_payloads()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::handle_ttls_plain_pap_payloads()");

	eap_status_e status(eap_status_not_found);

	switch(message_type)
	{
	case eap_ttls_tunneled_message_type_pap_response:
		// Here are included User-Name, User-Password AVPs.
		status = ttls_server_handles_pap_response(payloads, received_eap_identifier);
		break;
	case eap_ttls_tunneled_message_type_pap_reply_message:
		// Here are included Reply-Message AVP.
		status = ttls_server_handles_pap_reply_message(payloads, received_eap_identifier);
		break;
	default:
		status = eap_status_unexpected_message;
		break;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------


EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::complete_verify_ttls_pap_username_and_password(
	const eap_status_e authentication_result,
	const eap_variable_data_c * const ttls_pap_reply_message)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TTLS: %s: tls_application_eap_core_c::complete_verify_ttls_pap_username_and_password()\n"),
		(m_is_client == true ? "client": "server")));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: tls_application_eap_core_c::complete_verify_ttls_pap_username_and_password()");

	eap_status_e status(eap_status_not_found);

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(
		m_am_tools,
		m_receive_network_id.get_destination_id(),
		m_receive_network_id.get_source_id(),
		m_receive_network_id.get_type());

	status = authentication_result;

	if (authentication_result == eap_status_ok)
	{
		eap_state_notification_c notification(
			m_am_tools,
			&send_network_id,
			m_is_client,
			eap_state_notification_eap,
			eap_protocol_layer_eap,
			m_peap_tunneled_eap_type,
			eap_state_none,
			eap_state_authentication_finished_successfully,
			m_received_eap_identifier,
			true);
		m_application_partner->state_notification(&notification);
	}
	else
	{
		if (ttls_pap_reply_message != 0
			&& ttls_pap_reply_message->get_is_valid_data() == true)
		{
			eap_variable_data_c tunneled_data(m_am_tools);
			eap_variable_data_c avp(m_am_tools);

			{
				status = create_ttls_diameter_avp(
					&avp,
					ttls_pap_reply_message,
					eap_diameter_avp_code_reply_message,
					false);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = tunneled_data.add_data(&avp);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			eap_buf_chain_wr_c forwarded_packet(
				eap_write_buffer,
				m_am_tools,
				tunneled_data.get_data(),
				tunneled_data.get_data_length(),
				false,
				false,
				0ul);
			if (forwarded_packet.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = get_application_partner()->packet_send(
				&forwarded_packet,
				0ul,
				forwarded_packet.get_data_length(),
				forwarded_packet.get_buffer_length());
		}
		else
		{
			eap_state_notification_c notification(
				m_am_tools,
				&send_network_id,
				m_is_client,
				eap_state_notification_eap,
				eap_protocol_layer_eap,
				m_peap_tunneled_eap_type,
				eap_state_none,
				eap_state_authentication_terminated_unsuccessfully,
				m_received_eap_identifier,
				true);
			m_application_partner->state_notification(&notification);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e tls_application_eap_core_c::alert_received(
	const tls_alert_level_e alert_level,
	const tls_alert_description_e alert_description)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(alert_level);
	EAP_UNREFERENCED_PARAMETER(alert_description);

	eap_tls_trace_string_c tls_trace;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ERROR: %s: tls_application_eap_core_c::alert_received(), level %d=%s, description %d=%s\n"),
		 (m_is_client == true ? "client": "server"),
		 alert_level,
		 tls_trace.get_alert_level_string(alert_level),
		 alert_description,
		 tls_trace.get_alert_description_string(alert_description)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

// End.
