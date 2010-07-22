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
* %version: 29.1.3 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 66 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_type_aka.h"
#include "eap_type_aka_header.h"
#include "eap_type_aka_payloads.h"
#include "abs_eap_am_type_aka.h"
#include "eap_crypto_api.h"
#include "eap_state_notification.h"
#include "abs_eap_am_mutex.h"
#include "eap_automatic_variable.h"
#include "eap_buffer.h"


//--------------------------------------------------

/** @file */

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::generate_nai(
	eap_variable_data_c * const new_nai,
	const bool use_manual_default_realm,
	const eap_variable_data_c * const nai_realm,
	const eap_variable_data_c * const id_IMSI_or_pseudonym,
	const bool id_is_imsi,
	const eap_variable_data_c * const IMSI,
	const eap_variable_data_c * const automatic_realm,
	const u32_t length_of_mnc)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (id_IMSI_or_pseudonym == 0
		|| id_IMSI_or_pseudonym->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_status_e status = eap_status_not_supported;
	
	status = new_nai->init(id_IMSI_or_pseudonym->get_data_length()+1u);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	new_nai->set_is_valid();

	eap_variable_data_c local_username(m_am_tools);
	if (local_username.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = local_username.set_buffer_length(id_IMSI_or_pseudonym->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	local_username.set_data_length(id_IMSI_or_pseudonym->get_data_length());

	m_am_tools->memmove(
		local_username.get_data(id_IMSI_or_pseudonym->get_data_length()),
		id_IMSI_or_pseudonym->get_data(id_IMSI_or_pseudonym->get_data_length()),
		id_IMSI_or_pseudonym->get_data_length());

	new_nai->set_data_length(0u);

	if (id_is_imsi == true)
	{
		// Note the first octet is reserved for IMSI prefix.
		status = new_nai->add_data(AKA_IMSI_PREFIX_CHARACTER, 1u);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// This could be IMSI or pseudonym.
	status = new_nai->add_data(&local_username);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (use_manual_default_realm == true
		&& nai_realm != 0
		&& nai_realm->get_is_valid_data() == true)
	{
		if (nai_realm->get_data_length() > 0ul)
		{
			status = new_nai->add_data(AKA_AT_CHARACTER, 1u);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		status = new_nai->add_data(nai_realm);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (IMSI != 0
		&& IMSI->get_is_valid_data() == true
		&& IMSI->get_data_length() >= EAP_TYPE_AKA_MINIMUM_IMSI_LENGTH)
	{
		// We must use automatic realm (Example: "wlan.mnc456.mcc123.3gppnetwork.org").

		status = new_nai->add_data(AKA_AT_CHARACTER, 1u);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (automatic_realm != 0
			&& automatic_realm->get_is_valid_data() == true)
		{
			status = new_nai->add_data(automatic_realm);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			status = new_nai->add_data(AKA_OWLAN_ORG_PREFIX_STRING, AKA_OWLAN_ORG_PREFIX_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = new_nai->add_data(AKA_OWLAN_DOT_STRING, AKA_OWLAN_DOT_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = new_nai->add_data(AKA_OWLAN_MNC_STRING, AKA_OWLAN_MNC_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// MNC part.
			if (length_of_mnc == EAP_TYPE_AKA_MNC_LENGTH_2_BYTES)
			{
				// Add zero digit.
				u8_t zero = '0';
				status = new_nai->add_data(&zero, sizeof(zero));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			status = new_nai->add_data(IMSI->get_data_offset(EAP_TYPE_AKA_MNC_OFFSET, length_of_mnc), length_of_mnc);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = new_nai->add_data(AKA_OWLAN_DOT_STRING, AKA_OWLAN_DOT_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = new_nai->add_data(AKA_OWLAN_MCC_STRING, AKA_OWLAN_MCC_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// MCC part is in index 0 and it is 3 bytes long.
			status = new_nai->add_data(IMSI->get_data_offset(EAP_TYPE_AKA_MCC_OFFSET, EAP_TYPE_AKA_MCC_LENGTH), EAP_TYPE_AKA_MCC_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = new_nai->add_data(AKA_OWLAN_DOT_STRING, AKA_OWLAN_DOT_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = new_nai->add_data(AKA_OWLAN_ORG_STRING, AKA_OWLAN_ORG_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("new_nai"),
		new_nai->get_data(new_nai->get_data_length()),
		new_nai->get_data_length()));

	if (new_nai->get_data_length() < sizeof(u8_t))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_nai);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::query_AKA_IMSI_or_pseudonym_or_reauthentication_id(
	eap_variable_data_c * const IMSI,
	eap_variable_data_c * const pseudonym_identity,
	eap_variable_data_c * const reauthentication_identity,
	eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
	u32_t * const length_of_mnc,
	const bool /*must_be_synchronous*/,
	const aka_payload_AT_type_e required_identity,
	const eap_type_aka_complete_e required_completion,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	save_current_state();
	set_state(eap_type_aka_state_pending_identity_query);

	status = m_am_type_aka->query_AKA_IMSI_or_pseudonym_or_reauthentication_id(
		IMSI,
		pseudonym_identity,
		reauthentication_identity,
		automatic_realm,
		length_of_mnc,
		required_identity,
		required_completion,
		received_eap_identifier);

	if (status == eap_status_pending_request)
	{
		// This is pending query, that will be completed by complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() call.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status == eap_status_completed_request)
	{
		// This is already completed by complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() call.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status != eap_status_ok
		&& status != eap_status_success)
	{
		// This is an error case.
		restore_saved_previous_state();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status == eap_status_ok)
	{
		if (m_use_pseudonym_identity == false)
		{
			// We do not want use pseudonym identity.
			pseudonym_identity->reset();
		}

		if (m_use_reauthentication_identity == false)
		{
			// We do not want use re-authentication identity.
			reauthentication_identity->reset();
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::query_AKA_RES(
	eap_type_aka_authentication_vector_c * const authentication_vector
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	status = set_RAND(authentication_vector->get_RAND());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = set_AUTN(authentication_vector->get_AUTN());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_state(eap_type_aka_state_pending_kc_sres_query);

	status = m_am_type_aka->query_AKA_RES(authentication_vector);

	if (status == eap_status_pending_request)
	{
		// This is pending query, that will be completed by complete_AKA_RES_query() call.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status == eap_status_completed_request)
	{
		// This is already completed by complete_AKA_RES_query() call.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status != eap_status_ok
		&& status != eap_status_success)
	{
		// This is a error case.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

u32_t eap_type_aka_c::get_mnc_length(const u32_t mcc)
{
	u32_t * const mcc_array = reinterpret_cast<u32_t *>(m_2_digit_mnc_map_of_mcc_of_imsi_array.get_data(
		m_2_digit_mnc_map_of_mcc_of_imsi_array.get_data_length()));

	u32_t count = m_2_digit_mnc_map_of_mcc_of_imsi_array.get_data_length() / sizeof(u32_t);

	for (u32_t ind = 0ul; ind < count; ind++)
	{
		if (mcc == mcc_array[ind])
		{
			return EAP_TYPE_AKA_MNC_LENGTH_2_BYTES;
		}
	}

	return EAP_TYPE_AKA_DEFAULT_MNC_LENGTH_3_BYTES;
}

//--------------------------------------------------

eap_status_e eap_type_aka_c::create_uma_realm(
	eap_variable_data_c * const automatic_realm,
	const eap_variable_data_c * const IMSI,
	const u32_t length_of_mnc)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	// Create special automatic realm for UMA.
	automatic_realm->reset();

	if (m_use_uma_profile == true)
	{
		// Create special automatic realm for UMA.
		automatic_realm->reset();

		if (m_uma_automatic_realm_prefix.get_is_valid_data() == true)
		{
			status = automatic_realm->add_data(&m_uma_automatic_realm_prefix);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		if (automatic_realm->get_data_length() > 0ul)
		{
			status = automatic_realm->add_data(AKA_OWLAN_DOT_STRING, AKA_OWLAN_DOT_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		status = automatic_realm->add_data(AKA_OWLAN_MNC_STRING, AKA_OWLAN_MNC_STRING_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// MNC part.
		if (length_of_mnc == EAP_TYPE_AKA_MNC_LENGTH_2_BYTES)
		{
			// Add zero digit.
			u8_t zero = '0';
			status = automatic_realm->add_data(&zero, sizeof(zero));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		status = automatic_realm->add_data(IMSI->get_data_offset(EAP_TYPE_AKA_MNC_OFFSET, length_of_mnc), length_of_mnc);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = automatic_realm->add_data(AKA_OWLAN_DOT_STRING, AKA_OWLAN_DOT_STRING_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = automatic_realm->add_data(AKA_OWLAN_MCC_STRING, AKA_OWLAN_MCC_STRING_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// MCC part is in index 0 and it is 3 bytes long.
		status = automatic_realm->add_data(IMSI->get_data_offset(EAP_TYPE_AKA_MCC_OFFSET, EAP_TYPE_AKA_MCC_LENGTH), EAP_TYPE_AKA_MCC_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = automatic_realm->add_data(AKA_OWLAN_DOT_STRING, AKA_OWLAN_DOT_STRING_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = automatic_realm->add_data(AKA_OWLAN_ORG_STRING, AKA_OWLAN_ORG_STRING_LENGTH);
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

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query(
	const eap_variable_data_c * const IMSI,
	const eap_variable_data_c * const p_pseudonym_identity,
	const eap_variable_data_c * const p_reauthentication_identity,
	const eap_variable_data_c * const p_automatic_realm, ///< If this is not used, do not add any data to this parameter.
	const u32_t length_of_mnc,
	const eap_type_aka_complete_e required_completion,
	const u8_t received_eap_identifier,
	const eap_status_e completion_status
)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	if (completion_status != eap_status_ok
		|| IMSI == 0
		|| p_pseudonym_identity == 0
		|| p_reauthentication_identity == 0)
	{
		set_state(eap_type_aka_state_failure);

		// The eap_status_process_general_error error value is more important
		// than return value of set_session_timeout().
		(void) get_type_partner()->set_session_timeout(0ul);

		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	const eap_variable_data_c * local_pseudonym_identity = p_pseudonym_identity;
	const eap_variable_data_c * local_reauthentication_identity = p_reauthentication_identity;

	if (m_use_pseudonym_identity == false)
	{
		// We do not want use pseudonym identity.
		local_pseudonym_identity = 0;
	}
	
	if (m_use_reauthentication_identity == false)
	{
		// We do not want use re-authentication identity.
		local_reauthentication_identity = 0;
	}

	if (get_state() != eap_type_aka_state_pending_identity_query)
	{
		// Authentication is terminated or state is wrong. Cannot continue.
		set_state(eap_type_aka_state_failure);

		// The eap_status_handler_does_not_exists_error error value is more important
		// than return value of set_session_timeout().
		(void) get_type_partner()->set_session_timeout(0ul);

		return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c local_automatic_realm(m_am_tools);

	if (p_automatic_realm == 0
		|| p_automatic_realm->get_is_valid_data() == false)
	{
		{
			// Here we read the length of the MNC.
			const u8_t * const MCC = IMSI->get_data_offset(EAP_TYPE_AKA_MCC_OFFSET, EAP_TYPE_AKA_MCC_LENGTH);
			if (MCC == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u32_t MCC_value(0ul);

			status = m_am_tools->number_string_to_u32(
				MCC,
				3ul,
				&MCC_value);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			m_length_of_mnc = get_mnc_length(MCC_value);
		}

		status = create_uma_realm(&local_automatic_realm, IMSI, m_length_of_mnc);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (local_automatic_realm.get_is_valid_data() == true)
		{
			status = m_automatic_realm.set_copy_of_buffer(&local_automatic_realm);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else
	{
		status = local_automatic_realm.set_copy_of_buffer(p_automatic_realm);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_length_of_mnc = length_of_mnc;

		status = m_automatic_realm.set_copy_of_buffer(p_automatic_realm);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	m_automatic_realm_read = true;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	if (required_completion == eap_type_aka_complete_query_eap_identity)
	{
		status = handle_eap_identity_query(
			get_send_network_id(),
			0,
			get_last_eap_identifier(),
			IMSI,
			local_pseudonym_identity,
			local_reauthentication_identity,
			&local_automatic_realm,
			m_length_of_mnc,
			false);
		if (status != eap_status_ok
			&& status != eap_status_completed_request)
		{
			restore_saved_previous_state();
		}
	}
	else if (required_completion == eap_type_aka_complete_aka_identity_request)
	{
		if (local_reauthentication_identity != 0
			&& local_reauthentication_identity->get_is_valid_data() == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query reauthentication_identity\n")));
			
			status = get_reauthentication_identity()->set_copy_of_buffer(local_reauthentication_identity);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			status = store_identity(get_reauthentication_identity(), false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (local_pseudonym_identity != 0
			&& local_pseudonym_identity->get_is_valid_data() == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query pseudonym\n")));
			
			get_reauthentication_identity()->reset();
			status = get_pseudonym()->set_copy_of_buffer(local_pseudonym_identity);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			status = store_identity(get_pseudonym(), false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (IMSI->get_is_valid_data() == true
			&& IMSI->get_data_length() >= EAP_TYPE_AKA_MINIMUM_IMSI_LENGTH)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query IMSI\n")));
			
			get_reauthentication_identity()->reset();
			get_pseudonym()->reset();
			status = get_IMSI()->set_copy_of_buffer(IMSI);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			status = store_identity(get_IMSI(), true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		save_current_state();
		set_state(eap_type_aka_state_analyse_aka_identity_request);
		
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query(0x%08x).\n"),
			 this));
		
		// Here we swap the addresses.
		eap_am_network_id_c receive_network_id(m_am_tools,
			get_send_network_id()->get_destination_id(),
			get_send_network_id()->get_source_id(),
			get_send_network_id()->get_type());

		status = send_aka_identity_response_message(
			&receive_network_id,
			received_eap_identifier,
			get_include_identity_to_aka_identity_response(),
			&local_automatic_realm);
		
		if (status != eap_status_ok)
		{
			restore_saved_previous_state();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::complete_AKA_RES_query(
	const eap_type_aka_authentication_vector_c * const authentication_vector,
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	if (completion_status != eap_status_ok
		|| authentication_vector == 0
		|| authentication_vector->get_is_valid() == false)
	{
		if (completion_status == eap_status_not_fresh_challenges)
		{
			(void) initialize_error_message(completion_status);

			restore_saved_previous_state();
		}
		else
		{
			set_state(eap_type_aka_state_failure);

			// The eap_status_process_general_error error value is more important
			// than return value of set_session_timeout().
			(void) get_type_partner()->set_session_timeout(0ul);
		}

		return EAP_STATUS_RETURN(m_am_tools, completion_status);
	}

	if (get_state() != eap_type_aka_state_pending_kc_sres_query)
	{
		// Authentication is terminated or state is wrong. Cannot continue.
		set_state(eap_type_aka_state_failure);

		// The eap_status_handler_does_not_exists_error error value is more important
		// than return value of set_session_timeout().
		(void) get_type_partner()->set_session_timeout(0ul);

		return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = process_AKA_kc_sres(
		authentication_vector);

	if (status != eap_status_ok
		&& status != eap_status_success)
	{
		(void) initialize_error_message(status);

		restore_saved_previous_state();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::process_AKA_kc_sres(
	const eap_type_aka_authentication_vector_c * const authentication_vector)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	eap_variable_data_c MAC_RAND(m_am_tools);
	if (MAC_RAND.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (get_state() != eap_type_aka_state_pending_kc_sres_query
		|| authentication_vector == 0
		|| authentication_vector->get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (get_identity() == 0
		|| get_identity()->get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("RAND"),
		authentication_vector->get_RAND()->get_data(authentication_vector->get_RAND()->get_data_length()),
		authentication_vector->get_RAND()->get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AUTN"),
		authentication_vector->get_AUTN()->get_data(authentication_vector->get_AUTN()->get_data_length()),
		authentication_vector->get_AUTN()->get_data_length()));

	if (authentication_vector->get_vector_status() == eap_status_ok)
	{
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("RES"),
			authentication_vector->get_RES()->get_data(authentication_vector->get_RES()->get_data_length()),
			authentication_vector->get_RES()->get_data_length()));
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CK"),
			authentication_vector->get_CK()->get_data(authentication_vector->get_CK()->get_data_length()),
			authentication_vector->get_CK()->get_data_length()));
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("IK"),
			authentication_vector->get_IK()->get_data(authentication_vector->get_IK()->get_data_length()),
			authentication_vector->get_IK()->get_data_length()));
	}
	else if (authentication_vector->get_vector_status() == eap_status_syncronization_failure)
	{
		// ERROR: send EAP-Response/AKA-Synchronization-Failure
		status = send_aka_synchronization_failure_response_message(
			authentication_vector);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		// ERROR: send EAP-Response/AKA-Authentication-Reject
		status = send_aka_authentication_reject_response_message(
			authentication_vector);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, authentication_vector->get_vector_status());
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("identity"),
		get_identity()->get_data(get_identity()->get_data_length()),
		get_identity()->get_data_length()));

	status = get_RES()->set_copy_of_buffer(authentication_vector->get_RES());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c XKEY(m_am_tools);
	eap_variable_data_c K_encr(m_am_tools);
	eap_variable_data_c K_aut(m_am_tools);
	eap_variable_data_c master_session_key(m_am_tools);

	if (XKEY.get_is_valid() == false
		|| K_encr.get_is_valid() == false
		|| K_aut.get_is_valid() == false
		|| master_session_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = generate_shared_secred_keys(
		EAP_TYPE_AKA_KEYMAT_SIZE,
		authentication_vector->get_CK(),
		authentication_vector->get_IK(),
		&XKEY,
		&K_encr,
		&K_aut,
		&master_session_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (get_saved_EAP_packet()->get_is_valid_data() == true)
	{
		aka_payloads_c * const l_aka_payloads = new aka_payloads_c(m_am_tools);
		eap_automatic_variable_c<aka_payloads_c> l_aka_payloads_automatic(m_am_tools, l_aka_payloads);

		if (l_aka_payloads == 0
			|| l_aka_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		aka_header_c saved_EAP_packet(
			m_am_tools,
			get_saved_EAP_packet()->get_data(get_saved_EAP_packet()->get_data_length()),
			get_saved_EAP_packet()->get_data_length());

		if (saved_EAP_packet.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = parse_aka_packet(
			&saved_EAP_packet,
			get_saved_EAP_packet()->get_data_length(),
			l_aka_payloads);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = check_message_authentication_code(
			&K_aut,
			l_aka_payloads,
			&saved_EAP_packet,
			saved_EAP_packet.get_length());
		if (status != eap_status_ok)
		{
			(void) initialize_error_message(status);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (m_received_checkcode.get_is_valid_data() == true)
		{
			// Verify AT_CHECKCODE.
			status = checkcode_verify(
				&m_received_checkcode);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// Decrypt and parse encrypted payload.
		if (l_aka_payloads->get_IV()->get_payload_included() == true
		|| l_aka_payloads->get_ENCR_DATA()->get_payload_included() == true)
		{
			if (l_aka_payloads->get_IV()->get_payload_included() == true
			&& l_aka_payloads->get_ENCR_DATA()->get_payload_included() == true
			&& l_aka_payloads->get_MAC()->get_payload_included() == true)
			{
				status = decrypt_DATA_payload(
					l_aka_payloads,
					&K_encr);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = handle_DATA_payload(
					aka_subtype_Challenge,
					l_aka_payloads);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				// All of these must be included
				// or none of these must be included.
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
		}
		else
		{
			// No encrypted payload.
			// AKA AM should remove re-authentication identity from favourite place.

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::process_AKA_kc_sres(0x%08x): Resets re-authentication identity from database.\n"),
				 this));

			status = m_am_type_aka->store_reauthentication_id(
				&m_send_network_id,
				0);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			get_reauthentication_identity()->reset();
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_type_aka_authentication_vector_c * const copy_authentication_vector = authentication_vector->copy();
	if (copy_authentication_vector == 0
		|| copy_authentication_vector->get_is_valid() == false)
	{
		delete copy_authentication_vector;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_authentication_vector(copy_authentication_vector);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = send_challenge_response_message(
		&K_aut);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Store keys.
	status = get_XKEY()->set_copy_of_buffer(&XKEY);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	status = get_K_encr()->set_copy_of_buffer(&K_encr);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	status = get_K_aut()->set_copy_of_buffer(&K_aut);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	status = get_master_session_key()->set_copy_of_buffer(&master_session_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// In order to use re-authentication, the client and the server need to
	// store the following values: original XKEY, K_aut, K_encr, latest
	// counter value and the next re-authentication identity.
	status = m_am_type_aka->store_reauth_parameters(
		&XKEY,
		&K_aut,
		&K_encr,
		EAP_TYPE_AKA_INITIAL_REAUTH_COUNTER);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Authentication was successful.
	if (m_use_result_indication == true)
	{
		// This version waits result indication.
		if (m_authentication_type == AKA_AUTHENTICATION_TYPE_REAUTHENTICATION)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("EAP_type_AKA: %s, re-authentication OK, waits result indication\n"),
				(m_is_client == true) ? "client": "server"));
		}
		else if (m_authentication_type == AKA_AUTHENTICATION_TYPE_FULL_AUTH)
		{
			if (m_identity_type == AKA_IDENTITY_TYPE_PSEUDONYM_ID)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
					(EAPL("EAP_type_AKA: %s, full authentication OK, pseudonym identity, waits result indication\n"),
					(m_is_client == true) ? "client": "server"));
			}
			else if (m_identity_type == AKA_IDENTITY_TYPE_IMSI_ID)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
					(EAPL("EAP_type_AKA: %s, full authentication OK, IMSI identity, waits result indication\n"),
					(m_is_client == true) ? "client": "server"));
			}
			else if (m_identity_type == AKA_IDENTITY_TYPE_RE_AUTH_ID)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
					(EAPL("EAP_type_AKA: %s, full authentication OK, Re-auth identity, waits result indication\n"),
					(m_is_client == true) ? "client": "server"));
			}
			else
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_AKA_ERROR|TRACE_TEST_VECTORS,
					(EAPL("ERROR: EAP_type_AKA: %s, full authentication OK, unknown identity\n"),
					(m_is_client == true) ? "client": "server"));

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
			}
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_AKA_ERROR|TRACE_TEST_VECTORS,
				(EAPL("ERROR: EAP_type_AKA: %s, unknown authentication OK, unknown identity\n"),
				(m_is_client == true) ? "client": "server"));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}

		set_state(eap_type_aka_state_waiting_for_notification_request_success);
	}
	else if (m_wait_eap_success_packet == false)
	{
		// This version does not wait EAP-Success message.
		if (get_send_network_id()->get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		// Here we swap the addresses.
		eap_am_network_id_c receive_network_id(m_am_tools,
			get_send_network_id()->get_destination_id(),
			get_send_network_id()->get_source_id(),
			get_send_network_id()->get_type());

		// This version does not wait EAP-Success message.
		status = finish_successful_authentication(
			&receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		// This version waits the EAP-Success message.

		if (m_authentication_type == AKA_AUTHENTICATION_TYPE_REAUTHENTICATION)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("EAP_type_AKA: %s, re-authentication OK, waits EAP-Success\n"),
				(m_is_client == true) ? "client": "server"));
		}
		else if (m_authentication_type == AKA_AUTHENTICATION_TYPE_FULL_AUTH)
		{
			if (m_identity_type == AKA_IDENTITY_TYPE_PSEUDONYM_ID)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
					(EAPL("EAP_type_AKA: %s, full authentication OK, pseudonym identity, waits EAP-Success\n"),
					(m_is_client == true) ? "client": "server"));
			}
			else if (m_identity_type == AKA_IDENTITY_TYPE_IMSI_ID)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
					(EAPL("EAP_type_AKA: %s, full authentication OK, IMSI identity, waits EAP-Success\n"),
					(m_is_client == true) ? "client": "server"));
			}
			else if (m_identity_type == AKA_IDENTITY_TYPE_RE_AUTH_ID)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
					(EAPL("EAP_type_AKA: %s, full authentication OK, Re-auth identity, waits EAP-Success\n"),
					(m_is_client == true) ? "client": "server"));
			}
			else
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_AKA_ERROR|TRACE_TEST_VECTORS,
					(EAPL("ERROR: EAP_type_AKA: %s, full authentication OK, unknown identity, waits EAP-Success\n"),
					(m_is_client == true) ? "client": "server"));

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
			}
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_AKA_ERROR|TRACE_TEST_VECTORS,
				(EAPL("ERROR: EAP_type_AKA: %s, unknown authentication OK, unknown identity, waits EAP-Success\n"),
				(m_is_client == true) ? "client": "server"));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}

		set_state(eap_type_aka_state_waiting_for_success);
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::send_aka_identity_response_message(
	const eap_am_network_id_c * const receive_network_id,
	const u8_t received_eap_identifier,
	const aka_payload_AT_type_e include_identity_to_aka_identity_response,
	const eap_variable_data_c * const automatic_realm)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("    send: handler 0x%08x, AKA-type %10s, %s, state %2d=%s\n"),
		this,
		EAPL("aka_subtype_Identity"),
		(get_is_client()) ? EAPL("client") : EAPL("server"),
		get_state(),
		get_state_string()
		));

	eap_buf_chain_wr_c aka_initial_reply(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (aka_initial_reply.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means AKA does process every re-transmitted EAP-Request.
		aka_initial_reply.set_do_packet_retransmission(false);
	}

	EAP_ASSERT_ALWAYS(EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH >= (m_aka_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_aka_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_aka_header_offset+m_MTU;
	}

	aka_header_c aka_response(
		m_am_tools,
		aka_initial_reply.get_data_offset(
			m_aka_header_offset,
			(packet_buffer_free-m_aka_header_offset)),
		(packet_buffer_free-m_aka_header_offset));

	if (aka_response.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());

	aka_response.reset_header(
		packet_buffer_free-m_aka_header_offset,
		m_use_eap_expanded_type);
	aka_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_code(eap_code_response);
	aka_response.set_identifier(received_eap_identifier);
	aka_response.set_type(
		eap_type_aka,
		m_use_eap_expanded_type);

	aka_response.set_subtype(aka_subtype_Identity);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::send_aka_identity_response_message(0x%08x): include_identity_to_start_response %d=%s.\n"),
		 this,
		 include_identity_to_aka_identity_response,
		 aka_payload_AT_header_c::get_payload_AT_string(include_identity_to_aka_identity_response)));

	update_buffer_indexes(
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		m_aka_header_offset+aka_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t aka_data_free = packet_buffer_free;
	u32_t aka_data_offset = 0u;
	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_identity_type == AKA_IDENTITY_TYPE_RE_AUTH_ID)
	{
		// Re-authentication identity MUST be removed after first use.
		// EAP-AKA AM should remove re-authentication identity from favourite place.

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_aka_c::send_aka_identity_response_message(0x%08x): Resets re-authentication identity from database.\n"),
			 this));

		status = m_am_type_aka->store_reauthentication_id(
			&m_send_network_id,
			0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Do not reset the local copy of re-authentocation identity.
	}


	if (include_identity_to_aka_identity_response == aka_payload_AT_PERMANENT_ID_REQ)
	{
		m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;
		set_identity_type(AKA_IDENTITY_TYPE_IMSI_ID);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_aka_c::send_aka_identity_response_message(0x%08x): Selects full authentication and IMSI identity.\n"),
			 this));
	}
	else if (include_identity_to_aka_identity_response == aka_payload_AT_FULLAUTH_ID_REQ)
	{
		eap_variable_data_c * const pseudonym = get_pseudonym();

		if (pseudonym->get_is_valid_data() == true)
		{
			// We have pseudonym.
			m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;
			set_identity_type(AKA_IDENTITY_TYPE_PSEUDONYM_ID);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::send_aka_identity_response_message(0x%08x): Selects full authentication and pseudonym identity.\n"),
				 this));
		}
		else // if (pseudonym->get_is_valid() == false)
		{
			// Because no pseudonym is available we must use IMSI.
			m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;
			set_identity_type(AKA_IDENTITY_TYPE_IMSI_ID);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::send_aka_identity_response_message(0x%08x): Selects full authentication and IMSI identity.\n"),
				 this));
		}
	}
	else if (include_identity_to_aka_identity_response == aka_payload_AT_ANY_ID_REQ)
	{
		eap_variable_data_c * const reauthentication_identity = get_reauthentication_identity();
		eap_variable_data_c * const pseudonym = get_pseudonym();

		if (reauthentication_identity->get_is_valid_data() == true)
		{
			// We have reauthentication identity. Re-authentication identity is NAI.
			m_authentication_type = AKA_AUTHENTICATION_TYPE_REAUTHENTICATION;
			set_identity_type(AKA_IDENTITY_TYPE_RE_AUTH_ID);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::send_aka_identity_response_message(0x%08x): Selects fast re-authentication and re-authentication identity.\n"),
				 this));
		}
		else if (pseudonym->get_is_valid_data() == true)
		{
			// We have pseudonym.
			m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;
			set_identity_type(AKA_IDENTITY_TYPE_PSEUDONYM_ID);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::send_aka_identity_response_message(0x%08x): Selects full authentication and pseudonym identity.\n"),
				 this));
		}
		else if (get_IMSI()->get_is_valid_data() == true)
		{
			// Because no pseudonym is available we must use IMSI.
			m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;
			set_identity_type(AKA_IDENTITY_TYPE_IMSI_ID);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::send_aka_identity_response_message(0x%08x): Selects full authentication and IMSI identity.\n"),
				 this));
		}
		else
		{
			// ERROR, no identity available.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}
	}


	if (include_identity_to_aka_identity_response != aka_payload_NONE)
	{
		if (m_identity_type == AKA_IDENTITY_TYPE_IMSI_ID)
		{
			eap_variable_data_c NAI(m_am_tools);
			if (NAI.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = NAI.init(1u);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			NAI.set_is_valid();

			status = generate_nai(
				&NAI,
				m_use_manual_realm,
				get_nai_realm(),
				get_IMSI(),
				true,
				get_IMSI(),
				automatic_realm,
				m_length_of_mnc);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = add_pseudonym_or_imsi_payload(
				&aka_response,
				EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
				aka_response.get_header_length(),
				&aka_data_offset,
				&aka_data_free,
				&packet_buffer_free,
				&packet_buffer_offset,
				&NAI,
				aka_payload_AT_IDENTITY);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Save used NAI.
			status = get_NAI()->set_copy_of_buffer(&NAI);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::send_aka_identity_response_message(): Client sends IMSI identity.\n")));
		}
		else if (m_identity_type == AKA_IDENTITY_TYPE_PSEUDONYM_ID)
		{
			eap_variable_data_c * const pseudonym = get_pseudonym();

			if (pseudonym->get_is_valid_data() == true)
			{
				// We have pseudonym.

				eap_variable_data_c NAI(m_am_tools);
				if (NAI.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = NAI.init(1u);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				NAI.set_is_valid();

				status = generate_nai(
					&NAI,
					m_use_manual_realm,
					get_nai_realm(),
					pseudonym,
					false,
					get_IMSI(),
					automatic_realm,
					m_length_of_mnc);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = add_pseudonym_or_imsi_payload(
					&aka_response,
					EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
					aka_response.get_header_length(),
					&aka_data_offset,
					&aka_data_free,
					&packet_buffer_free,
					&packet_buffer_offset,
					&NAI,
					aka_payload_AT_IDENTITY);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// Save used NAI.
				status = get_NAI()->set_copy_of_buffer(&NAI);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_type_aka_c::send_aka_identity_response_message(): Client sends pseudonym identity.\n")));
			}
			else // if (pseudonym->get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
			}
		}
		else if (m_identity_type == AKA_IDENTITY_TYPE_RE_AUTH_ID)
		{
			eap_variable_data_c * const reauthentication_identity = get_reauthentication_identity();

			if (reauthentication_identity->get_is_valid_data() == true)
			{
				// We have reauthentication identity. Re-authentication identity is NAI.
				status = add_pseudonym_or_imsi_payload(
					&aka_response,
					EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
					aka_response.get_header_length(),
					&aka_data_offset,
					&aka_data_free,
					&packet_buffer_free,
					&packet_buffer_offset,
					reauthentication_identity,
					aka_payload_AT_IDENTITY);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// Save used NAI.
				status = get_NAI()->set_copy_of_buffer(reauthentication_identity);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_type_aka_c::send_aka_identity_response_message(): Client sends re-authentication identity.\n")));
			}
			else
			{
				// ERROR, no identity available.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
			}
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	aka_response.set_data_length(
		aka_data_offset,
		m_use_eap_expanded_type);
	aka_initial_reply.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
		== packet_buffer_offset);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = checkcode_save_message_client(
		aka_response.get_header_buffer(
			aka_response.get_header_length()
			+aka_response.get_data_length()),
		aka_response.get_header_length()
		+aka_response.get_data_length(),
		0);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = packet_send(
		&send_network_id,
		&aka_initial_reply,
		m_aka_header_offset,
		aka_response.get_header_length()+aka_response.get_data_length(),
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		if (m_authentication_type == AKA_AUTHENTICATION_TYPE_REAUTHENTICATION)
		{
			set_state(eap_type_aka_state_waiting_for_reauth_request);
		}
		else
		{
			set_state(eap_type_aka_state_waiting_for_challenge_request);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::send_aka_synchronization_failure_response_message(
	const eap_type_aka_authentication_vector_c * const authentication_vector
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: handler 0x%08x, AKA-type %10s, %s, state %2d=%s\n"),
		this,
		EAPL("send_synchronization_failure_response_message"),
		(get_is_client()) ? EAPL("client") : EAPL("server"),
		get_state(),
		get_state_string()
		));

	eap_buf_chain_wr_c eap_notification_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_notification_packet.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means AKA does process every re-transmitted EAP-Request.
		eap_notification_packet.set_do_packet_retransmission(false);
	}

	EAP_ASSERT_ALWAYS(EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH >= (m_aka_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_aka_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_aka_header_offset+m_MTU;
	}

	aka_header_c aka_response(
		m_am_tools,
		eap_notification_packet.get_data_offset(
			m_aka_header_offset,
			(packet_buffer_free-m_aka_header_offset)),
		(packet_buffer_free-m_aka_header_offset));

	if (aka_response.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	aka_response.reset_header(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_code(eap_code_response);
	aka_response.set_identifier(static_cast<u8_t>(get_last_eap_identifier()));
	aka_response.set_type(
		eap_type_aka,
		m_use_eap_expanded_type);
	aka_response.set_subtype(aka_subtype_Synchronization_Failure);


	update_buffer_indexes(
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		m_aka_header_offset+aka_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t aka_data_free = packet_buffer_free;
	u32_t aka_data_offset = 0u;
	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c orig_K_aut(m_am_tools);
	if (orig_K_aut.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = add_AUTS_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		authentication_vector->get_AUTS(),
		aka_payload_AT_AUTS);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	aka_response.set_data_length(
		aka_data_offset,
		m_use_eap_expanded_type);
	eap_notification_packet.set_data_length(packet_buffer_offset);
	
	EAP_ASSERT_ALWAYS(
		m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
		== packet_buffer_offset);
	
	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_notification_packet.set_data_length(packet_buffer_offset);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send_aka_synchronization_failure_response_message(): aka_subtype_Synchronization_Failure packet"),
		aka_response.get_header_buffer(aka_response.get_length()),
		aka_response.get_length()));

	status = packet_send(
		get_send_network_id(),
		&eap_notification_packet,
		m_aka_header_offset,
		aka_response.get_length(),
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		set_state(eap_type_aka_state_waiting_for_challenge_request);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::send_aka_authentication_reject_response_message(
	const eap_type_aka_authentication_vector_c * const /*authentication_vector*/
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: handler 0x%08x, AKA-type %10s, %s, state %2d=%s\n"),
		this,
		EAPL("send_authentication_reject_response_message"),
		(get_is_client()) ? EAPL("client") : EAPL("server"),
		get_state(),
		get_state_string()
		));

	eap_buf_chain_wr_c eap_notification_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_notification_packet.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means AKA does process every re-transmitted EAP-Request.
		eap_notification_packet.set_do_packet_retransmission(false);
	}

	EAP_ASSERT_ALWAYS(EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH >= (m_aka_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_aka_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_aka_header_offset+m_MTU;
	}

	aka_header_c aka_response(
		m_am_tools,
		eap_notification_packet.get_data_offset(
			m_aka_header_offset,
			(packet_buffer_free-m_aka_header_offset)),
		(packet_buffer_free-m_aka_header_offset));

	if (aka_response.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	aka_response.reset_header(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_code(eap_code_response);
	aka_response.set_identifier(static_cast<u8_t>(get_last_eap_identifier()));
	aka_response.set_type(
		eap_type_aka,
		m_use_eap_expanded_type);
	aka_response.set_subtype(aka_subtype_Authentication_Reject);


	update_buffer_indexes(
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		m_aka_header_offset+aka_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t aka_data_offset = 0u;
	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	aka_response.set_data_length(
		aka_data_offset,
		m_use_eap_expanded_type);
	eap_notification_packet.set_data_length(packet_buffer_offset);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send_aka_authentication_reject_response_message: aka_subtype_Authentication_Reject packet"),
		aka_response.get_header_buffer(aka_response.get_length()),
		aka_response.get_length()));

	status = packet_send(
		get_send_network_id(),
		&eap_notification_packet,
		m_aka_header_offset,
		aka_response.get_length(),
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::send_aka_notification_response(
	const eap_aka_notification_codes_e notification_code,
	const bool add_at_counter_attribute)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: handler 0x%08x, AKA-type %10s, %s, state %2d=%s\n"),
		this,
		EAPL("send_aka_notification_response"),
		(get_is_client()) ? EAPL("client") : EAPL("server"),
		get_state(),
		get_state_string()
		));

	eap_buf_chain_wr_c eap_notification_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_notification_packet.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means AKA does process every re-transmitted EAP-Request.
		eap_notification_packet.set_do_packet_retransmission(false);
	}

	EAP_ASSERT_ALWAYS(EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH >= (m_aka_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_aka_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_aka_header_offset+m_MTU;
	}

	aka_header_c aka_response(
		m_am_tools,
		eap_notification_packet.get_data_offset(
			m_aka_header_offset,
			(packet_buffer_free-m_aka_header_offset)),
		(packet_buffer_free-m_aka_header_offset));

	if (aka_response.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	aka_response.reset_header(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_code(eap_code_response);
	aka_response.set_identifier(static_cast<u8_t>(get_last_eap_identifier()));
	aka_response.set_type(
		eap_type_aka,
		m_use_eap_expanded_type);
	aka_response.set_subtype(aka_subtype_Notification);


	update_buffer_indexes(
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		m_aka_header_offset+aka_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t aka_data_free = packet_buffer_free;
	u32_t aka_data_offset = 0u;
	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c * K_aut = 0;

	eap_variable_data_c orig_K_aut(m_am_tools);
	if (orig_K_aut.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (get_aka_notification_code_P_bit(notification_code) == false)
	{
		u8_t *MAC_data = 0;
		u32_t MAC_data_length = 0u;
		eap_type_aka_MAC_attributes_c MAC_attributes;

		if (add_at_counter_attribute == true)
		{
			// If EAP-Request/AKA/Notification is used on fast a re-authentication
			// exchange, and if the P bit in AT_NOTIFICATION is set to zero, then
			// AT_COUNTER is used for replay protection. In this case, the
			// AT_ENCR_DATA and AT_IV attributes MUST be included, and the
			// encapsulated plaintext attributes MUST include the AT_COUNTER
			// attribute. The counter value included in AT_COUNTER MUST be the same
			// as in the EAP-Request/AKA/Re-authentication packet on the same fast
			// re-authentication exchange.

			// - - - - - - - - - - - - - - - - - - - - - - - -

			eap_variable_data_c orig_XKEY(m_am_tools);
			eap_variable_data_c orig_K_encr(m_am_tools);

			if (orig_XKEY.get_is_valid() == false
				|| orig_K_encr.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u32_t reauth_counter = 0u;

			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_aka->query_reauth_parameters(
				&orig_XKEY,
				&orig_K_aut,
				&orig_K_encr,
				&reauth_counter);
			if (status != eap_status_ok)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			K_aut = &orig_K_aut;

			// -   -   -   -   -   -   -   -   -   -   -   -

			crypto_aes_c aes(m_am_tools);

			if (aes.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = m_am_type_aka->generate_encryption_IV(
				get_IV()->get_payload_buffer(),
				aes.get_block_size());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}


			status = add_variable_payload(
				&aka_response,
				EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
				aka_response.get_header_length(),
				&aka_data_offset,
				&aka_data_free,
				&packet_buffer_free,
				&packet_buffer_offset,
				get_IV()->get_payload_buffer(),
				aka_payload_AT_IV);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}


			// Encrypted data.
			{
				aka_payload_AT_header_c gp_encrypted_data(
					m_am_tools,
					aka_response.get_data_offset(
						aka_data_offset, 
						aka_data_free),
					aka_data_free);
				if (aka_response.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
				}

				// Initialize the length of encrypted data to maximum length.
				// Later this will be set to correct length.
				gp_encrypted_data.reset_header(aka_payload_AT_header_c::get_max_payload_data_length());
				gp_encrypted_data.set_current_payload(aka_payload_AT_ENCR_DATA);

				update_payload_indexes(
					EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
					aka_response.get_header_length(),
					gp_encrypted_data.get_header_length(),
					&aka_data_offset,
					&aka_data_free,
					&packet_buffer_offset,
					&packet_buffer_free);

				u32_t encrypted_data_offset_begin = packet_buffer_offset;

				// -   -   -   -   -   -   -   -   -   -   -   -

				status = add_counter_payload(
					&aka_response,
					EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
					aka_response.get_header_length(),
					&aka_data_offset,
					&aka_data_free,
					&packet_buffer_free,
					&packet_buffer_offset,
					static_cast<u16_t>(reauth_counter));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// -   -   -   -   -   -   -   -   -   -   -   -

				status = add_padding_payload(
					&aka_response,
					EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
					aka_response.get_header_length(),
					&aka_data_offset,
					&aka_data_free,
					&packet_buffer_free,
					&packet_buffer_offset,
					(packet_buffer_offset - encrypted_data_offset_begin) // Length of the plain text.
					);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				gp_encrypted_data.set_data_length(
					static_cast<u16_t>(packet_buffer_offset - encrypted_data_offset_begin));

				// -   -   -   -   -   -   -   -   -   -   -   -

				status = encrypt_DATA_payload(
					gp_encrypted_data.get_data(gp_encrypted_data.get_data_length()),
					gp_encrypted_data.get_data_length(),
					get_IV()->get_payload_buffer(),
					&orig_K_encr);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_AKA_TRACE_PAYLOAD("Payload added", &gp_encrypted_data);
			}

		}
		else
		{
			K_aut = get_K_aut();
		} // if (add_counter_payload == true)

		// -   -   -   -   -   -   -   -   -   -   -   -

		// Add AT_MAC attribute.
		status = add_mac_payload(
			&aka_response,
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			&MAC_data,
			&MAC_data_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// -   -   -   -   -   -   -   -   -   -   -   -

		aka_response.set_data_length(
			aka_data_offset,
			m_use_eap_expanded_type);
		eap_notification_packet.set_data_length(packet_buffer_offset);

		EAP_ASSERT_ALWAYS(
			m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
			== packet_buffer_offset);

		// -   -   -   -   -   -   -   -   -   -   -   -

		MAC_attributes.init(
			MAC_data,
			MAC_data_length,
			aka_response.get_header_buffer(aka_response.get_length()),
			aka_response.get_length());

		status = create_message_authentication_code(
			&MAC_attributes,
			aka_response.get_subtype(),
			aka_response.get_code(),
			K_aut);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		aka_response.set_data_length(
			aka_data_offset,
			m_use_eap_expanded_type);
		eap_notification_packet.set_data_length(packet_buffer_offset);

		EAP_ASSERT_ALWAYS(
			m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
			== packet_buffer_offset);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_notification_packet.set_data_length(packet_buffer_offset);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("send_aka_notification_response: aka_subtype_Notification packet"),
		aka_response.get_header_buffer(aka_response.get_length()),
		aka_response.get_length()));

	status = packet_send(
		get_send_network_id(),
		&eap_notification_packet,
		m_aka_header_offset,
		aka_response.get_length(),
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::send_aka_client_error_response()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_AKA_ERROR, 
		(EAPL("ERROR: send: handler 0x%08x, AKA-type %10s, %s, state %2d=%s\n"),
		this,
		EAPL("send_aka_client_error_response"),
		(get_is_client()) ? EAPL("client") : EAPL("server"),
		get_state(),
		get_state_string()
		));

	eap_buf_chain_wr_c eap_client_error_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_client_error_packet.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means AKA does process every re-transmitted EAP-Request.
		eap_client_error_packet.set_do_packet_retransmission(false);
	}

	EAP_ASSERT_ALWAYS(EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH >= (m_aka_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_aka_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_aka_header_offset+m_MTU;
	}

	aka_header_c aka_response(
		m_am_tools,
		eap_client_error_packet.get_data_offset(
			m_aka_header_offset,
			(packet_buffer_free-m_aka_header_offset)),
		(packet_buffer_free-m_aka_header_offset));

	if (aka_response.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	aka_response.reset_header(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_code(eap_code_response);
	aka_response.set_identifier(static_cast<u8_t>(get_last_eap_identifier()));
	aka_response.set_type(
		eap_type_aka,
		m_use_eap_expanded_type);
	aka_response.set_subtype(aka_subtype_Client_Error);


	update_buffer_indexes(
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		m_aka_header_offset+aka_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t aka_data_free = packet_buffer_free;
	u32_t aka_data_offset = 0u;

	eap_status_e status = add_client_error_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		m_client_error_code);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	aka_response.set_data_length(
		aka_data_offset,
		m_use_eap_expanded_type);
	eap_client_error_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
		== packet_buffer_offset);

	status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_client_error_packet.set_data_length(packet_buffer_offset);

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("    send: EAP-Response/Client-Error packet"),
		aka_response.get_header_buffer(aka_response.get_length()),
		aka_response.get_length()));

	status = packet_send(
		get_send_network_id(),
		&eap_client_error_packet,
		m_aka_header_offset,
		aka_response.get_length(),
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::send_challenge_response_message(
		eap_variable_data_c * const K_aut)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("    send: handler 0x%08x, AKA-type %10s, %s, state %2d=%s\n"),
		this,
		EAPL("aka_subtype_Challenge"),
		(get_is_client()) ? EAPL("client") : EAPL("server"),
		get_state(),
		get_state_string()
		));


	eap_variable_data_c checkcode_digest(m_am_tools);
	if (checkcode_digest.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = eap_status_process_general_error;

	status = checkcode_final(
		&checkcode_digest);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	eap_buf_chain_wr_c aka_initial_reply(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (aka_initial_reply.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means AKA does process every re-transmitted EAP-Request.
		aka_initial_reply.set_do_packet_retransmission(false);
	}

	EAP_ASSERT_ALWAYS(EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH >= (m_aka_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_aka_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_aka_header_offset+m_MTU;
	}

	aka_header_c aka_response(
		m_am_tools,
		aka_initial_reply.get_data_offset(
			m_aka_header_offset,
			(packet_buffer_free-m_aka_header_offset)),
		(packet_buffer_free-m_aka_header_offset));

	if (aka_response.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}


	aka_response.reset_header(
		packet_buffer_free,
		m_use_eap_expanded_type);
	aka_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_code(eap_code_response);
	aka_response.set_identifier(get_last_eap_identifier());
	aka_response.set_type(
		eap_type_aka,
		m_use_eap_expanded_type);
	aka_response.set_subtype(aka_subtype_Challenge);

	update_buffer_indexes(
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		m_aka_header_offset+aka_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_type_aka_c::send_challenge_response_message(0x%08x).\n"),
		this));

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t aka_data_free = packet_buffer_free;
	u32_t aka_data_offset = 0u;

	u8_t *MAC_data = 0;
	u32_t MAC_data_length = 0u;
	eap_type_aka_MAC_attributes_c MAC_attributes;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_use_result_indication == true)
	{
		// We support use of protected success indications.
		status = add_simple_payload(
			&aka_response,
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			aka_payload_AT_RESULT_IND);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_variable_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		&checkcode_digest,
		aka_payload_AT_CHECKCODE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_RES_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		get_authentication_vector()->get_RES(),
		aka_payload_AT_RES);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_mac_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		&MAC_data,
		&MAC_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	aka_response.set_data_length(
		aka_data_offset,
		m_use_eap_expanded_type);
	aka_initial_reply.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
		== packet_buffer_offset);

	// -   -   -   -   -   -   -   -   -   -   -   -

	MAC_attributes.init(
		MAC_data,
		MAC_data_length,
		aka_response.get_header_buffer(aka_response.get_length()),
		aka_response.get_length());

	status = create_message_authentication_code(
		&MAC_attributes,
		aka_response.get_subtype(),
		aka_response.get_code(),
		K_aut);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	aka_response.set_data_length(
		aka_data_offset,
		m_use_eap_expanded_type);
	aka_initial_reply.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
		== packet_buffer_offset);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = packet_send(
		get_send_network_id(),
		&aka_initial_reply,
		m_aka_header_offset,
		aka_response.get_header_length()+aka_response.get_data_length(),
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH
		);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::send_reauthentication_response_message(
	const eap_variable_data_c * const orig_XKEY,
	const eap_variable_data_c * const orig_K_aut,
	const eap_variable_data_c * const orig_K_encr,
	const eap_variable_data_c * const reauth_username,
	const eap_variable_data_c * const reauth_nonce_s,
	const u16_t reauth_counter,
	const u8_t eap_identifier,
	const bool include_at_counter_too_small)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("    send: handler 0x%08x, AKA-subtype %10s, %s, state %2d=%s\n"),
		this,
		EAPL("aka_subtype_Re_authentication"),
		EAPL("client"),
		get_state(),
		get_state_string()
		));


	eap_variable_data_c checkcode_digest(m_am_tools);
	if (checkcode_digest.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = eap_status_process_general_error;

	status = checkcode_final(
		&checkcode_digest);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	eap_buf_chain_wr_c request_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (request_packet.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means AKA does process every re-transmitted EAP-Request.
		request_packet.set_do_packet_retransmission(false);
	}

	EAP_ASSERT_ALWAYS(EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH >= (m_aka_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_aka_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_aka_header_offset+m_MTU;
	}

	aka_header_c aka_response(
		m_am_tools,
		request_packet.get_data_offset(
			m_aka_header_offset,
			(packet_buffer_free-m_aka_header_offset)),
		(packet_buffer_free-m_aka_header_offset));

	if (aka_response.get_is_valid() == false)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("send_reauthentication_response_message: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	aka_response.reset_header(
		packet_buffer_free-m_aka_header_offset,
		m_use_eap_expanded_type);
	aka_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_aka_header_offset),
		m_use_eap_expanded_type);
	aka_response.set_code(eap_code_response);
	aka_response.set_identifier(eap_identifier);
	aka_response.set_type(
		eap_type_aka,
		m_use_eap_expanded_type);
	aka_response.set_subtype(aka_subtype_Re_authentication);

	update_buffer_indexes(
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		m_aka_header_offset+aka_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::send_reauthentication_response_message(0x%08x).\n"),
		this));

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t aka_data_free = packet_buffer_free;
	u32_t aka_data_offset = 0u;

	eap_variable_data_c master_session_key(m_am_tools);
	if (master_session_key.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = generate_reauth_shared_secred_keys(
		EAP_TYPE_AKA_KEYMAT_SIZE,
		orig_XKEY,
		reauth_counter,
		reauth_username,
		reauth_nonce_s,
		&master_session_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	if (m_use_result_indication == true)
	{
		// We support use of protected success indications.
		status = add_simple_payload(
			&aka_response,
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			aka_payload_AT_RESULT_IND);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_variable_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		&checkcode_digest,
		aka_payload_AT_CHECKCODE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	crypto_aes_c aes(m_am_tools);

	if (aes.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = m_am_type_aka->generate_encryption_IV(
		get_IV()->get_payload_buffer(),
		aes.get_block_size());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = add_variable_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		get_IV()->get_payload_buffer(),
		aka_payload_AT_IV);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	u8_t *MAC_data = 0;
	u32_t MAC_data_length = 0u;
	eap_type_aka_MAC_attributes_c MAC_attributes;

	// Encrypted data.
	{
		aka_payload_AT_header_c gp_encrypted_data(
			m_am_tools,
			aka_response.get_data_offset(
				aka_data_offset, 
				aka_data_free),
			aka_data_free);
		if (gp_encrypted_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		// Initialize the length of encrypted data to maximum length.
		// Later this will be set to correct length.
		gp_encrypted_data.reset_header(aka_payload_AT_header_c::get_max_payload_data_length());
		gp_encrypted_data.set_current_payload(aka_payload_AT_ENCR_DATA);

		update_payload_indexes(
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			gp_encrypted_data.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_offset,
			&packet_buffer_free);

		u32_t encrypted_data_offset_begin = packet_buffer_offset;


		// -   -   -   -   -   -   -   -   -   -   -   -

		if (include_at_counter_too_small == true)
		{
			status = add_simple_payload(
				&aka_response,
				EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
				aka_response.get_header_length(),
				&aka_data_offset,
				&aka_data_free,
				&packet_buffer_free,
				&packet_buffer_offset,
				aka_payload_AT_COUNTER_TOO_SMALL);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// -   -   -   -   -   -   -   -   -   -   -   -

		status = add_counter_payload(
			&aka_response,
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			reauth_counter);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// -   -   -   -   -   -   -   -   -   -   -   -

		status = add_padding_payload(
			&aka_response,
			EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
			aka_response.get_header_length(),
			&aka_data_offset,
			&aka_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			(packet_buffer_offset - encrypted_data_offset_begin) // Length of the plain text.
			);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		gp_encrypted_data.set_data_length(
			static_cast<u16_t>(packet_buffer_offset - encrypted_data_offset_begin));

		// -   -   -   -   -   -   -   -   -   -   -   -

		status = encrypt_DATA_payload(
			gp_encrypted_data.get_data(gp_encrypted_data.get_data_length()),
			gp_encrypted_data.get_data_length(),
			get_IV()->get_payload_buffer(),
			orig_K_encr);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_AKA_TRACE_PAYLOAD("Payload added", &gp_encrypted_data);
	}



	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_mac_payload(
		&aka_response,
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH,
		aka_response.get_header_length(),
		&aka_data_offset,
		&aka_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		&MAC_data,
		&MAC_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	aka_response.set_data_length(
		aka_data_offset,
		m_use_eap_expanded_type);
	request_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
		== packet_buffer_offset);

	// -   -   -   -   -   -   -   -   -   -   -   -

	MAC_attributes.init(
		MAC_data,
		MAC_data_length,
		aka_response.get_header_buffer(aka_response.get_length()),
		aka_response.get_length());

	status = create_message_authentication_code(
		&MAC_attributes,
		aka_response.get_subtype(),
		aka_response.get_code(),
		orig_K_aut);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	aka_response.set_data_length(
		aka_data_offset,
		m_use_eap_expanded_type);
	request_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_aka_header_offset+aka_response.get_header_length()+aka_response.get_data_length()
		== packet_buffer_offset);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::send_reauthentication_request_message()\n")));

	status = packet_send(
		get_send_network_id(),
		&request_packet,
		m_aka_header_offset,
		aka_response.get_header_length()+aka_response.get_data_length(),
		EAP_TYPE_AKA_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		if (include_at_counter_too_small == false)
		{
			status = get_master_session_key()->set_copy_of_buffer(&master_session_key);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}
	else if (include_at_counter_too_small == true)
	{
		// The full authentication must follow.
		m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::decrypt_DATA_payload(
	aka_payloads_c * const p_aka_payloads,
	const eap_variable_data_c * const encryption_key
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	crypto_aes_c aes(m_am_tools);
	crypto_cbc_c cbc_aes(m_am_tools, &aes, false);

	if (cbc_aes.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t aes_key_length = aes.get_key_length();
	if (encryption_key->get_data_length() < aes_key_length)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	if (p_aka_payloads->get_ENCR_DATA()->get_data_length() == 0
		|| (p_aka_payloads->get_ENCR_DATA()->get_data_length() % aes_key_length) != 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	if (p_aka_payloads->get_IV()->get_payload_included() == false
		|| p_aka_payloads->get_IV()->get_data_length() == 0u
		|| encryption_key->get_is_valid_data() == false
		|| encryption_key->get_data_length() == 0u)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	if (p_aka_payloads->get_ENCR_DATA()->get_payload_included() == false
		|| p_aka_payloads->get_ENCR_DATA()->get_data_length() == 0u)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
	}


	status = cbc_aes.set_decryption_key(
		p_aka_payloads->get_IV()->get_data(p_aka_payloads->get_IV()->get_data_length()),
		p_aka_payloads->get_IV()->get_data_length(),
		encryption_key->get_data(encryption_key->get_data_length()),
		aes_key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = cbc_aes.decrypt_data(
		p_aka_payloads->get_ENCR_DATA()->get_data(p_aka_payloads->get_ENCR_DATA()->get_data_length()),
		p_aka_payloads->get_ENCR_DATA()->get_data_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_DATA_payload(
	const aka_subtype_e subtype,
	aka_payloads_c * const p_aka_payloads
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	if (p_aka_payloads->get_ENCR_DATA() == 0
		|| p_aka_payloads->get_ENCR_DATA()->get_data_length() == 0u)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t state_payload_buffer_length = p_aka_payloads->get_ENCR_DATA()->get_data_length();
	const aka_payload_AT_header_c gp_data_payload(
		m_am_tools,
		p_aka_payloads->get_ENCR_DATA()->get_data(state_payload_buffer_length),
		state_payload_buffer_length);

	if (gp_data_payload.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	status = parse_aka_payload(
		&gp_data_payload,
		&state_payload_buffer_length,
		p_aka_payloads,
		subtype);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (p_aka_payloads->get_NEXT_PSEUDONYM()->get_payload_included() == true)
	{
		if (p_aka_payloads->get_padding_payload()->get_payload_included() == true
			&& p_aka_payloads->get_padding_payload()->get_data_length() > 0u)
		{
			crypto_aes_c aes(m_am_tools);
			crypto_cbc_c cbc_aes(m_am_tools, &aes, false);

			if (cbc_aes.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// Check the padding bytes.
			// Must be filled with zero (0x00) bytes.
			status = cbc_aes.check_padding_bytes(
				p_aka_payloads->get_padding_payload()->get_data(p_aka_payloads->get_padding_payload()->get_data_length()),
				p_aka_payloads->get_padding_payload()->get_data_length(),
				0ul);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// AKA AM could store pseudonym to favourite place.
		status = m_am_type_aka->store_pseudonym_id(
			get_send_network_id(),
			p_aka_payloads->get_NEXT_PSEUDONYM()->get_payload_buffer());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (p_aka_payloads->get_NEXT_REAUTH_ID()->get_payload_included() == true)
	{
		if (p_aka_payloads->get_padding_payload()->get_payload_included() == true
			&& p_aka_payloads->get_padding_payload()->get_data_length() > 0u)
		{
			crypto_aes_c aes(m_am_tools);
			crypto_cbc_c cbc_aes(m_am_tools, &aes, false);

			if (cbc_aes.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// Check the padding bytes.
			// Must be filled with zero (0x00) bytes.
			status = cbc_aes.check_padding_bytes(
				p_aka_payloads->get_padding_payload()->get_data(p_aka_payloads->get_padding_payload()->get_data_length()),
				p_aka_payloads->get_padding_payload()->get_data_length(),
				0ul);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// AKA AM could store pseudonym to favourite place.
		status = m_am_type_aka->store_reauthentication_id(
			get_send_network_id(),
			p_aka_payloads->get_NEXT_REAUTH_ID()->get_payload_buffer());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		// AKA AM should remove pseudonym from favourite place.

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_aka_c::handle_DATA_payload(0x%08x): Resets re-authentication identity from database.\n"),
			 this));

		status = m_am_type_aka->store_reauthentication_id(
			get_send_network_id(),
			0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		get_reauthentication_identity()->reset();
	}

	status = eap_status_ok;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_aka_identity_request_message(
	const eap_am_network_id_c * const receive_network_id,
	aka_header_c * const received_aka,
	const u32_t /* aka_packet_length */,
	aka_payloads_c * const p_aka_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	if (get_state() == eap_type_aka_state_waiting_for_aka_identity_request
		|| get_state() == eap_type_aka_state_pseydonym_waiting_for_aka_identity_request
		|| get_state() == eap_type_aka_state_imsi_waiting_for_aka_identity_request
		|| get_state() == eap_type_aka_state_waiting_for_challenge_request
		|| get_state() == eap_type_aka_state_waiting_for_reauth_request)
	{
		// This could be first or retransmission request.

		// Checks the payloads existence.
		if (p_aka_payloads->check_payloads(
				aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
				aka_payloads_c::eap_aka_payload_status_must_not_be, // MAC
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ENCR_DATA
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
				aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
				aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
				aka_payloads_c::eap_aka_payload_status_optional,    // PERMANENT_ID_REQ
				aka_payloads_c::eap_aka_payload_status_optional,    // FULLAUTH_ID_REQ
				aka_payloads_c::eap_aka_payload_status_optional,    // ANY_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IV
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NOTIFICATION
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
				aka_payloads_c::eap_aka_payload_status_must_not_be, // CLIENT_ERROR_CODE
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RESULT_IND
				aka_payloads_c::eap_aka_payload_status_must_not_be  // CHECKCODE
				) == true
			)
		{
			// NOTE, this message is unauthenticated. Anybody could sent this message.

			aka_payload_AT_type_e include_identity_to_aka_identity_response = aka_payload_NONE;


			if ( get_state() == eap_type_aka_state_imsi_waiting_for_aka_identity_request
					|| get_state() == eap_type_aka_state_waiting_for_challenge_request
					|| get_state() == eap_type_aka_state_waiting_for_aka_identity_request
					|| get_state() == eap_type_aka_state_pseydonym_waiting_for_aka_identity_request
					|| get_state() == eap_type_aka_state_waiting_for_reauth_request)
			{
				if ((p_aka_payloads->get_PERMANENT_ID_REQ()->get_payload_included() == true
						&& p_aka_payloads->get_FULLAUTH_ID_REQ()->get_payload_included() == true)
					|| (p_aka_payloads->get_PERMANENT_ID_REQ()->get_payload_included() == true
						&& p_aka_payloads->get_ANY_ID_REQ()->get_payload_included() == true)
					|| (p_aka_payloads->get_FULLAUTH_ID_REQ()->get_payload_included() == true
						&& p_aka_payloads->get_ANY_ID_REQ()->get_payload_included() == true))
				{
					// Only one of these is allowed.
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_AKA_ERROR, 
						(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_request_message(0x%08x), illegal payloads.\n"),
						this));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}
				else if (p_aka_payloads->get_PERMANENT_ID_REQ()->get_payload_included() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message ")
						 EAPL("aka_payload_AT_PERMANENT_ID_REQ\n")));
					// Note, this is optional, included only when pseudonym decode failed in server.
					include_identity_to_aka_identity_response = aka_payload_AT_PERMANENT_ID_REQ;
				}
				else if (p_aka_payloads->get_FULLAUTH_ID_REQ()->get_payload_included() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message ")
						 EAPL("aka_payload_AT_FULLAUTH_ID_REQ\n")));
					// Note, this is optional, included only when reauthentication identity decode failed in server.
					include_identity_to_aka_identity_response = aka_payload_AT_FULLAUTH_ID_REQ;
				}
				else if (p_aka_payloads->get_ANY_ID_REQ()->get_payload_included() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message ")
						 EAPL("aka_payload_AT_ANY_ID_REQ\n")));
					// Note, this is optional, included only when server have no identity of client.
					include_identity_to_aka_identity_response = aka_payload_AT_ANY_ID_REQ;
				}
			}

			set_include_identity_to_aka_identity_response(include_identity_to_aka_identity_response);

			if (include_identity_to_aka_identity_response == aka_payload_NONE
				&& (get_identity() == 0
				 || get_identity()->get_is_valid_data() == false))
			{
				// We must query the previous sent EAP-Identity from EAP_Core.
				// The EAP_Core saves the sent EAP-Identity when the EAP-Identity is
				// sent to the network.
				// Previous EAP-type was NOT this instance. EAP-Identity was queried from other instance.
				status = get_type_partner()->get_saved_eap_identity(get_identity());
				if (status != eap_status_ok)
				{
					// We do not have the identity server accepted anymore.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = get_NAI()->set_copy_of_buffer(get_identity());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}


			status = checkcode_save_message_client(
				received_aka->get_header_buffer(
					received_aka->get_header_length()
					+received_aka->get_data_length()),
				received_aka->get_header_length()
				+received_aka->get_data_length(),
				p_aka_payloads);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (include_identity_to_aka_identity_response == aka_payload_AT_ANY_ID_REQ
				&& (get_reauthentication_identity()->get_is_valid_data() == false
					&& get_pseudonym()->get_is_valid_data() == false
					&& get_IMSI()->get_is_valid_data() == false
					&& m_automatic_realm_read == false))
			{
				eap_variable_data_c IMSI(m_am_tools);
				eap_variable_data_c pseudonym(m_am_tools);
				eap_variable_data_c reauthentication_identity(m_am_tools);

				if (IMSI.get_is_valid() == false
					|| pseudonym.get_is_valid() == false
					|| reauthentication_identity.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_type_aka_c::handle_aka_identity_request_message ")
					 EAPL("aka_payload_AT_ANY_ID_REQ\n")));

				status = query_AKA_IMSI_or_pseudonym_or_reauthentication_id(
					&IMSI,
					&pseudonym,
					&reauthentication_identity,
					&m_automatic_realm,
					&m_length_of_mnc,
					false,
					include_identity_to_aka_identity_response,
					eap_type_aka_complete_aka_identity_request,
					received_aka->get_identifier());

				if (status == eap_status_pending_request)
				{
					// This is pending query, that will be completed by complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() call.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else if (status == eap_status_completed_request)
				{
					// This is already completed by complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() call.
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message(): ")
						 EAPL("completed returns eap_type_aka_state_variable_e %d=%s.\n"),
						 get_state(),
						 get_state_string()));

					status = eap_status_ok;
					
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else if (status != eap_status_ok)
				{
					// This is the error case.

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message(): ")
						 EAPL("error returns eap_type_aka_state_variable_e %d=%s.\n"),
						 get_state(),
						 get_state_string()));
					
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				
				if (reauthentication_identity.get_is_valid_data() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message ")
						 EAPL("reauthentication_identity\n")));

					status = get_reauthentication_identity()->set_copy_of_buffer(&reauthentication_identity);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = store_identity(get_reauthentication_identity(), false);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
				else if (pseudonym.get_is_valid_data() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message pseudonym\n")));

					get_reauthentication_identity()->reset();
					status = get_pseudonym()->set_copy_of_buffer(&pseudonym);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = store_identity(get_pseudonym(), false);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
				else if (IMSI.get_is_valid_data() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message IMSI\n")));

					get_reauthentication_identity()->reset();
					get_pseudonym()->reset();
					status = get_IMSI()->set_copy_of_buffer(&IMSI);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = store_identity(get_IMSI(), true);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
			else if (include_identity_to_aka_identity_response == aka_payload_AT_FULLAUTH_ID_REQ
					&& (get_pseudonym()->get_is_valid_data() == false
						&& get_IMSI()->get_is_valid_data() == false
						&& m_automatic_realm_read == false))
			{
				eap_variable_data_c IMSI(m_am_tools);
				eap_variable_data_c pseudonym(m_am_tools);
				eap_variable_data_c reauthentication_identity(m_am_tools);

				if (IMSI.get_is_valid() == false
					|| pseudonym.get_is_valid() == false
					|| reauthentication_identity.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_type_aka_c::handle_aka_identity_request_message ")
					 EAPL("aka_payload_AT_FULLAUTH_ID_REQ\n")));

				status = query_AKA_IMSI_or_pseudonym_or_reauthentication_id(
					&IMSI,
					&pseudonym,
					&reauthentication_identity,
					&m_automatic_realm,
					&m_length_of_mnc,
					false,
					include_identity_to_aka_identity_response,
					eap_type_aka_complete_aka_identity_request,
					received_aka->get_identifier());

				if (status == eap_status_pending_request)
				{
					// This is pending query, that will be completed by complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() call.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else if (status == eap_status_completed_request)
				{
					// This is already completed by complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() call.
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message(): ")
						 EAPL("completed returns eap_type_aka_state_variable_e %d=%s.\n"),
						 get_state(),
						 get_state_string()));

					status = eap_status_ok;

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else if (status != eap_status_ok)
				{
					// This is the error case.

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message(): ")
						 EAPL("error returns eap_type_aka_state_variable_e %d=%s.\n"),
						 get_state(),
						 get_state_string()));
					
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				if (pseudonym.get_is_valid_data() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message pseudonym\n")));

					get_reauthentication_identity()->reset();
					status = get_pseudonym()->set_copy_of_buffer(&pseudonym);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = store_identity(get_pseudonym(), false);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
				else if (IMSI.get_is_valid_data() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message IMSI\n")));

					get_reauthentication_identity()->reset();
					get_pseudonym()->reset();
					status = get_IMSI()->set_copy_of_buffer(&IMSI);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = store_identity(get_IMSI(), true);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
			else if (include_identity_to_aka_identity_response == aka_payload_AT_PERMANENT_ID_REQ
					&& get_IMSI()->get_is_valid_data() == false
					&& m_automatic_realm_read == false)
			{
				eap_variable_data_c IMSI(m_am_tools);
				eap_variable_data_c pseudonym(m_am_tools);
				eap_variable_data_c reauthentication_identity(m_am_tools);

				if (IMSI.get_is_valid() == false
					|| pseudonym.get_is_valid() == false
					|| reauthentication_identity.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_type_aka_c::handle_aka_identity_request_message ")
					 EAPL("aka_payload_AT_PERMANENT_ID_REQ\n")));

				status = query_AKA_IMSI_or_pseudonym_or_reauthentication_id(
					&IMSI,
					&pseudonym,
					&reauthentication_identity,
					&m_automatic_realm,
					&m_length_of_mnc,
					false,
					include_identity_to_aka_identity_response,
					eap_type_aka_complete_aka_identity_request,
					received_aka->get_identifier());

				if (status == eap_status_pending_request)
				{
					// This is pending query, that will be completed by complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() call.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else if (status == eap_status_completed_request)
				{
					// This is already completed by complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() call.
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message(): ")
						 EAPL("completed returns eap_type_aka_state_variable_e %d=%s.\n"),
						 get_state(),
						 get_state_string()));
					
					status = eap_status_ok;

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else if (status != eap_status_ok)
				{
					// This is the error case.

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message(): ")
						 EAPL("error returns eap_type_aka_state_variable_e %d=%s.\n"),
						 get_state(),
						 get_state_string()));
					
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				if (IMSI.get_is_valid_data() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_identity_request_message IMSI\n")));

					get_reauthentication_identity()->reset();
					get_pseudonym()->reset();
					status = get_IMSI()->set_copy_of_buffer(&IMSI);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = store_identity(get_IMSI(), true);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
				else
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}


			save_current_state();
			set_state(eap_type_aka_state_analyse_aka_identity_request);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::handle_aka_identity_request_message(0x%08x).\n"),
				 this));

			status = send_aka_identity_response_message(
				receive_network_id,
				received_aka->get_identifier(),
				include_identity_to_aka_identity_response,
				&m_automatic_realm);

			if (status != eap_status_ok)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			// Not correct AKA-payloads are included.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_request_message(1): ")
				 EAPL("Not correct AKA-payloads are included in eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_aka_identity_request_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_aka_notification_request_message_reauthentication(
	const eap_am_network_id_c * const receive_network_id,
	aka_header_c * const received_aka,
	const u32_t /*aka_packet_length*/,
	aka_payloads_c * const p_aka_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: handler 0x%08x, AKA-type %10s, %s, state %2d=%s\n"),
		 this,
		 EAPL("handle_aka_notification_request_message_reauthentication"),
		 (get_is_client()) ? EAPL("client") : EAPL("server"),
		 get_state(),
		 get_state_string()
		 ));

	// The second most significant bit of the notification code is called
	// the Phase bit (P bit). It specifies at which phase of the EAP-AKA
	// exchange the notification can be used.
	if (get_aka_notification_code_P_bit(m_aka_notification_code) == false
		&& (get_state() == eap_type_aka_state_waiting_for_success
			|| get_state() == eap_type_aka_state_success
			|| get_state() == eap_type_aka_state_waiting_for_notification_request_success)
		)
	{
		// If the P bit is set to zero,
		// the notification can only be used after a successful EAP/AKA/
		// Challenge round in full authentication or a successful EAP/AKA/
		// Re-authentication round in reautentication. A re-authentication round
		// is considered successful only if the peer has successfully verified
		// AT_MAC and AT_COUNTER attributes, and does not include the
		// AT_COUNTER_TOO_SMALL attribute in EAP-Response/AKA/Re-authentication.

		// The AT_MAC attribute MUST beincluded if the P bit of the notification
		// code in AT_NOTIFICATION is set to zero, and MUST NOT be included in
		// cases when the P bit is set to one. The P bit is discussed in Section
		// 4.4.
		if (p_aka_payloads->check_payloads(
				aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
				aka_payloads_c::eap_aka_payload_status_must_be,     // MAC
				aka_payloads_c::eap_aka_payload_status_must_be,     // ENCR_DATA
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
				aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
				aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
				aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_be,     // IV
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
				aka_payloads_c::eap_aka_payload_status_must_be,     // NOTIFICATION
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
				aka_payloads_c::eap_aka_payload_status_must_not_be, // CLIENT_ERROR_CODE
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RESULT_IND
				aka_payloads_c::eap_aka_payload_status_must_not_be  // CHECKCODE
				) == true
			)
		{
			eap_variable_data_c orig_XKEY(m_am_tools);
			eap_variable_data_c orig_K_aut(m_am_tools);
			eap_variable_data_c orig_K_encr(m_am_tools);

			if (orig_XKEY.get_is_valid() == false
				|| orig_K_aut.get_is_valid() == false
				|| orig_K_encr.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u32_t reauth_counter = 0u;

			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_aka->query_reauth_parameters(
				&orig_XKEY,
				&orig_K_aut,
				&orig_K_encr,
				&reauth_counter);
			if (status != eap_status_ok)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = check_message_authentication_code(
				&orig_K_aut,
				p_aka_payloads,
				received_aka,
				received_aka->get_length());
			if (status != eap_status_ok)
			{
				(void) initialize_error_message(status);

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			bool authentication_ok = true;

			// Decrypt and parse encrypted payload.
			{
				aka_payloads_c * const l_aka_payloads = new aka_payloads_c(m_am_tools);
				eap_automatic_variable_c<aka_payloads_c> l_aka_payloads_automatic(m_am_tools, l_aka_payloads);

				if (l_aka_payloads == 0
					|| l_aka_payloads->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = decrypt_DATA_payload(
					p_aka_payloads,
					&orig_K_encr);
				if (status != eap_status_ok)
				{
					restore_saved_previous_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				u32_t state_payload_buffer_length = p_aka_payloads->get_ENCR_DATA()->get_data_length();
				const aka_payload_AT_header_c gp_data_payload(
					m_am_tools,
					p_aka_payloads->get_ENCR_DATA()->get_data(state_payload_buffer_length),
					state_payload_buffer_length);

				status = parse_aka_payload(
					&gp_data_payload,
					&state_payload_buffer_length,
					l_aka_payloads,
					received_aka->get_subtype());
				if (status != eap_status_ok)
				{
					restore_saved_previous_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}


				if (l_aka_payloads->get_COUNTER()->get_payload_included() == false)
				{
					restore_saved_previous_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
				}

				u32_t counter = l_aka_payloads->get_COUNTER()->get_original_header()->get_reserved();

				if (counter == reauth_counter)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_aka_notification_request_message_reauthentication(): ")
						EAPL("reauth counter %d OK, %d=%s.\n"),
						reauth_counter,
						get_state(),
						get_state_string()));
				}
				else
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_AKA_ERROR, 
						(EAPL("ERROR: eap_type_aka_c::handle_aka_notification_request_message_reauthentication(): ")
						EAPL("reauth counter %d wrong, should be %d, %d=%s.\n"),
						counter,
						reauth_counter,
						get_state(),
						get_state_string()));

					authentication_ok = false;
				}
			}

			// The most significant bit is called the Failure bit (F bit).
			// The F bit specifies whether the notification implies failure.
			if (authentication_ok == false
				|| get_aka_notification_code_F_bit(m_aka_notification_code) == false)
			{
				// The code values with the F bit set to zero (code values 0...32767)
				// are used on unsuccessful cases.
				// The receipt of a notification code from this range implies failed EAP
				// exchange, so the peer can use the notification as a failure indication.

				set_state(eap_type_aka_state_failure);

				// This will terminate session immediately.
				(void) get_type_partner()->set_session_timeout(0ul);
			}


			// EAP-Response/AKA-Notification must be send
			// before finish_successful_authentication() call.
			status = send_aka_notification_response(
				m_aka_notification_code,
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}


			if (authentication_ok == true
				&& get_aka_notification_code_F_bit(m_aka_notification_code) == true)
			{
				// The receipt of a notification code with the F bit set to one (values
				// 32768...65536) does not imply failure. Notification code 32768 has
				// been reserved as a general notification code to indicate successful
				// authentication.
				if (m_aka_notification_code == eap_aka_notification_F_set_no_P_user_authenticated)
				{
					if (m_wait_eap_success_packet == false)
					{
						status = finish_successful_authentication(
							receive_network_id);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
					else
					{
						// This version waits the EAP-Success message.
						set_state(eap_type_aka_state_waiting_for_success);
						status = eap_status_ok;

						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
							(EAPL("EAP_type_AKA: %s, re-authentication OK, waits EAP-Success\n"),
							 (m_is_client == true) ? "client": "server"));
					}
				}
			}

		}
		else
		{
			// Not correct AKA-payloads are included.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_aka_notification_request_message(1): ")
				EAPL("Not correct AKA-payloads are included in eap_type_aka_state_variable_e %d=%s.\n"),
				get_state(),
				get_state_string()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
	}
	else if (get_aka_notification_code_P_bit(m_aka_notification_code) == true
		&& (get_state() == eap_type_aka_state_waiting_for_identity_request
			|| get_state() == eap_type_aka_state_pending_identity_query
			|| get_state() == eap_type_aka_state_waiting_for_aka_identity_request
			|| get_state() == eap_type_aka_state_imsi_waiting_for_aka_identity_request
			|| get_state() == eap_type_aka_state_pseydonym_waiting_for_aka_identity_request
			|| get_state() == eap_type_aka_state_analyse_aka_identity_request
			|| get_state() == eap_type_aka_state_waiting_for_challenge_request
			|| get_state() == eap_type_aka_state_analyses_challenge_request
			|| get_state() == eap_type_aka_state_pending_kc_sres_query
			|| get_state() == eap_type_aka_state_waiting_for_reauth_request
			|| get_state() == eap_type_aka_state_analyses_reauthentication_request
			|| get_state() == eap_type_aka_state_waiting_for_success
			|| get_state() == eap_type_aka_state_success
			|| get_state() == eap_type_aka_state_waiting_for_notification_request_success
			|| get_state() == eap_type_aka_state_failure))
	{
		// If the P bit is set to one, the notification can only by used before
		// the EAP/AKA/Challenge round in full authentication, or before the
		// EAP/AKA/Re-authentication round in reauthentication.

		// The most significant bit is called the Failure bit (F bit).
		// The F bit specifies whether the notification implies failure.
		if (get_aka_notification_code_F_bit(m_aka_notification_code) == false)
		{
			// The code values with the F bit set to zero (code values 0...32767)
			// are used on unsuccessful cases.
			// The receipt of a notification code from this range implies failed EAP
			// exchange, so the peer can use the notification as a failure indication.
		}
		else //if (get_aka_notification_code_F_bit(m_aka_notification_code) == true)
		{
			// The receipt of a notification code with the F bit set to one (values
			// 32768...65536) does not imply failure. Notification code 32768 has
			// been reserved as a general notification code to indicate successful
			// authentication.
		}

		status = initialize_notification_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_aka_notification_request_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_aka_notification_request_message_full_authentication(
	const eap_am_network_id_c * const receive_network_id,
	aka_header_c * const received_aka,
	const u32_t /*aka_packet_length*/,
	aka_payloads_c * const p_aka_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: handler 0x%08x, AKA-type %10s, %s, state %2d=%s\n"),
		 this,
		 EAPL("handle_aka_notification_request_message_full_authentication"),
		 (get_is_client()) ? EAPL("client") : EAPL("server"),
		 get_state(),
		 get_state_string()
		 ));

	// The second most significant bit of the notification code is called
	// the Phase bit (P bit). It specifies at which phase of the EAP-AKA
	// exchange the notification can be used.
	if (get_aka_notification_code_P_bit(m_aka_notification_code) == false
		&& (get_state() == eap_type_aka_state_waiting_for_success
			|| get_state() == eap_type_aka_state_success
			|| get_state() == eap_type_aka_state_waiting_for_notification_request_success)
		)
	{
		// If the P bit is set to zero,
		// the notification can only be used after a successful EAP/AKA/
		// Challenge round in full authentication or a successful EAP/AKA/
		// Re-authentication round in reautentication. A re-authentication round
		// is considered successful only if the peer has successfully verified
		// AT_MAC and AT_COUNTER attributes, and does not include the
		// AT_COUNTER_TOO_SMALL attribute in EAP-Response/AKA/Re-authentication.

		// The AT_MAC attribute MUST beincluded if the P bit of the notification
		// code in AT_NOTIFICATION is set to zero, and MUST NOT be included in
		// cases when the P bit is set to one. The P bit is discussed in Section
		// 4.4.
		if (p_aka_payloads->check_payloads(
				aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
				aka_payloads_c::eap_aka_payload_status_must_be,     // MAC
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ENCR_DATA
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
				aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
				aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
				aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IV
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
				aka_payloads_c::eap_aka_payload_status_must_be,     // NOTIFICATION
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
				aka_payloads_c::eap_aka_payload_status_must_not_be, // CLIENT_ERROR_CODE
				aka_payloads_c::eap_aka_payload_status_optional,    // RESULT_IND
				aka_payloads_c::eap_aka_payload_status_must_not_be  // CHECKCODE
				) == true
			)
		{
			status = check_message_authentication_code(
				get_K_aut(),
				p_aka_payloads,
				received_aka,
				received_aka->get_length());
			if (status != eap_status_ok)
			{
				(void) initialize_error_message(status);

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (m_use_result_indication == false
				&& m_aka_notification_code == eap_aka_notification_F_set_no_P_user_authenticated)
			{
				// ERROR: We did not require result indication and server send it to us.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			// The most significant bit is called the Failure bit (F bit).
			// The F bit specifies whether the notification implies failure.
			if (get_aka_notification_code_F_bit(m_aka_notification_code) == false)
			{
				// The code values with the F bit set to zero (code values 0...32767)
				// are used on unsuccessful cases.
				// The receipt of a notification code from this range implies failed EAP
				// exchange, so the peer can use the notification as a failure indication.

				set_state(eap_type_aka_state_failure);

				// This will terminate session immediately.
				(void) get_type_partner()->set_session_timeout(0ul);
			}
			else //if (get_aka_notification_code_F_bit(m_aka_notification_code) == true)
			{
				// The receipt of a notification code with the F bit set to one (values
				// 32768...65536) does not imply failure. Notification code 32768 has
				// been reserved as a general notification code to indicate successful
				// authentication.
				if (m_aka_notification_code == eap_aka_notification_F_set_no_P_user_authenticated)
				{
					if (m_wait_eap_success_packet == false)
					{
						status = finish_successful_authentication(
							receive_network_id);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
					else
					{
						// This version waits the EAP-Success message.
						set_state(eap_type_aka_state_waiting_for_success);
						status = eap_status_ok;

						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
							(EAPL("EAP_type_AKA: %s, full-authentication OK, waits EAP-Success\n"),
							 (m_is_client == true) ? "client": "server"));
					}
				}
			}

			status = send_aka_notification_response(
				m_aka_notification_code,
				false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			// Not correct AKA-payloads are included.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_aka_notification_request_message(1): ")
				EAPL("Not correct AKA-payloads are included in eap_type_aka_state_variable_e %d=%s.\n"),
				get_state(),
				get_state_string()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
	}
	else if (get_aka_notification_code_P_bit(m_aka_notification_code) == true
		&& (get_state() == eap_type_aka_state_waiting_for_identity_request
			|| get_state() == eap_type_aka_state_pending_identity_query
			|| get_state() == eap_type_aka_state_waiting_for_aka_identity_request
			|| get_state() == eap_type_aka_state_imsi_waiting_for_aka_identity_request
			|| get_state() == eap_type_aka_state_pseydonym_waiting_for_aka_identity_request
			|| get_state() == eap_type_aka_state_analyse_aka_identity_request
			|| get_state() == eap_type_aka_state_waiting_for_challenge_request
			|| get_state() == eap_type_aka_state_analyses_challenge_request
			|| get_state() == eap_type_aka_state_pending_kc_sres_query
			|| get_state() == eap_type_aka_state_waiting_for_reauth_request
			|| get_state() == eap_type_aka_state_analyses_reauthentication_request
			|| get_state() == eap_type_aka_state_waiting_for_success
			|| get_state() == eap_type_aka_state_success
			|| get_state() == eap_type_aka_state_waiting_for_notification_request_success
			|| get_state() == eap_type_aka_state_failure))
	{
		// If the P bit is set to one, the notification can only by used before
		// the EAP/AKA/Challenge round in full authentication, or before the
		// EAP/AKA/Re-authentication round in reauthentication.

		// The most significant bit is called the Failure bit (F bit).
		// The F bit specifies whether the notification implies failure.
		if (get_aka_notification_code_F_bit(m_aka_notification_code) == false)
		{
			// The code values with the F bit set to zero (code values 0...32767)
			// are used on unsuccessful cases.
			// The receipt of a notification code from this range implies failed EAP
			// exchange, so the peer can use the notification as a failure indication.
		}
		else //if (get_aka_notification_code_F_bit(m_aka_notification_code) == true)
		{
			// The receipt of a notification code with the F bit set to one (values
			// 32768...65536) does not imply failure. Notification code 32768 has
			// been reserved as a general notification code to indicate successful
			// authentication.
		}

		status = initialize_notification_message();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_aka_notification_request_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_aka_notification_request_message(
	const eap_am_network_id_c * const receive_network_id,
	aka_header_c * const received_aka,
	const u32_t aka_packet_length,
	aka_payloads_c * const p_aka_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_UNREFERENCED_PARAMETER(received_aka);
	EAP_UNREFERENCED_PARAMETER(aka_packet_length);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

	if (get_state() == eap_type_aka_state_waiting_for_identity_request
		|| get_state() == eap_type_aka_state_pending_identity_query
		|| get_state() == eap_type_aka_state_waiting_for_aka_identity_request
		|| get_state() == eap_type_aka_state_imsi_waiting_for_aka_identity_request
		|| get_state() == eap_type_aka_state_pseydonym_waiting_for_aka_identity_request
		|| get_state() == eap_type_aka_state_analyse_aka_identity_request
		|| get_state() == eap_type_aka_state_waiting_for_challenge_request
		|| get_state() == eap_type_aka_state_analyses_challenge_request
		|| get_state() == eap_type_aka_state_pending_kc_sres_query
		|| get_state() == eap_type_aka_state_waiting_for_notification_request_success
		|| get_state() == eap_type_aka_state_waiting_for_success
		|| get_state() == eap_type_aka_state_waiting_for_reauth_request
		|| get_state() == eap_type_aka_state_analyses_reauthentication_request
		|| get_state() == eap_type_aka_state_success
		|| get_state() == eap_type_aka_state_failure
	)
	{
		// This could be first or retransmission request.

		// Checks the payloads existence.
		if (p_aka_payloads->check_payloads(
				aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
				aka_payloads_c::eap_aka_payload_status_optional,    // MAC
				aka_payloads_c::eap_aka_payload_status_optional,    // ENCR_DATA
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
				aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
				aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
				aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
				aka_payloads_c::eap_aka_payload_status_optional,    // IV
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
				aka_payloads_c::eap_aka_payload_status_must_be,     // NOTIFICATION
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
				aka_payloads_c::eap_aka_payload_status_must_not_be, // CLIENT_ERROR_CODE
				aka_payloads_c::eap_aka_payload_status_optional,    // RESULT_IND
				aka_payloads_c::eap_aka_payload_status_must_not_be  // CHECKCODE
				) == true
			)
		{
			// NOTE, this message is unauthenticated. Anybody could sent this message.

			// We store the received notification code. This will be handled after session timeouts.
			m_aka_notification_code =
				static_cast<eap_aka_notification_codes_e>(
					p_aka_payloads->get_NOTIFICATION()->get_original_header()->get_reserved());

			save_current_state();

			set_last_eap_identifier(received_aka->get_identifier());

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::handle_aka_notification_request_message(0x%08x), ")
				 EAPL("notification_code = 0x%04x, F bit %d, P bit %d, state %d=%s.\n"),
				 this,
				 m_aka_notification_code,
				 get_aka_notification_code_F_bit(m_aka_notification_code),
				 get_aka_notification_code_P_bit(m_aka_notification_code),
				 get_state(),
				 get_state_string()));

			if (m_authentication_type == AKA_AUTHENTICATION_TYPE_REAUTHENTICATION)
			{
				status = handle_aka_notification_request_message_reauthentication(
					receive_network_id,
					received_aka,
					aka_packet_length,
					p_aka_payloads);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				status = handle_aka_notification_request_message_full_authentication(
					receive_network_id,
					received_aka,
					aka_packet_length,
					p_aka_payloads);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		else
		{
			// Not correct AKA-payloads are included.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_aka_notification_request_message(1): ")
				EAPL("Not correct AKA-payloads are included in eap_type_aka_state_variable_e %d=%s.\n"),
				get_state(),
				get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_aka_notification_request_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_challenge_request_message(
	const eap_am_network_id_c * const /* receive_network_id */,
	aka_header_c * const received_aka,
	const u32_t aka_packet_length,
	aka_payloads_c * const p_aka_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	if (get_state() == eap_type_aka_state_waiting_for_challenge_request
		|| get_state() == eap_type_aka_state_waiting_for_reauth_request // Server could start full authentication.
		|| (get_state() == eap_type_aka_state_waiting_for_success && m_use_result_indication == false)
		|| (get_state() == eap_type_aka_state_waiting_for_notification_request_success && m_use_result_indication == true))
	{
		// This could be first or retransmission request.

		// Checks the payloads existence.
		if (p_aka_payloads->check_payloads(
				aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
				aka_payloads_c::eap_aka_payload_status_must_be,     // MAC
				aka_payloads_c::eap_aka_payload_status_optional,    // ENCR_DATA
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
				aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
				aka_payloads_c::eap_aka_payload_status_must_be,     // n_RANDs
				aka_payloads_c::eap_aka_payload_status_must_be,     // AUTN
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
				aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
				aka_payloads_c::eap_aka_payload_status_optional,    // IV
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NOTIFICATION
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
				aka_payloads_c::eap_aka_payload_status_must_not_be, // CLIENT_ERROR_CODE
				aka_payloads_c::eap_aka_payload_status_optional,    // RESULT_IND
				aka_payloads_c::eap_aka_payload_status_optional     // CHECKCODE
				) == true
			)
		{
			if (p_aka_payloads->get_RESULT_IND()->get_payload_included() == true)
			{
				m_use_result_indication = m_allow_use_result_indication;
			}
			else
			{
				m_use_result_indication = false;
			}

			if (p_aka_payloads->get_IV()->get_payload_included() == true
			|| p_aka_payloads->get_ENCR_DATA()->get_payload_included() == true)
			{
				if (p_aka_payloads->get_IV()->get_payload_included() == true
				&& p_aka_payloads->get_ENCR_DATA()->get_payload_included() == true)
				{
					// OK
				}
				else
				{
					// All of these must be included
					// or none of these must be included.
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
				}
			}

			// The whole EAP packet must copied.
			// The MAC is checked later after n*Kc and n*SRES is get from AKA.
			status = get_saved_EAP_packet()->set_copy_of_buffer(
				received_aka->get_header_buffer(aka_packet_length),
				aka_packet_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (p_aka_payloads->get_CHECKCODE()->get_payload_included() == true)
			{
				// Save AT_CHECKCODE.
				status = m_received_checkcode.set_copy_of_buffer(
					p_aka_payloads->get_CHECKCODE()->get_payload_buffer());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			if (get_state() == eap_type_aka_state_waiting_for_reauth_request)
			{
				// Server started a full authentication.
				m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;
			}

			set_last_eap_identifier(received_aka->get_identifier());

			save_current_state();
			set_state(eap_type_aka_state_analyses_challenge_request);

			// - - - - - - - - - - - - - - - - - - - - - - - -

			eap_variable_data_c CK(m_am_tools);
			eap_variable_data_c IK(m_am_tools);
			eap_variable_data_c RES(m_am_tools);

			if (CK.get_is_valid() == false
				|| IK.get_is_valid() == false
				|| RES.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			eap_type_aka_authentication_vector_c authentication_vector(m_am_tools);

			if (authentication_vector.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = authentication_vector.get_RAND()->set_copy_of_buffer(
				p_aka_payloads->get_RAND()->get_payload_buffer());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = authentication_vector.get_AUTN()->set_copy_of_buffer(
				p_aka_payloads->get_AUTN()->get_payload_buffer());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = query_AKA_RES(
				&authentication_vector);
			if (status == eap_status_pending_request)
			{
				// Request will be completed later using complete_AKA_RES_query() function.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
			else if (status == eap_status_completed_request)
			{
				// Request was already completed by AM using complete_AKA_RES_query() function.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
			else if (status == eap_status_success)
			{
				// eap_status_success means the authentication was successful.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else if (status == eap_status_ok)
			{
				// The query_AKA_RES() function call is synchronous.
				// We must call process_AKA_kc_sres().
			}
			else
			{
				// This is an error case.
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// eap_status_ok status value means n_kc and n_sres were read but not processed.
			// Next we must call process_AKA_kc_sres().

			// - - - - - - - - - - - - - - - - - - - - - - - -

			status = process_AKA_kc_sres(
				&authentication_vector);

			if (status != eap_status_ok
				&& status != eap_status_success)
			{
				(void) initialize_error_message(status);

				restore_saved_previous_state();
			}

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			// Not correct AKA-payloads are included.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_challenge_request_message(6): ")
				 EAPL("Not correct AKA-payloads are included in eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else if (get_state() == eap_type_aka_state_pending_kc_sres_query)
	{
		// This is re-transmitted EAP-Request/AKA/Challenge.
		// We dischard it quietly.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eap_type_aka_c::handle_challenge_request_message(): ")
			 EAPL("Re-transmitted message %d=%s dropped in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_challenge_request_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_reauthentication_request_message(
	const eap_am_network_id_c * const receive_network_id,
	aka_header_c * const received_aka,
	const u32_t aka_packet_length,
	aka_payloads_c * const p_aka_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	if (get_state() == eap_type_aka_state_waiting_for_reauth_request
		|| (get_state() == eap_type_aka_state_waiting_for_success && m_use_result_indication == false)
		|| (get_state() == eap_type_aka_state_waiting_for_notification_request_success && m_use_result_indication == true))
	{
		// This could be first or retransmission request.

		// Checks the payloads existence.
		if (p_aka_payloads->check_payloads(
				aka_payloads_c::eap_aka_payload_status_must_not_be, // nonce_s
				aka_payloads_c::eap_aka_payload_status_must_be,     // MAC
				aka_payloads_c::eap_aka_payload_status_must_be,     // ENCR_DATA
				aka_payloads_c::eap_aka_payload_status_must_not_be, // IDENTITY
				aka_payloads_c::eap_aka_payload_status_must_not_be, // padding
				aka_payloads_c::eap_aka_payload_status_must_not_be, // n_RANDs
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTN
				aka_payloads_c::eap_aka_payload_status_must_not_be, // AUTS
				aka_payloads_c::eap_aka_payload_status_must_not_be, // RES
				aka_payloads_c::eap_aka_payload_status_must_not_be, // PERMANENT_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // FULLAUTH_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_not_be, // ANY_ID_REQ
				aka_payloads_c::eap_aka_payload_status_must_be,     // IV
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_PSEUDONYM
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NEXT_REAUTH_ID
				aka_payloads_c::eap_aka_payload_status_must_not_be, // NOTIFICATION
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER
				aka_payloads_c::eap_aka_payload_status_must_not_be, // COUNTER_TOO_SMALL
				aka_payloads_c::eap_aka_payload_status_must_not_be, // CLIENT_ERROR_CODE
				aka_payloads_c::eap_aka_payload_status_optional,    // RESULT_IND
				aka_payloads_c::eap_aka_payload_status_optional     // CHECKCODE
				) == true
			)
		{

			set_last_eap_identifier(received_aka->get_identifier());

			save_current_state();
			set_state(eap_type_aka_state_analyses_reauthentication_request);

			// - - - - - - - - - - - - - - - - - - - - - - - -

			eap_variable_data_c orig_XKEY(m_am_tools);
			eap_variable_data_c orig_K_aut(m_am_tools);
			eap_variable_data_c orig_K_encr(m_am_tools);

			if (orig_XKEY.get_is_valid() == false
				|| orig_K_aut.get_is_valid() == false
				|| orig_K_encr.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u32_t reauth_counter = 0u;
			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_aka->query_reauth_parameters(
				&orig_XKEY,
				&orig_K_aut,
				&orig_K_encr,
				&reauth_counter);
			if (status != eap_status_ok)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = check_message_authentication_code(
				&orig_K_aut,
				p_aka_payloads,
				received_aka,
				aka_packet_length);
			if (status != eap_status_ok)
			{
				(void) initialize_error_message(status);

				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (p_aka_payloads->get_CHECKCODE()->get_payload_included() == true)
			{
				// Verify AT_CHECKCODE.
				status = checkcode_verify(
					p_aka_payloads->get_CHECKCODE()->get_payload_buffer());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			if (p_aka_payloads->get_RESULT_IND()->get_payload_included() == true)
			{
				m_use_result_indication = m_allow_use_result_indication;
			}
			else
			{
				m_use_result_indication = false;
			}

			// Decrypt and parse encrypted payload.
			if (p_aka_payloads->get_IV()->get_payload_included() == true
			|| p_aka_payloads->get_ENCR_DATA()->get_payload_included() == true)
			{
				if (p_aka_payloads->get_IV()->get_payload_included() == true
				&& p_aka_payloads->get_ENCR_DATA()->get_payload_included() == true
				&& p_aka_payloads->get_MAC()->get_payload_included() == true)
				{
					aka_payloads_c * const l_aka_payloads = new aka_payloads_c(m_am_tools);
					eap_automatic_variable_c<aka_payloads_c> l_aka_payloads_automatic(m_am_tools, l_aka_payloads);

					if (l_aka_payloads == 0
						|| l_aka_payloads->get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					bool include_at_counter_too_small = false;

					status = decrypt_DATA_payload(
						p_aka_payloads,
						&orig_K_encr);
					if (status != eap_status_ok)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					u32_t state_payload_buffer_length = p_aka_payloads->get_ENCR_DATA()->get_data_length();
					const aka_payload_AT_header_c gp_data_payload(
						m_am_tools,
						p_aka_payloads->get_ENCR_DATA()->get_data(state_payload_buffer_length),
						state_payload_buffer_length);

					status = parse_aka_payload(
						&gp_data_payload,
						&state_payload_buffer_length,
						l_aka_payloads,
						received_aka->get_subtype());
					if (status != eap_status_ok)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}


					if (l_aka_payloads->get_COUNTER()->get_payload_included() == false
						|| l_aka_payloads->get_NONCE_S()->get_payload_included() == false)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
					}

					u32_t counter = l_aka_payloads->get_COUNTER()->get_original_header()->get_reserved();

					if (m_aka_test_version == true
						&& m_fail_reauthentication_counter_check == true)
					{
						--counter;
					}

					if (get_saved_previous_state() == eap_type_aka_state_waiting_for_reauth_request)
					{
						if (counter < reauth_counter)
						{
							// When the client detects that the
							// counter value is not fresh, it includes the AT_COUNTER_TOO_SMALL
							// attribute in EAP-Response/AKA/Re-authentication. This attribute
							// doesn't contain any data but it is a request for the server to
							// initiate full authentication. In this case, the client MUST ignore
							// the contents of the server's AT_NEXT_REAUTH_ID attribute.
							include_at_counter_too_small = true;
							l_aka_payloads->get_NEXT_REAUTH_ID()->reset();
						}
					}
					else if (get_saved_previous_state() == eap_type_aka_state_waiting_for_success
						|| get_state() == eap_type_aka_state_waiting_for_notification_request_success)
					{
						// This is retransmission request.
						if (counter+1ul < reauth_counter)
						{
							// When the client detects that the
							// counter value is not fresh, it includes the AT_COUNTER_TOO_SMALL
							// attribute in EAP-Response/AKA/Re-authentication. This attribute
							// doesn't contain any data but it is a request for the server to
							// initiate full authentication. In this case, the client MUST ignore
							// the contents of the server's AT_NEXT_REAUTH_ID attribute.
							include_at_counter_too_small = true;
							l_aka_payloads->get_NEXT_REAUTH_ID()->reset();
						}
					}

					if (l_aka_payloads->get_NEXT_REAUTH_ID()->get_payload_included() == true)
					{
						// Save next re-authentication identity.
						// AKA AM could store pseudonym to favourite place.
						status = m_am_type_aka->store_reauthentication_id(
							get_send_network_id(),
							l_aka_payloads->get_NEXT_REAUTH_ID()->get_payload_buffer());
						if (status != eap_status_ok)
						{
							restore_saved_previous_state();
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
					else
					{
						// AKA AM should remove re-authentiction ID from favourite place.

						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("eap_type_aka_c::handle_reauthentication_request_message(0x%08x): Resets re-authentication identity from database.\n"),
							 this));

						status = m_am_type_aka->store_reauthentication_id(
							get_send_network_id(),
							0);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						get_reauthentication_identity()->reset();
					}

					status = get_NONCE_S()->set_copy_of_buffer(
						l_aka_payloads->get_NONCE_S()->get_payload_buffer());
					if (status != eap_status_ok)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = send_reauthentication_response_message(
						&orig_XKEY,
						&orig_K_aut,
						&orig_K_encr,
						get_NAI(),
						l_aka_payloads->get_NONCE_S()->get_payload_buffer(),
						static_cast<u16_t>(counter),
						received_aka->get_identifier(),
						include_at_counter_too_small);
					if (status != eap_status_ok)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					// OK, server re-authenticates correcly.

					if (include_at_counter_too_small == true)
					{
						// Re-authentication failed.
						// We will expect full authentication.
						set_state(eap_type_aka_state_waiting_for_aka_identity_request);
						status = eap_status_ok;
					}
					else
					{
						// Authentication was successful.
						if (m_use_result_indication == true)
						{
							// This version waits the result indication.
							set_state(eap_type_aka_state_waiting_for_notification_request_success);
							status = eap_status_ok;

							EAP_TRACE_DEBUG(
								m_am_tools, 
								TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
								(EAPL("EAP_type_AKA: %s, re-authentication OK, waits result indication\n"),
								 (m_is_client == true) ? "client": "server"));
						}
						else if (m_wait_eap_success_packet == false)
						{
							// This version does not wait EAP-Success message.
							status = finish_successful_authentication(
								receive_network_id);
							if (status != eap_status_ok)
							{
								restore_saved_previous_state();
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}
						}
						else
						{
							// This version waits the EAP-Success message.
							set_state(eap_type_aka_state_waiting_for_success);
							status = eap_status_ok;

							EAP_TRACE_DEBUG(
								m_am_tools, 
								TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
								(EAPL("EAP_type_AKA: %s, re-authentication OK, waits EAP-Success\n"),
								 (m_is_client == true) ? "client": "server"));
						}
					}

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else
				{
					// All of these must be included
					// or none of these must be included.
					restore_saved_previous_state();
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
				}
			}
			else
			{
				// Not correct AKA-payloads are included.
				restore_saved_previous_state();
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_AKA_ERROR, 
					(EAPL("ERROR: eap_type_aka_c::handle_reauthentication_request_message(6): ")
					 EAPL("Not correct AKA-payloads are included in eap_type_aka_state_variable_e %d=%s.\n"),
					 get_state(),
					 get_state_string()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}
		}
		else
		{
			// Not correct AKA-payloads are included.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::handle_reauthentication_request_message(6): ")
				 EAPL("Not correct AKA-payloads are included in eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::handle_reauthentication_request_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_aka_state_variable_e %d=%s.\n"),
			 received_aka->get_subtype(),
			 received_aka->get_subtype_string(),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::handle_eap_identity_query(
	const eap_am_network_id_c * const send_network_id,
	eap_variable_data_c * const p_identity,
	const u8_t eap_identifier,
	const eap_variable_data_c * const IMSI,
	const eap_variable_data_c * const pseudonym,
	const eap_variable_data_c * const reauthentication_identity,
	const eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
	const u32_t length_of_mnc,
	const bool must_be_synchronous)
{
	const eap_variable_data_c *current_identity = 0;

	eap_variable_data_c manual_identity(m_am_tools);

	if (manual_identity.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	bool IMSI_is_used = false;
	bool reauth_id_is_used = false;
	eap_status_e status = eap_status_process_general_error;

	if (get_state() != eap_type_aka_state_pending_identity_query)
	{
		// Authentication is state is wrong. Cannot continue.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_gsmsim_state);
	}

	if (must_be_synchronous == true
		&& p_identity == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (IMSI == 0
		|| IMSI->get_is_valid_data() == false
		|| IMSI->get_data_length() < EAP_TYPE_AKA_MINIMUM_IMSI_LENGTH)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
	}


	// We must save queried re-authentication and pseudonym identity.
	if (reauthentication_identity != 0
		&& reauthentication_identity->get_is_valid_data() == true)
	{
		status = get_reauthentication_identity()->set_copy_of_buffer(reauthentication_identity);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (pseudonym != 0
		&& pseudonym->get_is_valid_data() == true)
	{
		status = get_pseudonym()->set_copy_of_buffer(pseudonym);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	if (m_use_manual_username == true
		&& m_manual_username.get_is_valid_data() == true
		&& m_use_manual_realm == true
		&& m_manual_realm.get_is_valid_data() == true)
	{
		// Here manual username could be zero or more bytes in length.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_aka_c::handle_eap_identity_query(): Client sends manual username and realm.\n")));

		status = manual_identity.set_copy_of_buffer(&m_manual_username);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		current_identity = &manual_identity;
		IMSI_is_used = false;
	}
	else if (m_use_manual_username == true
			 && m_manual_username.get_is_valid_data() == true
			 && m_use_manual_realm == false)
	{
		// We will send manual username with automatic realm.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_aka_c::handle_eap_identity_query(): Client sends manual username and automatic realm.\n")));

		status = manual_identity.set_copy_of_buffer(&m_manual_username);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		current_identity = &manual_identity;
		IMSI_is_used = false;
	}
	else if (reauthentication_identity != 0
		&& reauthentication_identity->get_is_valid_data() == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_aka_c::handle_eap_identity_query(): Client sends re-authentication identity.\n")));

		current_identity = reauthentication_identity;
		IMSI_is_used = false;
		reauth_id_is_used = true;

		status = get_reauthentication_identity()->set_copy_of_buffer(reauthentication_identity);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (pseudonym != 0
		&& pseudonym->get_is_valid_data() == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_aka_c::handle_eap_identity_query(): Client sends pseudonym username.\n")));

		current_identity = pseudonym;
		IMSI_is_used = false;

		status = get_pseudonym()->set_copy_of_buffer(pseudonym);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (m_use_random_identity_on_eap_identity_response == true)
	{
		// Generate random username.
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_aka_c::handle_eap_identity_query(): Client sends random username.\n")));

		const u32_t EAP_TLS_PEAP_RANDOM_IDENTITY_LENGTH = 16;

		eap_variable_data_c random_username(m_am_tools);
		eap_variable_data_c random_bytes(m_am_tools);

		if (random_username.get_is_valid() == false
			|| random_bytes.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		
		status = random_bytes.init(EAP_TLS_PEAP_RANDOM_IDENTITY_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		random_bytes.set_is_valid();
		random_bytes.set_data_length(EAP_TLS_PEAP_RANDOM_IDENTITY_LENGTH);
		
		status = m_am_tools->get_crypto()->get_rand_bytes(
			random_bytes.get_data(random_bytes.get_data_length()),
			random_bytes.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		// Change first byte to 'r' to make it different than the default IMSI prefix '1'.
		// This will cause the first identity char 'S' after ascii armor conversion.
		*random_bytes.get_data(1ul) = static_cast<u8_t>('r');

		const u32_t EAP_AKA_RANDOM_IDENTITY_BUFFER_LENGTH
			= 3ul+(EAP_TLS_PEAP_RANDOM_IDENTITY_LENGTH+1u)*4u/3u;
		
		status = random_username.init(EAP_AKA_RANDOM_IDENTITY_BUFFER_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		random_username.set_is_valid();
		random_username.set_data_length(EAP_AKA_RANDOM_IDENTITY_BUFFER_LENGTH);
		
		u32_t random_identity_length = random_username.get_data_length();
		
		status = m_am_tools->convert_bytes_to_ascii_armor(
			random_bytes.get_data_offset(0u, random_bytes.get_data_length()),
			random_bytes.get_data_length(),
			random_username.get_data_offset(0u, random_username.get_data_length()),
			&random_identity_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		random_username.set_data_length(random_identity_length);
		
		status = manual_identity.set_copy_of_buffer(&random_username);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		current_identity = &manual_identity;
		IMSI_is_used = false;
	}
	else if (IMSI != 0
		&& IMSI->get_is_valid_data() == true
		&& IMSI->get_data_length() >= EAP_TYPE_AKA_MINIMUM_IMSI_LENGTH)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_aka_c::handle_eap_identity_query(): Client sends IMSI username.\n")));

		current_identity = IMSI;
		IMSI_is_used = true;
	}

	if (current_identity != 0)
	{
		status = get_IMSI()->set_copy_of_buffer(IMSI);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = store_identity(current_identity, IMSI_is_used);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("current_identity"),
			current_identity->get_data(current_identity->get_data_length()),
			current_identity->get_data_length()));

		eap_variable_data_c NAI(m_am_tools);

		if (NAI.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if (reauth_id_is_used == true)
		{
			// Re-authentication identity is NAI.
			status = NAI.set_copy_of_buffer(current_identity);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			status = generate_nai(
				&NAI,
				m_use_manual_realm,
				get_nai_realm(),
				current_identity,
				IMSI_is_used,
				get_IMSI(),
				automatic_realm,
				length_of_mnc);
		}

		if (status == eap_status_ok)
		{
			status = get_NAI()->set_copy_of_buffer(&NAI);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (must_be_synchronous == false)
			{
				status = get_type_partner()->complete_eap_identity_query(
					send_network_id,
					get_NAI(),
					eap_identifier);
				if (status == eap_status_ok)
				{
					if (p_identity != 0)
					{
						status = p_identity->set_copy_of_buffer(get_NAI());
					}

					if (status == eap_status_ok)
					{
						status = eap_status_completed_request;
					}
				}		
			}
			else
			{
				status = p_identity->set_copy_of_buffer(get_NAI());
			}

			if (status == eap_status_ok
				|| status == eap_status_completed_request)
			{
				if (m_use_random_identity_on_eap_identity_response == true)
				{
					m_authentication_type = AKA_AUTHENTICATION_TYPE_NONE;
					set_identity_type(AKA_IDENTITY_TYPE_NONE);
					set_state(eap_type_aka_state_waiting_for_aka_identity_request);

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_eap_identity_query(0x%08x): Selects none.\n"),
						 this));
				}
				else if (reauthentication_identity != 0
					&& reauthentication_identity->get_is_valid_data() == true)
				{
					m_authentication_type = AKA_AUTHENTICATION_TYPE_REAUTHENTICATION;
					set_identity_type(AKA_IDENTITY_TYPE_RE_AUTH_ID);
					set_state(eap_type_aka_state_waiting_for_reauth_request);

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_eap_identity_query(0x%08x): Selects fast re-authentication and re-authentication identity.\n"),
						 this));
				}
				else if (pseudonym != 0
					&& pseudonym->get_is_valid_data() == true)
				{
					m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;
					set_identity_type(AKA_IDENTITY_TYPE_PSEUDONYM_ID);
					set_state(eap_type_aka_state_waiting_for_challenge_request);

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_aka_c::handle_eap_identity_query(0x%08x): Selects full authentication and pseudonym identity.\n"),
						 this));
				}
				else
				{
					if (m_use_manual_username == true)
					{
						m_authentication_type = AKA_AUTHENTICATION_TYPE_NONE;
						set_identity_type(AKA_IDENTITY_TYPE_NONE);
						set_state(eap_type_aka_state_waiting_for_aka_identity_request);

						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("eap_type_aka_c::handle_eap_identity_query(0x%08x): Selects none.\n"),
							 this));
					}
					else
					{
						m_authentication_type = AKA_AUTHENTICATION_TYPE_FULL_AUTH;
						set_identity_type(AKA_IDENTITY_TYPE_IMSI_ID);
						set_state(eap_type_aka_state_waiting_for_challenge_request);

						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("eap_type_aka_c::handle_eap_identity_query(0x%08x): Selects full authentication and IMSI identity.\n"),
							 this));
					}
				}
			}
		}
	}
	else
	{
		status = eap_status_illegal_nai;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::query_eap_identity(
	const bool must_be_synchronous,
	eap_variable_data_c * const identity,
	const eap_am_network_id_c * const receive_network_id,
	const u8_t eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_variable_data_c IMSI(m_am_tools);
	eap_variable_data_c pseudonym(m_am_tools);
	eap_variable_data_c reauthentication_identity(m_am_tools);

	if (IMSI.get_is_valid() == false
		|| pseudonym.get_is_valid() == false
		|| reauthentication_identity.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		receive_network_id->get_destination_id(),
		receive_network_id->get_source_id(),
		receive_network_id->get_type());

	eap_status_e status = eap_status_process_general_error;

	if (get_state() == eap_type_aka_state_none)
	{
		status = new_handler(
			receive_network_id,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_aka_c::query_eap_identity(): eap_type_aka_state_variable_e %d=%s.\n"),
		get_state(),
		get_state_string()));

	if (get_state() == eap_type_aka_state_waiting_for_identity_request
		|| (m_aka_test_version == true
			&& get_state() == eap_type_aka_state_success)) // This one is for testing purposes.
	{
		set_last_eap_identifier(eap_identifier);

		eap_variable_data_c automatic_realm(m_am_tools);
		if (automatic_realm.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = query_AKA_IMSI_or_pseudonym_or_reauthentication_id(
			&IMSI,
			&pseudonym,
			&reauthentication_identity,
			&automatic_realm,
			&m_length_of_mnc,
			must_be_synchronous,
			aka_payload_AT_ANY_ID_REQ,
			eap_type_aka_complete_query_eap_identity,
			eap_identifier);
		if (status == eap_status_pending_request)
		{
			// This is pending query, that will be completed by complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() call.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (status == eap_status_completed_request)
		{
			// This is already completed by complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() call.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::query_eap_identity(): ")
				 EAPL("completed returns eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (status != eap_status_ok)
		{
			// This is the error case.
			restore_saved_previous_state();

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::query_eap_identity(): ")
				 EAPL("error returns eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else // status == eap_status_ok
		{
			status = handle_eap_identity_query(
				&send_network_id,
				identity,
				eap_identifier,
				&IMSI,
				&pseudonym,
				&reauthentication_identity,
				&automatic_realm,
				m_length_of_mnc,
				must_be_synchronous);

			if (status != eap_status_ok
				&& status != eap_status_completed_request)
			{
				restore_saved_previous_state();
			}

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::query_eap_identity(): handle_eap_identity_query() ")
				 EAPL("returns eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else if (get_state() == eap_type_aka_state_waiting_for_aka_identity_request
		|| get_state() == eap_type_aka_state_pseydonym_waiting_for_aka_identity_request
		|| get_state() == eap_type_aka_state_imsi_waiting_for_aka_identity_request
		|| get_state() == eap_type_aka_state_waiting_for_reauth_request)
	{
		// This is re-transmission request. We do not change our state.
		// Just send EAP-Identity again.
		if (get_NAI()->get_is_valid_data() == true)
		{
			status = identity->set_copy_of_buffer(get_NAI());

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_aka_c::query_eap_identity(): handle_eap_identity_query() ")
				 EAPL("returns eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_AKA_ERROR, 
				(EAPL("ERROR: eap_type_aka_c::query_eap_identity(): ")
				 EAPL("EAP-Request/Identity cannot be completed, identity (NAI) ")
				 EAPL("is missing. in eap_type_aka_state_variable_e %d=%s.\n"),
				 get_state(),
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (get_state() == eap_type_aka_state_pending_identity_query)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_aka_c::query_eap_identity(): ignores re-transmitted query_eap_identity()")
			 EAPL("in eap_type_aka_state_variable_e %d=%s.\n"),
			 get_state(),
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_pending_request);
	}


	// Wrong message in this state.
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_AKA_ERROR, 
		(EAPL("WARNING: eap_type_aka_c::query_eap_identity(): ")
		 EAPL("Wrong message EAP-Request/Identity in eap_type_aka_state_variable_e %d=%s.\n"),
		 get_state(),
		 get_state_string()));		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::set_initial_eap_identifier(
	const eap_am_network_id_c * const receive_network_id,
	const u8_t initial_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = new_handler(
		receive_network_id,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_AKA_ERROR, 
			(EAPL("ERROR: eap_type_aka_c::aka_packet_process(): ")
			 EAPL("new_handler() failed, status %d.\n"),
			 status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	set_last_eap_identifier(static_cast<u8_t>(initial_identifier-1u));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::eap_acknowledge(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	if (get_state() == eap_type_aka_state_waiting_for_success
		&& m_wait_eap_success_packet == true)
	{
		status = finish_successful_authentication(
			receive_network_id);
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ignored eap_acknowledge(): state %d=%s, is client %d\n"),
			get_state(),
			get_state_string(),
			(m_is_client == true)));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(_DEBUG) && defined(USE_EAP_AKA_TEST_VECTORS)
	#include "read_rand_and_triplets.h"
#endif //#if defined(_DEBUG) && defined(USE_EAP_AKA_TEST_VECTORS)


//
EAP_FUNC_EXPORT eap_status_e eap_type_aka_c::generate_nonce(
	const u32_t nonce_size,
	eap_variable_data_c * const nonce)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = nonce->init(nonce_size);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	nonce->set_is_valid();
	nonce->set_data_length(nonce_size);

#if defined(_DEBUG) && defined(USE_EAP_AKA_TEST_VECTORS)
	if (m_nonce_mt_file.get_is_valid() == true)
	{
		status = read_rand_from_file(m_am_tools, &m_nonce_mt_file, nonce);
		if (status != eap_status_ok)
		{
			status = m_am_tools->get_crypto()->get_rand_bytes(
				nonce->get_data(nonce->get_data_length()),
				nonce->get_data_length());
		}
	}
	else
#endif //#if defined(_DEBUG) && defined(USE_EAP_AKA_TEST_VECTORS)
	{
		status = m_am_tools->get_crypto()->get_rand_bytes(
			nonce->get_data(nonce->get_data_length()),
			nonce->get_data_length());
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------



// End.
