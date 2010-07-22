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
* %version: 31.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 76 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_type_gsmsim.h"
#include "eap_type_gsmsim_header.h"
#include "eap_type_gsmsim_payloads.h"
#include "eap_type_gsmsim_mac_attributes.h"
#include "abs_eap_am_type_gsmsim.h"
#include "eap_crypto_api.h"
#include "eap_state_notification.h"
#include "abs_eap_am_mutex.h"
#include "eap_automatic_variable.h"
#include "eap_type_gsmsim_header.h"
#include "eap_am_type_gsmsim.h"


//--------------------------------------------------

/** @file */

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::generate_nai(
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
	status = local_username.set_buffer_length(id_IMSI_or_pseudonym->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	local_username.set_data_length(id_IMSI_or_pseudonym->get_data_length());

	m_am_tools->memmove(
		local_username.get_data(id_IMSI_or_pseudonym->get_data_length()),
		id_IMSI_or_pseudonym->get_data(),
		id_IMSI_or_pseudonym->get_data_length());

	new_nai->set_data_length(0u);

	if (id_is_imsi == true)
	{
		// Note the first octet is reserved for IMSI prefix.
		status = new_nai->add_data(GSMSIM_IMSI_PREFIX_CHARACTER, 1u);
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
			status = new_nai->add_data(GSMSIM_AT_CHARACTER, 1u);
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
		&& IMSI->get_data_length() >= EAP_TYPE_GSMSIM_MINIMUM_IMSI_LENGTH)
	{
		status = new_nai->add_data(GSMSIM_AT_CHARACTER, 1u);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (automatic_realm != 0
			&& automatic_realm->get_is_valid_data() == true)
		{
			// We must use automatic realm.

			status = new_nai->add_data(automatic_realm);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			// We must use automatic realm (Example: "wlan.mnc456.mcc123.3gppnetwork.org").

			status = new_nai->add_data(GSMSIM_OWLAN_ORG_PREFIX_STRING, GSMSIM_OWLAN_ORG_PREFIX_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = new_nai->add_data(GSMSIM_OWLAN_DOT_STRING, GSMSIM_OWLAN_DOT_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = new_nai->add_data(GSMSIM_OWLAN_MNC_STRING, GSMSIM_OWLAN_MNC_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// MNC part.
			if (length_of_mnc == EAP_TYPE_GSMSIM_MNC_LENGTH_2_BYTES)
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
			status = new_nai->add_data(IMSI->get_data_offset(EAP_TYPE_GSMSIM_MNC_OFFSET, length_of_mnc), length_of_mnc);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = new_nai->add_data(GSMSIM_OWLAN_DOT_STRING, GSMSIM_OWLAN_DOT_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = new_nai->add_data(GSMSIM_OWLAN_MCC_STRING, GSMSIM_OWLAN_MCC_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// MCC part is in index 0 and it is 3 bytes long.
			status = new_nai->add_data(IMSI->get_data_offset(EAP_TYPE_GSMSIM_MCC_OFFSET, EAP_TYPE_GSMSIM_MCC_LENGTH), EAP_TYPE_GSMSIM_MCC_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = new_nai->add_data(GSMSIM_OWLAN_DOT_STRING, GSMSIM_OWLAN_DOT_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = new_nai->add_data(GSMSIM_OWLAN_ORG_STRING, GSMSIM_OWLAN_ORG_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("new_nai"),
		new_nai->get_data(),
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::query_SIM_IMSI_or_pseudonym_or_reauthentication_id(
	eap_variable_data_c * const IMSI,
	eap_variable_data_c * const pseudonym_identity,
	eap_variable_data_c * const reauthentication_identity,
	eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
	u32_t * const length_of_mnc,
	const bool must_be_synchronous,
	const gsmsim_payload_AT_type_e required_identity,
	const eap_type_gsmsim_complete_e required_completion,
	const u8_t received_eap_identifier)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	save_current_state();
	set_state(eap_type_gsmsim_state_pending_identity_query);

	status = m_am_type_gsmsim->query_SIM_IMSI_or_pseudonym_or_reauthentication_id(
		must_be_synchronous,
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
		// This is pending query, that will be completed by complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() call.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status == eap_status_completed_request)
	{
		// This is already completed by complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() call.
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::check_rands(
	const eap_variable_data_c * const n_rands
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if ((n_rands->get_data_length() % SIM_RAND_LENGTH) != 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
	}

	const u32_t rand_count = n_rands->get_data_length() / SIM_RAND_LENGTH;

	if (rand_count < m_minimum_rand_count)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_enough_challenges);
	}

	u32_t ind = 0ul;

	for (ind = 0ul; ind+1ul < rand_count; ind++)
	{
		const u8_t * const rand_a = n_rands->get_data_offset(ind*SIM_RAND_LENGTH, SIM_RAND_LENGTH);
		for (u32_t b_ind = ind+1ul; b_ind < rand_count; b_ind++)
		{
			const u8_t * const rand_b = n_rands->get_data_offset(b_ind*SIM_RAND_LENGTH, SIM_RAND_LENGTH);
			if (rand_a == 0
				|| rand_b == 0
				|| m_am_tools->memcmp(rand_a, rand_b, SIM_RAND_LENGTH) == 0)
			{
				// ERROR: Two equal RANDs.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
			}
		}
	}

	if (m_do_rand_uniqueness_check == true)
	{
		eap_status_e status = m_am_type_gsmsim->check_is_rand_unused(n_rands);
		if (status != eap_status_ok)
		{
			// ERROR: RAND is used already.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_not_fresh_challenges);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::query_SIM_kc_sres(
	const eap_variable_data_c * const n_rands,
	eap_variable_data_c * const n_kc,
	eap_variable_data_c * const n_sres
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	status = check_rands(n_rands);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_n_rands.set_copy_of_buffer(n_rands);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

   set_state(eap_type_gsmsim_state_pending_kc_sres_query);

	status = m_am_type_gsmsim->query_SIM_kc_sres(
		false,
		n_rands,
		n_kc,
		n_sres);

	if (status == eap_status_pending_request)
	{
		// This is pending query, that will be completed by complete_SIM_kc_sres() call.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (status == eap_status_completed_request)
	{
		// This is already completed by complete_SIM_kc_sres() call.
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

u32_t eap_type_gsmsim_c::get_mnc_length(const u32_t mcc)
{
	u32_t * const mcc_array = reinterpret_cast<u32_t *>(m_2_digit_mnc_map_of_mcc_of_imsi_array.get_data(
		m_2_digit_mnc_map_of_mcc_of_imsi_array.get_data_length()));

	u32_t count = m_2_digit_mnc_map_of_mcc_of_imsi_array.get_data_length() / sizeof(u32_t);

	for (u32_t ind = 0ul; ind < count; ind++)
	{
		if (mcc == mcc_array[ind])
		{
			return EAP_TYPE_GSMSIM_MNC_LENGTH_2_BYTES;
		}
	}

	return EAP_TYPE_GSMSIM_DEFAULT_MNC_LENGTH_3_BYTES;
}

//--------------------------------------------------

eap_status_e eap_type_gsmsim_c::create_uma_realm(
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
		}

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (automatic_realm->get_data_length() > 0ul)
		{
			status = automatic_realm->add_data(GSMSIM_OWLAN_DOT_STRING, GSMSIM_OWLAN_DOT_STRING_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		status = automatic_realm->add_data(GSMSIM_OWLAN_MNC_STRING, GSMSIM_OWLAN_MNC_STRING_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// MNC part.
		if (length_of_mnc == EAP_TYPE_GSMSIM_MNC_LENGTH_2_BYTES)
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
		status = automatic_realm->add_data(IMSI->get_data_offset(EAP_TYPE_GSMSIM_MNC_OFFSET, length_of_mnc), length_of_mnc);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = automatic_realm->add_data(GSMSIM_OWLAN_DOT_STRING, GSMSIM_OWLAN_DOT_STRING_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = automatic_realm->add_data(GSMSIM_OWLAN_MCC_STRING, GSMSIM_OWLAN_MCC_STRING_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// MCC part is in index 0 and it is 3 bytes long.
		status = automatic_realm->add_data(IMSI->get_data_offset(EAP_TYPE_GSMSIM_MCC_OFFSET, EAP_TYPE_GSMSIM_MCC_LENGTH), EAP_TYPE_GSMSIM_MCC_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = automatic_realm->add_data(GSMSIM_OWLAN_DOT_STRING, GSMSIM_OWLAN_DOT_STRING_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = automatic_realm->add_data(GSMSIM_OWLAN_ORG_STRING, GSMSIM_OWLAN_ORG_STRING_LENGTH);
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query(
	const eap_variable_data_c * const IMSI,
	const eap_variable_data_c * const p_pseudonym_identity,
	const eap_variable_data_c * const p_reauthentication_identity,
	const eap_variable_data_c * const p_automatic_realm, ///< This could be zero pointer if this is not used.
	const u32_t length_of_mnc,
	const eap_type_gsmsim_complete_e required_completion,
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
		set_state(eap_type_gsmsim_state_failure);

		// The eap_status_process_general_error error value is more important
		// than return value of set_session_timeout().
		get_type_partner()->set_session_timeout(0ul);

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

	if (m_state != eap_type_gsmsim_state_pending_identity_query)
	{
		// Authentication is terminated or state is wrong. Cannot continue.
		set_state(eap_type_gsmsim_state_failure);

		// The eap_status_handler_does_not_exists_error error value is more important
		// than return value of set_session_timeout().
		get_type_partner()->set_session_timeout(0ul);

		return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c local_automatic_realm(m_am_tools);

	if (p_automatic_realm == 0
		|| p_automatic_realm->get_is_valid_data() == false)
	{
		{
			// Here we read the length of the MNC.
			const u8_t * const MCC = IMSI->get_data_offset(EAP_TYPE_GSMSIM_MCC_OFFSET, EAP_TYPE_GSMSIM_MCC_LENGTH);
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

		if (local_automatic_realm.get_is_valid() == true)
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

		status = m_automatic_realm.set_copy_of_buffer(p_automatic_realm);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_length_of_mnc = length_of_mnc;

	}

	m_automatic_realm_read = true;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	if (required_completion == eap_type_gsmsim_complete_query_eap_identity)
	{
		status = handle_eap_identity_query(
			&m_send_network_id,
			0,
			m_last_eap_identifier,
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
	else if (required_completion == eap_type_gsmsim_complete_start_request)
	{
		if (local_reauthentication_identity != 0
			&& local_reauthentication_identity->get_is_valid_data() == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query reauthentication_identity\n")));
			
			status = m_reauthentication_identity.set_copy_of_buffer(local_reauthentication_identity);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			status = store_identity(&m_reauthentication_identity, false);
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
				(EAPL("complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query pseudonym\n")));
			
			m_reauthentication_identity.reset();
			status = m_pseudonym.set_copy_of_buffer(local_pseudonym_identity);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			status = store_identity(&m_pseudonym, false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (IMSI->get_is_valid_data() == true
			&& IMSI->get_data_length() >= EAP_TYPE_GSMSIM_MINIMUM_IMSI_LENGTH)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query IMSI\n")));
			
			m_reauthentication_identity.reset();
			m_pseudonym.reset();
			status = m_IMSI.set_copy_of_buffer(IMSI);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			status = store_identity(&m_IMSI, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		save_current_state();
		set_state(eap_type_gsmsim_state_analyse_start_request);
		
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query(0x%08x).\n"),
			 this));
		
		// Here we swap the addresses.
		eap_am_network_id_c receive_network_id(m_am_tools,
			m_send_network_id.get_destination_id(),
			m_send_network_id.get_source_id(),
			m_send_network_id.get_type());

		status = send_start_response_message(
			&receive_network_id,
			received_eap_identifier,
			m_gsmsim_selected_version,
			m_include_identity_to_start_response,
			&local_automatic_realm,
			m_length_of_mnc);
		
		if (status == eap_status_ok)
		{
		}
		else
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::complete_SIM_kc_sres(
	const eap_variable_data_c * const n_rand,
	const eap_variable_data_c * const n_kc,
	const eap_variable_data_c * const n_sres,
	const eap_status_e completion_status)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	if (completion_status != eap_status_ok
		|| n_rand == 0
		|| n_kc == 0
		|| n_sres == 0)
	{
		if (completion_status == eap_status_not_fresh_challenges)
		{
			(void) initialize_error_message(completion_status);

			restore_saved_previous_state();
		}
		else
		{
			set_state(eap_type_gsmsim_state_failure);

			// The eap_status_process_general_error error value is more important
			// than return value of set_session_timeout().
			get_type_partner()->set_session_timeout(0ul);
		}

		return EAP_STATUS_RETURN(m_am_tools, completion_status);
	}


	if (m_state != eap_type_gsmsim_state_pending_kc_sres_query)
	{
		// Authentication is terminated or state is wrong. Cannot continue.
		set_state(eap_type_gsmsim_state_failure);

		// The eap_status_handler_does_not_exists_error error value is more important
		// than return value of set_session_timeout().
		get_type_partner()->set_session_timeout(0ul);

		return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = process_SIM_kc_sres(
		n_rand,
		n_kc,
		n_sres);

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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::process_SIM_kc_sres(
	const eap_variable_data_c * const n_rand,
	const eap_variable_data_c * const n_kc,
	const eap_variable_data_c * const n_sres)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	eap_variable_data_c MAC_RAND(m_am_tools);

	if (m_state != eap_type_gsmsim_state_pending_kc_sres_query
		|| n_rand == 0
		|| n_kc == 0
		|| n_sres == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (m_identity.get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
	}

	if (m_nonce_mt.get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, (EAPL("n*RAND"),
		n_rand->get_data(),
		n_rand->get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("n*KC"),
		n_kc->get_data(),
		n_kc->get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("n*SRES"),
		n_sres->get_data(),
		n_sres->get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("identity"),
		m_identity.get_data(),
		m_identity.get_data_length()));
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("NONCE MT"),
		m_nonce_mt.get_data(),
		m_nonce_mt.get_data_length()));


	status = m_n_sres.set_copy_of_buffer(n_sres);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c XKEY(m_am_tools);
	eap_variable_data_c K_encr(m_am_tools);
	eap_variable_data_c K_aut(m_am_tools);
	eap_variable_data_c master_session_key(m_am_tools);

	status = generate_shared_secred_keys(
		EAP_TYPE_GSMSIM_KEYMAT_SIZE,
		n_kc,
		n_sres,
		&XKEY,
		&K_encr,
		&K_aut,
		&master_session_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (m_saved_EAP_packet.get_is_valid_data() == true)
	{
		gsmsim_payloads_c * const l_gsmsim_payloads = new gsmsim_payloads_c(m_am_tools);
		eap_automatic_variable_c<gsmsim_payloads_c> l_gsmsim_payloads_automatic(m_am_tools, l_gsmsim_payloads);

		if (l_gsmsim_payloads == 0
			|| l_gsmsim_payloads->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		gsmsim_header_c saved_EAP_packet(
			m_am_tools,
			m_saved_EAP_packet.get_data(),
			m_saved_EAP_packet.get_data_length());

		if (saved_EAP_packet.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}

		status = parse_gsmsim_packet(
			&saved_EAP_packet,
			m_saved_EAP_packet.get_data_length(),
			l_gsmsim_payloads);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = check_message_authentication_code(
			&K_aut,
			l_gsmsim_payloads,
			&saved_EAP_packet,
			saved_EAP_packet.get_length());
		if (status != eap_status_ok)
		{
			(void) initialize_error_message(status);

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Decrypt and parse encrypted payload.
		if (l_gsmsim_payloads->get_IV()->get_payload_included() == true
		|| l_gsmsim_payloads->get_ENCR_DATA()->get_payload_included() == true)
		{
			if (l_gsmsim_payloads->get_IV()->get_payload_included() == true
			&& l_gsmsim_payloads->get_ENCR_DATA()->get_payload_included() == true
			&& l_gsmsim_payloads->get_MAC()->get_payload_included() == true)
			{
				status = decrypt_DATA_payload(
					l_gsmsim_payloads,
					&K_encr);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = handle_DATA_payload(
					gsmsim_subtype_Challenge,
					l_gsmsim_payloads);
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
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}
		}
		else
		{
			// No encrypted payload.
			// GSMSIM AM should remove re-authentication identity from favourite place.

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::process_SIM_kc_sres(0x%08x): Resets re-authentication identity from database.\n"),
				 this));

			status = m_am_type_gsmsim->store_reauthentication_id(
				&m_send_network_id,
				0);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			m_reauthentication_identity.reset();
		}
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = send_challenge_response_message(
		&K_aut);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Store keys.
	status = m_XKEY.set_copy_of_buffer(&XKEY);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	status = m_K_encr.set_copy_of_buffer(&K_encr);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	status = m_K_aut.set_copy_of_buffer(&K_aut);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	status = m_master_session_key.set_copy_of_buffer(&master_session_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// In order to use re-authentication, the client and the server need to
	// store the following values: original XKEY, K_aut, K_encr, latest
	// counter value and the next re-authentication identity.
	status = m_am_type_gsmsim->store_reauth_parameters(
		&XKEY,
		&K_aut,
		&K_encr,
		EAP_TYPE_GSMSIM_INITIAL_REAUTH_COUNTER);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Authentication was successful.
	if (m_use_result_indication == true)
	{
		// This version waits result indication.
		if (m_authentication_type == GSMSIM_AUTHENTICATION_TYPE_REAUTHENTICATION)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("EAP_type_GSMSIM: %s, re-authentication OK, waits result indication\n"),
				(m_is_client == true) ? "client": "server"));
		}
		else if (m_authentication_type == GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH)
		{
			if (m_identity_type == GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
					(EAPL("EAP_type_GSMSIM: %s, full authentication OK, pseudonym identity, waits result indication\n"),
					(m_is_client == true) ? "client": "server"));
			}
			else if (m_identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
					(EAPL("EAP_type_GSMSIM: %s, full authentication OK, IMSI identity, waits result indication\n"),
					(m_is_client == true) ? "client": "server"));
			}
			else if (m_identity_type == GSMSIM_IDENTITY_TYPE_RE_AUTH_ID)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
					(EAPL("EAP_type_GSMSIM: %s, full authentication OK, Re-auth identity, waits result indication\n"),
					(m_is_client == true) ? "client": "server"));
			}
			else
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_GSMSIM_ERROR|TRACE_TEST_VECTORS,
					(EAPL("ERROR: EAP_type_GSMSIM: %s, full authentication OK, unknown identity\n"),
					(m_is_client == true) ? "client": "server"));

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
			}
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_GSMSIM_ERROR|TRACE_TEST_VECTORS,
				(EAPL("ERROR: EAP_type_GSMSIM: %s, unknown authentication OK, unknown identity\n"),
				(m_is_client == true) ? "client": "server"));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}

		set_state(eap_type_gsmsim_state_waiting_for_notification_request_success);
	}
	else if (m_wait_eap_success_packet == false)
	{
		// This version does not wait EAP-Success message.
		if (m_send_network_id.get_is_valid_data() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		// Here we swap the addresses.
		eap_am_network_id_c receive_network_id(m_am_tools,
			m_send_network_id.get_destination_id(),
			m_send_network_id.get_source_id(),
			m_send_network_id.get_type());

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

		if (m_authentication_type == GSMSIM_AUTHENTICATION_TYPE_REAUTHENTICATION)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
				(EAPL("EAP_type_GSMSIM: %s, re-authentication OK, waits EAP-Success\n"),
				(m_is_client == true) ? "client": "server"));
		}
		else if (m_authentication_type == GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH)
		{
			if (m_identity_type == GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
					(EAPL("EAP_type_GSMSIM: %s, full authentication OK, pseudonym identity, waits EAP-Success\n"),
					(m_is_client == true) ? "client": "server"));
			}
			else if (m_identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
					(EAPL("EAP_type_GSMSIM: %s, full authentication OK, IMSI identity, waits EAP-Success\n"),
					(m_is_client == true) ? "client": "server"));
			}
			else if (m_identity_type == GSMSIM_IDENTITY_TYPE_RE_AUTH_ID)
			{
				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
					(EAPL("EAP_type_GSMSIM: %s, full authentication OK, Re-auth identity, waits EAP-Success\n"),
					(m_is_client == true) ? "client": "server"));
			}
			else
			{
				EAP_TRACE_ERROR(
					m_am_tools,
					TRACE_FLAGS_GSMSIM_ERROR|TRACE_TEST_VECTORS,
					(EAPL("ERROR: EAP_type_GSMSIM: %s, full authentication OK, unknown identity, waits EAP-Success\n"),
					(m_is_client == true) ? "client": "server"));

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
			}
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_GSMSIM_ERROR|TRACE_TEST_VECTORS,
				(EAPL("ERROR: EAP_type_GSMSIM: %s, unknown authentication OK, unknown identity, waits EAP-Success\n"),
				(m_is_client == true) ? "client": "server"));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}

		set_state(eap_type_gsmsim_state_waiting_for_success);
		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::send_start_response_message(
	const eap_am_network_id_c * const receive_network_id,
	const u8_t received_eap_identifier,
	const eap_gsmsim_version version,
	const gsmsim_payload_AT_type_e include_identity_to_start_response,
	const eap_variable_data_c * const automatic_realm, ///< This could be zero pointer if this is not used.
	const u32_t /* length_of_mnc */
)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("    send: GSMSIM-type %10s, %s, state %2d=%s\n"),
		EAPL("gsmsim_subtype_Start"),
		(m_is_client) ? EAPL("client") : EAPL("server"),
		m_state,
		get_state_string()
		));

	eap_buf_chain_wr_c gsmsim_initial_reply(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (gsmsim_initial_reply.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)
	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means GSMSIM does process every re-transmitted EAP-Request.
		gsmsim_initial_reply.set_do_packet_retransmission(false);
	}
#endif //#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)

	EAP_ASSERT_ALWAYS(EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH >= (m_gsmsim_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_gsmsim_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_gsmsim_header_offset+m_MTU;
	}

	gsmsim_header_c gsmsim_response(
		m_am_tools,
		gsmsim_initial_reply.get_data_offset(
			m_gsmsim_header_offset,
			(packet_buffer_free-m_gsmsim_header_offset)),
		(packet_buffer_free-m_gsmsim_header_offset));

	if (gsmsim_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
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

	gsmsim_response.reset_header(
		packet_buffer_free-m_gsmsim_header_offset,
		m_use_eap_expanded_type);
	gsmsim_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_gsmsim_header_offset),
		m_use_eap_expanded_type);
	gsmsim_response.set_code(eap_code_response);
	gsmsim_response.set_identifier(received_eap_identifier);
	gsmsim_response.set_type(
		eap_type_gsmsim,
		m_use_eap_expanded_type);

	gsmsim_response.set_subtype(gsmsim_subtype_Start);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::send_start_response_message(0x%08x): include_identity_to_start_response %d=%s.\n"),
		 this,
		 include_identity_to_start_response,
		 gsmsim_payload_AT_header_c::get_payload_AT_string(include_identity_to_start_response)));

	update_buffer_indexes(
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		m_gsmsim_header_offset+gsmsim_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t gsmsim_data_free = packet_buffer_free;
	u32_t gsmsim_data_offset = 0u;
	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_identity_type == GSMSIM_IDENTITY_TYPE_RE_AUTH_ID)
	{
		// Re-authentication identity MUST be removed after first use.
		// GSMSIM AM should remove re-authentication identity from favourite place.

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_gsmsim_c::send_start_response_message(0x%08x): Resets re-authentication identity from database.\n"),
			 this));

		status = m_am_type_gsmsim->store_reauthentication_id(
			&m_send_network_id,
			0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Do not reset the local copy of re-authentocation identity.
	}

	if (include_identity_to_start_response == gsmsim_payload_AT_PERMANENT_ID_REQ)
	{
		m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;
		set_identity_type(GSMSIM_IDENTITY_TYPE_IMSI_ID);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_gsmsim_c::send_start_response_message(0x%08x): Selects full authentication and IMSI identity.\n"),
			 this));
	}
	else if (include_identity_to_start_response == gsmsim_payload_AT_FULLAUTH_ID_REQ)
	{
		eap_variable_data_c * const pseudonym = &m_pseudonym;

		if (pseudonym->get_is_valid_data() == true)
		{
			// We have pseudonym.
			m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;
			set_identity_type(GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::send_start_response_message(0x%08x): Selects full authentication and pseudonym identity.\n"),
				 this));
		}
		else // if (pseudonym->get_is_valid() == false)
		{
			// Because no pseudonym is available we must use IMSI.
			m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;
			set_identity_type(GSMSIM_IDENTITY_TYPE_IMSI_ID);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::send_start_response_message(0x%08x): Selects full authentication and IMSI identity.\n"),
				 this));
		}
	}
	else if (include_identity_to_start_response == gsmsim_payload_AT_ANY_ID_REQ)
	{
		eap_variable_data_c * const reauthentication_identity = &m_reauthentication_identity;
		eap_variable_data_c * const pseudonym = &m_pseudonym;

		if (reauthentication_identity->get_is_valid_data() == true)
		{
			// We have reauthentication identity. Re-authentication identity is NAI.
			m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_REAUTHENTICATION;
			set_identity_type(GSMSIM_IDENTITY_TYPE_RE_AUTH_ID);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::send_start_response_message(0x%08x): Selects fast re-authentication and re-authentication identity.\n"),
				 this));
		}
		else if (pseudonym->get_is_valid_data() == true)
		{
			// We have pseudonym.
			m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;
			set_identity_type(GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::send_start_response_message(0x%08x): Selects full authentication and pseudonym identity.\n"),
				 this));
		}
		else if (m_IMSI.get_is_valid_data() == true)
		{
			// Because no pseudonym is available we must use IMSI.
			m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;
			set_identity_type(GSMSIM_IDENTITY_TYPE_IMSI_ID);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::send_start_response_message(0x%08x): Selects full authentication and IMSI identity.\n"),
				 this));
		}
		else
		{
			// ERROR, no identity available.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}
	}

	if (m_authentication_type == GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH)
	{
		status = add_variable_payload(
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			&m_nonce_mt,
			gsmsim_payload_AT_NONCE_MT);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = add_version_payload(
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			version);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	if (include_identity_to_start_response != gsmsim_payload_NONE)
	{
		if (m_identity_type == GSMSIM_IDENTITY_TYPE_IMSI_ID)
		{
			eap_variable_data_c NAI(m_am_tools);
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
				&m_IMSI,
				true,
				&m_IMSI,
				automatic_realm,
				m_length_of_mnc);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = add_pseudonym_or_imsi_payload(
				&gsmsim_response,
				EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
				gsmsim_response.get_header_length(),
				&gsmsim_data_offset,
				&gsmsim_data_free,
				&packet_buffer_free,
				&packet_buffer_offset,
				&NAI,
				gsmsim_payload_AT_IDENTITY);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Save used NAI.
			status = m_NAI.set_copy_of_buffer(&NAI);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::send_start_response_message(): Client sends IMSI identity.\n")));
		}
		else if (m_identity_type == GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID)
		{
			eap_variable_data_c * const pseudonym = &m_pseudonym;

			if (pseudonym->get_is_valid_data() == true)
			{
				// We have pseudonym.

				eap_variable_data_c NAI(m_am_tools);
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
					&m_IMSI,
					automatic_realm,
					m_length_of_mnc);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = add_pseudonym_or_imsi_payload(
					&gsmsim_response,
					EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
					gsmsim_response.get_header_length(),
					&gsmsim_data_offset,
					&gsmsim_data_free,
					&packet_buffer_free,
					&packet_buffer_offset,
					&NAI,
					gsmsim_payload_AT_IDENTITY);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// Save used NAI.
				status = m_NAI.set_copy_of_buffer(&NAI);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_type_gsmsim_c::send_start_response_message(): Client sends pseudonym identity.\n")));
			}
			else // if (pseudonym->get_is_valid_data() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
			}
		}
		else if (m_identity_type == GSMSIM_IDENTITY_TYPE_RE_AUTH_ID)
		{
			eap_variable_data_c * const reauthentication_identity = &m_reauthentication_identity;

			if (reauthentication_identity->get_is_valid_data() == true)
			{
				// We have reauthentication identity. Re-authentication identity is NAI.
				status = add_pseudonym_or_imsi_payload(
					&gsmsim_response,
					EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
					gsmsim_response.get_header_length(),
					&gsmsim_data_offset,
					&gsmsim_data_free,
					&packet_buffer_free,
					&packet_buffer_offset,
					reauthentication_identity,
					gsmsim_payload_AT_IDENTITY);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				// Save used NAI.
				status = m_NAI.set_copy_of_buffer(reauthentication_identity);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_type_gsmsim_c::send_start_response_message(): Client sends re-authentication identity.\n")));
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

	gsmsim_response.set_data_length(
		gsmsim_data_offset,
		m_use_eap_expanded_type);
	gsmsim_initial_reply.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
		== packet_buffer_offset);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = packet_send(
		&send_network_id,
		&gsmsim_initial_reply,
		m_gsmsim_header_offset,
		gsmsim_response.get_header_length()+gsmsim_response.get_data_length(),
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		if (m_authentication_type == GSMSIM_AUTHENTICATION_TYPE_REAUTHENTICATION)
		{
			// Now we have on-going re-authentication.
			set_state(eap_type_gsmsim_state_waiting_for_reauth_request);
		}
		else
		{
			// Now we have on-going full-authentication.
			set_state(eap_type_gsmsim_state_waiting_for_challenge_request);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::send_gsmsim_notification_response(
	const eap_gsmsim_notification_codes_e notification_code,
	const bool add_at_counter_attribute)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: GSMSIM-type %10s, %s, state %2d=%s\n"),
		EAPL("send_gsmsim_notification_response"),
		(m_is_client) ? EAPL("client") : EAPL("server"),
		m_state,
		get_state_string()
		));

	eap_buf_chain_wr_c eap_notification_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_notification_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)
	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means GSMSIM does process every re-transmitted EAP-Request.
		eap_notification_packet.set_do_packet_retransmission(false);
	}
#endif //#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)

	EAP_ASSERT_ALWAYS(EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH >= (m_gsmsim_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_gsmsim_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_gsmsim_header_offset+m_MTU;
	}

	gsmsim_header_c gsmsim_response(
		m_am_tools,
		eap_notification_packet.get_data_offset(
			m_gsmsim_header_offset,
			(packet_buffer_free-m_gsmsim_header_offset)),
		(packet_buffer_free-m_gsmsim_header_offset));

	if (gsmsim_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	gsmsim_response.reset_header(
		static_cast<u16_t>(packet_buffer_free-m_gsmsim_header_offset),
		m_use_eap_expanded_type);
	gsmsim_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_gsmsim_header_offset),
		m_use_eap_expanded_type);
	gsmsim_response.set_code(eap_code_response);
	gsmsim_response.set_identifier(static_cast<u8_t>(m_last_eap_identifier));
	gsmsim_response.set_type(
		eap_type_gsmsim,
		m_use_eap_expanded_type);
	gsmsim_response.set_subtype(gsmsim_subtype_Notification);


	update_buffer_indexes(
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		m_gsmsim_header_offset+gsmsim_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t gsmsim_data_free = packet_buffer_free;
	u32_t gsmsim_data_offset = 0u;
	eap_status_e status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c * K_aut = 0;
	eap_variable_data_c orig_K_aut(m_am_tools);

	if (get_gsmsim_notification_code_P_bit(notification_code) == false)
	{
		u8_t *MAC_data = 0;
		u32_t MAC_data_length = 0u;
		eap_type_gsmsim_MAC_attributes_c MAC_attributes;

		if (add_at_counter_attribute == true)
		{
			// If EAP-Request/SIM/Notification is used on fast a re-authentication
			// exchange, and if the P bit in AT_NOTIFICATION is set to zero, then
			// AT_COUNTER is used for replay protection. In this case, the
			// AT_ENCR_DATA and AT_IV attributes MUST be included, and the
			// encapsulated plaintext attributes MUST include the AT_COUNTER
			// attribute. The counter value included in AT_COUNTER MUST be the same
			// as in the EAP-Request/SIM/Re-authentication packet on the same fast
			// re-authentication exchange.

			// - - - - - - - - - - - - - - - - - - - - - - - -

			eap_variable_data_c orig_XKEY(m_am_tools);
			eap_variable_data_c orig_K_encr(m_am_tools);
			u32_t reauth_counter = 0u;

			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_gsmsim->query_reauth_parameters(
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

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_type_gsmsim_c::send_gsmsim_notification_response(): %s, m_saved_reauth_counter %d.\n"),
				 (m_is_client == true ? "client": "server"),
				 reauth_counter));

			K_aut = &orig_K_aut;

			// -   -   -   -   -   -   -   -   -   -   -   -

			crypto_aes_c aes(m_am_tools);

			if (aes.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = m_am_type_gsmsim->generate_encryption_IV(
				m_IV.get_payload_buffer(),
				aes.get_block_size());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}


			status = add_variable_payload(
				&gsmsim_response,
				EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
				gsmsim_response.get_header_length(),
				&gsmsim_data_offset,
				&gsmsim_data_free,
				&packet_buffer_free,
				&packet_buffer_offset,
				m_IV.get_payload_buffer(),
				gsmsim_payload_AT_IV);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}


			// Encrypted data.
			{
				gsmsim_payload_AT_header_c gp_encrypted_data(
					m_am_tools,
					gsmsim_response.get_data_offset(
						gsmsim_data_offset, 
						gsmsim_data_free),
					gsmsim_data_free);
				if (gsmsim_response.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
				}

				// Initialize the length of encrypted data to maximum length.
				// Later this will be set to correct length.
				gp_encrypted_data.reset_header(gsmsim_payload_AT_header_c::get_max_payload_data_length());
				gp_encrypted_data.set_current_payload(gsmsim_payload_AT_ENCR_DATA);

				update_payload_indexes(
					EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
					gsmsim_response.get_header_length(),
					gp_encrypted_data.get_header_length(),
					&gsmsim_data_offset,
					&gsmsim_data_free,
					&packet_buffer_offset,
					&packet_buffer_free);

				u32_t encrypted_data_offset_begin = packet_buffer_offset;

				// -   -   -   -   -   -   -   -   -   -   -   -

				status = add_counter_payload(
					&gsmsim_response,
					EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
					gsmsim_response.get_header_length(),
					&gsmsim_data_offset,
					&gsmsim_data_free,
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
					&gsmsim_response,
					EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
					gsmsim_response.get_header_length(),
					&gsmsim_data_offset,
					&gsmsim_data_free,
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
					m_IV.get_payload_buffer(),
					&orig_K_encr);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_encrypted_data);
			}

		}
		else
		{
			K_aut = &m_K_aut;
		} // if (add_counter_payload == true)

		// -   -   -   -   -   -   -   -   -   -   -   -

		// Add AT_MAC attribute.
		status = add_mac_payload(
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
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

		gsmsim_response.set_data_length(
			gsmsim_data_offset,
			m_use_eap_expanded_type);
		eap_notification_packet.set_data_length(packet_buffer_offset);

		EAP_ASSERT_ALWAYS(
			m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
			== packet_buffer_offset);

		// -   -   -   -   -   -   -   -   -   -   -   -

		MAC_attributes.init(
			MAC_data,
			MAC_data_length,
			gsmsim_response.get_header_buffer(gsmsim_response.get_length()),
			gsmsim_response.get_length());

		status = create_message_authentication_code(
			&MAC_attributes,
			gsmsim_response.get_subtype(),
			gsmsim_response.get_code(),
			K_aut);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		gsmsim_response.set_data_length(
			gsmsim_data_offset,
			m_use_eap_expanded_type);

		eap_notification_packet.set_data_length(packet_buffer_offset);

		EAP_ASSERT_ALWAYS(
			m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
			== packet_buffer_offset);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_notification_packet.set_data_length(packet_buffer_offset);

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("    send: EAP-Response/Notification packet"),
		gsmsim_response.get_header_buffer(gsmsim_response.get_length()),
		gsmsim_response.get_length()));

	status = packet_send(
		&m_send_network_id,
		&eap_notification_packet,
		m_gsmsim_header_offset,
		gsmsim_response.get_length(),
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::send_gsmsim_client_error_response()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_GSMSIM_ERROR, 
		(EAPL("ERROR: send: GSMSIM-type %10s, %s, state %2d=%s, m_client_error_code %d\n"),
		EAPL("send_gsmsim_client_error_response"),
		(m_is_client) ? EAPL("client") : EAPL("server"),
		m_state,
		get_state_string(),
		m_client_error_code
		));

	eap_buf_chain_wr_c eap_client_error_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (eap_client_error_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)
	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means GSMSIM does process every re-transmitted EAP-Request.
		eap_client_error_packet.set_do_packet_retransmission(false);
	}
#endif //#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)

	EAP_ASSERT_ALWAYS(EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH >= (m_gsmsim_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_gsmsim_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_gsmsim_header_offset+m_MTU;
	}

	gsmsim_header_c gsmsim_response(
		m_am_tools,
		eap_client_error_packet.get_data_offset(
			m_gsmsim_header_offset,
			(packet_buffer_free-m_gsmsim_header_offset)),
		(packet_buffer_free-m_gsmsim_header_offset));

	if (gsmsim_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	gsmsim_response.reset_header(
		static_cast<u16_t>(packet_buffer_free-m_gsmsim_header_offset),
		m_use_eap_expanded_type);
	gsmsim_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_gsmsim_header_offset),
		m_use_eap_expanded_type);
	gsmsim_response.set_code(eap_code_response);
	gsmsim_response.set_identifier(static_cast<u8_t>(m_last_eap_identifier));
	gsmsim_response.set_type(
		eap_type_gsmsim,
		m_use_eap_expanded_type);
	gsmsim_response.set_subtype(gsmsim_subtype_Client_Error);


	update_buffer_indexes(
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		m_gsmsim_header_offset+gsmsim_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t gsmsim_data_free = packet_buffer_free;
	u32_t gsmsim_data_offset = 0u;

	eap_status_e status = add_client_error_payload(
		&gsmsim_response,
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		gsmsim_response.get_header_length(),
		&gsmsim_data_offset,
		&gsmsim_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		m_client_error_code);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	gsmsim_response.set_data_length(
		gsmsim_data_offset,
		m_use_eap_expanded_type);

	eap_client_error_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
		== packet_buffer_offset);

	status = eap_status_process_general_error;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	eap_client_error_packet.set_data_length(packet_buffer_offset);

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("    send: EAP-Response/Client-Error packet"),
		gsmsim_response.get_header_buffer(gsmsim_response.get_length()),
		gsmsim_response.get_length()));

	status = packet_send(
		&m_send_network_id,
		&eap_client_error_packet,
		m_gsmsim_header_offset,
		gsmsim_response.get_length(),
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::send_challenge_response_message(
		eap_variable_data_c * const K_aut)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("    send: GSMSIM-type %10s, %s, state %2d=%s\n"),
		EAPL("gsmsim_subtype_Challenge"),
		(m_is_client) ? EAPL("client") : EAPL("server"),
		m_state,
		get_state_string()
		));

	eap_buf_chain_wr_c gsmsim_initial_reply(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (gsmsim_initial_reply.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)
	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means GSMSIM does process every re-transmitted EAP-Request.
		gsmsim_initial_reply.set_do_packet_retransmission(false);
	}
#endif //#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)

	EAP_ASSERT_ALWAYS(EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH >= (m_gsmsim_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_gsmsim_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_gsmsim_header_offset+m_MTU;
	}

	gsmsim_header_c gsmsim_response(
		m_am_tools,
		gsmsim_initial_reply.get_data_offset(
			m_gsmsim_header_offset,
			(packet_buffer_free-m_gsmsim_header_offset)),
		(packet_buffer_free-m_gsmsim_header_offset));

	if (gsmsim_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet_send: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}


	gsmsim_response.reset_header(
		packet_buffer_free,
		m_use_eap_expanded_type);
	gsmsim_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_gsmsim_header_offset),
		m_use_eap_expanded_type);
	gsmsim_response.set_code(eap_code_response);
	gsmsim_response.set_identifier(m_last_eap_identifier);
	gsmsim_response.set_type(
		eap_type_gsmsim,
		m_use_eap_expanded_type);
	gsmsim_response.set_subtype(gsmsim_subtype_Challenge);

	update_buffer_indexes(
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		m_gsmsim_header_offset+gsmsim_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_type_gsmsim_c::send_challenge_response_message(0x%08x).\n"),
		this));

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t gsmsim_data_free = packet_buffer_free;
	u32_t gsmsim_data_offset = 0u;
	eap_status_e status = eap_status_process_general_error;

	u8_t *MAC_data = 0;
	u32_t MAC_data_length = 0u;
	eap_type_gsmsim_MAC_attributes_c MAC_attributes;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	if (m_use_result_indication == true)
	{
		// We support use of protected success indications.
		status = add_simple_payload(
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			gsmsim_payload_AT_RESULT_IND);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_mac_payload(
		&gsmsim_response,
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		gsmsim_response.get_header_length(),
		&gsmsim_data_offset,
		&gsmsim_data_free,
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

	gsmsim_response.set_data_length(
		gsmsim_data_offset,
		m_use_eap_expanded_type);

	gsmsim_initial_reply.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
		== packet_buffer_offset);

	// -   -   -   -   -   -   -   -   -   -   -   -

	MAC_attributes.init(
		MAC_data,
		MAC_data_length,
		gsmsim_response.get_header_buffer(gsmsim_response.get_length()),
		gsmsim_response.get_length());

	status = create_message_authentication_code(
		&MAC_attributes,
		gsmsim_response.get_subtype(),
		gsmsim_response.get_code(),
		K_aut);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	gsmsim_response.set_data_length(
		gsmsim_data_offset,
		m_use_eap_expanded_type);

	gsmsim_initial_reply.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
		== packet_buffer_offset);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = packet_send(
		&m_send_network_id,
		&gsmsim_initial_reply,
		m_gsmsim_header_offset,
		gsmsim_response.get_header_length()+gsmsim_response.get_data_length(),
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH
		);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::send_reauthentication_response_message(
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
		(EAPL("    send: GSMSIM-subtype %10s, %s, state %2d=%s\n"),
		EAPL("gsmsim_subtype_Re_authentication"),
		EAPL("client"),
		m_state,
		get_state_string()
		));

	eap_status_e status = eap_status_process_general_error;

	eap_buf_chain_wr_c request_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH);

	if (request_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)
	if (m_is_client == true
		&& m_client_responds_retransmitted_packets == true)
	{
		// We do not wan't lower layers do re-transmissions behalf of us.
		// This means GSMSIM does process every re-transmitted EAP-Request.
		request_packet.set_do_packet_retransmission(false);
	}
#endif //#if defined(USE_EAP_TYPE_GSMSIM_OWN_RE_TRANSMISSION)

	EAP_ASSERT_ALWAYS(EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH >= (m_gsmsim_header_offset+m_trailer_length));
	u32_t packet_buffer_free = EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH-m_trailer_length;
	u32_t packet_buffer_offset = 0u;

	if (m_gsmsim_header_offset+m_MTU < packet_buffer_free)
	{
		packet_buffer_free = m_gsmsim_header_offset+m_MTU;
	}

	gsmsim_header_c gsmsim_response(
		m_am_tools,
		request_packet.get_data_offset(
			m_gsmsim_header_offset,
			(packet_buffer_free-m_gsmsim_header_offset)),
		(packet_buffer_free-m_gsmsim_header_offset));

	if (gsmsim_response.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("send_reauthentication_response_message: packet buffer corrupted.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	gsmsim_response.reset_header(
		packet_buffer_free-m_gsmsim_header_offset,
		m_use_eap_expanded_type);
	gsmsim_response.set_length(
		static_cast<u16_t>(packet_buffer_free-m_gsmsim_header_offset),
		m_use_eap_expanded_type);
	gsmsim_response.set_code(eap_code_response);
	gsmsim_response.set_identifier(eap_identifier);
	gsmsim_response.set_type(
		eap_type_gsmsim,
		m_use_eap_expanded_type);
	gsmsim_response.set_subtype(gsmsim_subtype_Re_authentication);

	update_buffer_indexes(
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		m_gsmsim_header_offset+gsmsim_response.get_header_length(),
		&packet_buffer_offset,
		&packet_buffer_free);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::send_reauthentication_response_message(0x%08x).\n"),
		this));

	// - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t gsmsim_data_free = packet_buffer_free;
	u32_t gsmsim_data_offset = 0u;

	eap_variable_data_c master_session_key(m_am_tools);

	status = generate_reauth_shared_secred_keys(
		EAP_TYPE_GSMSIM_KEYMAT_SIZE,
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
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
			&packet_buffer_free,
			&packet_buffer_offset,
			gsmsim_payload_AT_RESULT_IND);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// -   -   -   -   -   -   -   -   -   -   -   -

	crypto_aes_c aes(m_am_tools);

	if (aes.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = m_am_type_gsmsim->generate_encryption_IV(
		m_IV.get_payload_buffer(),
		aes.get_block_size());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = add_variable_payload(
		&gsmsim_response,
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		gsmsim_response.get_header_length(),
		&gsmsim_data_offset,
		&gsmsim_data_free,
		&packet_buffer_free,
		&packet_buffer_offset,
		m_IV.get_payload_buffer(),
		gsmsim_payload_AT_IV);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	u8_t *MAC_data = 0;
	u32_t MAC_data_length = 0u;
	eap_type_gsmsim_MAC_attributes_c MAC_attributes;

	// Encrypted data.
	{
		gsmsim_payload_AT_header_c gp_encrypted_data(
			m_am_tools,
			gsmsim_response.get_data_offset(
				gsmsim_data_offset, 
				gsmsim_data_free),
			gsmsim_data_free);
		if (gp_encrypted_data.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		// Initialize the length of encrypted data to maximum length.
		// Later this will be set to correct length.
		gp_encrypted_data.reset_header(gsmsim_payload_AT_header_c::get_max_payload_data_length());
		gp_encrypted_data.set_current_payload(gsmsim_payload_AT_ENCR_DATA);

		update_payload_indexes(
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			gp_encrypted_data.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
			&packet_buffer_offset,
			&packet_buffer_free);

		u32_t encrypted_data_offset_begin = packet_buffer_offset;


		// -   -   -   -   -   -   -   -   -   -   -   -

		if (include_at_counter_too_small == true)
		{
			status = add_simple_payload(
				&gsmsim_response,
				EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
				gsmsim_response.get_header_length(),
				&gsmsim_data_offset,
				&gsmsim_data_free,
				&packet_buffer_free,
				&packet_buffer_offset,
				gsmsim_payload_AT_COUNTER_TOO_SMALL);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// -   -   -   -   -   -   -   -   -   -   -   -

		status = add_counter_payload(
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
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
			&gsmsim_response,
			EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
			gsmsim_response.get_header_length(),
			&gsmsim_data_offset,
			&gsmsim_data_free,
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
			m_IV.get_payload_buffer(),
			orig_K_encr);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_GSMSIM_TRACE_PAYLOAD("Payload added", &gp_encrypted_data);
	}



	// -   -   -   -   -   -   -   -   -   -   -   -

	status = add_mac_payload(
		&gsmsim_response,
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH,
		gsmsim_response.get_header_length(),
		&gsmsim_data_offset,
		&gsmsim_data_free,
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

	gsmsim_response.set_data_length(
		gsmsim_data_offset,
		m_use_eap_expanded_type);

	request_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
		== packet_buffer_offset);

	// -   -   -   -   -   -   -   -   -   -   -   -

	MAC_attributes.init(
		MAC_data,
		MAC_data_length,
		gsmsim_response.get_header_buffer(gsmsim_response.get_length()),
		gsmsim_response.get_length());

	status = create_message_authentication_code(
		&MAC_attributes,
		gsmsim_response.get_subtype(),
		gsmsim_response.get_code(),
		orig_K_aut);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	gsmsim_response.set_data_length(
		gsmsim_data_offset,
		m_use_eap_expanded_type);

	request_packet.set_data_length(packet_buffer_offset);

	EAP_ASSERT_ALWAYS(
		m_gsmsim_header_offset+gsmsim_response.get_header_length()+gsmsim_response.get_data_length()
		== packet_buffer_offset);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_gsmsim_c::send_reauthentication_request_message()\n")));

	status = packet_send(
		&m_send_network_id,
		&request_packet,
		m_gsmsim_header_offset,
		gsmsim_response.get_header_length()+gsmsim_response.get_data_length(),
		EAP_TYPE_GSMSIM_LOCAL_PACKET_BUFFER_LENGTH
		);

	if (status == eap_status_ok)
	{
		if (include_at_counter_too_small == false)
		{
			status = m_master_session_key.set_copy_of_buffer(&master_session_key);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (include_at_counter_too_small == true)
		{
			// The full authentication must follow.
			m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::decrypt_DATA_payload(
	gsmsim_payloads_c * const p_gsmsim_payloads,
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

	if (p_gsmsim_payloads->get_ENCR_DATA()->get_data_length() == 0
		|| (p_gsmsim_payloads->get_ENCR_DATA()->get_data_length() % aes_key_length) != 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	if (p_gsmsim_payloads->get_IV()->get_payload_included() == false
		|| p_gsmsim_payloads->get_IV()->get_data_length() == 0u
		|| encryption_key->get_is_valid_data() == false
		|| encryption_key->get_data_length() == 0u)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	if (p_gsmsim_payloads->get_ENCR_DATA()->get_payload_included() == false
		|| p_gsmsim_payloads->get_ENCR_DATA()->get_data_length() == 0u)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
	}


	status = cbc_aes.set_decryption_key(
		p_gsmsim_payloads->get_IV()->get_data(p_gsmsim_payloads->get_IV()->get_data_length()),
		p_gsmsim_payloads->get_IV()->get_data_length(),
		encryption_key->get_data(),
		aes_key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = cbc_aes.decrypt_data(
		p_gsmsim_payloads->get_ENCR_DATA()->get_data(p_gsmsim_payloads->get_ENCR_DATA()->get_data_length()),
		p_gsmsim_payloads->get_ENCR_DATA()->get_data_length());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_DATA_payload(
	const gsmsim_subtype_e subtype,
	gsmsim_payloads_c * const p_gsmsim_payloads
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_process_general_error;

	if (p_gsmsim_payloads->get_ENCR_DATA() == 0
		|| p_gsmsim_payloads->get_ENCR_DATA()->get_data_length() == 0u)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u32_t state_payload_buffer_length = p_gsmsim_payloads->get_ENCR_DATA()->get_data_length();
	const gsmsim_payload_AT_header_c gp_data_payload(
		m_am_tools,
		p_gsmsim_payloads->get_ENCR_DATA()->get_data(state_payload_buffer_length),
		state_payload_buffer_length);

	if (gp_data_payload.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	status = parse_gsmsim_payload(
		&gp_data_payload,
		&state_payload_buffer_length,
		p_gsmsim_payloads,
		subtype);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (p_gsmsim_payloads->get_NEXT_PSEUDONYM()->get_payload_included() == true)
	{
		if (p_gsmsim_payloads->get_padding_payload()->get_payload_included() == true
			&& p_gsmsim_payloads->get_padding_payload()->get_data_length() > 0u)
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
				p_gsmsim_payloads->get_padding_payload()->get_data(p_gsmsim_payloads->get_padding_payload()->get_data_length()),
				p_gsmsim_payloads->get_padding_payload()->get_data_length(),
				0ul);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// GSMSIM AM could store pseudonym to favourite place.
		status = m_am_type_gsmsim->store_pseudonym_id(
			&m_send_network_id,
			p_gsmsim_payloads->get_NEXT_PSEUDONYM()->get_payload_buffer());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (p_gsmsim_payloads->get_NEXT_REAUTH_ID()->get_payload_included() == true)
	{
		if (p_gsmsim_payloads->get_padding_payload()->get_payload_included() == true
			&& p_gsmsim_payloads->get_padding_payload()->get_data_length() > 0u)
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
				p_gsmsim_payloads->get_padding_payload()->get_data(p_gsmsim_payloads->get_padding_payload()->get_data_length()),
				p_gsmsim_payloads->get_padding_payload()->get_data_length(),
				0ul);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		// GSMSIM AM could store pseudonym to favourite place.
		status = m_am_type_gsmsim->store_reauthentication_id(
			&m_send_network_id,
			p_gsmsim_payloads->get_NEXT_REAUTH_ID()->get_payload_buffer());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		// GSMSIM AM should remove re-authentication identity from favourite place.

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_gsmsim_c::handle_DATA_payload(0x%08x): Resets re-authentication identity from database.\n"),
			 this));

		status = m_am_type_gsmsim->store_reauthentication_id(
			&m_send_network_id,
			0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		m_reauthentication_identity.reset();
	}

	status = eap_status_ok;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_start_request_message(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t /* gsmsim_packet_length */,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	eap_status_e status = eap_status_process_general_error;

#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	const eap_type_gsmsim_state_variable_e gsmsim_start_request_states[] =
	{
		eap_type_gsmsim_state_waiting_for_start_request,
		eap_type_gsmsim_state_pseydonym_waiting_for_start_request,
		eap_type_gsmsim_state_imsi_waiting_for_start_request,
		eap_type_gsmsim_state_waiting_for_challenge_request,
		eap_type_gsmsim_state_waiting_for_reauth_request,
	};

	if (verify_states(gsmsim_start_request_states, GSMSIM_STATE_COUNT(gsmsim_start_request_states)) == true)
#else
	if (m_state == eap_type_gsmsim_state_waiting_for_start_request
		|| m_state == eap_type_gsmsim_state_pseydonym_waiting_for_start_request
		|| m_state == eap_type_gsmsim_state_imsi_waiting_for_start_request
		|| m_state == eap_type_gsmsim_state_waiting_for_challenge_request
		|| m_state == eap_type_gsmsim_state_waiting_for_reauth_request)
#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	{
		// This could be first or retransmission request.

		// Checks the payloads existence.
		if (p_gsmsim_payloads->check_payloads(
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_mt
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // MAC
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ENCR_DATA
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IDENTITY
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // n_RANDs
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional,    // PERMANENT_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional,    // FULLAUTH_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional,    // ANY_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IV
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NOTIFICATION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // VERSION_LIST
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // SELECTED_VERSION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be,  // CLIENT_ERROR_CODE
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be  // RESULT_IND
				) == true
			)
		{
			// NOTE, this message is unauthenticated. Anybody could sent this message.

			bool includes_other_version_than_1 = false;

			eap_gsmsim_version selected_version = select_version(
				p_gsmsim_payloads->get_VERSION_LIST(),
				&includes_other_version_than_1);

			if (selected_version == GSMSIM_ILLEGAL_VERSION)
			{
				// ERROR, no supported version.
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: eap_type_gsmsim_c::handle_start_request_message(0x%08x), illegal version list.\n"),
					this));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
			}

			if (p_gsmsim_payloads->get_includes_unknown_attribute() != gsmsim_payload_NONE
				&& includes_other_version_than_1 == false)
			{
				// EAP-SIM version 1 must NOT include unknown attributes.
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: eap_type_gsmsim_c::handle_start_request_message(0x%08x), illegal payload %d=0x%04x.\n"),
					this,
					p_gsmsim_payloads->get_includes_unknown_attribute(),
					p_gsmsim_payloads->get_includes_unknown_attribute()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}

			gsmsim_payload_AT_type_e include_identity_to_start_response = gsmsim_payload_NONE;


			{
				if ((p_gsmsim_payloads->get_PERMANENT_ID_REQ()->get_payload_included() == true
						&& p_gsmsim_payloads->get_FULLAUTH_ID_REQ()->get_payload_included() == true)
					|| (p_gsmsim_payloads->get_PERMANENT_ID_REQ()->get_payload_included() == true
						&& p_gsmsim_payloads->get_ANY_ID_REQ()->get_payload_included() == true)
					|| (p_gsmsim_payloads->get_FULLAUTH_ID_REQ()->get_payload_included() == true
						&& p_gsmsim_payloads->get_ANY_ID_REQ()->get_payload_included() == true))
				{
					// Only one of these is allowed.
					EAP_TRACE_ERROR(
						m_am_tools, 
						TRACE_FLAGS_GSMSIM_ERROR, 
						(EAPL("ERROR: eap_type_gsmsim_c::handle_start_request_message(0x%08x), illegal payloads.\n"),
						this));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
				}
				else if (p_gsmsim_payloads->get_PERMANENT_ID_REQ()->get_payload_included() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_start_request_message ")
						 EAPL("gsmsim_payload_AT_PERMANENT_ID_REQ\n")));
					// Note, this is optional, included only when pseudonym decode failed in server.
					include_identity_to_start_response = gsmsim_payload_AT_PERMANENT_ID_REQ;
				}
				else if (p_gsmsim_payloads->get_FULLAUTH_ID_REQ()->get_payload_included() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_start_request_message ")
						 EAPL("gsmsim_payload_AT_FULLAUTH_ID_REQ\n")));
					// Note, this is optional, included only when reauthentication identity decode failed in server.
					include_identity_to_start_response = gsmsim_payload_AT_FULLAUTH_ID_REQ;
				}
				else if (p_gsmsim_payloads->get_ANY_ID_REQ()->get_payload_included() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_start_request_message ")
						 EAPL("gsmsim_payload_AT_ANY_ID_REQ\n")));
					// Note, this is optional, included only when server have no identity of client.
					include_identity_to_start_response = gsmsim_payload_AT_ANY_ID_REQ;
				}
			}

			if (m_nonce_mt.get_is_valid_data() == false)
			{
				// Note, if this message is retransmitted request the NONCE_MT 
				// is already generated.
				status = generate_nonce(EAP_TYPE_GSMSIM_NONCE_MT_SIZE, &m_nonce_mt);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			u32_t version_payload_length = p_gsmsim_payloads->get_VERSION_LIST()->get_original_header()->get_data_length();
			u32_t real_payload_length = p_gsmsim_payloads->get_VERSION_LIST()->get_original_header()->get_reserved();

			if (real_payload_length == 0
				|| real_payload_length > version_payload_length)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_no_matching_protocol_version);
			}
			
			u32_t version_count = real_payload_length/sizeof(u16_t);
			u16_t *payload_version_list = reinterpret_cast<u16_t *>(p_gsmsim_payloads->get_VERSION_LIST()
				->get_original_header()->get_data(real_payload_length));
			
			status = save_version(payload_version_list, version_count, selected_version);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			m_include_identity_to_start_response = include_identity_to_start_response;


			if (include_identity_to_start_response == gsmsim_payload_NONE
				&& (m_identity.get_is_valid_data() == false))
			{
				// We must query the previous sent EAP-Identity from EAP_Core.
				// The EAP_Core saves the sent EAP-Identity when the EAP-Identity is
				// sent to the network.
				// Previous EAP-type was NOT this instance. EAP-Identity was queried from other instance.
				status = get_type_partner()->get_saved_eap_identity(&m_identity);
				if (status != eap_status_ok)
				{
					// We do not have the identity server accepted anymore.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = m_NAI.set_copy_of_buffer(&m_identity);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}


			if (include_identity_to_start_response == gsmsim_payload_AT_ANY_ID_REQ
				&& (m_reauthentication_identity.get_is_valid_data() == false
					&& m_pseudonym.get_is_valid_data() == false
					&& m_IMSI.get_is_valid_data() == false
					&& m_automatic_realm_read == false))
			{
				eap_variable_data_c IMSI(m_am_tools);
				eap_variable_data_c pseudonym(m_am_tools);
				eap_variable_data_c reauthentication_identity(m_am_tools);

				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_type_gsmsim_c::handle_start_request_message ")
					 EAPL("gsmsim_payload_AT_ANY_ID_REQ\n")));

				status = query_SIM_IMSI_or_pseudonym_or_reauthentication_id(
					&IMSI,
					&pseudonym,
					&reauthentication_identity,
					&m_automatic_realm,
					&m_length_of_mnc,
					false,
					include_identity_to_start_response,
					eap_type_gsmsim_complete_start_request,
					received_gsmsim->get_identifier());

				if (status == eap_status_pending_request)
				{
					// This is pending query, that will be completed by complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() call.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else if (status == eap_status_completed_request)
				{
					// This is already completed by complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() call.
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_start_request_message(): ")
						 EAPL("completed returns eap_type_gsmsim_state_variable_e %d=%s.\n"),
						 m_state,
						 get_state_string()));

					status = eap_status_ok;
					
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else if (status != eap_status_ok)
				{
					// This is the error case.

					EAP_TRACE_ERROR(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_start_request_message(): ")
						 EAPL("error returns eap_type_gsmsim_state_variable_e %d=%s.\n"),
						 m_state,
						 get_state_string()));
					
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				
				if (reauthentication_identity.get_is_valid_data() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_start_request_message ")
						 EAPL("reauthentication_identity\n")));

					status = m_reauthentication_identity.set_copy_of_buffer(&reauthentication_identity);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = store_identity(&m_reauthentication_identity, false);
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
						(EAPL("eap_type_gsmsim_c::handle_start_request_message pseudonym\n")));

					m_reauthentication_identity.reset();
					status = m_pseudonym.set_copy_of_buffer(&pseudonym);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = store_identity(&m_pseudonym, false);
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
						(EAPL("eap_type_gsmsim_c::handle_start_request_message IMSI\n")));

					m_reauthentication_identity.reset();
					m_pseudonym.reset();
					status = m_IMSI.set_copy_of_buffer(&IMSI);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = store_identity(&m_IMSI, true);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
			else if (include_identity_to_start_response == gsmsim_payload_AT_FULLAUTH_ID_REQ
					&& (m_pseudonym.get_is_valid_data() == false
						&& m_IMSI.get_is_valid_data() == false
						&& m_automatic_realm_read == false))
			{
				eap_variable_data_c IMSI(m_am_tools);
				eap_variable_data_c pseudonym(m_am_tools);
				eap_variable_data_c reauthentication_identity(m_am_tools);

				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_type_gsmsim_c::handle_start_request_message ")
					 EAPL("gsmsim_payload_AT_FULLAUTH_ID_REQ\n")));

				status = query_SIM_IMSI_or_pseudonym_or_reauthentication_id(
					&IMSI,
					&pseudonym,
					&reauthentication_identity,
					&m_automatic_realm,
					&m_length_of_mnc,
					false,
					include_identity_to_start_response,
					eap_type_gsmsim_complete_start_request,
					received_gsmsim->get_identifier());

				if (status == eap_status_pending_request)
				{
					// This is pending query, that will be completed by complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() call.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else if (status == eap_status_completed_request)
				{
					// This is already completed by complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() call.
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_start_request_message(): ")
						 EAPL("completed returns eap_type_gsmsim_state_variable_e %d=%s.\n"),
						 m_state,
						 get_state_string()));

					status = eap_status_ok;

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else if (status != eap_status_ok)
				{
					// This is the error case.

					EAP_TRACE_ERROR(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_start_request_message(): ")
						 EAPL("error returns eap_type_gsmsim_state_variable_e %d=%s.\n"),
						 m_state,
						 get_state_string()));
					
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				if (pseudonym.get_is_valid_data() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_start_request_message pseudonym\n")));

					m_reauthentication_identity.reset();
					status = m_pseudonym.set_copy_of_buffer(&pseudonym);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = store_identity(&m_pseudonym, false);
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
						(EAPL("eap_type_gsmsim_c::handle_start_request_message IMSI\n")));

					m_reauthentication_identity.reset();
					m_pseudonym.reset();
					status = m_IMSI.set_copy_of_buffer(&IMSI);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = store_identity(&m_IMSI, true);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
			else if (include_identity_to_start_response == gsmsim_payload_AT_PERMANENT_ID_REQ
					&& m_IMSI.get_is_valid_data() == false
					&& m_automatic_realm_read == false)
			{
				eap_variable_data_c IMSI(m_am_tools);
				eap_variable_data_c pseudonym(m_am_tools);
				eap_variable_data_c reauthentication_identity(m_am_tools);

				EAP_TRACE_DEBUG(
					m_am_tools, 
					TRACE_FLAGS_DEFAULT, 
					(EAPL("eap_type_gsmsim_c::handle_start_request_message ")
					 EAPL("gsmsim_payload_AT_PERMANENT_ID_REQ\n")));

				status = query_SIM_IMSI_or_pseudonym_or_reauthentication_id(
					&IMSI,
					&pseudonym,
					&reauthentication_identity,
					&m_automatic_realm,
					&m_length_of_mnc,
					false,
					include_identity_to_start_response,
					eap_type_gsmsim_complete_start_request,
					received_gsmsim->get_identifier());

				if (status == eap_status_pending_request)
				{
					// This is pending query, that will be completed by complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() call.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else if (status == eap_status_completed_request)
				{
					// This is already completed by complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() call.
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_start_request_message(): ")
						 EAPL("completed returns eap_type_gsmsim_state_variable_e %d=%s.\n"),
						 m_state,
						 get_state_string()));
					
					status = eap_status_ok;

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
				else if (status != eap_status_ok)
				{
					// This is the error case.

					EAP_TRACE_ERROR(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_start_request_message(): ")
						 EAPL("error returns eap_type_gsmsim_state_variable_e %d=%s.\n"),
						 m_state,
						 get_state_string()));
					
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				if (IMSI.get_is_valid_data() == true)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_start_request_message IMSI\n")));

					m_reauthentication_identity.reset();
					m_pseudonym.reset();
					status = m_IMSI.set_copy_of_buffer(&IMSI);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = store_identity(&m_IMSI, true);
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
			set_state(eap_type_gsmsim_state_analyse_start_request);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::handle_start_request_message(0x%08x).\n"),
				 this));

			status = send_start_response_message(
				receive_network_id,
				received_gsmsim->get_identifier(),
				selected_version,
				include_identity_to_start_response,
				&m_automatic_realm,
				m_length_of_mnc);

			if (status != eap_status_ok)
			{
				restore_saved_previous_state();
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			// Not correct GSMSIM-payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_start_request_message(1): ")
				 EAPL("Not correct GSMSIM-payloads are included in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_start_request_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 received_gsmsim->get_subtype(),
			 received_gsmsim->get_subtype_string(),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_gsmsim_notification_request_message_reauthentication(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t /*gsmsim_packet_length*/,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: GSMSIM-type %10s, %s, state %2d=%s\n"),
		 EAPL("handle_gsmsim_notification_request_message_reauthentication"),
		 (m_is_client) ? EAPL("client") : EAPL("server"),
		 m_state,
		 get_state_string()
		 ));

#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	const eap_type_gsmsim_state_variable_e gsmsim_notification_request_message_reauthentication_states_1[] =
	{
		eap_type_gsmsim_state_waiting_for_success,
		eap_type_gsmsim_state_success,
		eap_type_gsmsim_state_waiting_for_notification_request_success,
	};

	const eap_type_gsmsim_state_variable_e gsmsim_notification_request_message_reauthentication_states_2[] =
	{
		eap_type_gsmsim_state_waiting_for_identity_request,
		eap_type_gsmsim_state_pending_identity_query,
		eap_type_gsmsim_state_waiting_for_start_request,
		eap_type_gsmsim_state_imsi_waiting_for_start_request,
		eap_type_gsmsim_state_pseydonym_waiting_for_start_request,
		eap_type_gsmsim_state_analyse_start_request,
		eap_type_gsmsim_state_waiting_for_challenge_request,
		eap_type_gsmsim_state_analyses_challenge_request,
		eap_type_gsmsim_state_pending_kc_sres_query,
		eap_type_gsmsim_state_waiting_for_reauth_request,
		eap_type_gsmsim_state_analyses_reauthentication_request,
		eap_type_gsmsim_state_waiting_for_success,
		eap_type_gsmsim_state_success,
		eap_type_gsmsim_state_waiting_for_notification_request_success,
		eap_type_gsmsim_state_failure,
	};

	if (get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code) == false
		&& verify_states(gsmsim_notification_request_message_reauthentication_states_1,
						 GSMSIM_STATE_COUNT(gsmsim_notification_request_message_reauthentication_states_1)) == true)
#else
	// The second most significant bit of the notification code is called
	// the Phase bit (P bit). It specifies at which phase of the EAP-SIM
	// exchange the notification can be used.
	if (get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code) == false
		&& (m_state == eap_type_gsmsim_state_waiting_for_success
			|| m_state == eap_type_gsmsim_state_success
			|| m_state == eap_type_gsmsim_state_waiting_for_notification_request_success)
		)
#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	{
		// If the P bit is set to zero,
		// the notification can only be used after a successful EAP/SIM/
		// Challenge round in full authentication or a successful EAP/SIM/
		// Re-authentication round in reautentication. A re-authentication round
		// is considered successful only if the peer has successfully verified
		// AT_MAC and AT_COUNTER attributes, and does not include the
		// AT_COUNTER_TOO_SMALL attribute in EAP-Response/SIM/Re-authentication.

		// The AT_MAC attribute MUST beincluded if the P bit of the notification
		// code in AT_NOTIFICATION is set to zero, and MUST NOT be included in
		// cases when the P bit is set to one. The P bit is discussed in Section
		// 4.4.
		if (p_gsmsim_payloads->check_payloads(
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_mt
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // MAC
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // ENCR_DATA
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IDENTITY
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // n_RANDs
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // PERMANENT_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // FULLAUTH_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ANY_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // IV
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // NOTIFICATION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // VERSION_LIST
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // SELECTED_VERSION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // CLIENT_ERROR_CODE
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be  // RESULT_IND
				) == true
			)
		{
			eap_variable_data_c orig_XKEY(m_am_tools);
			eap_variable_data_c orig_K_aut(m_am_tools);
			eap_variable_data_c orig_K_encr(m_am_tools);
			u32_t reauth_counter = 0u;

			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_gsmsim->query_reauth_parameters(
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

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_type_gsmsim_c::handle_gsmsim_notification_request_message_reauthentication(): %s, m_saved_reauth_counter %d.\n"),
				 (m_is_client == true ? "client": "server"),
				 reauth_counter));

			status = check_message_authentication_code(
				&orig_K_aut,
				p_gsmsim_payloads,
				received_gsmsim,
				received_gsmsim->get_length());
			if (status != eap_status_ok)
			{
				(void) initialize_error_message(status);

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			bool authentication_ok = true;

			// Decrypt and parse encrypted payload.
			{
				gsmsim_payloads_c * const l_gsmsim_payloads = new gsmsim_payloads_c(m_am_tools);
				eap_automatic_variable_c<gsmsim_payloads_c> l_gsmsim_payloads_automatic(m_am_tools, l_gsmsim_payloads);

				if (l_gsmsim_payloads == 0
					|| l_gsmsim_payloads->get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				status = decrypt_DATA_payload(
					p_gsmsim_payloads,
					&orig_K_encr);
				if (status != eap_status_ok)
				{
					restore_saved_previous_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				u32_t state_payload_buffer_length = p_gsmsim_payloads->get_ENCR_DATA()->get_data_length();
				const gsmsim_payload_AT_header_c gp_data_payload(
					m_am_tools,
					p_gsmsim_payloads->get_ENCR_DATA()->get_data(state_payload_buffer_length),
					state_payload_buffer_length);

				status = parse_gsmsim_payload(
					&gp_data_payload,
					&state_payload_buffer_length,
					l_gsmsim_payloads,
					received_gsmsim->get_subtype());
				if (status != eap_status_ok)
				{
					restore_saved_previous_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}


				if (l_gsmsim_payloads->get_COUNTER()->get_payload_included() == false)
				{
					restore_saved_previous_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
				}

				u32_t counter = l_gsmsim_payloads->get_COUNTER()->get_original_header()->get_reserved();

				if (counter == reauth_counter)
				{
					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_gsmsim_notification_request_message_reauthentication(): ")
						EAPL("reauth counter %d OK, %d=%s.\n"),
						reauth_counter,
						m_state,
						get_state_string()));
				}
				else
				{
					EAP_TRACE_ERROR(
						m_am_tools, 
						TRACE_FLAGS_GSMSIM_ERROR, 
						(EAPL("ERROR: eap_type_gsmsim_c::handle_gsmsim_notification_request_message_reauthentication(): ")
						EAPL("reauth counter %d wrong, should be %d, %d=%s.\n"),
						counter,
						reauth_counter,
						m_state,
						get_state_string()));

					authentication_ok = false;
				}
			}


			bool do_increase_reauth_counter(false);

			// The most significant bit is called the Failure bit (F bit).
			// The F bit specifies whether the notification implies failure.
			if (authentication_ok == false
				|| get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == false)
			{
				// The code values with the F bit set to zero (code values 0...32767)
				// are used on unsuccessful cases.
				// The receipt of a notification code from this range implies failed EAP
				// exchange, so the peer can use the notification as a failure indication.

				set_state(eap_type_gsmsim_state_failure);

				// This will terminate session immediately.
				get_type_partner()->set_session_timeout(0ul);
			}
			else //if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == true)
			{
				// The receipt of a notification code with the F bit set to one (values
				// 32768...65536) does not imply failure. Notification code 32768 has
				// been reserved as a general notification code to indicate successful
				// authentication.
				if (m_gsmsim_notification_code == eap_gsmsim_notification_F_set_no_P_user_authenticated)
				{
					do_increase_reauth_counter = true;

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
						set_state(eap_type_gsmsim_state_waiting_for_success);
						status = eap_status_ok;

						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
							(EAPL("EAP_type_GSMSIM: %s, re-authentication OK, waits EAP-Success\n"),
							 (m_is_client == true) ? "client": "server"));
					}
				}
			}

			status = send_gsmsim_notification_response(
				m_gsmsim_notification_code,
				true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (do_increase_reauth_counter == true)
			{
				// Re-authentication counter is increased only on first time.
				// In order to use re-authentication, the client and the server need to
				// update re-authentication counter value.
				status = m_am_type_gsmsim->increase_reauth_counter();
				if (status != eap_status_ok)
				{
					restore_saved_previous_state();
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		else
		{
			// Not correct GSMSIM-payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_gsmsim_notification_request_message(1): ")
				EAPL("Not correct GSMSIM-payloads are included in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				m_state,
				get_state_string()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
	}
#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	else if (get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code) == true
		&& verify_states(gsmsim_notification_request_message_reauthentication_states_2,
						 GSMSIM_STATE_COUNT(gsmsim_notification_request_message_reauthentication_states_2)) == true)
#else
	else if (get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code) == true
		&& (m_state == eap_type_gsmsim_state_waiting_for_identity_request
			|| m_state == eap_type_gsmsim_state_pending_identity_query
			|| m_state == eap_type_gsmsim_state_waiting_for_start_request
			|| m_state == eap_type_gsmsim_state_imsi_waiting_for_start_request
			|| m_state == eap_type_gsmsim_state_pseydonym_waiting_for_start_request
			|| m_state == eap_type_gsmsim_state_analyse_start_request
			|| m_state == eap_type_gsmsim_state_waiting_for_challenge_request
			|| m_state == eap_type_gsmsim_state_analyses_challenge_request
			|| m_state == eap_type_gsmsim_state_pending_kc_sres_query
			|| m_state == eap_type_gsmsim_state_waiting_for_reauth_request
			|| m_state == eap_type_gsmsim_state_analyses_reauthentication_request
			|| m_state == eap_type_gsmsim_state_waiting_for_success
			|| m_state == eap_type_gsmsim_state_success
			|| m_state == eap_type_gsmsim_state_waiting_for_notification_request_success
			|| m_state == eap_type_gsmsim_state_failure))
#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	{
		// If the P bit is set to one, the notification can only by used before
		// the EAP/SIM/Challenge round in full authentication, or before the
		// EAP/SIM/Re-authentication round in reauthentication.

		// The most significant bit is called the Failure bit (F bit).
		// The F bit specifies whether the notification implies failure.
		if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == false)
		{
			// The code values with the F bit set to zero (code values 0...32767)
			// are used on unsuccessful cases.
			// The receipt of a notification code from this range implies failed EAP
			// exchange, so the peer can use the notification as a failure indication.
		}
		else //if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == true)
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
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_gsmsim_notification_request_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 received_gsmsim->get_subtype(),
			 received_gsmsim->get_subtype_string(),
			 m_state,
			 get_state_string()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_gsmsim_notification_request_message_full_authentication(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t /*gsmsim_packet_length*/,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("send: GSMSIM-type %10s, %s, state %2d=%s\n"),
		 EAPL("handle_gsmsim_notification_request_message_full_authentication"),
		 (m_is_client) ? EAPL("client") : EAPL("server"),
		 m_state,
		 get_state_string()
		 ));

#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	const eap_type_gsmsim_state_variable_e gsmsim_notification_request_message_full_authentication_states_1[] =
	{
		eap_type_gsmsim_state_waiting_for_success,
		eap_type_gsmsim_state_success,
		eap_type_gsmsim_state_waiting_for_notification_request_success,
	};

	const eap_type_gsmsim_state_variable_e gsmsim_notification_request_message_full_authentication_states_2[] =
	{
		eap_type_gsmsim_state_waiting_for_identity_request,
		eap_type_gsmsim_state_pending_identity_query,
		eap_type_gsmsim_state_waiting_for_start_request,
		eap_type_gsmsim_state_imsi_waiting_for_start_request,
		eap_type_gsmsim_state_pseydonym_waiting_for_start_request,
		eap_type_gsmsim_state_analyse_start_request,
		eap_type_gsmsim_state_waiting_for_challenge_request,
		eap_type_gsmsim_state_analyses_challenge_request,
		eap_type_gsmsim_state_pending_kc_sres_query,
		eap_type_gsmsim_state_waiting_for_reauth_request,
		eap_type_gsmsim_state_analyses_reauthentication_request,
		eap_type_gsmsim_state_waiting_for_success,
		eap_type_gsmsim_state_success,
		eap_type_gsmsim_state_waiting_for_notification_request_success,
		eap_type_gsmsim_state_failure,
	};

	if (get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code) == false
		&& verify_states(gsmsim_notification_request_message_full_authentication_states_1,
						 GSMSIM_STATE_COUNT(gsmsim_notification_request_message_full_authentication_states_1)) == true)
#else
	// The second most significant bit of the notification code is called
	// the Phase bit (P bit). It specifies at which phase of the EAP-SIM
	// exchange the notification can be used.
	if (get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code) == false
		&& (m_state == eap_type_gsmsim_state_waiting_for_success
			|| m_state == eap_type_gsmsim_state_success
			|| m_state == eap_type_gsmsim_state_waiting_for_notification_request_success)
		)
#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	{
		// If the P bit is set to zero,
		// the notification can only be used after a successful EAP/SIM/
		// Challenge round in full authentication or a successful EAP/SIM/
		// Re-authentication round in reautentication. A re-authentication round
		// is considered successful only if the peer has successfully verified
		// AT_MAC and AT_COUNTER attributes, and does not include the
		// AT_COUNTER_TOO_SMALL attribute in EAP-Response/SIM/Re-authentication.

		// The AT_MAC attribute MUST beincluded if the P bit of the notification
		// code in AT_NOTIFICATION is set to zero, and MUST NOT be included in
		// cases when the P bit is set to one. The P bit is discussed in Section
		// 4.4.
		if (p_gsmsim_payloads->check_payloads(
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_mt
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // MAC
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ENCR_DATA
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IDENTITY
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // n_RANDs
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // PERMANENT_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // FULLAUTH_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ANY_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IV
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // NOTIFICATION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // VERSION_LIST
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // SELECTED_VERSION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // CLIENT_ERROR_CODE
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional     // RESULT_IND
				) == true
			)
		{
			status = check_message_authentication_code(
				&m_K_aut,
				p_gsmsim_payloads,
				received_gsmsim,
				received_gsmsim->get_length());
			if (status != eap_status_ok)
			{
				(void) initialize_error_message(status);

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (m_use_result_indication == false
				&& m_gsmsim_notification_code == eap_gsmsim_notification_F_set_no_P_user_authenticated)
			{
				// ERROR: We did not require result indication and server send it to us.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
			}

			// The most significant bit is called the Failure bit (F bit).
			// The F bit specifies whether the notification implies failure.
			if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == false)
			{
				// The code values with the F bit set to zero (code values 0...32767)
				// are used on unsuccessful cases.
				// The receipt of a notification code from this range implies failed EAP
				// exchange, so the peer can use the notification as a failure indication.

				set_state(eap_type_gsmsim_state_failure);

				// This will terminate session immediately.
				get_type_partner()->set_session_timeout(0ul);
			}
			else //if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == true)
			{
				// The receipt of a notification code with the F bit set to one (values
				// 32768...65536) does not imply failure. Notification code 32768 has
				// been reserved as a general notification code to indicate successful
				// authentication.
				if (m_gsmsim_notification_code == eap_gsmsim_notification_F_set_no_P_user_authenticated)
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
						set_state(eap_type_gsmsim_state_waiting_for_success);
						status = eap_status_ok;

						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
							(EAPL("EAP_type_GSMSIM: %s, full-authentication OK, waits EAP-Success\n"),
							 (m_is_client == true) ? "client": "server"));
					}
				}
			}

			status = send_gsmsim_notification_response(
				m_gsmsim_notification_code,
				false);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			// Not correct GSMSIM-payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_gsmsim_notification_request_message(1): ")
				EAPL("Not correct GSMSIM-payloads are included in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				m_state,
				get_state_string()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
	}
#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	else if (get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code) == true
		&& verify_states(gsmsim_notification_request_message_full_authentication_states_2,
						 GSMSIM_STATE_COUNT(gsmsim_notification_request_message_full_authentication_states_2)) == true)
#else
	else if (get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code) == true
		&& (m_state == eap_type_gsmsim_state_waiting_for_identity_request
			|| m_state == eap_type_gsmsim_state_pending_identity_query
			|| m_state == eap_type_gsmsim_state_waiting_for_start_request
			|| m_state == eap_type_gsmsim_state_imsi_waiting_for_start_request
			|| m_state == eap_type_gsmsim_state_pseydonym_waiting_for_start_request
			|| m_state == eap_type_gsmsim_state_analyse_start_request
			|| m_state == eap_type_gsmsim_state_waiting_for_challenge_request
			|| m_state == eap_type_gsmsim_state_analyses_challenge_request
			|| m_state == eap_type_gsmsim_state_pending_kc_sres_query
			|| m_state == eap_type_gsmsim_state_waiting_for_reauth_request
			|| m_state == eap_type_gsmsim_state_analyses_reauthentication_request
			|| m_state == eap_type_gsmsim_state_waiting_for_success
			|| m_state == eap_type_gsmsim_state_success
			|| m_state == eap_type_gsmsim_state_waiting_for_notification_request_success
			|| m_state == eap_type_gsmsim_state_failure))
#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	{
		// If the P bit is set to one, the notification can only by used before
		// the EAP/SIM/Challenge round in full authentication, or before the
		// EAP/SIM/Re-authentication round in reauthentication.

		// The most significant bit is called the Failure bit (F bit).
		// The F bit specifies whether the notification implies failure.
		if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == false)
		{
			// The code values with the F bit set to zero (code values 0...32767)
			// are used on unsuccessful cases.
			// The receipt of a notification code from this range implies failed EAP
			// exchange, so the peer can use the notification as a failure indication.
		}
		else //if (get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code) == true)
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
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_gsmsim_notification_request_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 received_gsmsim->get_subtype(),
			 received_gsmsim->get_subtype_string(),
			 m_state,
			 get_state_string()));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_gsmsim_notification_request_message(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t gsmsim_packet_length,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_UNREFERENCED_PARAMETER(received_gsmsim);
	EAP_UNREFERENCED_PARAMETER(gsmsim_packet_length);
	EAP_UNREFERENCED_PARAMETER(receive_network_id);

#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	const eap_type_gsmsim_state_variable_e gsmsim_notification_request_message_states[] =
	{
		eap_type_gsmsim_state_waiting_for_identity_request,
		eap_type_gsmsim_state_pending_identity_query,
		eap_type_gsmsim_state_waiting_for_start_request,
		eap_type_gsmsim_state_imsi_waiting_for_start_request,
		eap_type_gsmsim_state_pseydonym_waiting_for_start_request,
		eap_type_gsmsim_state_analyse_start_request,
		eap_type_gsmsim_state_waiting_for_challenge_request,
		eap_type_gsmsim_state_analyses_challenge_request,
		eap_type_gsmsim_state_pending_kc_sres_query,
		eap_type_gsmsim_state_waiting_for_notification_request_success,
		eap_type_gsmsim_state_waiting_for_success,
		eap_type_gsmsim_state_waiting_for_reauth_request,
		eap_type_gsmsim_state_analyses_reauthentication_request,
		eap_type_gsmsim_state_success,
		eap_type_gsmsim_state_failure,
	};

	if (verify_states(gsmsim_notification_request_message_states,
					  GSMSIM_STATE_COUNT(gsmsim_notification_request_message_states)) == true)
#else
	if (m_state == eap_type_gsmsim_state_waiting_for_identity_request
		|| m_state == eap_type_gsmsim_state_pending_identity_query
		|| m_state == eap_type_gsmsim_state_waiting_for_start_request
		|| m_state == eap_type_gsmsim_state_imsi_waiting_for_start_request
		|| m_state == eap_type_gsmsim_state_pseydonym_waiting_for_start_request
		|| m_state == eap_type_gsmsim_state_analyse_start_request
		|| m_state == eap_type_gsmsim_state_waiting_for_challenge_request
		|| m_state == eap_type_gsmsim_state_analyses_challenge_request
		|| m_state == eap_type_gsmsim_state_pending_kc_sres_query
		|| m_state == eap_type_gsmsim_state_waiting_for_notification_request_success
		|| m_state == eap_type_gsmsim_state_waiting_for_success
		|| m_state == eap_type_gsmsim_state_waiting_for_reauth_request
		|| m_state == eap_type_gsmsim_state_analyses_reauthentication_request
		|| m_state == eap_type_gsmsim_state_success
		|| m_state == eap_type_gsmsim_state_failure
	)
#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	{
		// This could be first or retransmission request.

		// Checks the payloads existence.
		if (p_gsmsim_payloads->check_payloads(
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_mt
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional,    // MAC
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional,    // ENCR_DATA
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IDENTITY
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // n_RANDs
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // PERMANENT_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // FULLAUTH_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ANY_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional,    // IV
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // NOTIFICATION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // VERSION_LIST
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // SELECTED_VERSION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // CLIENT_ERROR_CODE
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional     // RESULT_IND
				) == true
			)
		{
			// NOTE, this message is unauthenticated. Anybody could sent this message.

			// We store the received notification code. This will be handled after session timeouts.
			m_gsmsim_notification_code =
				static_cast<eap_gsmsim_notification_codes_e>(
					p_gsmsim_payloads->get_NOTIFICATION()->get_original_header()->get_reserved());

			save_current_state();

			m_last_eap_identifier = received_gsmsim->get_identifier();

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::handle_gsmsim_notification_request_message(0x%08x), ")
				 EAPL("notification_code = 0x%04x, F bit %d, P bit %d, state %d=%s.\n"),
				 this,
				 m_gsmsim_notification_code,
				 get_gsmsim_notification_code_F_bit(m_gsmsim_notification_code),
				 get_gsmsim_notification_code_P_bit(m_gsmsim_notification_code),
				 m_state,
				 get_state_string()));

			if (m_authentication_type == GSMSIM_AUTHENTICATION_TYPE_REAUTHENTICATION)
			{
				status = handle_gsmsim_notification_request_message_reauthentication(
					receive_network_id,
					received_gsmsim,
					gsmsim_packet_length,
					p_gsmsim_payloads);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
			else
			{
				status = handle_gsmsim_notification_request_message_full_authentication(
					receive_network_id,
					received_gsmsim,
					gsmsim_packet_length,
					p_gsmsim_payloads);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		else
		{
			// Not correct GSMSIM-payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_gsmsim_notification_request_message(1): ")
				EAPL("Not correct GSMSIM-payloads are included in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				m_state,
				get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
		}
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_gsmsim_notification_request_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 received_gsmsim->get_subtype(),
			 received_gsmsim->get_subtype_string(),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_challenge_request_message(
	const eap_am_network_id_c * const /* receive_network_id */,
	gsmsim_header_c * const received_gsmsim,
	const u32_t gsmsim_packet_length,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	if (m_state == eap_type_gsmsim_state_waiting_for_challenge_request
		|| (m_state == eap_type_gsmsim_state_waiting_for_success && m_use_result_indication == false)
		|| (m_state == eap_type_gsmsim_state_waiting_for_notification_request_success && m_use_result_indication == true))
	{
		// This could be first or retransmission request.

		// Checks the payloads existence.
		if (p_gsmsim_payloads->check_payloads(
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_mt
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // MAC
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional,    // ENCR_DATA
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IDENTITY
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // n_RANDs
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // PERMANENT_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // FULLAUTH_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ANY_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional,    // IV
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NOTIFICATION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // VERSION_LIST
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // SELECTED_VERSION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be,  // CLIENT_ERROR_CODE
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional     // RESULT_IND
				) == true
			)
		{
			if (p_gsmsim_payloads->get_RESULT_IND()->get_payload_included() == true)
			{
				m_use_result_indication = m_allow_use_result_indication;
			}
			else
			{
				m_use_result_indication = false;
			}

			if (p_gsmsim_payloads->get_IV()->get_payload_included() == true
			|| p_gsmsim_payloads->get_ENCR_DATA()->get_payload_included() == true)
			{
				if (p_gsmsim_payloads->get_IV()->get_payload_included() == true
				&& p_gsmsim_payloads->get_ENCR_DATA()->get_payload_included() == true)
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
			// The MAC is checked later after n*Kc and n*SRES is get from SIM.
			status = m_saved_EAP_packet.set_copy_of_buffer(
				received_gsmsim->get_header_buffer(gsmsim_packet_length),
				gsmsim_packet_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			m_last_eap_identifier = received_gsmsim->get_identifier();

			save_current_state();
			set_state(eap_type_gsmsim_state_analyses_challenge_request);

			// - - - - - - - - - - - - - - - - - - - - - - - -

			eap_variable_data_c n_kc(m_am_tools);
			eap_variable_data_c n_sres(m_am_tools);

			status = query_SIM_kc_sres(
				p_gsmsim_payloads->get_n_RANDs()->get_payload_buffer(),
				&n_kc,
				&n_sres);
			if (status == eap_status_pending_request)
			{
				// Request will be completed later using complete_SIM_kc_sres() function.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
			else if (status == eap_status_completed_request)
			{
				// Request was already completed by AM using complete_SIM_kc_sres() function.
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
				// The query_SIM_kc_sres() function call is synchronous.
				// We must call process_SIM_kc_sres().
			}
			else
			{
				// This is an error case.
				restore_saved_previous_state();

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// eap_status_ok status value means n_kc and n_sres were read but not processed.
			// Next we must call process_SIM_kc_sres().

			// - - - - - - - - - - - - - - - - - - - - - - - -

			status = process_SIM_kc_sres(
				p_gsmsim_payloads->get_n_RANDs()->get_payload_buffer(),
				&n_kc,
				&n_sres);

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
			// Not correct GSMSIM-payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_challenge_request_message(6): ")
				 EAPL("Not correct GSMSIM-payloads are included in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else if (m_state == eap_type_gsmsim_state_pending_kc_sres_query)
	{
		// This is re-transmitted EAP-Request/SIM/Challenge.
		// We dischard it quietly.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("WARNING: eap_type_gsmsim_c::handle_challenge_request_message(): ")
			 EAPL("Re-transmitted message %d=%s dropped in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 received_gsmsim->get_subtype(),
			 received_gsmsim->get_subtype_string(),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_drop_packet_quietly);
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_challenge_request_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 received_gsmsim->get_subtype(),
			 received_gsmsim->get_subtype_string(),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_reauthentication_request_message(
	const eap_am_network_id_c * const receive_network_id,
	gsmsim_header_c * const received_gsmsim,
	const u32_t gsmsim_packet_length,
	gsmsim_payloads_c * const p_gsmsim_payloads)
{
	eap_status_e status = eap_status_process_general_error;

	if (m_state == eap_type_gsmsim_state_waiting_for_reauth_request
		|| (m_state == eap_type_gsmsim_state_waiting_for_success && m_use_result_indication == false)
		|| (m_state == eap_type_gsmsim_state_waiting_for_notification_request_success && m_use_result_indication == true))
	{
		// This could be first or retransmission request.

		// Checks the payloads existence.
		if (p_gsmsim_payloads->check_payloads(
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_mt
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // nonce_s
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // MAC
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // ENCR_DATA
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // IDENTITY
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // padding
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // n_RANDs
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // PERMANENT_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // FULLAUTH_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // ANY_ID_REQ
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_be,     // IV
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_PSEUDONYM
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NEXT_REAUTH_ID
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // NOTIFICATION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // VERSION_LIST
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // SELECTED_VERSION
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be, // COUNTER_TOO_SMALL
				gsmsim_payloads_c::eap_gsmsim_payload_status_must_not_be,  // CLIENT_ERROR_CODE
				gsmsim_payloads_c::eap_gsmsim_payload_status_optional     // RESULT_IND
				) == true
			)
		{

			m_last_eap_identifier = received_gsmsim->get_identifier();

			save_current_state();
			set_state(eap_type_gsmsim_state_analyses_reauthentication_request);

			// - - - - - - - - - - - - - - - - - - - - - - - -

			eap_variable_data_c orig_XKEY(m_am_tools);
			eap_variable_data_c orig_K_aut(m_am_tools);
			eap_variable_data_c orig_K_encr(m_am_tools);
			u32_t reauth_counter = 0u;
			// In order to use re-authentication, the client and the server need to
			// store the following values: original XKEY, K_aut, K_encr, latest
			// counter value and the next re-authentication identity.
			status = m_am_type_gsmsim->query_reauth_parameters(
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

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_type_gsmsim_c::handle_reauthentication_request_message(): %s, m_saved_reauth_counter %d.\n"),
				 (m_is_client == true ? "client": "server"),
				 reauth_counter));

			status = check_message_authentication_code(
				&orig_K_aut,
				p_gsmsim_payloads,
				received_gsmsim,
				gsmsim_packet_length);
			if (status != eap_status_ok)
			{
				(void) initialize_error_message(status);

				restore_saved_previous_state();

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (p_gsmsim_payloads->get_RESULT_IND()->get_payload_included() == true)
			{
				m_use_result_indication = m_allow_use_result_indication;
			}
			else
			{
				m_use_result_indication = false;
			}

			// Decrypt and parse encrypted payload.
			if (p_gsmsim_payloads->get_IV()->get_payload_included() == true
			|| p_gsmsim_payloads->get_ENCR_DATA()->get_payload_included() == true)
			{
				if (p_gsmsim_payloads->get_IV()->get_payload_included() == true
				&& p_gsmsim_payloads->get_ENCR_DATA()->get_payload_included() == true
				&& p_gsmsim_payloads->get_MAC()->get_payload_included() == true)
				{
					gsmsim_payloads_c * const l_gsmsim_payloads = new gsmsim_payloads_c(m_am_tools);
					eap_automatic_variable_c<gsmsim_payloads_c> l_gsmsim_payloads_automatic(m_am_tools, l_gsmsim_payloads);

					if (l_gsmsim_payloads == 0
						|| l_gsmsim_payloads->get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					bool include_at_counter_too_small = false;

					status = decrypt_DATA_payload(
						p_gsmsim_payloads,
						&orig_K_encr);
					if (status != eap_status_ok)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					u32_t state_payload_buffer_length = p_gsmsim_payloads->get_ENCR_DATA()->get_data_length();
					const gsmsim_payload_AT_header_c gp_data_payload(
						m_am_tools,
						p_gsmsim_payloads->get_ENCR_DATA()->get_data(state_payload_buffer_length),
						state_payload_buffer_length);

					status = parse_gsmsim_payload(
						&gp_data_payload,
						&state_payload_buffer_length,
						l_gsmsim_payloads,
						received_gsmsim->get_subtype());
					if (status != eap_status_ok)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}


					if (l_gsmsim_payloads->get_COUNTER()->get_payload_included() == false
						|| l_gsmsim_payloads->get_NONCE_S()->get_payload_included() == false)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
					}

					u32_t counter = l_gsmsim_payloads->get_COUNTER()->get_original_header()->get_reserved();

					if (m_gsmsim_test_version == true
						&& m_fail_reauthentication_counter_check == true)
					{
						--counter;
					}

					if (m_saved_previous_state == eap_type_gsmsim_state_waiting_for_reauth_request)
					{
						if (counter < reauth_counter)
						{
							// When the client detects that the
							// counter value is not fresh, it includes the AT_COUNTER_TOO_SMALL
							// attribute in EAP-Response/SIM/Re-authentication. This attribute
							// doesn't contain any data but it is a request for the server to
							// initiate full authentication. In this case, the client MUST ignore
							// the contents of the server's AT_NEXT_REAUTH_ID attribute.
							include_at_counter_too_small = true;
							l_gsmsim_payloads->get_NEXT_REAUTH_ID()->reset();
						}
					}
					else if (m_saved_previous_state == eap_type_gsmsim_state_waiting_for_success
						|| m_state == eap_type_gsmsim_state_waiting_for_notification_request_success)
					{
						// This is retransmission request.
						if (counter+1ul < reauth_counter)
						{
							// When the client detects that the
							// counter value is not fresh, it includes the AT_COUNTER_TOO_SMALL
							// attribute in EAP-Response/SIM/Re-authentication. This attribute
							// doesn't contain any data but it is a request for the server to
							// initiate full authentication. In this case, the client MUST ignore
							// the contents of the server's AT_NEXT_REAUTH_ID attribute.
							include_at_counter_too_small = true;
							l_gsmsim_payloads->get_NEXT_REAUTH_ID()->reset();
						}
					}

					if (l_gsmsim_payloads->get_NEXT_REAUTH_ID()->get_payload_included() == true)
					{
						// Save next re-authentication identity.
						// GSMSIM AM could store pseudonym to favourite place.
						status = m_am_type_gsmsim->store_reauthentication_id(
							&m_send_network_id,
							l_gsmsim_payloads->get_NEXT_REAUTH_ID()->get_payload_buffer());
						if (status != eap_status_ok)
						{
							restore_saved_previous_state();
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
					else
					{
						// GSMSIM AM should remove re-authentication identity from favourite place.

						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("eap_type_gsmsim_c::handle_reauthentication_request_message(0x%08x): Resets re-authentication identity from database.\n"),
							 this));

						status = m_am_type_gsmsim->store_reauthentication_id(
							&m_send_network_id,
							0);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						m_reauthentication_identity.reset();
					}

					status = m_nonce_s.set_copy_of_buffer(
						l_gsmsim_payloads->get_NONCE_S()->get_payload_buffer());
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
						&m_NAI,
						l_gsmsim_payloads->get_NONCE_S()->get_payload_buffer(),
						static_cast<u16_t>(counter),
						received_gsmsim->get_identifier(),
						include_at_counter_too_small);
					if (status != eap_status_ok)
					{
						restore_saved_previous_state();
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					// OK, server re-authenticates correcly.

					if (m_use_result_indication == false
						&& m_saved_previous_state == eap_type_gsmsim_state_waiting_for_reauth_request)
					{
						// Re-authentication counter is increased only on first time.
						// In order to use re-authentication, the client and the server need to
						// update re-authentication counter value.
						status = m_am_type_gsmsim->increase_reauth_counter();
						if (status != eap_status_ok)
						{
							restore_saved_previous_state();
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}

					if (include_at_counter_too_small == true)
					{
						// Re-authentication failed.
						// We will expect full authentication.
						set_state(eap_type_gsmsim_state_waiting_for_start_request);
						status = eap_status_ok;
					}
					else
					{
						// Authentication was successful.
						if (m_use_result_indication == true)
						{
							// This version waits the result indication.
							set_state(eap_type_gsmsim_state_waiting_for_notification_request_success);
							status = eap_status_ok;

							EAP_TRACE_DEBUG(
								m_am_tools, 
								TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
								(EAPL("EAP_type_GSMSIM: %s, re-authentication OK, waits result indication\n"),
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
							set_state(eap_type_gsmsim_state_waiting_for_success);
							status = eap_status_ok;

							EAP_TRACE_DEBUG(
								m_am_tools, 
								TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, 
								(EAPL("EAP_type_GSMSIM: %s, re-authentication OK, waits EAP-Success\n"),
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
				// Not correct GSMSIM-payloads are included.
				restore_saved_previous_state();
				EAP_TRACE_ERROR(
					m_am_tools, 
					TRACE_FLAGS_GSMSIM_ERROR, 
					(EAPL("ERROR: eap_type_gsmsim_c::handle_reauthentication_request_message(6): ")
					 EAPL("Not correct GSMSIM-payloads are included in eap_type_gsmsim_state_variable_e %d=%s.\n"),
					 m_state,
					 get_state_string()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
			}
		}
		else
		{
			// Not correct GSMSIM-payloads are included.
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::handle_reauthentication_request_message(6): ")
				 EAPL("Not correct GSMSIM-payloads are included in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
	}
	else
	{
		// Wrong message in this state.
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::handle_reauthentication_request_message(): ")
			 EAPL("Wrong message %d=%s in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 received_gsmsim->get_subtype(),
			 received_gsmsim->get_subtype_string(),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::handle_eap_identity_query(
	const eap_am_network_id_c * const send_network_id,
	eap_variable_data_c * const p_identity,
	const u8_t eap_identifier,
	const eap_variable_data_c * const IMSI,
	const eap_variable_data_c * const pseudonym,
	const eap_variable_data_c * const reauthentication_identity,
	const eap_variable_data_c * const automatic_realm,
	const u32_t length_of_mnc,
	const bool must_be_synchronous)
{
	const eap_variable_data_c *current_identity = 0;
	eap_variable_data_c manual_identity(m_am_tools);
	bool IMSI_is_used = false;
	bool reauth_id_is_used = false;
	eap_status_e status = eap_status_process_general_error;

	if (m_state != eap_type_gsmsim_state_pending_identity_query)
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
		|| IMSI->get_data_length() < EAP_TYPE_GSMSIM_MINIMUM_IMSI_LENGTH)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
	}


	// We must save queried re-authentication and pseudonym identity.
	if (reauthentication_identity != 0
		&& reauthentication_identity->get_is_valid_data() == true)
	{
		status = m_reauthentication_identity.set_copy_of_buffer(reauthentication_identity);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (pseudonym != 0
		 && pseudonym->get_is_valid_data() == true)
	{
		status = m_pseudonym.set_copy_of_buffer(pseudonym);
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
			(EAPL("eap_type_gsmsim_c::handle_eap_identity_query(): Client sends manual username and realm.\n")));

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
			(EAPL("eap_type_gsmsim_c::handle_eap_identity_query(): Client sends manual username and automatic realm.\n")));

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
			(EAPL("eap_type_gsmsim_c::handle_eap_identity_query(): Client sends re-authentication identity.\n")));

		current_identity = reauthentication_identity;
		IMSI_is_used = false;
		reauth_id_is_used = true;

		status = m_reauthentication_identity.set_copy_of_buffer(reauthentication_identity);
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
			(EAPL("eap_type_gsmsim_c::handle_eap_identity_query(): Client sends pseudonym username.\n")));

		current_identity = pseudonym;
		IMSI_is_used = false;

		status = m_pseudonym.set_copy_of_buffer(pseudonym);
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
			(EAPL("eap_type_gsmsim_c::handle_eap_identity_query(): Client sends random username.\n")));

		const u32_t EAP_TLS_PEAP_RANDOM_IDENTITY_LENGTH = 16;
		eap_variable_data_c random_username(m_am_tools);
		eap_variable_data_c random_bytes(m_am_tools);
		
		status = random_bytes.init(EAP_TLS_PEAP_RANDOM_IDENTITY_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		random_bytes.set_is_valid();
		random_bytes.set_data_length(EAP_TLS_PEAP_RANDOM_IDENTITY_LENGTH);
		
		status = m_am_tools->get_crypto()->get_rand_bytes(
			random_bytes.get_data(),
			random_bytes.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		// Change first byte to 'r' to make it different than the default IMSI prefix '1'.
		// This will cause the first identity char 'S' after ascii armor conversion.
		*random_bytes.get_data(1ul) = static_cast<u8_t>('r');

		const u32_t EAP_GSMSIM_RANDOM_IDENTITY_BUFFER_LENGTH
			= 3ul+(EAP_TLS_PEAP_RANDOM_IDENTITY_LENGTH+1u)*4u/3u;
		
		status = random_username.init(EAP_GSMSIM_RANDOM_IDENTITY_BUFFER_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		random_username.set_is_valid();
		random_username.set_data_length(EAP_GSMSIM_RANDOM_IDENTITY_BUFFER_LENGTH);
		
		u32_t random_identity_length = random_username.get_data_length();
		
		status = m_am_tools->convert_bytes_to_ascii_armor(
			random_bytes.get_data(),
			random_bytes.get_data_length(),
			random_username.get_data(random_username.get_data_length()),
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
		&& IMSI->get_data_length() >= EAP_TYPE_GSMSIM_MINIMUM_IMSI_LENGTH)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_gsmsim_c::handle_eap_identity_query(): Client sends IMSI username.\n")));

		current_identity = IMSI;
		IMSI_is_used = true;
	}

	if (current_identity != 0)
	{
		status = m_IMSI.set_copy_of_buffer(IMSI);
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
			current_identity->get_data(),
			current_identity->get_data_length()));

		eap_variable_data_c NAI(m_am_tools);

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
				&m_IMSI,
				automatic_realm,
				length_of_mnc);
		}

		if (status == eap_status_ok)
		{
			status = m_NAI.set_copy_of_buffer(&NAI);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			if (must_be_synchronous == false)
			{
				status = get_type_partner()->complete_eap_identity_query(
					send_network_id,
					&m_NAI,
					eap_identifier);
				if (status == eap_status_ok)
				{
					if (p_identity != 0)
					{
						status = p_identity->set_copy_of_buffer(&m_NAI);
					}

					if (status == eap_status_ok)
					{
						status = eap_status_completed_request;
					}
				}		
			}
			else
			{
				status = p_identity->set_copy_of_buffer(&m_NAI);
			}

			if (status == eap_status_ok
				|| status == eap_status_completed_request)
			{
				if (m_use_random_identity_on_eap_identity_response == true)
				{
					m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_NONE;
					set_identity_type(GSMSIM_IDENTITY_TYPE_NONE);
					set_state(eap_type_gsmsim_state_waiting_for_start_request);

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_eap_identity_query(0x%08x): Selects none.\n"),
						 this));
				}
				else if (reauthentication_identity != 0
					&& reauthentication_identity->get_is_valid_data() == true)
				{
					m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_REAUTHENTICATION;
					set_identity_type(GSMSIM_IDENTITY_TYPE_RE_AUTH_ID);
					set_state(eap_type_gsmsim_state_waiting_for_reauth_request);

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_eap_identity_query(0x%08x): Selects fast re-authentication and re-authentication identity.\n"),
						 this));
				}
				else if (pseudonym != 0
					&& pseudonym->get_is_valid_data() == true)
				{
					m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;
					set_identity_type(GSMSIM_IDENTITY_TYPE_PSEUDONYM_ID);
					set_state(eap_type_gsmsim_state_pseydonym_waiting_for_start_request);

					EAP_TRACE_DEBUG(
						m_am_tools, 
						TRACE_FLAGS_DEFAULT, 
						(EAPL("eap_type_gsmsim_c::handle_eap_identity_query(0x%08x): Selects full authentication and pseudonym identity.\n"),
						 this));
				}
				else
				{
					if (m_use_manual_username == true)
					{
						m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_NONE;
						set_identity_type(GSMSIM_IDENTITY_TYPE_NONE);
						set_state(eap_type_gsmsim_state_waiting_for_start_request);

						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("eap_type_gsmsim_c::handle_eap_identity_query(0x%08x): Selects none.\n"),
							 this));
					}
					else
					{
						m_authentication_type = GSMSIM_AUTHENTICATION_TYPE_FULL_AUTH;
						set_identity_type(GSMSIM_IDENTITY_TYPE_IMSI_ID);
						set_state(eap_type_gsmsim_state_imsi_waiting_for_start_request);

						EAP_TRACE_DEBUG(
							m_am_tools, 
							TRACE_FLAGS_DEFAULT, 
							(EAPL("eap_type_gsmsim_c::handle_eap_identity_query(0x%08x): Selects full authentication and IMSI identity.\n"),
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
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::query_eap_identity(
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

	if (send_network_id.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = eap_status_process_general_error;

	if (m_state == eap_type_gsmsim_state_none)
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
		(EAPL("eap_type_gsmsim_c::query_eap_identity(): eap_type_gsmsim_state_variable_e %d=%s.\n"),
		m_state,
		get_state_string()));


#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	const eap_type_gsmsim_state_variable_e gsmsim_query_eap_identity_states[] =
	{
		eap_type_gsmsim_state_waiting_for_start_request,
		eap_type_gsmsim_state_pseydonym_waiting_for_start_request,
		eap_type_gsmsim_state_imsi_waiting_for_start_request,
		eap_type_gsmsim_state_waiting_for_reauth_request,
	};
#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)


	if (m_state == eap_type_gsmsim_state_waiting_for_identity_request
		|| (m_gsmsim_test_version == true
			&& m_state == eap_type_gsmsim_state_success)) // This one is for testing purposes.
	{
		m_last_eap_identifier = eap_identifier;

		eap_variable_data_c automatic_realm(m_am_tools);

		status = query_SIM_IMSI_or_pseudonym_or_reauthentication_id(
			&IMSI,
			&pseudonym,
			&reauthentication_identity,
			&automatic_realm,
			&m_length_of_mnc,
			must_be_synchronous,
			gsmsim_payload_AT_ANY_ID_REQ,
			eap_type_gsmsim_complete_query_eap_identity,
			eap_identifier);
		if (status == eap_status_pending_request)
		{
			// This is pending query, that will be completed by complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() call.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (status == eap_status_completed_request)
		{
			// This is already completed by complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query() call.
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::query_eap_identity(): ")
				 EAPL("completed returns eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				 get_state_string()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else if (status != eap_status_ok)
		{
			// This is the error case.
			restore_saved_previous_state();

			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::query_eap_identity(): ")
				 EAPL("error returns eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
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
				(EAPL("eap_type_gsmsim_c::query_eap_identity(): handle_eap_identity_query() ")
				 EAPL("returns eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				 get_state_string()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	else if (verify_states(gsmsim_query_eap_identity_states,
					  GSMSIM_STATE_COUNT(gsmsim_query_eap_identity_states)) == true)
#else
	else if (m_state == eap_type_gsmsim_state_waiting_for_start_request
		|| m_state == eap_type_gsmsim_state_pseydonym_waiting_for_start_request
		|| m_state == eap_type_gsmsim_state_imsi_waiting_for_start_request
		|| m_state == eap_type_gsmsim_state_waiting_for_reauth_request)
#endif //#if defined(USE_EAP_GSMSIM_VERIFY_STATES)
	{
		// This is re-transmission request. We do not change our state.
		// Just send EAP-Identity again.
		if (m_NAI.get_is_valid_data() == true)
		{
			status = identity->set_copy_of_buffer(&m_NAI);

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_type_gsmsim_c::query_eap_identity(): handle_eap_identity_query() ")
				 EAPL("returns eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				 get_state_string()));
		}
		else
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_GSMSIM_ERROR, 
				(EAPL("ERROR: eap_type_gsmsim_c::query_eap_identity(): ")
				 EAPL("EAP-Request/Identity cannot be completed, identity (NAI) ")
				 EAPL("is missing. in eap_type_gsmsim_state_variable_e %d=%s.\n"),
				 m_state,
				 get_state_string()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
		}
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else if (m_state == eap_type_gsmsim_state_pending_identity_query)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_type_gsmsim_c::query_eap_identity(): ignores re-transmitted query_eap_identity()")
			 EAPL("in eap_type_gsmsim_state_variable_e %d=%s.\n"),
			 m_state,
			 get_state_string()));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_pending_request);
	}


	// Wrong message in this state.
	EAP_TRACE_ERROR(
		m_am_tools, 
		TRACE_FLAGS_GSMSIM_ERROR, 
		(EAPL("WARNING: eap_type_gsmsim_c::query_eap_identity(): ")
		 EAPL("Wrong message EAP-Request/Identity in eap_type_gsmsim_state_variable_e %d=%s.\n"),
		 m_state,
		 get_state_string()));		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::eap_acknowledge(
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	if (m_state == eap_type_gsmsim_state_waiting_for_success
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
			m_state,
			get_state_string(),
			(m_is_client == true)));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::set_initial_eap_identifier(
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
			TRACE_FLAGS_GSMSIM_ERROR, 
			(EAPL("ERROR: eap_type_gsmsim_c::set_initial_eap_identifier(): ")
			 EAPL("new_handler() failed, status %d.\n"),
			 status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_last_eap_identifier = static_cast<u8_t>(initial_identifier-1u);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)
	#include "read_rand_and_triplets.h"
#endif //#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)


//
EAP_FUNC_EXPORT eap_status_e eap_type_gsmsim_c::generate_nonce(
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

#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)
	if (m_nonce_mt_file.get_is_valid_data() == true)
	{
		status = read_rand_from_file(m_am_tools, &m_nonce_mt_file, nonce);
		if (status != eap_status_ok)
		{
			status = m_am_tools->get_crypto()->get_rand_bytes(
				nonce->get_data(),
				nonce->get_data_length());
		}
	}
	else
#endif //#if defined(_DEBUG) && defined(USE_EAP_GSMSIM_TEST_VECTORS)
	{
		status = m_am_tools->get_crypto()->get_rand_bytes(
			nonce->get_data(),
			nonce->get_data_length());
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------



// End.
