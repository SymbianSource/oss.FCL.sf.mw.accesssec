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
* %version: %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 194 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#define EAP_AM_MEMORY_GUARD
	#include "eap_am_memory.h"
#undef EAP_AM_MEMORY_GUARD

#include "eap_tools.h"
#include "eap_am_type_gsmsim_symbian_simulator.h"
#include "eap_am_crypto.h"
#include "abs_eap_am_mutex.h"

const u32_t SIM_IMSI_LENGTH = 15u;

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_am_type_gsmsim_simulator_c::~eap_am_type_gsmsim_simulator_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_am_type_gsmsim_simulator_c::eap_am_type_gsmsim_simulator_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	const CEapPluginInterface::TIndexType aIndexType,
	const TInt aIndex)
: eap_am_type_gsmsim_c(tools)
, m_am_tools(tools)
, m_partner(partner)
, saved_pseudonym(tools)
, m_is_valid(eap_boolean_true)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(aIndexType);
	EAP_UNREFERENCED_PARAMETER(aIndex);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::store_reauth_keys(
	const eap_variable_data_c * const XKEY,
	const eap_variable_data_c * const K_aut,
	const eap_variable_data_c * const K_encr)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(XKEY);
	EAP_UNREFERENCED_PARAMETER(K_aut);
	EAP_UNREFERENCED_PARAMETER(K_encr);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

const eap_status_e eap_am_type_gsmsim_simulator_c::authentication_finished(
	const eap_boolean_e true_when_successfull,
	const eap_gsmsim_authentication_type_e authentication_type)
{
	EAP_UNREFERENCED_PARAMETER(true_when_successfull);
	EAP_UNREFERENCED_PARAMETER(authentication_type);

    eap_status_e status = eap_status_ok;
	return status;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::query_reauth_parameters(
	eap_variable_data_c * const reauth_XKEY,
	eap_variable_data_c * const reauth_K_aut,
	eap_variable_data_c * const reauth_K_encr,
	u32_t * const reauth_counter)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(reauth_XKEY);
	EAP_UNREFERENCED_PARAMETER(reauth_K_aut);
	EAP_UNREFERENCED_PARAMETER(reauth_K_encr);
	EAP_UNREFERENCED_PARAMETER(reauth_counter);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::increase_reauth_counter()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_not_supported;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT const eap_status_e eap_am_type_gsmsim_simulator_c::configure()
{
	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::query_SIM_imsi(
	u8_t * const imsi, const u32_t max_length, u32_t * const imsi_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	const char tmp_imsi[] = "244070100000001";
	*imsi_length = m_am_tools->strlen(tmp_imsi);
	if (*imsi_length > max_length)
	{
		// ERROR, too short buffer.
		*imsi_length = 0u;
		return eap_status_allocation_error;
	}
	m_am_tools->memcpy(imsi, tmp_imsi, m_am_tools->strlen(tmp_imsi));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::store_pseudonym_id(
	const eap_am_network_id_c * const /*network_id*/,
	const eap_variable_data_c * const pseudonym)
{
	return saved_pseudonym.set_copy_of_buffer(pseudonym);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::store_reauthentication_id(
	const eap_am_network_id_c * const /*network_id*/,
	const eap_variable_data_c * const /* reauthentication_id */)
{
	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::query_SIM_IMSI_or_pseudonym_or_reauthentication_id(
	const eap_boolean_e must_be_synchronous,
	eap_variable_data_c * const IMSI,
	eap_variable_data_c * const pseudonym_identity,
	eap_variable_data_c * const /* reauthentication_identity */)
{
	EAP_UNREFERENCED_PARAMETER(must_be_synchronous);

	eap_status_e status = eap_status_process_general_error;

	if (IMSI == 0
		|| pseudonym_identity == 0)
	{
		// Something is really wrong.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_process_general_error;
	}

	if (IMSI->get_is_valid() == eap_boolean_false
		|| IMSI->get_buffer_length() < SIM_IMSI_LENGTH)
	{
		IMSI->init(SIM_IMSI_LENGTH);
		IMSI->set_is_valid();
	}

	if (saved_pseudonym.get_is_valid() == eap_boolean_true)
	{
		// We have stored pseudonym_identity.
		if (pseudonym_identity == 0)
		{
			// Something is really wrong.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return eap_status_process_general_error;
		}
		pseudonym_identity->set_copy_of_buffer(&saved_pseudonym);
	}


	{
		u32_t imsi_length = 0u;

		status = query_SIM_imsi(
			IMSI->get_data(SIM_IMSI_LENGTH),
			SIM_IMSI_LENGTH,
			&imsi_length);

		if (status != eap_status_ok
			|| imsi_length != SIM_IMSI_LENGTH)
		{
			return status;
		}

		IMSI->set_data_length(imsi_length);
	}

	if (must_be_synchronous == eap_boolean_false)
	{
		status = get_am_partner()->complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query(
			IMSI,
			pseudonym_identity,
			0);

		if (status == eap_status_ok)
		{
			status = eap_status_completed_request;
		}
	}

	return status;
}

//--------------------------------------------------

//
eap_status_e eap_am_type_gsmsim_simulator_c::cancel_SIM_IMSI_or_pseudonym_or_reauthentication_id_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::query_SIM_kc_and_sres(
	const u8_t * const /* imsi */, const u32_t /* imsi_length */,
	const u8_t * const rand, const u32_t rand_length,
	u8_t * const kc, u32_t * const kc_length,
	u8_t * const sres, u32_t * const sres_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(rand_length);

	EAP_ASSERT_ALWAYS(rand_length == SIM_RAND_LENGTH);
	EAP_ASSERT_ALWAYS(*kc_length == SIM_KC_LENGTH);
	EAP_ASSERT_ALWAYS(*sres_length == SIM_SRES_LENGTH);
	
	const u8_t test_Ki[SIM_RAND_LENGTH] = {0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5};

	u8_t tmp[SIM_KC_LENGTH + SIM_SRES_LENGTH];
	m_am_tools->memset(tmp, 0, sizeof(tmp));

	u32_t i = 0;

	for(i = 0; i < (SIM_KC_LENGTH + SIM_SRES_LENGTH); i++)
	{
		tmp[i] = (u8_t)(rand[i] ^ test_Ki[i]);
	}

	m_am_tools->memcpy(sres, tmp, *sres_length);
	m_am_tools->memcpy(kc, tmp + *sres_length, *kc_length);


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::handle_gsmsim_notification(
	eap_gsmsim_triplet_status_e /* gsmsim_notification_code */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::query_SIM_triplets(
	const eap_boolean_e must_be_synchronous,
	const eap_variable_data_c * const /* p_username */,
	eap_variable_data_c * const /* p_imsi */,
	eap_type_sim_triplet_array_c * const triplets,
	eap_type_gsmsim_identity_type * const type)
{
	EAP_UNREFERENCED_PARAMETER(must_be_synchronous);
	EAP_UNREFERENCED_PARAMETER(type);

	// NOTE if user needs to use state_selector or imsi after return from query_SIM_triplets()
	// function those parameters MUST be copied using copy() member function of each parameter.
	// For example: saved_imsi = p_imsi_or_pseudonym->copy()
	//              saved_state_selector = state_selector->copy()

	eap_status_e status = eap_status_process_general_error;
	const u32_t rand_length = 16u;
	const u8_t test_rand[] = "0123456789abcdef";
	const u8_t test_Ki[rand_length] = {0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,
										0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5};
	const u32_t triplet_count = 2u;
	u32_t ind;
	u32_t i = 0;

	if (triplets == 0)
	{
		// Something is really wrong.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_process_general_error;
	}

	triplets->set_triplet_count(triplet_count);

	for (ind = 0u; ind < triplet_count; ind++)
	{
		eap_type_saesim_triplet_c *tripl = triplets->get_triplet(m_am_tools, ind);
		u8_t tmp[rand_length] = {0,};

		status = tripl->get_rand()->set_copy_of_buffer((u8_t *)test_rand, 16);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return status;
		}

		status = tripl->get_kc()->init(SIM_KC_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return status;
		}

		tripl->get_kc()->set_is_valid();
		tripl->get_kc()->set_data_length(SIM_KC_LENGTH);

		status = tripl->get_sres()->init(SIM_SRES_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return status;
		}

		tripl->get_sres()->set_is_valid();
		tripl->get_sres()->set_data_length(SIM_SRES_LENGTH);

		for (i = 0; i < (SIM_KC_LENGTH + SIM_SRES_LENGTH); i++)
		{
			tmp[i] = (u8_t)(test_rand[i] ^ test_Ki[i]);
		}

		tripl->get_sres()->set_copy_of_buffer(tmp, SIM_SRES_LENGTH);
		tripl->get_kc()->set_copy_of_buffer(tmp + SIM_SRES_LENGTH, SIM_KC_LENGTH);

	}

	return status;
}

#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

//--------------------------------------------------

#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::cancel_SIM_triplets_query()
{
	EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: cancel_SIM_triplets_query() not supported here..\n")));
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::query_SIM_kc_sres(
	const eap_boolean_e must_be_synchronous,
	//const eap_variable_data_c * const p_imsi,
	const eap_variable_data_c * const p_n_rands,
	eap_variable_data_c * const n_kc,
	eap_variable_data_c * const n_sres)
{
	EAP_UNREFERENCED_PARAMETER(must_be_synchronous);

	// NOTE if user needs to use state_selector or n_rands after return from query_SIM_kc_sres()
	// function those parameters MUST be copied using copy() member function of each parameter.
	// For example: saved_n_rands = n_rands->copy()
	//              saved_state_selector = state_selector->copy()

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == eap_boolean_true);

	if (n_kc == 0
		|| n_sres == 0
		|| p_n_rands == 0)
	{
		// Something is really wrong.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}


	eap_status_e status = eap_status_process_general_error;
	eap_variable_data_c copy_of_imsi(m_am_tools);

	// First we must query IMSI.
	u32_t imsi_length = 0u;

	copy_of_imsi.init(SIM_IMSI_LENGTH);
	copy_of_imsi.set_is_valid();

	status = query_SIM_imsi(
		copy_of_imsi.get_data(copy_of_imsi.get_data_length()),
		SIM_IMSI_LENGTH,
		&imsi_length);

	if (status != eap_status_ok
		|| imsi_length != SIM_IMSI_LENGTH)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	copy_of_imsi.set_data_length(imsi_length);


	eap_variable_data_c *copy_of_n_rands = p_n_rands->copy();

	if (copy_of_n_rands == 0)
	{
		return eap_status_allocation_error;
	}


	u32_t kc_length = SIM_KC_LENGTH;
	u32_t sres_length = SIM_SRES_LENGTH;

	u32_t count = copy_of_n_rands->get_data_length() / SIM_RAND_LENGTH;

	if (n_kc->get_is_valid() == eap_boolean_false
		|| n_kc->get_buffer_length() < count*SIM_KC_LENGTH)
	{
		n_kc->init(count*SIM_KC_LENGTH);
		n_kc->set_is_valid();
	}

	if (n_sres->get_is_valid() == eap_boolean_false
		|| n_sres->get_buffer_length() < count*SIM_SRES_LENGTH)
	{
		n_sres->init(count*SIM_SRES_LENGTH);
		n_sres->set_is_valid();
	}

	u8_t *rand = copy_of_n_rands->get_data(copy_of_n_rands->get_data_length());
	u8_t *kc = n_kc->get_data(n_kc->get_data_length());
	u8_t *sres = n_sres->get_data(n_sres->get_data_length());

	for (u32_t ind = 0u; ind < count; ind++)
	{
		kc_length = SIM_KC_LENGTH;
		sres_length = SIM_SRES_LENGTH;
		query_SIM_kc_and_sres(
			copy_of_imsi.get_data(copy_of_imsi.get_data_length()),
			copy_of_imsi.get_data_length(),
			rand+(ind*SIM_RAND_LENGTH),
			SIM_RAND_LENGTH,
			kc+(ind*SIM_KC_LENGTH),
			&kc_length,
			sres+(ind*SIM_SRES_LENGTH),
			&sres_length);
	}

	n_kc->set_data_length(count*SIM_KC_LENGTH);
	n_sres->set_data_length(count*SIM_SRES_LENGTH);

	status = get_am_partner()->complete_SIM_kc_sres(
		copy_of_n_rands,
		n_kc,
		n_sres);

	delete copy_of_n_rands;

	if (status == eap_status_ok)
	{
		status = eap_status_completed_request;
	}

	return status;
}

//--------------------------------------------------

//
eap_status_e eap_am_type_gsmsim_simulator_c::cancel_SIM_kc_sres_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::generate_encryption_IV(
	eap_variable_data_c * const encryption_IV,
		const u32_t IV_length)
{
	encryption_IV->init(IV_length);
	encryption_IV->set_is_valid();
	encryption_IV->set_data_length(IV_length);

	m_am_tools->get_crypto()->add_rand_seed_hw_ticks();

	eap_status_e status = m_am_tools->get_crypto()->get_rand_bytes(
		encryption_IV->get_data(encryption_IV->get_data_length()),
		encryption_IV->get_data_length());

	return status;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::query_imsi_from_username(
	const eap_boolean_e must_be_synchronous,
	const u8_t next_eap_identifier,
	const eap_am_network_id_c * const /* network_id */,
	const eap_variable_data_c * const /* username */,
	eap_variable_data_c * const imsi,
	eap_type_gsmsim_identity_type * const type)
{
	EAP_UNREFERENCED_PARAMETER(must_be_synchronous);
	EAP_UNREFERENCED_PARAMETER(next_eap_identifier);
	EAP_UNREFERENCED_PARAMETER(type);

	// Note this is syncronous call.

	imsi->init(SIM_IMSI_LENGTH);
	imsi->set_is_valid();
	u32_t imsi_length = 0u;
	query_SIM_imsi(
		imsi->get_data(imsi->get_data_length()),
		SIM_IMSI_LENGTH,
		&imsi_length);
	EAP_ASSERT_ALWAYS(imsi_length == SIM_IMSI_LENGTH);
	imsi->set_data_length(imsi_length);
	return eap_status_ok;

}

//--------------------------------------------------

//
eap_status_e eap_am_type_gsmsim_simulator_c::cancel_imsi_from_username_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::generate_reauthentication_id(
	const eap_am_network_id_c * const network_id,
	const eap_variable_data_c * const imsi,
	eap_variable_data_c * const reauthentication_identity,
	const u32_t maximum_reauthentication_identity_length)
{
	// This is an example.

	return generate_pseudonym_id(
		network_id,
		imsi,
		reauthentication_identity,
		maximum_reauthentication_identity_length);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_gsmsim_simulator_c::generate_pseudonym_id(
	const eap_am_network_id_c * const /* network_id */,
	const eap_variable_data_c * const imsi,
	eap_variable_data_c * const pseudonym,
	const u32_t maximum_pseudonym_length)
{
	// This is an example. Pseudonym is mostly same length as IMSI.
	eap_variable_data_c tmp_pseudonym(m_am_tools);
	tmp_pseudonym.init(imsi->get_data_length());
	tmp_pseudonym.set_is_valid();
	tmp_pseudonym.set_data_length(imsi->get_data_length());

	m_am_tools->get_crypto()->add_rand_seed_hw_ticks();

	eap_status_e status = m_am_tools->get_crypto()->get_rand_bytes(
		tmp_pseudonym.get_data(tmp_pseudonym.get_data_length()),
		tmp_pseudonym.get_data_length());


	pseudonym->init(tmp_pseudonym.get_data_length()*2u);
	pseudonym->set_is_valid();
	pseudonym->set_data_length(imsi->get_data_length()*2u);

	u32_t pseudonym_length = pseudonym->get_data_length();
	m_am_tools->convert_bytes_to_hex_ascii(
		tmp_pseudonym.get_data_offset(0u, tmp_pseudonym.get_data_length()),
		tmp_pseudonym.get_data_length(),
		pseudonym->get_data_offset(0u, pseudonym->get_data_length()),
		&pseudonym_length);

	if (pseudonym_length > maximum_pseudonym_length)
	{
		pseudonym_length = maximum_pseudonym_length;
	}
	pseudonym->set_data_length(pseudonym_length);

	return status;
}


//--------------------------------------------------

EAP_FUNC_EXPORT void eap_am_type_gsmsim_simulator_c::set_is_valid()
{
	m_is_valid = eap_boolean_true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_boolean_e eap_am_type_gsmsim_simulator_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT const eap_status_e eap_am_type_gsmsim_simulator_c::type_configure_read(
	eap_config_string field,
	const u32_t field_length,
	eap_variable_data_c * const data)
{
	// Here configuration data must be read from type spesific database.

	// NOTE: This is really just for simulation.
	// Read is routed to partner object.
	eap_status_e status = m_partner->read_configure(
			field,
			field_length,
			data);
	return status;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT const eap_status_e eap_am_type_gsmsim_simulator_c::type_configure_write(
	eap_config_string field,
	const u32_t field_length,
	eap_variable_data_c * const data)
{
	// Here configuration data must be read from type spesific database.

	// NOTE: This is really just for simulation.
	// Write is routed to partner object.
	eap_status_e status = m_partner->write_configure(
			field,
			field_length,
			data);
	return status;
}

//--------------------------------------------------


// End.
