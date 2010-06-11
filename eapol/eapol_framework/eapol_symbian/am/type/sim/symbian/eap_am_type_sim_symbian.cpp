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
	#define EAP_FILE_NUMBER_ENUM 352 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_type_sim_symbian.h"
#include "abs_eap_am_crypto.h"
#include "abs_eap_am_mutex.h"

const u32_t SIM_IMSI_LENGTH = 8u;

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_am_type_sim_simulator_c::~eap_am_type_sim_simulator_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_am_type_sim_simulator_c::eap_am_type_sim_simulator_c(
	abs_eap_am_tools_c * const tools, abs_eap_am_type_sim_c * const partner)
: eap_am_type_sim_c(tools, partner)
, m_am_tools(tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_sim_simulator_c::query_SIM_imsi(
	u8_t * const imsi, const u32_t max_length, u32_t * const imsi_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	u32_t ind = 0u;
	for (ind = 0u; ind < max_length; ind++)
	{
		imsi[ind] = static_cast<u8_t>(~ind;
	}
	*imsi_length = ind;
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_process_general_error;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_type_sim_simulator_c::query_SIM_kc_and_sres(
	const u8_t * const imsi, const u32_t imsi_length,
	const u8_t * const rand, const u32_t /*rand_length*/,
	u8_t * const kc, u32_t * const kc_length,
	u8_t * const sres, u32_t * const sres_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (imsi == 0
		|| rand == 0
		|| kc == 0
		|| sres == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_ASSERT_ALWAYS(*kc_length >= 8u);
	EAP_ASSERT_ALWAYS(*sres_length >= 4u);

	eap_variable_data_c aes_context(m_am_tools);
	eap_variable_data_c encryption_IV(m_am_tools);
	eap_variable_data_c imsi_tmp(m_am_tools);
	u8_t tmp_buffer[16u];

	eap_status_e status = imsi_tmp.add_data(imsi, imsi_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	status = imsi_tmp.add_data(imsi, imsi_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	status = m_am_tools->get_crypto()->cbc_aes_set_encryption_key(
		&aes_context,
		//&encryption_IV,
		imsi_tmp.get_data(imsi_tmp.get_data_length()),
		imsi_tmp.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	status = encryption_IV.init(m_am_tools->get_crypto()->aes_key_length());
	if (status != eap_status_ok)
	{
		return status;
	}
	encryption_IV.set_is_valid();

	encryption_IV.set_data_length(m_am_tools->get_crypto()->aes_key_length());
	m_am_tools->memset(
		encryption_IV.get_data(encryption_IV.get_data_length()),
		0,
		encryption_IV.get_data_length());

	status = m_am_tools->get_crypto()->cbc_aes_encrypt_data(
		&aes_context,
		&encryption_IV,
		rand,
		tmp_buffer,
		sizeof(tmp_buffer));

	m_am_tools->memmove(kc, tmp_buffer, *kc_length);


	eap_variable_data_c kc_tmp(m_am_tools);
	u8_t sres_tmp[16u];

	status = kc_tmp.add_data(kc, *kc_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	status = kc_tmp.add_data(kc, *kc_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	status = m_am_tools->get_crypto()->cbc_aes_set_encryption_key(
		&aes_context,
		//&encryption_IV,
		kc_tmp.get_data(kc_tmp.get_data_length()),
		kc_tmp.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	status = encryption_IV.init(m_am_tools->get_crypto()->aes_key_length());
	if (status != eap_status_ok)
	{
		return status;
	}
	encryption_IV.set_is_valid();

	encryption_IV.set_data_length(m_am_tools->get_crypto()->aes_key_length());
	m_am_tools->memset(
		encryption_IV.get_data(encryption_IV.get_data_length()),
		0,
		encryption_IV.get_data_length());

	status = m_am_tools->get_crypto()->cbc_aes_encrypt_data(
		&aes_context,
		&encryption_IV,
		rand,
		sres_tmp,
		sizeof(sres_tmp));

	m_am_tools->memmove(sres, sres_tmp, *sres_length);


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

eap_status_e eap_am_type_sim_simulator_c::query_SIM_triplets(
	//const eap_state_selector_c * const p_state_selector,
	const eap_variable_data_c * const p_imsi,
	eap_type_sim_triplet_array_c * const triplets)
{
	// NOTE if user needs to use imsi after return from query_SIM_triplets()
	// function that parameter MUST be copied using copy() member function of each parameter.
	// For example: saved_imsi = imsi->copy()

	eap_status_e status = eap_status_process_general_error;

	const u32_t triplet_count = 2u;



// End.
