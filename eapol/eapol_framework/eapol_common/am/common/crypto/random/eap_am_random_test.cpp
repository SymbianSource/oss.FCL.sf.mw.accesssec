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
	#define EAP_FILE_NUMBER_ENUM 5 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_random_test.h"

//--------------------------------------------------

#if 1
	#define EAP_TEST_RANDOM_TRACE_DEBUG EAP_TRACE_DEBUG
	#define EAP_TEST_RANDOM_TRACE_DATA_DEBUG EAP_TRACE_DATA_DEBUG
#else
	#define EAP_TEST_RANDOM_TRACE_DEBUG(tools, flags, params)
	#define EAP_TEST_RANDOM_TRACE_DATA_DEBUG(tools, flags, prefix, data, data_length)
#endif

static const u32_t EAP_TRACE_MASK_TEST_RANDOM = eap_am_tools_c::eap_trace_mask_crypto_test_random;

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_am_random_test_c::~eap_am_random_test_c()
{
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_am_random_test_c::eap_am_random_test_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_state(tools)
	, m_hash(tools)
	, m_rand_counter(0ul)
	, m_do_seeding(false)
	, m_is_valid(false)
{
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT void eap_am_random_test_c::set_do_reseeding(const bool does_reseeding_when_true)
{
	m_do_seeding = does_reseeding_when_true;
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_am_random_test_c::init(
	const void * const bytes,
	const u32_t length)
{
	if (m_is_valid == true)
	{
		// Already initialized.
		return eap_status_ok;
	}

	m_state.reset();

	eap_status_e status = m_state.set_buffer_length(m_hash.get_digest_length());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	m_state.set_data_length(m_state.get_buffer_length());

	if (m_state.get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	m_am_tools->memset(m_state.get_data(m_state.get_data_length()), 0, m_state.get_data_length());

	m_is_valid = true;

	if (length > 0ul)
	{
		status = internal_rand_seed(
			bytes,
			length);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_am_random_test_c::internal_rand_seed(
	const void * const bytes,
	const u32_t length)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_ASSERT_ALWAYS(m_is_valid == true);

	status = m_hash.hash_init();
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_hash.hash_update(
		m_state.get_data(m_state.get_data_length()),
		m_state.get_data_length());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_hash.hash_update(
		bytes,
		length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t md_length = m_state.get_data_length();

	status = m_hash.hash_final(
		m_state.get_data(m_state.get_data_length()),
		&md_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_ASSERT(md_length == m_state.get_data_length());

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_am_random_test_c::add_rand_seed(
	const void * const bytes,
	const u32_t length)
{
	eap_status_e status = eap_status_ok;

	EAP_ASSERT_ALWAYS(m_is_valid == true);

	if (m_do_seeding == true)
	{
		EAP_TEST_RANDOM_TRACE_DATA_DEBUG(
			m_am_tools, 
			EAP_TRACE_MASK_TEST_RANDOM, 
			(EAPL("PSEUDO RANDOM SEED:"),
			 bytes,
			 length));

		status = internal_rand_seed(
			bytes,
			length);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

// 
EAP_FUNC_EXPORT eap_status_e eap_am_random_test_c::get_rand_bytes(
	void * const p_bytes,
	const u32_t length)
{
	eap_status_e status = eap_status_process_general_error;

	EAP_ASSERT_ALWAYS(m_is_valid == true);

	if (p_bytes == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (length == 0ul)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	u32_t count = length / m_state.get_data_length();
	if ((length % m_state.get_data_length()) != 0)
	{
		++count;
	}
	
	u32_t missing_bytes = length;
	u8_t * const bytes = static_cast<u8_t *>(p_bytes);

	for (u32_t ind = 0ul; ind < count; ind++)
	{
		++m_rand_counter;

		status = internal_rand_seed(
			&m_rand_counter,
			sizeof(m_rand_counter));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = internal_rand_seed(
			m_state.get_data(m_state.get_data_length()),
			m_state.get_data_length());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u32_t copied_data = missing_bytes;
		if (copied_data >= m_state.get_data_length())
		{
			copied_data = m_state.get_data_length();
		}

		m_am_tools->memmove(bytes+(m_state.get_data_length()*ind), m_state.get_data(copied_data), copied_data);

		missing_bytes -= copied_data;
	}

	EAP_TEST_RANDOM_TRACE_DATA_DEBUG(
		m_am_tools, 
		EAP_TRACE_MASK_TEST_RANDOM, 
		(EAPL("PSEUDO RANDOM DATA:"),
		 p_bytes,
		 length));

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------


//--------------------------------------------------
// End.
