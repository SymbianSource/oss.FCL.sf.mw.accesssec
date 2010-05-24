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
	#define EAP_FILE_NUMBER_ENUM 3 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_crypto_api.h"
#include "eap_am_bloom_algorithm.h"

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_am_bloom_algorithm_c::~eap_am_bloom_algorithm_c()
{
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_am_bloom_algorithm_c::eap_am_bloom_algorithm_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_am_bloom_algorithm_store_c * const store,
		const u32_t bloom_bit_index_size)
	: m_am_tools(tools)
	, m_store(store)
	, m_bloom_bit_index_size(bloom_bit_index_size)
	, m_is_valid(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = set_bloom_bit_index_size(bloom_bit_index_size);
	if (status != eap_status_ok)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: BLOOM: Illegal bit index size %d.\n"),
			 bloom_bit_index_size));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	if (m_store == 0
		|| m_store->get_is_valid() == false)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: BLOOM: Store is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	status = m_store->set_bloom_bit_index_size(bloom_bit_index_size);
	if (status != eap_status_ok)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: BLOOM: Illegal bit index size %d.\n"),
			 bloom_bit_index_size));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

/// This is the count of bits in the index of Bloom algorithm.
EAP_FUNC_EXPORT eap_status_e eap_am_bloom_algorithm_c::set_bloom_bit_index_size(const u32_t bloom_bit_index_size)
{
	if (bloom_bit_index_size > 32ul)
	{
		// This is absolut maximum value.
		// Much smaller value should be used in real application.
		// 32 bits long index means 2^32 bit long bit store.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	else if (bloom_bit_index_size < 4ul)
	{
		// This is absolut minimum value.
		// Much bigger value should be used in real application.
		// 4 bits long index means 2^4 bit long bit store.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	m_bloom_bit_index_size = bloom_bit_index_size;
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

/**
 * @code
 *  0                   1                   2                   3                   4                   5
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | data 0        | data 1        | data 2        | data 3        | data 4        | data 5        | ...
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ^                     ^                     ^                     ^                     ^
 *  |                     |                     |                     |                     |
 *  |                     |                     |                     |                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  bit_index 0        |  bit_index 1        | bit_index 2         | bit_index 3         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 */
EAP_FUNC_EXPORT u32_t eap_am_bloom_algorithm_c::bloom_filter_get_index(
	const u32_t queried_bit_index,
	const void * const message_digest,
	const u32_t message_digest_length)
{
	const u8_t * const input_data = static_cast<const u8_t *>(message_digest);
	u32_t bit_index = 0ul;
	u32_t start_byte = (queried_bit_index * m_bloom_bit_index_size) / 8ul;
	u32_t end_byte = (queried_bit_index * m_bloom_bit_index_size + (m_bloom_bit_index_size - 1ul)) / 8ul;

	for (u32_t data_ind = start_byte; data_ind <= end_byte; data_ind++)
	{
		i32_t shift = ((data_ind+1ul) * 8ul) - ((queried_bit_index + 1ul) * m_bloom_bit_index_size);
		if (shift < 0)
		{
			const u32_t pre_mask = 0xffffffff >> (32ul - m_bloom_bit_index_size);
			const u8_t mask = static_cast<u8_t>(pre_mask >> (-shift));
			bit_index |= (input_data[data_ind] & mask) << (-shift);
		}
		else
		{
			const u8_t mask = static_cast<const u8_t>(0xff << shift);
			bit_index |= (input_data[data_ind] & mask) >> (shift);
		}
	}

	return bit_index;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_bloom_algorithm_c::bloom_filter_create_message_digest(
	const void * const blob,
	const u32_t blob_length,
	void * const message_digest,
	u32_t * const message_digest_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	crypto_sha1_c sha1(m_am_tools);

	if (sha1.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = sha1.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (message_digest == 0
		|| message_digest_length == 0
		|| *message_digest_length < sha1.get_digest_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	*message_digest_length = sha1.get_digest_length();

	status = sha1.hash_update(blob, blob_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_final(
		message_digest,
		message_digest_length);

	EAP_ASSERT_ALWAYS(sha1.get_digest_length() == *message_digest_length);

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("BLOOM: blob"),
		blob,
		blob_length));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_bloom_algorithm_c::bloom_filter_check_is_blob_new(
	const void * const blob,
	const u32_t blob_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_store->bloom_filter_check_does_bit_store_exists() != eap_status_ok)
	{
		// No valid BIT file. blobs are assumed new.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	static const u32_t DIGEST_LENGTH = 32ul;

	u8_t message_digest[DIGEST_LENGTH];
	u32_t message_digest_length = DIGEST_LENGTH;

	eap_status_e status = bloom_filter_create_message_digest(
		blob,
		blob_length,
		message_digest,
		&message_digest_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (u32_t ind = 0; ind < (message_digest_length * 8ul)/m_bloom_bit_index_size; ind++)
	{
		u32_t bit_index = bloom_filter_get_index(ind, message_digest, message_digest_length);

		if (m_store->bloom_filter_get_bit_index(bit_index) == 0)
		{
			// Because bit is NOT set this blob is new.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
	}

	// Because all bits are set this blob is most probably already used.

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_bloom_algorithm_c::bloom_filter_set_blob_is_used(
	const void * const blob,
	const u32_t blob_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_store->bloom_filter_check_does_bit_store_exists() != eap_status_ok)
	{
		// No valid BIT file. blobs are assumed new.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	static const u32_t DIGEST_LENGTH = 32ul;

	u8_t message_digest[DIGEST_LENGTH];
	u32_t message_digest_length = DIGEST_LENGTH;

	eap_status_e status = bloom_filter_create_message_digest(
		blob,
		blob_length,
		message_digest,
		&message_digest_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (u32_t ind = 0; ind < (message_digest_length * 8ul)/m_bloom_bit_index_size; ind++)
	{
		u32_t bit_index = bloom_filter_get_index(ind, message_digest, message_digest_length);

		status = m_store->bloom_filter_set_bit_index(bit_index);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_am_bloom_algorithm_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_am_bloom_algorithm_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------



// End.
