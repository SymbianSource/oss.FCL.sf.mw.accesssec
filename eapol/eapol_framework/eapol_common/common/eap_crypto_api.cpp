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
	#define EAP_FILE_NUMBER_ENUM 22 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_crypto_api.h"

//--------------------------------------------------

// This is simple optimization.
const u32_t EAP_CRYPTO_API_SHA1_DIGEST_BUFFER_BYTE_SIZE = 20ul;
const u32_t EAP_CRYPTO_API_SHA1_BLOCK_BYTE_SIZE = 64ul;

const u32_t EAP_CRYPTO_API_SHA_256_DIGEST_BUFFER_BYTE_SIZE = 32ul;
const u32_t EAP_CRYPTO_API_SHA_256_BLOCK_BYTE_SIZE = 64ul;

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT abs_crypto_cbc_block_algorithm_c::~abs_crypto_cbc_block_algorithm_c()
{
}


EAP_FUNC_EXPORT abs_crypto_block_algorithm_c::~abs_crypto_block_algorithm_c()
{
}

EAP_FUNC_EXPORT abs_crypto_stream_algorithm_c::~abs_crypto_stream_algorithm_c()
{
}

EAP_FUNC_EXPORT abs_crypto_hash_algorithm_c::~abs_crypto_hash_algorithm_c()
{
}

EAP_FUNC_EXPORT abs_crypto_hmac_algorithm_c::~abs_crypto_hmac_algorithm_c()
{
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------


EAP_FUNC_EXPORT crypto_hmac_c::~crypto_hmac_c()
{
	hmac_cleanup();

	delete m_key;
	m_key = 0;

	delete m_ipad;
	m_ipad = 0;

	delete m_opad;
	m_opad = 0;
}

EAP_FUNC_EXPORT crypto_hmac_c::crypto_hmac_c(
	abs_eap_am_tools_c * const tools,
	abs_crypto_hash_algorithm_c * const crypto_hash_algorithm,
	const bool free_crypto_hash_algorithm)
	: m_am_tools(tools)
	, m_crypto_hash_algorithm(crypto_hash_algorithm)
	, m_key(0)
	, m_ipad(0)
	, m_opad(0)
	, m_is_valid(false)
	, m_free_crypto_hash_algorithm(free_crypto_hash_algorithm)
{
	m_key = new eap_variable_data_c(m_am_tools);
	if (m_key == 0)
	{
		return;
	}

	m_ipad = new eap_variable_data_c(m_am_tools);
	if (m_ipad == 0)
	{
		return;
	}

	m_opad = new eap_variable_data_c(m_am_tools);
	if (m_opad == 0)
	{
		return;
	}

	set_is_valid();
}

EAP_FUNC_EXPORT void crypto_hmac_c::set_is_valid()
{
	m_is_valid = true;
}

EAP_FUNC_EXPORT bool crypto_hmac_c::get_is_valid()
{
	return m_is_valid;
}

EAP_FUNC_EXPORT u32_t crypto_hmac_c::get_digest_length()
{
	return m_crypto_hash_algorithm->get_digest_length();
}

EAP_FUNC_EXPORT eap_status_e crypto_hmac_c::initialize_pad(
	eap_variable_data_c * const p_pad,
	const u8_t pad_value)
{
	if (get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = p_pad->set_buffer_length(
		m_crypto_hash_algorithm->get_block_size());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	p_pad->set_data_length(m_crypto_hash_algorithm->get_block_size());

	u32_t ind = 0ul;
	u8_t * key = m_key->get_data(m_key->get_data_length());
	u8_t * ipad = p_pad->get_data(p_pad->get_data_length());
	
	for (ind = 0ul; ind < m_key->get_data_length(); ind++)
	{
		ipad[ind] = static_cast<u8_t>(key[ind] ^ pad_value);
	}
	
	for (ind = m_key->get_data_length()
			 ; ind < m_crypto_hash_algorithm->get_block_size(); ind++)
	{
		ipad[ind] = pad_value;
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_status_e crypto_hmac_c::hmac_set_key(
	const eap_variable_data_c * const hmac_key)
{
	if (hmac_key == 0
		|| hmac_key->get_is_valid_data() == false
		|| get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = eap_status_process_general_error;

	status = m_crypto_hash_algorithm->hash_init();
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (hmac_key->get_data_length()
		> m_crypto_hash_algorithm->get_block_size())
	{
		status = m_crypto_hash_algorithm->hash_update(
			hmac_key->get_data(hmac_key->get_data_length()),
			hmac_key->get_data_length());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = m_key->set_buffer_length(
			m_crypto_hash_algorithm->get_digest_length());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		m_key->set_data_length(m_crypto_hash_algorithm->get_digest_length());

		u32_t md_length = m_key->get_data_length();

		status = m_crypto_hash_algorithm->hash_final(
			m_key->get_data(m_key->get_data_length()),
			&md_length);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_ASSERT(md_length == m_key->get_data_length());
	}
	else
	{
		status = m_key->set_copy_of_buffer(hmac_key);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - -
	// Initialize inner pad.

	{
		static const u8_t EAP_HMAC_IPAD = 0x36;

		status = initialize_pad(
			m_ipad,
			EAP_HMAC_IPAD);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - -
	// Initialize outer pad.

	{
		static const u8_t EAP_HMAC_OPAD = 0x5C;

		status = initialize_pad(
			m_opad,
			EAP_HMAC_OPAD);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	// - - - - - - - - - - - - - - - - - - - -

	status = m_crypto_hash_algorithm->hash_init();
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_crypto_hash_algorithm->hash_update(
		m_ipad->get_data(m_ipad->get_data_length()),
		m_ipad->get_data_length());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_status_e crypto_hmac_c::hmac_update(
	const void * const data,
	const u32_t data_length)
{
	if (get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = m_crypto_hash_algorithm->hash_update(
		data,
		data_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_status_e crypto_hmac_c::hmac_final(
	void * const message_digest,
	u32_t *md_length_or_null)
{
	if (get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_variable_data_c idigest(m_am_tools);

	eap_status_e status = idigest.set_buffer_length(
		m_crypto_hash_algorithm->get_digest_length());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	idigest.set_data_length(m_crypto_hash_algorithm->get_digest_length());

	u32_t md_length = idigest.get_data_length();

	status = m_crypto_hash_algorithm->hash_final(
		idigest.get_data(idigest.get_data_length()),
		&md_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_ASSERT(md_length == m_crypto_hash_algorithm->get_digest_length());

	// - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_crypto_hash_algorithm->hash_init();
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_crypto_hash_algorithm->hash_update(
		m_opad->get_data(m_opad->get_data_length()),
		m_opad->get_data_length());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_crypto_hash_algorithm->hash_update(
		idigest.get_data(idigest.get_data_length()),
		idigest.get_data_length());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_crypto_hash_algorithm->hash_final(
		message_digest,
		md_length_or_null);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (md_length_or_null != 0)
	{
		EAP_ASSERT(*md_length_or_null
				   == m_crypto_hash_algorithm->get_digest_length());
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}


EAP_FUNC_EXPORT eap_status_e crypto_hmac_c::hmac_128_final(
	void * const message_digest,
	u32_t *md_length_or_null)
{
	if (message_digest == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t tmp_length = get_digest_length();
	eap_variable_data_c tmp_digest(m_am_tools);
	if (tmp_digest.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	eap_status_e status = tmp_digest.set_buffer_length(tmp_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = hmac_final(
		tmp_digest.get_buffer(tmp_digest.get_buffer_length()),
		&tmp_length);
	if (status != eap_status_ok
		|| tmp_length != tmp_digest.get_buffer_length())
	{
		if (md_length_or_null != 0)
		{
			*md_length_or_null = 0;
		}
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	else
	{
		status = tmp_digest.set_data_length(tmp_length);
		if (status != eap_status_ok)
	    {
			return EAP_STATUS_RETURN(m_am_tools, status);
	    }

		if (md_length_or_null != 0)
		{
			*md_length_or_null = HMAC_SHA1_128_SIZE;
		}

		m_am_tools->memmove(
			message_digest,
			tmp_digest.get_data(HMAC_SHA1_128_SIZE),
			HMAC_SHA1_128_SIZE);

		return EAP_STATUS_RETURN(m_am_tools, status);
	}
}

EAP_FUNC_EXPORT eap_status_e crypto_hmac_c::hmac_cleanup()
{
	if (m_key != 0)
	{
		m_key->reset();
	}

	if (m_ipad != 0)
	{
		m_ipad->reset();
	}

	if (m_opad != 0)
	{
		m_opad->reset();
	}

	if (m_free_crypto_hash_algorithm == true)
	{
		delete m_crypto_hash_algorithm;
	}
	m_crypto_hash_algorithm = 0;

	m_is_valid = false;

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_cbc_c::~crypto_cbc_c()
{
	reset();
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_cbc_c::crypto_cbc_c(
	abs_eap_am_tools_c * const tools,
	abs_crypto_block_algorithm_c * const crypto_block_algorithm,
	const bool free_crypto_block_algorithm)
	: m_am_tools(tools)
	, m_crypto_block_algorithm(crypto_block_algorithm)
	, m_is_valid(false)
	, m_tmp_IV(0)
	, m_encr_offset(0ul)
	, m_encr_dispatch(0)
	, m_encr_hold(0)
	, m_saved_in_buffer(0)
	, m_saved_out_buffer(0)
	, m_iv_buffer_1(0)
	, m_iv_buffer_2(0)
	, m_free_crypto_block_algorithm(free_crypto_block_algorithm)
{
	m_tmp_IV = new eap_variable_data_c(m_am_tools);
	m_encr_dispatch = new u8_t *[m_crypto_block_algorithm->get_block_size()];
	m_encr_hold = new u8_t [m_crypto_block_algorithm->get_block_size()];
	m_saved_in_buffer = new u8_t [m_crypto_block_algorithm->get_block_size()];
	m_saved_out_buffer = new u8_t [m_crypto_block_algorithm->get_block_size()];
	m_iv_buffer_1 = new u8_t [m_crypto_block_algorithm->get_block_size()];
	m_iv_buffer_2 = new u8_t [m_crypto_block_algorithm->get_block_size()];

	if (m_tmp_IV == 0
		|| m_encr_dispatch == 0
		|| m_encr_hold == 0
		|| m_saved_in_buffer == 0
		|| m_saved_out_buffer == 0
		|| m_iv_buffer_1 == 0
		|| m_iv_buffer_2 == 0)
	{
		reset();
	}
	else
	{
		set_is_valid();
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_cbc_c::reset()
{
	m_is_valid = false;

	if (m_tmp_IV != 0)
	{
		m_tmp_IV->reset();
		delete m_tmp_IV;
		m_tmp_IV = 0;
	}

	if (m_crypto_block_algorithm != 0)
	{
		if (m_encr_dispatch != 0)
		{
			m_am_tools->memset(
				m_encr_dispatch,
				0,
				m_crypto_block_algorithm->get_block_size());
		}

		if (m_encr_hold != 0)
		{
			m_am_tools->memset(
				m_encr_hold,
				0,
				m_crypto_block_algorithm->get_block_size());
		}
	}

	delete [] m_encr_dispatch;
	m_encr_dispatch = 0;

	delete [] m_encr_hold;
	m_encr_hold = 0;

	delete [] m_saved_in_buffer;
	m_saved_in_buffer = 0;

	delete [] m_saved_out_buffer;
	m_saved_out_buffer = 0;

	delete [] m_iv_buffer_1;
	m_iv_buffer_1 = 0;

	delete [] m_iv_buffer_2;
	m_iv_buffer_2 = 0;

	if (m_free_crypto_block_algorithm == true)
	{
		delete m_crypto_block_algorithm;
	}
	m_crypto_block_algorithm = 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_cbc_c::cbc_xor_block(
	const void * const cipher_IV,
	void * const data_block,
	const u32_t block_size,
	const u32_t key_length)
{
	EAP_UNREFERENCED_PARAMETER(block_size);
	EAP_UNREFERENCED_PARAMETER(key_length);
	EAP_ASSERT((block_size % m_crypto_block_algorithm->get_block_size()) == 0);
	EAP_ASSERT((key_length % m_crypto_block_algorithm->get_key_length()) == 0);

#if defined(USE_EAP_64_BIT_MULTIPLICATION)
	if ((reinterpret_cast<u32_t>(cipher_IV) % sizeof(u64_t)) == 0
		&& (reinterpret_cast<u32_t>(data_block) % sizeof(u64_t)) == 0)
	{
		const u64_t * const pIV = static_cast<const u64_t *>(cipher_IV);
		u64_t * const pdata = static_cast<u64_t *>(data_block);

		for (u32_t ind = 0u; ind < block_size/sizeof(u64_t); ind++)
		{
			pdata[ind] = static_cast<u64_t>(pdata[ind] ^ pIV[ind]);
		}
	}
	else
#endif //#if defined(USE_EAP_64_BIT_MULTIPLICATION)
	if ((reinterpret_cast<u32_t>(cipher_IV) % sizeof(u32_t)) == 0
		&& (reinterpret_cast<u32_t>(data_block) % sizeof(u32_t)) == 0)
	{
		const u32_t * const pIV = static_cast<const u32_t *>(cipher_IV);
		u32_t * const pdata = static_cast<u32_t *>(data_block);

		for (u32_t ind = 0u; ind < block_size/sizeof(u32_t); ind++)
		{
			pdata[ind] = static_cast<u32_t>(pdata[ind] ^ pIV[ind]);
		}
	}
	else if ((reinterpret_cast<u32_t>(cipher_IV) % sizeof(u16_t)) == 0
		&& (reinterpret_cast<u32_t>(data_block) % sizeof(u16_t)) == 0)
	{
		const u16_t * const pIV = static_cast<const u16_t *>(cipher_IV);
		u16_t * const pdata = static_cast<u16_t *>(data_block);

		for (u32_t ind = 0u; ind < block_size/sizeof(u16_t); ind++)
		{
			pdata[ind] = static_cast<u16_t>(pdata[ind] ^ pIV[ind]);
		}
	}
	else
	{
		const u8_t * const pIV = static_cast<const u8_t *>(cipher_IV);
		u8_t * const pdata = static_cast<u8_t *>(data_block);

		for (u32_t ind = 0u; ind < block_size/sizeof(u8_t); ind++)
		{
			pdata[ind] = static_cast<u8_t>(pdata[ind] ^ pIV[ind]);
		}
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_cbc_c::cbc_copy_block(
	void * const target,
	const void * const source,
	const u32_t block_size,
	const u32_t key_length)
{
	EAP_UNREFERENCED_PARAMETER(key_length);
	EAP_ASSERT((block_size % m_crypto_block_algorithm->get_block_size()) == 0);
	EAP_ASSERT((key_length % m_crypto_block_algorithm->get_key_length()) == 0);

#if defined(USE_EAP_64_BIT_MULTIPLICATION)
	if ((reinterpret_cast<u32_t>(source) % sizeof(u64_t)) == 0
		&& (reinterpret_cast<u32_t>(target) % sizeof(u64_t)) == 0)
	{
		const u64_t * const p_source
			= static_cast<const u64_t *>(source);
		u64_t * const p_target = static_cast<u64_t *>(target);

		for (u32_t ind = 0u; ind < block_size/sizeof(u64_t); ind++)
		{
			p_target[ind] = p_source[ind];
		}
	}
	else
#endif //#if defined(USE_EAP_64_BIT_MULTIPLICATION)
	if ((reinterpret_cast<u32_t>(source) % sizeof(u32_t)) == 0
		&& (reinterpret_cast<u32_t>(target) % sizeof(u32_t)) == 0)
	{
		const u32_t * const p_source
			= static_cast<const u32_t *>(source);
		u32_t * const p_target = static_cast<u32_t *>(target);

		for (u32_t ind = 0u; ind < block_size/sizeof(u32_t); ind++)
		{
			p_target[ind] = p_source[ind];
		}
	}
	else if ((reinterpret_cast<u32_t>(source) % sizeof(u16_t)) == 0
		&& (reinterpret_cast<u32_t>(target) % sizeof(u16_t)) == 0)
	{
		const u16_t * const p_source
			= static_cast<const u16_t *>(source);
		u16_t * const p_target = static_cast<u16_t *>(target);

		for (u32_t ind = 0u; ind < block_size/sizeof(u16_t); ind++)
		{
			p_target[ind] = p_source[ind];
		}
	}
	else
	{
		const u8_t * const p_source = static_cast<const u8_t *>(source);
		u8_t * const p_target = static_cast<u8_t *>(target);

		for (u32_t ind = 0u; ind < block_size/sizeof(u8_t); ind++)
		{
			p_target[ind] = p_source[ind];
		}
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_cbc_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_cbc_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT const eap_variable_data_c * crypto_cbc_c::get_tmp_IV()
{
	return m_tmp_IV;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_cbc_c::get_encrypts()
{
	return m_crypto_block_algorithm->get_encrypts();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_cbc_c::get_key_length()
{
	return m_crypto_block_algorithm->get_key_length();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_cbc_c::get_block_size()
{
	return m_crypto_block_algorithm->get_block_size();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_cbc_c::aligned_data_length(
	u32_t data_length)
{
	const u32_t fill_bytes = data_length
		% (m_crypto_block_algorithm->get_block_size());

	// NOTE, this will always add padding bytes (1...BLOCK_SIZE).
	data_length += ((m_crypto_block_algorithm->get_block_size())-fill_bytes);

	return data_length;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_cbc_c::add_padding_bytes(
	void * const buffer,
	const u32_t buffer_length,
	const u8_t padding_byte)
{
	u8_t * const p_buffer = static_cast<u8_t *>(buffer);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CBC: encrypt_function: crypto_cbc_c::add_padding_bytes(): buffer=0x%08x, buffer_length=%d, padding_byte=0x%02x\n"),
		buffer,
		buffer_length,
		padding_byte));

	for(u32_t ind = 0; ind < buffer_length; ind++)
	{
		p_buffer[ind] = padding_byte;
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("crypto_cbc_c::add_padding_bytes()"),
		 p_buffer,
		 buffer_length));

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_cbc_c::check_padding_bytes(
	const void * const buffer,
	const u32_t buffer_length,
	const u8_t padding_byte)
{
	const u8_t * const p_buffer = static_cast<const u8_t *>(buffer);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CBC: encrypt_function: crypto_cbc_c::check_padding_bytes(): buffer=0x%08x, buffer_length=%d, padding_byte=0x%02x\n"),
		buffer,
		buffer_length,
		padding_byte));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("crypto_cbc_c::check_padding_bytes()"),
		 p_buffer,
		 buffer_length));

	for(u32_t ind = 0; ind < buffer_length; ind++)
	{
		if (p_buffer[ind] != padding_byte)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_padding);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_cbc_c::set_encryption_key(
	const void * const encryption_IV,
	const u32_t encryption_IV_length,
	const void * const key,
	const u32_t key_length)
{
	eap_status_e status = m_tmp_IV->set_copy_of_buffer(
		encryption_IV, encryption_IV_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return m_crypto_block_algorithm->set_encryption_key(
		key,
		key_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_cbc_c::set_decryption_key(
	const void * const encryption_IV,
	const u32_t encryption_IV_length,
	const void * const key,
	const u32_t key_length)
{
	eap_status_e status = m_tmp_IV->set_copy_of_buffer(
		encryption_IV, encryption_IV_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return m_crypto_block_algorithm->set_decryption_key(
		key,
		key_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_cbc_c::internal_encrypt_data(
	const void * const data_in,
	void * const data_out,
	const u32_t data_length)
{
	if ((data_length % m_crypto_block_algorithm->get_block_size()) != 0)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			eap_status_data_length_not_aligned_to_block_size);
	}

	const u8_t * const p_data_in = static_cast<const u8_t *>(data_in);
	u8_t * const p_data_out = static_cast<u8_t *>(data_out);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("encrypt data_in"),
		data_in, data_length));

	cbc_copy_block(
		m_saved_in_buffer,
		data_in,
		m_crypto_block_algorithm->get_block_size(),
		m_crypto_block_algorithm->get_key_length());

	cbc_xor_block(
		m_tmp_IV->get_data(m_tmp_IV->get_data_length()),
		m_saved_in_buffer,
		m_crypto_block_algorithm->get_block_size(),
		m_crypto_block_algorithm->get_key_length());

	u32_t ind;
	eap_status_e status = eap_status_ok;

	for (ind = 0u; ind < data_length
			 ; ind += m_crypto_block_algorithm->get_block_size())
	{
		if (ind > 0u)
		{
			cbc_copy_block(
				m_saved_in_buffer,
				p_data_in+ind,
				m_crypto_block_algorithm->get_block_size(),
				m_crypto_block_algorithm->get_key_length());

			cbc_xor_block(
				p_data_out+(ind-m_crypto_block_algorithm->get_block_size()),
				m_saved_in_buffer,
				m_crypto_block_algorithm->get_block_size(),
				m_crypto_block_algorithm->get_key_length());
		}

		status = m_crypto_block_algorithm->encrypt_block(
			m_saved_in_buffer,
			m_saved_out_buffer,
			m_crypto_block_algorithm->get_block_size());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		cbc_copy_block(
			p_data_out+ind,
			m_saved_out_buffer,
			m_crypto_block_algorithm->get_block_size(),
			m_crypto_block_algorithm->get_key_length());

	}

	// Save the last block.
	status = m_tmp_IV->set_copy_of_buffer(
		p_data_out+(ind-m_crypto_block_algorithm->get_block_size()),
		m_crypto_block_algorithm->get_block_size());

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("encrypt data_out"),
		 data_out,
		 data_length));

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_cbc_c::encrypt_data(
	const void * const data_in,
	void * const data_out,
	const u32_t data_length)
{
	EAP_ASSERT(data_in != data_out);

	eap_status_e status = internal_encrypt_data(
		data_in,
		data_out,
		data_length);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_cbc_c::encrypt_data(
	void * const data_in_out,
	const u32_t data_length)
{

	eap_status_e status = internal_encrypt_data(
		data_in_out,
		data_in_out,
		data_length);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_cbc_c::internal_decrypt_data(
	const void * const data_in,
	void * const data_out,
	const u32_t data_length)
{
	u8_t *saved_iv_buffer = m_iv_buffer_1;
	u8_t *encrypted_buffer = m_iv_buffer_2;

	if ((data_length % m_crypto_block_algorithm->get_block_size()) != 0u)
	{
		return EAP_STATUS_RETURN(
			m_am_tools,
			eap_status_data_length_not_aligned_to_block_size);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("decrypt data_in"),
		 data_in,
		 data_length));

	const u8_t * const p_data_in = static_cast<const u8_t *>(data_in);
	u8_t * const p_data_out = static_cast<u8_t *>(data_out);

	cbc_copy_block(
		saved_iv_buffer,
		m_tmp_IV->get_data(m_tmp_IV->get_data_length()),
		m_crypto_block_algorithm->get_block_size(),
		m_crypto_block_algorithm->get_key_length());

	u32_t ind;
	eap_status_e status = eap_status_ok;

	for (ind = 0u; ind < data_length
			 ; ind += m_crypto_block_algorithm->get_block_size())
	{
		cbc_copy_block(
			encrypted_buffer,
			p_data_in+ind,
			m_crypto_block_algorithm->get_block_size(),
			m_crypto_block_algorithm->get_key_length());

		cbc_copy_block(
			m_saved_in_buffer,
			p_data_in+ind,
			m_crypto_block_algorithm->get_block_size(),
			m_crypto_block_algorithm->get_key_length());

		status = m_crypto_block_algorithm->decrypt_block(
			m_saved_in_buffer,
			m_saved_out_buffer,
			m_crypto_block_algorithm->get_block_size());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		cbc_xor_block(
			saved_iv_buffer,
			m_saved_out_buffer,
			m_crypto_block_algorithm->get_block_size(),
			m_crypto_block_algorithm->get_key_length());

		cbc_copy_block(
			p_data_out+ind,
			m_saved_out_buffer,
			m_crypto_block_algorithm->get_block_size(),
			m_crypto_block_algorithm->get_key_length());

		u8_t *tmp = encrypted_buffer;
		encrypted_buffer = saved_iv_buffer;
		saved_iv_buffer = tmp;
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("decrypt data_out"),
		 data_out,
		 data_length));

	// Save the last block.
	status = m_tmp_IV->set_copy_of_buffer(
		saved_iv_buffer,
		m_crypto_block_algorithm->get_block_size());

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_cbc_c::decrypt_data(
	const void * const data_in,
	void * const data_out,
	const u32_t data_length)
{
	EAP_ASSERT(data_in != data_out);

	eap_status_e status = internal_decrypt_data(
		data_in,
		data_out,
		data_length);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_cbc_c::decrypt_data(
	void * const data_in_out,
	const u32_t data_length)
{

	eap_status_e status = internal_decrypt_data(
		data_in_out,
		data_in_out,
		data_length);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_cbc_c::update_non_aligned(
	const void * const msg_in,
	void * const msg_out,
	const u32_t msg_size)
{
	EAP_ASSERT_ALWAYS(msg_in != msg_out);

	const u8_t *inp = reinterpret_cast<const u8_t *>(msg_in);
	u8_t *oup = static_cast<u8_t *>(msg_out);
	i32_t len = static_cast<i32_t>(msg_size);
	i32_t tail;
	eap_status_e status = eap_status_process_general_error;

	if (m_encr_offset)
	{
		//
		// Non aligned handling
		//
		while (len > 0
			&& m_encr_offset
			   < static_cast<i32_t>(m_crypto_block_algorithm->get_block_size()))
		{
			m_encr_dispatch[m_encr_offset] = oup++;
			m_encr_hold[m_encr_offset++] = *inp++;
			len--;
		}

		if (m_encr_offset == static_cast<i32_t>(m_crypto_block_algorithm->get_block_size()))
		{
			// Got full block, flush out
			if (m_crypto_block_algorithm->get_encrypts() == true)
			{
				status = encrypt_data(
					m_encr_hold,
					m_crypto_block_algorithm->get_block_size());
			}
			else
			{
				status = decrypt_data(
					m_encr_hold,
					m_crypto_block_algorithm->get_block_size());
			}

			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			for (m_encr_offset = 0
					 ; m_encr_offset
					 < static_cast<i32_t>(m_crypto_block_algorithm->get_block_size())
					 ; ++m_encr_offset)
			{
				*(m_encr_dispatch[m_encr_offset]) = m_encr_hold[m_encr_offset];
			}
			m_encr_offset = 0;
		}
		// Either len == 0 or (encrypt->encr_offset) == 0, or both!!!
	}

	tail = len % m_crypto_block_algorithm->get_block_size();
	len -= tail;
	if (len > 0)
	{
		if (m_crypto_block_algorithm->get_encrypts() == true)
		{
			status = encrypt_data(
				inp,
				oup,
				len);
		}
		else
		{
			status = decrypt_data(
				inp,
				oup,
				len);
		}

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (tail > 0)
	{
		oup += len;
		inp += len;
		while (m_encr_offset < tail)
		{
			m_encr_dispatch[m_encr_offset] = oup++;
			m_encr_hold[m_encr_offset++] = *inp++;
		}
		status = eap_status_ok;
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_cbc_c::update_non_aligned(
	void * const msg_in_out,
	const u32_t msg_size)
{
	u8_t *msg = static_cast<u8_t *>(msg_in_out);
	i32_t len = static_cast<i32_t>(msg_size);
	i32_t tail;
	eap_status_e status = eap_status_process_general_error;

	if (m_encr_offset)
	{
		//
		// Non aligned handling
		//
		while (len > 0
			&& m_encr_offset
			   < static_cast<i32_t>(m_crypto_block_algorithm->get_block_size()))
		{
			m_encr_dispatch[m_encr_offset] = msg;
			m_encr_hold[m_encr_offset++] = *msg++;
			len--;
		}

		if (m_encr_offset == static_cast<i32_t>(m_crypto_block_algorithm->get_block_size()))
		{
			// Got full block, flush out
			if (m_crypto_block_algorithm->get_encrypts() == true)
			{
				status = encrypt_data(
					m_encr_hold,
					m_crypto_block_algorithm->get_block_size());
			}
			else
			{
				status = decrypt_data(
					m_encr_hold,
					m_crypto_block_algorithm->get_block_size());
			}

			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			for (m_encr_offset = 0
					 ; m_encr_offset
					 < static_cast<i32_t>(m_crypto_block_algorithm->get_block_size())
					 ; ++m_encr_offset)
			{
				*(m_encr_dispatch[m_encr_offset]) = m_encr_hold[m_encr_offset];
			}
			m_encr_offset = 0;
		}
		// Either len == 0 or (encrypt->encr_offset) == 0, or both!!!
	}

	tail = len % m_crypto_block_algorithm->get_block_size();
	len -= tail;
	if (len > 0)
	{
		if (m_crypto_block_algorithm->get_encrypts() == true)
		{
			status = encrypt_data(
				msg,
				len);
		}
		else
		{
			status = decrypt_data(
				msg,
				len);
		}

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	if (tail > 0)
	{
		msg += len;
		while (m_encr_offset < tail)
		{
			m_encr_dispatch[m_encr_offset] = msg;
			m_encr_hold[m_encr_offset++] = *msg++;
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_cbc_c::finalize_non_aligned()
{
	eap_status_e status = eap_status_ok;

	if (m_encr_offset > 0)
	{
		if ((m_encr_offset
			 % m_crypto_block_algorithm->get_block_size()) != 0u)
		{
			EAP_ASSERT_ALWAYS(
				(m_encr_offset
				 % m_crypto_block_algorithm->get_block_size()) == 0u);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_data_length_not_aligned_to_block_size);
		}

		i32_t ind;

		/* Unfinished business... flush it out! */
		if (m_crypto_block_algorithm->get_encrypts() == true)
		{
			status = encrypt_data(
				m_encr_hold,
				m_crypto_block_algorithm->get_block_size());
		}
		else
		{
			status = decrypt_data(
				m_encr_hold,
				m_crypto_block_algorithm->get_block_size());
		}

		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		for (ind = 0u; ind < m_encr_offset; ++ind)
		{
			*(m_encr_dispatch[ind]) = m_encr_hold[ind];
		}
		m_encr_offset = 0;	/* (should not be needed, but... ) */
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_aes_c::~crypto_aes_c()
{
	if (m_aes_context.get_is_valid_data() == true)
	{
		m_am_tools->get_crypto()->aes_cleanup(&m_aes_context);
	}
	m_aes_context.reset();
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_aes_c::crypto_aes_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(false)
	, m_aes_context(tools)
	, m_block_size(0u)
	, m_encrypt(false)
{
	m_block_size = m_am_tools->get_crypto()->aes_block_size();

	m_aes_context.reset();

	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_aes_c::get_encrypts()
{
	return m_encrypt;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_aes_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_aes_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_aes_c::get_key_length()
{
	return m_am_tools->get_crypto()->aes_key_length();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_aes_c::get_block_size()
{
	return m_block_size;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_aes_c::set_encryption_key(
	const void * const key,
	const u32_t key_length)
{
	m_encrypt = true;

	return m_am_tools->get_crypto()->aes_set_encryption_key(
		&m_aes_context, static_cast<const u8_t *>(key), key_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_aes_c::set_decryption_key(
	const void * const key,
	const u32_t key_length)
{
	m_encrypt = false;

	return m_am_tools->get_crypto()->aes_set_decryption_key(
		&m_aes_context, static_cast<const u8_t *>(key), key_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_aes_c::encrypt_block(
	const void * const data_in,
	void * const data_out,
	const u32_t data_length)
{
	EAP_ASSERT_TOOLS(m_am_tools, ((reinterpret_cast<u32_t>(data_in) % 4) == 0));
	EAP_ASSERT_TOOLS(m_am_tools, ((reinterpret_cast<u32_t>(data_out) % 4) == 0));

	return m_am_tools->get_crypto()->aes_encrypt_block(
		&m_aes_context,
		static_cast<const u8_t *>(data_in),
		static_cast<u8_t *>(data_out),
		data_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_aes_c::decrypt_block(
	const void * const data_in,
	void * const data_out,
	const u32_t data_length)
{
	EAP_ASSERT_TOOLS(m_am_tools, ((reinterpret_cast<u32_t>(data_in) % 4) == 0));
	EAP_ASSERT_TOOLS(m_am_tools, ((reinterpret_cast<u32_t>(data_out) % 4) == 0));

	return m_am_tools->get_crypto()->aes_decrypt_block(
		&m_aes_context,
		static_cast<const u8_t *>(data_in),
		static_cast<u8_t *>(data_out), data_length);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_3des_ede_c::~crypto_3des_ede_c()
{
	if (m_context.get_is_valid_data() == true)
	{
		m_am_tools->get_crypto()->cleanup_3des_ede(&m_context);
	}
	m_context.reset();
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_3des_ede_c::crypto_3des_ede_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(false)
	, m_context(tools)
	, m_block_size(0u)
	, m_encrypt(false)
{
	m_block_size = m_am_tools->get_crypto()->block_size_3des_ede();

	m_context.reset();

	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_3des_ede_c::get_encrypts()
{
	return m_encrypt;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_3des_ede_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_3des_ede_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_3des_ede_c::get_key_length()
{
	return m_am_tools->get_crypto()->key_length_3des_ede();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_3des_ede_c::get_block_size()
{
	return m_block_size;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_3des_ede_c::set_encryption_key(
	const void * const key,
	const u32_t key_length)
{
	m_encrypt = true;

	return m_am_tools->get_crypto()->set_encryption_key_3des_ede(
		&m_context, static_cast<const u8_t *>(key), key_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_3des_ede_c::set_decryption_key(
	const void * const key,
	const u32_t key_length)
{
	m_encrypt = false;

	return m_am_tools->get_crypto()->set_decryption_key_3des_ede(
		&m_context, static_cast<const u8_t *>(key), key_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_3des_ede_c::encrypt_block(
	const void * const data_in,
	void * const data_out,
	const u32_t data_length)
{
	EAP_ASSERT_TOOLS(m_am_tools, ((reinterpret_cast<u32_t>(data_in) % 4) == 0));
	EAP_ASSERT_TOOLS(m_am_tools, ((reinterpret_cast<u32_t>(data_out) % 4) == 0));

	return m_am_tools->get_crypto()->encrypt_block_3des_ede(
		&m_context,
		static_cast<const u8_t *>(data_in),
		static_cast<u8_t *>(data_out),
		data_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_3des_ede_c::decrypt_block(
	const void * const data_in,
	void * const data_out,
	const u32_t data_length)
{
	EAP_ASSERT_TOOLS(m_am_tools, ((reinterpret_cast<u32_t>(data_in) % 4) == 0));
	EAP_ASSERT_TOOLS(m_am_tools, ((reinterpret_cast<u32_t>(data_out) % 4) == 0));

	return m_am_tools->get_crypto()->decrypt_block_3des_ede(
		&m_context,
		static_cast<const u8_t *>(data_in),
		static_cast<u8_t *>(data_out),
		data_length);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_aes_wrap_c::~crypto_aes_wrap_c()
{
}

EAP_FUNC_EXPORT crypto_aes_wrap_c::crypto_aes_wrap_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	  , m_aes(tools)
	  , m_key(tools)
	  , m_encrypt(false)
	  , m_is_valid(false)
{
	if (m_aes.get_is_valid() == false)
	{
		return;
	}

	if (m_key.get_is_valid() == false)
	{
		return;
	}

	set_is_valid();
}

EAP_FUNC_EXPORT void crypto_aes_wrap_c::set_is_valid()
{
	m_is_valid = true;
}

EAP_FUNC_EXPORT bool crypto_aes_wrap_c::get_is_valid()
{
	return m_is_valid;
}

EAP_FUNC_EXPORT bool crypto_aes_wrap_c::get_encrypts()
{
	return m_encrypt;
}

EAP_FUNC_EXPORT u32_t crypto_aes_wrap_c::get_key_length()
{
	return m_aes.get_key_length();
}

EAP_FUNC_EXPORT u32_t crypto_aes_wrap_c::get_block_size()
{
	return EAP_CRYPTO_AES_WRAP_BLOCK_SIZE;
}

EAP_FUNC_EXPORT eap_status_e crypto_aes_wrap_c::set_encryption_key(
	const void * const key,
	const u32_t key_length)
{
	eap_status_e status = m_key.set_copy_of_buffer(key, key_length);

	m_encrypt = true;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("AES-Wrap enc key"),
		 m_key.get_data(),
		 m_key.get_data_length()));

	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_status_e crypto_aes_wrap_c::set_decryption_key(
	const void * const key,
	const u32_t key_length)
{
	eap_status_e status = m_key.set_copy_of_buffer(key, key_length);

	m_encrypt = false;

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("AES-Wrap dec key"),
		 m_key.get_data(),
		 m_key.get_data_length()));

	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_status_e crypto_aes_wrap_c::add_padding_bytes(
	void * const buffer,
	const u32_t buffer_length)
{
	if (buffer == 0
		|| buffer_length == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u8_t * data = static_cast<u8_t *>(buffer);
	
	data[0] = 0xdd;

	for (u32_t ind = 1ul; ind < buffer_length; ind++)
	{
		data[ind] = 0x00;
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

EAP_FUNC_EXPORT eap_status_e crypto_aes_wrap_c::encrypt_block(
	const void * const data_in,
	const u32_t data_in_length,
	void * const data_out,
	const u32_t data_out_length)
{
#if !defined(DISABLE_CRYPTO_AES_WRAP)
	/*
	  Inputs:  Plaintext, n 64-bit values {P1, P2, ..., Pn}, and
	           Key, K (the KEK).
	  Outputs: Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}.
	*/
	if (data_in == 0
		|| data_out == 0
		|| (data_in_length % get_block_size()) != 0
		|| data_out_length < data_in_length+get_block_size())
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("plain data"),
		 data_in,
		 data_in_length));

	/*
	  1) Initialize variables.
   
	  Set A = IV, an initial value (see 2.2.3)
	  For i = 1 to n
	      R[i] = P[i]
	*/

	u64_t A_integrity_reg;
	EAP_ASSERT_TOOLS(m_am_tools, sizeof(A_integrity_reg) == sizeof(EAP_CRYPTO_AES_WRAP_DEFAULT_INITIAL_IV));
	m_am_tools->memmove(&A_integrity_reg, EAP_CRYPTO_AES_WRAP_DEFAULT_INITIAL_IV, sizeof(A_integrity_reg));

	eap_variable_data_c Register(m_am_tools);

	eap_status_e status = Register.set_copy_of_buffer(data_in, data_in_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	/*
	  2) Calculate intermediate values.

	  For j = 0 to 5
	      For i=1 to n
		      B = AES(K, A | R[i])
			  A = MSB(64, B) ^ t where t = (n*j)+i
			  R[i] = LSB(64, B)
	*/

	u64_t n_block_count = Register.get_data_length() / 8ul;
	u64_t B_tmp_buffer[2];
	eap_variable_data_c data(m_am_tools);

	status = data.set_buffer_length(sizeof(A_integrity_reg) + EAP_CRYPTO_AES_WRAP_BLOCK_SIZE);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	for (u64_t j_ind = 0ul; j_ind <= 5ul; j_ind++)
	{
		for (u64_t i_ind = 1ul; i_ind <= n_block_count; i_ind++)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_EAP_AM_CRYPTO,
				(EAPL("\n")));

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_EAP_AM_CRYPTO,
				(EAPL("crypto_aes_wrap_c::encrypt_block(): j_ind %d, i_ind %d\n"),
				 j_ind,
				 i_ind));

			eap_status_e status = m_aes.set_encryption_key(
				m_key.get_data(),
				m_key.get_data_length());
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_EAP_AM_CRYPTO,
				(EAPL("In A_integrity_reg"),
				 &A_integrity_reg,
				 sizeof(A_integrity_reg)));

			status = data.set_copy_of_buffer(&A_integrity_reg, sizeof(A_integrity_reg));
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			u8_t * const Ri_reg = Register.get_data_offset(
				static_cast<u32_t>((i_ind-1ul))*static_cast<u32_t>(EAP_CRYPTO_AES_WRAP_BLOCK_SIZE),
				static_cast<u32_t>(EAP_CRYPTO_AES_WRAP_BLOCK_SIZE));
			if (Ri_reg == 0)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_EAP_AM_CRYPTO,
				(EAPL("         In Ri_reg"),
				 Ri_reg,
				 static_cast<u32_t>(EAP_CRYPTO_AES_WRAP_BLOCK_SIZE)));

			status = data.add_data(Ri_reg, EAP_CRYPTO_AES_WRAP_BLOCK_SIZE);
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_ASSERT_TOOLS(m_am_tools, sizeof(B_tmp_buffer) == data.get_data_length());

			status = m_aes.encrypt_block(
				data.get_data(),
				B_tmp_buffer,
				data.get_data_length());
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_EAP_AM_CRYPTO,
				(EAPL("  Enc B_tmp_buffer"),
				 B_tmp_buffer,
				 sizeof(B_tmp_buffer)));

			u64_t counter = m_am_tools->multiply_u64(n_block_count, j_ind) + i_ind;

			A_integrity_reg = eap_htonll(
				m_am_tools->xor_u64(
					eap_ntohll(*B_tmp_buffer),
					counter));

			m_am_tools->memmove(Ri_reg, B_tmp_buffer+1, sizeof(u64_t));
		}
	}

	/*
	  3) Output the results.

	  Set C[0] = A
	  For i = 1 to n
	      C[i] = R[i]
	*/
	
	u8_t * const C = static_cast<u8_t *>(data_out);

	m_am_tools->memmove(C, &A_integrity_reg, EAP_CRYPTO_AES_WRAP_BLOCK_SIZE);

	for (u32_t i_ind = 1ul; i_ind <= n_block_count; i_ind++)
	{
		u32_t offset = static_cast<u32_t>(i_ind)*static_cast<u32_t>(EAP_CRYPTO_AES_WRAP_BLOCK_SIZE);

		u8_t * const Ri_reg = Register.get_data_offset(
			static_cast<u32_t>((i_ind-1ul))*static_cast<u32_t>(EAP_CRYPTO_AES_WRAP_BLOCK_SIZE),
			static_cast<u32_t>(EAP_CRYPTO_AES_WRAP_BLOCK_SIZE));
		if (Ri_reg == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		m_am_tools->memmove((C + offset), Ri_reg, EAP_CRYPTO_AES_WRAP_BLOCK_SIZE);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("encrypted data"),
		 data_out,
		 data_out_length));

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);

#else // !defined(DISABLE_CRYPTO_AES_WRAP)
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
#endif

}

EAP_FUNC_EXPORT eap_status_e crypto_aes_wrap_c::decrypt_block(
	const void * const data_in,
	const u32_t data_in_length,
	void * const data_out,
	const u32_t data_out_length)
{
#if !defined(DISABLE_CRYPTO_AES_WRAP)
	/*
	  Inputs:  Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}, and
	           Key, K (the KEK).
	  Outputs: Plaintext, n 64-bit values {P0, P1, K, Pn}.
	*/
	if (data_in == 0
		|| data_out == 0
		|| (data_in_length % get_block_size()) != 0
		|| data_out_length < data_in_length-get_block_size())
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("encrypted data"),
		 data_in,
		 data_in_length));

	/*
	  1) Initialize variables.

	  Set A = C[0]
	  For i = 1 to n
	      R[i] = C[i]
	*/
	u64_t A_integrity_reg(0ul);
	const u8_t * const cipher_text = static_cast<const u8_t *>(data_in);

	m_am_tools->memmove(&A_integrity_reg, cipher_text, EAP_CRYPTO_AES_WRAP_BLOCK_SIZE);

	eap_variable_data_c Register(m_am_tools);

	eap_status_e status = Register.set_copy_of_buffer(
		(cipher_text + static_cast<u32_t>(EAP_CRYPTO_AES_WRAP_BLOCK_SIZE)),
		data_in_length - static_cast<u32_t>(EAP_CRYPTO_AES_WRAP_BLOCK_SIZE));
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	/*
	  2) Compute intermediate values.

	  For j = 5 to 0
	      For i = n to 1
		      B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
			  A = MSB(64, B)
			  R[i] = LSB(64, B)
	*/

	u64_t n_block_count = Register.get_data_length() / 8ul;
	u64_t B_tmp_buffer[2];
	eap_variable_data_c data(m_am_tools);

	status = data.set_buffer_length(sizeof(A_integrity_reg) + EAP_CRYPTO_AES_WRAP_BLOCK_SIZE);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u64_t j_ind(5ul);

	for(;;)
	{
		for (u64_t i_ind = n_block_count; i_ind >= 1; i_ind--)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_EAP_AM_CRYPTO,
				(EAPL("\n")));

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_EAP_AM_CRYPTO,
				(EAPL("crypto_aes_wrap_c::decrypt_block(): j_ind %d, i_ind %d\n"),
				 j_ind,
				 i_ind));

			eap_status_e status = m_aes.set_decryption_key(
				m_key.get_data(),
				m_key.get_data_length());
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			u64_t counter = m_am_tools->multiply_u64(n_block_count, j_ind) + i_ind;

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_EAP_AM_CRYPTO,
				(EAPL("In A_integrity_reg"),
				 &A_integrity_reg,
				 sizeof(A_integrity_reg)));

			A_integrity_reg = eap_htonll(
				m_am_tools->xor_u64(
					eap_ntohll(A_integrity_reg),
					counter));

			status = data.set_copy_of_buffer(&A_integrity_reg, sizeof(A_integrity_reg));
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			u8_t * const Ri_reg = Register.get_data_offset(
				static_cast<u32_t>((i_ind-1ul))*static_cast<u32_t>(EAP_CRYPTO_AES_WRAP_BLOCK_SIZE),
				static_cast<u32_t>(EAP_CRYPTO_AES_WRAP_BLOCK_SIZE));
			if (Ri_reg == 0)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_EAP_AM_CRYPTO,
				(EAPL("         In Ri_reg"),
				 Ri_reg,
				 EAP_CRYPTO_AES_WRAP_BLOCK_SIZE));

			status = data.add_data(Ri_reg, EAP_CRYPTO_AES_WRAP_BLOCK_SIZE);
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_ASSERT_TOOLS(m_am_tools, sizeof(B_tmp_buffer) == data.get_data_length());

			status = m_aes.decrypt_block(
				data.get_data(),
				B_tmp_buffer,
				data.get_data_length());
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_EAP_AM_CRYPTO,
				(EAPL("  Dec B_tmp_buffer"),
				 B_tmp_buffer,
				 sizeof(B_tmp_buffer)));

			A_integrity_reg = *B_tmp_buffer;

			m_am_tools->memmove(Ri_reg, B_tmp_buffer+1, sizeof(u64_t));
		}
		
		if (j_ind == 0)
		{
			// Terminates the loop.
			break;
		}

		// Decrementation must be after the termination test,
		// because we need to run the loop also with j_ind value 0.
		--j_ind;
	}

	/*
	  3) Output results.

	  If A is an appropriate initial value (see 2.2.3),
	  Then
	      For i = 1 to n
	          P[i] = R[i]
	  Else
	      Return an error
	*/

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("plain data"),
		 Register.get_data(),
		 Register.get_data_length()));

	if (m_am_tools->memcmp(&A_integrity_reg, EAP_CRYPTO_AES_WRAP_DEFAULT_INITIAL_IV, sizeof(A_integrity_reg)) == 0)
	{
		// OK
		m_am_tools->memmove(data_out, Register.get_data(), Register.get_data_length());

		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_authentication_failure);
	}

#else // !defined(DISABLE_CRYPTO_AES_WRAP)

	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);

#endif

}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_random_c::~crypto_random_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_random_c::crypto_random_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(false)
{
	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_random_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_random_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_random_c::get_rand_bytes(
	void * const buffer,
	const u32_t count)
{
	return m_am_tools->get_crypto()->get_rand_bytes(
		static_cast<u8_t *>(buffer), count);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_random_c::get_rand_bytes(
	eap_variable_data_c * const buffer,
	const u32_t count)
{
	if (buffer == 0
		|| buffer->get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = buffer->init(count);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = buffer->set_data_length(count);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = get_rand_bytes(
		buffer->get_data(),
		buffer->get_data_length());
	if (status != eap_status_ok)
	{
		buffer->reset();
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_random_c::get_rand_integer(
	const u32_t minimum,
	const u32_t maximum)
{
	const u32_t MAX_U32 = ~(static_cast<u32_t>(0ul));

	u32_t random = 0ul;

	if ((maximum - minimum) == MAX_U32 )
	{
		eap_status_e status = get_rand_bytes(&random, sizeof(random));
		if (status != eap_status_ok)
		{
			return 0;
		}
	}
	else
	{
		u32_t frame = ((maximum+1)-minimum);
		u32_t randomized = 0;
		u32_t max_value = MAX_U32 - (MAX_U32 % frame);

		do
		{
			eap_status_e status = get_rand_bytes(&randomized, sizeof(randomized));
			if (status != eap_status_ok)
			{
				return 0;
			}
		}
		while(randomized >= max_value);
		
		random = ((randomized % frame) + minimum);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("RANDOM u32_t %lu\n"),
		 random));
	
	return random;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_random_c::add_rand_seed(
	const void * const buffer,
	const u32_t count)
{
	return m_am_tools->get_crypto()->add_rand_seed(
		static_cast<const u8_t *>(buffer), count);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_random_c::add_rand_seed_hw_ticks()
{
	return m_am_tools->get_crypto()->add_rand_seed_hw_ticks();
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_sha_256_c::~crypto_sha_256_c()
{
	hash_cleanup();
	m_sha_256_context.reset();
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_sha_256_c::crypto_sha_256_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_sha_256_context(tools)
	, m_is_valid(false)
{
	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_sha_256_c::copy_context(
	const eap_variable_data_c * const sha_256_context)
{
	if (sha_256_context == 0
		|| sha_256_context->get_is_valid_data() == false)
	{
		set_is_invalid();
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = m_am_tools->get_crypto()->sha_256_copy_context(
		&m_sha_256_context,
		sha_256_context);
	if (status != eap_status_ok)
	{
		set_is_invalid();
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_sha_256_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_sha_256_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_sha_256_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_sha_256_c::get_digest_length()
{
	// This is simple optimization.
	return EAP_CRYPTO_API_SHA_256_DIGEST_BUFFER_BYTE_SIZE;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_sha_256_c::get_block_size()
{
	// This is simple optimization.
	return EAP_CRYPTO_API_SHA_256_BLOCK_BYTE_SIZE;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_sha_256_c::hash_init()
{
	eap_status_e status = m_am_tools->get_crypto()->sha_256_init(&m_sha_256_context);
	if (m_sha_256_context.get_is_valid_data() == false)
	{
		set_is_invalid();
		if (status == eap_status_ok)
		{
			status = eap_status_allocation_error;
		}
	}
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_sha_256_c::hash_update(
	const void * const data,
	const u32_t data_length)
{
	eap_status_e status = m_am_tools->get_crypto()->sha_256_update(
		&m_sha_256_context,
		static_cast<const u8_t *>(data),
		data_length);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_sha_256_c::hash_final(
	void * const message_digest,
	u32_t *md_length_or_null)
{
	eap_status_e status = m_am_tools->get_crypto()->sha_256_final(
		&m_sha_256_context,
		static_cast<u8_t *>(message_digest),
		md_length_or_null);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_sha_256_c::hash_cleanup()
{
	if (m_sha_256_context.get_is_valid_data() == true)
	{
		m_am_tools->get_crypto()->sha_256_cleanup(&m_sha_256_context);
	}
	
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT abs_crypto_hash_algorithm_c * crypto_sha_256_c::copy()
{
	crypto_sha_256_c * const new_context = new crypto_sha_256_c(m_am_tools);
	if (new_context == 0)
	{
		return 0;
	}

	eap_status_e status = new_context->copy_context(&m_sha_256_context);
	if (status != eap_status_ok)
	{
		delete new_context;
		return 0;
	}

	return new_context;
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_sha1_c::~crypto_sha1_c()
{
	hash_cleanup();
	m_sha1_context.reset();
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_sha1_c::crypto_sha1_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_sha1_context(tools)
	, m_is_valid(false)
{
	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_sha1_c::copy_context(
	const eap_variable_data_c * const sha1_context)
{
	if (sha1_context == 0
		|| sha1_context->get_is_valid_data() == false)
	{
		set_is_invalid();
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = m_am_tools->get_crypto()->sha1_copy_context(
		&m_sha1_context,
		sha1_context);
	if (status != eap_status_ok)
	{
		set_is_invalid();
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_sha1_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_sha1_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_sha1_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_sha1_c::get_digest_length()
{
	// This is simple optimization.
	return EAP_CRYPTO_API_SHA1_DIGEST_BUFFER_BYTE_SIZE;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_sha1_c::get_block_size()
{
	// This is simple optimization.
	return EAP_CRYPTO_API_SHA1_BLOCK_BYTE_SIZE;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_sha1_c::hash_init()
{
	eap_status_e status = m_am_tools->get_crypto()->sha1_init(&m_sha1_context);
	if (m_sha1_context.get_is_valid_data() == false)
	{
		set_is_invalid();
		if (status == eap_status_ok)
		{
			status = eap_status_allocation_error;
		}
	}
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_sha1_c::hash_update(
	const void * const data,
	const u32_t data_length)
{
	eap_status_e status = m_am_tools->get_crypto()->sha1_update(
		&m_sha1_context,
		static_cast<const u8_t *>(data),
		data_length);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_sha1_c::hash_final(
	void * const message_digest,
	u32_t *md_length_or_null)
{
	eap_status_e status = m_am_tools->get_crypto()->sha1_final(
		&m_sha1_context,
		static_cast<u8_t *>(message_digest),
		md_length_or_null);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_sha1_c::hash_cleanup()
{
	if (m_sha1_context.get_is_valid_data() == true)
	{
		m_am_tools->get_crypto()->sha1_cleanup(&m_sha1_context);
	}
	
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT abs_crypto_hash_algorithm_c * crypto_sha1_c::copy()
{
	crypto_sha1_c * const new_context = new crypto_sha1_c(m_am_tools);
	if (new_context == 0)
	{
		return 0;
	}

	eap_status_e status = new_context->copy_context(&m_sha1_context);
	if (status != eap_status_ok)
	{
		delete new_context;
		return 0;
	}

	return new_context;
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT
crypto_ephemeral_diffie_hellman_c::~crypto_ephemeral_diffie_hellman_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT
crypto_ephemeral_diffie_hellman_c::crypto_ephemeral_diffie_hellman_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(false)
{
	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_ephemeral_diffie_hellman_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_ephemeral_diffie_hellman_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e
crypto_ephemeral_diffie_hellman_c::generate_diffie_hellman_keys(
	eap_variable_data_c * const own_private_dh_key,
	eap_variable_data_c * const own_public_dh_key,
	const void * const prime,
	const u32_t prime_length,
	const void * const group_generator,
	const u32_t group_generator_length)
{
	return m_am_tools->get_crypto()->generate_diffie_hellman_keys(
		own_private_dh_key,
		own_public_dh_key,
		static_cast<const u8_t *>(prime),
		prime_length,
		static_cast<const u8_t *>(group_generator),
		group_generator_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e
crypto_ephemeral_diffie_hellman_c::generate_g_power_to_xy(
	const eap_variable_data_c * const own_private_dh_key,
	const eap_variable_data_c * const peer_public_dh_key,
	eap_variable_data_c * const shared_dh_key,
	const void * const prime,
	const u32_t prime_length,
	const void * const group_generator,
	const u32_t group_generator_length)
{
	return m_am_tools->get_crypto()->generate_g_power_to_xy(
		own_private_dh_key,
		peer_public_dh_key,
		shared_dh_key,
		static_cast<const u8_t *>(prime),
		prime_length,
		static_cast<const u8_t *>(group_generator),
		group_generator_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e
crypto_ephemeral_diffie_hellman_c::dh_cleanup(
	const eap_variable_data_c * const dh_context)
{
	return m_am_tools->get_crypto()->dh_cleanup(
		dh_context);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_md5_c::~crypto_md5_c()
{
	hash_cleanup();
	m_md5_context.reset();
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_md5_c::crypto_md5_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_md5_context(tools)
	, m_is_valid(false)
{
	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_md5_c::copy_context(
	const eap_variable_data_c * const md5_context)
{
	if (md5_context == 0
		|| md5_context->get_is_valid_data() == false)
	{
		set_is_invalid();
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = m_am_tools->get_crypto()->md5_copy_context(
		&m_md5_context,
		md5_context);
	if (status != eap_status_ok)
	{
		set_is_invalid();
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_md5_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_md5_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_md5_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_md5_c::get_digest_length()
{
	return m_am_tools->get_crypto()->get_md5_digest_length(&m_md5_context);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_md5_c::get_block_size()
{
	return m_am_tools->get_crypto()->get_md5_block_size(&m_md5_context);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_md5_c::hash_init()
{
	eap_status_e status = m_am_tools->get_crypto()->md5_init(&m_md5_context);

	if (m_md5_context.get_is_valid_data() == false)
	{
		set_is_invalid();
		if (status == eap_status_ok)
		{
			status = eap_status_allocation_error;
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_md5_c::hash_update(
	const void * const data,
	const u32_t data_length)
{
	eap_status_e status = m_am_tools->get_crypto()->md5_update(
		&m_md5_context,
		static_cast<const u8_t *>(data),
		data_length);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_md5_c::hash_final(
	void * const message_digest,
	u32_t *md_length_or_null)
{
	eap_status_e status = m_am_tools->get_crypto()->md5_final(
		&m_md5_context,
		static_cast<u8_t *>(message_digest),
		md_length_or_null);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_md5_c::hash_cleanup()
{
	if (m_md5_context.get_is_valid_data() == true)
	{
		m_am_tools->get_crypto()->md5_cleanup(&m_md5_context);
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT abs_crypto_hash_algorithm_c * crypto_md5_c::copy()
{
	crypto_md5_c * const new_context = new crypto_md5_c(m_am_tools);
	if (new_context == 0)
	{
		return 0;
	}

	eap_status_e status = new_context->copy_context(&m_md5_context);
	if (status != eap_status_ok)
	{
		delete new_context;
		return 0;
	}

	return new_context;
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_md4_c::~crypto_md4_c()
{
	hash_cleanup();
	m_md4_context.reset();
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_md4_c::crypto_md4_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_md4_context(tools)
	, m_is_valid(false)
{
	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_md4_c::copy_context(
	const eap_variable_data_c * const md4_context)
{
	if (md4_context == 0
		|| md4_context->get_is_valid_data() == false)
	{
		set_is_invalid();
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = m_am_tools->get_crypto()->md4_copy_context(
		&m_md4_context,
		md4_context);
	if (status != eap_status_ok)
	{
		set_is_invalid();
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_md4_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_md4_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_md4_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_md4_c::get_digest_length()
{
	return m_am_tools->get_crypto()->get_md4_digest_length(&m_md4_context);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t crypto_md4_c::get_block_size()
{
	return m_am_tools->get_crypto()->get_md4_block_size(&m_md4_context);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_md4_c::hash_init()
{
	// Cleanup the previous context.
	hash_cleanup();

	eap_status_e status = m_am_tools->get_crypto()->md4_init(&m_md4_context);

	if (m_md4_context.get_is_valid_data() == false)
	{
		set_is_invalid();
		if (status == eap_status_ok)
		{
			status = eap_status_allocation_error;
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_md4_c::hash_update(
	const void * const data,
	const u32_t data_length)
{
	eap_status_e status = m_am_tools->get_crypto()->md4_update(
		&m_md4_context,
		static_cast<const u8_t *>(data),
		data_length);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_md4_c::hash_final(
	void * const message_digest,
	u32_t *md_length_or_null)
{
	eap_status_e status = m_am_tools->get_crypto()->md4_final(
		&m_md4_context,
		static_cast<u8_t *>(message_digest),
		md_length_or_null);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_md4_c::hash_cleanup()
{
	if (m_md4_context.get_is_valid_data() == true)
	{
		m_am_tools->get_crypto()->md4_cleanup(&m_md4_context);
	}
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT abs_crypto_hash_algorithm_c * crypto_md4_c::copy()
{
	crypto_md4_c * const new_context = new crypto_md4_c(m_am_tools);
	if (new_context == 0)
	{
		return 0;
	}

	eap_status_e status = new_context->copy_context(&m_md4_context);
	if (status != eap_status_ok)
	{
		delete new_context;
		return 0;
	}

	return new_context;
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_rc4_c::~crypto_rc4_c()
{
	if (m_rc4_context.get_is_valid_data() == true)
	{
		m_am_tools->get_crypto()->rc4_cleanup(&m_rc4_context);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_rc4_c::crypto_rc4_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_rc4_context(tools)
	, m_is_valid(false)
{
	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_rc4_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_rc4_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_rc4_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rc4_c::set_key(
	const eap_variable_data_c * const key)
{
	return m_am_tools->get_crypto()->rc4_set_key(&m_rc4_context, key);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rc4_c::discard_stream(
	const u32_t count_of_discarded_octets)
{
	eap_status_e status = eap_status_ok;

	for (u32_t ind = 0ul; ind < count_of_discarded_octets; ind++)
	{
		u8_t octet = 0;
		status = encrypt_data(
			&octet,
			sizeof(octet));
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	} // for()

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rc4_c::encrypt_data(
	void * const data_in_out,
	const u32_t data_length)
{
	return m_am_tools->get_crypto()->rc4_encrypt(
		&m_rc4_context,
		data_in_out,
		data_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rc4_c::encrypt_data(
	const void * const data_in, 
	void * const data_out,
	const u32_t data_length)
{
	return m_am_tools->get_crypto()->rc4_encrypt(
		&m_rc4_context,
		data_in,
		data_out,
		data_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rc4_c::decrypt_data(
	void * const data_in_out,
	const u32_t data_length)
{
	return m_am_tools->get_crypto()->rc4_decrypt(
		&m_rc4_context,
		data_in_out,
		data_length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rc4_c::decrypt_data(
	const void * const data_in, 
	void * const data_out,
	const u32_t data_length)
{
	return m_am_tools->get_crypto()->rc4_decrypt(
		&m_rc4_context,
		data_in,
		data_out,
		data_length);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_tls_base_prf_c::~crypto_tls_base_prf_c()
{
	tls_prf_cleanup();
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_tls_base_prf_c::crypto_tls_base_prf_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(false)
{
	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_tls_base_prf_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_tls_base_prf_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_tls_base_prf_c::get_is_valid()
{
	return 	m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_tls_base_prf_c::tls_prf_A_value(
	abs_crypto_hmac_algorithm_c * const hash,
	eap_variable_data_c * const key,
	eap_variable_data_c * const seed,
	eap_variable_data_c * const A_output)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (hash == 0
		|| key == 0
		|| seed == 0
		|| A_output == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// First we initialize A value.

	eap_status_e status = hash->hmac_set_key(key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = hash->hmac_update(
		seed->get_data(seed->get_data_length()),
		seed->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t hmac_md_length = hash->get_digest_length();

	status = hash->hmac_final(
		A_output->get_data(hmac_md_length),
		&hmac_md_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_tls_base_prf_c::tls_prf_one_round(
	abs_crypto_hmac_algorithm_c * const hash,
	const eap_variable_data_c * const key,
	eap_variable_data_c * const A_input,
	eap_variable_data_c * const seed,
	void * const out_buffer,
	const u32_t out_buffer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (hash == 0
		|| key == 0
		|| A_input == 0
		|| seed == 0
		|| out_buffer == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = hash->hmac_set_key(key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = hash->hmac_update(
		A_input->get_data(A_input->get_data_length()),
		A_input->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = hash->hmac_update(
		seed->get_data(seed->get_data_length()),
		seed->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	u32_t hmac_md_length = hash->get_digest_length();

	if (hmac_md_length > out_buffer_length)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
	}

	status = hash->hmac_final(
		out_buffer,
		&hmac_md_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_tls_base_prf_c::tls_prf_cleanup()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_tls_sha1_prf_c::~crypto_tls_sha1_prf_c()
{
	tls_prf_cleanup();

	delete m_sha1_context;
	m_sha1_context = 0;

	delete m_A_sha1_context;
	m_A_sha1_context = 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_tls_sha1_prf_c::crypto_tls_sha1_prf_c(
	abs_eap_am_tools_c * const tools)
	: crypto_tls_base_prf_c(tools)
	, m_am_tools(tools)
	, m_sha1_context(0)
	, m_A_sha1_context(0)
	, m_sha1_key(tools)
	, m_seed(tools)
	, m_is_valid(false)
{
	{
		crypto_sha1_c * sha1 = new crypto_sha1_c(m_am_tools);
		if (sha1 == 0
			|| sha1->get_is_valid() == false)
		{
			delete sha1;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}

		m_sha1_context = new crypto_hmac_c(m_am_tools, sha1, true);
		if (m_sha1_context == 0
			|| m_sha1_context->get_is_valid() == false)
		{
			delete m_sha1_context;
			m_sha1_context = 0;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}
	}

	{
		crypto_sha1_c * sha1 = new crypto_sha1_c(m_am_tools);
		if (sha1 == 0
			|| sha1->get_is_valid() == false)
		{
			delete sha1;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}

		m_A_sha1_context = new crypto_hmac_c(m_am_tools, sha1, true);
		if (m_A_sha1_context == 0
			|| m_A_sha1_context->get_is_valid() == false)
		{
			delete m_A_sha1_context;
			m_A_sha1_context = 0;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}
	}

	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_tls_sha1_prf_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_tls_sha1_prf_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_tls_sha1_prf_c::get_is_valid()
{
	return 	m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_tls_sha1_prf_c::tls_prf_init(
	const eap_variable_data_c * const secret,
	const eap_variable_data_c * const label,
	const eap_variable_data_c * const seed)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (secret->get_is_valid_data() == false
		|| secret->get_data_length() == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (label->get_is_valid_data() == false
		|| label->get_data_length() == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// NOTE seed could be empty buffer.
	if (seed->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c input(m_am_tools);

	eap_status_e status = input.add_data(label);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = input.add_data(seed);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_seed.set_copy_of_buffer(&input);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("tls_prf_init(): m_seed"),
		m_seed.get_data(m_seed.get_data_length()),
		m_seed.get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_sha1_key.set_copy_of_buffer(
		secret);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("tls_prf_init(): m_sha1_key"),
		m_sha1_key.get_data(m_sha1_key.get_data_length()),
		m_sha1_key.get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_tls_sha1_prf_c::tls_prf_output(
	void * const pseudo_random_data,
	const u32_t pseudo_random_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (pseudo_random_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = eap_status_not_supported;

	EAP_ASSERT_ALWAYS(get_is_valid() == true);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_A_sha1_context->hmac_set_key(&m_sha1_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = m_sha1_context->hmac_set_key(&m_sha1_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c A_sha1_output(m_am_tools);

	status = A_sha1_output.init(m_A_sha1_context->get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	A_sha1_output.set_is_valid();
	A_sha1_output.set_data_length(A_sha1_output.get_buffer_length());

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c sha1_output(m_am_tools);

	status = sha1_output.init(
		pseudo_random_data_length+m_sha1_context->get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	sha1_output.set_is_valid();
	sha1_output.set_data_length(sha1_output.get_buffer_length());

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		u32_t hmac_sha1_md_length = m_sha1_context->get_digest_length();
		u32_t sha1_count = sha1_output.get_data_length()
			/ m_sha1_context->get_digest_length();

		// First we initialize A value:
		// A(0) = seed
		status = tls_prf_A_value(
			m_A_sha1_context,
			&m_sha1_key,
			&m_seed,
			&A_sha1_output);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// out(1) = HMAC_hash(secret, A(1) + seed)
		status = tls_prf_one_round(
			m_sha1_context,
			&m_sha1_key,
			&A_sha1_output,
			&m_seed,
			sha1_output.get_data_offset(0ul, hmac_sha1_md_length),
			hmac_sha1_md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		for (u32_t ind = 1ul; ind < sha1_count; ind++)
		{
			// Next A value is:
			// A(i) = HMAC_hash(secret, A(i-1)).
			status = tls_prf_A_value(
				m_A_sha1_context,
				&m_sha1_key,
				&A_sha1_output,
				&A_sha1_output);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// out(i) = HMAC_hash(secret, A(i) + seed)
			status = tls_prf_one_round(
				m_sha1_context,
				&m_sha1_key,
				&A_sha1_output,
				&m_seed,
				sha1_output.get_data_offset(
					ind*hmac_sha1_md_length,
					hmac_sha1_md_length),
				hmac_sha1_md_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		} // for()
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Final operation is copy sha1_output to output buffer.

	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAP_AM_CRYPTO,
			(EAPL("crypto_tls_sha1_prf_c::tls_prf_output(): sha1_output"),
			 sha1_output.get_data(pseudo_random_data_length),
			 pseudo_random_data_length));

		EAP_ASSERT(pseudo_random_data_length <= sha1_output.get_data_length());

		const u8_t * const sha1_buffer = sha1_output.get_data(
			pseudo_random_data_length);
		if (sha1_buffer == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u8_t * const p_pseudo_random_data
			= static_cast<u8_t *>(pseudo_random_data);

		m_am_tools->memmove(
			p_pseudo_random_data,
			sha1_buffer,
			pseudo_random_data_length);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAP_AM_CRYPTO,
			(EAPL("crypto_tls_sha1_prf_c::tls_prf_output(): ")
			 EAPL("p_pseudo_random_data"),
			 p_pseudo_random_data,
			 pseudo_random_data_length));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_tls_sha1_prf_c::tls_prf_cleanup()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_sha1_context != 0)
	{
		m_sha1_context->hmac_cleanup();
	}

	if (m_A_sha1_context != 0)
	{
		m_A_sha1_context->hmac_cleanup();
	}

	m_sha1_key.reset();
	m_seed.reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_tls_md5_prf_c::~crypto_tls_md5_prf_c()
{
	tls_prf_cleanup();

	delete m_md5_context;
	m_md5_context = 0;

	delete m_A_md5_context;
	m_A_md5_context = 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_tls_md5_prf_c::crypto_tls_md5_prf_c(
	abs_eap_am_tools_c * const tools)
	: crypto_tls_base_prf_c(tools)
	, m_am_tools(tools)
	, m_md5_context(0)
	, m_A_md5_context(0)
	, m_md5_key(tools)
	, m_seed(tools)
	, m_is_valid(false)
{
	{
		crypto_md5_c * md5 = new crypto_md5_c(m_am_tools);
		if (md5 == 0
			|| md5->get_is_valid() == false)
		{
			delete md5;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}

		m_md5_context = new crypto_hmac_c(m_am_tools, md5, true);
		if (m_md5_context == 0
			|| m_md5_context->get_is_valid() == false)
		{
			delete m_md5_context;
			m_md5_context = 0;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}
	}

	{
		crypto_md5_c * md5 = new crypto_md5_c(m_am_tools);
		if (md5 == 0
			|| md5->get_is_valid() == false)
		{
			delete md5;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}

		m_A_md5_context = new crypto_hmac_c(m_am_tools, md5, true);
		if (m_A_md5_context == 0
			|| m_A_md5_context->get_is_valid() == false)
		{
			delete m_A_md5_context;
			m_A_md5_context = 0;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}
	}

	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_tls_md5_prf_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_tls_md5_prf_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_tls_md5_prf_c::get_is_valid()
{
	return 	m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_tls_md5_prf_c::tls_prf_init(
	const eap_variable_data_c * const secret,
	const eap_variable_data_c * const label,
	const eap_variable_data_c * const seed)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (secret->get_is_valid_data() == false
		|| secret->get_data_length() == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (label->get_is_valid_data() == false
		|| label->get_data_length() == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (seed->get_is_valid_data() == false
		|| seed->get_data_length() == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c input(m_am_tools);

	eap_status_e status = input.add_data(label);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = input.add_data(seed);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_seed.set_copy_of_buffer(&input);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("tls_prf_init(): m_seed"),
		 m_seed.get_data(m_seed.get_data_length()),
		 m_seed.get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_md5_key.set_copy_of_buffer(
		secret);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("tls_prf_init(): m_md5_key"),
		 m_md5_key.get_data(m_md5_key.get_data_length()),
		 m_md5_key.get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_tls_md5_prf_c::tls_prf_output(
	void * const pseudo_random_data,
	const u32_t pseudo_random_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (pseudo_random_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = eap_status_not_supported;

	EAP_ASSERT_ALWAYS(get_is_valid() == true);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_A_md5_context->hmac_set_key(&m_md5_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = m_md5_context->hmac_set_key(&m_md5_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c A_md5_output(m_am_tools);

	status = A_md5_output.init(m_A_md5_context->get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	A_md5_output.set_is_valid();
	A_md5_output.set_data_length(A_md5_output.get_buffer_length());

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c md5_output(m_am_tools);

	status = md5_output.init(
		pseudo_random_data_length+m_md5_context->get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	md5_output.set_is_valid();
	md5_output.set_data_length(md5_output.get_buffer_length());

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		u32_t hmac_md5_md_length = m_md5_context->get_digest_length();
		u32_t md5_count = md5_output.get_data_length()
			/ m_md5_context->get_digest_length();

		// First we initialize A value:
		// A(0) = seed
		status = tls_prf_A_value(
			m_A_md5_context,
			&m_md5_key,
			&m_seed,
			&A_md5_output);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// out(1) = HMAC_hash(secret, A(1) + seed)
		status = tls_prf_one_round(
			m_md5_context,
			&m_md5_key,
			&A_md5_output,
			&m_seed,
			md5_output.get_data_offset(0ul, hmac_md5_md_length),
			hmac_md5_md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		for (u32_t ind = 1ul; ind < md5_count; ind++)
		{
			// Next A value is:
			// A(i) = HMAC_hash(secret, A(i-1)).
			status = tls_prf_A_value(
				m_A_md5_context,
				&m_md5_key,
				&A_md5_output,
				&A_md5_output);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// out(i) = HMAC_hash(secret, A(i) + seed)
			status = tls_prf_one_round(
				m_md5_context,
				&m_md5_key,
				&A_md5_output,
				&m_seed,
				md5_output.get_data_offset(
					ind*hmac_md5_md_length,
					hmac_md5_md_length),
				hmac_md5_md_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		} // for()
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Final operation is copy md5_output to output buffer.

	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAP_AM_CRYPTO,
			(EAPL("crypto_tls_md5_prf_c::tls_prf_output(): md5_output"),
			 md5_output.get_data(pseudo_random_data_length),
			 pseudo_random_data_length));

		EAP_ASSERT(pseudo_random_data_length <= md5_output.get_data_length());

		const u8_t * const md5_buffer
			= md5_output.get_data(pseudo_random_data_length);
		if (md5_buffer == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u8_t * const p_pseudo_random_data
			= static_cast<u8_t *>(pseudo_random_data);

		m_am_tools->memmove(
			p_pseudo_random_data,
			md5_buffer,
			pseudo_random_data_length);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAP_AM_CRYPTO,
			(EAPL("crypto_tls_md5_prf_c::tls_prf_output(): ")
			 EAPL("p_pseudo_random_data"),
			 p_pseudo_random_data,
			 pseudo_random_data_length));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_tls_md5_prf_c::tls_prf_cleanup()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_md5_context != 0)
	{
		m_md5_context->hmac_cleanup();
	}

	if (m_A_md5_context != 0)
	{
		m_A_md5_context->hmac_cleanup();
	}

	m_md5_key.reset();
	m_seed.reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_tls_prf_c::~crypto_tls_prf_c()
{
	tls_prf_cleanup();

	delete m_tls_md5_prf;
	m_tls_md5_prf = 0;

	delete m_tls_sha1_prf;
	m_tls_sha1_prf = 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_tls_prf_c::crypto_tls_prf_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_tls_md5_prf(0)
	, m_tls_sha1_prf(0)
	, m_is_valid(false)
{
	m_tls_md5_prf = new crypto_tls_md5_prf_c(tools);
	if (m_tls_md5_prf == 0)
	{
		return;
	}

	m_tls_sha1_prf = new crypto_tls_sha1_prf_c(tools);
	if (m_tls_sha1_prf == 0)
	{
		return;
	}

	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_tls_prf_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_tls_prf_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_tls_prf_c::get_is_valid()
{
	return 	m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_tls_prf_c::tls_prf_init(
	const eap_variable_data_c * const secret,
	const eap_variable_data_c * const label,
	const eap_variable_data_c * const seed)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_tls_md5_prf == 0
		|| m_tls_sha1_prf == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (secret->get_is_valid_data() == false
		|| secret->get_data_length() == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (label->get_is_valid_data() == false
		|| label->get_data_length() == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (seed->get_is_valid_data() == false
		|| seed->get_data_length() == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	bool is_odd_key = false;
	if ((secret->get_data_length() % 2) != 0)
	{
		// Odd length, one byte will be shared with both keys.
		is_odd_key = true;
	}

	u32_t key_length = secret->get_data_length() / 2ul;
	u32_t sha1_key_offset = key_length;

	if (is_odd_key == true)
	{
		++key_length;
	}

	eap_variable_data_c md5_secret(m_am_tools);
	eap_variable_data_c sha1_secret(m_am_tools);

	eap_status_e status = md5_secret.set_buffer(
		secret->get_data_offset(0ul, key_length),
		key_length,
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1_secret.set_buffer(
		secret->get_data_offset(sha1_key_offset, key_length),
		key_length,
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = m_tls_md5_prf->tls_prf_init(&md5_secret, label, seed);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_tls_sha1_prf->tls_prf_init(&sha1_secret, label, seed);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_tls_prf_c::tls_prf_output(
	void * const pseudo_random_data,
	const u32_t pseudo_random_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_not_supported;

	EAP_ASSERT_ALWAYS(get_is_valid() == true);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c tls_md5_prf_output(m_am_tools);
	eap_variable_data_c tls_sha1_prf_output(m_am_tools);


	status = tls_md5_prf_output.init(pseudo_random_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	tls_md5_prf_output.set_is_valid();
	tls_md5_prf_output.set_data_length(tls_md5_prf_output.get_buffer_length());

	status = tls_sha1_prf_output.init(pseudo_random_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	tls_sha1_prf_output.set_is_valid();
	tls_sha1_prf_output.set_data_length(
		tls_sha1_prf_output.get_buffer_length());


	status = m_tls_md5_prf->tls_prf_output(
		tls_md5_prf_output.get_data(tls_md5_prf_output.get_data_length()),
		tls_md5_prf_output.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = m_tls_sha1_prf->tls_prf_output(
		tls_sha1_prf_output.get_data(tls_sha1_prf_output.get_data_length()),
		tls_sha1_prf_output.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Final operation is XOR the md5_output and sha1_output.

	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAP_AM_CRYPTO,
			(EAPL("tls_prf_init(): tls_md5_prf_output"),
			 tls_md5_prf_output.get_data(tls_md5_prf_output.get_data_length()),
			 tls_md5_prf_output.get_data_length()));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAP_AM_CRYPTO,
			(EAPL("tls_prf_init(): tls_sha1_prf_output"),
			 tls_sha1_prf_output.get_data(
				 tls_sha1_prf_output.get_data_length()),
			 tls_sha1_prf_output.get_data_length()));

		EAP_ASSERT(
			pseudo_random_data_length
			<= tls_md5_prf_output.get_data_length());
		EAP_ASSERT(
			pseudo_random_data_length
			<= tls_sha1_prf_output.get_data_length());

		const u8_t * const md5_buffer
			= tls_md5_prf_output.get_data(pseudo_random_data_length);
		const u8_t * const sha1_buffer
			= tls_sha1_prf_output.get_data(pseudo_random_data_length);
		u8_t * const p_pseudo_random_data
			= static_cast<u8_t *>(pseudo_random_data);

		for (u32_t ind = 0u; ind < pseudo_random_data_length; ind++)
		{
			p_pseudo_random_data[ind]
				= static_cast<u8_t>((md5_buffer[ind] ^ sha1_buffer[ind]));
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAP_AM_CRYPTO,
			(EAPL("tls_prf_init(): p_pseudo_random_data"),
			 p_pseudo_random_data,
			 pseudo_random_data_length));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_tls_prf_c::tls_prf_cleanup()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_tls_md5_prf != 0)
	{
		m_tls_md5_prf->tls_prf_cleanup();
	}

	if (m_tls_sha1_prf != 0)
	{
		m_tls_sha1_prf->tls_prf_cleanup();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------


EAP_FUNC_EXPORT crypto_eap_fast_hmac_sha1_prf_c::~crypto_eap_fast_hmac_sha1_prf_c()
{
	t_prf_cleanup();

	delete m_context;
	m_context = 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_eap_fast_hmac_sha1_prf_c::crypto_eap_fast_hmac_sha1_prf_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_context(0)
	, m_key(tools)
	, m_S_value(tools)
	, m_is_valid(false)
{
	{
		crypto_sha1_c * sha1 = new crypto_sha1_c(m_am_tools);
		if (sha1 == 0
			|| sha1->get_is_valid() == false)
		{
			delete sha1;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}

		m_context = new crypto_hmac_c(m_am_tools, sha1, true);
		if (m_context == 0
			|| m_context->get_is_valid() == false)
		{
			delete m_context;
			m_context = 0;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return;
		}
	}

	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_eap_fast_hmac_sha1_prf_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_eap_fast_hmac_sha1_prf_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_eap_fast_hmac_sha1_prf_c::get_is_valid()
{
	return 	m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_eap_fast_hmac_sha1_prf_c::t_prf_init(
	const eap_variable_data_c * const key,
	const eap_variable_data_c * const label,
	const eap_variable_data_c * const seed)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (key->get_is_valid_data() == false
		|| key->get_data_length() == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (label->get_is_valid_data() == false
		|| label->get_data_length() == 0ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// NOTE seed could be empty buffer.
	if (seed != 0
		&& seed->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	m_S_value.reset();

	eap_status_e status = m_S_value.set_copy_of_buffer(label);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u8_t byte_counter(0ul);

	status = m_S_value.add_data(&byte_counter, sizeof(byte_counter));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (seed != 0)
	{
		status = m_S_value.add_data(seed);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("tls_prf_init(): m_S_value"),
		m_S_value.get_data(),
		m_S_value.get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_key.set_copy_of_buffer(key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("tls_prf_init(): m_key"),
		m_key.get_data(),
		m_key.get_data_length()));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_eap_fast_hmac_sha1_prf_c::t_prf_output(
	void * const pseudo_random_data,
	const u16_t pseudo_random_data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (pseudo_random_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = eap_status_not_supported;

	EAP_ASSERT_ALWAYS(get_is_valid() == true);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	status = m_context->hmac_set_key(&m_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_variable_data_c sha1_output(m_am_tools);

	u32_t required_data = pseudo_random_data_length+m_context->get_digest_length();

	status = sha1_output.init(
		required_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	sha1_output.set_is_valid();
	sha1_output.set_data_length(0ul);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		u32_t hmac_sha1_md_length = m_context->get_digest_length();
		u32_t sha1_count = required_data
			/ m_context->get_digest_length();

		// - - - - - - - - - - - - - - - - - - - - - - - -

		// - - - - - - - - - - - - - - - - - - - - - - - -

		eap_variable_data_c T_value(m_am_tools);
		if (T_value.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = T_value.set_buffer_length(hmac_sha1_md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = T_value.set_data_length(0ul);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - -

		u16_t network_order_pseudo_random_data_length(eap_htons(pseudo_random_data_length));
		u8_t byte_counter(0ul);

		for (u32_t ind = 0ul; ind < sha1_count; ind++)
		{
			++byte_counter;

			// Next A value is:
			// T(i) = HMAC_hash(key, T(i-1) + S + outputlength + 0x(i)).

			status = m_context->hmac_set_key(&m_key);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_context->hmac_update(T_value.get_data(), T_value.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_context->hmac_update(m_S_value.get_data(), m_S_value.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_context->hmac_update(&network_order_pseudo_random_data_length, sizeof(network_order_pseudo_random_data_length));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_context->hmac_update(&byte_counter, sizeof(byte_counter));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			u32_t digest_length(m_context->get_digest_length());

			status = T_value.set_data_length(digest_length);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = m_context->hmac_final(
				T_value.get_data(),
				&digest_length);

			if (m_context->get_digest_length() != digest_length)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = sha1_output.add_data(&T_value);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

		} // for()
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Final operation is copy sha1_output to output buffer.

	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAP_AM_CRYPTO,
			(EAPL("crypto_eap_fast_hmac_sha1_prf_c::tls_prf_output(): sha1_output"),
			 sha1_output.get_data(pseudo_random_data_length),
			 pseudo_random_data_length));

		EAP_ASSERT(pseudo_random_data_length <= sha1_output.get_data_length());

		const u8_t * const sha1_buffer = sha1_output.get_data(
			pseudo_random_data_length);
		if (sha1_buffer == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		u8_t * const p_pseudo_random_data
			= static_cast<u8_t *>(pseudo_random_data);

		m_am_tools->memmove(
			p_pseudo_random_data,
			sha1_buffer,
			pseudo_random_data_length);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAP_AM_CRYPTO,
			(EAPL("crypto_eap_fast_hmac_sha1_prf_c::tls_prf_output(): ")
			 EAPL("p_pseudo_random_data"),
			 p_pseudo_random_data,
			 pseudo_random_data_length));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_eap_fast_hmac_sha1_prf_c::t_prf_cleanup()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (m_context != 0)
	{
		m_context->hmac_cleanup();
	}

	m_key.reset();
	m_S_value.reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_rsa_c::~crypto_rsa_c()
{
	cleanup();
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_rsa_c::crypto_rsa_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_context(tools)
	, m_is_valid(false)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_rsa_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_rsa_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_rsa_c::get_is_valid()
{
	return 	m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rsa_c::init()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_tools->get_crypto()->rsa_init(&m_context);

	if (m_context.get_is_valid_data() == false)
	{
		set_is_invalid();
		if (status == eap_status_ok)
		{
			status = eap_status_allocation_error;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rsa_c::encrypt_with_public_key(
	const eap_variable_data_c * const public_rsa_key,
	const eap_variable_data_c * const input_data,
	eap_variable_data_c * const output_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_tools->get_crypto()
		->rsa_encrypt_with_public_key(
			&m_context,
			public_rsa_key,
			input_data,
			output_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rsa_c::decrypt_with_public_key(
	const eap_variable_data_c * const public_rsa_key,
	const eap_variable_data_c * const input_data,
	eap_variable_data_c * const output_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_tools->get_crypto()
		->rsa_decrypt_with_public_key(
			&m_context,
			public_rsa_key,
			input_data,
			output_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rsa_c::encrypt_with_private_key(
	const eap_variable_data_c * const private_rsa_key,
	const eap_variable_data_c * const input_data,
	eap_variable_data_c * const output_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_tools->get_crypto()
		->rsa_encrypt_with_private_key(
			&m_context,
			private_rsa_key,
			input_data,
			output_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rsa_c::decrypt_with_private_key(
	const eap_variable_data_c * const private_rsa_key,
	const eap_variable_data_c * const input_data,
	eap_variable_data_c * const output_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_tools->get_crypto()
		->rsa_decrypt_with_private_key(
			&m_context,
			private_rsa_key,
			input_data,
			output_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rsa_c::sign(
	const eap_variable_data_c * const private_rsa_key,
	const eap_variable_data_c * const hash,
	eap_variable_data_c * const signed_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_tools->get_crypto()->rsa_sign(
		&m_context,
		private_rsa_key,
		hash,
		signed_hash);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rsa_c::verify(
	const eap_variable_data_c * const public_rsa_key,
	const eap_variable_data_c * const hash,
	const eap_variable_data_c * const signed_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_tools->get_crypto()->rsa_verify(
		&m_context,
		public_rsa_key,
		hash,
		signed_hash);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_rsa_c::cleanup()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_tools->get_crypto()->rsa_cleanup(&m_context);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_dsa_c::~crypto_dsa_c()
{
	cleanup();
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_dsa_c::crypto_dsa_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_context(tools)
	, m_is_valid(false)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_dsa_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void crypto_dsa_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_dsa_c::get_is_valid()
{
	return 	m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_dsa_c::init()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_tools->get_crypto()->dsa_init(&m_context);

	if (m_context.get_is_valid_data() == false)
	{
		set_is_invalid();
		if (status == eap_status_ok)
		{
			status = eap_status_allocation_error;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_dsa_c::sign(
	const eap_variable_data_c * const private_dsa_key,
	const eap_variable_data_c * const hash,
	eap_variable_data_c * const signed_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_tools->get_crypto()->dsa_sign(
		&m_context,
		private_dsa_key,
		hash,
		signed_hash);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_dsa_c::verify(
	const eap_variable_data_c * const public_dsa_key,
	const eap_variable_data_c * const dsa_param_p,
	const eap_variable_data_c * const dsa_param_q,
	const eap_variable_data_c * const dsa_param_g,
	const eap_variable_data_c * const hash,
	const eap_variable_data_c * const signed_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_tools->get_crypto()->dsa_verify(
		&m_context,
		public_dsa_key,
		dsa_param_p,
		dsa_param_q,
		dsa_param_g,
		hash,
		signed_hash);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_dsa_c::cleanup()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = m_am_tools->get_crypto()->dsa_cleanup(&m_context);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT crypto_wpa_psk_password_hash_c::~crypto_wpa_psk_password_hash_c()
{	
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_wpa_psk_password_hash_c::crypto_wpa_psk_password_hash_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(false)
{
	set_is_valid();
}

//--------------------------------------------------

void crypto_wpa_psk_password_hash_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

void crypto_wpa_psk_password_hash_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_wpa_psk_password_hash_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

// These are the functions for calculating PSK from ascii string 
// taken from 802.11i D3.0

/*
* password - ascii string up to 63 characters in length
* ssid - octet string up to 32 octets
* ssidlength - length of ssid in octets
* output must be 40 octets in length and outputs 256 bits of key
*/
EAP_FUNC_EXPORT eap_status_e crypto_wpa_psk_password_hash_c::password_hash(
	const eap_variable_data_c * const password,
	const eap_variable_data_c * const ssid,	
	eap_variable_data_c * const output,
	void * object,
	eap_status_e (*progress_callback)(void*, u32_t))
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Hashing WPA PSK ASCII password.\n")));		

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT, 
		(EAPL("password"),
		password->get_data(),
		password->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT, 
		(EAPL("ssid"),
		ssid->get_data(),
		ssid->get_data_length()));

	// Buffer must be reset before new HASH is added to it.
	// This causes the new HASH addition to the begin of the buffer.
	// This is small optimization that does not free the old buffer.
	eap_status_e status = output->reset_start_offset_and_data_length();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if ((password->get_data_length() > 63) || (ssid->get_data_length() > 32))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	status = password_hash_F(password, ssid, 4096, 1, output, object, progress_callback);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
		
	status = password_hash_F(password, ssid, 4096, 2, output, object, progress_callback);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// truncate the buffer to 32 bytes
	output->set_data_length(WPA_PSK_LENGTH);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WPA PSK"),
		output->get_data(),
		output->get_data_length()));


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

eap_status_e crypto_wpa_psk_password_hash_c::password_hash_F(
	const eap_variable_data_c * const password,
	const eap_variable_data_c * const ssid,	
	u32_t iterations,
	u32_t count,
	eap_variable_data_c * const output,
	void * object,
	eap_status_e (*progress_callback)(void*, u32_t))
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_process_general_error);
	
	crypto_sha1_c sha1(m_am_tools);
	
	status = sha1.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	u32_t digest_length = sha1.get_digest_length();

	crypto_hmac_c hmac(m_am_tools, &sha1, false);

	u32_t i_ind, j_ind;

	// Check for illegal characters
	for (i_ind = 0; i_ind < password->get_data_length(); i_ind++)
	{
		u8_t * const character = password->get_data_offset(i_ind, 1);
		if (character == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		if(!((*character >= 32) && (*character <= 126)))
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}
	}

	eap_variable_data_c digest(m_am_tools);	
	eap_variable_data_c digest1(m_am_tools);

	status = digest.set_copy_of_buffer(ssid);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u8_t tmp[] = {
		static_cast<u8_t>((count>>24) & 0xff),
		static_cast<u8_t>((count>>16) & 0xff),
		static_cast<u8_t>((count>>8) & 0xff),
		static_cast<u8_t>(count & 0xff)
	};

	status = digest.add_data(tmp, sizeof(tmp));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = hmac.hmac_set_key(password);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = hmac.hmac_update(
			digest.get_data(),
			digest.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = digest1.set_buffer_length(digest_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = hmac.hmac_final(
		digest1.get_buffer(digest_length),
			0);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	digest1.set_data_length(digest_length);

	status = digest.set_buffer_length(digest_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	digest.set_data_length(digest_length);

	/* output = U1 */
	status = output->add_data(&digest1);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u8_t * p_output = output->get_data_offset((count - 1) * digest_length, digest_length);
	if (p_output == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	u32_t callback_trigger = 0ul;

	for (i_ind = 1; i_ind < iterations; i_ind++) 
	{
		callback_trigger++;

		if (callback_trigger > 400
			&& progress_callback != 0
			&& object != 0)
		{
			callback_trigger = 0;
			status = progress_callback(object, 400);		
			if (status != eap_status_ok)
			{
				// This means that the operation was cancelled.
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WPA PSK password hashing cancelled.\n")));
				return EAP_STATUS_RETURN(m_am_tools, status);
			}			
		}

		status = hmac.hmac_set_key(password);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DATA_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT, 
				(EAPL("illegal password:"),
				password->get_data(),
				password->get_data_length()));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = hmac.hmac_update(
			digest1.get_data(),
			digest1.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	
		status = hmac.hmac_final(
			digest.get_data(sha1.get_digest_length()),
				0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		digest.set_data_length(digest_length);

		status = digest1.set_copy_of_buffer(&digest);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		/* output = output xor Un */		
		u8_t * p_digest = digest.get_data(digest_length);
		if (p_digest == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		for (j_ind = 0; j_ind < digest_length; j_ind++)
		{
			p_output[j_ind] = static_cast<u8_t>(p_output[j_ind] ^ p_digest[j_ind]);
		}
	} // for()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------


EAP_FUNC_EXPORT crypto_nt_hash_c::~crypto_nt_hash_c()
{	
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_nt_hash_c::crypto_nt_hash_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(false)
{
	set_is_valid();
}

//--------------------------------------------------

void crypto_nt_hash_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

void crypto_nt_hash_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_nt_hash_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_nt_hash_c::nt_password_hash(
	const eap_variable_data_c * const password_utf8,
	eap_variable_data_c * const password_hash,
	const u32_t /* digest_size */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	if (password_utf8 == 0
		|| password_hash == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_variable_data_c tmp_password_unicode(m_am_tools);
	eap_status_e status = m_am_tools->convert_utf8_to_unicode(tmp_password_unicode, *password_utf8);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Ms-Chap-V2 wants the byte order of password is little endian
#if defined(EAP_BIG_ENDIAN)
	{
		u32_t password_size = tmp_password_unicode.get_data_length();
		u8_t * password = tmp_password_unicode.get_data(password_size);
		u8_t tmp;

		for (i = 0; i < password_size; i += 2)
		{
			// Swap bytes
			tmp = password[i];
			password[i] = password[i + 1];
			password[i + 1] = tmp;
		}
	}
#endif // EAP_BIG_ENDIAN


	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: nt_password_hash(), password_unicode"),
		tmp_password_unicode.get_data(),
		tmp_password_unicode.get_data_length()));

	crypto_md4_c md4(m_am_tools);

	status = md4.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = md4.hash_update(
		tmp_password_unicode.get_data(),
		tmp_password_unicode.get_data_length()); // unicode-chars
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	password_hash->reset();

	status = password_hash->set_buffer_length(md4.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = password_hash->set_data_length(md4.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = md4.hash_final(password_hash->get_data(md4.get_digest_length()), 0);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_nt_hash_c::hash_nt_password_hash(
	const eap_variable_data_c * const password_hash,
	eap_variable_data_c * const password_hash_hash,
	const u32_t digest_size)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	if (!password_hash
	|| !password_hash_hash)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	crypto_md4_c md4(m_am_tools);

	eap_status_e status = md4.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = md4.hash_update(password_hash->get_data(digest_size), digest_size);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	password_hash_hash->reset();

	status = password_hash_hash->set_buffer_length(md4.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = password_hash_hash->set_data_length(md4.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = md4.hash_final(password_hash_hash->get_data(md4.get_digest_length()), 0);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAP_type_MSCHAPV2: hash_nt_password_hash(), password_hash_hash"),
		password_hash_hash->get_data(),
		password_hash_hash->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/* RFC 3079 */

static const u8_t eap_type_mschapv2_magic1[] = {
	0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
	0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
	0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79 };

EAP_FUNC_EXPORT eap_status_e crypto_nt_hash_c::get_master_key(
	const eap_variable_data_c * const in_password_hash_hash,
	const eap_variable_data_c * const in_nt_response,
	eap_variable_data_c * const out_master_key,
	const u32_t in_master_key_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::get_master_key(): this = 0x%08x\n"),
		this));

	if (in_password_hash_hash == 0
		|| in_password_hash_hash->get_is_valid_data() == false
		|| in_nt_response == 0
		|| in_nt_response->get_is_valid_data() == false
		|| out_master_key == 0
		|| out_master_key->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	crypto_sha1_c sha1(m_am_tools);

	eap_status_e status = sha1.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(
		in_password_hash_hash->get_data(),
		in_password_hash_hash->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(
		in_nt_response->get_data(),
		in_nt_response->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(eap_type_mschapv2_magic1, sizeof(eap_type_mschapv2_magic1));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c digest(m_am_tools);
	if (digest.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	
	status = digest.set_buffer_length(sha1.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = digest.set_data_length(sha1.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_final(
		digest.get_data(), 0);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = out_master_key->set_copy_of_buffer(
		digest.get_data(in_master_key_length),
		in_master_key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

static const u8_t eap_type_mschapv2_magic2[] = {
	0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
	0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
	0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
	0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
	0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
	0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
	0x6b, 0x65, 0x79, 0x2e };

static const u8_t eap_type_mschapv2_magic3[] = {
	0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
	0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
	0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
	0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
	0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
	0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
	0x6b, 0x65, 0x79, 0x2e };
		

EAP_FUNC_EXPORT eap_status_e crypto_nt_hash_c::get_asymmetric_start_key(
	const eap_variable_data_c * const in_master_key,
	eap_variable_data_c * const out_session_key,
	const u32_t in_session_key_length,
	const bool in_is_send,
	const bool in_is_server)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::get_asymmetric_start_key(): this = 0x%08x\n"),
		this));

	if (in_master_key == 0
		|| in_master_key->get_is_valid_data() == false
		|| out_session_key == 0
		|| out_session_key->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	crypto_sha1_c sha1(m_am_tools);

	eap_status_e status = sha1.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	status = sha1.hash_update(
		in_master_key->get_data(),
		in_master_key->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const u32_t padding_size = 40;

	eap_variable_data_c padding(m_am_tools);
	if (padding.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = padding.set_buffer_length(padding_size);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = padding.set_data_length(padding_size);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const u32_t padding1_value = 0x00;

	m_am_tools->memset(padding.get_data(), padding1_value, padding.get_data_length()); // padding1

	status = sha1.hash_update(
		padding.get_data(),
		padding.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		const u8_t * magic = eap_type_mschapv2_magic2;

		if (in_is_send == in_is_server)
		{
			magic = eap_type_mschapv2_magic3;
		}

		status = sha1.hash_update(magic, sizeof(eap_type_mschapv2_magic2)); // magic2 and magic3 are both 84 bytes
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	const u32_t padding2_value = 0xf2;

	m_am_tools->memset(padding.get_data(), padding2_value, padding.get_data_length()); // padding2

	status = sha1.hash_update(
		padding.get_data(),
		padding.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c digest(m_am_tools);
	if (digest.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = digest.set_buffer_length(sha1.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = digest.set_data_length(sha1.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_final(digest.get_data(), 0);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = out_session_key->set_copy_of_buffer(digest.get_data(in_session_key_length), in_session_key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_nt_hash_c::get_new_key_from_sha(
	const eap_variable_data_c * const in_start_key,
	const eap_variable_data_c * const in_session_key,
	eap_variable_data_c * const out_interim_key,
	const u32_t in_interim_key_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_type_mschapv2_c::get_new_key_from_sha(): this = 0x%08x\n"),
		this));

	if (in_start_key == 0
		|| in_start_key->get_is_valid_data() == false
		|| in_session_key == 0
		|| in_session_key->get_is_valid_data() == false
		|| out_interim_key == 0
		|| out_interim_key->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	crypto_sha1_c sha1(m_am_tools);

	eap_status_e status = sha1.hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	status = sha1.hash_update(
		in_start_key->get_data(),
		in_start_key->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const u32_t padding_size = 40;

	eap_variable_data_c padding(m_am_tools);
	if (padding.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = padding.set_buffer_length(padding_size);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = padding.set_data_length(padding_size);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	const u32_t padding1_value = 0x00;

	m_am_tools->memset(padding.get_data(), padding1_value, padding.get_data_length()); // padding1

	status = sha1.hash_update(
		padding.get_data(),
		padding.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_update(
		in_session_key->get_data(),
		in_session_key->get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const u32_t padding2_value = 0xf2;

	m_am_tools->memset(padding.get_data(), padding2_value, padding.get_data_length()); // padding2

	status = sha1.hash_update(
		padding.get_data(),
		padding.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c digest(m_am_tools);
	if (digest.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = digest.set_buffer_length(sha1.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = digest.set_data_length(sha1.get_digest_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = sha1.hash_final(digest.get_data(), 0);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = out_interim_key->set_copy_of_buffer(digest.get_data(in_interim_key_length), in_interim_key_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

void crypto_kd_hmac_sha256_c::set_is_invalid()
{
	m_is_valid = false;
}

//--------------------------------------------------

void crypto_kd_hmac_sha256_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_kd_hmac_sha256_c::~crypto_kd_hmac_sha256_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT crypto_kd_hmac_sha256_c::crypto_kd_hmac_sha256_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(false)
{
	set_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool crypto_kd_hmac_sha256_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e crypto_kd_hmac_sha256_c::expand_key(
	eap_variable_data_c * const output,
	const u32_t required_output_size,
	const eap_variable_data_c * const key,
	const eap_variable_data_c * const label
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("\n")));
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("crypto_kd_hmac_sha256_c::expand_key()\n")));

	output->reset();

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
		(EAPL("crypto_kd_hmac_sha256_c::expand_key(): key"),
		key->get_data(),
		key->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("crypto_kd_hmac_sha256_c::expand_key(): label"),
		label->get_data(),
		label->get_data_length()));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("crypto_kd_hmac_sha256_c::expand_key(): required_output_size %d\n"),
		required_output_size));

	const u32_t prf_digest_size(hmac_sha_256.get_digest_length());
	const u32_t iterations((required_output_size + prf_digest_size - 1) / prf_digest_size);

	eap_status_e status = output->set_buffer_length(iterations * prf_digest_size);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = output->set_data_length(iterations * prf_digest_size);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c input(m_am_tools);
	if (input.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = input.set_buffer(label);
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

		status = hmac_sha_256.hmac_update(
			input.get_data(),
			input.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u32_t md_length(prf_digest_size);

		status = hmac_sha_256.hmac_final(
			output->get_data_offset(ind*prf_digest_size, prf_digest_size),
			&md_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = input.set_buffer(
			output->get_data_offset(ind*prf_digest_size, prf_digest_size),
			md_length,
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	} // for()

	status = output->set_data_length(required_output_size);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("crypto_kd_hmac_sha256_c::expand_key(): output"),
		output->get_data(),
		output->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
// End.
