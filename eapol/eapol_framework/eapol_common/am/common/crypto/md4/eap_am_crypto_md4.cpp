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
	#define EAP_FILE_NUMBER_ENUM 4 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_am_crypto_md4.h"

//--------------------------------------------------

#if 1
	#define EAP_MD4_TRACE_DEBUG EAP_TRACE_DEBUG
#else
	#define EAP_MD4_TRACE_DEBUG(tools, flags, params)
#endif

#if defined(USE_EAP_TRACE)
	static const u32_t EAP_TRACE_MASK_MD4 = eap_am_tools_c::eap_trace_mask_crypto_md4;
#endif //#if defined(USE_EAP_TRACE)	

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_crypto_md4_c::~eap_am_crypto_md4_c()
{
	hash_cleanup();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_crypto_md4_c::eap_am_crypto_md4_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_saved_data(tools)
	, m_full_hashed_data_length(0ul)
	, m_is_valid(false)
{
	m_H[0] = 0;
	m_W_in_host_order[0] = 0;

	if (m_saved_data.get_is_valid() == false)
	{
		return;
	}

	eap_status_e status = hash_init();
	if (status != eap_status_ok)
	{
		return;
	}

	set_is_valid();
}


//------------------------------------------------------------

/**
 * The set_is_invalid() function sets the state of the eap_am_crypto_md4_c
 * object invalid. 
 * The eap_am_crypto_md4_c object calls this function after it is initialized.
 */
EAP_FUNC_EXPORT void eap_am_crypto_md4_c::set_is_invalid()
{
	m_is_valid = false;
}

//------------------------------------------------------------

/**
 * The set_is_valid() function sets the state of the eap_am_crypto_md4_c
 * object valid. 
 * The eap_am_crypto_md4_c object calls this function after it is initialized.
 */
EAP_FUNC_EXPORT void eap_am_crypto_md4_c::set_is_valid()
{
	m_is_valid = true;
}

//------------------------------------------------------------

/**
 * The get_is_valid() function returns the status of the eap_am_crypto_md4_c
 * object. 
 * True indicates the object is allocated successfully.
 */
EAP_FUNC_EXPORT bool eap_am_crypto_md4_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

inline u32_t eap_am_crypto_md4_c::eap_md4_rotate_left(
	const u32_t value,
	const u32_t shift
	)
{
	return (value << shift) | (value >> (32ul - shift));
}

//--------------------------------------------------

inline void eap_am_crypto_md4_c::eap_md4_FF(
	const u32_t index,
	u32_t * const A,
	const u32_t B,
	const u32_t C,
	const u32_t D,
	const u32_t X,
	const u32_t S
	)
{	
	EAP_UNREFERENCED_PARAMETER(index);

	*A += eap_md4_F(B, C, D) + X;
	*A = eap_md4_rotate_left(*A, S);

	EAP_MD4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_MD4,
					(EAPL("MD4: t=%d\t%08x\t%08x\t%08x\t%08x\t%08x\t% 8d\n"),
					 index, *A, B, C, D, X, S));
}

//--------------------------------------------------

inline void eap_am_crypto_md4_c::eap_md4_GG(
	const u32_t index,
	u32_t * const A,
	const u32_t B,
	const u32_t C,
	const u32_t D,
	const u32_t X,
	const u32_t S
	)
{
	EAP_UNREFERENCED_PARAMETER(index);

	*A += eap_md4_G(B, C, D) + X + 0x5a827999;
	*A = eap_md4_rotate_left(*A, S);

	EAP_MD4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_MD4,
					(EAPL("MD4: t=%d\t%08x\t%08x\t%08x\t%08x\t%08x\t% 8d\n"),
					 index, *A, B, C, D, X, S));
}

//--------------------------------------------------

inline void eap_am_crypto_md4_c::eap_md4_HH(
	const u32_t index,
	u32_t * const A,
	const u32_t B,
	const u32_t C,
	const u32_t D,
	const u32_t X,
	const u32_t S
	)
{
	EAP_UNREFERENCED_PARAMETER(index);

	*A += eap_md4_H(B, C, D) + X + 0x6ed9eba1;
	*A = eap_md4_rotate_left(*A, S);

	EAP_MD4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_MD4,
					(EAPL("MD4: t=%d\t%08x\t%08x\t%08x\t%08x\t%08x\t% 8d\n"),
					 index, *A, B, C, D, X, S));
}

//--------------------------------------------------

inline u32_t eap_am_crypto_md4_c::eap_md4_F(
	const u32_t X,
	const u32_t Y,
	const u32_t Z
	)
{
	return (X & Y) | ((~X) & Z);
}

//--------------------------------------------------

inline u32_t eap_am_crypto_md4_c::eap_md4_G(
	const u32_t X,
	const u32_t Y,
	const u32_t Z
	)
{
	return (X & Y) | (X & Z) | (Y & Z);
}


//--------------------------------------------------

inline u32_t eap_am_crypto_md4_c::eap_md4_H(
	const u32_t X,
	const u32_t Y,
	const u32_t Z
	)
{
	return (X ^ Y ^ Z);
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_md4_c::eap_md4_process_data(
	const u32_t * const W,
	const u32_t W_count
	)
{
	if (W == 0
		//|| (reinterpret_cast<u32_t>(W) % sizeof(u32_t)) != 0
		|| W_count == 0
		|| (W_count % EAP_AM_CRYPTO_MD4_BLOCK_u32_COUNT) != 0)
	{
		EAP_ASSERT_ANYWAY;
		EAP_SYSTEM_DEBUG_BREAK();
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	eap_status_e status = eap_status_ok;

	// Array of 16 temporary 32-bit unsigned integers.
	u32_t count = W_count / EAP_AM_CRYPTO_MD4_BLOCK_u32_COUNT;	

	for (u32_t ind = 0ul; ind < count; ind++)
	{	
		for (u32_t ind_W = 0ul; ind_W < EAP_AM_CRYPTO_MD4_BLOCK_u32_COUNT
				 ; ind_W++)
		{
			// Here we must read data in 8-bit blocks bacause W can be aligned at any position.
			const u8_t * const data = reinterpret_cast<const u8_t *>(&W[ind*EAP_AM_CRYPTO_MD4_BLOCK_u32_COUNT+ind_W]);
			m_W_in_host_order[ind_W]
				= (data[0] <<  0)
				| (data[1] <<  8)
				| (data[2] << 16)
				| (data[3] << 24);
		} // for()
	
		status = eap_md4_transform_host_order(
			m_W_in_host_order,
			EAP_AM_CRYPTO_MD4_BLOCK_u32_COUNT);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	
	} // for()

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_md4_c::eap_md4_transform_host_order(
	const u32_t * const W,
	const u32_t W_count
	)
{
	u32_t A = m_H[0];
	u32_t B = m_H[1];
	u32_t C = m_H[2];
	u32_t D = m_H[3];

	if (W == 0
		//|| (reinterpret_cast<u32_t>(W) % sizeof(u32_t)) != 0
		|| W_count != EAP_AM_CRYPTO_MD4_BLOCK_u32_COUNT)
	{
		EAP_ASSERT_ANYWAY;
		EAP_SYSTEM_DEBUG_BREAK();
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t * const X = W;

#if defined(_DEBUG)

	EAP_MD4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_MD4,
					(EAPL("MD4: A=%08x\tB=%08x\tC=%08x\tD=%08x\n"),
					 A, B, C, D));

	u32_t ind;
	for (ind = 0ul; ind < W_count; ind++)
	{
		EAP_MD4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_MD4,
					(EAPL("MD4: W[%d]=%08x\n"),
					 ind,
					 W[ind]));
	} // for()

	EAP_MD4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_MD4,
					(EAPL("MD4: \n")));

	for (ind = 0ul; ind < sizeof(X)/sizeof(X[0]); ind++)
	{
		EAP_MD4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_MD4,
					(EAPL("MD4: X[%d]=%08x\n"),
					 ind,
					 X[ind]));
	} // for()

	EAP_MD4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_MD4,
					(EAPL("MD4: % 5s\t% 8s\t% 8s\t% 8s\t% 8s\t% 8s\t% 8s\n"),
					 "index", "A", "B", "C", "D", "X", "shift"));

#endif //#if defined(_DEBUG)


	eap_md4_FF( 1, &A, B, C, D, X[ 0], eap_md4_const_S11);
	eap_md4_FF( 2, &D, A, B, C, X[ 1], eap_md4_const_S12);
	eap_md4_FF( 3, &C, D, A, B, X[ 2], eap_md4_const_S13);
	eap_md4_FF( 4, &B, C, D, A, X[ 3], eap_md4_const_S14);
	eap_md4_FF( 5, &A, B, C, D, X[ 4], eap_md4_const_S11);
	eap_md4_FF( 6, &D, A, B, C, X[ 5], eap_md4_const_S12);
	eap_md4_FF( 7, &C, D, A, B, X[ 6], eap_md4_const_S13);
	eap_md4_FF( 8, &B, C, D, A, X[ 7], eap_md4_const_S14);
	eap_md4_FF( 9, &A, B, C, D, X[ 8], eap_md4_const_S11);
	eap_md4_FF(10, &D, A, B, C, X[ 9], eap_md4_const_S12);
	eap_md4_FF(11, &C, D, A, B, X[10], eap_md4_const_S13);
	eap_md4_FF(12, &B, C, D, A, X[11], eap_md4_const_S14);
	eap_md4_FF(13, &A, B, C, D, X[12], eap_md4_const_S11);
	eap_md4_FF(14, &D, A, B, C, X[13], eap_md4_const_S12);
	eap_md4_FF(15, &C, D, A, B, X[14], eap_md4_const_S13);
	eap_md4_FF(16, &B, C, D, A, X[15], eap_md4_const_S14);

	eap_md4_GG(17, &A, B, C, D, X[ 0], eap_md4_const_S21);
	eap_md4_GG(18, &D, A, B, C, X[ 4], eap_md4_const_S22);
	eap_md4_GG(19, &C, D, A, B, X[ 8], eap_md4_const_S23);
	eap_md4_GG(20, &B, C, D, A, X[12], eap_md4_const_S24);
	eap_md4_GG(21, &A, B, C, D, X[ 1], eap_md4_const_S21);
	eap_md4_GG(22, &D, A, B, C, X[ 5], eap_md4_const_S22);
	eap_md4_GG(23, &C, D, A, B, X[ 9], eap_md4_const_S23);
	eap_md4_GG(24, &B, C, D, A, X[13], eap_md4_const_S24);
	eap_md4_GG(25, &A, B, C, D, X[ 2], eap_md4_const_S21);
	eap_md4_GG(26, &D, A, B, C, X[ 6], eap_md4_const_S22);
	eap_md4_GG(27, &C, D, A, B, X[10], eap_md4_const_S23);
	eap_md4_GG(28, &B, C, D, A, X[14], eap_md4_const_S24);
	eap_md4_GG(29, &A, B, C, D, X[ 3], eap_md4_const_S21);
	eap_md4_GG(30, &D, A, B, C, X[ 7], eap_md4_const_S22);
	eap_md4_GG(31, &C, D, A, B, X[11], eap_md4_const_S23);
	eap_md4_GG(32, &B, C, D, A, X[15], eap_md4_const_S24);

	eap_md4_HH(33, &A, B, C, D, X[ 0], eap_md4_const_S31);
	eap_md4_HH(34, &D, A, B, C, X[ 8], eap_md4_const_S32);
	eap_md4_HH(35, &C, D, A, B, X[ 4], eap_md4_const_S33);
	eap_md4_HH(36, &B, C, D, A, X[12], eap_md4_const_S34);
	eap_md4_HH(37, &A, B, C, D, X[ 2], eap_md4_const_S31);
	eap_md4_HH(38, &D, A, B, C, X[10], eap_md4_const_S32);
	eap_md4_HH(39, &C, D, A, B, X[ 6], eap_md4_const_S33);
	eap_md4_HH(40, &B, C, D, A, X[14], eap_md4_const_S34);
	eap_md4_HH(41, &A, B, C, D, X[ 1], eap_md4_const_S31);
	eap_md4_HH(42, &D, A, B, C, X[ 9], eap_md4_const_S32);
	eap_md4_HH(43, &C, D, A, B, X[ 5], eap_md4_const_S33);
	eap_md4_HH(44, &B, C, D, A, X[13], eap_md4_const_S34);
	eap_md4_HH(45, &A, B, C, D, X[ 3], eap_md4_const_S31);
	eap_md4_HH(46, &D, A, B, C, X[11], eap_md4_const_S32);
	eap_md4_HH(47, &C, D, A, B, X[ 7], eap_md4_const_S33);
	eap_md4_HH(48, &B, C, D, A, X[15], eap_md4_const_S34);

	m_H[0] += A;
	m_H[1] += B;
	m_H[2] += C;
	m_H[3] += D;

	EAP_MD4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_MD4,
					(EAPL("MD4: digest=\t%08x\t%08x\t%08x\t%08x\n"),
					 m_H[0], m_H[1], m_H[2], m_H[3]));

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_md4_c::copy_message_digest(
	void * const output,
	u32_t * const max_output_size)
{
	if (output == 0
		|| max_output_size == 0
		|| *max_output_size < EAP_AM_CRYPTO_MD4_DIGEST_BUFFER_BYTE_SIZE)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

#if defined(EAP_LITTLE_ENDIAN)

	m_am_tools->memmove(output, m_H, EAP_AM_CRYPTO_MD4_DIGEST_BUFFER_BYTE_SIZE);

#elif defined(EAP_BIG_ENDIAN)

	// We must change the data from host order to network order.
	u32_t * const tmp_H = static_cast<u32_t *>(output);
	for (u32_t ind = 0ul; ind < EAP_AM_CRYPTO_MD4_DIGEST_BUFFER_u32_COUNT
			 ; ind++)
	{
		tmp_H[ind] = eap_htonl(m_H[ind]);
	} // for()

#else
#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant \
(i386)) or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
#endif

	*max_output_size = EAP_AM_CRYPTO_MD4_DIGEST_BUFFER_BYTE_SIZE;

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}


//--------------------------------------------------

/**
 * This function returns the size of message digest of HASH-algorithm.
 */
EAP_FUNC_EXPORT u32_t eap_am_crypto_md4_c::get_digest_length()
{
	return EAP_AM_CRYPTO_MD4_DIGEST_BUFFER_BYTE_SIZE;
}

//--------------------------------------------------

/**
 * This function returns the size of block of HASH-algorithm.
 */
EAP_FUNC_EXPORT u32_t eap_am_crypto_md4_c::get_block_size()
{
	return EAP_AM_CRYPTO_MD4_BLOCK_BYTE_SIZE;
}

//--------------------------------------------------

/**
 * This function initializes the context of MD4-algorithm.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_md4_c::hash_init()
{
	m_full_hashed_data_length = 0ul;

	m_H[0] = static_cast<u32_t>(EAP_MD4_INIT_H0);
	m_H[1] = static_cast<u32_t>(EAP_MD4_INIT_H1);
	m_H[2] = static_cast<u32_t>(EAP_MD4_INIT_H2);
	m_H[3] = static_cast<u32_t>(EAP_MD4_INIT_H3);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

/**
 * This function updates the context of MD4-algorithm with data.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_md4_c::hash_update(
	const void * const data,
	const u32_t data_length)
{
	eap_status_e status = eap_status_ok;
	u32_t prosessed_data_length = 0ul;

	m_full_hashed_data_length += data_length;

	EAP_MD4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_MD4,
					(EAPL("MD4: Processed data length %u\n"),
					 m_full_hashed_data_length));

	if (m_saved_data.get_is_valid_data() == true
		&& m_saved_data.get_data_length() > 0ul)
	{
		// Here we have remaining data to process from previous call
		// of hash_update().
		u32_t needed_data_length = EAP_AM_CRYPTO_MD4_BLOCK_BYTE_SIZE
			- m_saved_data.get_data_length();
		if (needed_data_length > data_length)
		{
			// Not enough input data.
			needed_data_length = data_length;
		}

		prosessed_data_length = needed_data_length;
		status = m_saved_data.add_data(data, needed_data_length);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (m_saved_data.get_data_length()
			== EAP_AM_CRYPTO_MD4_BLOCK_BYTE_SIZE)
		{
			// Enough data to process.
			// Just one block of integers in W array.
			status = eap_md4_process_data(
				reinterpret_cast<const u32_t *>(
					m_saved_data.get_data(
						m_saved_data.get_data_length())),
				EAP_AM_CRYPTO_MD4_BLOCK_u32_COUNT
				);
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			m_saved_data.reset();
		}

		EAP_ASSERT(m_saved_data.get_is_valid_data() == false
			|| m_saved_data.get_data_length()
				   <= EAP_AM_CRYPTO_MD4_BLOCK_BYTE_SIZE);
	}

	u32_t remaining_data_length = data_length - prosessed_data_length;
	u32_t full_block_count = remaining_data_length
		/ EAP_AM_CRYPTO_MD4_BLOCK_BYTE_SIZE;

	if (full_block_count > 0ul)
	{
		// Here we have full blocks to process.
		status = eap_md4_process_data(
			reinterpret_cast<const u32_t *>(
				static_cast<const u8_t *>(data)+prosessed_data_length),
			full_block_count * EAP_AM_CRYPTO_MD4_BLOCK_u32_COUNT
			);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		prosessed_data_length += sizeof(u32_t) * full_block_count
			* EAP_AM_CRYPTO_MD4_BLOCK_u32_COUNT;
	}

	if (data_length > prosessed_data_length)
	{
		// Save the remaining data.
		status = m_saved_data.add_data(
			static_cast<const u8_t *>(data)+prosessed_data_length,
			data_length-prosessed_data_length);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * This function writes the message digest to buffer.
 * @param Length is set if md_length_or_null is non-NULL.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_md4_c::hash_final(
	void * const message_digest,
	u32_t *md_length_or_null)
{
	eap_status_e status = eap_status_ok;

	if (message_digest == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// First add the one bit. We use one byte 0x80.
	u8_t bit_pad = 0x80;
	status = m_saved_data.add_data(&bit_pad, sizeof(bit_pad));
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Here we may have remaining data to process from previous call
	// of hash_update().
	u32_t min_data_length = m_saved_data.get_data_length() + sizeof(u64_t);
	u32_t padding_zero_count = 0ul;
	u32_t block_count = min_data_length / EAP_AM_CRYPTO_MD4_BLOCK_BYTE_SIZE;
	if ((min_data_length % EAP_AM_CRYPTO_MD4_BLOCK_BYTE_SIZE) != 0)
	{
		// Last block is not full.
		++block_count;
	}
	padding_zero_count = (block_count*EAP_AM_CRYPTO_MD4_BLOCK_BYTE_SIZE)
		- min_data_length;

	// Now we need to pad the remaining data.
	u32_t data_length = m_saved_data.get_data_length();
	status = m_saved_data.set_buffer_length(data_length+padding_zero_count);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	m_saved_data.set_data_length(data_length+padding_zero_count);

	u8_t * const padding = m_saved_data.get_data_offset(data_length, padding_zero_count);
	if (padding == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
	}

	m_am_tools->memset(
		padding,
		0,
		padding_zero_count);

	// And finally the length of the hashed data is added to block.
	// Note the length is in bits.

#if defined(EAP_LITTLE_ENDIAN)
	u64_t full_hashed_data_length = eap_shift_left_64_bit(m_full_hashed_data_length, 3ul);
#elif defined(EAP_BIG_ENDIAN)
	u64_t full_hashed_data_length = eap_htonll(eap_shift_left_64_bit(m_full_hashed_data_length, 3ul));
#else
#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
#endif
	status = m_saved_data.add_data(
		&full_hashed_data_length,
		sizeof(full_hashed_data_length));
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_ASSERT(m_saved_data.get_data_length()
			   >= EAP_AM_CRYPTO_MD4_BLOCK_BYTE_SIZE
			   && (m_saved_data.get_data_length()
				   % EAP_AM_CRYPTO_MD4_BLOCK_BYTE_SIZE) == 0);

	u32_t full_block_count = m_saved_data.get_data_length()
		/ EAP_AM_CRYPTO_MD4_BLOCK_BYTE_SIZE;

	status = eap_md4_process_data(
		reinterpret_cast<const u32_t *>(
			m_saved_data.get_data(
				m_saved_data.get_data_length())),
		full_block_count * EAP_AM_CRYPTO_MD4_BLOCK_u32_COUNT
		);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	m_saved_data.reset();


	u32_t output_length = 0ul;
	if (md_length_or_null == 0)
	{
		// Let's use temporary length variable.
		output_length = EAP_AM_CRYPTO_MD4_DIGEST_BUFFER_BYTE_SIZE;
		md_length_or_null = &output_length;
	}

	status = copy_message_digest(
		message_digest,
		md_length_or_null);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

/**
 * This function cleans up the MD4 context.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_md4_c::hash_cleanup()
{
	m_saved_data.reset();
	m_full_hashed_data_length = 0ul;
	m_am_tools->memset(m_H, 0, EAP_AM_CRYPTO_MD4_DIGEST_BUFFER_BYTE_SIZE);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

/**
 * This function copies the context of MD4.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_md4_c::copy_context(
	const eap_variable_data_c * const saved_data,
	const u64_t full_hashed_data_length,
	const u32_t * const H,
	const u32_t * const W_in_host_order)
{
	if (saved_data->get_is_valid_data() == true)
	{
		eap_status_e status = m_saved_data.set_copy_of_buffer(saved_data);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		// No saved data. Just reset.
		m_saved_data.reset();
	}
	
	m_full_hashed_data_length = full_hashed_data_length;

	m_am_tools->memmove(m_H, H, sizeof(m_H));

	m_am_tools->memmove(m_W_in_host_order, W_in_host_order, sizeof(m_W_in_host_order));

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

/**
 * This function copies the context of MD4.
 */
EAP_FUNC_EXPORT eap_am_crypto_md4_c * eap_am_crypto_md4_c::copy()
{
	eap_am_crypto_md4_c * const md4 = new eap_am_crypto_md4_c(m_am_tools);
	if (md4 == 0
		|| md4->get_is_valid() == false)
	{
		delete md4;
		return 0;
	}

	eap_status_e status = md4->copy_context(&m_saved_data, m_full_hashed_data_length, m_H, m_W_in_host_order);
	if (status != eap_status_ok)
	{
		delete md4;
		return 0;
	}

	return md4;
}

//--------------------------------------------------



// End.
