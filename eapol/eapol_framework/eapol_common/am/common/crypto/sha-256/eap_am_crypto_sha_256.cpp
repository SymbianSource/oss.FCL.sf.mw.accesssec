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
	#define EAP_FILE_NUMBER_ENUM 578 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_am_crypto_sha_256.h"

//--------------------------------------------------

#if 0
	#define EAP_SHA_256_TRACE_DEBUG EAP_TRACE_DEBUG
	#define EAP_SHA_256_TRACE_DATA_DEBUG EAP_TRACE_DATA_DEBUG
#else
	#define EAP_SHA_256_TRACE_DEBUG(tools, flags, params)
	#define EAP_SHA_256_TRACE_DATA_DEBUG(object_name, flags, _parameter_list_)
#endif

#if defined(USE_EAP_TRACE)	
	static const u32_t EAP_TRACE_MASK_SHA_256 = TRACE_FLAGS_DEFAULT;
#endif //#if defined(USE_EAP_TRACE)	


const unsigned long eap_am_crypto_sha_256_c::m_K[eap_am_crypto_sha_256_c::EAP_AM_CRYPTO_SHA_256_SCHEDULE_u32_COUNT] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_crypto_sha_256_c::~eap_am_crypto_sha_256_c()
{
	hash_cleanup();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_crypto_sha_256_c::eap_am_crypto_sha_256_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_saved_data(tools)
	, m_full_hashed_data_length(0ul)
	, m_is_valid(false)
{
	m_H[0] = 0;
	m_T[0] = 0;
	m_M_in_host_order[0] = 0;

	if (m_saved_data.get_is_valid() == false)
	{
		#if defined(USE_EAP_TRACE)	
			EAP_UNREFERENCED_PARAMETER(EAP_TRACE_MASK_SHA_256);
		#endif //#if defined(USE_EAP_TRACE)	
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
 * The set_is_invalid() function sets the state of the eap_am_crypto_sha_256_c
 * object invalid. 
 * The eap_am_crypto_sha_256_c object calls this function after it is initialized.
 */
EAP_FUNC_EXPORT void eap_am_crypto_sha_256_c::set_is_invalid()
{
	m_is_valid = false;
}

//------------------------------------------------------------

/**
 * The set_is_valid() function sets the state of the eap_am_crypto_sha_256_c
 * object valid. 
 * The eap_am_crypto_sha_256_c object calls this function after it is initialized.
 */
EAP_FUNC_EXPORT void eap_am_crypto_sha_256_c::set_is_valid()
{
	m_is_valid = true;
}

//------------------------------------------------------------

/**
 * The get_is_valid() function returns the status of the eap_am_crypto_sha_256_c
 * object. 
 * True indicates the object is allocated successfully.
 */
EAP_FUNC_EXPORT bool eap_am_crypto_sha_256_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

inline u32_t eap_am_crypto_sha_256_c::eap_sha_256_rotate(
	const u32_t value,
	const u32_t shift
	)
{
	return (value >> shift) | (value << (32ul - shift));
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e
eap_am_crypto_sha_256_c::eap_sha_256_process_data_host_order(
	const u32_t * M,
	u32_t M_count
	)
{
	u32_t A;
	u32_t B;
	u32_t C;
	u32_t D;
	u32_t E;
	u32_t F;
	u32_t G;
	u32_t H;

	u32_t S0;
	u32_t S1;
	u32_t T1;
	u32_t T2;

	u32_t W[EAP_AM_CRYPTO_SHA_256_SCHEDULE_u32_COUNT];

	if (M == 0
		|| M_count == 0
		|| (M_count % EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT) != 0)
	{
		EAP_ASSERT_ANYWAY;
		EAP_SYSTEM_DEBUG_BREAK();
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	do
	{
		m_am_tools->memmove(W, M, sizeof(u32_t) * EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT); // Initialize 16 W words.

		{
			// Extend 16 W words to 64 W words.
			for (u32_t ind = EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT; ind != EAP_AM_CRYPTO_SHA_256_SCHEDULE_u32_COUNT; ind++)
			{
				S0 = eap_sha_256_rotate(W[ind-15], 7) ^ eap_sha_256_rotate(W[ind-15], 18) ^ (W[ind-15] >> 3);
				S1 = eap_sha_256_rotate(W[ind-2], 17) ^ eap_sha_256_rotate(W[ind-2], 19) ^ (W[ind-2] >> 10);
				W[ind] = W[ind-16] + S0 + W[ind-7] + S1;
			}
		}


		#if defined(_DEBUG)
		{
			for (u32_t ind = 0ul; ind != M_count; ind++)
			{
				EAP_SHA_256_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA_256,
							(EAPL("SHA_256: M[%d]=%08x, W[%d]=%08x\n"),
							 ind,
							 M[ind],
							 ind,
							 W[ind]));
			} // for()

			EAP_SHA_256_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA_256,
					(EAPL("SHA_256: H[0]=0x%08x, H[1]=0x%08x, H[2]=0x%08x, H[3]=0x%08x, H[4]=0x%08x, H[5]=0x%08x, H[6]=0x%08x, H[7]=0x%08x\n"),
					 m_H[0],
					 m_H[1],
					 m_H[2],
					 m_H[3],
					 m_H[4],
					 m_H[5],
					 m_H[6],
					 m_H[7]));
			EAP_SHA_256_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA_256,
					(EAPL("SHA_256:\t% 4s\t% 8s\t% 8s\t% 8s\t% 8s\t% 8s\t% 8s\t% 8s\t% 8s\t% 8s\t% 8s\t% 8s\t% 8s\n"),
					"t", "A", "B", "C", "D", "E", "F", "G", "H", "T1", "T2", "S0", "S1"));
		}
		#endif //#if defined(_DEBUG)


		A = m_H[0];
		B = m_H[1];
		C = m_H[2];
		D = m_H[3];
		E = m_H[4];
		F = m_H[5];
		G = m_H[6];
		H = m_H[7];


		{
			for(u32_t ind = 0; ind != EAP_AM_CRYPTO_SHA_256_SCHEDULE_u32_COUNT; ind++)
			{
				S0 = eap_sha_256_rotate(A, 2) ^ eap_sha_256_rotate(A, 13) ^ eap_sha_256_rotate(A, 22);
				T2 = S0 + ((A & B) ^ (A & C) ^ (B & C));
				S1 = eap_sha_256_rotate(E, 6) ^ eap_sha_256_rotate(E, 11) ^ eap_sha_256_rotate(E, 25);
				T1 =  H + S1 + ((E & F) ^ ((~E) & G)) + m_K[ind] + W[ind];

				H = G;
				G = F;
				F = E;
				E = D + T1;
				D = C;
				C = B;
				B = A;
				A = T1 + T2;

				EAP_SHA_256_TRACE_DEBUG(
					m_am_tools,
					EAP_TRACE_MASK_SHA_256,
					(EAPL("SHA_256:\tt=%d\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\n"),
					 ind, A, B, C, D, E, F, G, H, T1, T2, S0, S1));
			}
		}

		m_H[0] = m_H[0] + A;
		m_H[1] = m_H[1] + B;
		m_H[2] = m_H[2] + C;
		m_H[3] = m_H[3] + D;
		m_H[4] = m_H[4] + E;
		m_H[5] = m_H[5] + F;
		m_H[6] = m_H[6] + G;
		m_H[7] = m_H[7] + H;

		M_count -= EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT;
		M += EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT;

	} while(M_count > 0ul);

	EAP_SHA_256_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA_256,
					(EAPL("SHA_256: digest=%08x %08x %08x %08x %08x %08x %08x %08x\n"),
					 m_H[0], m_H[1], m_H[2], m_H[3], m_H[4], m_H[5], m_H[6], m_H[7]));

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e
eap_am_crypto_sha_256_c::eap_sha_256_process_data_network_order(
	const u32_t * M,
	u32_t M_count
	)
{
	if (M == 0
		//|| (reinterpret_cast<u32_t>(M) % sizeof(u32_t)) != 0
		|| M_count == 0
		|| (M_count % EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT) != 0)
	{
		EAP_ASSERT_ANYWAY;
		EAP_SYSTEM_DEBUG_BREAK();
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = eap_status_ok;

	// Array of 16 temporary 32-bit unsigned integers.
	u32_t count = M_count / EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT;	

	for (u32_t ind = 0ul; ind != count; ind++)
	{	
		for (u32_t ind_M = 0ul; ind_M != EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT
				 ; ind_M++)
		{
			// Here we must read data in 8-bit blocks bacause M can be aligned at any position.
			const u8_t * const data
				= reinterpret_cast<const u8_t *>(
					&M[ind*EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT+ind_M]);

			m_M_in_host_order[ind_M]
				= (data[0] << 24)
				| (data[1] << 16)
				| (data[2] <<  8)
				| (data[3] <<  0);
		} // for()
	
		status = eap_sha_256_process_data_host_order(
			m_M_in_host_order,
			EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	
	} // for()
	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_sha_256_c::copy_message_digest(
	void * const output,
	u32_t * const max_output_size)
{
	if (output == 0
		|| max_output_size == 0
		|| *max_output_size < EAP_AM_CRYPTO_SHA_256_DIGEST_BUFFER_BYTE_SIZE)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

#if defined(EAP_LITTLE_ENDIAN)
	// We must change the data from host order to network order.
	u32_t * const tmp_H = static_cast<u32_t *>(output);
	for (u32_t ind = 0ul; ind != EAP_AM_CRYPTO_SHA_256_DIGEST_BUFFER_u32_COUNT
			 ; ind++)
	{
		tmp_H[ind] = eap_htonl(m_H[ind]);
	} // for()

#elif defined(EAP_BIG_ENDIAN)

	m_am_tools->memmove(
		output,
		m_H,
		EAP_AM_CRYPTO_SHA_256_DIGEST_BUFFER_BYTE_SIZE);

#else
#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
#endif

	*max_output_size = EAP_AM_CRYPTO_SHA_256_DIGEST_BUFFER_BYTE_SIZE;

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

/**
 * This function returns the size of message digest of HASH-algorithm.
 */
EAP_FUNC_EXPORT u32_t eap_am_crypto_sha_256_c::get_digest_length()
{
	return EAP_AM_CRYPTO_SHA_256_DIGEST_BUFFER_BYTE_SIZE;
}

//--------------------------------------------------

/**
 * This function returns the size of block of HASH-algorithm.
 */
EAP_FUNC_EXPORT u32_t eap_am_crypto_sha_256_c::get_block_size()
{
	return EAP_AM_CRYPTO_SHA_256_BLOCK_BYTE_SIZE;
}

//--------------------------------------------------

/**
 * This function initializes the context of SHA_256-algorithm.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_sha_256_c::hash_init()
{
	m_full_hashed_data_length = 0ul;

	m_H[0] = static_cast<u32_t>(EAP_SHA_256_INIT_H0);
	m_H[1] = static_cast<u32_t>(EAP_SHA_256_INIT_H1);
	m_H[2] = static_cast<u32_t>(EAP_SHA_256_INIT_H2);
	m_H[3] = static_cast<u32_t>(EAP_SHA_256_INIT_H3);
	m_H[4] = static_cast<u32_t>(EAP_SHA_256_INIT_H4);
	m_H[5] = static_cast<u32_t>(EAP_SHA_256_INIT_H5);
	m_H[6] = static_cast<u32_t>(EAP_SHA_256_INIT_H6);
	m_H[7] = static_cast<u32_t>(EAP_SHA_256_INIT_H7);

	if (m_saved_data.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = m_saved_data.set_data_length(0ul);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
/**
 * This function updates the context of SHA_256-algorithm with data.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_sha_256_c::hash_update(
	const void * const data,
	const u32_t data_length)
{
	eap_status_e status = eap_status_ok;
	u32_t prosessed_data_length = 0ul;
	
		
	m_full_hashed_data_length += data_length;

	EAP_SHA_256_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA_256,
					(EAPL("SHA_256: Processed data length %u\n"),
					 m_full_hashed_data_length));

	if (m_saved_data.get_is_valid_data() == true
		&& m_saved_data.get_data_length() > 0ul)
	{
		EAP_SHA_256_TRACE_DATA_DEBUG(
			m_am_tools,
			EAP_TRACE_MASK_SHA_256,
			(EAPL("SHA_256 saved data"),
			 m_saved_data.get_data(m_saved_data.get_data_length()),
			 m_saved_data.get_data_length()));
		
		// Here we have remaining data to process from previous call
		// of hash_update().
		u32_t needed_data_length = EAP_AM_CRYPTO_SHA_256_BLOCK_BYTE_SIZE
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
			== EAP_AM_CRYPTO_SHA_256_BLOCK_BYTE_SIZE)
		{
			// Enough data to process.
			// Just one block of integers in W array.

			status = eap_sha_256_process_data_network_order(
				reinterpret_cast<const u32_t *>(
					m_saved_data.get_data(
						m_saved_data.get_data_length())),
				EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT
				);
		
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// This is optimization of buffer allocations.
			status = m_saved_data.set_data_length(0ul);
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		
		EAP_ASSERT(m_saved_data.get_is_valid_data() == false
		|| m_saved_data.get_data_length()
			   <= EAP_AM_CRYPTO_SHA_256_BLOCK_BYTE_SIZE);
	
	}

	u32_t remaining_data_length = data_length - prosessed_data_length;
	u32_t full_block_count = remaining_data_length
		/ EAP_AM_CRYPTO_SHA_256_BLOCK_BYTE_SIZE;

	if (full_block_count > 0ul)
	{
		// Here we have full blocks to process.
		status = eap_sha_256_process_data_network_order(
			reinterpret_cast<const u32_t *>(
				static_cast<const u8_t *>(data)+prosessed_data_length),
			full_block_count * EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT
			);
		
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		prosessed_data_length += sizeof(u32_t) * full_block_count
			* EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT;
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
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_sha_256_c::hash_final(
	void * const message_digest,
	u32_t *md_length_or_null)
{
	eap_status_e status = eap_status_ok;

	if (message_digest == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_saved_data.get_is_valid_data() == true)
	{
		EAP_SHA_256_TRACE_DATA_DEBUG(
			m_am_tools,
			EAP_TRACE_MASK_SHA_256,
			(EAPL("SHA_256 saved data"),
			 m_saved_data.get_data(m_saved_data.get_data_length()),
			 m_saved_data.get_data_length()));
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
	u32_t block_count = min_data_length / EAP_AM_CRYPTO_SHA_256_BLOCK_BYTE_SIZE;
	if ((min_data_length % EAP_AM_CRYPTO_SHA_256_BLOCK_BYTE_SIZE) != 0)
	{
		// Last block is not full.
		++block_count;
	}
	padding_zero_count = (block_count*EAP_AM_CRYPTO_SHA_256_BLOCK_BYTE_SIZE)
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
	u64_t full_hashed_data_length_in_network_order
		= eap_htonll(eap_shift_left_64_bit(m_full_hashed_data_length, 3ul));
	status = m_saved_data.add_data(
		&full_hashed_data_length_in_network_order,
		sizeof(full_hashed_data_length_in_network_order));
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_ASSERT(m_saved_data.get_data_length()
			   >= EAP_AM_CRYPTO_SHA_256_BLOCK_BYTE_SIZE
			   && (m_saved_data.get_data_length()
				   % EAP_AM_CRYPTO_SHA_256_BLOCK_BYTE_SIZE) == 0);

	u32_t full_block_count = m_saved_data.get_data_length()
		/ EAP_AM_CRYPTO_SHA_256_BLOCK_BYTE_SIZE;

	status = eap_sha_256_process_data_network_order(
		reinterpret_cast<const u32_t *>(
			m_saved_data.get_data(
				m_saved_data.get_data_length())),
		full_block_count * EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT
		);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// This is optimization of buffer allocations.
	status = m_saved_data.set_data_length(0ul);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	u32_t output_length = 0ul;
	if (md_length_or_null == 0)
	{
		// Let's use temporary length variable.
		output_length = EAP_AM_CRYPTO_SHA_256_DIGEST_BUFFER_BYTE_SIZE;
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
 * This function cleans up the SHA_256 context.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_sha_256_c::hash_cleanup()
{
	m_saved_data.reset();

	m_full_hashed_data_length = 0ul;

	m_am_tools->memset(m_H, 0, EAP_AM_CRYPTO_SHA_256_DIGEST_BUFFER_BYTE_SIZE);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

/**
 * This function copies the context of SHA_256.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_sha_256_c::copy_context(
	const eap_variable_data_c * const saved_data,
	const u64_t full_hashed_data_length,
	const u32_t * const H,
	const u32_t * const T,
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

	m_am_tools->memmove(m_T, T, sizeof(m_T));

	m_am_tools->memmove(m_M_in_host_order, W_in_host_order, sizeof(m_M_in_host_order));

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

/**
 * This function copies the context of SHA_256.
 */
EAP_FUNC_EXPORT eap_am_crypto_sha_256_c * eap_am_crypto_sha_256_c::copy()
{
	eap_am_crypto_sha_256_c * const sha_256 = new eap_am_crypto_sha_256_c(m_am_tools);
	if (sha_256 == 0
		|| sha_256->get_is_valid() == false)
	{
		delete sha_256;
		return 0;
	}

	eap_status_e status = sha_256->copy_context(
		&m_saved_data,
		m_full_hashed_data_length,
		m_H,
		m_T,
		m_M_in_host_order);
	if (status != eap_status_ok)
	{
		delete sha_256;
		return 0;
	}

	return sha_256;
}

//--------------------------------------------------



// End.
