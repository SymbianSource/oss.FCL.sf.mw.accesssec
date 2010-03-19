/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wapi_am_crypto_sms4.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 4 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.1.1
*/

// This is enumeration of WAPI source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 20010 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"
#include "wapi_am_crypto_sms4.h"


//------------------------------------------------------------
// SMS4 constants 

// CK
const u32_t wapi_am_crypto_sms4_c::m_CK[wapi_am_crypto_sms4_c::WAPI_AM_CRYPTO_SMS4_CK_u32_COUNT] =
{
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// FK
const u32_t wapi_am_crypto_sms4_c::m_FK[wapi_am_crypto_sms4_c::WAPI_AM_CRYPTO_SMS4_FK_u32_COUNT] =
{
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};


// S-box
const u8_t wapi_am_crypto_sms4_c::m_SBOX[wapi_am_crypto_sms4_c::WAPI_AM_CRYPTO_SMS4_SBOX_u8_SIZE] =
{
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

//------------------------------------------------------------



EAP_FUNC_EXPORT wapi_am_crypto_sms4_c::~wapi_am_crypto_sms4_c()
{
	m_is_valid = false;
}

//------------------------------------------------------------

EAP_FUNC_EXPORT wapi_am_crypto_sms4_c::wapi_am_crypto_sms4_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(false)
{
	set_is_valid();
}

//------------------------------------------------------------

EAP_FUNC_EXPORT void wapi_am_crypto_sms4_c::set_is_invalid()
{
	m_is_valid = false;
}

//------------------------------------------------------------

EAP_FUNC_EXPORT void wapi_am_crypto_sms4_c::set_is_valid()
{
	m_is_valid = true;
}

//------------------------------------------------------------

EAP_FUNC_EXPORT bool wapi_am_crypto_sms4_c::get_is_valid()
{
	return m_is_valid;
}

//------------------------------------------------------------

EAP_FUNC_EXPORT u32_t wapi_am_crypto_sms4_c::get_key_size()
{
	return WAPI_AM_CRYPTO_SMS4_KEY_u8_SIZE;
}

//------------------------------------------------------------

EAP_FUNC_EXPORT u32_t wapi_am_crypto_sms4_c::get_block_size()
{
	return WAPI_AM_CRYPTO_SMS4_BLOCK_u8_SIZE;
}

//------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_crypto_sms4_c::set_key(
	const eap_variable_data_c * const p_key)
{

	// key in network order

	// check if key is ok
	if( p_key == 0 ||
		p_key->get_is_valid() == false ||
		p_key->get_data_length() != WAPI_AM_CRYPTO_SMS4_KEY_u8_SIZE )
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_encryption_parameter_size);
	}

	// temporary table to hold the currently
	// needed key data words
	u32_t key_table[WAPI_AM_CRYPTO_SMS4_KEY_u8_SIZE/4];
	u32_t ind = 0;

	for( ind = 0; ind < WAPI_AM_CRYPTO_SMS4_KEY_u8_SIZE/4; ++ind )
	{
		// read key from variable data to a u32_t table for faster processing
		// TODO: Is this ok for endianness on other platforms?
		key_table[ind] = eap_read_u32_t_network_order(p_key->get_data() + ind*4, 4);
	}
		
	// temporary variable to hold the current
	// expansion result (one word)
	u32_t tmp_K;

	// XOR key words with FKs
	for( ind = 0; ind < WAPI_AM_CRYPTO_SMS4_KEY_u8_SIZE/4; ++ind )
	{
		key_table[ind] = key_table[ind] ^ m_FK[ind];
	}

	// compute the key expansion
	for( ind = 0; ind < WAPI_AM_CRYPTO_SMS4_KEY_SCHEDULE_u32_SIZE; ++ind )
	{

		// See SMS4 spec for these
		tmp_K = key_table[1] ^ key_table[2] ^ key_table[3] ^ m_CK[ind];
		sms4_substitute( &tmp_K );
		L_key( &tmp_K );
		tmp_K ^= key_table[0];

		// store the result for the next round
		key_table[0] = key_table[1];
		key_table[1] = key_table[2];
		key_table[2] = key_table[3];
		key_table[3] = tmp_K;

		// store the expansion result
		m_key_schedule[ind] = tmp_K;

	} // for()


	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//------------------------------------------------------------

/*
 * Performs L' function for a key word.
 */

EAP_FUNC_EXPORT void wapi_am_crypto_sms4_c::L_key( u32_t* data )
{
	*data ^= sms4_rotate_left(*data, 13) ^ sms4_rotate_left(*data, 23);
	return;
}

//------------------------------------------------------------

/*
 * Performs S-box substitution for a data word,
 * i.e. four S-box substitutions.
 */

EAP_FUNC_EXPORT void wapi_am_crypto_sms4_c::sms4_substitute( u32_t* data )
{	
	u8_t* tmp = reinterpret_cast<u8_t*>(data);

	// S-box substitution to the bytes of the word
	*tmp = m_SBOX[*tmp];
	*(tmp+1) = m_SBOX[*(tmp+1)];
	*(tmp+2) = m_SBOX[*(tmp+2)];
	*(tmp+3) = m_SBOX[*(tmp+3)];

	return;
}

//------------------------------------------------------------

/*
 * Performs L function for a data word.
 */

EAP_FUNC_EXPORT void wapi_am_crypto_sms4_c::L_data( u32_t* data )
{
	*data ^= 
		sms4_rotate_left(*data, 2) ^ 
		sms4_rotate_left(*data, 10) ^ 
		sms4_rotate_left(*data, 18) ^
		sms4_rotate_left(*data, 24);
	return;
}

//------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_crypto_sms4_c::ecb_process_data(
	const void * const data_in, 
	void * const data_out,
	const u32_t data_blocks,
	bool encrypt)
{

	// data in network order

	// check if data is ok
	if( data_in == 0 ||
		data_out == 0 ||
		data_blocks <= 0 )
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_encryption_parameter_size);
	}

	// temporary pointers to data_in and data_out
	const u8_t* p_data_in = reinterpret_cast<const u8_t*>(data_in);
	u8_t* p_data_out = reinterpret_cast<u8_t*>(data_out);

	// count of the processed blocks
	u32_t blocks_processed = 0;

	// temporary table to hold the currently needed data words
	u32_t data_table[WAPI_AM_CRYPTO_SMS4_BLOCK_u8_SIZE/4];
	u32_t ind = 0;
	eap_status_e status(eap_status_ok);

	// temporary variable to hold the current result (one word)
	u32_t tmp_X;

	// ecrypt data in ECB mode
	while( blocks_processed < data_blocks ) 
	{

		for( ind = 0; ind < 4; ++ind )
		{
			// read network order data to a u32_t table for faster processing
			// TODO: Is this ok for endianness on other platforms?
			data_table[ind] = eap_read_u32_t_network_order(p_data_in + ind*4, 4);
		}
		
		// execute the SMS4 rounds
		for( ind = 0; ind < 32; ++ind )
		{

			// See SMS4 spec for these
			tmp_X = data_table[1] ^ data_table[2] ^ data_table[3];

			if( encrypt == true )
			{
				tmp_X ^= m_key_schedule[ind];
			}
			else
			{
				// in decryption the key schedule is reversed
				tmp_X ^= m_key_schedule[WAPI_AM_CRYPTO_SMS4_KEY_SCHEDULE_u32_SIZE-1-ind];
			}

			sms4_substitute( &tmp_X );
			L_data( &tmp_X );
			tmp_X ^= data_table[0];

			// store the result for the next round
			data_table[0] = data_table[1];
			data_table[1] = data_table[2];
			data_table[2] = data_table[3];
			data_table[3] = tmp_X;

		} // for()

		// the result of the final round is the output,
		// except that the order of the words is reversed 
		// (R function in the SMS4 spec)
		for( ind = 0; ind < 4; ++ind )
		{
			status = eap_write_u32_t_network_order( p_data_out+4*ind, 4, data_table[3-ind] );
			if( status != eap_status_ok )
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		++blocks_processed;
		// take the next data block for processing
		p_data_in += 16;
		p_data_out += 16;

	} // for()

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_crypto_sms4_c::ecb_encrypt(
	const void * const data_in, 
	void * const data_out,
	const u32_t data_blocks)
{
	eap_status_e status = ecb_process_data( data_in, data_out, data_blocks, true );
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_crypto_sms4_c::ecb_decrypt(
	const void * const data_in, 
	void * const data_out,
	const u32_t data_blocks)
{
	eap_status_e status = ecb_process_data( data_in, data_out, data_blocks, false );
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//------------------------------------------------------------

// End.
