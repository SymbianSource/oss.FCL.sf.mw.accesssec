/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wapi_am_crypto_sms4.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 5 % << Don't touch! Updated by Synergy at check-out.
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
* Template version: 4.2
*/


//------------------------------------------------------------

#if !defined(_WAPI_AM_CRYPTO_SMS4_H_)
#define _WAPI_AM_CRYPTO_SMS4_H_

#include "eap_am_types.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
#include "eap_am_tools.h"

#if defined(ecb_encrypt)
#undef ecb_encrypt
#endif //#if defined(ecb_encrypt)

//------------------------------------------------------------

/// This class implements the SMS4 block cipher used in WAPI
class EAP_EXPORT wapi_am_crypto_sms4_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	enum wapi_sms4_sizes
	{
		WAPI_AM_CRYPTO_SMS4_KEY_u8_SIZE = 16ul, ///< 16 u8_t integers
		WAPI_AM_CRYPTO_SMS4_BLOCK_u8_SIZE = 16ul, ///< 16 u8_t integers
		WAPI_AM_CRYPTO_SMS4_CK_u32_COUNT = 32ul, ///< 32 u32_t integers
		WAPI_AM_CRYPTO_SMS4_FK_u32_COUNT = 4ul, ///< 4 u32_t integers 
		WAPI_AM_CRYPTO_SMS4_SBOX_u8_SIZE = 256ul, ///< 256 u8_t integers
		WAPI_AM_CRYPTO_SMS4_KEY_SCHEDULE_u32_SIZE = 32ul ///< 32 u32_t integers
	};

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// Round keys are stored into this variable.
	u32_t m_key_schedule[WAPI_AM_CRYPTO_SMS4_KEY_SCHEDULE_u32_SIZE];

	static const u32_t m_CK[WAPI_AM_CRYPTO_SMS4_CK_u32_COUNT];
	static const u32_t m_FK[WAPI_AM_CRYPTO_SMS4_FK_u32_COUNT];
	static const u8_t m_SBOX[WAPI_AM_CRYPTO_SMS4_SBOX_u8_SIZE];

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The set_is_invalid() function sets the state of the object invalid. 
	 */
	EAP_FUNC_IMPORT void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the object valid. 
	 */
	EAP_FUNC_IMPORT void set_is_valid();

	EAP_FUNC_IMPORT void L_key( u32_t* data );

	EAP_FUNC_IMPORT void L_data( u32_t* data );

	EAP_FUNC_IMPORT void sms4_substitute( u32_t* data );

	EAP_FUNC_IMPORT eap_status_e ecb_process_data(
		const void * const data_in, 
		void * const data_out,
		const u32_t data_blocks,
		bool encrypt);  /// < true for encrypt, false for decrypt

	// cyclic left shift
	inline u32_t sms4_rotate_left(
		const u32_t value,
		const u32_t shift)
	{
		return (value << shift) | (value >> (32ul - shift));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_IMPORT virtual ~wapi_am_crypto_sms4_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_IMPORT wapi_am_crypto_sms4_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the object. 
	 * True indicates the object is allocated successfully.
	 */
	EAP_FUNC_IMPORT bool get_is_valid();

	/**
	 * This function sets the SMS4 key
	 * and generates the key schedule (i.e. intializes 
	 * the context).
	 */
	EAP_FUNC_IMPORT eap_status_e set_key(
		const eap_variable_data_c * const key);

	/**
	 * Returns the size of SMS4 key. 
	 * This will be constant 16 bytes (128 bits).
	 */
	EAP_FUNC_IMPORT u32_t get_key_size();

	/**
	 * Returns the SMS4 block size. 
	 * This will be constant 16 bytes (128 bits).
	 */
	EAP_FUNC_IMPORT u32_t get_block_size();

	/**
	 * This function performs SMS4 encryption
	 * for input data blocks in ECB mode. The length of data must 
	 * be aligned to the block size of SMS4.
	 */
	EAP_FUNC_IMPORT eap_status_e ecb_encrypt(
		const void * const data_in, 
		void * const data_out,
		const u32_t data_blocks ///< This is the number of blocks to be processed
		);

	/**
	 * This function performs SMS4 decryption
	 * for input data blocks in ECB mode. The length of data must 
	 * be aligned to the block size of SMS4.
	 */
	EAP_FUNC_IMPORT eap_status_e ecb_decrypt(
		const void * const data_in, 
		void * const data_out,
		const u32_t data_blocks ///< This is the number of blocks to be processed
		);
};

#endif //#if !defined(_WAPI_AM_CRYPTO_SMS4_H_)

//------------------------------------------------------------



// End.
