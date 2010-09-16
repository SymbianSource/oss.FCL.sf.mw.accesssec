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

#if !defined( _EAP_AM_CRYPTO_SHA_256_H_ )
#define _EAP_AM_CRYPTO_SHA_256_H_

#include "eap_am_types.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_CRYPTO_SHA_256_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H 
	#define EAP_FUNC_EXPORT_EAP_AM_CRYPTO_SHA_256_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_CRYPTO_SHA_256_H 
#elif defined(EAP_EXPORT_EAP_AM_CRYPTO_SHA_256_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_CRYPTO_SHA_256_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_CRYPTO_SHA_256_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_CRYPTO_SHA_256_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_CRYPTO_SHA_256_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_am_tools.h"


//--------------------------------------------------

/// The eap_am_crypto_sha_256_c class includes the state of 
/// one instance of SHA_256 algorithm.
class EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H eap_am_crypto_sha_256_c
{

private:
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	enum eap_sha_256_H_init
	{
		EAP_SHA_256_INIT_H0 = 0x6a09e667,
		EAP_SHA_256_INIT_H1 = 0xbb67ae85,
		EAP_SHA_256_INIT_H2 = 0x3c6ef372,
		EAP_SHA_256_INIT_H3 = 0xa54ff53a,
		EAP_SHA_256_INIT_H4 = 0x510e527f,
		EAP_SHA_256_INIT_H5 = 0x9b05688c,
		EAP_SHA_256_INIT_H6 = 0x1f83d9ab,
		EAP_SHA_256_INIT_H7 = 0x5be0cd19,
	};

	enum eap_sha_256_sizes
	{
		EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT = 16ul, ///< 16 u32_t integers.
		EAP_AM_CRYPTO_SHA_256_BLOCK_BYTE_SIZE
			= EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT
			* sizeof(u32_t), ///< in bytes.
		EAP_AM_CRYPTO_SHA_256_DIGEST_BUFFER_u32_COUNT
			= 8ul, ///< 8 u32_t integers.
		EAP_AM_CRYPTO_SHA_256_DIGEST_BUFFER_BYTE_SIZE
			= EAP_AM_CRYPTO_SHA_256_DIGEST_BUFFER_u32_COUNT
			* sizeof(u32_t), ///< in bytes.
		EAP_AM_CRYPTO_SHA_256_SCHEDULE_u32_COUNT = 64ul, ///< 64 u32_t integers.
	};

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This buffer saves remaining data between subsequent calls
	/// of hash_update().
	eap_variable_data_c m_saved_data;

	/// This attribute saves the length of hashed data.
	u64_t m_full_hashed_data_length;

	/// Array of 16 temporary 32-bit unsigned integers.
	u32_t m_T[EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT];

	static const unsigned long m_K[EAP_AM_CRYPTO_SHA_256_SCHEDULE_u32_COUNT];
	
	u32_t m_M_in_host_order[EAP_AM_CRYPTO_SHA_256_BLOCK_u32_COUNT];

	/// This buffer saves the digest value between subsequent call
	/// of hash_update().
	u32_t m_H[EAP_AM_CRYPTO_SHA_256_DIGEST_BUFFER_u32_COUNT];

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	inline u32_t eap_sha_256_rotate(
		const u32_t value,
		const u32_t shift
		);

	/// @param W is an array of modulo 16 input 32-bit unsigned integers
	/// in host order.
	/// @param W_count is count of integers in W array.
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H eap_status_e eap_sha_256_process_data_host_order(
		const u32_t * W,
		u32_t W_count
		);

	/// @param W is an array of modulo 16 input 32-bit unsigned integers
	/// in host order.
	/// @param W_count is count of integers in W array.
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H eap_status_e eap_sha_256_process_data_network_order(
		const u32_t * W,
		u32_t W_count
		);

	/**
	 * This function cleans up the SHA_256 context.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H eap_status_e hash_cleanup();

	/**
	 * This function copies the message digest to output buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H eap_status_e copy_message_digest(
		void * const output,
		u32_t * const max_output_size);


	/**
	 * The set_is_invalid() function sets the state of the eap_am_crypto_md4_c
	 * object invalid. 
	 * The eap_am_crypto_md4_c object calls this function after it is
	 * initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the eap_am_crypto_md4_c
	 * object valid. 
	 * The eap_am_crypto_md4_c object calls this function after it is
	 * initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H void set_is_valid();

	/**
	 * This function copies the context of SHA_256.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H eap_status_e copy_context(
		const eap_variable_data_c * const saved_data,
		const u64_t full_hashed_data_length,
		const u32_t * const H,
		const u32_t * const T,
		const u32_t * const W_in_host_order);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H virtual ~eap_am_crypto_sha_256_c();

	/**
	 * Constructor initializes the member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H eap_am_crypto_sha_256_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the
	 * eap_am_crypto_md4_c object. 
	 * True indicates the object is allocated successfully.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H bool get_is_valid();

	/**
	 * This function returns the size of message digest of HASH-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H u32_t get_digest_length();

	/**
	 * This function returns the size of block of HASH-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H u32_t get_block_size();

	/**
	 * This function initializes the context of SHA_256-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H eap_status_e hash_init();

	/**
	 * This function updates the context of SHA_256-algorithm with data.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H eap_status_e hash_update(
		const void * const data,
		const u32_t data_length);

	/**
	 * This function writes the message digest to buffer.
	 * @param Length is set if md_length_or_null is non-NULL.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H eap_status_e hash_final(
		void * const message_digest,
		u32_t *md_length_or_null);

	/**
	 * This function copies the context of SHA_256.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA_256_H eap_am_crypto_sha_256_c * copy();

};

//--------------------------------------------------

#endif //#if !defined( _EAP_AM_CRYPTO_SHA_256_H_ )



// End.
