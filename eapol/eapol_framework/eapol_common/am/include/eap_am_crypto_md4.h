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

#if !defined( _EAP_AM_CRYPTO_MD4_H_ )
#define _EAP_AM_CRYPTO_MD4_H_

#include "eap_am_types.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_CRYPTO_MD4_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_MD4_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H 
	#define EAP_FUNC_EXPORT_EAP_AM_CRYPTO_MD4_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_CRYPTO_MD4_H 
#elif defined(EAP_EXPORT_EAP_AM_CRYPTO_MD4_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_MD4_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_CRYPTO_MD4_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_CRYPTO_MD4_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_MD4_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_CRYPTO_MD4_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_CRYPTO_MD4_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_am_tools.h"


//--------------------------------------------------

/// The eap_am_crypto_md4_c class includes the state of 
/// one instance of MD4 algorithm.
class EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_MD4_H eap_am_crypto_md4_c
{

private:
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	enum eap_md4_init
	{
		EAP_MD4_INIT_H0 = 0x67452301ul,
		EAP_MD4_INIT_H1 = 0xefcdab89ul,
		EAP_MD4_INIT_H2 = 0x98badcfeul,
		EAP_MD4_INIT_H3 = 0x10325476ul,
	};

	enum eap_md4_const
	{
		eap_md4_const_S11 =  3,
		eap_md4_const_S12 =  7,
		eap_md4_const_S13 = 11,
		eap_md4_const_S14 = 19,
		eap_md4_const_S21 =  3,
		eap_md4_const_S22 =  5,
		eap_md4_const_S23 =  9,
		eap_md4_const_S24 = 13,
		eap_md4_const_S31 =  3,
		eap_md4_const_S32 =  9,
		eap_md4_const_S33 = 11,
		eap_md4_const_S34 = 15,
	};

	enum eap_md4_sizes
	{
		EAP_AM_CRYPTO_MD4_BLOCK_u32_COUNT = 16ul, ///< 16 u32_t integers.
		EAP_AM_CRYPTO_MD4_BLOCK_BYTE_SIZE
			= EAP_AM_CRYPTO_MD4_BLOCK_u32_COUNT * sizeof(u32_t), ///< in bytes.
		EAP_AM_CRYPTO_MD4_DIGEST_BUFFER_u32_COUNT = 4ul, ///< 4 u32_t integers.
		EAP_AM_CRYPTO_MD4_DIGEST_BUFFER_BYTE_SIZE
			= EAP_AM_CRYPTO_MD4_DIGEST_BUFFER_u32_COUNT
			* sizeof(u32_t), ///< in bytes.
	};

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This buffer saves remaining data between subsequent calls 
	/// of hash_update().
	eap_variable_data_c m_saved_data;

	/// This attribute saves the length of hashed data.
	u64_t m_full_hashed_data_length;

	u32_t m_W_in_host_order[EAP_AM_CRYPTO_MD4_BLOCK_u32_COUNT];

	/// This buffer saves the digest value between subsequent calls 
	/// of hash_update().
	u32_t m_H[EAP_AM_CRYPTO_MD4_DIGEST_BUFFER_u32_COUNT];

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	inline u32_t eap_md4_F(
		const u32_t X,
		const u32_t Y,
		const u32_t Z
		);

	inline u32_t eap_md4_G(
		const u32_t X,
		const u32_t Y,
		const u32_t Z
		);

	inline u32_t eap_md4_H(
		const u32_t X,
		const u32_t Y,
		const u32_t Z
		);

	inline u32_t eap_md4_rotate_left(
		const u32_t value,
		const u32_t shift
		);

	inline void eap_md4_FF(
		const u32_t index,
		u32_t * const A,
		const u32_t B,
		const u32_t C,
		const u32_t D,
		const u32_t X,
		const u32_t S
		);

	inline void eap_md4_GG(
		const u32_t index,
		u32_t * const A,
		const u32_t B,
		const u32_t C,
		const u32_t D,
		const u32_t X,
		const u32_t S
		);

	inline void eap_md4_HH(
		const u32_t index,
		u32_t * const A,
		const u32_t B,
		const u32_t C,
		const u32_t D,
		const u32_t X,
		const u32_t S
		);

	/// @param W is an array of 16 input 32-bit unsigned integers
	/// in host order.
	/// @param W_count is count of integers in W array.
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H eap_status_e eap_md4_transform_host_order(
		const u32_t * const W,
		const u32_t W_count
		);

	/// @param W is an array of 16 input 32-bit unsigned integers
	/// in network order.
	/// @param W_count is count of integers in W array.
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H eap_status_e eap_md4_process_data(
		const u32_t * const W,
		const u32_t W_count
		);

	/**
	 * This function cleans up the MD4 context.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H eap_status_e hash_cleanup();

	/**
	 * This function copies the message digest to output buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H eap_status_e copy_message_digest(
		void * const output,
		u32_t * const max_output_size);


	/**
	 * The set_is_invalid() function sets the state of the eap_am_crypto_md4_c
	 * object invalid. 
	 * The eap_am_crypto_md4_c object calls this function after it is
	 * initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the eap_am_crypto_md4_c
	 * object valid. 
	 * The eap_am_crypto_md4_c object calls this function after it is
	 * initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H void set_is_valid();

	/**
	 * This function copies the context of MD4.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H eap_status_e copy_context(
		const eap_variable_data_c * const saved_data,
		const u64_t full_hashed_data_length,
		const u32_t * const H,
		const u32_t * const W_in_host_order);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H virtual ~eap_am_crypto_md4_c();

	/**
	 * Constructor initializes the member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H eap_am_crypto_md4_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the
	 * eap_am_crypto_md4_c object. 
	 * True indicates the object is allocated successfully.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H bool get_is_valid();

	/**
	 * This function returns the size of message digest of HASH-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H u32_t get_digest_length();

	/**
	 * This function returns the size of block of HASH-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H u32_t get_block_size();

	/**
	 * This function initializes the context of MD4-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H eap_status_e hash_init();

	/**
	 * This function updates the context of MD4-algorithm with data.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H eap_status_e hash_update(
		const void * const data,
		const u32_t data_length);

	/**
	 * This function writes the message digest to buffer.
	 * @param Length is set if md_length_or_null is non-NULL.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H eap_status_e hash_final(
		void * const message_digest,
		u32_t *md_length_or_null);

	/**
	 * This function copies the context of MD4.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_MD4_H eap_am_crypto_md4_c * copy();
};

//--------------------------------------------------

#endif //#if !defined( _EAP_AM_CRYPTO_OPENSSL_H_ )



// End.
