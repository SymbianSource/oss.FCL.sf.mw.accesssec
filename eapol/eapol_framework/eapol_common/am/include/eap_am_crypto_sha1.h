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

#if !defined( _EAP_AM_CRYPTO_SHA1_H_ )
#define _EAP_AM_CRYPTO_SHA1_H_

#include "eap_am_types.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_CRYPTO_SHA1_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_SHA1_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H 
	#define EAP_FUNC_EXPORT_EAP_AM_CRYPTO_SHA1_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_CRYPTO_SHA1_H 
#elif defined(EAP_EXPORT_EAP_AM_CRYPTO_SHA1_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_SHA1_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_CRYPTO_SHA1_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_CRYPTO_SHA1_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_SHA1_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_CRYPTO_SHA1_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_CRYPTO_SHA1_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_am_tools.h"


//--------------------------------------------------

/// The eap_am_crypto_sha1_c class includes the state of 
/// one instance of SHA1 algorithm.
class EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_SHA1_H eap_am_crypto_sha1_c
{

private:
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	enum eap_sha1_H_init
	{
		EAP_SHA1_INIT_H0 = 0x67452301ul,
		EAP_SHA1_INIT_H1 = 0xefcdab89ul,
		EAP_SHA1_INIT_H2 = 0x98badcfeul,
		EAP_SHA1_INIT_H3 = 0x10325476ul,
		EAP_SHA1_INIT_H4 = 0xc3d2e1f0ul,
	};

	enum eap_sha1_K
	{
		EAP_SHA1_K__0_19 = 0x5a827999ul,
		EAP_SHA1_K_20_39 = 0x6ed9eba1ul,
		EAP_SHA1_K_40_59 = 0x8f1bbcdcul,
		EAP_SHA1_K_60_79 = 0xca62c1d6ul,
	};

	enum eap_sha1_sizes
	{
		EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT = 16ul, ///< 16 u32_t integers.
		EAP_AM_CRYPTO_SHA1_BLOCK_BYTE_SIZE
			= EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT
			* sizeof(u32_t), ///< in bytes.
		EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_u32_COUNT
			= 5ul, ///< 5 u32_t integers.
		EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_BYTE_SIZE
			= EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_u32_COUNT
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

	/// Array of 16 temporary 32-bit unsigned integers.
	u32_t m_T[EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT];

	
	u32_t m_W_in_host_order[EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT];

	/// This buffer saves the digest value between subsequent call
	/// of hash_update().
	u32_t m_H[EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_u32_COUNT];

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	inline u32_t eap_sha1_rotate(
		const u32_t value,
		const u32_t shift
		);

	inline u32_t eap_sha1_b_substitution(
		const u32_t Wt_3,
		const u32_t Wt_8,
		const u32_t Wt_14,
		const u32_t Wt_16
		);

	inline u32_t eap_sha1_ft_0_19(
		const u32_t B,
		const u32_t C,
		const u32_t D
		);

	inline u32_t eap_sha1_ft_20_39(
		const u32_t B,
		const u32_t C,
		const u32_t D
		);

	inline u32_t eap_sha1_ft_40_59(
		const u32_t B,
		const u32_t C,
		const u32_t D
		);

	inline u32_t eap_sha1_ft_60_79(
		const u32_t B,
		const u32_t C,
		const u32_t D
		);

	inline void d_substitution(
		u32_t * const A,
		u32_t * const B,
		u32_t * const C,
		u32_t * const D,
		u32_t * const E,
		const u32_t temp
		);

	inline void d_substitution_0_15(
		const u32_t t,
		u32_t * const A,
		u32_t * const B,
		u32_t * const C,
		u32_t * const D,
		u32_t * const E,
		const u32_t Wt
		);

	inline void d_substitution_16_19(
		const u32_t t,
		u32_t * const A,
		u32_t * const B,
		u32_t * const C,
		u32_t * const D,
		u32_t * const E,
		u32_t * const Wt,
		const u32_t Wt_3,
		const u32_t Wt_8,
		const u32_t Wt_14,
		const u32_t Wt_16
		);

	inline void d_substitution_20_39(
		const u32_t t,
		u32_t * const A,
		u32_t * const B,
		u32_t * const C,
		u32_t * const D,
		u32_t * const E,
		u32_t * const Wt,
		const u32_t Wt_3,
		const u32_t Wt_8,
		const u32_t Wt_14,
		const u32_t Wt_16
		);

	inline void d_substitution_40_59(
		const u32_t t,
		u32_t * const A,
		u32_t * const B,
		u32_t * const C,
		u32_t * const D,
		u32_t * const E,
		u32_t * const Wt,
		const u32_t Wt_3,
		const u32_t Wt_8,
		const u32_t Wt_14,
		const u32_t Wt_16
		);

	inline void d_substitution_60_79(
		const u32_t t,
		u32_t * const A,
		u32_t * const B,
		u32_t * const C,
		u32_t * const D,
		u32_t * const E,
		u32_t * const Wt,
		const u32_t Wt_3,
		const u32_t Wt_8,
		const u32_t Wt_14,
		const u32_t Wt_16
		);
	
	/// @param W is an array of modulo 16 input 32-bit unsigned integers
	/// in host order.
	/// @param W_count is count of integers in W array.
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H eap_status_e eap_sha1_process_data_host_order(
		const u32_t * W,
		u32_t W_count
		);

	/// @param W is an array of modulo 16 input 32-bit unsigned integers
	/// in host order.
	/// @param W_count is count of integers in W array.
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H eap_status_e eap_sha1_process_data_network_order(
		const u32_t * W,
		u32_t W_count
		);

	/**
	 * This function cleans up the SHA1 context.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H eap_status_e hash_cleanup();

	/**
	 * This function copies the message digest to output buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H eap_status_e copy_message_digest(
		void * const output,
		u32_t * const max_output_size);


	/**
	 * The set_is_invalid() function sets the state of the eap_am_crypto_md4_c
	 * object invalid. 
	 * The eap_am_crypto_md4_c object calls this function after it is
	 * initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the eap_am_crypto_md4_c
	 * object valid. 
	 * The eap_am_crypto_md4_c object calls this function after it is
	 * initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H void set_is_valid();

	/**
	 * This function copies the context of SHA1.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H eap_status_e copy_context(
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
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H virtual ~eap_am_crypto_sha1_c();

	/**
	 * Constructor initializes the member attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H eap_am_crypto_sha1_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the
	 * eap_am_crypto_md4_c object. 
	 * True indicates the object is allocated successfully.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H bool get_is_valid();

	/**
	 * This function returns the size of message digest of HASH-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H u32_t get_digest_length();

	/**
	 * This function returns the size of block of HASH-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H u32_t get_block_size();

	/**
	 * This function initializes the context of SHA1-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H eap_status_e hash_init();

	/**
	 * This function updates the context of SHA1-algorithm with data.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H eap_status_e hash_update(
		const void * const data,
		const u32_t data_length);

	/**
	 * This function writes the message digest to buffer.
	 * @param Length is set if md_length_or_null is non-NULL.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H eap_status_e hash_final(
		void * const message_digest,
		u32_t *md_length_or_null);

	/**
	 *  
	 *  eap_sha1_dss_G_function() implements the G() function using
	 *  modified SHA-1 using the routine in Appendix 3.3 Constructing
	 *  The Function G From SHA-1 in the SECURE HASH STANDARD, FIPS PUB 180-1.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H eap_status_e eap_sha1_dss_G_function(
		const void * const data,
		const u32_t data_length,
		void * const output,
		u32_t * const output_length
		);

	/**
	 * This function copies the context of SHA1.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_SHA1_H eap_am_crypto_sha1_c * copy();

};

//--------------------------------------------------

#endif //#if !defined( _EAP_AM_CRYPTO_OPENSSL_H_ )



// End.
