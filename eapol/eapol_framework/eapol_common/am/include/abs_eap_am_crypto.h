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

#if !defined( _ABS_EAP_AM_CRYPTO_H_ )
#define _ABS_EAP_AM_CRYPTO_H_

#include "eap_am_types.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_CRYPTO_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_CRYPTO_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_CRYPTO_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_CRYPTO_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_CRYPTO_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_CRYPTO_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_CRYPTO_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_CRYPTO_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_CRYPTO_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_CRYPTO_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_CRYPTO_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_CRYPTO_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_CRYPTO_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_CRYPTO_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_CRYPTO_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_CRYPTO_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_CRYPTO_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_am_tools.h"
#include "eap_array.h"

#if 0
const u32_t TRACE_FLAGS_EAP_AM_CRYPTO = 
	eap_am_tools_c::eap_trace_mask_crypto
	| eap_am_tools_c::eap_trace_mask_debug;
#else
const u32_t TRACE_FLAGS_EAP_AM_CRYPTO = 
	eap_am_tools_c::eap_trace_mask_crypto;
#endif

const u32_t EAP_AES_BLOCK_SIZE = 16u;

const u32_t EAP_3DES_EDE_CBC_BLOCK_SIZE = 8ul;


class abs_eap_am_tools_c;
class eap_variable_data_c;

/// Class eap_am_crypto offers services to authenticate data, encrypt data,
/// decrypt data, generate keys and generate cryptographically strong random data.
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_CRYPTO_H abs_eap_am_crypto_c
{
private:
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	/**
	 * Destructor does nothing special.
	 */
	 virtual ~abs_eap_am_crypto_c()
	 {
	 }

	/**
	 * The configure() function is called after the constructor of the 
	 * object is successfully executed. During the function call the object 
	 * could query the configuration. Each derived class must define this function.
	 * Needed configuration depends on the implementation.
	 */
	virtual eap_status_e configure() = 0;

	/**
	 * The get_is_valid() function returns the status of the eap_core object.
	 * True indicates the object is initialized succesfully.
	 */
	 virtual bool get_is_valid() const = 0 ;
	
	 virtual void set_is_valid() = 0;
	
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function activates random generator for test use.
	 * It does generate predictive pseudorandom data.
	 */
	virtual void use_test_random(
		const u8_t * const seed,
		const u32_t seed_length,
		const bool does_continuous_seeding_when_true) = 0;

	/**
	 * The get_rand_bytes() function fills count random bytes to buffer.
	 */
	 virtual eap_status_e get_rand_bytes(
		u8_t * const buffer,
		const u32_t count) = 0;

	/**
	 * The add_rand_seed() function seeds count bytes from buffer to the random data pool.
	 * The seed bytes could be any data that increases entropy of the random data pool.
	 * For example time stamps of send and received messages, likewise addresses, 
	 * cookies and nonces included in messages.
	 */
	 virtual eap_status_e add_rand_seed(
		const u8_t * const buffer,
		const u32_t count) = 0;

	/**
	 * The add_rand_seed_hw_ticks() function adds hardware ticks read with 
	 * the abs_eap_am_tools::get_hardware_ticks()  function. This could be used to 
	 * seed the random data pool with time stamps.
	 */
	 virtual eap_status_e add_rand_seed_hw_ticks() = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The generate_diffie_hellman_keys() function generates private and public 
	 * Diffie-Hellman keys. The key_length parameter is not fully supported. 
	 * It is used only for sanity checks. Only one well-known group is supported.
	 * @param dh_context Saves context here. Is private key in OpenSSL and CDHKey in Symbian.
	 */
	 virtual eap_status_e generate_diffie_hellman_keys(
		eap_variable_data_c * const dh_context,
		eap_variable_data_c * const own_public_dh_key,
		const u8_t * const prime,
		const u32_t prime_length,
		const u8_t * const group_generator,
		const u32_t group_generator_length) = 0;

	/**
	 * The generate_g_power_to_xy() function generates shared secret 
	 * Diffie-Hellman key from own_private_dh_key and peer_public_dh_key.
	 * The key_length parameter is not fully supported. It is used only for sanity checks. 
	 * Only one well-known group is supported.
	 * @param dh_context Gets context. Is private key in OpenSSL and CDHKey in Symbian.
	 */
	 virtual eap_status_e generate_g_power_to_xy(
		const eap_variable_data_c * const dh_context,
		const eap_variable_data_c * const peer_public_dh_key,
		eap_variable_data_c * const shared_dh_key,
		const u8_t * const prime,
		const u32_t prime_length,
		const u8_t * const group_generator,
		const u32_t group_generator_length) = 0;

	/**
	 * This functions cleans up the diffie-hellman context.
	 */
	 virtual eap_status_e dh_cleanup(
		const eap_variable_data_c * const dh_context) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function returns the size of message digest of SHA1-algorithm.
	 */
	 virtual u32_t get_sha_256_digest_length(
		eap_variable_data_c * const sha_256_context) = 0;

	/**
	 * This function returns the block size of SHA1-algorithm.
	 */
	 virtual u32_t get_sha_256_block_size(
		eap_variable_data_c * const sha_256_context) = 0;

	/**
	 * The sha_256_init() function initializes SHA1.
	 * Internal context of SHA1 is stored to sha_256_context.
	 */
	 virtual eap_status_e sha_256_init(
		eap_variable_data_c * const sha_256_context) = 0;

	/**
	 * The sha_256_update() function updates the context of 
	 * sha_256_context with data_length bytes of data.
	 */
	 virtual eap_status_e sha_256_update(
		eap_variable_data_c * const sha_256_context,
		const u8_t * const data,
		const u32_t data_length) = 0;

	/**
	 * The sha_256_final() function writes the message authentication code 
	 * (MAC) to buffer pointed by message_digest. The length of MAC is stored 
	 * to buffer pointed by md_length_or_null, If md_length_or_null is non NULL.
	 */
	 virtual eap_status_e sha_256_final(
		eap_variable_data_c * const sha_256_context,
		u8_t * const message_digest,
		u32_t *md_length_or_null) = 0;

	/**
	 * The hmac_sha_256_cleanup() cleanups the SHA1 context.
	 */
	 virtual eap_status_e sha_256_cleanup(
		eap_variable_data_c * const sha_256_context) = 0;

	/**
	 * The sha_256_copy_context() copies the SHA1 context.
	 */
	 virtual eap_status_e sha_256_copy_context(
		eap_variable_data_c * const copied_sha_256_context,
		const eap_variable_data_c * const original_sha_256_context) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function returns the size of message digest of SHA1-algorithm.
	 */
	 virtual u32_t get_sha1_digest_length(
		eap_variable_data_c * const sha1_context) = 0;

	/**
	 * This function returns the block size of SHA1-algorithm.
	 */
	 virtual u32_t get_sha1_block_size(
		eap_variable_data_c * const sha1_context) = 0;

	/**
	 * The sha1_init() function initializes SHA1.
	 * Internal context of SHA1 is stored to sha1_context.
	 */
	 virtual eap_status_e sha1_init(
		eap_variable_data_c * const sha1_context) = 0;

	/**
	 * The sha1_update() function updates the context of 
	 * sha1_context with data_length bytes of data.
	 */
	 virtual eap_status_e sha1_update(
		eap_variable_data_c * const sha1_context,
		const u8_t * const data,
		const u32_t data_length) = 0;

	/**
	 * The sha1_final() function writes the message authentication code 
	 * (MAC) to buffer pointed by message_digest. The length of MAC is stored 
	 * to buffer pointed by md_length_or_null, If md_length_or_null is non NULL.
	 */
	 virtual eap_status_e sha1_final(
		eap_variable_data_c * const sha1_context,
		u8_t * const message_digest,
		u32_t *md_length_or_null) = 0;

	/**
	 * The hmac_sha1_cleanup() cleanups the SHA1 context.
	 */
	 virtual eap_status_e sha1_cleanup(
		eap_variable_data_c * const sha1_context) = 0;

	/**
	 * The sha1_copy_context() copies the SHA1 context.
	 */
	 virtual eap_status_e sha1_copy_context(
		eap_variable_data_c * const copied_sha1_context,
		const eap_variable_data_c * const original_sha1_context) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The aes_key_length() function returns the length of key AES-algorithm. 
	 * This will be constant 16 bytes (128 bits). Still it is better use function 
	 * to help changes if the length of key is changed in future. 
	 */
	 virtual u32_t aes_key_length() = 0;

	/**
	 * The aes_block_size() function returns the block size of AES-algorithm. 
	 * This will be constant 16 bytes (128 bits). Still it is better use function 
	 * to help changes if the size is changed in future.
	 */
	 virtual u32_t aes_block_size() = 0;


	/**
	 * The aes_set_encryption_key() function initializes the encryption 
	 * context of AES-algorithm to the aes_context using key_length bytes from buffer key. 
	 */
	 virtual eap_status_e aes_set_encryption_key(
		eap_variable_data_c * const aes_context,
		const u8_t * const key,
		const u32_t key_length) = 0;

	/**
	 * The aes_set_decryption_key() function initializes the decryption context of 
	 * AES-algorithm to the aes_context using key_length bytes from buffer key.
	 */
	 virtual eap_status_e aes_set_decryption_key(
		eap_variable_data_c * const aes_context,
		const u8_t * const key,
		const u32_t key_length) = 0;

	virtual eap_status_e aes_cleanup(
		eap_variable_data_c * const aes_context) = 0;

	/**
	 * The aes_encrypt_block() function encrypts data of data_length bytes 
	 * using encryption_IV initialization vector. NOTE the length of data must 
	 * be aligned to block size of AES-algorithm.
	 * This version takes pointers to input and output buffers as a parameter.
	 * Those buffers must be fully separated. Some optimizations are used taking 
	 * advance from separate buffers. 
	 */
	 virtual eap_status_e aes_encrypt_block(
		eap_variable_data_c * const aes_context,
		const u8_t * const data_in,
		u8_t * const data_out,
		const u32_t data_length) = 0;

	/**
	 * The aes_decrypt_block() function decrypts data of data_length bytes 
	 * using decryption_IV initialization vector. NOTE the length of data must 
	 * be aligned to block size of AES-algorithm.
	 * This version takes pointers to input and output buffers as a parameter.
	 * Those buffers must be fully separated. Some optimizations are used 
	 * taking advance from separate buffers.
	 */
	 virtual eap_status_e aes_decrypt_block(
		eap_variable_data_c * const aes_context,
		const u8_t * const data_in,
		u8_t * const data_out,
		const u32_t data_length) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The key_length() function returns the length of key 3DES-EDE-algorithm. 
	 * This will be constant 16 bytes (128 bits). Still it is better use function 
	 * to help changes if the length of key is changed in future. 
	 */
	 virtual u32_t key_length_3des_ede() = 0;

	/**
	 * The block_size() function returns the block size of 3DES-EDE-algorithm. 
	 * This will be constant 16 bytes (128 bits). Still it is better use function 
	 * to help changes if the size is changed in future.
	 */
	 virtual u32_t block_size_3des_ede() = 0;


	/**
	 * The cbc_set_encryption_key() function initializes the encryption 
	 * context of 3DES-EDE-algorithm to the context using key_length bytes from buffer key. 
	 */
	 virtual eap_status_e set_encryption_key_3des_ede(
		eap_variable_data_c * const context,
		const u8_t * const key,
		const u32_t key_length) = 0;

	/**
	 * The cbc_set_decryption_key() function initializes the decryption context of 
	 * 3DES-EDE-algorithm to the context using key_length bytes from buffer key.
	 */
	 virtual eap_status_e set_decryption_key_3des_ede(
		eap_variable_data_c * const context,
		const u8_t * const key,
		const u32_t key_length) = 0;

	 virtual eap_status_e cleanup_3des_ede(
		 eap_variable_data_c * const context) = 0;

	/**
	 * The cbc_encrypt_data() function encrypts data of data_length bytes 
	 * using encryption_IV initialization vector. NOTE the length of data must 
	 * be aligned to block size of 3DES-EDE-algorithm.
	 * This version takes pointers to input and output buffers as a parameter.
	 * Those buffers must be fully separated. Some optimizations are used taking 
	 * advance from separate buffers. 
	 */
	 virtual eap_status_e encrypt_block_3des_ede(
		eap_variable_data_c * const context,
		const u8_t * const data_in,
		u8_t * const data_out,
		const u32_t data_length) = 0;

	/**
	 * The cbc_decrypt_data() function decrypts data of data_length bytes 
	 * using decryption_IV initialization vector. NOTE the length of data must 
	 * be aligned to block size of 3DES-EDE-algorithm.
	 * This version takes pointers to input and output buffers as a parameter.
	 * Those buffers must be fully separated. Some optimizations are used 
	 * taking advance from separate buffers.
	 */
	 virtual eap_status_e decrypt_block_3des_ede(
		eap_variable_data_c * const context,
		const u8_t * const data_in,
		u8_t * const data_out,
		const u32_t data_length) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Key derivation is based on the random number generation specified in
	 * NIST Federal Information Processing Standards (FIPS) Publication
	 * 186-2 [9]. The random number generator is specified in the change
	 * notice 1 (2001 October 5) of [9] (Algorithm 1). As specified in the
	 * change notice (page 74), when Algorithm 1 is used as a general-
	 * purpose random number generator, the "mod q" term in step 3.3 is
	 * omitted. The function G used in the algorithm is constructed via
	 * Secure Hash Standard as specified in Appendix 3.3 of the standard.
	 
	 * 160-bit XKEY and XVAL values are used, so b = 160. The initial
	 * secret seed value XKEY is computed from the n GSM Kc keys and the
	 * NONCE_MT with the following formula:
	 * @code
	 * XKEY = SHA1(n*Kc| NONCE_MT)
	 * 
	 * Random generator becomes as follows:
	 * Step 1. Choose a new, secret value for the seed-key, XKEY.
	 * Step 2. In hexadecimal notation let
	 *             t = 67452301 EFCDAB89 98BADCFE 10325476 C3D2E1F0.
	 *             This is the initial value for H0 || H1 || H2 || H3 || H4 in the SHS.
	 * Step 3. For j = 0 to m - 1 do
	 *             c. xj = G(t,XKEY).
	 *             d. XKEY = (1 + XKEY + xj) mod 2^b.
	 * @endcode
	 */
	 virtual eap_status_e dss_pseudo_random(
		u8_t *out,
		u32_t out_length,
		u8_t *xkey,
		u32_t xkey_length) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function returns the size of message digest of MD5-algorithm.
	 */
	 virtual u32_t get_md5_digest_length(
		eap_variable_data_c * const md5_context) = 0;

	/**
	 * This function returns the block size of MD5-algorithm.
	 */
	 virtual u32_t get_md5_block_size(
		eap_variable_data_c * const md5_context) = 0;

	/**
	 * The sha1_init() function initializes MD5.
	 * Internal context of MD5 is stored to sha1_context.
	 */
	 virtual eap_status_e md5_init(
		eap_variable_data_c * const md5_context) = 0;

	/**
	 * The md5_update() function updates the context of 
	 * md5_context with data_length bytes of data.
	 */
	 virtual eap_status_e md5_update(
		eap_variable_data_c * const md5_context,
		const u8_t * const data,
		const u32_t data_length) = 0;

	/**
	 * The md5_final() function writes the message authentication code 
	 * (MAC) to buffer pointed by message_digest. The length of MAC is stored 
	 * to buffer pointed by md_length_or_null, If md_length_or_null is non NULL.
	 */
	 virtual eap_status_e md5_final(
		eap_variable_data_c * const md5_context,
		u8_t * const message_digest,
		u32_t *md_length_or_null) = 0;

	/**
	 * The hmac_md5_cleanup() cleanups the MD5 context.
	 */
	 virtual eap_status_e md5_cleanup(
		eap_variable_data_c * const md5_context) = 0;

	/**
	 * The md5_copy_context() copies the MD5 context.
	 */
	 virtual eap_status_e md5_copy_context(
		eap_variable_data_c * const copied_md5_context,
		const eap_variable_data_c * const original_md5_context) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function returns the size of message digest of MD4-algorithm.
	 */
	 virtual u32_t get_md4_digest_length(
		eap_variable_data_c * const md4_context) = 0;

	/**
	 * This function returns the block size of MD4-algorithm.
	 */
	 virtual u32_t get_md4_block_size(
		eap_variable_data_c * const md4_context) = 0;

	/**
	 * The sha1_init() function initializes MD4.
	 * Internal context of MD4 is stored to sha1_context.
	 */
	 virtual eap_status_e md4_init(
		eap_variable_data_c * const md4_context) = 0;

	/**
	 * The md4_update() function updates the context of 
	 * md4_context with data_length bytes of data.
	 */
	 virtual eap_status_e md4_update(
		eap_variable_data_c * const md4_context,
		const u8_t * const data,
		const u32_t data_length) = 0;

	/**
	 * The md4_final() function writes the message authentication code 
	 * (MAC) to buffer pointed by message_digest. The length of MAC is stored 
	 * to buffer pointed by md_length_or_null, If md_length_or_null is non NULL.
	 */
	 virtual eap_status_e md4_final(
		eap_variable_data_c * const md4_context,
		u8_t * const message_digest,
		u32_t *md_length_or_null) = 0;

	/**
	 * The hmac_md4_cleanup() cleanups the MD4 context.
	 */
	 virtual eap_status_e md4_cleanup(
		eap_variable_data_c * const md4_context) = 0;

	/**
	 * The md4_copy_context() copies the MD4 context.
	 */
	 virtual eap_status_e md4_copy_context(
		eap_variable_data_c * const copied_md4_context,
		const eap_variable_data_c * const original_md4_context) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	* Used to set the RC4 key.
	*/
	virtual eap_status_e rc4_set_key(
		eap_variable_data_c * const rc4_context, 
		const eap_variable_data_c * const key) = 0;

	/**
	* Used to clean up the RC4 context.
	*/
	virtual eap_status_e rc4_cleanup(
		eap_variable_data_c * const rc4_context) = 0;

	/**
	* Encrypts RC4 data.
	*/
	virtual eap_status_e rc4_encrypt(
		const eap_variable_data_c * const rc4_context, 
		void * const data_in_out, 
		const u32_t data_length) = 0;

	/**
	* Encrypts RC4 data.
	*/
	virtual eap_status_e rc4_encrypt(
		const eap_variable_data_c * const rc4_context, 
		const void * const data_in, 
		void * const data_out,
		const u32_t data_length) = 0;

	/**
	* Decrypts RC4 data.
	*/
	virtual eap_status_e rc4_decrypt(
		const eap_variable_data_c * const rc4_context, 
		void * const data_in_out,
		const u32_t data_length) = 0;

	/**
	* Decrypts RC4 data.
	*/
	virtual eap_status_e rc4_decrypt(
		const eap_variable_data_c * const rc4_context, 
		const void * const data_in, 
		void * const data_out,
		const u32_t data_length) = 0;
	
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The rsa_init() function initializes context of RSA.
	 * Internal context of RSA is stored to rsa_context.
	 */
	 virtual eap_status_e rsa_init(
		eap_variable_data_c * const rsa_context) = 0;

	 virtual eap_status_e rsa_encrypt_with_public_key(
		eap_variable_data_c * const rsa_context,
		const eap_variable_data_c * const public_rsa_key,
		const eap_variable_data_c * const input_data,
		eap_variable_data_c * const output_data) = 0;

	 virtual eap_status_e rsa_decrypt_with_public_key(
		eap_variable_data_c * const rsa_context,
		const eap_variable_data_c * const public_rsa_key,
		const eap_variable_data_c * const input_data,
		eap_variable_data_c * const output_data) = 0;

	 virtual eap_status_e rsa_encrypt_with_private_key(
		eap_variable_data_c * const rsa_context,
		const eap_variable_data_c * const private_rsa_key,
		const eap_variable_data_c * const input_data,
		eap_variable_data_c * const output_data) = 0;

	 virtual eap_status_e rsa_decrypt_with_private_key(
		eap_variable_data_c * const rsa_context,
		const eap_variable_data_c * const private_rsa_key,
		const eap_variable_data_c * const input_data,
		eap_variable_data_c * const output_data) = 0;

	 virtual eap_status_e rsa_sign(
		eap_variable_data_c * const rsa_context,
		const eap_variable_data_c * const private_rsa_key,
		const eap_variable_data_c * const hash,
		eap_variable_data_c * const signed_hash) = 0;

	 virtual eap_status_e rsa_verify(
		eap_variable_data_c * const rsa_context,
		const eap_variable_data_c * const public_rsa_key,
		const eap_variable_data_c * const hash,
		const eap_variable_data_c * const signed_hash) = 0;

	/**
	 * The rsa_cleanup() function cleans up context of RSA.
	 * Internal context of RSA is stored to rsa_context.
	 */
	 virtual eap_status_e rsa_cleanup(
		eap_variable_data_c * const rsa_context) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The dsa_init() function initializes context of DSA.
	 * Internal context of DSA is stored to dsa_context.
	 */
	 virtual eap_status_e dsa_init(
		eap_variable_data_c * const dsa_context) = 0;

	 virtual eap_status_e dsa_sign(
		eap_variable_data_c * const dsa_context,
		const eap_variable_data_c * const private_dsa_key,
		const eap_variable_data_c * const hash,
		eap_variable_data_c * const signed_hash) = 0;

	 virtual eap_status_e dsa_verify(
		eap_variable_data_c * const dsa_context,		
		const eap_variable_data_c * const public_dsa_key,
		const eap_variable_data_c * const dsa_param_p,
		const eap_variable_data_c * const dsa_param_q,
		const eap_variable_data_c * const dsa_param_g,
		const eap_variable_data_c * const hash,
		const eap_variable_data_c * const signed_hash) = 0;

	/**
	 * The dsa_cleanup() function cleans up context of DSA.
	 * Internal context of DSA is stored to dsa_context.
	 */
	 virtual eap_status_e dsa_cleanup(
		eap_variable_data_c * const dsa_context) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

};

#endif //#if !defined( _ABS_EAP_AM_CRYPTO_H )



// End.
