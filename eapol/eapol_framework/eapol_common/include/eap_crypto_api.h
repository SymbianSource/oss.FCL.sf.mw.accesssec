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

#if !defined( _EAP_CRYPTO_API_H_ )
#define _EAP_CRYPTO_API_H_

#include "eap_am_types.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_CRYPTO_API_H)
	#define EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_CRYPTO_API_H 
	#define EAP_FUNC_EXPORT_EAP_CRYPTO_API_H 
	#define EAP_C_FUNC_EXPORT_EAP_CRYPTO_API_H 
#elif defined(EAP_EXPORT_EAP_CRYPTO_API_H)
	#define EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_CRYPTO_API_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_CRYPTO_API_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_CRYPTO_API_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_CRYPTO_API_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_CRYPTO_API_H 
	#define EAP_C_FUNC_EXPORT_EAP_CRYPTO_API_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_crypto.h"
#include "eap_array.h"

#if defined(des_set_key)
// OpenSSL defines this.
#undef des_set_key
#endif //#if defined(des_set_key)


const u32_t HMAC_SHA1_SIZE = 20u; // bytes = 160 bits
const u32_t HMAC_SHA1_128_SIZE = 16u; // bytes = 128 bits
const u32_t HMAC_MD5_SIZE = 20u; // bytes = 160 bits
const u32_t HMAC_MD5_128_SIZE = 16u; // bytes = 128 bits

const u32_t WPA_PSK_LENGTH = 32;

/// The abs_crypto_block_algorithm_c class describes interface of CBC block encryption algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H abs_crypto_cbc_block_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -


	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~abs_crypto_cbc_block_algorithm_c();

	/**
	 * The set_is_valid() function sets the state of the
	 * abs_crypto_block_algorithm_c object valid. The abs_crypto_block_algorithm_c object 
	 * calls this function after it is initialized.
	 */
	virtual void set_is_valid() = 0;

	/**
	 * The get_is_valid() function returns the status of the abs_crypto_block_algorithm_c object.
	 * True indicates the object is initialized.
	 */
	virtual bool get_is_valid() = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The get_encrypts() function returns true when encryption is initialized.
	 * It returns false when decryption is initialized.
	 */
	virtual bool get_encrypts() = 0;

	/**
	 * This function returns the length of AES key in bytes.
	 */
	virtual u32_t get_key_length() = 0;

	/**
	 * This function returns the length of AES block size in bytes.
	 */
	virtual u32_t get_block_size() = 0;

	/**
	 * Calculates the data length aligned to block size.
	 */
	virtual u32_t aligned_data_length(
		u32_t data_length) = 0;

	/**
	 * This function returns the internally stored initialization vector.
	 * The last encrypted and decrypted block is stored to this buffer 
	 * between subsequent encryption and decryption calls. 
	 * User of crypto_cbc_c object could get the last stored block calling this function.
	 */
	virtual const eap_variable_data_c * get_tmp_IV() = 0;

	/**
	 * This function adds count padding bytes to buffer. All padding bytes are zero (0x00).
	 */
	virtual eap_status_e add_padding_bytes(
		void * const buffer,
		const u32_t buffer_length,
		const u8_t padding_byte) = 0;

	/**
	 * This function checks the count padding bytes of buffer are zero (0x00).
	 */
	virtual eap_status_e check_padding_bytes(
		const void * const buffer,
		const u32_t buffer_length,
		const u8_t padding_byte) = 0;

	/**
	 * This function sets the mode to encryption, 
	 * sets the initialization vector and the encryption key.
	 */
	virtual eap_status_e set_encryption_key(
		const void * const encryption_IV,
		const u32_t encryption_IV_length,
		const void * const key,
		const u32_t key_length) = 0;

	/**
	 * This function sets the mode to decryption, 
	 * sets the initialization vector and the decryption key.
	 */
	virtual eap_status_e set_decryption_key(
		const void * const encryption_IV,
		const u32_t encryption_IV_length,
		const void * const key,
		const u32_t key_length) = 0;

	/**
	 * This function encrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	virtual eap_status_e encrypt_data(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length) = 0;

	/**
	 * This function encrypts continuous data bytes in data_in_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	virtual eap_status_e encrypt_data(
		void * const data_in_out,
		const u32_t data_length) = 0;

	/**
	 * This function decrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	virtual eap_status_e decrypt_data(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length) = 0;

	/**
	 * This function decrypts continuous data bytes in data_in_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	virtual eap_status_e decrypt_data(
		void * const data_in_out,
		const u32_t data_length) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The update_non_aligned() function updates the context of 
	 * AES-algorithm with data bytes. The direction (encryption/decryption) 
	 * depends of the initialized context. NOTE the length of data feed in 
	 * separate calls of update_non_aligned() does not need to be 
	 * aligned to AES-block size. Only the sum of whole data must be aligned to AES-block size.
	 * This version takes pointers to input and output buffers as a parameter. 
	 * Those buffers must be fully separated. Some optimizations are used 
	 * taking advance from separate buffers. 
	 */
	virtual eap_status_e update_non_aligned(
		const void * const msg_in,
		void * const msg_out,
		const u32_t msg_size) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The update_non_aligned() function updates the context of 
	 * AES-algorithm with data bytes. The direction (encryption/decryption) 
	 * depends of the initialized context. NOTE the length of data feed in 
	 * separate calls of update_non_aligned() does not need to be 
	 * aligned to AES-block size. Only the sum of whole data must be aligned to AES-block size.
	 * This version takes one pointer to buffer. The buffer is used for input and output data. 
	 */
	virtual eap_status_e update_non_aligned(
		void * const msg_in_out,
		const u32_t msg_size) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The finalize_non_aligned() finalizes the AES-context. 
	 * The sum of length of feed data must be aligned to AES-block size 
	 * before this function is called.
	 */
	virtual eap_status_e finalize_non_aligned() = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -
};



/// The abs_crypto_block_algorithm_c class describes interface of block encryption algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H abs_crypto_block_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -


	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~abs_crypto_block_algorithm_c();

	/**
	 * The set_is_valid() function sets the state of the
	 * abs_crypto_block_algorithm_c object valid. The abs_crypto_block_algorithm_c object 
	 * calls this function after it is initialized.
	 */
	virtual void set_is_valid() = 0;

	/**
	 * The get_is_valid() function returns the status of the abs_crypto_block_algorithm_c object.
	 * True indicates the object is initialized.
	 */
	virtual bool get_is_valid() = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The get_encrypts() function returns true when encryption is initialized.
	 * It returns false when decryption is initialized.
	 */
	virtual bool get_encrypts() = 0;

	/**
	 * This function returns the length of key in bytes.
	 */
	virtual u32_t get_key_length() = 0;

	/**
	 * This function returns the length of block size in bytes.
	 */
	virtual u32_t get_block_size() = 0;

	/**
	 * This function sets the mode to encryption, 
	 * sets the initialization vector and the encryption key.
	 */
	virtual eap_status_e set_encryption_key(
		const void * const key,
		const u32_t key_length) = 0;

	/**
	 * This function sets the mode to decryption, 
	 * sets the initialization vector and the decryption key.
	 */
	virtual eap_status_e set_decryption_key(
		const void * const key,
		const u32_t key_length) = 0;

	/**
	 * This function encrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	virtual eap_status_e encrypt_block(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length) = 0;

	/**
	 * This function decrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	virtual eap_status_e decrypt_block(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -
};



/// The abs_crypto_stream_algorithm_c class describes interface of stream encryption algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H abs_crypto_stream_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -


	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~abs_crypto_stream_algorithm_c();

	/**
	 * The set_is_valid() function sets the state of the
	 * abs_crypto_block_algorithm_c object valid. The abs_crypto_block_algorithm_c object 
	 * calls this function after it is initialized.
	 */
	virtual void set_is_valid() = 0;

	/**
	 * The get_is_valid() function returns the status of the abs_crypto_block_algorithm_c object.
	 * True indicates the object is initialized.
	 */
	virtual bool get_is_valid() = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function sets the key.
	 */
	virtual eap_status_e set_key(
		const eap_variable_data_c * const key) = 0;

	/**
	 * This function discards desired count of stream.
	 */
	virtual eap_status_e discard_stream(const u32_t count_of_discarded_octets) = 0;

	/**
	 * This function encrypts continuous data bytes in data_in_out buffer. 
	 */
	virtual eap_status_e encrypt_data(
		void * const data_in_out,
		const u32_t data_length) = 0;

	/**
	 * This function encrypts continuous data bytes from data_in to data_out buffer. 
	 */
	virtual eap_status_e encrypt_data(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length) = 0;

	/**
	 * This function encrypts continuous data bytes in data_in_out buffer. 
	 */
	virtual eap_status_e decrypt_data(
		void * const data_in_out,
		const u32_t data_length) = 0;

	/**
	 * This function decrypts continuous data bytes from data_in to data_out buffer. 
	 */
	virtual eap_status_e decrypt_data(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length) = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -
};



/// The abs_crypto_hash_algorithm_c class describes interface the MAC algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H abs_crypto_hash_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -


	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~abs_crypto_hash_algorithm_c();

	/**
	 * The set_is_valid() function sets the state of the
	 * abs_crypto_hash_algorithm_c object valid. The abs_crypto_hash_algorithm_c object 
	 * calls this function after it is initialized.
	 */
	virtual void set_is_valid() = 0;

	/**
	 * The get_is_valid() function returns the status of the abs_crypto_hash_algorithm_c object.
	 * True indicates the object is initialized.
	 */
	virtual bool get_is_valid() = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function returns the size of message digest of HASH-algorithm.
	 */
	virtual u32_t get_digest_length() = 0;

	/**
	 * This function returns the block size of HASH-algorithm.
	 */
	virtual u32_t get_block_size() = 0;

	/**
	 * This function sets the mode to encryption, 
	 * sets the initialization vector and the encryption key.
	 */
	virtual eap_status_e hash_init() = 0;

	/**
	 * This function updates the context of HASH-algorithm with data.
	 */
	virtual eap_status_e hash_update(
		const void * const data,
		const u32_t data_length) = 0;

	/**
	 * This function writes the message digest to buffer. 
	 * Length is set if md_length_or_null is non-NULL.
	 */
	virtual eap_status_e hash_final(
		void * const message_digest,
		u32_t *md_length_or_null) = 0;

	/**
	 * This function cleans up the HMAC-SHA1 context.
	 */
	virtual eap_status_e hash_cleanup() = 0;

	/**
	 * This function returns a copy of the context of HASH-algorithm.
	 * Caller must free the copy.
	 */
	virtual abs_crypto_hash_algorithm_c * copy() = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -
};


//------------------------------------------------------------


/// The abs_crypto_mac_algorithm_c class describes interface the HMAC algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H abs_crypto_hmac_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -


	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~abs_crypto_hmac_algorithm_c();

	/**
	 * The set_is_valid() function sets the state of the
	 * abs_crypto_mac_algorithm_c object valid. The abs_crypto_mac_algorithm_c object 
	 * calls this function after it is initialized.
	 */
	virtual void set_is_valid() = 0;

	/**
	 * The get_is_valid() function returns the status of the abs_crypto_mac_algorithm_c object.
	 * True indicates the object is initialized.
	 */
	virtual bool get_is_valid() = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function returns the size of message digest of HMAC-algorithm.
	 */
	virtual u32_t get_digest_length() = 0;

	/**
	 * This function sets the mode to encryption, 
	 * sets the initialization vector and the encryption key.
	 */
	virtual eap_status_e hmac_set_key(
		const eap_variable_data_c * const mac_key) = 0;

	/**
	 * This function updates the context of HMAC-algorithm with data.
	 */
	virtual eap_status_e hmac_update(
		const void * const data,
		const u32_t data_length) = 0;

	/**
	 * This function writes the message digest to buffer. 
	 * Length is set if md_length_or_null is non-NULL.
	 */
	virtual eap_status_e hmac_final(
		void * const message_digest,
		u32_t *md_length_or_null) = 0;

	/**
	 * This function cleans up the HMAC context.
	 */
	virtual eap_status_e hmac_cleanup() = 0;

	// - - - - - - - - - - - - - - - - - - - - - - - -
};


//------------------------------------------------------------


/// The crypto_hmac_c class describes HMAC algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_hmac_c
: public abs_crypto_hmac_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to the block encryption algorithm.
	abs_crypto_hash_algorithm_c * m_crypto_hash_algorithm;

	/// This is the initialized key.
	eap_variable_data_c * m_key;

	/// This is the initialized inner pad.
	eap_variable_data_c * m_ipad;

	/// This is the initialized outer pad.
	eap_variable_data_c * m_opad;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/// This object must free m_crypto_hash_algorithm when this value is true.
	bool m_free_crypto_hash_algorithm;


	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e initialize_pad(
		eap_variable_data_c * const p_pad,
		const u8_t pad_value);

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_hmac_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_hmac_c(
		abs_eap_am_tools_c * const tools,
		abs_crypto_hash_algorithm_c * const crypto_hash_algorithm,
		const bool free_crypto_hash_algorithm);

	/**
	 * The set_is_valid() function sets the state of the
	 * abs_crypto_mac_algorithm_c object valid. The abs_crypto_mac_algorithm_c object 
	 * calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	/**
	 * The get_is_valid() function returns the status of the abs_crypto_mac_algorithm_c object.
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function returns the size of message digest of HMAC-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_digest_length();

	/**
	 * This function sets the mode to encryption, 
	 * sets the initialization vector and the encryption key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hmac_set_key(
		const eap_variable_data_c * const hmac_key);

	/**
	 * This function updates the context of HMAC-algorithm with data.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hmac_update(
		const void * const data,
		const u32_t data_length);

	/**
	 * This function writes the message digest to buffer. 
	 * Length is set if md_length_or_null is non-NULL.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hmac_final(
		void * const message_digest,
		u32_t *md_length_or_null);

	/**
	 * This function writes the message digest of HMAC of 128 bits in length to buffer. 
	 * Length is set if md_length_or_null is non-NULL.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hmac_128_final(
		void * const message_digest,
		u32_t *md_length_or_null);

	/**
	 * This function cleans up the HMAC context.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hmac_cleanup();

	// - - - - - - - - - - - - - - - - - - - - - - - -
};


//------------------------------------------------------------

/// The crypto_cbc_c class includes the state of 
/// one instance of CBC block encryption algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_cbc_c
: public abs_crypto_cbc_block_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to the block encryption algorithm.
	abs_crypto_block_algorithm_c * m_crypto_block_algorithm;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/// This stores the initialization vector between subsequent
	/// calls of encryption or decryption.
	eap_variable_data_c * m_tmp_IV;

	/// This stores the offset of non-aligned data between 
	/// subsequent calls of encryption or decryption.
	i32_t m_encr_offset;

	/// This stores pointers to non-aligned data targets between 
	/// subsequent calls of encryption or decryption.
	u8_t **m_encr_dispatch;

	/// This stores the non-aligned data between subsequent 
	/// calls of encryption or decryption.
	u8_t *m_encr_hold;

	u8_t *m_saved_in_buffer;
	u8_t *m_saved_out_buffer;

	u8_t *m_iv_buffer_1;
	u8_t *m_iv_buffer_2;

	bool m_free_crypto_block_algorithm;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void reset();

	/**
	 * Run xor to data and IV block.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void cbc_xor_block(
		const void * const encryption_IV,
		void * const data_block,
		const u32_t block_size,
		const u32_t key_length);

	/**
	 * Copies source to target.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void cbc_copy_block(
		void * const target,
		const void * const source,
		const u32_t block_size,
		const u32_t key_length);

	/**
	 * This function encrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e internal_encrypt_data(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length);

	/**
	 * This function decrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e internal_decrypt_data(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length);


	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_cbc_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_cbc_c(
		abs_eap_am_tools_c * const tools,
		abs_crypto_block_algorithm_c * const crypto_block_algorithm,
		const bool free_crypto_block_algorithm);

	/**
	 * The get_encrypts() function returns true when encryption is initialized.
	 * It returns false when decryption is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual bool get_encrypts();

	/**
	 * This function returns the length of CBC key in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual u32_t get_key_length();

	/**
	 * This function returns the length of CBC block size in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual u32_t get_block_size();

	/**
	 * The set_is_valid() function sets the state of the
	 * crypto_cbc_c object valid. The crypto_cbc_c object 
	 * calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	/**
	 * The get_is_valid() function returns the status of the crypto_cbc_c object.
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function returns the internally stored initialization vector.
	 * The last encrypted and decrypted block is stored to this buffer 
	 * between subsequent encryption and decryption calls. 
	 * User of crypto_cbc_c object could get the last stored block calling this function.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H const eap_variable_data_c * get_tmp_IV();

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Calculates the data length aligned to block size.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t aligned_data_length(
		u32_t data_length);

	/**
	 * This function adds count padding bytes to buffer. All padding bytes are zero (0x00).
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e add_padding_bytes(
		void * const buffer,
		const u32_t buffer_length,
		const u8_t padding_byte);

	/**
	 * This function checks the count padding bytes of buffer are zero (0x00).
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e check_padding_bytes(
		const void * const buffer,
		const u32_t buffer_length,
		const u8_t padding_byte);

	/**
	 * This function sets the mode to encryption, 
	 * sets the initialization vector and the encryption key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e set_encryption_key(
		const void * const encryption_IV,
		const u32_t encryption_IV_length,
		const void * const key,
		const u32_t key_length);

	/**
	 * This function sets the mode to decryption, 
	 * sets the initialization vector and the decryption key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e set_decryption_key(
		const void * const encryption_IV,
		const u32_t encryption_IV_length,
		const void * const key,
		const u32_t key_length);

	/**
	 * This function encrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e encrypt_data(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length);

	/**
	 * This function encrypts continuous data bytes in data_in_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e encrypt_data(
		void * const data_in_out,
		const u32_t data_length);

	/**
	 * This function decrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e decrypt_data(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length);

	/**
	 * This function decrypts continuous data bytes in data_in_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e decrypt_data(
		void * const data_in_out,
		const u32_t data_length);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The update_non_aligned() function updates the context of 
	 * CBC-algorithm with data bytes. The direction (encryption/decryption) 
	 * depends of the initialized context. NOTE the length of data feed in 
	 * separate calls of update_non_aligned() does not need to be 
	 * aligned to CBC-block size. Only the sum of whole data must be aligned to CBC-block size.
	 * This version takes pointers to input and output buffers as a parameter. 
	 * Those buffers must be fully separated. Some optimizations are used 
	 * taking advance from separate buffers. 
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e update_non_aligned(
		const void * const msg_in,
		void * const msg_out,
		const u32_t msg_size);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The update_non_aligned() function updates the context of 
	 * CBC-algorithm with data bytes. The direction (encryption/decryption) 
	 * depends of the initialized context. NOTE the length of data feed in 
	 * separate calls of update_non_aligned() does not need to be 
	 * aligned to CBC-block size. Only the sum of whole data must be aligned to CBC-block size.
	 * This version takes one pointer to buffer. The buffer is used for input and output data. 
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e update_non_aligned(
		void * const msg_in_out,
		const u32_t msg_size);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The finalize_non_aligned() finalizes the CBC-context. 
	 * The sum of length of feed data must be aligned to CBC-block size 
	 * before this function is called.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e finalize_non_aligned();

	// - - - - - - - - - - - - - - - - - - - - - - - -
};


//------------------------------------------------------------

/// The crypto_aes_c class includes the state of 
/// one instance of AES block encryption algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_aes_c
: public abs_crypto_block_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/// Context is stored to this variable.
	/// This hides the whole implementation.
	/// This includes the context of AES-block cipher.
	/// This depends on the crypto library.
	eap_variable_data_c m_aes_context;

	/// This is the used block size.
	u32_t m_block_size;

	/// This is set true when encryption is the current mode.
	/// Decryption initializes this false.
	bool m_encrypt;


	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_aes_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_aes_c(abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_encrypts();

	/**
	 * The set_is_valid() function sets the state of the
	 * crypto_aes_c object valid. The crypto_aes_c object 
	 * calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	/**
	 * The get_is_valid() function returns the status of the crypto_aes_c object.
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function returns the length of AES key in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_key_length();

	/**
	 * This function returns the length of AES block size in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_block_size();


	/**
	 * This function sets the mode to encryption, 
	 * sets the initialization vector and the encryption key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e set_encryption_key(
		const void * const key,
		const u32_t key_length);

	/**
	 * This function sets the mode to decryption, 
	 * sets the initialization vector and the decryption key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e set_decryption_key(
		const void * const key,
		const u32_t key_length);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function encrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e encrypt_block(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length);

	/**
	 * This function decrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e decrypt_block(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length);

	// - - - - - - - - - - - - - - - - - - - - - - - -
};


//------------------------------------------------------------

/// The crypto_3des_ede_c class includes the state of 
/// one instance of 3DES-EDE block encryption algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_3des_ede_c
: public abs_crypto_block_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/// Context is stored to this variable.
	/// This hides the whole implementation.
	/// This includes the context of 3DES-EDE-block cipher.
	/// This depends on the crypto library.
	eap_variable_data_c m_context;

	/// This is the used block size.
	u32_t m_block_size;

	/// This is set true when encryption is the current mode.
	/// Decryption initializes this false.
	bool m_encrypt;


	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_3des_ede_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_3des_ede_c(abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_encrypts();

	/**
	 * The set_is_valid() function sets the state of the
	 * crypto_3des_ede_c object valid. The crypto_3des_ede_c object 
	 * calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	/**
	 * The get_is_valid() function returns the status of the crypto_3des_ede_c object.
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function returns the length of 3DES-EDE key in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_key_length();

	/**
	 * This function returns the length of 3DES-EDE block size in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_block_size();


	/**
	 * This function sets the mode to encryption, 
	 * sets the initialization vector and the encryption key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e set_encryption_key(
		const void * const key,
		const u32_t key_length);

	/**
	 * This function sets the mode to decryption, 
	 * sets the initialization vector and the decryption key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e set_decryption_key(
		const void * const key,
		const u32_t key_length);

	/**
	 * This function encrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e encrypt_block(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length);

	/**
	 * This function decrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e decrypt_block(
		const void * const data_in,
		void * const data_out,
		const u32_t data_length);

	// - - - - - - - - - - - - - - - - - - - - - - - -
};


//------------------------------------------------------------


const u8_t EAP_CRYPTO_AES_WRAP_DEFAULT_INITIAL_IV[] = {
	0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6,
	};

const u64_t EAP_CRYPTO_AES_WRAP_BLOCK_SIZE = sizeof(u64_t);


/// The crypto_aes_wrap_c class describes interface of block encryption algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_aes_wrap_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is the AES the block encryption algorithm.
	crypto_aes_c m_aes;

	eap_variable_data_c m_key;

	/// This is set true when encryption is the current mode.
	/// Decryption initializes this false.
	bool m_encrypt;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_aes_wrap_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_aes_wrap_c(abs_eap_am_tools_c * const tools);

	/**
	 * The set_is_valid() function sets the state of the
	 * crypto_aes_wrap_c object valid. The crypto_aes_wrap_c object 
	 * calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	/**
	 * The get_is_valid() function returns the status of the crypto_aes_wrap_c object.
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * The get_encrypts() function returns true when encryption is initialized.
	 * It returns false when decryption is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_encrypts();

	/**
	 * This function returns the length of key in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_key_length();

	/**
	 * This function returns the length of block size in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_block_size();

	/**
	 * This function sets the mode to encryption, 
	 * sets the initialization vector and the encryption key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e set_encryption_key(
		const void * const key,
		const u32_t key_length);

	/**
	 * This function sets the mode to decryption, 
	 * sets the initialization vector and the decryption key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e set_decryption_key(
		const void * const key,
		const u32_t key_length);

	/**
	 * This function adds buffer_length padding bytes to buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e add_padding_bytes(
		void * const buffer,
		const u32_t buffer_length);

	/**
	 * This function encrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e encrypt_block(
		const void * const data_in,
		const u32_t data_in_length,
		void * const data_out,
		const u32_t data_out_length);

	/**
	 * This function decrypts continuous data bytes from data_in to data_out buffer. 
	 * Note the length of the data must be aligned to block size of the cipher.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e decrypt_block(
		const void * const data_in,
		const u32_t data_in_length,
		void * const data_out,
		const u32_t data_out_length);

	// - - - - - - - - - - - - - - - - - - - - - - - -
};



//------------------------------------------------------------

/// The crypto_random_c class includes the state of 
/// one instance of random generator.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_random_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_random_c();

	/**
	 * Constructor initializes the object.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_random_c(abs_eap_am_tools_c * const tools);

	/**
	 * The set_is_valid() function sets the state of the crypto_random_c object valid. 
	 * The crypto_random_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	/**
	 * The get_is_valid() function returns the status of the crypto_random_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function copies count random bytes to buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e get_rand_bytes(
		void * const buffer,
		const u32_t count);

	/**
	 * This function copies count random bytes to buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e get_rand_bytes(
		eap_variable_data_c * const buffer,
		const u32_t count);

	/**
	 * This function creates random integer value between minimum and maximum inclusively.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_rand_integer(
		const u32_t minimum,
		const u32_t maximum);

	/**
	 * This function seeds the random generator with count bytes from buffer. 
	 * User could call this function as many times as is needed and at any time.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e add_rand_seed(
		const void * const buffer,
		const u32_t count);

	/**
	 * This function seeds random generator with the hardware ticks. 
	 * User could call this function as many times as is needed and at any time.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e add_rand_seed_hw_ticks();

};


//------------------------------------------------------------

/// The crypto_sha_256_c class includes the state of 
/// one instance of SHA-256 algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_sha_256_c
: public abs_crypto_hash_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// Context is stored to this variable.
	/// This hides the whole implementation.
	/// includes the context of the SHA-256 algorithm. 
	/// This depends on the crypto library.
	eap_variable_data_c m_sha_256_context;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_sha_256_c object invalid. 
	 * The crypto_sha_256_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_sha_256_c object valid. 
	 * The crypto_sha_256_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_sha_256_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_sha_256_c(abs_eap_am_tools_c * const tools);

	/**
	 * This function copies the context from parameter sha_256_context to this object.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e copy_context(const eap_variable_data_c * const sha_256_context);

	/**
	 * The get_is_valid() function returns the status of the crypto_sha_256_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function returns the size of message digest of SHA-256-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_digest_length();

	/**
	 * This function returns the block size of SHA-256-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_block_size();

	/**
	 * This function initializes the context of SHA-256-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_init();

	/**
	 * This function updates the context of SHA-256-algorithm with data.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_update(
		const void * const data,
		const u32_t data_length);

	/**
	 * This function writes the message digest to buffer.
	 * @param Length is set if md_length_or_null is non-NULL.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_final(
		void * const message_digest,
		u32_t *md_length_or_null);

	/**
	 * This function cleans up the SHA-256 context.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_cleanup();

	/**
	 * This function returns a copy of the context of SHA-256-algorithm.
	 * Caller must free the copy.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H abs_crypto_hash_algorithm_c * copy();
};


//------------------------------------------------------------

/// The crypto_sha1_c class includes the state of 
/// one instance of SHA1 algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_sha1_c
: public abs_crypto_hash_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// Context is stored to this variable.
	/// This hides the whole implementation.
	/// includes the context of the SHA1 algorithm. 
	/// This depends on the crypto library.
	eap_variable_data_c m_sha1_context;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_sha1_c object invalid. 
	 * The crypto_sha1_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_sha1_c object valid. 
	 * The crypto_sha1_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_sha1_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_sha1_c(abs_eap_am_tools_c * const tools);

	/**
	 * This function copies the context from parameter sha1_context to this object.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e copy_context(const eap_variable_data_c * const sha1_context);

	/**
	 * The get_is_valid() function returns the status of the crypto_sha1_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function returns the size of message digest of SHA1-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_digest_length();

	/**
	 * This function returns the block size of SHA1-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_block_size();

	/**
	 * This function initializes the context of SHA1-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_init();

	/**
	 * This function updates the context of SHA1-algorithm with data.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_update(
		const void * const data,
		const u32_t data_length);

	/**
	 * This function writes the message digest to buffer.
	 * @param Length is set if md_length_or_null is non-NULL.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_final(
		void * const message_digest,
		u32_t *md_length_or_null);

	/**
	 * This function cleans up the SHA1 context.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_cleanup();

	/**
	 * This function returns a copy of the context of SHA1-algorithm.
	 * Caller must free the copy.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H abs_crypto_hash_algorithm_c * copy();
};


//------------------------------------------------------------

/// The crypto_ephemeral_diffie_hellman_c class includes
/// the state of one instance of ephemeral Diffie-Hellman key exchange algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_ephemeral_diffie_hellman_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_ephemeral_diffie_hellman_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_ephemeral_diffie_hellman_c(abs_eap_am_tools_c * const tools);

	/**
	 * The set_is_valid() function sets the state of the crypto_ephemeral_diffie_hellman_c
	 * object valid. The crypto_ephemeral_diffie_hellman_c object calls this function
	 * after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	/**
	 * The get_is_valid() function returns the status of the crypto_ephemeral_diffie_hellman_c object.
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function creates the private and public keys using the prime and generator.
	 * Returns context in dh_context. It must be given to generate_g_power_to_xy and
	 * dh_cleanup.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e generate_diffie_hellman_keys(
		eap_variable_data_c * const dh_context,
		eap_variable_data_c * const own_public_dh_key,
		const void * const prime,
		const u32_t prime_length,
		const void * const group_generator,
		const u32_t group_generator_length);

	/**
	 * This function creates the shared Diffie-Hellman key using own private key,
	 * peer public key, prime and group generator.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e generate_g_power_to_xy(
		const eap_variable_data_c * const dh_context,
		const eap_variable_data_c * const peer_public_dh_key,
		eap_variable_data_c * const shared_dh_key,
		const void * const prime,
		const u32_t prime_length,
		const void * const group_generator,
		const u32_t group_generator_length);

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e dh_cleanup(
		const eap_variable_data_c * const dh_context);

};

//------------------------------------------------------------

/// The crypto_sha1_c class includes the state of 
/// one instance of MD5 algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_md5_c
: public abs_crypto_hash_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// Context is stored to this variable.
	/// This hides the whole implementation.
	/// includes the context of the MD5 algorithm. 
	/// This depends on the crypto library.
	eap_variable_data_c m_md5_context;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_md5_c object invalid. 
	 * The crypto_md5_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_md5_c object valid. 
	 * The crypto_md5_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_md5_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_md5_c(abs_eap_am_tools_c * const tools);

	/**
	 * This function copies the context from parameter sha1_context to this object.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e copy_context(const eap_variable_data_c * const sha1_context);

	/**
	 * The get_is_valid() function returns the status of the crypto_md5_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function returns the size of message digest of MD5-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_digest_length();

	/**
	 * This function returns the block size of MD5-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_block_size();

	/**
	 * This function initializes the context of MD5-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_init();

	/**
	 * This function updates the context of MD5-algorithm with data.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_update(
		const void * const data,
		const u32_t data_length);

	/**
	 * This function writes the message digest to buffer.
	 * @param Length is set if md_length_or_null is non-NULL.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_final(
		void * const message_digest,
		u32_t *md_length_or_null);

	/**
	 * This function cleans up the MD5 context.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_cleanup();

	/**
	 * This function returns a copy of the context of MD5-algorithm.
	 * Caller must free the copy.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H abs_crypto_hash_algorithm_c * copy();
};


//------------------------------------------------------------

/// The crypto_sha1_c class includes the state of 
/// one instance of MD4 algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_md4_c
: public abs_crypto_hash_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// Context is stored to this variable.
	/// This hides the whole implementation.
	/// includes the context of the MD4 algorithm. 
	/// This depends on the crypto library.
	eap_variable_data_c m_md4_context;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_md4_c object invalid. 
	 * The crypto_md4_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_md4_c object valid. 
	 * The crypto_md4_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_md4_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_md4_c(abs_eap_am_tools_c * const tools);

	/**
	 * This function copies the context from parameter sha1_context to this object.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e copy_context(const eap_variable_data_c * const sha1_context);

	/**
	 * The get_is_valid() function returns the status of the crypto_md4_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function returns the size of message digest of MD4-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_digest_length();

	/**
	 * This function returns the block size of MD4-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H u32_t get_block_size();

	/**
	 * This function initializes the context of MD4-algorithm.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_init();

	/**
	 * This function updates the context of MD4-algorithm with data.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_update(
		const void * const data,
		const u32_t data_length);

	/**
	 * This function writes the message digest to buffer.
	 * @param Length is set if md_length_or_null is non-NULL.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_final(
		void * const message_digest,
		u32_t *md_length_or_null);

	/**
	 * This function cleans up the MD4 context.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_cleanup();

	/**
	 * This function returns a copy of the context of MD4-algorithm.
	 * Caller must free the copy.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H abs_crypto_hash_algorithm_c * copy();
};


//------------------------------------------------------------
/// The crypto_rc4_c class includes the state of 
/// one instance of RC4 algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_rc4_c
: public abs_crypto_stream_algorithm_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// Context is stored to this variable.
	/// This hides the whole implementation.
	/// includes the context of the RC4 algorithm. 
	/// This depends on the crypto library.
	eap_variable_data_c m_rc4_context;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_rc4_c object invalid. 
	 * The crypto_rc4_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_rc4_c object valid. 
	 * The crypto_rc4_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_rc4_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_rc4_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the crypto_rc4_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function sets the RC4 key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e set_key(const eap_variable_data_c * const key);

	/**
	 * This function discards desired count of RC4 stream.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e discard_stream(const u32_t count_of_discarded_octets);

	/**
	 * This function encrypts continuous data bytes in data_in_out buffer. 
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e encrypt_data(
		void * const data_in_out,
		const u32_t data_length);

	/**
	 * This function does RC4 encryption.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e encrypt_data(
		const void * const data_in, 
		void * const data_out,
		const u32_t data_length);

	/**
	 * This function decrypts continuous data bytes in data_in_out buffer. 
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e decrypt_data(
		void * const data_in_out,
		const u32_t data_length);

	/**
	 * This function does RC4 decryption.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e decrypt_data(
		const void * const data_in, 
		void * const data_out,
		const u32_t data_length);

};

//------------------------------------------------------------

/// The crypto_tls_base_prf_c class includes the state of 
/// one instance of TLS-PRF base algorithms.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_tls_base_prf_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_tls_base_prf_c object invalid. 
	 * The crypto_tls_base_prf_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_tls_base_prf_c object valid. 
	 * The crypto_tls_base_prf_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_tls_base_prf_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_tls_base_prf_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the crypto_tls_base_prf_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e tls_prf_A_value(
		abs_crypto_hmac_algorithm_c * const hash,
		eap_variable_data_c * const key,
		eap_variable_data_c * const seed,
		eap_variable_data_c * const A_md5_output);

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e tls_prf_one_round(
		abs_crypto_hmac_algorithm_c * const hash,
		const eap_variable_data_c * const key,
		eap_variable_data_c * const A_input,
		eap_variable_data_c * const seed,
		void * const out_buffer,
		const u32_t out_buffer_length);

	/**
	 * This function cleans up the TLS-PRF context.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e tls_prf_cleanup();

};

//------------------------------------------------------------

/// The crypto_tls_sha1_prf_c class includes the state of 
/// one instance of TLS-PRF SHA1 algorithm.
/// This is needed because compound authentication
/// binding of PEAP does use only P_SHA-1 for generating
/// compound keyed MACs and the compound session keys.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_tls_sha1_prf_c
: public crypto_tls_base_prf_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	crypto_hmac_c * m_sha1_context;
	crypto_hmac_c * m_A_sha1_context;

	eap_variable_data_c m_sha1_key;

	eap_variable_data_c m_seed;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_tls_sha1_prf_c object invalid. 
	 * The crypto_tls_sha1_prf_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_tls_sha1_prf_c object valid. 
	 * The crypto_tls_sha1_prf_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_tls_sha1_prf_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_tls_sha1_prf_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the crypto_tls_sha1_prf_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function initializes the context of TLS-PRF algorithm using the key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e tls_prf_init(
		const eap_variable_data_c * const secret,
		const eap_variable_data_c * const label,
		const eap_variable_data_c * const seed);

	/**
	 * This function writes the message digest to buffer. 
	 * Length is set if md_length_or_null is non-NULL.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e tls_prf_output(
		void * const pseudo_random_data,
		const u32_t pseudo_random_data_length);

	/**
	 * This function cleans up the TLS-PRF context.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e tls_prf_cleanup();

};

//------------------------------------------------------------

/// The crypto_tls_md5_prf_c class includes the state of 
/// one instance of TLS-PRF MD5 algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_tls_md5_prf_c
: public crypto_tls_base_prf_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	crypto_hmac_c * m_md5_context;
	crypto_hmac_c * m_A_md5_context;

	eap_variable_data_c m_md5_key;

	eap_variable_data_c m_seed;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_tls_md5_prf_c object invalid. 
	 * The crypto_tls_md5_prf_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_tls_md5_prf_c object valid. 
	 * The crypto_tls_md5_prf_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_tls_md5_prf_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_tls_md5_prf_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the crypto_tls_md5_prf_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function initializes the context of TLS-PRF algorithm using the key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e tls_prf_init(
		const eap_variable_data_c * const secret,
		const eap_variable_data_c * const label,
		const eap_variable_data_c * const seed);

	/**
	 * This function writes the message digest to buffer. 
	 * Length is set if md_length_or_null is non-NULL.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e tls_prf_output(
		void * const pseudo_random_data,
		const u32_t pseudo_random_data_length);

	/**
	 * This function cleans up the TLS-PRF context.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e tls_prf_cleanup();

};

//------------------------------------------------------------

/// The crypto_tls_prf_c class includes the state of 
/// one instance of TLS-PRF algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_tls_prf_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	crypto_tls_md5_prf_c * m_tls_md5_prf;
	crypto_tls_sha1_prf_c * m_tls_sha1_prf;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_tls_prf_c object invalid. 
	 * The crypto_tls_prf_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_tls_prf_c object valid. 
	 * The crypto_tls_prf_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_tls_prf_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_tls_prf_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the crypto_tls_prf_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function initializes the context of TLS-PRF algorithm using the key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e tls_prf_init(
		const eap_variable_data_c * const secret,
		const eap_variable_data_c * const label,
		const eap_variable_data_c * const seed);

	/**
	 * This function writes the message digest to buffer. 
	 * Length is set if md_length_or_null is non-NULL.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e tls_prf_output(
		void * const pseudo_random_data,
		const u32_t pseudo_random_data_length);

	/**
	 * This function cleans up the TLS-PRF context.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e tls_prf_cleanup();

};

//------------------------------------------------------------


/// The crypto_eap_fast_hmac_sha1_prf_c class includes the state of 
/// one instance of T-PRF algorithm used in EAP-FAST.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_eap_fast_hmac_sha1_prf_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	crypto_hmac_c * m_context;

	eap_variable_data_c m_key;

	eap_variable_data_c m_S_value;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_eap_fast_hmac_sha1_prf_c object invalid. 
	 * The crypto_eap_fast_hmac_sha1_prf_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_eap_fast_hmac_sha1_prf_c object valid. 
	 * The crypto_eap_fast_hmac_sha1_prf_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_eap_fast_hmac_sha1_prf_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_eap_fast_hmac_sha1_prf_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the crypto_eap_fast_hmac_sha1_prf_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function initializes the context of T-PRF algorithm using the key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e t_prf_init(
		const eap_variable_data_c * const key,
		const eap_variable_data_c * const label,
		const eap_variable_data_c * const seed);

	/**
	 * This function writes the message digest to buffer. 
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e t_prf_output(
		void * const pseudo_random_data,
		const u16_t pseudo_random_data_length);

	/**
	 * This function cleans up the T-PRF context.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e t_prf_cleanup();

};


//------------------------------------------------------------

/// The crypto_tls_prf_c class includes the state of 
/// one instance of RSA algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_rsa_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// Context is stored to this variable.
	/// This hides the whole implementation.
	/// Includes the context of the RSA algorithm. 
	/// This depends on the crypto library.
	eap_variable_data_c m_context;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_rsa_c object invalid. 
	 * The crypto_rsa_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_rsa_c object valid. 
	 * The crypto_rsa_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_rsa_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_rsa_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the crypto_rsa_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function initializes the context of RSA algorithm using the key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e init();

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e encrypt_with_public_key(
		const eap_variable_data_c * const public_rsa_key,
		const eap_variable_data_c * const input_data,
		eap_variable_data_c * const output_data);

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e decrypt_with_public_key(
		const eap_variable_data_c * const public_rsa_key,
		const eap_variable_data_c * const input_data,
		eap_variable_data_c * const output_data);

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e encrypt_with_private_key(
		const eap_variable_data_c * const private_rsa_key,
		const eap_variable_data_c * const input_data,
		eap_variable_data_c * const output_data);

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e decrypt_with_private_key(
		const eap_variable_data_c * const private_rsa_key,
		const eap_variable_data_c * const input_data,
		eap_variable_data_c * const output_data);

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e sign(
		const eap_variable_data_c * const private_dsa_key,
		const eap_variable_data_c * const hash,
		eap_variable_data_c * const signed_hash);

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e verify(
		const eap_variable_data_c * const public_rsa_key,
		const eap_variable_data_c * const hash,
		const eap_variable_data_c * const signed_hash);

	/**
	 * This function cleans up the RSA context.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e cleanup();

};

//------------------------------------------------------------

/// The crypto_tls_prf_c class includes the state of 
/// one instance of DSA algorithm.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_dsa_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// Context is stored to this variable.
	/// This hides the whole implementation.
	/// Includes the context of the DSA algorithm. 
	/// This depends on the crypto library.
	eap_variable_data_c m_context;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_dsa_c object invalid. 
	 * The crypto_dsa_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_dsa_c object valid. 
	 * The crypto_dsa_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_dsa_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_dsa_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the crypto_dsa_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();

	/**
	 * This function initializes the context of DSA algorithm using the key.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e init();

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e sign(
		const eap_variable_data_c * const private_dsa_key,
		const eap_variable_data_c * const hash,
		eap_variable_data_c * const signed_hash);

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e verify(
		const eap_variable_data_c * const public_dsa_key,
		const eap_variable_data_c * const dsa_param_p,
		const eap_variable_data_c * const dsa_param_q,
		const eap_variable_data_c * const dsa_param_g,
		const eap_variable_data_c * const hash,
		const eap_variable_data_c * const signed_hash);

	/**
	 * This function cleans up the DSA context.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e cleanup();

};

//------------------------------------------------------------

/// The crypto_wpa_psk_password_hash_c class includes the functions for
/// generating WPA PSK from an ASCII password
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_wpa_psk_password_hash_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_rc4_c object invalid. 
	 * The crypto_rc4_c object calls this function after it is initialized.
	 */
	void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_rc4_c object valid. 
	 * The crypto_rc4_c object calls this function after it is initialized.
	 */
	void set_is_valid();

	/**
	* Calculates the PSK hash from an ASCII password
	*/
	eap_status_e password_hash_F(
		const eap_variable_data_c * const password,
		const eap_variable_data_c * const ssid,	
		u32_t iterations,
		u32_t count,
		eap_variable_data_c * const output,
		void * object,
		eap_status_e (*progress_callback)(void*, u32_t));


	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_wpa_psk_password_hash_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_wpa_psk_password_hash_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the crypto_wpa_psk_password_hash object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();
	
	/**
	* Calculates the PSK hash from an ASCII password
	*/
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e password_hash(
		const eap_variable_data_c * const password,
		const eap_variable_data_c * const ssid,	
		eap_variable_data_c * const output,
		void * object = 0,
		eap_status_e (*progress_callback)(void*, u32_t) = 0);

};

//------------------------------------------------------------

/// The crypto_wpa_psk_password_hash_c class includes the functions for
/// generating WPA PSK from an ASCII password
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_nt_hash_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_rc4_c object invalid. 
	 * The crypto_rc4_c object calls this function after it is initialized.
	 */
	void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_rc4_c object valid. 
	 * The crypto_rc4_c object calls this function after it is initialized.
	 */
	void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_nt_hash_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_nt_hash_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the crypto_wpa_psk_password_hash object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();
	
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e nt_password_hash(
		const eap_variable_data_c * const password_utf8,
		eap_variable_data_c * const password_hash,
		const u32_t digest_size);

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e hash_nt_password_hash(
		const eap_variable_data_c * const password_hash,
		eap_variable_data_c * const password_hash_hash,
		const u32_t digest_size);

	/* RFC 3079 */

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e get_master_key(
		const eap_variable_data_c * const password_hash_hash,
		const eap_variable_data_c * const nt_response,
		eap_variable_data_c * const master_key,
		const u32_t in_master_key_length);

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e get_asymmetric_start_key(
		const eap_variable_data_c * const in_master_key,
		eap_variable_data_c * const out_session_key,
		const u32_t in_session_key_length,
		const bool in_is_send,
		const bool in_is_server);

	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e get_new_key_from_sha(
		const eap_variable_data_c * const in_start_key,
		const eap_variable_data_c * const in_session_key,
		eap_variable_data_c * const out_interim_key,
		const u32_t in_interim_key_length);
	
};

//------------------------------------------------------------

/// The crypto_kd_hmac_sha256_c class includes the functions for
/// KD-HMAC-SHA256.
class EAP_CLASS_VISIBILITY_EAP_CRYPTO_API_H crypto_kd_hmac_sha256_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	/**
	 * The set_is_invalid() function sets the state of the crypto_kd_hmac_sha256_c object invalid. 
	 * The crypto_kd_hmac_sha256_c object calls this function after it is initialized.
	 */
	void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the crypto_kd_hmac_sha256_c object valid. 
	 * The crypto_kd_hmac_sha256_c object calls this function after it is initialized.
	 */
	void set_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H virtual ~crypto_kd_hmac_sha256_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H crypto_kd_hmac_sha256_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the crypto_kd_hmac_sha256_c object. 
	 * True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H bool get_is_valid();
	
	EAP_FUNC_VISIBILITY_EAP_CRYPTO_API_H eap_status_e expand_key(
		eap_variable_data_c * const output,
		const u32_t required_output_size,
		const eap_variable_data_c * const key,
		const eap_variable_data_c * const label
		);
};

//------------------------------------------------------------

#endif //#if !defined( _EAP_CRYPTO_API_H_ )



// End.
