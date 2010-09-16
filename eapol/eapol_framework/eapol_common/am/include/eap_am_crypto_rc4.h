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

//------------------------------------------------------------

#if !defined(_EAP_AM_CRYPTO_RC4_H_)
#define _EAP_AM_CRYPTO_RC4_H_

#include "eap_am_types.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_CRYPTO_RC4_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_RC4_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H 
	#define EAP_FUNC_EXPORT_EAP_AM_CRYPTO_RC4_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_CRYPTO_RC4_H 
#elif defined(EAP_EXPORT_EAP_AM_CRYPTO_RC4_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_RC4_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_CRYPTO_RC4_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_CRYPTO_RC4_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_RC4_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_CRYPTO_RC4_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_CRYPTO_RC4_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_am_tools.h"

#undef set_key

//------------------------------------------------------------

/// The eap_am_crypto_rc4_c class includes the state of 
/// one instance of RC4 algorithm.
class EAP_CLASS_VISIBILITY_EAP_AM_CRYPTO_RC4_H eap_am_crypto_rc4_c
{

	// - - - - - - - - - - - - - - - - - - - - - - - -
private:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	enum eap_am_crypto_rc4_constant
	{
		eap_am_crypto_rc4_constant_state_size = 256,
	};

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// State is stored to this variable.
	u8_t m_state[eap_am_crypto_rc4_constant_state_size];

	/// This is the index i.
	u8_t m_ind_i;

	/// This is the index j.
	u8_t m_ind_j;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Function cleanups the state and variables.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H eap_status_e cleanup();

	/**
	 * The set_is_invalid() function sets the state of the eap_am_crypto_rc4_c
	 * object invalid. 
	 * The eap_am_crypto_rc4_c object calls this function after it is
	 * initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H void set_is_invalid();

	/**
	 * The set_is_valid() function sets the state of the eap_am_crypto_rc4_c
	 * object valid. 
	 * The eap_am_crypto_rc4_c object calls this function after it is
	 * initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H void set_is_valid();

	/**
	 * Function swaps the values.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H inline void swap(
		u8_t * const s_i,
		u8_t * const s_j);

	/**
	 * Function returns the next random byte.
	 */
	inline u8_t get_random_byte();

	/**
	 * Function XORs input data buffer with generated pseudo random data
	 * and stores result to output data buffer.
	 */
	inline eap_status_e process_data(
		const void * const p_data_in,
		void * const p_data_out,
		const u32_t data_length);

	// - - - - - - - - - - - - - - - - - - - - - - - -
public:
	// - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * Destructor resets the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H virtual ~eap_am_crypto_rc4_c();

	/**
	 * Constructor initializes the used internal buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H eap_am_crypto_rc4_c(abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the
	 * eap_am_crypto_rc4_c object. 
	 * True indicates the object is allocated successfully.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H bool get_is_valid();

	/**
	 * This function sets the RC4 key.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H eap_status_e set_key(
		const eap_variable_data_c * const key);

	/**
	 * This function does RC4 encryption.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H eap_status_e encrypt_data(
		const void * const data_in, 
		void * const data_out,
		const u32_t data_length);

	/**
	 * This function does RC4 decryption.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_CRYPTO_RC4_H eap_status_e decrypt_data(
		const void * const data_in, 
		void * const data_out,
		const u32_t data_length);
};

#endif //#if !defined(_EAP_AM_CRYPTO_RC4_H_)

//------------------------------------------------------------



// End.
