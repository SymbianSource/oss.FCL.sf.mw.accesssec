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
	#define EAP_FILE_NUMBER_ENUM 6 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"
#include "eap_am_crypto_rc4.h"

//------------------------------------------------------------

#if 1
	#define EAP_RC4_TRACE_DEBUG EAP_TRACE_DEBUG
#else
	#define EAP_RC4_TRACE_DEBUG(tools, flags, params)
#endif

#if defined(USE_EAP_TRACE)	
	static const u32_t EAP_TRACE_MASK_RC4 = eap_am_tools_c::eap_trace_mask_crypto_rc4;
#endif //#if defined(USE_EAP_TRACE)	

//------------------------------------------------------------

/**
 * Destructor resets the used internal buffers.
 */
EAP_FUNC_EXPORT eap_am_crypto_rc4_c::~eap_am_crypto_rc4_c()
{
	cleanup();
}

//------------------------------------------------------------

/**
 * Constructor initializes the used internal buffers.
 */
EAP_FUNC_EXPORT eap_am_crypto_rc4_c::eap_am_crypto_rc4_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_ind_i(0ul)
	, m_ind_j(0ul)
	, m_is_valid(false)
{
	m_state[0] = 0;
	set_is_valid();
}

//--------------------------------------------------

/**
 * This function cleans up the RC4 context.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_rc4_c::cleanup()
{
	m_ind_i = 0ul;
	m_ind_j = 0ul;
	m_is_valid = false;
	m_am_tools->memset(m_state, 0, eap_am_crypto_rc4_constant_state_size);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//------------------------------------------------------------

/**
 * The set_is_invalid() function sets the state of the eap_am_crypto_rc4_c
 * object invalid. 
 * The eap_am_crypto_rc4_c object calls this function after it is initialized.
 */
EAP_FUNC_EXPORT void eap_am_crypto_rc4_c::set_is_invalid()
{
	m_is_valid = false;
}

//------------------------------------------------------------

/**
 * The set_is_valid() function sets the state of the eap_am_crypto_rc4_c
 * object valid. 
 * The eap_am_crypto_rc4_c object calls this function after it is initialized.
 */
EAP_FUNC_EXPORT void eap_am_crypto_rc4_c::set_is_valid()
{
	m_is_valid = true;
}

//------------------------------------------------------------

/**
 * The get_is_valid() function returns the status of the eap_am_crypto_rc4_c
 * object. 
 * True indicates the object is allocated successfully.
 */
EAP_FUNC_EXPORT bool eap_am_crypto_rc4_c::get_is_valid()
{
	return m_is_valid;
}

//------------------------------------------------------------

/**
 * Function swaps the values.
 */
EAP_FUNC_EXPORT inline void eap_am_crypto_rc4_c::swap(
	u8_t * const s_i,
	u8_t * const s_j)
{
	const u8_t tmp = *s_i;
	*s_i = *s_j;
	*s_j = tmp;
}

//------------------------------------------------------------

/**
 * This function sets the RC4 key.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_rc4_c::set_key(
	const eap_variable_data_c * const p_key)
{
	u32_t ind = 0ul;

	// Note the size of ind must be bigger than 8-bits.
	for (ind = 0ul; ind < eap_am_crypto_rc4_constant_state_size
			 ; ind++)
	{
		m_state[ind] = static_cast<u8_t>(ind);

		EAP_RC4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_RC4,
					(EAPL("RC4: m_state[%d]=0x%02x\n"),
					ind,
					m_state[ind]));
	} // for()

	const u32_t key_length = p_key->get_data_length();
	const u8_t * const key = p_key->get_data(key_length);

	m_ind_i = 0ul;
	m_ind_j = 0ul;

	// Note the size of ind must be bigger than 8-bits.
	for (ind = 0ul; ind < eap_am_crypto_rc4_constant_state_size
			 ; ind++)
	{
		m_ind_j = static_cast<u8_t>(
			static_cast<u8_t>(m_ind_j)
			+ static_cast<u8_t>(m_state[ind])
			+ static_cast<u8_t>(key[ind % key_length]));

		swap(&(m_state[ind]), &(m_state[m_ind_j]));

		EAP_RC4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_RC4,
					(EAPL("RC4: swapped m_state[%d]=0x%02x and m_state[%d]=0x%02x\n"),
					ind,
					m_state[ind],
					m_ind_j,
					m_state[m_ind_j]));
	} // for()

	m_ind_i = 0ul;
	m_ind_j = 0ul;

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//------------------------------------------------------------

/**
 */
inline u8_t eap_am_crypto_rc4_c::get_random_byte()
{
	m_ind_i = static_cast<u8_t>(m_ind_i + 1ul);
	
	m_ind_j = static_cast<u8_t>(m_ind_j + m_state[m_ind_i]);
	
	swap(&(m_state[m_ind_i]), &(m_state[m_ind_j]));
	
	u8_t random_byte = m_state[static_cast<u8_t>(m_state[m_ind_i]
									   + m_state[m_ind_j])];

	EAP_RC4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_RC4,
				(EAPL("RC4: random_byte=0x%02x\n"),
				random_byte));

	return random_byte;
}

//------------------------------------------------------------

/**
 * This function does RC4 encryption.
 */
inline eap_status_e eap_am_crypto_rc4_c::process_data(
	const void * const p_data_in,
	void * const p_data_out,
	const u32_t data_length)
{
	const u8_t * const data_in = static_cast<const u8_t *>(p_data_in);
	u8_t * const data_out = static_cast<u8_t *>(p_data_out);

	for (u32_t ind = 0ul; ind < data_length; ind++)
	{
		EAP_RC4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_RC4,
					(EAPL("RC4: data_in[%d]=0x%02x\n"),
					ind,
					data_in[ind]));

		data_out[ind] = static_cast<u8_t>(data_in[ind] ^ get_random_byte());

		EAP_RC4_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_RC4,
					(EAPL("RC4: data_out[%d]=0x%02x\n"),
					ind,
					data_out[ind]));
	} // for()

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//------------------------------------------------------------

/**
 * This function does RC4 encryption.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_rc4_c::encrypt_data(
	const void * const p_data_in,
	void * const p_data_out,
	const u32_t data_length)
{
	return EAP_STATUS_RETURN(
		m_am_tools,
		process_data(p_data_in, p_data_out, data_length));
}

//------------------------------------------------------------

/**
 * This function does RC4 decryption.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_rc4_c::decrypt_data(
	const void * const p_data_in,
	void * const p_data_out,
	const u32_t data_length)
{
	return EAP_STATUS_RETURN(
		m_am_tools,
		process_data(p_data_in, p_data_out, data_length));
}

//------------------------------------------------------------



// End.
