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

#if !defined(_EAPOL_SESSION_KEY_H_)
#define _EAPOL_SESSION_KEY_H_

#include "eap_variable_data.h"
#include "eapol_key_types.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_SESSION_KEY_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_SESSION_KEY_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H 
	#define EAP_FUNC_EXPORT_EAPOL_SESSION_KEY_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_SESSION_KEY_H 
#elif defined(EAP_EXPORT_EAPOL_SESSION_KEY_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_SESSION_KEY_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_SESSION_KEY_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_SESSION_KEY_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_SESSION_KEY_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_SESSION_KEY_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_SESSION_KEY_H 
#endif
// End: added by script change_export_macros.sh.


/// A eapol_session_key_c class.
/// This is used for session key encapsulation.
class EAP_CLASS_VISIBILITY_EAPOL_SESSION_KEY_H eapol_session_key_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools; ///< This is pointer to the tools class. @see abs_eap_am_tools_c.

	eap_variable_data_c m_key; ///< Here is the key.

	eap_variable_data_c m_sequence_number; ///< Here is the current sequence number for GTK. NOTE m_key_type should be GTK.

	eapol_key_type_e m_key_type; ///< This the type of the key.

	u32_t m_key_index; ///< This is the index of the key.

	bool m_key_tx_bit; ///< This is the TX bit of the key.

	bool m_is_valid;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eapol_session_key_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H virtual ~eapol_session_key_c();

	/**
	 * The constructor of the eapol_session_key_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H eapol_session_key_c(
		abs_eap_am_tools_c * const tools,
		eap_variable_data_c * const key, ///< Here is the key.
		const eapol_key_type_e key_type, ///< This the type of the key.
		const u32_t key_index, ///< This is the index of the key.
		const bool key_tx_bit, ///< This is the TX bit of the key.
		const u8_t * const key_RSC, ///< This is the RSC counter
		const u32_t key_RSC_size ///< This is the size of RSC counter
		);

	/**
	 * The constructor of the eapol_session_key_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H eapol_session_key_c(
		abs_eap_am_tools_c * const tools
		);

	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H const eap_variable_data_c * get_key() const;

	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H const eap_variable_data_c * get_sequence_number() const;

	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H eapol_key_type_e get_key_type() const;

	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H u32_t get_key_index() const;

	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H bool get_key_tx_bit() const;

	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H bool get_is_valid() const;


	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H eap_status_e set_key(const eap_variable_data_c * const key);

	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H eap_status_e set_sequence_number(eap_variable_data_c * const sequence_number);

	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H void set_key_type(const eapol_key_type_e key_type);

	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H void set_key_index(const u32_t key_index);

	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H void set_key_tx_bit(const bool key_tx_bit);

	EAP_FUNC_VISIBILITY_EAPOL_SESSION_KEY_H static eap_const_string get_eapol_key_type_string(
		const eapol_key_type_e key_type);

	//--------------------------------------------------
}; // class eapol_session_key_c

#endif //#if !defined(_EAPOL_SESSION_KEY_H_)

//--------------------------------------------------



// End.
