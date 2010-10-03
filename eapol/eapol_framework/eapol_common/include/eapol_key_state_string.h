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

#if !defined(_EAPOL_KEY_STATE_STRING_H_)
#define _EAPOL_KEY_STATE_STRING_H_


#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_KEY_STATE_STRING_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_KEY_STATE_STRING_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_STRING_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_KEY_STATE_STRING_H 
	#define EAP_FUNC_EXPORT_EAPOL_KEY_STATE_STRING_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_KEY_STATE_STRING_H 
#elif defined(EAP_EXPORT_EAPOL_KEY_STATE_STRING_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_KEY_STATE_STRING_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_STRING_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_KEY_STATE_STRING_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_KEY_STATE_STRING_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_KEY_STATE_STRING_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_KEY_STATE_STRING_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_STRING_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_KEY_STATE_STRING_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_KEY_STATE_STRING_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_KEY_STATE_STRING_H 
#endif
// End: added by script change_export_macros.sh.
#include "eapol_rsna_key_data_header.h"
#include "eapol_rsna_key_header.h"
#include "eap_am_network_id.h"
#include "eapol_key_types.h"

//--------------------------------------------------


/// This class includes the debug strings of the tls_cipher_suites_e, tls_certificate_type_e and tls_compression_method_e.
class EAP_CLASS_VISIBILITY_EAPOL_KEY_STATE_STRING_H eapol_key_state_string_c
{
public:

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_STRING_H virtual ~eapol_key_state_string_c();

	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_STRING_H eapol_key_state_string_c();

	/**
	 * Function returns string of eapol_key_state_e.
	 * @param state is the queried string.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_STRING_H static eap_const_string get_eapol_key_state_string(
		const eapol_key_state_e state);

	/**
	 * Function returns string of eapol_key_handshake_type_e.
	 * @param state is the queried string.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_STRING_H static eap_const_string get_eapol_key_handshake_type_string(
		const eapol_key_handshake_type_e handshake_type);

	/**
	 * Function returns string of eapol_key_handshake_type_e.
	 * @param state is the queried string.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_STRING_H static eap_const_string get_eapol_key_authentication_type_string(
		const eapol_key_authentication_type_e authentication_type);

	/**
	 * Function returns string of eapol_key_descriptor_type_e.
	 * @param state is the queried string.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_KEY_STATE_STRING_H static eap_const_string get_eapol_key_descriptor_type_string(
		const eapol_key_descriptor_type_e key_descriptor_type);

};

//--------------------------------------------------

#endif //#if !defined(_EAPOL_KEY_STATE_STRING_H_)

//--------------------------------------------------


// End.
