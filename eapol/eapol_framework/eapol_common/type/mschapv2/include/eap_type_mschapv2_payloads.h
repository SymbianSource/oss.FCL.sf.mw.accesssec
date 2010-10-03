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

#ifndef _MSCHAPV2_PAYLOADS_H_
#define _MSCHAPV2_PAYLOADS_H_

#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_MSCHAPV2_PAYLOADS_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_PAYLOADS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_PAYLOADS_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_PAYLOADS_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_PAYLOADS_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_PAYLOADS_H 
#elif defined(EAP_EXPORT_EAP_TYPE_MSCHAPV2_PAYLOADS_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_PAYLOADS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_PAYLOADS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_PAYLOADS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_PAYLOADS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_PAYLOADS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_PAYLOADS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_PAYLOADS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_PAYLOADS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_PAYLOADS_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_PAYLOADS_H 
#endif
// End: added by script change_export_macros.sh.


class EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_PAYLOADS_H mschapv2_data_c
{
private:

    eap_variable_data_c m_username; // Ascii
	eap_variable_data_c m_password; // Unicode

    eap_variable_data_c m_challenge;
    eap_variable_data_c m_peer_challenge;

    u8_t m_identifier;
    u8_t m_mschapv2id;

    u32_t m_error_code;

    // Client
    eap_boolean_e m_password_prompt_enabled;

    eap_variable_data_c m_nt_response;
	eap_variable_data_c m_new_password;

protected:

public:

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_PAYLOADS_H ~mschapv2_data_c();

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_PAYLOADS_H mschapv2_data_c(abs_eap_am_tools_c * const tools);

    eap_boolean_e get_password_prompt_enabled() const;

    void set_password_prompt_enabled(eap_boolean_e is_enabled);

    eap_variable_data_c * const get_username();

    eap_variable_data_c * const get_password();

	eap_variable_data_c * const get_challenge();

	eap_variable_data_c * const get_peer_challenge();

    // Client

	eap_variable_data_c * const get_nt_response();

    eap_variable_data_c * const get_new_password();

    u8_t get_identifier() const;

    void set_identifier(u8_t identifier);

    u8_t get_mschapv2id() const;

    void set_mschapv2id(u8_t mschapv2id);

    u32_t get_error_code() const;

    void set_error_code(u32_t error_code);
};

#endif //_MSCHAPV2_PAYLOADS_H_
