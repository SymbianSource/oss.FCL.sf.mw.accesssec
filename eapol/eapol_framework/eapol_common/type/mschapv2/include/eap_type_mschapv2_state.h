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

#ifndef _MSCHAPV2_STATE_H_
#define _MSCHAPV2_STATE_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_MSCHAPV2_STATE_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_STATE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_STATE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_STATE_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_STATE_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_STATE_H 
#elif defined(EAP_EXPORT_EAP_TYPE_MSCHAPV2_STATE_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_STATE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_STATE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_STATE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_STATE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_STATE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_STATE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_STATE_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_MSCHAPV2_STATE_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_tools.h"

/**
 * This is the internal state of the MSCHAPV2 EAP type.
 */
enum eap_type_mschapv2_state_variable_e
{
	// Common
	eap_type_mschapv2_state_none,

	eap_type_mschapv2_state_success,
	eap_type_mschapv2_state_failure,

	// Client
	eap_type_mschapv2_state_identity_request,
	eap_type_mschapv2_state_challenge_request,
	eap_type_mschapv2_state_success_request,
	eap_type_mschapv2_state_failure_request,
	eap_type_mschapv2_state_change_password_request,

	// Server
	eap_type_mschapv2_state_identity_response,
	eap_type_mschapv2_state_challenge_response,
	eap_type_mschapv2_state_success_response,
	eap_type_mschapv2_state_failure_response,
	eap_type_mschapv2_state_change_password_response
};

class EAP_CLASS_VISIBILITY_EAP_TYPE_MSCHAPV2_STATE_H eap_type_mschapv2_state_c
{

private:

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	bool m_is_client;
	eap_type_mschapv2_state_variable_e m_state;
	eap_type_mschapv2_state_variable_e m_prev_state;
	eap_type_mschapv2_state_variable_e m_next_state;

	bool m_failure_message_received;

public:
	eap_type_mschapv2_state_c(abs_eap_am_tools_c * const tools, const bool client);

	EAP_FUNC_VISIBILITY_EAP_TYPE_MSCHAPV2_STATE_H virtual ~eap_type_mschapv2_state_c();

	void reset();

	eap_type_mschapv2_state_variable_e get_state() const;

	void set_state(const eap_type_mschapv2_state_variable_e new_state);

	void set_state(const eap_type_mschapv2_state_variable_e new_state, const eap_type_mschapv2_state_variable_e next_state);

	bool is_valid_state(const eap_type_mschapv2_state_variable_e new_state) const;

	void set_failure_message_received();

	void unset_failure_message_received();

	void cancel_eap_failure_timer();

	static eap_const_string get_state_string(const eap_type_mschapv2_state_variable_e state);
};




#endif //_MSCHAPV2_STATE_H_
