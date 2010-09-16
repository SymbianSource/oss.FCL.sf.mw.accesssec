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

#ifndef EAP_TYPE_SECURID_STATE_H
#define EAP_TYPE_SECURID_STATE_H

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_SECURID_STATE_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_SECURID_STATE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_STATE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_SECURID_STATE_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_SECURID_STATE_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_SECURID_STATE_H 
#elif defined(EAP_EXPORT_EAP_TYPE_SECURID_STATE_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_SECURID_STATE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_SECURID_STATE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_SECURID_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_SECURID_STATE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_SECURID_STATE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_SECURID_STATE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_SECURID_STATE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_SECURID_STATE_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_SECURID_STATE_H 
#endif
// End: added by script change_export_macros.sh.

/**
 * This is the internal state of the SecurId and GTC EAP type.
 */
enum eap_type_securid_state_variable_e
{
	eap_type_securid_state_none,
	eap_type_securid_state_identity_query,

	eap_type_securid_state_passcode_query,
	eap_type_securid_state_pincode_query,
	eap_type_securid_state_success,
	eap_type_securid_state_failure,

	eap_type_securid_state_gtc_user_input_query,

	eap_type_securid_state_identity_response,
	eap_type_securid_state_passcode_response,

	eap_type_securid_state_gtc_response
};


class EAP_CLASS_VISIBILITY_EAP_TYPE_SECURID_STATE_H eap_type_securid_state_c
{
private:

	bool m_is_client;
	eap_type_securid_state_variable_e m_state;
	eap_type_securid_state_variable_e m_next_state;
	eap_type_securid_state_variable_e m_prev_state;

public:
	eap_type_securid_state_c(const bool client);

	virtual ~eap_type_securid_state_c();

	eap_type_securid_state_variable_e get_state() const;

	void set_state(const eap_type_securid_state_variable_e new_state);

	void set_state(const eap_type_securid_state_variable_e new_state, const eap_type_securid_state_variable_e next_state);

	bool is_valid_state(const eap_type_securid_state_variable_e new_state) const;

	void set_failure_message_received();

	void unset_failure_message_received();

	void cancel_eap_failure_timer();
};


#endif // EAP_TYPE_SECURID_STATE_H

//--------------------------------------------------


// End.
