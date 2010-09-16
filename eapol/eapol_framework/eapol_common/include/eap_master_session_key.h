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

#if !defined(_EAP_MASTER_SESSION_KEY_H_)
#define _EAP_MASTER_SESSION_KEY_H_

#include "eap_am_types.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_MASTER_SESSION_KEY_H)
	#define EAP_CLASS_VISIBILITY_EAP_MASTER_SESSION_KEY_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_MASTER_SESSION_KEY_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_MASTER_SESSION_KEY_H 
	#define EAP_FUNC_EXPORT_EAP_MASTER_SESSION_KEY_H 
	#define EAP_C_FUNC_EXPORT_EAP_MASTER_SESSION_KEY_H 
#elif defined(EAP_EXPORT_EAP_MASTER_SESSION_KEY_H)
	#define EAP_CLASS_VISIBILITY_EAP_MASTER_SESSION_KEY_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_MASTER_SESSION_KEY_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_MASTER_SESSION_KEY_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_MASTER_SESSION_KEY_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_MASTER_SESSION_KEY_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_MASTER_SESSION_KEY_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_MASTER_SESSION_KEY_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_MASTER_SESSION_KEY_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_MASTER_SESSION_KEY_H 
	#define EAP_C_FUNC_EXPORT_EAP_MASTER_SESSION_KEY_H 
#endif
// End: added by script change_export_macros.sh.
//#include "eap_am_memory.h"
#include "eap_am_assert.h"
#include "eap_status.h"
#include "eap_variable_data.h"
#include "eap_header.h"

//--------------------------------------------------

class abs_eap_am_tools_c;


/// This class stores data of master session key.
class EAP_CLASS_VISIBILITY_EAP_MASTER_SESSION_KEY_H eap_master_session_key_c
: public eap_variable_data_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c
	abs_eap_am_tools_c * const m_am_tools;

	/// LEAP uses password in the RADIUS message generation too.
	eap_variable_data_c m_leap_password;

	/// This is the EAP-type.
	eap_type_value_e m_eap_type;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor of the eap_variable_data class will release 
	 * the buffer if attribute m_free_buffer is true.
	 */
	EAP_FUNC_VISIBILITY_EAP_MASTER_SESSION_KEY_H virtual ~eap_master_session_key_c();

	/**
	 * Constructor takes only one parameter called tools.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 */
	EAP_FUNC_VISIBILITY_EAP_MASTER_SESSION_KEY_H eap_master_session_key_c(
		abs_eap_am_tools_c * const tools,
		const eap_type_value_e eap_type);

	EAP_FUNC_VISIBILITY_EAP_MASTER_SESSION_KEY_H eap_type_value_e get_eap_type() const;

	EAP_FUNC_VISIBILITY_EAP_MASTER_SESSION_KEY_H void set_eap_type(eap_type_value_e type);

	EAP_FUNC_VISIBILITY_EAP_MASTER_SESSION_KEY_H const eap_variable_data_c * get_leap_password() const;

	EAP_FUNC_VISIBILITY_EAP_MASTER_SESSION_KEY_H eap_status_e copy_leap_password(const eap_variable_data_c * const key);

	EAP_FUNC_VISIBILITY_EAP_MASTER_SESSION_KEY_H eap_status_e set_copy(const eap_master_session_key_c * const msk);

	//--------------------------------------------------
}; // class eap_master_session_key_c


#endif //#if !defined(_EAP_MASTER_SESSION_KEY_H_)



// End.
