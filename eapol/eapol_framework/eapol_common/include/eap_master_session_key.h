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
//#include "eap_am_memory.h"
#include "eap_am_assert.h"
#include "eap_status.h"
#include "eap_variable_data.h"
#include "eap_header.h"

//--------------------------------------------------

class abs_eap_am_tools_c;


/// This class stores data of master session key.
class EAP_EXPORT eap_master_session_key_c
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
	EAP_FUNC_IMPORT virtual ~eap_master_session_key_c();

	/**
	 * Constructor takes only one parameter called tools.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 */
	EAP_FUNC_IMPORT eap_master_session_key_c(
		abs_eap_am_tools_c * const tools,
		const eap_type_value_e eap_type);

	EAP_FUNC_IMPORT eap_type_value_e get_eap_type() const;

	EAP_FUNC_IMPORT void set_eap_type(eap_type_value_e type);

	EAP_FUNC_IMPORT const eap_variable_data_c * get_leap_password() const;

	EAP_FUNC_IMPORT eap_status_e copy_leap_password(const eap_variable_data_c * const key);

	EAP_FUNC_IMPORT eap_status_e set_copy(const eap_master_session_key_c * const msk);

	//--------------------------------------------------
}; // class eap_master_session_key_c


#endif //#if !defined(_EAP_MASTER_SESSION_KEY_H_)



// End.
