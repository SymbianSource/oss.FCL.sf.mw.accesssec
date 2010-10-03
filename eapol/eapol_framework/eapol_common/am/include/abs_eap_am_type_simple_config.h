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

#if !defined(_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H_)
#define _ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H 
#endif
// End: added by script change_export_macros.sh.

class eap_am_network_id_c;


/// This class declares the functions adaptation module of EAP-SIMPLE_CONFIG type
/// requires from the EAP-SIMPLE_CONFIG type.
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H abs_eap_am_type_simple_config_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~abs_eap_am_type_simple_config_c()
	{
	}

	// 
	abs_eap_am_type_simple_config_c()
	{
	}

	virtual bool get_is_client() = 0;

	/** Client adaptation module of EAP-SIMPLE_CONFIG type calls this function.
	 *  AM gives identity to EAP-SIMPLE_CONFIG type.
	 *  This function completes asyncronously query_eap_identity() function call.
	 *  The parameter completion_status must be eap_status_ok when query is successfull.
	 */
	virtual eap_status_e complete_eap_identity_query(
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier,
		const eap_status_e completion_status,
		const bool use_manual_username,
		const eap_variable_data_c * const manual_username,
		const bool use_manual_realm,
		const eap_variable_data_c * const manual_realm
		) = 0;


	//--------------------------------------------------
}; // class abs_eap_am_type_simple_config_c

#endif //#if !defined(_ABS_EAP_AM_TYPE_SIMPLE_CONFIG_H_)

//--------------------------------------------------



// End.
