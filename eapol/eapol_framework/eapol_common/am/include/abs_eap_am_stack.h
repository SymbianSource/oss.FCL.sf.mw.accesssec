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

#if !defined(_ABS_EAP_AM_STACK_H_)
#define _ABS_EAP_AM_STACK_H_

#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_STACK_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_STACK_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_STACK_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_STACK_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_STACK_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_STACK_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_STACK_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_STACK_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_STACK_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_STACK_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_STACK_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_STACK_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_STACK_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_STACK_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_STACK_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_STACK_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_STACK_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_expanded_type.h"
#include "eap_array.h"

class abs_eap_am_message_if_c;
class eap_configuration_field_c;
class eap_variable_data_c;
class abs_eap_am_tools_c;
class abs_eap_base_type_c;
class eap_base_type_c;
class eap_am_network_id_c;

/** @file */

/// This class is the common part of EAP message interface.
/// This class is interface to the message creation and parsing function.
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_STACK_H abs_eap_am_stack_c
{

private:

	// ----------------------------------------------------------------------

public:

	virtual ~abs_eap_am_stack_c()
	{
	}

	virtual eap_status_e complete_get_802_11_authentication_mode(
		const eap_status_e completion_status,
		const eap_am_network_id_c * const receive_network_id,
		const eapol_key_802_11_authentication_mode_e mode) = 0;

	// ----------------------------------------------------------------------
};

#endif //#if !defined(_ABS_EAP_AM_STACK_H_)


//--------------------------------------------------
// End
