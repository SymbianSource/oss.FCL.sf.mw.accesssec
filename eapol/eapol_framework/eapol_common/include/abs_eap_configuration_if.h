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

#if !defined(_ABS_EAPOL_WLAN_CONFIGURATION_REFERENCE_IF_H_)
#define _ABS_EAPOL_WLAN_CONFIGURATION_REFERENCE_IF_H_

//--------------------------------------------------

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_CONFIGURATION_IF_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_CONFIGURATION_IF_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_CONFIGURATION_IF_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_CONFIGURATION_IF_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_CONFIGURATION_IF_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_CONFIGURATION_IF_H 
#elif defined(EAP_EXPORT_ABS_EAP_CONFIGURATION_IF_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_CONFIGURATION_IF_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_CONFIGURATION_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_CONFIGURATION_IF_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_CONFIGURATION_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_CONFIGURATION_IF_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_CONFIGURATION_IF_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_CONFIGURATION_IF_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_CONFIGURATION_IF_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_CONFIGURATION_IF_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_CONFIGURATION_IF_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_am_types.h"
#include "eap_status.h"

#if defined(USE_EAP_SIMPLE_CONFIG)
#include "simple_config_types.h"
#include "simple_config_credential.h"
#include "simple_config_payloads.h"
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)


/// This class is abstract interface to configure EAP settings.
class EAP_CLASS_VISIBILITY_ABS_EAP_CONFIGURATION_IF_H abs_eap_configuration_if_c
{

private:
	//--------------------------------------------------

	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/* The destructor does nothing */
	virtual ~abs_eap_configuration_if_c()
	{
	};
	
#if defined(USE_EAP_SIMPLE_CONFIG)
	/**
	 * This function tells AM to save SIMPLE_CONFIG configuration parameters.
	 * This is always syncronous call.
	 */
	virtual eap_status_e save_simple_config_session(
		const simple_config_state_e state,
		EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array,
		const eap_variable_data_c * const new_password,
		const simple_config_Device_Password_ID_e Device_Password_ID,
		const simple_config_payloads_c * const other_configuration
		) = 0;
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

}; // class abs_eapol_wlan_configuration_reference_if_c


#endif //#if !defined(_ABS_EAPOL_WLAN_CONFIGURATION_REFERENCE_IF_H_)

//--------------------------------------------------


// End.
