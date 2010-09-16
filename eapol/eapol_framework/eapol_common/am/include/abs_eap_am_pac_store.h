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
* %version: 7 %
*/

#if !defined(_ABS_EAP_AM_PAC_STORE_H_)
#define _ABS_EAP_AM_PAC_STORE_H_

#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_PAC_STORE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_PAC_STORE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_PAC_STORE_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_PAC_STORE_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_PAC_STORE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_PAC_STORE_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_PAC_STORE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_PAC_STORE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_PAC_STORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_PAC_STORE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_PAC_STORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_PAC_STORE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_PAC_STORE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_PAC_STORE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_PAC_STORE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_PAC_STORE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_PAC_STORE_H 
#endif
// End: added by script change_export_macros.sh.

/** @file */

/// This class is the common part of EAP message interface.
/// This class is interface to the message creation and parsing function.
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_PAC_STORE_H abs_eap_am_pac_store_c
{

private:

	// ----------------------------------------------------------------------

public:

	virtual ~abs_eap_am_pac_store_c()
	{
	}

	virtual eap_status_e complete_is_master_key_present(
	  const bool is_present) = 0;

	virtual eap_status_e complete_is_master_key_and_password_matching(
	  const bool is_matching) = 0;

	virtual eap_status_e complete_create_and_save_master_key(
		const eap_status_e completion_status) = 0;

	virtual eap_status_e complete_compare_pac_store_password(
		const bool is_matching) = 0;

	virtual eap_status_e complete_is_pacstore_password_present(
		const bool is_present) = 0;

	virtual eap_status_e complete_set_pac_store_password(
		const eap_status_e completion_status) = 0;

	virtual eap_status_e complete_destroy_pac_store(
		const eap_status_e completion_status) = 0;

	// ----------------------------------------------------------------------
};

#endif //#if !defined(_ABS_EAP_AM_PAC_STORE_H_)


//--------------------------------------------------
// End
