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
* %version: 3 %
*/

#if !defined(_ABS_PAC_STORE_INITIALIZER_H_)
#define _ABS_PAC_STORE_INITIALIZER_H_

#include "eap_fast_types.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_PAC_STORE_INITIALIZER_H)
	#define EAP_CLASS_VISIBILITY_ABS_PAC_STORE_INITIALIZER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_PAC_STORE_INITIALIZER_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_PAC_STORE_INITIALIZER_H 
	#define EAP_FUNC_EXPORT_ABS_PAC_STORE_INITIALIZER_H 
	#define EAP_C_FUNC_EXPORT_ABS_PAC_STORE_INITIALIZER_H 
#elif defined(EAP_EXPORT_ABS_PAC_STORE_INITIALIZER_H)
	#define EAP_CLASS_VISIBILITY_ABS_PAC_STORE_INITIALIZER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_PAC_STORE_INITIALIZER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_PAC_STORE_INITIALIZER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_PAC_STORE_INITIALIZER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_PAC_STORE_INITIALIZER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_PAC_STORE_INITIALIZER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_PAC_STORE_INITIALIZER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_PAC_STORE_INITIALIZER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_PAC_STORE_INITIALIZER_H 
	#define EAP_C_FUNC_EXPORT_ABS_PAC_STORE_INITIALIZER_H 
#endif
// End: added by script change_export_macros.sh.


/// The class is the interface to partner class of the tls_base_application_c class which starts the PAC-store initialization.
/// This declares the pure virtual member functions tls_base_application_c class could call.
class EAP_CLASS_VISIBILITY_ABS_PAC_STORE_INITIALIZER_H abs_pac_store_initializer_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the abs_pac_store_initializer_c class does nothing special.
	 */
	virtual ~abs_pac_store_initializer_c()
	{
	}

	/**
	 * The constructor of the abs_pac_store_initializer_c class does nothing special.
	 */
	abs_pac_store_initializer_c()
	{
	}

#if defined(USE_FAST_EAP_TYPE)

	virtual eap_status_e complete_start_initialize_PAC_store(
		const eap_fast_completion_operation_e completion_operation,
		const eap_fast_initialize_pac_store_completion_e completion) = 0;

#endif //#if defined(USE_FAST_EAP_TYPE)

	//--------------------------------------------------
}; // class abs_pac_store_initializer_c

#endif //#if !defined(_ABS_PAC_STORE_INITIALIZER_H_)

//--------------------------------------------------

// End.
