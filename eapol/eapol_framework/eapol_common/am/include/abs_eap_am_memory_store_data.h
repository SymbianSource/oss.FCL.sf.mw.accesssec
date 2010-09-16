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

#if !defined( _ABS_EAP_AM_TOOLS_MEMORY_STORE_DATA_H_ )
#define _ABS_EAP_AM_TOOLS_MEMORY_STORE_DATA_H_


#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_MEMORY_STORE_DATA_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_MEMORY_STORE_DATA_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_MEMORY_STORE_DATA_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_MEMORY_STORE_DATA_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_MEMORY_STORE_DATA_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_MEMORY_STORE_DATA_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_MEMORY_STORE_DATA_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_MEMORY_STORE_DATA_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_MEMORY_STORE_DATA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_MEMORY_STORE_DATA_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_MEMORY_STORE_DATA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_MEMORY_STORE_DATA_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_MEMORY_STORE_DATA_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_MEMORY_STORE_DATA_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_MEMORY_STORE_DATA_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_MEMORY_STORE_DATA_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_MEMORY_STORE_DATA_H 
#endif
// End: added by script change_export_macros.sh.

/// This class is base class for data stored to memory store.
/**
 * Here are no real functions.
 */
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_MEMORY_STORE_DATA_H abs_eap_am_memory_store_data_c
{
public:

	/**
	 * The destructor of the abs_eap_am_memory_store_data_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MEMORY_STORE_DATA_H virtual ~abs_eap_am_memory_store_data_c();

	/**
	 * The constructor of the abs_eap_am_memory_store_data_c does nothing special.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_MEMORY_STORE_DATA_H abs_eap_am_memory_store_data_c();

};

#endif //#if !defined( _ABS_EAP_AM_TOOLS_MEMORY_STORE_DATA_H_ )



// End.
