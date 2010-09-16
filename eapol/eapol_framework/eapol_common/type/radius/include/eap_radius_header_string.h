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

#if !defined( _EAP_RADIUS_HEADER_STRING_H_ )
#define _EAP_RADIUS_HEADER_STRING_H_

/** @file */

#include "eap_variable_data.h"
#include "eap_status.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_RADIUS_HEADER_STRING_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_HEADER_STRING_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_STRING_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_HEADER_STRING_H 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_HEADER_STRING_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_HEADER_STRING_H 
#elif defined(EAP_EXPORT_EAP_RADIUS_HEADER_STRING_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_HEADER_STRING_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_STRING_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_HEADER_STRING_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_HEADER_STRING_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_HEADER_STRING_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_HEADER_STRING_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_STRING_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_HEADER_STRING_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_HEADER_STRING_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_HEADER_STRING_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_radius_header.h"

/// This class includes the debug strings of the eap_header_base_c.
class EAP_CLASS_VISIBILITY_EAP_RADIUS_HEADER_STRING_H eap_radius_header_string_c
{
public:

	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_STRING_H virtual ~eap_radius_header_string_c();

	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_STRING_H eap_radius_header_string_c();

	/**
	 * Function returns string of eap_code_value_e.
	 * @param code is the queried string.
	 */
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_STRING_H static eap_const_string get_code_string(const eap_radius_code_value_e code);

};


#endif //#if !defined( _EAP_RADIUS_HEADER_STRING_H_ )



// End.
