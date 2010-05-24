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

#if !defined( _EAP_STATUS_STRING_H_ )
#define _EAP_STATUS_STRING_H_

/** @file */

#include "eap_am_compiler_flags.h"

#include "eap_variable_data.h"
#include "eap_status.h"
#include "eap_am_export.h"

//----------------------------------------------------------------------------------

/// This class includes the debug strings of the eap_status_e.
class EAP_EXPORT eap_status_string_c
{
public:

	EAP_FUNC_IMPORT virtual ~eap_status_string_c();

	EAP_FUNC_IMPORT eap_status_string_c();

	/**
	 * Function returns string of eap_status_e.
	 * @param status is the queried string.
	 */
	EAP_FUNC_IMPORT static eap_const_string get_status_string(const eap_status_e status);

};

//----------------------------------------------------------------------------------

#endif //#if !defined( _EAP_STATUS_STRING_H_ )



// End.
