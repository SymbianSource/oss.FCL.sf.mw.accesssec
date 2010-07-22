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

#if !defined(_EAP_TYPE_ALL_H_)
#define _EAP_TYPE_ALL_H_

//#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_export.h"
#include "eap_base_type.h"
#include "abs_eap_base_type.h"
#include "eap_variable_data.h"

class abs_eap_configuration_if_c;

//--------------------------------------------------

/** @file */ 

/**
 * This function creates a new instance of EAP-type.
 * @param tools is pointer to the abs_eap_am_tools class created by the adaptation module.
 * @param partner is pointer to the caller of the new_eap_type().
 * @param type is the EAP-type that will be created.
 *
 * NOTE one module could include many EAP-types.
 * EAP-type will callback caller using the partner pointer.
 */
EAP_C_FUNC_IMPORT eap_base_type_c * const new_eap_type(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	const eap_type_value_e eap_type,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id
#if defined(USE_EAP_SIMPLE_CONFIG)
	, abs_eap_configuration_if_c * const configuration_if
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
	);

//--------------------------------------------------

#endif //#if !defined(_EAP_TYPE_ALL_H_)




// End.
