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

#error Do not use this anymore.

#if !defined(_EAP_HANDLE_H_)
#define _EAP_HANDLE_H_

#include "eap_am_types.h"
#include "eap_am_network_id.h"
#include "eap_am_export.h"
#include "abs_eap_am_tools.h"
//#include "eap_am_memory.h"
#include "eap_am_assert.h"
#include "eap_header.h"
#include "eap_status.h"

//--------------------------------------------------

/// This class stores connection information of one session.
class EAP_EXPORT eap_handle_c
: public eap_variable_data_c
{
private:

	eap_am_network_id_c m_send_network_id;

	eap_type_value_e m_eap_type;

public:

	EAP_FUNC_IMPORT virtual ~eap_handle_c();

	EAP_FUNC_IMPORT eap_handle_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_IMPORT eap_handle_c(
		abs_eap_am_tools_c * const tools,
		eap_variable_data_c * const selector,
		const eap_am_network_id_c * const network_id,
		const eap_type_value_e p_eap_type);

	EAP_FUNC_IMPORT eap_status_e set_handle(
		eap_variable_data_c * const selector,
		const eap_am_network_id_c * const network_id,
		const eap_type_value_e p_eap_type);

	EAP_FUNC_IMPORT const eap_am_network_id_c * get_send_network_id() const;

	EAP_FUNC_IMPORT eap_type_value_e get_eap_type() const;

	EAP_FUNC_IMPORT void reset();
};

//--------------------------------------------------



#endif //#if !defined(_EAP_HANDLE_H_)



// End.
