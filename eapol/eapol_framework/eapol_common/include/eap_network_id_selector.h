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
* %version: 10 %
*/

#if !defined(_EAP_NETWORK_ID_SELECTOR_H_)
#define _EAP_NETWORK_ID_SELECTOR_H_

#include "eap_tools.h"
#include "eap_am_export.h"
#include "eap_variable_data.h"
#include "eap_am_network_id.h"


//--------------------------------------------------

class EAP_EXPORT eap_network_id_selector_c
: public eap_variable_data_c
{
private:

	abs_eap_am_tools_c * const m_am_tools;

public:

	EAP_FUNC_IMPORT virtual ~eap_network_id_selector_c();

	EAP_FUNC_IMPORT eap_network_id_selector_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_IMPORT eap_network_id_selector_c(
		abs_eap_am_tools_c * const tools,
		const eap_am_network_id_c * const network_id);

	EAP_FUNC_IMPORT eap_status_e set_selector(
		const eap_am_network_id_c * const network_id);

	EAP_FUNC_IMPORT eap_network_id_selector_c(
		abs_eap_am_tools_c * const tools,
		const eap_network_id_selector_c * const selector);


	//
	EAP_FUNC_IMPORT eap_network_id_selector_c * copy() const;

};


#endif //#if !defined(_EAP_NETWORK_ID_SELECTOR_H_)

//--------------------------------------------------



// End.
