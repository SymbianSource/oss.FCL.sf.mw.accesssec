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

#if !defined(_EAP_NETWORK_ID_SELECTOR_H_)
#define _EAP_NETWORK_ID_SELECTOR_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_NETWORK_ID_SELECTOR_H)
	#define EAP_CLASS_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H 
	#define EAP_FUNC_EXPORT_EAP_NETWORK_ID_SELECTOR_H 
	#define EAP_C_FUNC_EXPORT_EAP_NETWORK_ID_SELECTOR_H 
#elif defined(EAP_EXPORT_EAP_NETWORK_ID_SELECTOR_H)
	#define EAP_CLASS_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_NETWORK_ID_SELECTOR_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_NETWORK_ID_SELECTOR_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_NETWORK_ID_SELECTOR_H 
	#define EAP_C_FUNC_EXPORT_EAP_NETWORK_ID_SELECTOR_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_variable_data.h"
#include "eap_am_network_id.h"


//--------------------------------------------------

class EAP_CLASS_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H eap_network_id_selector_c
: public eap_variable_data_c
{
private:

	abs_eap_am_tools_c * const m_am_tools;

public:

	EAP_FUNC_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H virtual ~eap_network_id_selector_c();

	EAP_FUNC_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H eap_network_id_selector_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H eap_network_id_selector_c(
		abs_eap_am_tools_c * const tools,
		const eap_am_network_id_c * const network_id);

	EAP_FUNC_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H eap_status_e set_selector(
		const eap_am_network_id_c * const network_id);

	EAP_FUNC_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H eap_network_id_selector_c(
		abs_eap_am_tools_c * const tools,
		const eap_network_id_selector_c * const selector);


	//
	EAP_FUNC_VISIBILITY_EAP_NETWORK_ID_SELECTOR_H eap_network_id_selector_c * copy() const;

};


#endif //#if !defined(_EAP_NETWORK_ID_SELECTOR_H_)

//--------------------------------------------------



// End.
