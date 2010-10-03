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
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_HANDLE_H)
	#define EAP_CLASS_VISIBILITY_EAP_HANDLE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_HANDLE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_HANDLE_H 
	#define EAP_FUNC_EXPORT_EAP_HANDLE_H 
	#define EAP_C_FUNC_EXPORT_EAP_HANDLE_H 
#elif defined(EAP_EXPORT_EAP_HANDLE_H)
	#define EAP_CLASS_VISIBILITY_EAP_HANDLE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_HANDLE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_HANDLE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_HANDLE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_HANDLE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_HANDLE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_HANDLE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_HANDLE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_HANDLE_H 
	#define EAP_C_FUNC_EXPORT_EAP_HANDLE_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_tools.h"
//#include "eap_am_memory.h"
#include "eap_am_assert.h"
#include "eap_header.h"
#include "eap_status.h"

//--------------------------------------------------

/// This class stores connection information of one session.
class EAP_CLASS_VISIBILITY_EAP_HANDLE_H eap_handle_c
: public eap_variable_data_c
{
private:

	eap_am_network_id_c m_send_network_id;

	eap_type_value_e m_eap_type;

public:

	EAP_FUNC_VISIBILITY_EAP_HANDLE_H virtual ~eap_handle_c();

	EAP_FUNC_VISIBILITY_EAP_HANDLE_H eap_handle_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAP_HANDLE_H eap_handle_c(
		abs_eap_am_tools_c * const tools,
		eap_variable_data_c * const selector,
		const eap_am_network_id_c * const network_id,
		const eap_type_value_e p_eap_type);

	EAP_FUNC_VISIBILITY_EAP_HANDLE_H eap_status_e set_handle(
		eap_variable_data_c * const selector,
		const eap_am_network_id_c * const network_id,
		const eap_type_value_e p_eap_type);

	EAP_FUNC_VISIBILITY_EAP_HANDLE_H const eap_am_network_id_c * get_send_network_id() const;

	EAP_FUNC_VISIBILITY_EAP_HANDLE_H eap_type_value_e get_eap_type() const;

	EAP_FUNC_VISIBILITY_EAP_HANDLE_H void reset();
};

//--------------------------------------------------



#endif //#if !defined(_EAP_HANDLE_H_)



// End.
