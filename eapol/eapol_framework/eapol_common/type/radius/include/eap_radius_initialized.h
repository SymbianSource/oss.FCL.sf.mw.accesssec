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

#if !defined(_RADIUS_INITIALIZED_H_)
#define _RADIUS_INITIALIZED_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_RADIUS_INITIALIZED_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_INITIALIZED_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_INITIALIZED_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_INITIALIZED_H 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_INITIALIZED_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_INITIALIZED_H 
#elif defined(EAP_EXPORT_EAP_RADIUS_INITIALIZED_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_INITIALIZED_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_INITIALIZED_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_INITIALIZED_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_INITIALIZED_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_INITIALIZED_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_INITIALIZED_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_INITIALIZED_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_INITIALIZED_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_INITIALIZED_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_INITIALIZED_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "eap_radius_header.h"
#include "eap_radius_types.h"
#include "eap_radius_payloads.h"
#include "abs_eap_radius_state.h"
#include "abs_eap_am_tools.h"


const u32_t RADIUS_MAX_OFFER_COUNT = 3;


class EAP_CLASS_VISIBILITY_EAP_RADIUS_INITIALIZED_H eap_radius_initialized_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	u32_t m_counter;

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~eap_radius_initialized_c();

	// 
	eap_radius_initialized_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_radius_state_c * const /*partner*/);

	u32_t counter();

	void increment();

	void reset();

};


#endif //#if !defined(_RADIUS_INITIALIZED_H_)

//--------------------------------------------------



// End.
