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

#if !defined(_RADIUS_STATE_H_)
#define _RADIUS_STATE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_RADIUS_STATE_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_STATE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_STATE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_STATE_H 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_STATE_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_STATE_H 
#elif defined(EAP_EXPORT_EAP_RADIUS_STATE_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_STATE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_STATE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_STATE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_STATE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_STATE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_STATE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_STATE_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_STATE_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "eap_radius_header.h"
#include "eap_radius_types.h"
#include "eap_radius_payloads.h"
#include "abs_eap_radius_state.h"
#include "abs_eap_base_timer.h"
#if defined(USE_EAP_TYPE_SERVER_RADIUS)
	#include "eap_sim_triplets.h"
#endif //#if defined(USE_EAP_TYPE_SERVER_RADIUS)
#include "eap_radius_state_notification.h"
#include "eap_am_network_id.h"


#endif //#if !defined(_RADIUS_STATE_H_)

//--------------------------------------------------



// End.
