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

#if !defined(_RADIUS_STATE_H_)
#define _RADIUS_STATE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
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
