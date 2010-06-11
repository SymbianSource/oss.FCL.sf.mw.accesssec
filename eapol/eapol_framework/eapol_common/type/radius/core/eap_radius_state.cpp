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

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 112 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_export.h"
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "eap_radius_header.h"
#include "eap_radius_types.h"
#include "eap_radius_payloads.h"
#include "abs_eap_radius_state.h"
#include "abs_eap_base_timer.h"
#include "eap_radius_state.h"
#include "eap_crypto_api.h"
#include "eap_state_notification.h"

//--------------------------------------------------


//--------------------------------------------------



// End.
