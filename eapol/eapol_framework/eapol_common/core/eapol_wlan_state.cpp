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
	#define EAP_FILE_NUMBER_ENUM 59 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eapol_wlan_state.h"

//--------------------------------------------------

EAP_FUNC_EXPORT eapol_wlan_state_c::~eapol_wlan_state_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eapol_wlan_state_c::eapol_wlan_state_c(
		abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(true)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eapol_wlan_state_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------

// End.
