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
* %version: 8 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 107 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_radius_initialized.h"


// 
eap_radius_initialized_c::~eap_radius_initialized_c()
{
}

// 
eap_radius_initialized_c::eap_radius_initialized_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_radius_state_c * const /*partner*/)
	: m_am_tools(tools)
	, m_counter(1u)
{
}

u32_t eap_radius_initialized_c::counter()
{
	return m_counter;
}

void eap_radius_initialized_c::increment()
{
	++m_counter;
}

//--------------------------------------------------

void eap_radius_initialized_c::reset()
{
	m_counter = 0u;
}

//--------------------------------------------------



// End.
