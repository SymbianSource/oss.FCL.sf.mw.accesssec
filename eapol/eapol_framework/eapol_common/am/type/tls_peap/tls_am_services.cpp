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
	#define EAP_FILE_NUMBER_ENUM 19 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#error no used anymore.


#include "eap_tools.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
#include "tls_am_services.h"

// 
EAP_FUNC_EXPORT tls_am_services_c::~tls_am_services_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

// 
EAP_FUNC_EXPORT tls_am_services_c::tls_am_services_c(abs_eap_am_tools_c * const tools)
: m_am_partner(0)
, m_am_tools(tools)
, m_is_valid(false)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	set_is_valid();
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

/** Function returns partner object of adaptation module of TLS.
 *  Partner object is the TLS object.
 */
EAP_FUNC_EXPORT abs_tls_am_services_c * tls_am_services_c::get_am_partner()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_am_partner;
}

/** Function sets partner object of adaptation module of TLS.
 *  Partner object is the TLS object.
 */
EAP_FUNC_EXPORT void tls_am_services_c::set_am_partner(abs_tls_am_services_c * const partner)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	m_am_partner = partner;
}

EAP_FUNC_EXPORT void tls_am_services_c::set_is_valid()
{
	m_is_valid = true;
}

EAP_FUNC_EXPORT bool tls_am_services_c::get_is_valid()
{
	return m_is_valid;
}

/** @file */ 


//--------------------------------------------------



// End.
