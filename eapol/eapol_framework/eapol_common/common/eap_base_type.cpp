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
	#define EAP_FILE_NUMBER_ENUM 20 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_base_type.h"


EAP_FUNC_EXPORT eap_base_type_c::~eap_base_type_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

EAP_FUNC_EXPORT eap_base_type_c::eap_base_type_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner)
: m_type_partner(partner)
, m_am_tools(tools)
, m_reference_count(0u)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

EAP_FUNC_EXPORT void eap_base_type_c::object_increase_reference_count()
{
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("REF: eap_base_type_c::object_increase_reference_count(): this 0x%08x, counter %d.\n"),
		this, m_reference_count+1));
	++m_reference_count;
}

EAP_FUNC_EXPORT u32_t eap_base_type_c::object_decrease_reference_count()
{
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("REF: eap_base_type_c::object_decrease_reference_count(): this 0x%08x, counter %d.\n"),
		this, m_reference_count));
	if (m_reference_count > 0u)
	{
		--m_reference_count;
	}
	else if (m_reference_count == 0u)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: eap_base_type_c::object_decrease_reference_count(): reference count already zero (0).\n")));
	}
	return m_reference_count;
}

EAP_FUNC_EXPORT abs_eap_base_type_c * eap_base_type_c::get_type_partner()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_type_partner;
}


//--------------------------------------------------



// End.
