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
	#define EAP_FILE_NUMBER_ENUM 61 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_type_selection.h"

//--------------------------------------------------

EAP_FUNC_EXPORT eap_type_selection_c::~eap_type_selection_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_type_selection_c::eap_type_selection_c(
	abs_eap_am_tools_c * const tools,
	const eap_type_value_e type,
	const bool is_enabled)
	: m_am_tools(tools)
	, m_type(type)
	, m_is_enabled(is_enabled)
	, m_is_valid(true)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_type_value_e eap_type_selection_c::get_type() const
{
	return m_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_type_selection_c::get_is_enabled() const
{
	return m_is_enabled;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_type_selection_c * eap_type_selection_c::copy() const
{
	eap_type_selection_c * const copy_object = new eap_type_selection_c(
		m_am_tools,
		m_type,
		m_is_enabled);

	return copy_object;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_type_selection_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_type_selection_c::get_is_valid_data() const
{
	return (m_type != eap_type_none);
}

//--------------------------------------------------


// End.
