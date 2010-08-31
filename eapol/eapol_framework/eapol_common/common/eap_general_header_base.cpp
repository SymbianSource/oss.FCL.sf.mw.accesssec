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
* %version: 11.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 24 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_general_header_base.h"


//
EAP_FUNC_EXPORT eap_general_header_base_c::~eap_general_header_base_c()
{
	// NOTE do not delete these attributes. These are references to objects owned by other objects.
	m_header_buffer = 0;
	m_header_buffer_length = 0ul;
}

// 
EAP_FUNC_EXPORT eap_general_header_base_c::eap_general_header_base_c(
	abs_eap_am_tools_c * const tools,
	void * const header_buffer,
	const u32_t header_buffer_length)
	: m_am_tools(tools)
	, m_header_buffer(static_cast<u8_t *>(header_buffer))
	, m_header_buffer_length(header_buffer_length)
#if defined(USE_EAP_ERROR_TESTS)
	, m_error_detected(true)
#endif //#if defined(USE_EAP_ERROR_TESTS)
{
}

EAP_FUNC_EXPORT void eap_general_header_base_c::set_header_buffer(u8_t * const header_buffer, const u32_t header_buffer_length)
{
	m_header_buffer = header_buffer;
	m_header_buffer_length = header_buffer_length;
}

EAP_FUNC_EXPORT u8_t * eap_general_header_base_c::get_header_buffer(const u32_t data_length) const
{
	if (m_header_buffer_length >= data_length)
	{
		return m_header_buffer;
	}
	return 0;
}

EAP_FUNC_EXPORT u32_t eap_general_header_base_c::get_header_buffer_length() const
{
	return m_header_buffer_length;
}

EAP_FUNC_EXPORT u8_t * eap_general_header_base_c::get_header_offset(
	const u32_t offset,
	const u32_t data_length) const
{
	if (get_header_buffer_length() >= offset+data_length)
	{
		return get_header_buffer(offset+data_length)+offset;
	}
	else
	{
		//NOTE: Cannot assert here because illagal message will always fail. EAP_ASSERT(get_header_buffer_length() >= offset+data_length);
		return 0;
	}
}

EAP_FUNC_EXPORT bool eap_general_header_base_c::get_is_valid() const
{
	if (get_header_buffer_length() == 0
		|| get_header_buffer(get_header_buffer_length()) == 0)
	{
		return false;
	}
	return true;
}

EAP_FUNC_EXPORT abs_eap_am_tools_c * eap_general_header_base_c::get_am_tools() const
{
	return m_am_tools;
}


#if defined(USE_EAP_ERROR_TESTS)

EAP_FUNC_EXPORT void eap_general_header_base_c::set_error_detected(const bool error_detected)
{
	m_error_detected = error_detected;
}

EAP_FUNC_EXPORT bool eap_general_header_base_c::get_error_detected()
{
	return m_error_detected;
}

#endif //#if defined(USE_EAP_ERROR_TESTS)


//--------------------------------------------------



// End.
