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
	#define EAP_FILE_NUMBER_ENUM 11 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory_store_data.h"

//#if !defined(NO_EAP_AM_MEMORY_STORE)


//-------------------------------------------------------------------

EAP_FUNC_EXPORT abs_eap_am_memory_store_data_c::~abs_eap_am_memory_store_data_c()
{
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT abs_eap_am_memory_store_data_c::abs_eap_am_memory_store_data_c()
{
}

//-------------------------------------------------------------------
//-------------------------------------------------------------------
//-------------------------------------------------------------------


EAP_FUNC_EXPORT eap_am_memory_store_tlv_data_c::~eap_am_memory_store_tlv_data_c()
{
}

EAP_FUNC_EXPORT eap_am_memory_store_tlv_data_c::eap_am_memory_store_tlv_data_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	  , m_tlv_data(tools)
	  , m_timer_id(0ul)
{
}

EAP_FUNC_EXPORT eap_status_e eap_am_memory_store_tlv_data_c::copy_message_data(
	const eap_tlv_message_data_c * const tlv_data,
	const u32_t timer_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_timer_id = timer_id;

	eap_status_e status = m_tlv_data.copy_message_data(
		tlv_data->get_message_data_length(),
		tlv_data->get_message_data());
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT u32_t eap_am_memory_store_tlv_data_c::get_timer_id() const
{
	return m_timer_id;
}

EAP_FUNC_EXPORT void * eap_am_memory_store_tlv_data_c::get_message_data() const
{
	return m_tlv_data.get_message_data();
}

EAP_FUNC_EXPORT u32_t eap_am_memory_store_tlv_data_c::get_message_data_length() const
{
	return m_tlv_data.get_message_data_length();
}

EAP_FUNC_EXPORT void eap_am_memory_store_tlv_data_c::object_increase_reference_count()
{
}

EAP_FUNC_EXPORT u32_t eap_am_memory_store_tlv_data_c::object_decrease_reference_count()
{
	return 0ul;
}


//#endif //#if !defined(NO_EAP_AM_MEMORY_STORE)



// End.
