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
	#define EAP_FILE_NUMBER_ENUM 46 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_core_nak_info.h"

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_core_nak_info_c::~eap_core_nak_info_c()
{
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_core_nak_info_c::eap_core_nak_info_c(
	abs_eap_am_tools_c * const tools,
	const eap_am_network_id_c * const receive_network_id,
	const eap_type_value_e proposed_eap_type,
	const u8_t eap_identifier)
		: eap_am_network_id_c(tools, receive_network_id)
		, m_proposed_eap_type(proposed_eap_type)
		, m_eap_identifier(eap_identifier)
{
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_type_value_e eap_core_nak_info_c::get_proposed_eap_type() const
{
	return m_proposed_eap_type;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT u8_t eap_core_nak_info_c::get_eap_identifier() const
{
	return m_eap_identifier;
}


//--------------------------------------------------
//--------------------------------------------------



// End.
