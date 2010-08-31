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
	#define EAP_FILE_NUMBER_ENUM 35 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "eap_am_memory.h"
#include "eap_rogue_ap_entry.h"

EAP_FUNC_EXPORT eap_rogue_ap_entry_c::~eap_rogue_ap_entry_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_rogue_ap_entry_c::eap_rogue_ap_entry_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_rogue_ap_reason(rogue_ap_none)
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_rogue_ap_entry_c * eap_rogue_ap_entry_c::copy() const
{
	eap_rogue_ap_entry_c * const new_object = new eap_rogue_ap_entry_c(m_am_tools);

	if (new_object != 0)
	{
		new_object->set_mac_address(get_mac_address());
		new_object->set_rogue_reason(get_rogue_reason());
	}

	return new_object;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_rogue_ap_entry_c::get_mac_address() const
{
	return const_cast<u8_t *>(m_rogue_ap_mac_address);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t * eap_rogue_ap_entry_c::get_mac_address(u8_t * const mac_address) const
{
	if (mac_address)
	{
		m_am_tools->memmove(mac_address, m_rogue_ap_mac_address, EAPOL_ETHERNET_ADDRESS_LENGTH);
	}
	return const_cast<u8_t *>(m_rogue_ap_mac_address);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_rogue_ap_entry_c::set_mac_address(const u8_t * const mac_address)
{
	if (mac_address)
	{
		m_am_tools->memmove(m_rogue_ap_mac_address, mac_address, EAPOL_ETHERNET_ADDRESS_LENGTH);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_rogue_ap_entry_c::set_rogue_reason(const eap_rogue_ap_reason_e reason)
{
	m_rogue_ap_reason = reason;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_rogue_ap_reason_e eap_rogue_ap_entry_c::get_rogue_reason() const
{
	return m_rogue_ap_reason;
}


// End of File
