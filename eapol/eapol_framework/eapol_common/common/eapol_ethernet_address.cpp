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
	#define EAP_FILE_NUMBER_ENUM 31 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eapol_ethernet_address.h"

eap_eth_address_c::eap_eth_address_c()
{
}

eap_eth_address_c::~eap_eth_address_c()
{
}

u8_t * eap_eth_address_c::get_address() const
{
	return const_cast<u8_t *>(m_address);
}

u32_t eap_eth_address_c::get_address_length() const
{
	return sizeof(m_address);
}

void eap_eth_address_c::set_address(abs_eap_am_tools_c * const m_am_tools, u8_t * const p_address, const u32_t length)
{
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	EAP_ASSERT_ALWAYS(length == EAPOL_ETHERNET_ADDRESS_LENGTH);

	for (u32_t ind = 0u; ind < length; ind++)
	{
		m_address[ind] = p_address[ind];
	}
}

void eap_eth_address_c::reset_address()
{
	for (u32_t ind = 0u; ind < EAPOL_ETHERNET_ADDRESS_LENGTH; ind++)
	{
		m_address[ind] = 0;
	}
}

//--------------------------------------------------



// End.
