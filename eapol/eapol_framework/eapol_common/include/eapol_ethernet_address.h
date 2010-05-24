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

#if !defined(_EAPOL_ETHERNET_ADDRESS_H_)
#define _EAPOL_ETHERNET_ADDRESS_H_

#include "eap_tools.h"
#include "eapol_header.h"
#include "eap_general_header_base.h"

const u32_t EAPOL_ETHERNET_ADDRESS_LENGTH = 6u;


class eap_eth_address_c
{
private:
	u8_t m_address[EAPOL_ETHERNET_ADDRESS_LENGTH];
public:

	eap_eth_address_c()
	{
	}

	virtual ~eap_eth_address_c()
	{
	}

	u8_t * get_address() const
	{
		return const_cast<u8_t *>(m_address);
	}

	u32_t get_address_length() const
	{
		return sizeof(m_address);
	}

	void set_address(abs_eap_am_tools_c * const m_am_tools, u8_t * const p_address, const u32_t length)
	{
		EAP_UNREFERENCED_PARAMETER(m_am_tools);

		EAP_ASSERT_TOOLS(m_am_tools, length == EAPOL_ETHERNET_ADDRESS_LENGTH);

		for (u32_t ind = 0u; ind < length; ind++)
		{
			m_address[ind] = p_address[ind];
		}
	}

	void reset_address()
	{
		for (u32_t ind = 0u; ind < EAPOL_ETHERNET_ADDRESS_LENGTH; ind++)
		{
			m_address[ind] = 0;
		}
	}
};


#endif //#if !defined(_EAPOL_ETHERNET_ADDRESS_H_)

//--------------------------------------------------



// End.
