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

#if !defined(_SAE_COOKIE_H_)
#define _SAE_COOKIE_H_


#include "eap_am_memory.h"


const u32_t SAE_COOKIE_LENGTH = 8u;


class sae_cookie_c
{
private:
	u8_t m_bytes[SAE_COOKIE_LENGTH];
public:

	sae_cookie_c()
	{
	}

	~sae_cookie_c()
	{
	}

	const u8_t * get_data() const
	{
		return reinterpret_cast<const u8_t *>(m_bytes);
	}

	u32_t get_data_length() const
	{
		return sizeof(m_bytes);
	}

	void set_bytes(abs_eap_am_tools_c * const m_am_tools, const u8_t * const p_bytes, const u32_t length)
	{
		EAP_UNREFERENCED_PARAMETER(m_am_tools);

		EAP_ASSERT_ALWAYS(length == SAE_COOKIE_LENGTH);

		for (u32_t ind = 0u; ind < length; ind++)
		{
			m_bytes[ind] = p_bytes[ind];
		}
	}

	void set_cookie(abs_eap_am_tools_c * const m_am_tools, const sae_cookie_c * const cookie)
	{
		set_bytes(m_am_tools, cookie->get_data(), cookie->get_data_length());
	}

	void reset_cookie()
	{
		for (u32_t ind = 0u; ind < SAE_COOKIE_LENGTH; ind++)
		{
			m_bytes[ind] = 0;
		}
	}

	sae_cookie_c * const copy(abs_eap_am_tools_c * const m_am_tools) const
	{
		sae_cookie_c * const new_cookie = new sae_cookie_c();
		if (new_cookie == 0)
		{
			return 0;
		}
		new_cookie->set_bytes(m_am_tools, get_data(), get_data_length());
		return new_cookie;
	}
};



//--------------------------------------------------

#endif //#if !defined(_SAE_COOKIE_H_)



// End.
