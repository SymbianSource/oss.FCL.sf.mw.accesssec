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

#if !defined(_MS_MPPE_KEYS_H_)
#define _MS_MPPE_KEYS_H_


//----------------------------------------------------------------------------

// Here is copy from draft-ietf-radius-mschap-attr-01.txt:
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Vendor-ID                                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Vendor-Type   | Vendor-Length |           Keys              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Keys (cont) total 24 bytes            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Keys (cont)                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Keys (cont)                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Keys (cont)                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Keys (cont)                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Keys (cont)              |      Padding                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Padding                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Padding                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

const u32_t MPPE_LM_KEY_LENGTH  =  8u;
const u32_t MPPE_NT_KEY_LENGTH  = 16u;
const u32_t MPPE_PADDING_LENGTH =  8u;

#pragma pack(1)

// 
class mppe_keys_c
{
private:
	//--------------------------------------------------

	u32_t m_vendor_id;
	u8_t m_vendor_type;
	u8_t m_vendor_length;
	u8_t m_LM_Key[MPPE_LM_KEY_LENGTH];
	u8_t m_NT_Key[MPPE_NT_KEY_LENGTH];
	u8_t m_padding[MPPE_PADDING_LENGTH];

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	~mppe_keys_c()
	{
	}

	// 
	mppe_keys_c(abs_eap_am_tools_c * const m_am_tools)
	{
		reset_header(m_am_tools);
	}

	void reset_header(abs_eap_am_tools_c * const m_am_tools)
	{
		m_vendor_id = eap_htonl(311); // microsoft
		m_vendor_type = 12u; // MS-CHAP-MPPE-Keys
		m_vendor_length = 34u;
		m_am_tools->memset(m_LM_Key, 0, sizeof(m_LM_Key));
		m_am_tools->memset(m_NT_Key, 0, sizeof(m_NT_Key));
		m_am_tools->memset(m_padding, 0, sizeof(m_padding));
	}

	eap_status_e set_LM_Key(
		abs_eap_am_tools_c * const m_am_tools,
		const u8_t * const key,
		const u32_t key_length)
	{
		if (key_length >= sizeof(m_LM_Key))
		{
			m_am_tools->memmove(m_LM_Key, key, sizeof(m_LM_Key));
			return eap_status_ok;
		}
		else
		{
			return eap_status_key_error;
		}
	}

	eap_status_e set_NT_Key(
		abs_eap_am_tools_c * const m_am_tools,
		const u8_t * const key,
		const u32_t key_length)
	{
		if (key_length >= sizeof(m_NT_Key))
		{
			m_am_tools->memmove(m_NT_Key, key, sizeof(m_NT_Key));
			return eap_status_ok;
		}
		else
		{
			return eap_status_key_error;
		}
	}

	// 
	//--------------------------------------------------
}; // class mppe_keys_c

#pragma pack()

#endif //#if !defined(_MS_MPPE_KEYS_H_)

//--------------------------------------------------



// End.
