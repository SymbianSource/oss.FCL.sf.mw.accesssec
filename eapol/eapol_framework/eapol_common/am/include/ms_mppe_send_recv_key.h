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

#if !defined(_MS_MPPE_SEND_RECV_KEY_H_)
#define _MS_MPPE_SEND_RECV_KEY_H_

//----------------------------------------------------------------------------

//
// Bytes needed:
//      4: Vendor-Id
//      1: Vendor-Type
//      1: Vendor-Length
//      2: Salt
//      1: Key-Length
//     32: Key
//     15: Padding
//     -----------------
//     56: Total
//
// Copy MS-MPPE-Send-Key
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Vendor-ID                                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Vendor-Type   | Vendor-Length |           Salt              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Key Length    |         Key total 32 bytes                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Key (cont)                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Key (cont)                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Key (cont)                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Key (cont)                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Key (cont)                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Key (cont)                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Key (cont)                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               |       Padding total 15 bytes                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Padding                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Padding                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Padding                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

const u32_t MS_MPPE_KEY_LENGTH     = 32u;
const u32_t MS_MPPE_PADDING_LENGTH = 15u;

const u8_t MS_MPPE_Send_Key = 16u;
const u8_t MS_MPPE_Recv_Key = 17u;

#pragma pack(1)

// 
class ms_mppe_send_recv_key_c
{
private:
	//--------------------------------------------------


	u32_t m_vendor_id;
	u8_t m_vendor_type;
	u8_t m_vendor_length;
	u16_t m_salt;
	u8_t m_key_length;
	u8_t m_key[MS_MPPE_KEY_LENGTH];
	u8_t m_padding[MS_MPPE_PADDING_LENGTH];

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	~ms_mppe_send_recv_key_c()
	{
	}

	// 
	ms_mppe_send_recv_key_c(abs_eap_am_tools_c * const m_am_tools)
	{
		reset_header(m_am_tools);
	}

	void reset_header(abs_eap_am_tools_c * const m_am_tools)
	{
		m_vendor_id = eap_htonl(311); // microsoft
		m_vendor_type = 0u;
		m_vendor_length = sizeof(*this) - sizeof(m_vendor_id);
		m_salt = 0u;
		m_key_length = 0u;
		m_am_tools->memset(m_key, 0, sizeof(m_key));
		m_am_tools->memset(m_padding, 0, sizeof(m_padding));
	}

	eap_status_e set_key(
		abs_eap_am_tools_c * const m_am_tools,
		const u8_t * const key,
		const u32_t key_length,
		const u8_t key_type)
	{
		if (key_length >= sizeof(m_key))
		{
			m_vendor_type = key_type; // MS-MPPE-Send-Key or MS-MPPE-Recv-Key
			m_key_length = sizeof(m_key);
			m_am_tools->memmove(m_key, key, sizeof(m_key));
			return eap_status_ok;
		}
		else
		{
			return eap_status_key_error;
		}
	}

	// 
	//--------------------------------------------------
}; // class ms_mppe_send_recv_key_c

#pragma pack()

#endif //#if !defined(_MS_MPPE_SEND_RECV_KEY_H_)

//--------------------------------------------------



// End.
