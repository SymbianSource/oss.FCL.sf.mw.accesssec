/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wai_usksa.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 4 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.1.1
*/

#include "wai_usksa.h"

//--------------------------------------------------

wai_usksa_c::~wai_usksa_c()
{
}

//--------------------------------------------------

wai_usksa_c::wai_usksa_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_USK(tools)
	, m_USKID(0ul)
	, m_unicast_cipher_suite(wai_unicast_cipher_suite_none)
{
}

//--------------------------------------------------

bool wai_usksa_c::get_is_valid() const
{
	return m_USK.get_is_valid();
}

//--------------------------------------------------

bool wai_usksa_c::get_is_valid_data() const
{
	return m_USK.get_is_valid_data();
}

//--------------------------------------------------

u8_t wai_usksa_c::get_USKID() const
{
	return m_USKID;
}

//--------------------------------------------------

eap_variable_data_c * wai_usksa_c::get_USK()
{
	return &m_USK;
}

//--------------------------------------------------

wai_unicast_cipher_suite_e wai_usksa_c::get_cipher_suite() const
{
	return m_unicast_cipher_suite;
}

//--------------------------------------------------

void wai_usksa_c::set_USKID(const u8_t USKID)
{
	m_USKID = USKID;
}

//--------------------------------------------------

void wai_usksa_c::set_cipher_suite(const wai_unicast_cipher_suite_e cipher)
{
	m_unicast_cipher_suite = cipher;
}

//--------------------------------------------------
// End of file.
