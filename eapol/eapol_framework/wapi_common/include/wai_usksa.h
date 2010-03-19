/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wai_usksa.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 6 % << Don't touch! Updated by Synergy at check-out.
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
* Template version: 4.2
*/


#if !defined(_WAI_USKSA_H_)
#define _WAI_USKSA_H_

#include "eap_am_export.h"
#include "abs_eap_am_tools.h"
#include "wapi_types.h"


class wai_usksa_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	eap_variable_data_c m_USK;

	u8_t m_USKID;

	wai_unicast_cipher_suite_e m_unicast_cipher_suite;

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~wai_usksa_c();

	wai_usksa_c(abs_eap_am_tools_c * const tools);

	bool get_is_valid() const;

	bool get_is_valid_data() const;


	u8_t get_USKID() const;

	eap_variable_data_c * get_USK();

	wai_unicast_cipher_suite_e get_cipher_suite() const;

	
	void set_USKID(const u8_t USKID);

	void set_cipher_suite(const wai_unicast_cipher_suite_e cipher);

	//--------------------------------------------------
};

#endif //#if !defined(_WAI_USKSA_H_)

// End of file.
