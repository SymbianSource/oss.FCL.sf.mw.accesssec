/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/ec_cs_data.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 5 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_EC_CS_DATA_H_)
#define _EC_CS_DATA_H_

#if defined(USE_WAPI_CORE)

#include "eap_am_export.h"
#include "eap_tools.h"
#include "ec_cs_types.h"

/** @file */

//----------------------------------------------------------------------------


//----------------------------------------------------------------------------

class abs_eap_am_tools_c;


class EAP_EXPORT ec_cs_data_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	ec_cs_data_change_status_e m_change_status;

	ec_cs_data_type_e m_type;

	eap_variable_data_c m_reference;

	eap_variable_data_c m_data;

	bool m_data_references_read;

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the ec_cs_data_c class does nothing.
	 */
	EAP_FUNC_IMPORT virtual ~ec_cs_data_c();

	/**
	 * The constructor of the ec_cs_data_c class simply initializes the attributes.
	 */
	EAP_FUNC_IMPORT ec_cs_data_c(
		abs_eap_am_tools_c * const tools);


	EAP_FUNC_IMPORT bool get_is_valid() const;

	EAP_FUNC_IMPORT bool get_is_valid_data() const;


	EAP_FUNC_IMPORT ec_cs_data_change_status_e get_change_status() const;

	EAP_FUNC_IMPORT void set_change_status(const ec_cs_data_change_status_e change_status);

	
	EAP_FUNC_IMPORT ec_cs_data_type_e get_type() const;

	EAP_FUNC_IMPORT void set_type(const ec_cs_data_type_e type);


	EAP_FUNC_IMPORT const eap_variable_data_c * get_reference() const;

	EAP_FUNC_IMPORT const eap_variable_data_c * get_data() const;

	EAP_FUNC_IMPORT eap_variable_data_c * get_writable_reference();

	EAP_FUNC_IMPORT eap_variable_data_c * get_writable_data();

	EAP_FUNC_IMPORT ec_cs_data_c * copy() const;

	EAP_FUNC_IMPORT i32_t compare(const ec_cs_data_c * const data) const;

	EAP_FUNC_IMPORT eap_status_e reset();

	EAP_FUNC_IMPORT eap_status_e set_copy_of_buffer(const ec_cs_data_c * const source);


	EAP_FUNC_IMPORT bool get_data_references_read();

	EAP_FUNC_IMPORT void set_data_references_read();

	//--------------------------------------------------
}; // ec_cs_data_c

//----------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_EC_CS_DATA_H_)


// End.
