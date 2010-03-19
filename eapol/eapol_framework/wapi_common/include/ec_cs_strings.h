/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/ec_cs_strings.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 7 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_EC_CS_STRINGS_H_)
#define _EC_CS_STRINGS_H_

#if defined(USE_WAPI_CORE)

#include "eap_tools.h"
#include "eap_general_header_base.h"
#include "ec_cs_types.h"

/** @file */

//----------------------------------------------------------------------------------

/// This class includes the debug strings of the Elliptic curve certificate store.
class EAP_EXPORT ec_cs_strings_c
{
public:

	EAP_FUNC_IMPORT virtual ~ec_cs_strings_c();

	EAP_FUNC_IMPORT ec_cs_strings_c();

	EAP_FUNC_IMPORT static eap_const_string get_ec_cs_store_data_string(const ec_cs_data_type_e type);

	EAP_FUNC_IMPORT static eap_const_string get_ec_cs_store_data_change_status_string(const ec_cs_data_change_status_e status);

	EAP_FUNC_IMPORT static eap_const_string get_ec_cs_store_data_string(const ec_cs_pending_operation_e type);

	/**
	 * Function returns string of ec_cs_tlv_type_e.
	 * @param status is the queried string.
	 */
	EAP_FUNC_IMPORT static eap_const_string get_ec_cs_tlv_header_string(const ec_cs_tlv_type_e type);

};

//----------------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_EC_CS_STRINGS_H_)



// End.
