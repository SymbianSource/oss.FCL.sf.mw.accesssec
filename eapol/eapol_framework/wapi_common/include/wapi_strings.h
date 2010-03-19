/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wapi_strings.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 10 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_WAPI_STRINGS_H_)
#define _WAPI_STRINGS_H_

#if defined(USE_WAPI_CORE)

#include "eap_tools.h"
#include "eap_general_header_base.h"
#include "wapi_types.h"

/** @file */

//----------------------------------------------------------------------------------

/// This class includes the debug strings of the Elliptic curve certificate store.
class EAP_EXPORT wapi_strings_c
{
public:

	EAP_FUNC_IMPORT virtual ~wapi_strings_c();

	EAP_FUNC_IMPORT wapi_strings_c();

	EAP_FUNC_IMPORT static eap_const_string get_wapi_completion_operation_string(const wapi_completion_operation_e type);

	EAP_FUNC_IMPORT static eap_const_string get_wai_protocol_version_string(const wai_protocol_version_e type);

	EAP_FUNC_IMPORT static eap_const_string get_wai_protocol_type_string(const wai_protocol_type_e type);

	EAP_FUNC_IMPORT static eap_const_string get_wai_protocol_subtype_string(const wai_protocol_subtype_e type);

	EAP_FUNC_IMPORT static eap_const_string get_wai_tlv_header_string(const wai_tlv_type_e type);

	EAP_FUNC_IMPORT static eap_const_string get_wai_payload_type_string(const wai_payload_type_e type);

	EAP_FUNC_IMPORT static eap_const_string get_wapi_core_state_string(const wapi_core_state_e state);

	EAP_FUNC_IMPORT static eap_const_string get_wapi_negotiation_state_string(const wapi_negotiation_state_e state);


};

//----------------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_WAPI_STRINGS_H_)



// End.
