/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/ec_cs_compare_reference_id.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 2 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_EC_CS_COMPARE_REFERENCE_H_)
#define _EC_CS_COMPARE_REFERENCE_H_

#if defined(USE_WAPI_CORE)

#include "eap_tools.h"
#include "eap_general_header_base.h"
#include "ec_cs_types.h"
#include "eap_array_algorithms.h"

/** @file */

//----------------------------------------------------------------------------------

class EAP_EXPORT ec_cs_compare_reference_c
: public abs_eap_array_compare_c<ec_cs_data_c>
{
public:

	EAP_FUNC_IMPORT virtual ~ec_cs_compare_reference_c();

	EAP_FUNC_IMPORT ec_cs_compare_reference_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_IMPORT i32_t compare(
		const ec_cs_data_c * const reference_from_array,
		const ec_cs_data_c * const certificate_identity) const;

private:

	abs_eap_am_tools_c * const m_am_tools;

};

//----------------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_EC_CS_COMPARE_REFERENCE_H_)



// End.
