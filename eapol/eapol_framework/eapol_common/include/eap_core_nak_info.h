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

#if !defined(_EAP_CORE_NAK_INFO_H_)
#define _EAP_CORE_NAK_INFO_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_CORE_NAK_INFO_H)
	#define EAP_CLASS_VISIBILITY_EAP_CORE_NAK_INFO_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_NAK_INFO_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_NAK_INFO_H 
	#define EAP_FUNC_EXPORT_EAP_CORE_NAK_INFO_H 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_NAK_INFO_H 
#elif defined(EAP_EXPORT_EAP_CORE_NAK_INFO_H)
	#define EAP_CLASS_VISIBILITY_EAP_CORE_NAK_INFO_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_NAK_INFO_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_NAK_INFO_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_CORE_NAK_INFO_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_NAK_INFO_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_CORE_NAK_INFO_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_NAK_INFO_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_NAK_INFO_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_CORE_NAK_INFO_H 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_NAK_INFO_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_core.h"
#include "eap_base_type.h"
#include "abs_eap_base_type.h"
#include "eap_variable_data.h"
#include "eap_core_map.h"
#include "eap_config.h"
#include "eap_am_network_id.h"
#include "abs_eap_am_mutex.h"
#include "eap_core_retransmission.h"
#include "abs_eap_stack_interface.h"


//--------------------------------------------------

/**
 * This class stores the information of received EAP-Nak.
 */
class eap_core_nak_info_c
: public eap_am_network_id_c
{

private:

	eap_type_value_e m_proposed_eap_type;

	u8_t m_eap_identifier;

public:

	/**
	 * The destructor of the eap_core_nak_info_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_NAK_INFO_H virtual ~eap_core_nak_info_c();

	/**
	 * The constructor initializes member attributes using parameters passed to it.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param send_network_id is the network identity.
	 * @param proposed_eap_type is the proposed EAP type.
	 */
	EAP_FUNC_VISIBILITY_EAP_CORE_NAK_INFO_H eap_core_nak_info_c(
		abs_eap_am_tools_c * const tools,
		const eap_am_network_id_c * const send_network_id,
		const eap_type_value_e proposed_eap_type,
		const u8_t eap_identifier);

	EAP_FUNC_VISIBILITY_EAP_CORE_NAK_INFO_H eap_type_value_e get_proposed_eap_type() const;

	EAP_FUNC_VISIBILITY_EAP_CORE_NAK_INFO_H u8_t get_eap_identifier() const;
};


#endif //#if !defined(_EAP_CORE_NAK_INFO_H_)

//--------------------------------------------------



// End.
