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

#if !defined(_GSMSIM_STATE_H_)
#define _GSMSIM_STATE_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_GSMSIM_STATE_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_STATE_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_STATE_H 
#elif defined(EAP_EXPORT_EAP_TYPE_GSMSIM_STATE_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_STATE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_STATE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_STATE_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_STATE_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_base_type.h"
#include "eap_variable_data.h"
#include "eap_type_gsmsim_header.h"
#include "eap_type_gsmsim_types.h"
#include "eap_type_gsmsim_payloads.h"
#include "abs_eap_type_gsmsim_state.h"
#include "abs_eap_base_timer.h"
#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	#include "eap_sim_triplets.h"
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
#include "eap_type_gsmsim_state_notification.h"
#include "eap_am_network_id.h"


const u32_t GSMSIM_STATE_MAX_TYPES = 4;


//-----------------------------------------------

/// This class stores the valid GSMSIM messages (gsmsim_subtype_e)
/// within a one state (eap_type_gsmsim_state_variable_e).
class EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H eap_type_gsmsim_state_variable_parameters_c
{
private:

	/// Array includes valid GSMSIM messages (gsmsim_subtype_e).
	gsmsim_subtype_e m_valid_types[GSMSIM_STATE_MAX_TYPES];

	/// The handler of this state must be initiator (server, authenticator).
	bool m_must_be_initiator;

	/// The handler of this state must be responsed (client, peer).
	bool m_must_be_responder;

public:

	/**
	 * Destructor does nothing.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H virtual ~eap_type_gsmsim_state_variable_parameters_c();

	/**
	 * Constructor initializes attributes with default values.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H eap_type_gsmsim_state_variable_parameters_c();

	/**
	 * This function checks the GSMSIM message is valid in this state.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H bool check_valid_types(gsmsim_subtype_e type) const;

	/**
	 * This function checks the initiator is valid in this state.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H bool check_initiator(const bool is_initiator) const;

	/**
	 * This function initializes this state to allow three GSMSIM message types.
	 */
	EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_STATE_H void init_state(
		const bool must_be_initiator,
		const bool must_be_responder,
		const gsmsim_subtype_e type0,
		const gsmsim_subtype_e type1,
		const gsmsim_subtype_e type2,
		const gsmsim_subtype_e type3
		);
};


#endif //#if !defined(_GSMSIM_STATE_H_)

//--------------------------------------------------



// End.
