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

#if !defined(_EAP_AM_TYPE_SIM_SYMBIAN_H_)
#define _EAP_AM_TYPE_SIM_SYMBIAN_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TYPE_SIM_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_SIM_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_SIM_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_TYPE_SIM_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_SIM_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_SIM_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_SIM_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_SIM_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_base_type.h"
#include "eap_am_type_sim.h"

// 
class EAP_CLASS_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H eap_am_type_sim_simulator_c
: public eap_am_type_sim_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H virtual ~eap_am_type_sim_simulator_c();

	// 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H eap_am_type_sim_simulator_c(
		abs_eap_am_tools_c * const m_am_tools, abs_eap_am_type_sim_c * const partner);

	// 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H eap_status_e query_SIM_imsi(
		u8_t * const imsi, const u32_t max_length, u32_t * const imsi_length);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H eap_status_e query_SIM_kc_and_sres(
		const u8_t * const imsi, const u32_t imsi_length,
		const u8_t * const rand, const u32_t rand_length,
		u8_t * const kc, u32_t * const kc_length,
		u8_t * const sres, u32_t * const sres_length);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H eap_status_e query_SIM_triplets(
		//const eap_state_selector_c * const state_selector,
		const eap_variable_data_c * const imsi,
		eap_type_sim_triplet_array_c * const triplets);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H eap_status_e query_SIM_kc_sres(
		//const eap_state_selector_c * const state_selector,
		const eap_variable_data_c * const n_rands,
		eap_variable_data_c * const n_kc,
		eap_variable_data_c * const n_sres);

	//--------------------------------------------------
}; // class eap_am_type_sim_simulator_c


/** @file */ 

/**
 * This function creates a new instance of adaptation module of simple SIM EAP-type.
 * @param tools is pointer to the abs_eap_am_tools class created by the adaptation module.
 * @param partner is pointer to the caller of the new_eap_am_type_sim().
 * Simple SIM EAP-type will callback caller using the partner pointer.
 */
EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_SIM_SYMBIAN_H  eap_am_type_sim_c *new_eap_am_type_sim(
	abs_eap_am_tools_c * const tools,
	abs_eap_am_type_sim_c * const partner);


#endif //#if !defined(_EAP_AM_TYPE_SIM_SYMBIAN_H_)

//--------------------------------------------------



// End.
