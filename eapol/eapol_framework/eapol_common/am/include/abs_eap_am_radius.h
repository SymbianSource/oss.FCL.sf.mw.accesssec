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

#if !defined(_ABS_EAP_AM_TYPE_RADIUS_H_)
#define _ABS_EAP_AM_TYPE_RADIUS_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_RADIUS_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_RADIUS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_RADIUS_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_RADIUS_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_RADIUS_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_RADIUS_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_RADIUS_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_RADIUS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_RADIUS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_RADIUS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_RADIUS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_RADIUS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_RADIUS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_RADIUS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_RADIUS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_RADIUS_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_RADIUS_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_sim_triplets.h"
#include "eap_radius_types.h"

/// This class declares the functions adaptation module of RADIUS EAP type
/// requires from the RADIUS EAP type.
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_RADIUS_H abs_eap_am_radius_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~abs_eap_am_radius_c()
	{
	}

	// 
	abs_eap_am_radius_c()
	{
	}

	virtual bool get_is_client() = 0;

	/** Client adaptation module of RADIUS EAP type calls this function.
	 *  AM gives IMSI and optional pseydonym to RADIUS EAP type.
	 *  This function completes asyncronously query_SIM_IMSI_or_pseudonym_or_reauthentication_id() function call.
	 */
	virtual eap_status_e complete_SIM_IMSI_or_pseudonym_or_reauthentication_id_query(
		const eap_variable_data_c * const IMSI,
		const eap_variable_data_c * const pseudonym,
		const eap_variable_data_c * const reauthentication_identity,
		const eap_variable_data_c * const automatic_realm, ///< This could be zero pointer if this is not used.
		const eap_radius_complete_e required_completion,
		const u8_t received_eap_identifier,
		const eap_status_e completion_status) = 0;


#if defined(USE_EAP_TYPE_SERVER_RADIUS)
	/** Server adaptation module of RADIUS EAP type calls this function.
	 *  AM give triplets to RADIUS EAP type.
	 *  This function completes asyncronously query_SIM_triplets() function call.
	 */
	virtual eap_status_e complete_SIM_triplets(
		eap_type_sim_triplet_array_c * const triplets,
		const eap_variable_data_c * const IMSI,
		const eap_radius_triplet_status_e triplet_status,
		const eap_radius_identity_type type,
		const eap_status_e completion_status) = 0;
#endif //#if defined(USE_EAP_TYPE_SERVER_RADIUS)


	/** Client adaptation module of RADIUS EAP type calls this function.
	 *  AM gives n RANDs, n Kcs and n SRESs to RADIUS EAP type.
	 *  This function completes asyncronously query_SIM_kc_sres() function call.
	 */
	virtual eap_status_e complete_SIM_kc_sres(
		const eap_variable_data_c * const n_rand,
		const eap_variable_data_c * const n_kc,
		const eap_variable_data_c * const n_sres,
		const eap_status_e completion_status) = 0;


#if defined(USE_EAP_TYPE_SERVER_RADIUS)
	/** Server adaptation module of RADIUS EAP type calls this function.
	 *  AM gives IMSI and username to RADIUS EAP type.
	 *  This function completes asyncronously query_imsi_from_username() function call.
	 */
	virtual eap_status_e complete_imsi_from_username(
		const u8_t next_eap_identifier,
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const username,
		const eap_variable_data_c * const imsi,
		const eap_radius_identity_type type,
		const eap_status_e completion_status,
		const eap_radius_complete_e completion_action) = 0;
#endif //#if defined(USE_EAP_TYPE_SERVER_RADIUS)


	//--------------------------------------------------
}; // class abs_eap_am_radius_c

#endif //#if !defined(_ABS_EAP_AM_TYPE_RADIUS_H_)

//--------------------------------------------------



// End.
