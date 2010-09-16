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

#if !defined(_ABS_EAP_AM_TYPE_AKA_H_)
#define _ABS_EAP_AM_TYPE_AKA_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_TYPE_AKA_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_TYPE_AKA_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_AKA_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_AKA_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_TYPE_AKA_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_TYPE_AKA_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_TYPE_AKA_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_TYPE_AKA_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_AKA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_AKA_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_TYPE_AKA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_TYPE_AKA_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_TYPE_AKA_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_AKA_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_TYPE_AKA_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_TYPE_AKA_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_TYPE_AKA_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_type_aka_authentication_vector.h"
#include "eap_type_aka_types.h"

/// This class declares the functions adaptation module of AKA EAP type
/// requires from the AKA EAP type.
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_TYPE_AKA_H abs_eap_am_type_aka_c
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
	virtual ~abs_eap_am_type_aka_c()
	{
	}

	// 
	abs_eap_am_type_aka_c()
	{
	}

	virtual bool get_is_client() = 0;

	/** Client adaptation module of AKA EAP type calls this function.
	 *  AM gives IMSI and optional pseydonym to AKA EAP type.
	 *  This function completes asyncronously query_AKA_IMSI_or_pseudonym_or_reauthentication_id() function call.
	 */
	virtual eap_status_e complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query(
		const eap_variable_data_c * const IMSI,
		const eap_variable_data_c * const pseudonym,
		const eap_variable_data_c * const reauthentication_identity,
		const eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
		const u32_t length_of_mnc,
		const eap_type_aka_complete_e required_completion,
		const u8_t received_eap_identifier,
		const eap_status_e completion_status) = 0;

	/** Server adaptation module of AKA EAP type calls this function.
	 *  AM give triplets to AKA EAP type.
	 *  This function completes asyncronously query_AKA_authentication_vector() function call.
	 */
	virtual eap_status_e complete_AKA_authentication_vector_query(
		eap_type_aka_authentication_vector_c * const authentication_vector,
		const eap_variable_data_c * const IMSI,
		const eap_aka_authentication_vector_status_e authentication_vector_status,
		const eap_type_aka_identity_type type,
		const eap_status_e completion_status,
		const u8_t next_eap_identifier) = 0;

	/** Client adaptation module of AKA EAP type calls this function.
	 *  AM gives n RANDs, n Kcs and n SRESs to AKA EAP type.
	 *  This function completes asyncronously query_AKA_RES() function call.
	 */
	virtual eap_status_e complete_AKA_RES_query(
		const eap_type_aka_authentication_vector_c * const authentication_vector,
		const eap_status_e completion_status) = 0;

	/** Server adaptation module of AKA EAP type calls this function.
	 *  AM gives IMSI and username to AKA EAP type.
	 *  This function completes asyncronously query_imsi_from_username() function call.
	 */
	virtual eap_status_e complete_imsi_from_username(
		const u8_t next_eap_identifier,
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const username,
		const eap_variable_data_c * const imsi,
		const eap_type_aka_identity_type type,
		const eap_status_e completion_status,
		const eap_type_aka_complete_e completion_action) = 0;

	/** Server adaptation module of AKA EAP type calls this function.
	 *  AM gives new authentication vector to AKA EAP type.
	 *  This function completes asyncronously query_re_syncronization() function call.
	 */
	virtual eap_status_e complete_re_syncronization_query(
		const u8_t next_eap_identifier,
		const eap_type_aka_authentication_vector_c * const authentication_vector) = 0;

	//--------------------------------------------------
}; // class abs_eap_am_type_aka_c

#endif //#if !defined(_ABS_EAP_AM_TYPE_AKA_H_)

//--------------------------------------------------



// End.
