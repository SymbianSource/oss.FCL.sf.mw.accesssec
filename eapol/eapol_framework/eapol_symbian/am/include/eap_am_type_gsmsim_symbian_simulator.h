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

#if !defined(_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H_)
#define _EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H 
#elif defined(EAP_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_base_type.h"
#include "eap_am_type_gsmsim.h"
#include "EapPluginInterface.h"

// 
class EAP_CLASS_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_am_type_gsmsim_simulator_c
: public eap_am_type_gsmsim_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	abs_eap_base_type_c * const m_partner;

	eap_variable_data_c saved_pseudonym;

	bool m_is_valid;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H virtual ~eap_am_type_gsmsim_simulator_c();

	// 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_am_type_gsmsim_simulator_c(
		abs_eap_am_tools_c * const m_am_tools,
		abs_eap_base_type_c * const partner,
		const CEapPluginInterface::TIndexType aIndexType,
		const TInt aIndex);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e configure();

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e shutdown();

	// 
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e query_SIM_imsi(
		u8_t * const imsi, const u32_t max_length, u32_t * const imsi_length);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e store_pseudonym_id(
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const pseudonym);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e store_reauthentication_id(
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const reauthentication_identity);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e query_SIM_IMSI_or_pseudonym_or_reauthentication_id(
		const bool must_be_synchronous,
		eap_variable_data_c * const IMSI,
		eap_variable_data_c * const pseudonym_identity,
		eap_variable_data_c * const reauthentication_identity,
		eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
		u32_t * const length_of_mnc,
		const gsmsim_payload_AT_type_e required_identity,
		const eap_type_gsmsim_complete_e required_completion,
		const u8_t received_eap_identifier);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e cancel_SIM_IMSI_or_pseudonym_or_reauthentication_id_query();

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e query_SIM_kc_and_sres(
		const u8_t * const imsi, const u32_t imsi_length,
		const u8_t * const rand, const u32_t rand_length,
		u8_t * const kc, u32_t * const kc_length,
		u8_t * const sres, u32_t * const sres_length);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e handle_gsmsim_notification(eap_gsmsim_notification_codes_e gsmsim_notification_code);


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e query_SIM_triplets(
		const bool must_be_synchronous,
		const eap_variable_data_c * const username,
		eap_variable_data_c * const imsi,
		eap_type_sim_triplet_array_c * const triplets,
		eap_type_gsmsim_identity_type * const type);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e cancel_SIM_triplets_query();
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e query_SIM_kc_sres(
		const bool must_be_synchronous,
		//const eap_variable_data_c * const imsi,
		const eap_variable_data_c * const n_rands,
		eap_variable_data_c * const n_kc,
		eap_variable_data_c * const n_sres);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e cancel_SIM_kc_sres_query();

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e generate_encryption_IV(
		eap_variable_data_c * const encryption_IV,
		const u32_t IV_length);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e generate_pseudonym_id(
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const imsi,
		eap_variable_data_c * const pseudonym,
		const u32_t maximum_pseudonym_length);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e generate_reauthentication_id(
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const imsi,
		eap_variable_data_c * const reauthentication_identity,
		const u32_t maximum_reauthentication_identity_length);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e store_reauth_parameters(
		const eap_variable_data_c * const XKEY,
		const eap_variable_data_c * const K_aut,
		const eap_variable_data_c * const K_encr,
		const u32_t reauth_counter);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e authentication_finished(
		const bool true_when_successfull,
		const eap_gsmsim_authentication_type_e authentication_type,
		const eap_type_gsmsim_identity_type identity_type);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e query_reauth_parameters(
		eap_variable_data_c * const XKEY,
		eap_variable_data_c * const K_aut,
		eap_variable_data_c * const K_encr,
		u32_t * const reauth_counter);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e increase_reauth_counter();


#if defined(USE_EAP_TYPE_SERVER_GSMSIM)
	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e query_imsi_from_username(
		const bool must_be_synchronous,
		const u8_t next_eap_identifier,
		const eap_am_network_id_c * const network_id,
		const eap_variable_data_c * const username,
		eap_variable_data_c * const imsi,
		eap_type_gsmsim_identity_type * const type,
		const eap_type_gsmsim_complete_e completion_action);
#endif //#if defined(USE_EAP_TYPE_SERVER_GSMSIM)


	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e cancel_imsi_from_username_query();

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e check_is_rand_unused(const eap_variable_data_c * const n_rands);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e set_rand_is_used(const eap_variable_data_c * const n_rands);

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H void set_is_valid();

	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H bool get_is_valid();

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e type_configure_read(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	//
	EAP_FUNC_VISIBILITY_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H eap_status_e type_configure_write(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data);

	//--------------------------------------------------
}; // class eap_am_type_gsmsim_simulator_c


#endif //#if !defined(_EAP_AM_TYPE_GSMSIM_SYMBIAN_SIMULATOR_H_)

//--------------------------------------------------



// End.
