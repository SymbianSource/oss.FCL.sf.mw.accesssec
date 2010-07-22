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

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 38 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



/** @file */

#include "eap_tools.h"
#include "eap_status_string.h"

//------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_string_c::~eap_status_string_c()
{
}

EAP_FUNC_EXPORT eap_status_string_c::eap_status_string_c()
{
}

EAP_FUNC_EXPORT eap_const_string eap_status_string_c::get_status_string(const eap_status_e status)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(status, eap_status_ok)
	else EAP_IF_RETURN_STRING(status, eap_status_success)
	else EAP_IF_RETURN_STRING(status, eap_status_pending_request)
	else EAP_IF_RETURN_STRING(status, eap_status_completed_request)
	else EAP_IF_RETURN_STRING(status, eap_status_drop_packet_quietly)
	else EAP_IF_RETURN_STRING(status, eap_status_not_supported)
	else EAP_IF_RETURN_STRING(status, eap_status_process_general_error)
	else EAP_IF_RETURN_STRING(status, eap_status_type_does_not_exists_error)
	else EAP_IF_RETURN_STRING(status, eap_status_allocation_error)
	else EAP_IF_RETURN_STRING(status, eap_status_process_illegal_packet_error)
	else EAP_IF_RETURN_STRING(status, eap_status_ethernet_type_not_supported)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_eap_code)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_eap_type)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_eap_identity)
	else EAP_IF_RETURN_STRING(status, eap_status_authentication_failure)
	else EAP_IF_RETURN_STRING(status, eap_status_encryption_failure)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_padding)
	else EAP_IF_RETURN_STRING(status, eap_status_randomize_failure)
	else EAP_IF_RETURN_STRING(status, eap_status_handler_exists_error)
	else EAP_IF_RETURN_STRING(status, eap_status_handler_does_not_exists_error)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_sae_state)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_eapol_version)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_eapol_type)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_eapol_oui)
	else EAP_IF_RETURN_STRING(status, eap_status_header_corrupted)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_sae_sequence_number)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_isakmp_header_version)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_isakmp_exchange_type)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_isakmp_flags)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_isakmp_message_id)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_isakmp_cookie)
	else EAP_IF_RETURN_STRING(status, eap_status_unsupported_isakmp_payload)
	else EAP_IF_RETURN_STRING(status, eap_status_key_error)
	else EAP_IF_RETURN_STRING(status, eap_status_too_many_offers)
	else EAP_IF_RETURN_STRING(status, eap_status_send_failed)
	else EAP_IF_RETURN_STRING(status, eap_status_data_length_not_aligned_to_block_size)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_network_id)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_handle)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_configure_field)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_configure_type)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_sae_header_version)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_sae_exchange_type)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_sae_flags)
	else EAP_IF_RETURN_STRING(status, eap_status_unsupported_sae_payload)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_sae_cookie)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_encryption_parameter_size)
	else EAP_IF_RETURN_STRING(status, eap_status_state_reference_count_not_zero)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_nai)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_nai_payload)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_data_payload)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_payload)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_hashed_index)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_gsmsim_state)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_eap_type_state)
	else EAP_IF_RETURN_STRING(status, eap_status_unsupported_gsmsim_payload)
	else EAP_IF_RETURN_STRING(status, eap_status_gsmsim_triplet_query_failed)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_index)
	else EAP_IF_RETURN_STRING(status, eap_status_timed_out)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_eap_subtype)
	else EAP_IF_RETURN_STRING(status, eap_status_exit_test)
	else EAP_IF_RETURN_STRING(status, eap_status_no_matching_protocol_version)
	else EAP_IF_RETURN_STRING(status, eap_status_too_short_message)
	else EAP_IF_RETURN_STRING(status, eap_status_too_long_message)
	else EAP_IF_RETURN_STRING(status, eap_status_hardware_not_ready)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_protocol)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_type)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_parameter)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_certificate)
	else EAP_IF_RETURN_STRING(status, eap_status_illegal_cipher_suite)
	else EAP_IF_RETURN_STRING(status, eap_status_bad_certificate)
	else EAP_IF_RETURN_STRING(status, eap_status_unsupported_certificate)
	else EAP_IF_RETURN_STRING(status, eap_status_certificate_revoked)
	else EAP_IF_RETURN_STRING(status, eap_status_certificate_expired)

	// This is splitted to decrease if nesting. Some compilers fails to compile.
	EAP_IF_RETURN_STRING(status, eap_status_user_certificate_unknown)
	else EAP_IF_RETURN_STRING(status, eap_status_ca_certificate_unknown)
	else EAP_IF_RETURN_STRING(status, eap_status_unknown_ca)
	else EAP_IF_RETURN_STRING(status, eap_status_access_denied)
	else EAP_IF_RETURN_STRING(status, eap_status_unexpected_message)
	else EAP_IF_RETURN_STRING(status, eap_status_buffer_too_short)
	else EAP_IF_RETURN_STRING(status, eap_status_not_found)
	else EAP_IF_RETURN_STRING(status, eap_status_not_enough_challenges)
	else EAP_IF_RETURN_STRING(status, eap_status_not_fresh_challenges)
	else EAP_IF_RETURN_STRING(status, eap_status_already_exists)
	else EAP_IF_RETURN_STRING(status, eap_status_insufficient_security)
	else EAP_IF_RETURN_STRING(status, eap_status_syncronization_failure)
	else EAP_IF_RETURN_STRING(status, eap_status_file_does_not_exist)
	else EAP_IF_RETURN_STRING(status, eap_status_end_of_file)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_authentication_type)
	else EAP_IF_RETURN_STRING(status, eap_status_section_ends)
	else EAP_IF_RETURN_STRING(status, eap_status_missing_payload)
	else EAP_IF_RETURN_STRING(status, eap_status_realm_check_failed)
	else EAP_IF_RETURN_STRING(status, eap_status_identity_query_failed)
	else EAP_IF_RETURN_STRING(status, eap_status_credential_query_failed)
	else EAP_IF_RETURN_STRING(status, eap_status_user_has_not_subscribed_to_the_requested_service)
	else EAP_IF_RETURN_STRING(status, eap_status_users_calls_are_barred)
	else EAP_IF_RETURN_STRING(status, eap_status_restricted_logon_hours)
	else EAP_IF_RETURN_STRING(status, eap_status_account_disabled)
	else EAP_IF_RETURN_STRING(status, eap_status_no_dialin_permission)
	else EAP_IF_RETURN_STRING(status, eap_status_password_expired)
	else EAP_IF_RETURN_STRING(status, eap_status_wrong_password)
	else EAP_IF_RETURN_STRING(status, eap_status_oob_interface_read_error)
	else EAP_IF_RETURN_STRING(status, eap_status_decryption_crc_failure)
	else EAP_IF_RETURN_STRING(status, eap_status_rf_band_2_4_ghz_not_supported)
	else EAP_IF_RETURN_STRING(status, eap_status_rf_band_5_0_ghz_not_supported)
	else EAP_IF_RETURN_STRING(status, eap_status_signal_too_weak)
	else EAP_IF_RETURN_STRING(status, eap_status_network_authentication_failure)
	else EAP_IF_RETURN_STRING(status, eap_status_network_association_failure)
	else EAP_IF_RETURN_STRING(status, eap_status_no_dhcp_response)
	else EAP_IF_RETURN_STRING(status, eap_status_failed_dhcp_configure)
	else EAP_IF_RETURN_STRING(status, eap_status_ip_address_conflict)
	else EAP_IF_RETURN_STRING(status, eap_status_could_not_connect_to_registrar)
	else EAP_IF_RETURN_STRING(status, eap_status_multiple_pbc_sessions_detected)
	else EAP_IF_RETURN_STRING(status, eap_status_rogue_activity_suspected)
	else EAP_IF_RETURN_STRING(status, eap_status_device_busy)
	else EAP_IF_RETURN_STRING(status, eap_status_setup_locked)
	else EAP_IF_RETURN_STRING(status, eap_status_message_timeout)
	else EAP_IF_RETURN_STRING(status, eap_status_registration_session_timeout)
	else EAP_IF_RETURN_STRING(status, eap_status_device_password_authentication_failure)
	else EAP_IF_RETURN_STRING(status, eap_status_pin_code_authentication_not_supported)
	else EAP_IF_RETURN_STRING(status, eap_status_push_button_authentication_not_supported)
	else EAP_IF_RETURN_STRING(status, eap_status_end_recursion)
	else EAP_IF_RETURN_STRING(status, eap_status_tunnel_compromise_error)
	else EAP_IF_RETURN_STRING(status, eap_status_unexpected_tlv_exhanged)
	else EAP_IF_RETURN_STRING(status, eap_status_no_pac_nor_certs_to_authenticate_with_provision_disabled)
	else EAP_IF_RETURN_STRING(status, eap_status_no_matching_pac_for_aid)
	else EAP_IF_RETURN_STRING(status, eap_status_pac_store_corrupted)
	else EAP_IF_RETURN_STRING(status, eap_status_user_cancel_authentication)
	else EAP_IF_RETURN_STRING(status, eap_status_no_match)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(status);
		return EAPL("Unknown EAP-status");
	}
}

//------------------------------------------------------------------------------
// End.
