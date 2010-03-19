/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/wapi_strings.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 23 % << Don't touch! Updated by Synergy at check-out.
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
* Template version: 4.1.1
*/



// This is enumeration of WAPI source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 707 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#if defined(USE_WAPI_CORE)

#include "eap_automatic_variable.h"
#include "ec_cs_types.h"
#include "ec_cs_data.h"
#include "wapi_strings.h"

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT wapi_strings_c::~wapi_strings_c()
{
}

EAP_FUNC_EXPORT wapi_strings_c::wapi_strings_c()
{
}

EAP_FUNC_EXPORT eap_const_string wapi_strings_c::get_wapi_completion_operation_string(const wapi_completion_operation_e type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, wapi_completion_operation_none)
	else EAP_IF_RETURN_STRING(type, wapi_completion_operation_continue_certificate_authentication)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(type);
		return EAPL("Unknown WAPI completion operation");
	}
}

EAP_FUNC_EXPORT eap_const_string wapi_strings_c::get_wai_protocol_version_string(const wai_protocol_version_e type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, wai_protocol_version_none)
	else EAP_IF_RETURN_STRING(type, wai_protocol_version_1)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(type);
		return EAPL("Unknown WAI protocol version");
	}
}

EAP_FUNC_EXPORT eap_const_string wapi_strings_c::get_wai_protocol_type_string(const wai_protocol_type_e type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, wai_protocol_type_none)
	else EAP_IF_RETURN_STRING(type, wai_protocol_type_wai)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(type);
		return EAPL("Unknown WAI protocol type");
	}
}

EAP_FUNC_EXPORT eap_const_string wapi_strings_c::get_wai_protocol_subtype_string(const wai_protocol_subtype_e type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, wai_protocol_subtype_none)
	else EAP_IF_RETURN_STRING(type, wai_protocol_subtype_pre_authentication_start)
	else EAP_IF_RETURN_STRING(type, wai_protocol_subtype_stakey_request)
	else EAP_IF_RETURN_STRING(type, wai_protocol_subtype_authentication_activation)
	else EAP_IF_RETURN_STRING(type, wai_protocol_subtype_access_authentication_request)
	else EAP_IF_RETURN_STRING(type, wai_protocol_subtype_access_authentication_response)
	else EAP_IF_RETURN_STRING(type, wai_protocol_subtype_certificate_authentication_request)
	else EAP_IF_RETURN_STRING(type, wai_protocol_subtype_certificate_authentication_response)
	else EAP_IF_RETURN_STRING(type, wai_protocol_subtype_unicast_key_negotiation_request)
	else EAP_IF_RETURN_STRING(type, wai_protocol_subtype_unicast_key_negotiation_response)
	else EAP_IF_RETURN_STRING(type, wai_protocol_subtype_unicast_key_negotiation_confirmation)
	else EAP_IF_RETURN_STRING(type, wai_protocol_subtype_multicast_key_announcement)
	else EAP_IF_RETURN_STRING(type, wai_protocol_subtype_multicast_key_announcement_response)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(type);
		return EAPL("Unknown WAI protocol subtype");
	}
}

EAP_FUNC_EXPORT eap_const_string wapi_strings_c::get_wai_tlv_header_string(const wai_tlv_type_e type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, wai_tlv_type_none)
	else EAP_IF_RETURN_STRING(type, wai_tlv_type_signature_attribute)
	else EAP_IF_RETURN_STRING(type, wai_tlv_type_echd_parameter)
	else EAP_IF_RETURN_STRING(type, wai_tlv_type_result_of_certificate_validation)
	else EAP_IF_RETURN_STRING(type, wai_tlv_type_identity_list)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(type);
		return EAPL("Unknown WAI TLV header type");
	}
}

EAP_FUNC_EXPORT eap_const_string wapi_strings_c::get_wai_payload_type_string(const wai_payload_type_e type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, wai_payload_type_none)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_flag)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_access_result)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_uskid)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_mskid_stakeyid)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_result)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_addid)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_bkid)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_key_announcement_identifier)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_data_sequence_number)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_message_authentication_code)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_authentication_identifier)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_nonce)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_key_data)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_wie)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_echd_parameter)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_signature_attributes)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_result_of_certificate_verification)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_identity_list)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_optional)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_certificate)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_identity)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_first_known)
	else EAP_IF_RETURN_STRING(type, wai_payload_type_last_known)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(type);
		return EAPL("Unknown WAI payload type");
	}
}

EAP_FUNC_EXPORT eap_const_string wapi_strings_c::get_wapi_core_state_string(const wapi_core_state_e state)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(state, wapi_core_state_none)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_start_unicast_key_negotiation)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_start_certificate_negotiation)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_start_multicast_key_announcement)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_wait_authentication_activation_message)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_process_authentication_activation_message)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_wait_access_authentication_request_message)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_process_access_authentication_request_message)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_process_access_authentication_request_message_ASU_signature_trusted_by_AE)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_process_access_authentication_request_message_AE_signature_trusted_by_ASUE)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_wait_certificate_authentication_request_message)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_wait_certificate_authentication_response_message)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_wait_access_authentication_response_message)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_process_access_authentication_response_message)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_process_access_authentication_response_message_ASU_signature)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_wait_unicast_key_negotiation_request_message)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_wait_unicast_key_negotiation_response_message)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_wait_unicast_key_negotiation_confirmation_message)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_wait_multicast_announcement_message)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_wait_multicast_announcement_response_message)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_authentication_ok)
	else EAP_IF_RETURN_STRING(state, wapi_core_state_authentication_failed)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(state);
		return EAPL("Unknown WAPI core state");
	}
};


EAP_FUNC_EXPORT eap_const_string wapi_strings_c::get_wapi_negotiation_state_string(const wapi_negotiation_state_e state)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(state, wapi_negotiation_state_none)
	else EAP_IF_RETURN_STRING(state, wapi_negotiation_state_initial_negotiation)
	else EAP_IF_RETURN_STRING(state, wapi_negotiation_state_rekeying)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(state);
		return EAPL("Unknown WAPI negotiation state");
	}
};

//----------------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
