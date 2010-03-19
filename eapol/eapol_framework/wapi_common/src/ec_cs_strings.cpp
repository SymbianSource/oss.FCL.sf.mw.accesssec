/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/src/ec_cs_strings.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 14 % << Don't touch! Updated by Synergy at check-out.
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
	#define EAP_FILE_NUMBER_ENUM 700 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#if defined(USE_WAPI_CORE)

#include "eap_automatic_variable.h"
#include "ec_cs_types.h"
#include "ec_cs_data.h"
#include "ec_cs_strings.h"

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT ec_cs_strings_c::~ec_cs_strings_c()
{
}

EAP_FUNC_EXPORT ec_cs_strings_c::ec_cs_strings_c()
{
}

EAP_FUNC_EXPORT eap_const_string ec_cs_strings_c::get_ec_cs_store_data_string(const ec_cs_data_type_e type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, ec_cs_data_type_none)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_master_key)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_password)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_device_seed)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_reference_counter)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_certificate_reference)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_certificate_file_password)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_ca_asu_id_list)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_ca_asu_id)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_client_asu_id_list)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_client_asu_id)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_ca_certificate_data)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_client_certificate_data)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_private_key_data)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_selected_ca_id)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_selected_client_id)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_user_authorization_reference)
	else EAP_IF_RETURN_STRING(type, ec_cs_data_type_user_authorization_data)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(type);
		return EAPL("Unknown EC CS data type string");
	}
}

EAP_FUNC_EXPORT eap_const_string ec_cs_strings_c::get_ec_cs_store_data_change_status_string(const ec_cs_data_change_status_e status)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(status, ec_cs_data_change_status_none)
	else EAP_IF_RETURN_STRING(status, ec_cs_data_change_status_modified)
	else EAP_IF_RETURN_STRING(status, ec_cs_data_change_status_new)
	else EAP_IF_RETURN_STRING(status, ec_cs_data_change_status_delete)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(status);
		return EAPL("Unknown EC CS data change status string");
	}
}

EAP_FUNC_EXPORT eap_const_string ec_cs_strings_c::get_ec_cs_store_data_string(const ec_cs_pending_operation_e type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, ec_cs_pending_operation_none)
	else EAP_IF_RETURN_STRING(type, ec_cs_pending_operation_certificate_authentication)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(type);
		return EAPL("Unknown EC CS data change status string");
	}
}

/**
 * Function returns string of ec_cs_tlv_type_e.
 * @param status is the queried string.
 */
EAP_FUNC_EXPORT eap_const_string ec_cs_strings_c::get_ec_cs_tlv_header_string(
	const ec_cs_tlv_type_e type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_none)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_Import_File)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_Import_File_Password)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_CS_certificate_data)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_CS_private_key_data)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_CS_ASU_ID)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_CS_ID_reference)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_CS_certificate_reference)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_CS_encrypted_block)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_CS_encryption_IV)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_CS_encrypted_data)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_CS_padding)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_CS_MAC)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_CS_master_key)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_CS_reference_counter)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_first_known)
	else EAP_IF_RETURN_STRING(type, ec_cs_tlv_type_last_known)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(type);
		return EAPL("Unknown EC CS TLV header string");
	}
}

//----------------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

// End.
