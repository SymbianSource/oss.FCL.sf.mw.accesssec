/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/ec_cs_types.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 27 % << Don't touch! Updated by Synergy at check-out.
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



#if !defined(_EC_CS_TYPES_H_)
#define _EC_CS_TYPES_H_

#if defined(USE_WAPI_CORE)

#include "eap_am_export.h"
#include "eap_tools.h"

/** @file */

//----------------------------------------------------------------------------

const u8_t EC_CS_ENCRYPTION_KEY_LABEL[] = "CS Encryption Key";
const u32_t EC_CS_ENCRYPTION_KEY_LABEL_SIZE = sizeof(EC_CS_ENCRYPTION_KEY_LABEL)-1ul;

const u8_t EC_CS_MAC_KEY_LABEL[] = "CS MAC Key";
const u32_t EC_CS_MAC_KEY_LABEL_SIZE = sizeof(EC_CS_MAC_KEY_LABEL)-1ul;

const u8_t EC_CS_SEED_SEPARATOR[] = { 0x00 };
const u32_t EC_CS_SEED_SEPARATOR_SIZE = sizeof(EC_CS_SEED_SEPARATOR);

const u8_t EC_CS_MASTER_KEY_SEED[] = "CS-Master-Key";
const u32_t EC_CS_MASTER_KEY_SEED_SIZE = sizeof(EC_CS_MASTER_KEY_SEED);

const u8_t EC_CS_REFERENCE_COUNTER_SEED[] = "Reference counter";
const u32_t EC_CS_REFERENCE_COUNTER_SEED_SIZE = sizeof(EC_CS_REFERENCE_COUNTER_SEED);

const u8_t EC_CS_CA_CERTIFICATE_DATA_DATA_SEED[] = "CA-Certificate-Data";
const u32_t EC_CS_CA_CERTIFICATE_DATA_DATA_SEED_SIZE = sizeof(EC_CS_CA_CERTIFICATE_DATA_DATA_SEED);

const u8_t EC_CS_USER_CERTIFICATE_DATA_DATA_SEED[] = "User-Certificate-Data";
const u32_t EC_CS_USER_CERTIFICATE_DATA_DATA_SEED_SIZE = sizeof(EC_CS_USER_CERTIFICATE_DATA_DATA_SEED);

const u8_t EC_CS_PRIVATE_KEY_DATA_SEED[] = "Private-Key-Data";
const u32_t EC_CS_PRIVATE_KEY_DATA_SEED_SIZE = sizeof(EC_CS_PRIVATE_KEY_DATA_SEED);

const u8_t EC_CS_CA_ASU_ID_DATA_SEED[] = "CA-ASU-ID";
const u32_t EC_CS_CA_ASU_ID_DATA_SEED_SIZE = sizeof(EC_CS_CA_ASU_ID_DATA_SEED);

const u8_t EC_CS_CLIENT_ASU_ID_DATA_SEED[] = "Client-ASU-ID";
const u32_t EC_CS_CLIENT_ASU_ID_DATA_SEED_SIZE = sizeof(EC_CS_CLIENT_ASU_ID_DATA_SEED);

const u32_t EC_CS_MASTER_KEY_SIZE = 32ul;
const u32_t EC_CS_ENCRYPTION_KEY_SIZE = 16ul;
const u32_t EC_CS_MAC_KEY_SIZE = 32ul;

const u8_t EC_CS_ZERO_REFERENCE[] = { 0x00, 0x00, 0x00, 0x00, };

const char WAPI_CS_MEMORY_STORE_KEY[] = "ec_certificate_store_c CS";

const u32_t EAP_FAST_PAC_STORE_DEFAULT_KEY_CACHE_TIMEOUT = 43200000u; // in milliseconds = 12 hours

const u32_t EAP_FAST_PAC_STORE_MASTER_KEY_SIZE = 32ul;
const u32_t EAP_FAST_PAC_STORE_ENCRYPTION_KEY_SIZE = 16ul;
const u32_t EAP_FAST_PAC_STORE_MAC_KEY_SIZE = 32ul;

//----------------------------------------------------------------------------

/// Enumeration describes the pending operation of Elliptic Curve Certificate Store.
enum ec_cs_pending_operation_e
{
	ec_cs_pending_operation_none,
	ec_cs_pending_operation_certificate_authentication,
	ec_cs_pending_operation_import_ca_certificate_file,
	ec_cs_pending_operation_import_client_certificate_file,
	ec_cs_pending_operation_select_client_certificate,
	ec_cs_pending_operation_query_certificate_list,
	ec_cs_pending_operation_verify_signature_with_public_key,
};

/// Enumeration describes the valid types of ec_cs_data_type_e.
enum ec_cs_data_type_e
{
	ec_cs_data_type_none,
	ec_cs_data_type_master_key,
	ec_cs_data_type_password,
	ec_cs_data_type_device_seed,
	ec_cs_data_type_reference_counter,
	ec_cs_data_type_certificate_reference,
	ec_cs_data_type_certificate_file_password,
	ec_cs_data_type_ca_asu_id_list, // Read all ec_cs_data_type_ca_asu_id objects.
	ec_cs_data_type_ca_asu_id,
	ec_cs_data_type_client_asu_id_list, // Read all ec_cs_data_type_client_asu_id objects.
	ec_cs_data_type_client_asu_id,
	ec_cs_data_type_ca_certificate_data,
	ec_cs_data_type_client_certificate_data,
	ec_cs_data_type_private_key_data,
	ec_cs_data_type_selected_ca_id,
	ec_cs_data_type_selected_client_id,
	ec_cs_data_type_user_authorization_reference, // This is used in internal RAM memory store.
	ec_cs_data_type_user_authorization_data, // This is used in internal RAM memory store.
};

/// Enumeration describes the change status of written ec_cs_data_c.
/// This value tells during write_certificate_store_data() whether the status is modified, new or delete.
enum ec_cs_data_change_status_e
{
	ec_cs_data_change_status_none,
	ec_cs_data_change_status_modified,
	ec_cs_data_change_status_new,
	ec_cs_data_change_status_delete,
};

/**
 * This is enumeration of Certificate Store Type-Length-Value (TLV) values.
 */
enum ec_cs_tlv_type_e
{
	ec_cs_tlv_type_none,

	ec_cs_tlv_type_Import_File,
	ec_cs_tlv_type_Import_File_Password,

	ec_cs_tlv_type_CS_certificate_data,
	ec_cs_tlv_type_CS_private_key_data,

	ec_cs_tlv_type_CS_ASU_ID,
	ec_cs_tlv_type_CS_ID_reference,
	ec_cs_tlv_type_CS_certificate_reference,
	ec_cs_tlv_type_CS_encrypted_block,
	ec_cs_tlv_type_CS_encryption_IV,
	ec_cs_tlv_type_CS_encrypted_data,
	ec_cs_tlv_type_CS_padding,
	ec_cs_tlv_type_CS_MAC,
	ec_cs_tlv_type_CS_master_key,
	ec_cs_tlv_type_CS_reference_counter,

	ec_cs_tlv_type_first_known         = ec_cs_tlv_type_Import_File, ///< First known TLV type.
	ec_cs_tlv_type_last_known          = ec_cs_tlv_type_CS_reference_counter, ///< Last known TLV type.
};

//----------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_EC_CS_TYPES_H_)


// End.
