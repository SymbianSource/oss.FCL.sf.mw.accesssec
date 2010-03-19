/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_symbian/include/certificate_store_db_parameters.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 15 % << Don't touch! Updated by Synergy at check-out.
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


#if !defined(_CERTIFICATESTOREDBPARAMETERNAMES_H_)
#define _CERTIFICATESTOREDBPARAMETERNAMES_H_


// For the certificate store database.
// Full path is not needed. The database certificatestore.dat will be saved in the 
// data cage path for DBMS. So it will be in "\private\100012a5\certificatestore.dat" in C: drive.
// The maximum length of database name is 0x40 (KDbMaxName) , which is defined in d32dbms.h.
_LIT( KCsDatabaseName, "c:certificatestore.dat" );

// For the security policy.
_LIT( KSecureUidFormatCertificate, "SECURE[20021357]" ); 


// Table names in certificate store
_LIT( KCsGeneralSettingsTableName,  "cs_general_settings" );
_LIT( KCsClientAsuIdListTableName,  "cs_client_asu_id_list" );
_LIT( KCsCaAsuIdListTableName,      "cs_ca_asu_id_list" );
_LIT( KCsClientCertificateTable,    "cs_client_certificate" );
_LIT( KCsCaCertificateTable,        "cs_ca_certificate" );
_LIT( KCsPrivateKeyTable,           "cs_private_key" );
_LIT( KCsWapiCertLabelTable,        "wapi_cs_cert_labels" );
_LIT( KCsWapiCertFileTable,         "wapi_cs_cert_files" );

/**
* Column names in general settings table.
*/
_LIT( KCsPassword, "CS_password" );
_LIT( KCsReferenceCounter, "CS_reference_counter" );
_LIT( KCsMasterKey, "CS_master_key" );
_LIT( KCsInitialized, "CS_initialized" );
_LIT( KCsPasswordMaxValidityTime, "CS_password_max_validity_time" );
_LIT( KCsLastPasswordIdentityTime, "CS_password_last_identity_time" );

/**
* Column names in client ASU ID list table.
*/ 
_LIT( KCsClientAsuIdReference, "CS_client_ASU_ID_reference" );
_LIT( KCsClientAsuIdData, "CS_client_ASU_ID_data" );

/**
* Column names in CA ASU ID list table.
*/ 
_LIT( KCsCaAsuIdReference, "CS_CA_ASU_ID_reference" );
_LIT( KCsCaAsuIdData, "CS_CA_ASU_ID_data" );

/**
* Column names in client certificate table
*/ 
_LIT( KCsClientCertAsuIdReference, "CS_client_cert_ASU_ID_reference" );
_LIT( KCsClientCertData, "CS_client_cert_data" );

/**
* Column names in CA certificate table
*/ 
_LIT( KCsCaCertAsuIdReference, "CS_CA_cert_ASU_ID_reference" );
_LIT( KCsCaCertData, "CS_CA_cert_data" );

/**
* Column names in private key table
*/ 
_LIT( KCsPrivateKeyAsuIdReference, "CS_private_key_ASU_ID_reference" );
_LIT( KCsPrivateKeyData, "CS_private_key_data" );

/**
* Column names in certificate label table for WAPI
*/ 
_LIT( KCsCertLabelAsuIdReference, "wapi_cs_cert_ASU_ID_reference" );
_LIT( KCsCACertLabel, "CS_CA_cert_label" );
_LIT( KCsUserCertLabel, "CS_user_cert_label" );

/**
* Column names in certificate file table for WAPI
*/ 
_LIT( KCsFileName, "CS_file_name" );

/* Constants that define maximum column
* lengths in CS DB.
*/ 
const TUint KCsMaxPasswordLengthInDb = 255;
const TUint KCsMaxRefCounterLengthInDb = 255;
const TUint KCsMaxMasterKeyLengthInDb = 255;
const TUint KCsMaxAsuIdRefLengthInDb = 10;  // 5 digits -> unicode
// maximum subject label length
const TUint KCsMaxWapiCertLabelLength = 255; 
// maximum lenght for the decoded identity in the db
const TUint KCsMaxWapiCertLabelTableLength = 800;

/**
* Maximum length of SQL query in CS DB.
*/ 
const TUint KMaxSqlQueryLength = 512;

/**
* Constant defines default column number.
*/ 
const TInt KDefaultColumnNumberOne = 1; // For DB view.

// The directory from where the certificates are imported
_LIT8(KCertificateStoreImportDir, "c:\\data\\WAPI\\");
// Max filesize for importable file
const TUint KMaxCertificateFileSize = 4096;

#endif // _CERTIFICATESTOREDBPARAMETERNAMES_H_
