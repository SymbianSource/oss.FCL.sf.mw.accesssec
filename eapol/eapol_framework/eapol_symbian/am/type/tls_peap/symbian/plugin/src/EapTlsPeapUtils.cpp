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
* %version: 141 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 438 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES
#include "EapTlsPeapUtils.h"
#include "EapTlsPeapDbDefaults.h"
#include "EapTlsPeapDbParameterNames.h"
#include <x500dn.h>
#include <x509cert.h>
#include <x509certext.h>

#include "EapPluginTools.h"
#include "EapConversion.h"
#include "EapAutomatic.h"

#ifdef USE_FAST_EAP_TYPE
#include "pac_store_db_parameters.h"
#endif //#ifdef USE_FAST_EAP_TYPE

#include <EapTraceSymbian.h>

#include "EapTlsPeapCertFetcher.h"

const TUint KMaxSqlQueryLength = 2048;
const TInt	KMicroSecsInAMinute = 60000000; // 60000000 micro seconds is 1 minute.
const TInt	KDefaultColumnInView_One = 1; // For DB view.
const TInt 	KMaxEapDbTableNameLength = 64;

// ================= MEMBER FUNCTIONS =======================

void EapTlsPeapUtils::OpenDatabaseL(
	RDbNamedDatabase& aDatabase,
	RFs& aFileServerSession,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	eap_type_value_e aEapType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenDatabaseL(): - Start - aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x, aEapType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type(),
		aEapType.get_vendor_id(),
		aEapType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::OpenDatabaseL()\n"));

	if (aEapType == eap_type_tls)
	{
		OpenTlsDatabaseL(aDatabase, aFileServerSession, aIndexType, aIndex, aTunnelingType);
	} 
	else if (aEapType == eap_type_peap)
	{
		OpenPeapDatabaseL(aDatabase, aFileServerSession, aIndexType, aIndex, aTunnelingType);
	} 
#if defined(USE_TTLS_EAP_TYPE)
	else if (aEapType == eap_type_ttls)
	{
		OpenTtlsDatabaseL(aDatabase, aFileServerSession, aIndexType, aIndex, aTunnelingType);
	} 
#endif // #if defined(USE_TTLS_EAP_TYPE)
#if defined(USE_FAST_EAP_TYPE)
	else if (aEapType == eap_type_fast)
	{
		OpenFastDatabaseL(aDatabase, aFileServerSession, aIndexType, aIndex, aTunnelingType);
	} 
#endif // #if defined(USE_FAST_EAP_TYPE)
	else if ( aEapType == eap_expanded_type_ttls_plain_pap.get_type() )
	{
		OpenTtlsDatabaseL( aDatabase, aFileServerSession, aIndexType, aIndex, aTunnelingType);
	}
	else
	{
		// Unsupported EAP type
		User::Leave(KErrNotSupported);
	}	
} // EapTlsPeapUtils::OpenDatabaseL()

// ---------------------------------------------------------

void EapTlsPeapUtils::OpenTlsDatabaseL(
	RDbNamedDatabase& aDatabase,
	RFs& aFileServerSession,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenTlsDatabaseL(): - Start - aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::OpenTlsDatabaseL()\n"));

	// 1. Open/create a database	
	
	TInt error(KErrNone);
	TFileName aPrivateDatabasePathName;

	EapPluginTools::CreateDatabaseLC(
		aDatabase,
		aFileServerSession,
		error,
		KTlsDatabaseName,
		aPrivateDatabasePathName);

	if(error == KErrNone)
	{
		aDatabase.Close();
	}
	else if (error != KErrAlreadyExists) 
	{
		User::LeaveIfError(error);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTlsDatabaseL(): - calls aDatabase.Open()\n")));

	error = aDatabase.Open(aFileServerSession, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTlsDatabaseL(): - Opened private DB for EAP-TLS. error=%d\n"), error));

	User::LeaveIfError(error);

	// 2. Create the eaptls table to database (ignore error if exists)
	
	// Table columns:
	//// NAME ////////////////////////////////////////// TYPE //////////// Constant ////////////////////
	//| ServiceType									| UNSIGNED INTEGER | KServiceType         |//
	//| ServiceIndex								| UNSIGNED INTEGER | KServiceIndex        |//
	//| TunnelingTypeVendorId                       | UNSIGNED INTEGER | KTunnelingTypeVendorId    |//
	//| TunnelingType								| UNSIGNED INTEGER | KTunnelingType		|//
	//| EAP_TLS_PEAP_use_manual_realm				| UNSIGNED INTEGER | cf_str_EAP_TLS_PEAP_use_manual_realm_literal      |//
	//| EAP_TLS_PEAP_manual_realm					| VARCHAR(255)     | cf_str_EAP_TLS_PEAP_manual_realm_literal				|//
	//| EAP_TLS_PEAP_use_manual_username			| UNSIGNED INTEGER | cf_str_EAP_TLS_PEAP_use_manual_username_literal   |//
	//| EAP_TLS_PEAP_manual_username				| VARCHAR(255)     | cf_str_EAP_TLS_PEAP_manual_username_literal			|//
	//| EAP_TLS_PEAP_cipher_suite					| UNSIGNED INTEGER | cf_str_EAP_TLS_PEAP_cipher_suite_literal	    |//
	//| EAP_TLS_server_authenticates_client			| UNSIGNED INTEGER | cf_str_TLS_server_authenticates_client_policy_in_client_literal |//
	//| CA_cert_label								| VARCHAR(255)     | KCACertLabel	    |//
	//| client_cert_label							| VARCHAR(255)     | KClientCertLabel	    |//
	//| EAP_TLS_PEAP_saved_session_id				| BINARY(32)       | cf_str_EAP_TLS_PEAP_saved_session_id_literal		    |//
	//| EAP_TLS_PEAP_saved_master_secret			| BINARY(48)       | cf_str_EAP_TLS_PEAP_saved_master_secret_literal	    |//
	//| EAP_TLS_PEAP_saved_cipher_suite				| UNSIGNED INTEGER | cf_str_EAP_TLS_PEAP_saved_cipher_suite_literal    |//
	//| EAP_TLS_PEAP_verify_certificate_realm		| UNSIGNED INTEGER | cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal		    |//
	//| EAP_TLS_max_session_validity_time			| BIGINT           | cf_str_EAP_TLS_max_session_validity_time_literal   |//
	//| EAP_TLS_last_full_authentication_time		| BIGINT           | KTLSLastFullAuthTime	   	|//	
	//| EAP_TLS_PEAP_use_identity_privacy	    	| UNSIGNED INTEGER | cf_str_EAP_TLS_PEAP_use_identity_privacy_literal|//
	//| EAP_TLS_PEAP_use_automatic_ca_certificate	| UNSIGNED INTEGER | cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal|//
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////	

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Table creation is divided into two parts because otherwise the SQL string would get too long
	_LIT(KSQLCreateTable1, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d),     \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d),     \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d),	  \
		 %S VARCHAR(%d),     \
		 %S BINARY(%d),		  \
		 %S BINARY(%d),		  \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S BIGINT, \
		 %S BIGINT, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER)");
											 
	sqlStatement.Format(KSQLCreateTable1,
		&KTlsDatabaseTableName,
		&KServiceType,
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType,
		&cf_str_EAP_TLS_PEAP_use_manual_realm_literal,
		&cf_str_EAP_TLS_PEAP_manual_realm_literal, KMaxRealmLengthInDB,
		&cf_str_EAP_TLS_PEAP_use_manual_username_literal,
		&cf_str_EAP_TLS_PEAP_manual_username_literal, KMaxUsernameLengthInDB,
		&cf_str_EAP_TLS_PEAP_cipher_suite_literal, 
		&cf_str_TLS_server_authenticates_client_policy_in_client_literal,
		&KCACertLabel, KMaxCertLabelLengthInDB,
		&KClientCertLabel, KMaxCertLabelLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_session_id_literal, KMaxSessionIdLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_master_secret_literal, KMaxMasterSecretLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_cipher_suite_literal,
		&cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal,		
		&cf_str_EAP_TLS_max_session_validity_time_literal,
		&KTLSLastFullAuthTime,
		&cf_str_EAP_TLS_PEAP_use_identity_privacy_literal,
		&cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal);	
	
	error = aDatabase.Execute(sqlStatement);
	if (error == KErrAlreadyExists)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTlsDatabaseL - Alter Table error=%d\n"), error) );
		_LIT( KColumnDef, "UNSIGNED INTEGER" );
		AlterTableL( aDatabase, EAddColumn , KTlsDatabaseTableName,
			cf_str_EAP_TLS_PEAP_use_identity_privacy_literal, KColumnDef);
	}
	else if (error != KErrNone)
	{
		User::Leave(error);
	}

	// Create table for _allowed_ user certificates
	
	//// NAME ////////////////// TYPE ////////////// Constant ///////////
	//| ServiceType			  | UNSIGNED INTEGER | KServiceType        |//
	//| ServiceIndex		  | UNSIGNED INTEGER | KServiceIndex       |//
	//| TunnelingTypeVendorId | UNSIGNED INTEGER | KTunnelingTypeVendorId    |//
	//| TunnelingType		  | UNSIGNED INTEGER | KTunnelingType		|//
	//| CertLabel			  | VARCHAR(255)     | KCertLabel        |//	
	//| SubjectKeyId		  | BINARY(20)       | KSubjectKeyIdentifier |// This is Symbian subjectkey id
	//| ActualSubjectKeyId    | BINARY(20)       | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
	//| SubjectName			  | VARCHAR(255)     | KSubjectName        |//	
	//| IssuerName			  | VARCHAR(255)     | KIssuerName        |//	
	//| SerialNumber		  | VARCHAR(255)     | KSerialNumber        |//	
	//| Thumbprint			  | BINARY(64)       | KThumbprint        |//	
	//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable2, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d), \
		 %S BINARY(%d), \
		 %S BINARY(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S BINARY(%d))");

	sqlStatement.Format(KSQLCreateTable2,
		&KTlsAllowedUserCertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex, 
		&KTunnelingTypeVendorId,
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);
				
	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}

	// Create table for _allowed_ CA certs

	//// NAME ////////////////// TYPE ////////////// Constant ///////////
	//| ServiceType		      | UNSIGNED INTEGER | KServiceType        |//
	//| ServiceIndex		  | UNSIGNED INTEGER | KServiceIndex       |//
	//| TunnelingTypeVendorId | UNSIGNED INTEGER | KTunnelingTypeVendorId    |//
	//| TunnelingType		  | UNSIGNED INTEGER | KTunnelingType		|//
	//| CertLabel			  | VARCHAR(255)     | KCACertLabel        |//	
	//| SubjectKeyId		  | BINARY(255)	     | KSubjectKeyIdentifier |// This is Symbian subjectkey id
	//| ActualSubjectKeyId    | BINARY(20)	     | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
	//| SubjectName			  | VARCHAR(255)     | KSubjectName        |//	
	//| IssuerName			  | VARCHAR(255)     | KIssuerName        |//	
	//| SerialNumber		  | VARCHAR(255)     | KSerialNumber        |//	
	//| Thumbprint			  | BINARY(64)	     | KThumbprint        |//	
	//////////////////////////////////////////////////////////////////////////////////////////////////////	

	_LIT(KSQLCreateTable3, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d), \
		 %S BINARY(%d), \
		 %S BINARY(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S BINARY(%d))");

	sqlStatement.Format(KSQLCreateTable3,
		&KTlsAllowedCACertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);
		
	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}

	// Create table for allowed cipher suites

	//// NAME ///////////////// TYPE ////////////// Constant ///////////
	//| ServiceType			  | UNSIGNED INTEGER | KServiceType        |//
	//| ServiceIndex		  | UNSIGNED INTEGER | KServiceIndex       |//
	//| TunnelingTypeVendorId | UNSIGNED INTEGER | KTunnelingTypeVendorId    |//
	//| TunnelingType		  | UNSIGNED INTEGER | KTunnelingType		|//
	//| CipherSuite			  | UNSIGNED INTEGER | KCipherSuite        |//	
	//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable4, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER)");

	sqlStatement.Format(KSQLCreateTable4,
		&KTlsAllowedCipherSuitesDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType, 
		&KCipherSuite);

	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}
	
	// 4. Check if database table contains a row for this service type and id 
		
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	
	sqlStatement.Format(KSQLQueryRow,
		&cf_str_EAP_TLS_PEAP_cipher_suite_literal,
		&KTlsDatabaseTableName, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());	
	
	RDbView view;
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	// View must be closed when no longer needed
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	// 5. If row is not found then add it
	
	TInt rows = view.CountL();
	CleanupStack::PopAndDestroy(); // view
	if (rows == 0)
	{
		_LIT(KSQLInsert, "SELECT * FROM %S");
		sqlStatement.Format(KSQLInsert, &KTlsDatabaseTableName);	

		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly));
		CleanupClosePushL(view);
		view.InsertL();

		// Get column set so we get the correct column numbers
		CDbColSet* colSet = view.ColSetL();
		CleanupStack::PushL(colSet);

		// Set the default values. The other three tables (certs, ca certs & cipher suites) are empty by default.
		view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt>(aIndexType));
		view.SetColL(colSet->ColNo(KServiceIndex), aIndex);
		view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal), default_EAP_TLS_PEAP_use_manual_realm);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal), default_EAP_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal), default_EAP_TLS_PEAP_use_manual_username);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal), default_EAP_username);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_cipher_suite_literal), default_EAP_TLS_PEAP_cipher_suite);
		
		view.SetColL(colSet->ColNo(cf_str_TLS_server_authenticates_client_policy_in_client_literal), default_EAP_TLS_server_authenticates_client);
		
		view.SetColL(colSet->ColNo(KCACertLabel), default_CA_cert_label);
		view.SetColL(colSet->ColNo(KClientCertLabel), default_client_cert_label);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal), default_EAP_TLS_PEAP_verify_certificate_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_max_session_validity_time_literal), default_MaxSessionTime);		
		
		view.SetColL(colSet->ColNo(KTLSLastFullAuthTime), default_FullAuthTime);		

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal), default_EAP_TLS_PEAP_TTLS_Privacy);		

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal), default_EAP_TLS_PEAP_use_automatic_ca_certificate);

		view.PutL();

		CleanupStack::PopAndDestroy( colSet );
		CleanupStack::PopAndDestroy( &view );
		
		// Add default disabled cipher suites
		_LIT(KSQLInsert2, "SELECT * FROM %S");
		sqlStatement.Format(KSQLInsert2, &KTlsAllowedCipherSuitesDatabaseTableName);
		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly));
		CleanupClosePushL(view);

		// Get column set so we get the correct column numbers
		colSet = view.ColSetL();
		CleanupStack::PushL(colSet);

		TInt i(0);
		while (default_allowed_cipher_suites[i] != 0)
		{
			view.InsertL();
			view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt>(aIndexType));
			view.SetColL(colSet->ColNo(KServiceIndex), aIndex);			
			view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
			view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
			view.SetColL(colSet->ColNo(KCipherSuite), default_allowed_cipher_suites[i]);
			view.PutL();
			i++;
		}
		
		CleanupStack::PopAndDestroy( colSet ); // Delete colSet.		
		CleanupStack::PopAndDestroy( &view ); // Close view.
	}
	
	// 6. Do the altering of tables here. 
	//    Add columns to existing certificate DB tables for Serial number, Issuer name etc. 

	TBufC<KDbMaxColName> tableName;

	// For the table _allowed_ USER certificates
	tableName = KTlsAllowedUserCertsDatabaseTableName;	
	AddExtraCertColumnsL(aDatabase,tableName);
	
	// For the table _allowed_ CA certificates	
	tableName = KTlsAllowedCACertsDatabaseTableName;	
	AddExtraCertColumnsL(aDatabase,tableName);
	

	aDatabase.Compact();

	CleanupStack::PopAndDestroy( buf );
	CleanupStack::Pop( &aDatabase );
	CleanupStack::Pop( &aFileServerSession );
}

// ---------------------------------------------------------

void EapTlsPeapUtils::OpenPeapDatabaseL(
	RDbNamedDatabase& aDatabase,
	RFs& aFileServerSession,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenPeapDatabaseL(): - Start - aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::OpenPeapDatabaseL()\n"));

	// 1. Open/create a database	

	TInt error(KErrNone);
	TFileName aPrivateDatabasePathName;

	EapPluginTools::CreateDatabaseLC(
		aDatabase,
		aFileServerSession,
		error,
		KPeapDatabaseName,
		aPrivateDatabasePathName);

	if(error == KErrNone)
	{
		aDatabase.Close();
	}
	else if (error != KErrAlreadyExists) 
	{
		User::LeaveIfError(error);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenPeapDatabaseL(): - calls aDatabase.Open()\n")));

	error = aDatabase.Open(aFileServerSession, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenPeapDatabaseL(): - Opened private DB for EAP-PEAP. error=%d\n"), error));

	User::LeaveIfError(error);

	// 2. Create the eappeap table to database (ignore error if exists)
	
	// Table columns:
	//// NAME /////////////////////////////////////////////// TYPE ////////////// Constant ///////////////////
	//| ServiceType										| UNSIGNED INTEGER 	| KServiceType        |//
	//| ServiceIndex									| UNSIGNED INTEGER 	| KServiceIndex       |//
	//| TunnelingTypeVendorId							| UNSIGNED INTEGER  | KTunnelingTypeVendorId    |//
	//| TunnelingType									| UNSIGNED INTEGER 	| KTunnelingType		|//
	//| EAP_TLS_PEAP_use_manual_realm					| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_use_manual_realm_literal      |//
	//| EAP_TLS_PEAP_manual_realm						| VARCHAR(255)     	| cf_str_EAP_TLS_PEAP_manual_realm_literal				|//
	//| EAP_TLS_PEAP_use_manual_username				| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_use_manual_username_literal   |//
	//| EAP_TLS_PEAP_manual_username					| VARCHAR(255)     	| cf_str_EAP_TLS_PEAP_manual_username_literal			|//
	//| EAP_TLS_PEAP_max_count_of_session_resumes		| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_max_count_of_session_resumes_literal    |//
	//| EAP_TLS_PEAP_cipher_suite						| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_cipher_suite_literal	   |//
	//| EAP_TLS_PEAP_used_PEAP_version					| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_used_PEAP_version_literal		    |//
	//| EAP_TLS_PEAP_accepted_PEAP_versions				| BINARY(12)	    | cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal|//
	//| PEAP_accepted_tunneled_client_types			   	| VARBINARY(240) 	| cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal      |//
	//| PEAP_unaccepted_tunneled_client_types		   	| VARBINARY(240) 	| cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal      |//
	//| EAP_TLS_server_authenticates_client		        | UNSIGNED INTEGER 	| cf_str_TLS_server_authenticates_client_policy_in_client_literal|//
	//| CA_cert_label								    | VARCHAR(255)     	| KCACertLabel	   |//
	//| client_cert_label							    | VARCHAR(255)     	| KClientCertLabel	   |//
	//| EAP_TLS_PEAP_saved_session_id				    | BINARY(32)       	| cf_str_EAP_TLS_PEAP_saved_session_id_literal		   |//
	//| EAP_TLS_PEAP_saved_master_secret			    | BINARY(48)       	| cf_str_EAP_TLS_PEAP_saved_master_secret_literal	   |//
	//| EAP_TLS_PEAP_saved_cipher_suite				    | UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_saved_cipher_suite_literal   |//
	//| EAP_TLS_PEAP_verify_certificate_realm			| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal		   |//
	//| EAP_PEAP_max_session_validity_time				| BIGINT	   		| cf_str_EAP_PEAP_max_session_validity_time_literal   |//
	//| EAP_PEAP_last_full_authentication_time			| BIGINT	   		| KPEAPLastFullAuthTime	   	|//	
	//| EAP_TLS_PEAP_use_identity_privacy	    		| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_use_identity_privacy_literal|//
	//| EAP_TLS_PEAP_use_automatic_ca_certificate		| UNSIGNED INTEGER  | cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal|//
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////	

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Table creation is divided into two parts because otherwise the SQL string would get too long
	_LIT(KSQLCreateTable1, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d),     \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d),     \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S BINARY(%d),		  \
		 %S VARBINARY(%d),	  \
		 %S VARBINARY(%d),	  \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d),	  \
		 %S VARCHAR(%d),     \
		 %S BINARY(%d),		  \
		 %S BINARY(%d),		  \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S BIGINT, \
		 %S BIGINT, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER)");

	sqlStatement.Format(KSQLCreateTable1,
		&KPeapDatabaseTableName,
		&KServiceType,
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType,
		&cf_str_EAP_TLS_PEAP_use_manual_realm_literal,
		&cf_str_EAP_TLS_PEAP_manual_realm_literal, KMaxRealmLengthInDB,
		&cf_str_EAP_TLS_PEAP_use_manual_username_literal,
		&cf_str_EAP_TLS_PEAP_manual_username_literal, KMaxUsernameLengthInDB,
		&cf_str_EAP_TLS_PEAP_cipher_suite_literal,
		&cf_str_EAP_TLS_PEAP_used_PEAP_version_literal,
		&cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal, KMaxPEAPVersionsStringLengthInDB,
		&cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, KMaxTunneledTypeStringLengthInDB,
		&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal, KMaxTunneledTypeStringLengthInDB,
		&cf_str_TLS_server_authenticates_client_policy_in_client_literal,
		&KCACertLabel, KMaxCertLabelLengthInDB,
		&KClientCertLabel, KMaxCertLabelLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_session_id_literal, KMaxSessionIdLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_master_secret_literal,  KMaxMasterSecretLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_cipher_suite_literal,
		&cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal,
		&cf_str_EAP_PEAP_max_session_validity_time_literal,
		&KPEAPLastFullAuthTime,	
		&cf_str_EAP_TLS_PEAP_use_identity_privacy_literal,
		&cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal);		
					
	error = aDatabase.Execute(sqlStatement);
	if (error == KErrAlreadyExists)
		{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenPeapDatabaseL - Alter Table error=%d\n"), error) );
		_LIT( KColumnDef, "UNSIGNED INTEGER" );
		AlterTableL( aDatabase, EAddColumn , KPeapDatabaseTableName,
				cf_str_EAP_TLS_PEAP_use_identity_privacy_literal, KColumnDef);
		}
		else if (error != KErrNone)
			{
			User::Leave(error);
			}

	// Create table for _allowed_ user certificates
	
	//// NAME ////////////////// TYPE ////////////// Constant ///////////
	//| ServiceType				| UNSIGNED INTEGER | KServiceType        |//
	//| ServiceIndex			| UNSIGNED INTEGER | KServiceIndex       |//
	//| TunnelingTypeVendorId	| UNSIGNED INTEGER | KTunnelingTypeVendorId    |//
	//| TunnelingType			| UNSIGNED INTEGER | KTunnelingType		|//
	//| CertLabel				| VARCHAR(255)     | KCACertLabel        |//	
	//| SubjectKeyId			| BINARY(20)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
	//| ActualSubjectKeyId		| BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
	//| SubjectName				| VARCHAR(255)     | KSubjectName        |//	
	//| IssuerName				| VARCHAR(255)     | KIssuerName        |//	
	//| SerialNumber			| VARCHAR(255)     | KSerialNumber        |//	
	//| Thumbprint				| BINARY(64)	   | KThumbprint        |//	
	//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable2, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d), \
		 %S BINARY(%d), \
		 %S BINARY(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S BINARY(%d))");

	sqlStatement.Format(KSQLCreateTable2,
		&KPeapAllowedUserCertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex, 
		&KTunnelingTypeVendorId,
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);
		
	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}	

	// Create table for _allowed_ CA certs

	//// NAME ////////////////// TYPE ////////////// Constant ///////////
	//| ServiceType				| UNSIGNED INTEGER | KServiceType        |//
	//| ServiceIndex			| UNSIGNED INTEGER | KServiceIndex       |//
	//| TunnelingTypeVendorId	| UNSIGNED INTEGER | KTunnelingTypeVendorId    |//
	//| TunnelingType			| UNSIGNED INTEGER | KTunnelingType		|//
	//| CACertLabel				| VARCHAR(255)     | KCACertLabel        |//	
	//| SubjectKeyId			| BINARY(20)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
	//| ActualSubjectKeyId		| BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
	//| SubjectName				| VARCHAR(255)     | KSubjectName        |//	
	//| IssuerName				| VARCHAR(255)     | KIssuerName        |//	
	//| SerialNumber			| VARCHAR(255)     | KSerialNumber        |//	
	//| Thumbprint				| BINARY(64)	   | KThumbprint        |//	
	//////////////////////////////////////////////////////////////////////////////////////////////////////	

	_LIT(KSQLCreateTable3, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d), \
		 %S BINARY(%d), \
		 %S BINARY(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S BINARY(%d))");
											 											 
	sqlStatement.Format(KSQLCreateTable3,
		&KPeapAllowedCACertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);
		
	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}

	// Create table for _allowed_ cipher suites

	//// NAME ///////////////////// TYPE ////////////// Constant ///////////
	//| ServiceType				| UNSIGNED INTEGER | KServiceType        |//
	//| ServiceIndex			| UNSIGNED INTEGER | KServiceIndex       |//
	//| TunnelingTypeVendorId	| UNSIGNED INTEGER | KTunnelingTypeVendorId    |//
	//| TunnelingType			| UNSIGNED INTEGER | KTunnelingType		|//
	//| CipherSuite				| UNSIGNED INTEGER | KCipherSuite        |//	
	//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable4, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER)");

	sqlStatement.Format(KSQLCreateTable4,
		&KPeapAllowedCipherSuitesDatabaseTableName, 
		&KServiceType,
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType,
		&KCipherSuite);

	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}

	// 4. Check if database table contains a row for this service type and id 
	 	
	_LIT(KSQLQueryRow, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	
	sqlStatement.Format(KSQLQueryRow,
		&KPeapDatabaseTableName, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());

	RDbView view;
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	// View must be closed when no longer needed
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());

	// 5. If row is not found then add it

	TInt rows = view.CountL();
	CleanupStack::PopAndDestroy(); // view
	if (rows == 0)
	{
		_LIT(KSQLInsert, "SELECT * FROM %S");
		sqlStatement.Format(KSQLInsert, &KPeapDatabaseTableName);	

		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly));
		CleanupClosePushL(view);
		view.InsertL();

		// Get column set so we get the correct column numbers
		CDbColSet* colSet = view.ColSetL();
		CleanupStack::PushL(colSet);

		// Set the default values. The other three tables (certs, ca certs & cipher suites) are empty by default.
		view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt>(aIndexType));
		view.SetColL(colSet->ColNo(KServiceIndex), aIndex);
		view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal), default_EAP_TLS_PEAP_use_manual_realm);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal), default_EAP_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal), default_EAP_TLS_PEAP_use_manual_username);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal), default_EAP_username);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_cipher_suite_literal), default_EAP_TLS_PEAP_cipher_suite);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_used_PEAP_version_literal), default_EAP_TLS_PEAP_used_PEAP_version);

		TInt i(0);

		while (default_EAP_TLS_PEAP_accepted_PEAP_versions[i] != -1)
		{
			i++;
		}
		
		TBuf8<KMaxPEAPVersionsStringLengthInDB> tmp;
		
		tmp.Copy(reinterpret_cast<const TUint8 *> (default_EAP_TLS_PEAP_accepted_PEAP_versions), i * sizeof(TInt));
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal), tmp);

		view.SetColL(colSet->ColNo(cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal), default_PEAP_tunneled_types);
		view.SetColL(colSet->ColNo(cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal), default_PEAP_tunneled_types);
		
		view.SetColL(colSet->ColNo(cf_str_TLS_server_authenticates_client_policy_in_client_literal), default_EAP_PEAP_TTLS_server_authenticates_client);
		view.SetColL(colSet->ColNo(KCACertLabel), default_CA_cert_label);
		view.SetColL(colSet->ColNo(KClientCertLabel), default_client_cert_label);	

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal), default_EAP_TLS_PEAP_verify_certificate_realm);

		view.SetColL(colSet->ColNo(cf_str_EAP_PEAP_max_session_validity_time_literal), default_MaxSessionTime);
		
		view.SetColL(colSet->ColNo(KPEAPLastFullAuthTime), default_FullAuthTime);

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal), default_EAP_TLS_PEAP_TTLS_Privacy);						

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal), default_EAP_TLS_PEAP_use_automatic_ca_certificate);

		view.PutL();
		
		CleanupStack::PopAndDestroy(colSet); 
		CleanupStack::PopAndDestroy( &view ); // Close view.

		// Add default disabled cipher suites
		_LIT(KSQLInsert2, "SELECT * FROM %S");
		sqlStatement.Format(KSQLInsert2, &KPeapAllowedCipherSuitesDatabaseTableName);
		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly));
		CleanupClosePushL(view);

		// Get column set so we get the correct column numbers
		colSet = view.ColSetL();
		CleanupStack::PushL(colSet);

		i = 0;
		while (default_allowed_cipher_suites[i] != 0)
		{
			view.InsertL();
			view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt>(aIndexType));
			view.SetColL(colSet->ColNo(KServiceIndex), aIndex);
			view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
			view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
			view.SetColL(colSet->ColNo(KCipherSuite), default_allowed_cipher_suites[i]);
			view.PutL();
			i++;
		}
		
		CleanupStack::PopAndDestroy( colSet );
		CleanupStack::PopAndDestroy( &view );
	} 
	
	// 6. Do the altering of tables here. 
	//    Add columns to existing certificate DB tables for Serial number, Issuer name etc. 

	TBufC<KDbMaxColName> tableName;

	// For the table _allowed_ USER certificates
	tableName = KPeapAllowedUserCertsDatabaseTableName;	
	AddExtraCertColumnsL(aDatabase,tableName);
	
	// For the table _allowed_ CA certificates	
	tableName = KPeapAllowedCACertsDatabaseTableName;	
	AddExtraCertColumnsL(aDatabase,tableName);

	aDatabase.Compact();

	CleanupStack::PopAndDestroy( buf );
	CleanupStack::Pop( &aDatabase );
	CleanupStack::Pop( &aFileServerSession );
}

#if defined(USE_TTLS_EAP_TYPE)

// ---------------------------------------------------------
// EapTlsPeapUtils::OpenTtlsDatabaseL()
// ---------------------------------------------------------
//
void EapTlsPeapUtils::OpenTtlsDatabaseL(
	RDbNamedDatabase& aDatabase,
	RFs& aFileServerSession,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): - Start - aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::OpenTtlsDatabaseL()\n"));

	// 1. Open/create a database	

	TInt error(KErrNone);
	TFileName aPrivateDatabasePathName;

	EapPluginTools::CreateDatabaseLC(
		aDatabase,
		aFileServerSession,
		error,
		KTtlsDatabaseName,
		aPrivateDatabasePathName);

	if(error == KErrNone)
	{
		aDatabase.Close();
	}
	else if (error != KErrAlreadyExists) 
	{
		User::LeaveIfError(error);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): - calls aDatabase.Open()\n")));

	error = aDatabase.Open(aFileServerSession, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): - Opened private DB for EAP-TTLS. error=%d\n"), error));

	User::LeaveIfError(error);


	// 2. Create the eapttls table to database (ignore error if exists)
	
	// Table columns:
	//// NAME //////////////////////////////////////////// TYPE ////////////// Constant ///////////////////
	//| ServiceType									| UNSIGNED INTEGER 	| KServiceType        |//
	//| ServiceIndex								| UNSIGNED INTEGER 	| KServiceIndex       |//
	//| TunnelingTypeVendorId                       | UNSIGNED INTEGER  | KTunnelingTypeVendorId    |//
	//| TunnelingType								| UNSIGNED INTEGER 	| KTunnelingType		|//
	//| EAP_TLS_PEAP_use_manual_realm				| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_use_manual_realm_literal      |//
	//| EAP_TLS_PEAP_manual_realm					| VARCHAR(255)     	| cf_str_EAP_TLS_PEAP_manual_realm_literal				|//
	//| EAP_TLS_PEAP_use_manual_username			| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_use_manual_username_literal   |//
	//| EAP_TLS_PEAP_manual_username				| VARCHAR(255)     	| cf_str_EAP_TLS_PEAP_manual_username_literal			|//
	//| EAP_TLS_PEAP_cipher_suite					| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_cipher_suite_literal	   |//
	//| EAP_TLS_PEAP_used_PEAP_version				| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_used_PEAP_version_literal		    |//
	//| EAP_TLS_PEAP_accepted_PEAP_versions			| BINARY(12)	    | cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal|//
	//| PEAP_accepted_tunneled_client_types			| VARBINARY(240) 	| cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal      |//
	//| PEAP_unaccepted_tunneled_client_types		| VARBINARY(240) 	| cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal      |//
	//| EAP_TLS_server_authenticates_client		    | UNSIGNED INTEGER 	| cf_str_TLS_server_authenticates_client_policy_in_client_literal|//
	//| CA_cert_label								| VARCHAR(255)     	| KCACertLabel	   |//
	//| client_cert_label							| VARCHAR(255)     	| KClientCertLabel	   |//
	//| EAP_TLS_PEAP_saved_session_id				| BINARY(32)       	| cf_str_EAP_TLS_PEAP_saved_session_id_literal		   |//
	//| EAP_TLS_PEAP_saved_master_secret			| BINARY(48)       	| cf_str_EAP_TLS_PEAP_saved_master_secret_literal	   |//
	//| EAP_TLS_PEAP_saved_cipher_suite				| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_saved_cipher_suite_literal   |//
	//| EAP_TLS_PEAP_verify_certificate_realm		| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal		   |//
	//| EAP_TTLS_max_session_validity_time			| BIGINT	   		| cf_str_EAP_TTLS_max_session_validity_time_literal   |//
	//| EAP_TTLS_last_full_authentication_time		| BIGINT	   		| KTTLSLastFullAuthTime	   	|//	
	//| EAP_TLS_PEAP_use_identity_privacy			| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_use_identity_privacy_literal		   |//


	//| EAP_TLS_PEAP_ttls_pap_password_prompt               | UNSIGNED INTEGER  | cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal           |//
	//| EAP_TLS_PEAP_ttls_pap_username                      | VARCHAR(253)      | cf_str_EAP_TLS_PEAP_ttls_pap_username_literal                  |//
	//| EAP_TLS_PEAP_ttls_pap_password                      | VARCHAR(128)      | cf_str_EAP_TLS_PEAP_ttls_pap_password_literal                  |//
	//| EAP_TLS_PEAP_ttls_pap_max_session_validity_time		| BIGINT		   	| cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal |//
	//| EAP_TLS_PEAP_ttls_pap_last_full_authentication_time	| BIGINT		   	| KTTLSPAPLastFullAuthTime	                             |//

	//| EAP_TLS_PEAP_use_automatic_ca_certificate		| UNSIGNED INTEGER  | cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal|//

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Table creation is divided into two parts because otherwise the SQL string would get too long
	_LIT(KSQLCreateTable1, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d),     \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d),     \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S BINARY(%d),		  \
		 %S VARBINARY(%d),	  \
		 %S VARBINARY(%d),	  \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d),	  \
		 %S VARCHAR(%d),     \
		 %S BINARY(%d),		  \
		 %S BINARY(%d),		  \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S BIGINT, \
		 %S BIGINT, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
         %S BIGINT, \
         %S BIGINT)");

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): sqlStatement.Format(KSQLCreateTable1)\n")) );

    sqlStatement.Format( KSQLCreateTable1,
        &KTtlsDatabaseTableName,
        &KServiceType,
        &KServiceIndex,
		&KTunnelingTypeVendorId,
        &KTunnelingType,
        &cf_str_EAP_TLS_PEAP_use_manual_realm_literal,
        &cf_str_EAP_TLS_PEAP_manual_realm_literal, KMaxRealmLengthInDB,
        &cf_str_EAP_TLS_PEAP_use_manual_username_literal,
        &cf_str_EAP_TLS_PEAP_manual_username_literal, KMaxUsernameLengthInDB,
        &cf_str_EAP_TLS_PEAP_cipher_suite_literal,
        &cf_str_EAP_TLS_PEAP_used_PEAP_version_literal,
        &cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal, KMaxPEAPVersionsStringLengthInDB,
        &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, KMaxTunneledTypeStringLengthInDB,
        &cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,	KMaxTunneledTypeStringLengthInDB,	
        &cf_str_TLS_server_authenticates_client_policy_in_client_literal,
        &KCACertLabel, KMaxCertLabelLengthInDB,
        &KClientCertLabel, KMaxCertLabelLengthInDB,
        &cf_str_EAP_TLS_PEAP_saved_session_id_literal, KMaxSessionIdLengthInDB,
        &cf_str_EAP_TLS_PEAP_saved_master_secret_literal, KMaxMasterSecretLengthInDB,
        &cf_str_EAP_TLS_PEAP_saved_cipher_suite_literal,
        &cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal,
        &cf_str_EAP_TTLS_max_session_validity_time_literal,
        &KTTLSLastFullAuthTime,
		&cf_str_EAP_TLS_PEAP_use_identity_privacy_literal,		
        &cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal,
        &cf_str_EAP_TLS_PEAP_ttls_pap_username_literal, KMaxPapUserNameLengthInDb,
        &cf_str_EAP_TLS_PEAP_ttls_pap_password_literal, KMaxPapPasswordLengthInDb,
        &cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal,
        &KTTLSPAPLastFullAuthTime);	


	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): aDatabase.Execute()\n")) );

	error = aDatabase.Execute(sqlStatement);
	if (error == KErrNone)
		{
		// SQL command will be too long if this is included to KSQLCreateTable1.
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): OK, Alter Table error=%d\n"), error) );
		
		_LIT( KColumnDef6, "UNSIGNED INTEGER" );
		AlterTableL( aDatabase, EAddColumn , KTtlsDatabaseTableName,
				cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal, KColumnDef6);
		}
	else if (error == KErrAlreadyExists)
		{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): Alter Table error=%d\n"), error) );
		
		_LIT( KColumnDef, "UNSIGNED INTEGER" );
		AlterTableL( aDatabase, EAddColumn , KTtlsDatabaseTableName,
				cf_str_EAP_TLS_PEAP_use_identity_privacy_literal, KColumnDef);

		_LIT( KColumnDef1, "UNSIGNED INTEGER" );
		AlterTableL( aDatabase, EAddColumn , KTtlsDatabaseTableName,
				cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal, KColumnDef1);

        HBufC* buf1 = HBufC::NewLC(KMaxSqlQueryLength);
        TPtr sqlStatement = buf1->Des();
       
        _LIT(KSQLAlterTableForVar, "VARCHAR (%d)");                                          
    
        sqlStatement.Format(KSQLAlterTableForVar, KMaxPapUserNameLengthInDb);
 
		AlterTableL( aDatabase, EAddColumn , KTtlsDatabaseTableName,
				cf_str_EAP_TLS_PEAP_ttls_pap_username_literal, sqlStatement);

        sqlStatement.Format(KSQLAlterTableForVar, KMaxPapPasswordLengthInDb);
        
		AlterTableL( aDatabase, EAddColumn , KTtlsDatabaseTableName,
				cf_str_EAP_TLS_PEAP_ttls_pap_password_literal, sqlStatement);

		CleanupStack::PopAndDestroy(buf1);
		
		_LIT( KColumnDef4, "BIGINT" );
		AlterTableL( aDatabase, EAddColumn , KTtlsDatabaseTableName,
				cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal, KColumnDef4);
				
		_LIT( KColumnDef5, "BIGINT" );
		AlterTableL( aDatabase, EAddColumn , KTtlsDatabaseTableName,
				KTTLSPAPLastFullAuthTime, KColumnDef5);
				
		_LIT( KColumnDef6, "UNSIGNED INTEGER" );
		AlterTableL( aDatabase, EAddColumn , KTtlsDatabaseTableName,
				cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal, KColumnDef6);
				
		}
	else if (error != KErrNone)
		{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::OpenTtlsDatabaseL(): aDatabase.Execute() failed error=%d\n"), error) );
		
		User::Leave(error);
		}

	// Create table for _allowed_ user certificates
	
	//// NAME ////////////////// TYPE ////////////// Constant ///////////
	//| ServiceType		  		| UNSIGNED INTEGER | KServiceType        |//
	//| ServiceIndex			| UNSIGNED INTEGER | KServiceIndex       |//
	//| TunnelingTypeVendorId	| UNSIGNED INTEGER  | KTunnelingTypeVendorId    |//
	//| TunnelingType			| UNSIGNED INTEGER | KTunnelingType		|//
	//| CertLabel				| VARCHAR(255)     | KCACertLabel        |//	
	//| SubjectKeyId			| BINARY(20)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
	//| ActualSubjectKeyId		| BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
	//| SubjectName				| VARCHAR(255)     | KSubjectName        |//	
	//| IssuerName				| VARCHAR(255)     | KIssuerName        |//	
	//| SerialNumber			| VARCHAR(255)     | KSerialNumber        |//	
	//| Thumbprint				| BINARY(64)	   | KThumbprint        |//	
	//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable2, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d), \
		 %S BINARY(%d), \
		 %S BINARY(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S BINARY(%d))");

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): sqlStatement.Format(KSQLCreateTable2)\n")) );

	sqlStatement.Format(KSQLCreateTable2,
		&KTtlsAllowedUserCertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);
		
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): aDatabase.Execute()\n")) );

	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}	

	// Create table for _allowed_ CA certs

	//// NAME ////////////////// TYPE ////////////// Constant ///////////
	//| ServiceType				| UNSIGNED INTEGER | KServiceType        |//
	//| ServiceIndex			| UNSIGNED INTEGER | KServiceIndex       |//
	//| TunnelingTypeVendorId	| UNSIGNED INTEGER | KTunnelingTypeVendorId    |//
	//| TunnelingType			| UNSIGNED INTEGER | KTunnelingType		|//
	//| CACertLabel				| VARCHAR(255)     | KCACertLabel        |//	
	//| SubjectKeyId			| BINARY(20)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
	//| ActualSubjectKeyId		| BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
	//| SubjectName				| VARCHAR(255)     | KSubjectName        |//	
	//| IssuerName				| VARCHAR(255)     | KIssuerName        |//	
	//| SerialNumber			| VARCHAR(255)     | KSerialNumber        |//	
	//| Thumbprint				| BINARY(64)	   | KThumbprint        |//	
	//////////////////////////////////////////////////////////////////////////////////////////////////////	

	_LIT(KSQLCreateTable3, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d), \
		 %S BINARY(%d), \
		 %S BINARY(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S BINARY(%d))");
											 
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): sqlStatement.Format(KSQLCreateTable3)\n")) );

	sqlStatement.Format(KSQLCreateTable3,
		&KTtlsAllowedCACertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);
		
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): aDatabase.Execute()\n")) );

	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}

	// Create table for _allowed_ cipher suites

	//// NAME ///////////////// TYPE ////////////// Constant ///////////
	//| ServiceType				| UNSIGNED INTEGER | KServiceType        |//
	//| ServiceIndex			| UNSIGNED INTEGER | KServiceIndex       |//
	//| TunnelingTypeVendorId	| UNSIGNED INTEGER | KTunnelingTypeVendorId    |//
	//| TunnelingType			| UNSIGNED INTEGER | KTunnelingType		|//
	//| CipherSuite				| UNSIGNED INTEGER | KCipherSuite        |//	
	//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable4, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER)");

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): sqlStatement.Format(KSQLCreateTable4)\n")) );

	sqlStatement.Format(KSQLCreateTable4,
		&KTtlsAllowedCipherSuitesDatabaseTableName, 
		&KServiceType,
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType,
		&KCipherSuite);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): aDatabase.Execute()\n")) );

	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}

	// 4. Check if database table contains a row for this service type and id  	
	
	_LIT(KSQLQueryRow, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): sqlStatement.Format(KSQLQueryRow)\n")) );

	sqlStatement.Format(KSQLQueryRow,
		&KTtlsDatabaseTableName, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());	
			
	RDbView view;

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): view.Prepare()\n")) );

	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	// View must be closed when no longer needed
	CleanupClosePushL(view);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): view.EvaluateAll()\n")) );

	User::LeaveIfError(view.EvaluateAll());
	
	// 5. If row is not found then add it
	
	TInt rows = view.CountL();

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): view.CountL()=%d\n"),
		rows));

	CleanupStack::PopAndDestroy(); // view
	if (rows == 0)
	{
		_LIT(KSQLInsert, "SELECT * FROM %S");

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): sqlStatement.Format(KSQLInsert)\n")) );

		sqlStatement.Format(KSQLInsert, &KTtlsDatabaseTableName);	

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): view.Prepare()\n")) );

		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly));
		CleanupClosePushL(view);

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): view.InsertL()\n")) );

		view.InsertL();

		// Get column set so we get the correct column numbers
		CDbColSet* colSet = view.ColSetL();
		CleanupStack::PushL(colSet);

		// Set the default values. The other three tables (certs, ca certs & cipher suites) are empty by default.
		view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt>(aIndexType));
		view.SetColL(colSet->ColNo(KServiceIndex), aIndex);		
		view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal), default_EAP_TLS_PEAP_use_manual_realm);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal), default_EAP_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal), default_EAP_TLS_PEAP_use_manual_username);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal), default_EAP_username);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_cipher_suite_literal), default_EAP_TLS_PEAP_cipher_suite);

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_used_PEAP_version_literal), default_EAP_TLS_PEAP_used_PEAP_version);

		TInt i(0);

		while (default_EAP_TLS_PEAP_accepted_PEAP_versions[i] != -1)
		{
			i++;
		}
		
		TBuf8<KMaxPEAPVersionsStringLengthInDB> tmp;
		
		tmp.Copy(reinterpret_cast<const TUint8 *> (default_EAP_TLS_PEAP_accepted_PEAP_versions), i * sizeof(TInt));
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal), tmp);

		view.SetColL(colSet->ColNo(cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal), default_PEAP_tunneled_types);
		view.SetColL(colSet->ColNo(cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal), default_PEAP_tunneled_types);		
		
		view.SetColL(colSet->ColNo(cf_str_TLS_server_authenticates_client_policy_in_client_literal), default_EAP_PEAP_TTLS_server_authenticates_client);
		view.SetColL(colSet->ColNo(KCACertLabel), default_CA_cert_label);
		
		view.SetColL(colSet->ColNo(KClientCertLabel), default_client_cert_label);	

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal), default_EAP_TLS_PEAP_verify_certificate_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TTLS_max_session_validity_time_literal), default_MaxSessionTime);
		
		view.SetColL(colSet->ColNo(KTTLSLastFullAuthTime), default_FullAuthTime);				

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal), default_EAP_TLS_PEAP_TTLS_Privacy);


		view.SetColL( colSet->ColNo(
			cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal ),
			KDefaultPapPasswordPrompt );
		
		view.SetColL( colSet->ColNo(
			cf_str_EAP_TLS_PEAP_ttls_pap_username_literal ),
			KDefaultPapUserName );
		
		view.SetColL( colSet->ColNo(
			cf_str_EAP_TLS_PEAP_ttls_pap_password_literal ),
			KDefaultPapPassword );
		
		view.SetColL( colSet->ColNo(
			cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal ),
			KDefaultMaxPapSessionTime );
		
		view.SetColL(
			colSet->ColNo( KTTLSPAPLastFullAuthTime ),
			KDefaultFullPapAuthTime );		

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): view.SetColL(cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal)\n")) );

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal), default_EAP_TLS_PEAP_use_automatic_ca_certificate);
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): view.PutL()\n")) );

		view.PutL();
		
		CleanupStack::PopAndDestroy(colSet); 
		CleanupStack::PopAndDestroy( &view );

		// Add default disabled cipher suites
		_LIT(KSQLInsert2, "SELECT * FROM %S");

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): sqlStatement.Format(KSQLInsert2)\n")) );

		sqlStatement.Format(KSQLInsert2, &KTtlsAllowedCipherSuitesDatabaseTableName);

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): view.Prepare()\n")) );

		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly));
		CleanupClosePushL(view);

		// Get column set so we get the correct column numbers
		colSet = view.ColSetL();
		CleanupStack::PushL(colSet);

		i = 0;
		while (default_allowed_cipher_suites[i] != 0)
		{
			view.InsertL();
			view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt>(aIndexType));
			view.SetColL(colSet->ColNo(KServiceIndex), aIndex);		
			view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
			view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
			view.SetColL(colSet->ColNo(KCipherSuite), default_allowed_cipher_suites[i]);
			view.PutL();
			i++;
		}
		
		CleanupStack::PopAndDestroy( colSet );
		CleanupStack::PopAndDestroy( &view );
	}
	 
	// 6. Do the altering of tables here. 
	//    Add columns to existing certificate DB tables for Serial number, Issuer name etc. 

	TBufC<KDbMaxColName> tableName;

	// For the table _allowed_ USER certificates
	tableName = KTtlsAllowedUserCertsDatabaseTableName;	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): AddExtraCertColumnsL()\n")) );
	AddExtraCertColumnsL(aDatabase,tableName);
	
	// For the table _allowed_ CA certificates	
	tableName = KTtlsAllowedCACertsDatabaseTableName;	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): AddExtraCertColumnsL()\n")) );
	AddExtraCertColumnsL(aDatabase,tableName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL(): aDatabase.Compact()\n")) );
	aDatabase.Compact();

	CleanupStack::PopAndDestroy( buf );
	CleanupStack::Pop( &aDatabase );
	CleanupStack::Pop( &aFileServerSession );

} // EapTlsPeapUtils::OpenTtlsDatabaseL()

#endif // #if defined(USE_TTLS_EAP_TYPE)

#if defined(USE_FAST_EAP_TYPE)

// ---------------------------------------------------------
// EapTlsPeapUtils::OpenFastDatabaseL()
// ---------------------------------------------------------
//
void EapTlsPeapUtils::OpenFastDatabaseL(
	RDbNamedDatabase& aDatabase,
	RFs& aFileServerSession,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL(): - Start - aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::OpenFastDatabaseL()\n"));

	// 1. Open/create a database	

	TInt error(KErrNone);
	TFileName aPrivateDatabasePathName;

	EapPluginTools::CreateDatabaseLC(
		aDatabase,
		aFileServerSession,
		error,
		KFastDatabaseName,
		aPrivateDatabasePathName);

	if(error == KErrNone)
	{
		aDatabase.Close();
	}
	else if (error != KErrAlreadyExists) 
	{
		User::LeaveIfError(error);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenFastDatabaseL(): - calls aDatabase.Open()\n")));

	error = aDatabase.Open(aFileServerSession, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenFastDatabaseL(): - Opened private DB for EAP-FAST. error=%d\n"), error));

	User::LeaveIfError(error);

	// 2. Create the eapfast tables to database (ignore error if exists)
	
	// Table 1: Create table for general settings of EAP-FAST.
	
	// Table columns:
	//// NAME //////////////////////////////////////////// TYPE ////////////// Constant ///////////////////
	//| ServiceType									| UNSIGNED INTEGER 	| KServiceType        |//
	//| ServiceIndex								| UNSIGNED INTEGER 	| KServiceIndex       |//
	//| TunnelingTypeVendorId                       | UNSIGNED INTEGER  | KTunnelingTypeVendorId    |//
	//| TunnelingType								| UNSIGNED INTEGER 	| KTunnelingType		|//
	//| EAP_TLS_PEAP_use_manual_realm				| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_use_manual_realm_literal      |//
	//| EAP_TLS_PEAP_manual_realm					| VARCHAR(255)     	| cf_str_EAP_TLS_PEAP_manual_realm_literal				|//
	//| EAP_TLS_PEAP_use_manual_username			| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_use_manual_username_literal   |//
	//| EAP_TLS_PEAP_manual_username				| VARCHAR(255)     	| cf_str_EAP_TLS_PEAP_manual_username_literal			|//
	//| EAP_TLS_PEAP_cipher_suite					| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_cipher_suite_literal	   |//
	//| EAP_TLS_PEAP_used_PEAP_version				| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_used_PEAP_version_literal		    |//
	//| EAP_TLS_PEAP_accepted_PEAP_versions			| BINARY(12)	    | cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal|//
	//| PEAP_accepted_tunneled_client_types			| VARBINARY(240) 	| cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal      |//
	//| PEAP_unaccepted_tunneled_client_types		| VARBINARY(240) 	| cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal      |//
	//| EAP_TLS_server_authenticates_client		    | UNSIGNED INTEGER 	| cf_str_TLS_server_authenticates_client_policy_in_client_literal|//
	//| EAP_TLS_PEAP_saved_session_id				| BINARY(32)       	| cf_str_EAP_TLS_PEAP_saved_session_id_literal		   |//
	//| EAP_TLS_PEAP_saved_master_secret			| BINARY(48)       	| cf_str_EAP_TLS_PEAP_saved_master_secret_literal	   |//
	//| EAP_TLS_PEAP_saved_cipher_suite				| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_saved_cipher_suite_literal   |//
	//| EAP_TLS_PEAP_verify_certificate_realm		| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal		   |//
	//| EAP_FAST_max_session_validity_time			| BIGINT	   		| cf_str_EAP_FAST_max_session_validity_time_literal   |//
	//| EAP_FAST_last_full_authentication_time		| BIGINT	   		| KFASTLastFullAuthTime	   	|//	
	//| EAP_TLS_PEAP_use_identity_privacy			| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_use_identity_privacy_literal		   |//
	//| EAP_TLS_PEAP_use_automatic_ca_certificate	| UNSIGNED INTEGER  | cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal|//
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////	

	/** moved to PAC store db, because time is the same for all IAPs **/	
	//| EAP_FAST_last_password_identity_time	| BIGINT	   		| KFASTLastPasswordIdentityTime	   	|//	
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////		
	
	
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL - Creating the tables for EAP-FAST\n")));
	
	_LIT(KSQLCreateTable1, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d),     \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d),     \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S BINARY(%d),		  \
		 %S VARBINARY(%d),	  \
		 %S VARBINARY(%d),	  \
		 %S UNSIGNED INTEGER, \
		 %S BINARY(%d),		  \
		 %S BINARY(%d),		  \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S BIGINT, \
		 %S BIGINT, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER)");

	sqlStatement.Format(KSQLCreateTable1,
		&KFastGeneralSettingsDBTableName,
		&KServiceType,
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType,
		&cf_str_EAP_TLS_PEAP_use_manual_realm_literal,
		&cf_str_EAP_TLS_PEAP_manual_realm_literal, KMaxRealmLengthInDB,
		&cf_str_EAP_TLS_PEAP_use_manual_username_literal,
		&cf_str_EAP_TLS_PEAP_manual_username_literal, KMaxUsernameLengthInDB,
		&cf_str_EAP_TLS_PEAP_cipher_suite_literal,
		&cf_str_EAP_TLS_PEAP_used_PEAP_version_literal,
		&cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal, KMaxPEAPVersionsStringLengthInDB,
		&cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, KMaxTunneledTypeStringLengthInDB,
		&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,	KMaxTunneledTypeStringLengthInDB,	
		&cf_str_TLS_server_authenticates_client_policy_in_client_literal,
		&cf_str_EAP_TLS_PEAP_saved_session_id_literal, KMaxSessionIdLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_master_secret_literal, KMaxMasterSecretLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_cipher_suite_literal,
		&cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal,
		&cf_str_EAP_FAST_max_session_validity_time_literal,
		&KFASTLastFullAuthTime,
		&cf_str_EAP_TLS_PEAP_use_identity_privacy_literal,
		&cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal);

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL - SQL query formated OK\n")));
	
	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL Created General settings table\n")));

	// Table 2: Create table for Special settings of EAP-FAST.
	
	// Table columns:
	//// NAME //////////////////////////////////////////// TYPE ////////////// Constant ///////////////////
	//| ServiceType									| UNSIGNED INTEGER 	| KServiceType        |//
	//| ServiceIndex								| UNSIGNED INTEGER 	| KServiceIndex       |//
	//| TunnelingTypeVendorId                       | UNSIGNED INTEGER  | KTunnelingTypeVendorId    |//
	//| TunnelingType								| UNSIGNED INTEGER 	| KTunnelingType		|//
	//| EAP_FAST_allow_server_authenticated_provisioning_mode| UNSIGNED INTEGER	| cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal	   	|//	
	//| EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP| UNSIGNED INTEGER	| cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal	   	|//	
	//| EAP_FAST_Warn_ADHP_No_PAC					| UNSIGNED INTEGER	| KFASTWarnADHPNoPAC|//
	//| EAP_FAST_Warn_ADHP_No_Matching_PAC			| UNSIGNED INTEGER	| KFASTWarnADHPNoMatchingPAC|//	
	//| EAP_FAST_Warn_Not_Default_Server			| UNSIGNED INTEGER	| KFASTWarnNotDefaultServer|//	
	//| EAP_FAST_PAC_Group_Import_Reference_Collection| VARCHAR(255)	| KFASTPACGroupImportReferenceCollection	   	|//	
	//| EAP_FAST_PAC_Group_DB_Reference_Collection	| BINARY(255)		| KFASTPACGroupDBReferenceCollection	   	|//		
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////	

	
	_LIT(KSQLCreateTable2, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d),     \
		 %S BINARY(%d)		  )");
											 
	sqlStatement.Format(KSQLCreateTable2,
		&KFastSpecialSettingsDBTableName,
		&KServiceType,
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType,
		&cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal,
		&cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal,
		&KFASTWarnADHPNoPAC,
		&KFASTWarnADHPNoMatchingPAC,
		&KFASTWarnNotDefaultServer,
		&KFASTPACGroupImportReferenceCollection, KMaxPACGroupRefCollectionLengthInDB,
		&KFASTPACGroupDBReferenceCollection, KMaxPACGroupRefCollectionLengthInDB);
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL - SQL query formated OK\n")));
	
	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL Created Specific settings table\n")));
	
	// Table 3: Create table for _allowed_ user certificates
	
	//// NAME ////////////////// TYPE ////////////// Constant ///////////
	//| ServiceType		  		| UNSIGNED INTEGER | KServiceType        |//
	//| ServiceIndex			| UNSIGNED INTEGER | KServiceIndex       |//
	//| TunnelingTypeVendorId	| UNSIGNED INTEGER  | KTunnelingTypeVendorId    |//
	//| TunnelingType			| UNSIGNED INTEGER | KTunnelingType		|//
	//| CertLabel				| VARCHAR(255)     | KCACertLabel        |//	
	//| SubjectKeyId			| BINARY(20)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
	//| ActualSubjectKeyId		| BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
	//| SubjectName				| VARCHAR(255)     | KSubjectName        |//	
	//| IssuerName				| VARCHAR(255)     | KIssuerName        |//	
	//| SerialNumber			| VARCHAR(255)     | KSerialNumber        |//	
	//| Thumbprint				| BINARY(64)	   | KThumbprint        |//	
	//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable3, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d), \
		 %S BINARY(%d), \
		 %S BINARY(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S BINARY(%d))");											 
											 
	sqlStatement.Format(KSQLCreateTable3,
		&KFastAllowedUserCertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL - SQL query formated OK\n")));
	
	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}	

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL Created User certificates table\n")));
	
	// Table 4: Create table for _allowed_ CA certs

	//// NAME ////////////////// TYPE ////////////// Constant ///////////
	//| ServiceType				| UNSIGNED INTEGER | KServiceType        |//
	//| ServiceIndex			| UNSIGNED INTEGER | KServiceIndex       |//
	//| TunnelingTypeVendorId	| UNSIGNED INTEGER  | KTunnelingTypeVendorId    |//
	//| TunnelingType			| UNSIGNED INTEGER | KTunnelingType		|//
	//| CACertLabel				| VARCHAR(255)     | KCACertLabel        |//	
	//| SubjectKeyId			| BINARY(20)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
	//| ActualSubjectKeyId		| BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
	//| SubjectName				| VARCHAR(255)     | KSubjectName        |//	
	//| IssuerName				| VARCHAR(255)     | KIssuerName        |//	
	//| SerialNumber			| VARCHAR(255)     | KSerialNumber        |//	
	//| Thumbprint				| BINARY(64)	   | KThumbprint        |//	
	//////////////////////////////////////////////////////////////////////////////////////////////////////	

	_LIT(KSQLCreateTable4, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(%d), \
		 %S BINARY(%d), \
		 %S BINARY(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S VARCHAR(%d), \
		 %S BINARY(%d))");
											 
	sqlStatement.Format(KSQLCreateTable4,
		&KFastAllowedCACertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL - SQL query formated OK\n")));
		
	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL Created CA certificates table\n")));
	
	// Table 5: Create table for _allowed_ cipher suites

	//// NAME ///////////////// TYPE ////////////// Constant ///////////
	//| ServiceType				| UNSIGNED INTEGER | KServiceType        |//
	//| ServiceIndex			| UNSIGNED INTEGER | KServiceIndex       |//
	//| TunnelingTypeVendorId	| UNSIGNED INTEGER  | KTunnelingTypeVendorId    |//
	//| TunnelingType			| UNSIGNED INTEGER | KTunnelingType		|//
	//| CipherSuite				| UNSIGNED INTEGER | KCipherSuite        |//	
	//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable5, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER)");

	sqlStatement.Format(KSQLCreateTable5,
		&KFastAllowedCipherSuitesDatabaseTableName, 
		&KServiceType,
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType,
		&KCipherSuite);

	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL Created Cipher suites table\n")));
	
	// 4. Check if database table contains a row for this service type and id  	
	
	_LIT(KSQLQueryRow, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQLQueryRow,
		&KFastGeneralSettingsDBTableName, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());	
			
	RDbView view;
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	// View must be closed when no longer needed
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	// 5. If a row is not found then add it
	
	TInt rows = view.CountL();
	CleanupStack::PopAndDestroy(); // view
	if (rows == 0)
	{
		// This is to add default values to the General settings table.
		_LIT(KSQLInsert, "SELECT * FROM %S");
		sqlStatement.Format(KSQLInsert, &KFastGeneralSettingsDBTableName);	

		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly));
		CleanupClosePushL(view);
		view.InsertL();

		// Get column set so we get the correct column numbers
		CDbColSet* colSet = view.ColSetL();
		CleanupStack::PushL(colSet);

		// Set the default values. The other three tables (certs, ca certs & cipher suites) are empty by default.
		view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt>(aIndexType));
		view.SetColL(colSet->ColNo(KServiceIndex), aIndex);		
		view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal), default_EAP_TLS_PEAP_use_manual_realm);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal), default_EAP_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal), default_EAP_TLS_PEAP_use_manual_username);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal), default_EAP_username);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_cipher_suite_literal), default_EAP_TLS_PEAP_cipher_suite);

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_used_PEAP_version_literal), default_EAP_TLS_PEAP_used_PEAP_version);

		TInt i(0);

		while (default_EAP_TLS_PEAP_accepted_PEAP_versions[i] != -1)
		{
			i++;
		}
		
		TBuf8<KMaxPEAPVersionsStringLengthInDB> tmp;
		
		tmp.Copy(reinterpret_cast<const TUint8 *> (default_EAP_TLS_PEAP_accepted_PEAP_versions), i * sizeof(TInt));
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal), tmp);

		view.SetColL(colSet->ColNo(cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal), default_PEAP_tunneled_types);
		view.SetColL(colSet->ColNo(cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal), default_PEAP_tunneled_types);		
		
		view.SetColL(colSet->ColNo(cf_str_TLS_server_authenticates_client_policy_in_client_literal), default_EAP_PEAP_TTLS_server_authenticates_client);

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal), default_EAP_TLS_PEAP_verify_certificate_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_FAST_max_session_validity_time_literal), default_MaxSessionTime);
		
		view.SetColL(colSet->ColNo(KFASTLastFullAuthTime), default_FullAuthTime);

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal), default_EAP_TLS_PEAP_TTLS_Privacy);		

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal), default_EAP_TLS_PEAP_use_automatic_ca_certificate);

		view.PutL();
		
		CleanupStack::PopAndDestroy(colSet); 
		CleanupStack::PopAndDestroy( &view ); // Close view.

		//--------------------------------------------------------//
		
		// This is to add default values to the Specific settings table.
		// KSQLInsert is "SELECT * FROM %S"
		sqlStatement.Format(KSQLInsert, &KFastSpecialSettingsDBTableName);	

		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly));
		CleanupClosePushL(view);
		view.InsertL();

		// Get column set so we get the correct column numbers
		colSet = view.ColSetL();
		CleanupStack::PushL(colSet);

		// Set the default values.
		view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt>(aIndexType));
		view.SetColL(colSet->ColNo(KServiceIndex), aIndex);		
		view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());

		view.SetColL(colSet->ColNo(cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal),
				default_EAP_FAST_Auth_Prov_Mode_Allowed);		
	 	view.SetColL(colSet->ColNo(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal),
	 			default_EAP_FAST_Unauth_Prov_Mode_Allowed);
							
		view.PutL();
		
		CleanupStack::PopAndDestroy(colSet); 
		CleanupStack::PopAndDestroy( &view );
		
		//--------------------------------------------------------//
		
		// Add default disabled cipher suites to cipher suites table.
		_LIT(KSQLInsert2, "SELECT * FROM %S");
		sqlStatement.Format(KSQLInsert2, &KFastAllowedCipherSuitesDatabaseTableName);
		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly));
		CleanupClosePushL(view);

		// Get column set so we get the correct column numbers
		colSet = view.ColSetL();
		CleanupStack::PushL(colSet);

		i = 0;
		while (default_allowed_cipher_suites[i] != 0)
		{
			view.InsertL();
			view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt>(aIndexType));
			view.SetColL(colSet->ColNo(KServiceIndex), aIndex);		
			view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
			view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
			view.SetColL(colSet->ColNo(KCipherSuite), default_allowed_cipher_suites[i]);
			view.PutL();
			i++;
		}
		
		CleanupStack::PopAndDestroy( colSet );
		CleanupStack::PopAndDestroy( &view );
	}

	aDatabase.Compact();

	CleanupStack::PopAndDestroy( buf );
	CleanupStack::Pop( &aDatabase );
	CleanupStack::Pop( &aFileServerSession );
	
} // EapTlsPeapUtils::OpenFastDatabaseL()

#endif // #if defined(USE_FAST_EAP_TYPE)

// ---------------------------------------------------------

void EapTlsPeapUtils::SetIndexL(
	RDbNamedDatabase& aDatabase,
	const TDesC& aTableName,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const TIndexType aNewIndexType,
	const TInt aNewIndex,
	const eap_type_value_e aNewTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetIndexL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x, aNewTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type(),
		aNewTunnelingType.get_vendor_id(),
		aNewTunnelingType.get_vendor_type()));
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetIndexL(): -Start- aNewIndexType=%d, aNewIndex=%d, aNewTunnelingType=%d \n"),
		aNewIndexType,
		aNewIndex,
		aNewTunnelingType.get_vendor_id(),
		aNewTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::SetIndexL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// First delete the target
	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL,
		&aTableName, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());		

	RDbView view;
	
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	
	// View must be closed when no longer needed
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());

	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	if (view.FirstL())
	{		
		do {
			view.GetL();
			{
				view.UpdateL();
				
			    view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(aNewIndexType));
    			view.SetColL(colSet->ColNo(KServiceIndex), static_cast<TUint>(aNewIndex));
				view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aNewTunnelingType.get_vendor_id());
				view.SetColL(colSet->ColNo(KTunnelingType), aNewTunnelingType.get_vendor_type());
				
				view.PutL();
			}
		} while (view.NextL() != EFalse);
	}
			
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);
}

// ---------------------------------------------------------

void EapTlsPeapUtils::ReadCertRowsToArrayL(
	RDbNamedDatabase& aDatabase,
	eap_am_tools_symbian_c * const /*aTools*/,
	const TDesC& aTableName, 
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	RPointerArray<EapCertificateEntry>& aArray)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::ReadCertRowsToArrayL(): - Start - aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::ReadCertRowsToArrayL()\n"));

	CleanupClosePushL( aArray );

	HBufC* buf = HBufC::NewLC(512);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	
	sqlStatement.Format(KSQLQueryRow,
		&aTableName,
		&KServiceType, 
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());
	
	RDbView view;
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());	

	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	if (view.FirstL())
	{
		do {

			view.GetL();
			
			{
				EapCertificateEntry * const certInfo = new EapCertificateEntry;
				if (certInfo == 0)
				{
					EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::ReadCertRowsToArrayL(): No memory\n")));
					User::Leave(KErrNoMemory);
				}

				// Store the line
				TPtrC ptr = view.ColDes(colSet->ColNo(KCertLabel));
	
				certInfo->SetLabel(ptr);
				
				TPtrC8 ptr2 = view.ColDes8(colSet->ColNo(KSubjectKeyIdentifier)); // This is for authentication and uses Symbian subjectkey id.
				certInfo->SetSubjectKeyId(ptr2);

				TInt error = aArray.Append(certInfo);

				EAP_TRACE_DEBUG_SYMBIAN((_L("ReadCertRowsToArrayL - Appended Cert with label=%S, error=%d\n"),
					certInfo->GetLabel(),
					error));

				EAP_TRACE_DATA_DEBUG_SYMBIAN(("ReadCertRowsToArrayL - Appended Cert's SubjectKeyID:",
					certInfo->GetSubjectKeyId().Ptr(),
					certInfo->GetSubjectKeyId().Length()));

				if (error != KErrNone)
				{
					delete certInfo;
					User::Leave(error);
				}
			}	

		} while (view.NextL() != EFalse);		
	}

	// Close database
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);
	CleanupStack::Pop( &aArray );
}

// ---------------------------------------------------------

void EapTlsPeapUtils::ReadUintRowsToArrayL(
	RDbNamedDatabase& aDatabase,
	eap_am_tools_symbian_c * const /*aTools*/,
	const TDesC& aTableName, 
	const TDesC& aColumnName,	
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	RArray<TUint>& aArray)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::ReadUintRowsToArrayL(): - Start - aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::ReadUintRowsToArrayL()\n"));

	CleanupClosePushL( aArray );

	HBufC* buf = HBufC::NewLC(512);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	
	sqlStatement.Format(KSQLQueryRow,
		&aColumnName,
		&aTableName, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType,
		aTunnelingType.get_vendor_type());
	
	RDbView view;
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	if (view.FirstL())
	{		
		do {
			view.GetL();

			switch (view.ColType(KDefaultColumnInView_One))
			{
			case EDbColUint32:
				{
					// Store the line
					TUint tmp = view.ColUint(KDefaultColumnInView_One);
					TInt error = aArray.Append(tmp);

					EAP_TRACE_DEBUG_SYMBIAN(
						(_L("EapTlsPeapUtils::ReadUintRowsToArrayL(): TUint=%d, error=%d\n"),
						tmp,
						error));

					if (error != KErrNone)
					{
						User::Leave(error);
					}
				}
				break;
			default:
				User::Leave(KErrArgument);
			}		

		} while (view.NextL() != EFalse);
	}

	// Close database
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);
	CleanupStack::Pop( &aArray );
}

// ---------------------------------------------------------

// Don't use this finction as Label is not saved for certificates saved by SetConfigurationL().
// Provisioning (OMA DM etc) use SetConfigurationL() to save certificate details.

TBool EapTlsPeapUtils::CompareTCertLabels(const TCertLabel& item1, const TCertLabel& item2)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CompareTCertLabels(): item1=\"%S\", item2=\"%S\"\n"),
		&item1,
		&item2));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::CompareTCertLabels()\n"));

	if (item1 == item2)
	{
		return ETrue;
	} 
	else
	{
		return EFalse;
	}
}

// ---------------------------------------------------------

TBool EapTlsPeapUtils::CompareSCertEntries(const EapCertificateEntry& item1, const EapCertificateEntry& item2)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CompareSCertEntries(): item1.Label=\"%S\", item2.Label=\"%S\"\n"),
		item1.GetLabel(),
		item2.GetLabel()));

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CompareSCertEntries(): item1.Label=\"%S\", item2.Label=\"%S\"\n"),
		item1.GetLabel(),
		item2.GetLabel()));

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::CompareSCertEntries(): SubjectKeyID_1:",
		item1.GetSubjectKeyId().Ptr(),
		item1.GetSubjectKeyId().Length()));

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::CompareSCertEntries(): SubjectKeyID_2:",
		item2.GetSubjectKeyId().Ptr(),
		item2.GetSubjectKeyId().Length()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::CompareSCertEntries()\n"));


	if (*(item1.GetLabel()) == *(item2.GetLabel())
		|| item1.GetLabel()->Length() == 0
		|| item2.GetLabel()->Length() == 0 ) // Label is not saved when certs are saved using OMA DM.
	{
		if (item1.GetSubjectKeyId() == item2.GetSubjectKeyId())
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::CompareSCertEntries, Certs matched\n")));
		
			return ETrue;
		}
	}
	
	return EFalse;
}

//--------------------------------------------------

// Stores the tunneled EAP type (expanded) to the database.
void EapTlsPeapUtils::SetTunnelingExpandedEapDataL(
	RDbNamedDatabase& aDatabase,
	eap_am_tools_symbian_c * const /*aTools*/,
	RPointerArray<TEapExpandedType> &aEnabledEAPArrary,
	RPointerArray<TEapExpandedType> &aDisabledEAPArrary,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetTunnelingExpandedEapDataL(): - Start - aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x, aEapType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type(),
		aEapType.get_vendor_id(),
		aEapType.get_vendor_type()));

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("Number of Tunneled EAP types: Enabled=%d, Disabled=%d\n"),
		aEnabledEAPArrary.Count(),
		aDisabledEAPArrary.Count()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::SetTunnelingExpandedEapDataL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	
	if (aEapType == eap_type_peap)
	{
		sqlStatement.Format(KSQLQueryRow,
			&cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal,
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KPeapDatabaseTableName,
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex, 
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	} 
#if defined(USE_TTLS_EAP_TYPE)
	else if (aEapType == eap_type_ttls)
	{
		sqlStatement.Format(KSQLQueryRow,
			&cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KTtlsDatabaseTableName,
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex, 
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	} 
#endif
#if defined(USE_FAST_EAP_TYPE)
	else if (aEapType == eap_type_fast)
	{
		sqlStatement.Format(KSQLQueryRow,
			&cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KFastGeneralSettingsDBTableName,
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex, 
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	} 
#endif

	else if ( aEapType == eap_expanded_type_ttls_plain_pap.get_type() )
	{
		sqlStatement.Format(KSQLQueryRow,
			&cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KTtlsDatabaseTableName,
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex, 
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	} 

	else
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetTunnelingExpandedEapDataL - Unsupported EAP-type=0xfe%06x%08x\n"),
			aEapType.get_vendor_id(),
			aEapType.get_vendor_type()));
			 
		// Unsupported EAP type
		User::Leave(KErrNotSupported);
	}	

	RDbView view;
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());	
	User::LeaveIfError(view.FirstL());	
	view.UpdateL();

	TInt enabledEAPCount = aEnabledEAPArrary.Count();
	TInt disabledEAPCount = aDisabledEAPArrary.Count();

	HBufC8 *acceptedDbText = HBufC8::NewLC( KEapExpandedTypeLength * enabledEAPCount ); // 8 bytes (64 bits) for an EAP type.
	HBufC8 *unacceptedDbText = HBufC8::NewLC( KEapExpandedTypeLength * disabledEAPCount ); // 8 bytes (64 bits) for an EAP type.
	
	TPtr8 acceptedPtr(acceptedDbText->Des());
	TPtr8 unacceptedPtr(unacceptedDbText->Des());
	
	// Fill in accepted tunneled type.		
	for(TInt i = 0 ; i< enabledEAPCount; i++)
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::SetTunnelingExpandedEapDataL():  enabled EAP-type=0xfe%06x%08x\n"),
			aEnabledEAPArrary[i]->GetVendorId(),
			aEnabledEAPArrary[i]->GetVendorType()));

		acceptedPtr.Append(aEnabledEAPArrary[i]->GetValue());					
	}
	
	// Fill in unaccepted tunneled type.		
	for(TInt i = 0 ; i< disabledEAPCount; i++)
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::SetTunnelingExpandedEapDataL(): disabled EAP-type=0xfe%06x%08x\n"),
			aDisabledEAPArrary[i]->GetVendorId(),
			aDisabledEAPArrary[i]->GetVendorType()));

		unacceptedPtr.Append(aDisabledEAPArrary[i]->GetValue());					
	}
	
	// Save the strings in the DB.
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);			
	
	// Validate length of strings
	if(acceptedPtr.Length() > KMaxTunneledTypeStringLengthInDB 
		|| unacceptedPtr.Length() > KMaxTunneledTypeStringLengthInDB)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetTunnelingExpandedEapDataL - Too long Tunneled EAP type string \n") ) );

		User::Leave(KErrArgument);		
	}
	
	view.SetColL(colSet->ColNo(cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal), acceptedPtr);
	view.SetColL(colSet->ColNo(cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal), unacceptedPtr);	

	CleanupStack::PopAndDestroy( colSet ); // Delete colSet.	

	view.PutL();

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::SetTunnelingExpandedEapDataL- Enabled extended EAP type data added to DB:",
		acceptedPtr.Ptr(), 
		acceptedPtr.Size() ) );

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::SetTunnelingExpandedEapDataL- Disabled extended EAP type data added to DB:",
		unacceptedPtr.Ptr(), 
		unacceptedPtr.Size() ) );

	CleanupStack::PopAndDestroy(unacceptedDbText); // Delete unacceptedDbText
	CleanupStack::PopAndDestroy(acceptedDbText); // Delete acceptedDbText	
	CleanupStack::PopAndDestroy(&view); // Close view
	CleanupStack::PopAndDestroy(buf); // Delete buf	
}

// ---------------------------------------------------------

// Retrieves the tunneled EAP type (expanded) from the database	.
void EapTlsPeapUtils::GetTunnelingExpandedEapDataL(
	RDbNamedDatabase& aDatabase,
	eap_am_tools_symbian_c * const /*aTools*/,
	RPointerArray<TEapExpandedType> &aEnabledEAPArrary,
	RPointerArray<TEapExpandedType> &aDisabledEAPArrary,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::GetTunnelingExpandedEapDataL(): - Start - aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x, aEapType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type(),
		aEapType.get_vendor_id(),
		aEapType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::GetTunnelingExpandedEapDataL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	if (aEapType == eap_type_peap)
	{
		sqlStatement.Format(KSQLQueryRow,
			&cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KPeapDatabaseTableName,
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex, 
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	} 
#if defined(USE_TTLS_EAP_TYPE)
	else if (aEapType == eap_type_ttls)
	{
		sqlStatement.Format(KSQLQueryRow,
			&cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KTtlsDatabaseTableName,
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex, 
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	} 
#endif
#if defined(USE_FAST_EAP_TYPE)
	else if (aEapType == eap_type_fast)
	{
		sqlStatement.Format(KSQLQueryRow,
			&cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KFastGeneralSettingsDBTableName,
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex, 
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	} 
#endif

	else if (aEapType == eap_expanded_type_ttls_plain_pap.get_type() )
	{
		sqlStatement.Format(KSQLQueryRow,
			&cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KTtlsDatabaseTableName,
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex, 
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	} 

	else
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::GetTunnelingExpandedEapDataL(): - Unsupported EAP-type=0xfe%06x%08x\n"),
			aEapType.get_vendor_id(),
			aEapType.get_vendor_type()));
			 
		// Unsupported EAP type
		User::Leave(KErrNotSupported);
	}	
	
	RDbView view;
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());	
	
	User::LeaveIfError(view.FirstL());
	
	view.GetL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);			
	
	TPtrC8 acceptedEAPData = view.ColDes8(colSet->ColNo(cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal));
	TPtrC8 unacceptedEAPData = view.ColDes8(colSet->ColNo(cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal));
	
	CleanupStack::PopAndDestroy( colSet ); // Delete colSet.	

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::GetTunnelingExpandedEapDataL- Enabled extended EAP type data from DB:",
		acceptedEAPData.Ptr(), 
		acceptedEAPData.Size() ) );
	
	EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::GetTunnelingExpandedEapDataL- Disabled extended EAP type data from DB:",
		unacceptedEAPData.Ptr(), 
		unacceptedEAPData.Size() ) );
	
	aEnabledEAPArrary.ResetAndDestroy();
	aDisabledEAPArrary.ResetAndDestroy();
		
	TUint acceptedLength = acceptedEAPData.Length();
	TUint unacceptedLength = unacceptedEAPData.Length();
	
	TEapExpandedType *expandedEAPTmp = 0;
	TUint index = 0;
	
	// For accepted or enabled tunneled EAP types. 	
	while(index < acceptedLength)
	{		
		expandedEAPTmp = new TEapExpandedType;

		if (expandedEAPTmp == 0)
		{
			aEnabledEAPArrary.ResetAndDestroy();
			aDisabledEAPArrary.ResetAndDestroy();
			User::LeaveIfError(KErrNoMemory);
		}

		*expandedEAPTmp = acceptedEAPData.Mid(index, KEapExpandedTypeLength);
						
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::GetTunnelingExpandedEapDataL():  enabled EAP-type=0xfe%06x%08x\n"),
			expandedEAPTmp->GetVendorId(),
			expandedEAPTmp->GetVendorType()));

		aEnabledEAPArrary.AppendL(expandedEAPTmp);

		index = index + KEapExpandedTypeLength;
	}
	
	index = 0;
	
	// For unaccepted or disabled tunneled EAP types.
	while(index < unacceptedLength)
	{		
		expandedEAPTmp = new TEapExpandedType;

		if (expandedEAPTmp == 0)
		{
			aEnabledEAPArrary.ResetAndDestroy();
			aDisabledEAPArrary.ResetAndDestroy();
			User::LeaveIfError(KErrNoMemory);
		}

		*expandedEAPTmp = unacceptedEAPData.Mid(index, KEapExpandedTypeLength);
						
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetTunnelingExpandedEapDataL(): disabled EAP-type=0xfe%06x%08x\n"),
			expandedEAPTmp->GetVendorId(),
			expandedEAPTmp->GetVendorType()));

		aDisabledEAPArrary.AppendL(expandedEAPTmp);

		index = index + KEapExpandedTypeLength;
	}

	CleanupStack::PopAndDestroy(&view); // Close view
	CleanupStack::PopAndDestroy(buf); // Delete buf
}

//--------------------------------------------------

TBool EapTlsPeapUtils::CipherSuiteUseRSAKeys(tls_cipher_suites_e aCipherSuite)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CipherSuiteUseRSAKeys(): aCipherSuite=%d\n"),
		aCipherSuite));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::CipherSuiteUseRSAKeys()\n"));

	if (aCipherSuite == tls_cipher_suites_TLS_RSA_WITH_3DES_EDE_CBC_SHA
		|| aCipherSuite == tls_cipher_suites_TLS_RSA_WITH_AES_128_CBC_SHA
		|| aCipherSuite == tls_cipher_suites_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
		|| aCipherSuite == tls_cipher_suites_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
		|| aCipherSuite == tls_cipher_suites_TLS_RSA_WITH_RC4_128_MD5
		|| aCipherSuite == tls_cipher_suites_TLS_RSA_WITH_RC4_128_SHA)
	{
		return ETrue;
	}

	return EFalse;

}

//--------------------------------------------------

TBool EapTlsPeapUtils::CipherSuiteUseDSAKeys(tls_cipher_suites_e aCipherSuite)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CipherSuiteUseDSAKeys(): aCipherSuite=%d\n"),
		aCipherSuite));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::CipherSuiteUseDSAKeys()\n"));

	if (aCipherSuite == tls_cipher_suites_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
		|| aCipherSuite == tls_cipher_suites_TLS_DHE_DSS_WITH_AES_128_CBC_SHA)
	{
		return ETrue;
	}

	return EFalse;
}

//--------------------------------------------------

TBool EapTlsPeapUtils::CipherSuiteIsEphemeralDHKeyExchange(tls_cipher_suites_e aCipherSuite)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CipherSuiteIsEphemeralDHKeyExchange(): aCipherSuite=%d\n"),
		aCipherSuite));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::CipherSuiteIsEphemeralDHKeyExchange()\n"));

	if (aCipherSuite == tls_cipher_suites_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
		|| aCipherSuite == tls_cipher_suites_TLS_DHE_DSS_WITH_AES_128_CBC_SHA
		|| aCipherSuite == tls_cipher_suites_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
		|| aCipherSuite == tls_cipher_suites_TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
	{
		return ETrue;
	}

	return EFalse;
}


// ---------------------------------------------------------
// EapTlsPeapUtils::SetConfigurationL()
// ---------------------------------------------------------
//
void EapTlsPeapUtils::SetConfigurationL(
	RDbNamedDatabase& aDatabase,
	const EAPSettings& aSettings, 
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetConfigurationL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x, aEapType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type(),
		aEapType.get_vendor_id(),
		aEapType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::SetConfigurationL()\n"));
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("*************************** EapTlsPeapUtils::SetConfigurationL(): Set the below values: ***************************\n")) );

	EAP_TRACE_SETTINGS(&aSettings);

	EAP_TRACE_DEBUG_SYMBIAN((_L("*************************** EapTlsPeapUtils::SetConfigurationL(): Set the above values: ***************************\n")) );


	// Validate length of inputs.
	if(aSettings.iUsername.Length() > KMaxUsernameLengthInDB
		|| aSettings.iRealm.Length() > KMaxRealmLengthInDB )
	{
		// Some inputs are too long. Can not be stored in DB.
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetConfigurationL(): Too long arguments\n")));
		
		User::Leave(KErrArgument);
	}

#ifdef USE_FAST_EAP_TYPE

	// Validate length of PAC Group Ref.
	if(aSettings.iPACGroupReference.Length() > KMaxPACGroupRefCollectionLengthInDB)
	{
		// Too long PAC Group Reference. Can not be stored in DB.
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetConfigurationL(): Too long PAC Group Ref!\n")));
		
		User::Leave(KErrArgument);
	}

#endif //#ifdef USE_FAST_EAP_TYPE		

	// Check if the settings are for the correct type
	if (aSettings.iEAPExpandedType != (*EapExpandedTypeTls.GetType())
		&& aSettings.iEAPExpandedType != (*EapExpandedTypePeap.GetType())
		&& aSettings.iEAPExpandedType != (*EapExpandedTypeTtls.GetType())
#ifdef USE_FAST_EAP_TYPE
		&& aSettings.iEAPExpandedType != (*EapExpandedTypeFast.GetType())
#endif //#ifdef USE_FAST_EAP_TYPE
		&& aSettings.iEAPExpandedType != (*EapExpandedTypeTtlsPap.GetType())
		)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetConfigurationL(): LEAVE - Unsupported EAP type\n")) );
		
		User::Leave(KErrNotSupported);
	}

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();	

	TPtrC settings;
	TPtrC usercerts;
	TPtrC cacerts;
	TPtrC ciphersuites;
	TPtrC maxSessionTime;
	TPtrC lastFullAuthTime;

#ifdef USE_FAST_EAP_TYPE
	TPtrC fastSpecialSettings;		
#endif
	
	if (aEapType == eap_type_tls)
	{
		settings.Set(KTlsDatabaseTableName);
		usercerts.Set(KTlsAllowedUserCertsDatabaseTableName);
		cacerts.Set(KTlsAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KTlsAllowedCipherSuitesDatabaseTableName);
		maxSessionTime.Set(cf_str_EAP_TLS_max_session_validity_time_literal);
		lastFullAuthTime.Set(KTLSLastFullAuthTime);
	}
	else if (aEapType == eap_type_peap)
	{
		settings.Set(KPeapDatabaseTableName);
		usercerts.Set(KPeapAllowedUserCertsDatabaseTableName);
		cacerts.Set(KPeapAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KPeapAllowedCipherSuitesDatabaseTableName);
		maxSessionTime.Set(cf_str_EAP_PEAP_max_session_validity_time_literal);
		lastFullAuthTime.Set(KPEAPLastFullAuthTime);
	}
	else if (aEapType == eap_type_ttls)
	{
		settings.Set(KTtlsDatabaseTableName);
		usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
		cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
		maxSessionTime.Set(cf_str_EAP_TTLS_max_session_validity_time_literal);
		lastFullAuthTime.Set(KTTLSLastFullAuthTime);
	}
#ifdef USE_FAST_EAP_TYPE		
	else if (aEapType == eap_type_fast)
	{
		settings.Set(KFastGeneralSettingsDBTableName); // This is general settings for FAST.
		fastSpecialSettings.Set(KFastSpecialSettingsDBTableName);
		
		usercerts.Set(KFastAllowedUserCertsDatabaseTableName);
		cacerts.Set(KFastAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KFastAllowedCipherSuitesDatabaseTableName);
		maxSessionTime.Set(cf_str_EAP_FAST_max_session_validity_time_literal);
		lastFullAuthTime.Set(KFASTLastFullAuthTime);
	}
#endif
	else if (aEapType == eap_expanded_type_ttls_plain_pap.get_type())
	{
		settings.Set( KTtlsDatabaseTableName );
		maxSessionTime.Set( cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal );
		lastFullAuthTime.Set( KTTLSPAPLastFullAuthTime );
	}
	else
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: SetConfigurationL(): LEAVE - Unsupported EAP-type=0xfe%06x%08x\n"),
			aEapType.get_vendor_id(),
			aEapType.get_vendor_type()) );

		// Should never happen
		User::Leave(KErrArgument);
	}

	RDbView view;

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	
	//////////////////////////////////////////
	// This is for settings for all EAP types.
	// For EAP-FAST it is General settings.
	//////////////////////////////////////////
	
	sqlStatement.Format(KSQL,
		&settings, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());		
		
	// Evaluate view
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement)));
	
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());	

	view.FirstL();
	
	view.UpdateL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	// Database view is ready for setting now. Set items one by one, if needed.


	//////////////////////////////////////////
	// This is only for plain PAP settings. //
	//////////////////////////////////////////
	if ( aEapType == eap_expanded_type_ttls_plain_pap.get_type() )
	{
		// Username
		if ( aSettings.iUsernamePresent )
		{
			// Validate length.
			if( aSettings.iUsername.Length() > KMaxPapUserNameLengthInDb )
		    {
				// Username too long. Can not be stored in DB.				
				EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetConfigurationL: Too long Username. Length=%d, max length=%d \n" ),
					aSettings.iUsername.Length(),
					KMaxPapUserNameLengthInDb) );

				CleanupStack::PopAndDestroy(colSet);
				CleanupStack::PopAndDestroy(&view);
				CleanupStack::PopAndDestroy(buf);
				User::Leave( KErrArgument );
		    }
			
			// Length is ok. Set the value in DB.
			view.SetColL( colSet->ColNo( cf_str_EAP_TLS_PEAP_ttls_pap_username_literal ),
				aSettings.iUsername);		
		}

		// Password existence.
		if (aSettings.iPasswordExistPresent
			&& !aSettings.iPasswordExist)
		{
			// Clear password from database.
			view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_ttls_pap_password_literal), KNullPasswordData);
			view.SetColNullL(colSet->ColNo(cf_str_EAP_TLS_PEAP_ttls_pap_password_literal));
		}

		// Password
		if ( aSettings.iPasswordPresent )
	    {
			// Validate length.
			if ( aSettings.iPassword.Length() > KMaxPapPasswordLengthInDb )
		    {
				// Password too long. Can not be stored in DB.				
				EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetConfigurationL: Too long Password. Length=%d, max length=%d\n" ),
					aSettings.iPassword.Length(),
					KMaxPapPasswordLengthInDb) );

				CleanupStack::PopAndDestroy(colSet);
				CleanupStack::PopAndDestroy(&view);
				CleanupStack::PopAndDestroy(buf);
				User::Leave( KErrArgument );
		    }
						
			// Length is ok. Set the value in DB.	
			view.SetColL( colSet->ColNo(
				cf_str_EAP_TLS_PEAP_ttls_pap_password_literal ),
				aSettings.iPassword );
	    }

		// Password prompt
		if ( aSettings.iShowPassWordPromptPresent )
	    {
			if ( aSettings.iShowPassWordPrompt )
			{
				view.SetColL( colSet->ColNo(
					cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal ),
					EPapPasswordPromptOn );
			}
			else
			{
				view.SetColL( colSet->ColNo(
					cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal ),
					EPapPasswordPromptOff );
			}
	    }
				
		// Session validity time
		if ( aSettings.iSessionValidityTimePresent )
	    {
			// User or device management wants to store the session validity time.
			// Convert the time to micro seconds and save.			
			TInt64 validityInMicro = (aSettings.iSessionValidityTime) * KMicroSecsInAMinute;
			view.SetColL( colSet->ColNo( maxSessionTime ), validityInMicro );

			// If max session validity time is supplied and non-zero, set password prompting ON.
			// It doesn't matter even if the password is supplied. If max session validity is supplied,
			// it means user needs to provide a password hence prompt should appear.			
			if( validityInMicro != 0)
		    {
				view.SetColL( colSet->ColNo(
					cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal ),
					EPapPasswordPromptOn );
		    }		
	    }
		
		// Last full authentication time should be made zero when EAP configurations are modified.
		// This makes sure that the next authentication with this EAP would be full authentication
		// instead of reauthentication even if the session is still valid.		
		view.SetColL( colSet->ColNo( lastFullAuthTime ), default_FullAuthTime );

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils: Session Validity: Resetting Full Auth Time since settings are modified\n")));
	    
		view.PutL();		

		CleanupStack::PopAndDestroy(colSet);
		CleanupStack::PopAndDestroy(&view);
		CleanupStack::PopAndDestroy(buf);
		
	    EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL(): Return PAP\n") ) );		
	    return; 
	} // if ( aEapVendorType == eap_expanded_type_ttls_plain_pap.get_type() )


	if (aSettings.iUseAutomaticCACertificatePresent)
	{
		// This is to set the automatic or manual status.
		TUint useAutomaticCACertificateStatus;
		
		if (aSettings.iUseAutomaticCACertificate)
		{
			useAutomaticCACertificateStatus = EEapDbTrue;
		}
		else
		{
			useAutomaticCACertificateStatus = EEapDbFalse;
		}
		
		// Set the value.
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal), useAutomaticCACertificateStatus);
	}


	if (aSettings.iUseAutomaticUsernamePresent)
	{
		// This is to set the automatic or manual status.
		TUint useManualUsernameStatus;
		
		if (aSettings.iUseAutomaticUsername)
		{
			useManualUsernameStatus = EEapDbFalse;
		}
		else
		{
			useManualUsernameStatus = EEapDbTrue;
		}
		
		// Set the value.
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal), useManualUsernameStatus);
	}


	if (aSettings.iUseAutomaticRealmPresent)
	{
		// This is to set the automatic or manual status.
		TUint useManualRealmStatus;
		
		if (aSettings.iUseAutomaticRealm)
		{
			useManualRealmStatus = EEapDbFalse;
		}
		else
		{
			useManualRealmStatus = EEapDbTrue;
		}

		// Set the value.
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal), useManualRealmStatus);
	}


	// Manual username
	if (aSettings.iUsernamePresent)
	{
		// Check if length of username is less than the max length.
		if(aSettings.iUsername.Length() > KMaxUsernameLengthInDB)
		{
			// Username too long. Can not be stored in DB.
			
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetConfigurationL(): Too long Username. Length=%d \n"),
				aSettings.iUsername.Length()));
			
			User::Leave(KErrArgument);
		}

		// Set the value in DB. Value could be empty. It doesn't matter.
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal), aSettings.iUsername);
		
	}
		
	// Manual realm
	if (aSettings.iRealmPresent)
	{
		// Check if length of realm is less than the max length.
		if(aSettings.iRealm.Length() > KMaxRealmLengthInDB)
		{
			// Realm too long. Can not be stored in DB.

			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetConfigurationL(): Too long Realm. Length=%d \n"),
				aSettings.iRealm.Length()));
			
			User::Leave(KErrArgument);
		}

		// Set the value in DB. Value could be empty. It doesn't matter.
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal), aSettings.iRealm);
	}
	
	// Verify server realm
	if (aSettings.iVerifyServerRealmPresent)
	{
		if (aSettings.iVerifyServerRealm)
		{
			view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal), 
				EEapDbTrue);
		}
		else
		{			
			view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal), 
				EEapDbFalse);
		}
	}
	
	// Require client authentication
	if (aSettings.iRequireClientAuthenticationPresent)
	{
		if (aSettings.iRequireClientAuthentication)
		{
			view.SetColL(colSet->ColNo(cf_str_TLS_server_authenticates_client_policy_in_client_literal),
				EEapDbTrue);
		}
		else
		{			
			view.SetColL(colSet->ColNo(cf_str_TLS_server_authenticates_client_policy_in_client_literal),
				EEapDbFalse);
		}
	}
	
	// Session validity time
	if (aSettings.iSessionValidityTimePresent)
	{
		// User or device management wants to store the session validity time.
		// Convert the time to micro seconds and save.
		
		TInt64 validityInMicro = (aSettings.iSessionValidityTime) *  KMicroSecsInAMinute;
		
		view.SetColL(colSet->ColNo(maxSessionTime), validityInMicro);
	}
	
	// Last full authentication time should be made zero when EAP configurations are modified.
	// This makes sure that the next authentication with this EAP would be full authentication
	// instead of reauthentication even if the session is still valid.
	
	view.SetColL(colSet->ColNo(lastFullAuthTime), default_FullAuthTime);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils: Session Validity: Resetting Full Auth Time since settings are modified\n")));	
	
	// PEAP versions
		
	if (aSettings.iPEAPVersionsPresent
		&& (aEapType == eap_type_peap
		|| aEapType == eap_type_ttls
#ifdef USE_FAST_EAP_TYPE		
		|| aEapType == eap_type_fast
#endif	
		))
	{
		TBuf8<KMaxPEAPVersionsStringLengthInDB> acceptedPEAPVersions;
		
		if (aSettings.iPEAPv0Allowed)
		{
			TInt tmp(0);
			acceptedPEAPVersions.Append(reinterpret_cast<const TUint8*>(&tmp), sizeof(TInt));
		}
		if (aSettings.iPEAPv1Allowed)
		{
			TInt tmp(1);
			acceptedPEAPVersions.Append(reinterpret_cast<const TUint8*>(&tmp), sizeof(TInt));
		}
		if (aSettings.iPEAPv2Allowed)
		{
			TInt tmp(2);
			acceptedPEAPVersions.Append(reinterpret_cast<const TUint8*>(&tmp), sizeof(TInt));
		}
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal), acceptedPEAPVersions); 	
	}

	if (aSettings.iUseIdentityPrivacyPresent)
	{
		// This is to set the automatic or manual status.
		TUint UseIdentityPrivacy = 0ul;
		
		if (aSettings.iUseIdentityPrivacy)
		{
			UseIdentityPrivacy = EEapDbTrue;
		}
		else
		{
			UseIdentityPrivacy = EEapDbFalse;
		}

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal), UseIdentityPrivacy); 	
	}
	
	view.PutL();
	
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	
#ifdef USE_FAST_EAP_TYPE		

	///////////////////////////////////////////////////////
	// This is only for EAP-FAST specific, Special settings.
	///////////////////////////////////////////////////////
	
	if(aEapType == eap_type_fast)
	{
		sqlStatement.Format(KSQL,
			&fastSpecialSettings, 
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex,
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());
		
		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement)));
		
		CleanupClosePushL(view);
		
		User::LeaveIfError(view.EvaluateAll());	

		view.FirstL();
		
		view.UpdateL();	
		
		// Get column set so we get the correct column numbers
		colSet = view.ColSetL();
		CleanupStack::PushL(colSet);	

		// Database view is ready for setting now. Set items one by one, if needed.
		
		// For provisioning modes.
		if (aSettings.iAuthProvModeAllowedPresent)
		{
			if (aSettings.iAuthProvModeAllowed)
			{
				view.SetColL(colSet->ColNo(cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal), 
					EEapDbTrue);
			}
			else
			{			
				view.SetColL(colSet->ColNo(cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal), 
					EEapDbFalse);
			}
		}
		
		if (aSettings.iUnauthProvModeAllowedPresent)
		{
			if (aSettings.iUnauthProvModeAllowed)
			{
				view.SetColL(colSet->ColNo(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal), 
					EEapDbTrue);
			}
			else
			{			
				view.SetColL(colSet->ColNo(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal), 
					EEapDbFalse);
			}
		}
		
		// For the warnings and prompts
		if (aSettings.iWarnADHPNoPACPresent)
		{
			if (aSettings.iWarnADHPNoPAC)
			{
				view.SetColL(colSet->ColNo(KFASTWarnADHPNoPAC), 
						EEapDbTrue);
			}
			else
			{			
				view.SetColL(colSet->ColNo(KFASTWarnADHPNoPAC), 
						EEapDbFalse);
			}
		}	
		
		if (aSettings.iWarnADHPNoMatchingPACPresent)
		{
			if (aSettings.iWarnADHPNoMatchingPAC)
			{
				view.SetColL(colSet->ColNo(KFASTWarnADHPNoMatchingPAC), 
						EEapDbTrue);
			}
			else
			{			
				view.SetColL(colSet->ColNo(KFASTWarnADHPNoMatchingPAC), 
						EEapDbFalse);
			}
		}	
		
		if (aSettings.iWarnNotDefaultServerPresent)
		{
			if (aSettings.iWarnADHPNoMatchingPAC)
			{
				view.SetColL(colSet->ColNo(KFASTWarnNotDefaultServer), 
						EEapDbTrue);
			}
			else
			{			
				view.SetColL(colSet->ColNo(KFASTWarnNotDefaultServer), 
						EEapDbFalse);
			}
		}	
		
		// For PAC group reference.
		if (aSettings.iPACGroupReferencePresent)
		{
			// The length of iPACGroupReference is already checked for max length.
			// So just store it in the DB.
			view.SetColL(colSet->ColNo(KFASTPACGroupImportReferenceCollection),
				aSettings.iPACGroupReference);
		}			
		
		view.PutL();
		
		CleanupStack::PopAndDestroy(colSet);
		CleanupStack::PopAndDestroy(&view);
	
	} // End: if(aEapType == eap_type_fast)
	
#endif // #ifdef USE_FAST_EAP_TYPE		
	
	//////////////////
	// Cipher suites
	//////////////////
	
	if (aSettings.iCipherSuitesPresent)
	{
		sqlStatement.Format(KSQL,
			&ciphersuites, 
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex,
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());
		
		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement)));
		
		CleanupClosePushL(view);
		
		User::LeaveIfError(view.EvaluateAll());	

		// Delete old rows
		if (view.FirstL())
		{
			do {
				view.DeleteL();
			} while (view.NextL() != EFalse);
		}	

		// Get column set so we get the correct column numbers
		colSet = view.ColSetL();
		CleanupStack::PushL(colSet);

		// Database view is ready for setting now. Set items one by one, if needed.
		
		for (TInt i = 0; i < aSettings.iCipherSuites.Count(); i++)
		{
			view.InsertL();
			view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(aIndexType));
			view.SetColL(colSet->ColNo(KServiceIndex), static_cast<TUint>(aIndex));
			view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
			view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
			view.SetColL(colSet->ColNo(KCipherSuite), aSettings.iCipherSuites[i]);
			view.PutL();
		}
		
		CleanupStack::PopAndDestroy(colSet);
		CleanupStack::PopAndDestroy(&view);
	}
	
	/////////////////////////
	// User + CA Certificates
	/////////////////////////
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL(): aSettings.iCertificatesPresent=%d \n"), aSettings.iCertificatesPresent ) );
	
	if (aSettings.iCertificatesPresent)
	{
		// Needed for getting the Symbian's subject key id.
		//CEapTlsPeapCertFetcher* certFetcher = CEapTlsPeapCertFetcher::NewL();
		//CleanupStack::PushL(certFetcher);
				
		TBuf8<KKeyIdentifierLength> symbianSubjectKeyID;		
		
		// For USER certificate.		
		sqlStatement.Format(KSQL,
			&usercerts, 
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex,
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());
			
		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement)));
	
		CleanupClosePushL(view);
	
		User::LeaveIfError(view.EvaluateAll());	

		// Delete old rows
		if (view.FirstL())
		{
			do {
				view.DeleteL();
			} while (view.NextL() != EFalse);
		}	
		
		// Get column set so we get the correct column numbers
		colSet = view.ColSetL();
		CleanupStack::PushL(colSet);

    	// Database view is ready for setting now. Set items one by one, if needed.
		
		TInt i(0);
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL(): aSettings.iCertificates.Count()=%d \n"), aSettings.iCertificates.Count() ) );

		for (i = 0; i < aSettings.iCertificates.Count(); i++)
		{
			if (aSettings.iCertificates[i]->GetIsEnabledPresent()
				&& aSettings.iCertificates[i]->GetIsEnabled()
				&& aSettings.iCertificates[i]->GetCertType() == EapCertificateEntry::EUser)
			{	
				// Validate the length and save other certificate details to the DB.
				if(aSettings.iCertificates[i]->GetSubjectName()->Length() > KKeyIdentifierLength
				   || aSettings.iCertificates[i]->GetIssuerName()->Length() > KGeneralStringMaxLength
				   || aSettings.iCertificates[i]->GetSerialNumber()->Length() > KGeneralStringMaxLength
				   || aSettings.iCertificates[i]->GetSubjectKeyId().Length() > KGeneralStringMaxLength
				   || aSettings.iCertificates[i]->GetThumbprint()->Length() > KThumbprintMaxLength)
				{
					// Too long data. Can not be stored in DB.

					EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL : Too long USER cert details.\n")));
										
					User::Leave(KErrArgument);
				}					
						
				EAP_TRACE_DATA_DEBUG_SYMBIAN(("THIS IS SubjectKeyID:",
						aSettings.iCertificates[i]->GetSubjectKeyId().Ptr(),
						aSettings.iCertificates[i]->GetSubjectKeyId().Length()));

				// The cert label column is left empty

				view.InsertL();			
				view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(aIndexType));
				view.SetColL(colSet->ColNo(KServiceIndex), static_cast<TUint>(aIndex));
				view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
				view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
																
				view.SetColL(colSet->ColNo(KSubjectName), *(aSettings.iCertificates[i]->GetSubjectName()));
				view.SetColL(colSet->ColNo(KIssuerName), *(aSettings.iCertificates[i]->GetIssuerName()));
				view.SetColL(colSet->ColNo(KSerialNumber), *(aSettings.iCertificates[i]->GetSerialNumber()));
				view.SetColL(colSet->ColNo(KActualSubjectKeyIdentifier), aSettings.iCertificates[i]->GetSubjectKeyId());
				
				// Special for thumb print (finger print). Need to convert it to 8 bits before storing in DB
				TBuf8<KThumbprintMaxLength> thumbPrint8Bit;
				thumbPrint8Bit.Copy(*(aSettings.iCertificates[i]->GetThumbprint()));
				
				view.SetColL(colSet->ColNo(KThumbprint), thumbPrint8Bit);
				
				view.SetColL(colSet->ColNo(KSubjectKeyIdentifier), aSettings.iCertificates[i]->GetSubjectKeyId());
			
				view.PutL();	
			}
		}

		CleanupStack::PopAndDestroy(colSet);
		CleanupStack::PopAndDestroy(&view);

		// Do the same for CA certificates.		
		sqlStatement.Format(KSQL,
			&cacerts, 
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex,
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());
		
		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement)));
		
		CleanupClosePushL(view);
		
		User::LeaveIfError(view.EvaluateAll());	
		
		// Delete old rows
		if (view.FirstL())
		{
			do {
				view.DeleteL();
			} while (view.NextL() != EFalse);
		}	
			
		// Get column set so we get the correct column numbers
		colSet = view.ColSetL();
		CleanupStack::PushL(colSet);

		for (i = 0; i < aSettings.iCertificates.Count(); i++)
		{
			if (aSettings.iCertificates[i]->GetIsEnabledPresent()
				&& aSettings.iCertificates[i]->GetIsEnabled()
				&& aSettings.iCertificates[i]->GetCertType() == EapCertificateEntry::ECA)
			{
				// Validate the length and save other certificate details to the DB.
				if(aSettings.iCertificates[i]->GetSubjectName()->Length() > KKeyIdentifierLength
				   || aSettings.iCertificates[i]->GetIssuerName()->Length() > KGeneralStringMaxLength
				   || aSettings.iCertificates[i]->GetSerialNumber()->Length() > KGeneralStringMaxLength
				   || aSettings.iCertificates[i]->GetSubjectKeyId().Length() > KGeneralStringMaxLength
				   || aSettings.iCertificates[i]->GetThumbprint()->Length() > KThumbprintMaxLength)
				{
					// Too long data. Can not be stored in DB.

					EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL:Too long CA cert details.\n")));
										
					User::Leave(KErrArgument);
				}					
					
				// The cert label column is left empty
				
				view.InsertL();			
				view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(aIndexType));
				view.SetColL(colSet->ColNo(KServiceIndex), static_cast<TUint>(aIndex));				
				view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
				view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
								
				view.SetColL(colSet->ColNo(KSubjectName), *(aSettings.iCertificates[i]->GetSubjectName()));
				view.SetColL(colSet->ColNo(KIssuerName), *(aSettings.iCertificates[i]->GetIssuerName()));
				view.SetColL(colSet->ColNo(KSerialNumber), *(aSettings.iCertificates[i]->GetSerialNumber()));
				view.SetColL(colSet->ColNo(KActualSubjectKeyIdentifier), aSettings.iCertificates[i]->GetSubjectKeyId());
				
				// Special for thumb print (finger print). Need to convert it to 8 bits before storing in DB
				TBuf8<KThumbprintMaxLength> thumbPrint8Bit;
				thumbPrint8Bit.Copy(*(aSettings.iCertificates[i]->GetThumbprint()));
				
				view.SetColL(colSet->ColNo(KThumbprint), thumbPrint8Bit);
				
				// Get the "symbian's subject key id" using symbian API.
				// We use this subject key id for authentication.

				view.SetColL(colSet->ColNo(KSubjectKeyIdentifier), aSettings.iCertificates[i]->GetSubjectKeyId());

				EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "EapTlsPeapUtils::SetConfigurationL(): Adding CA cert to DB, Supplied (Actual) SubjectKeyID:",
					aSettings.iCertificates[i]->GetSubjectKeyId().Ptr(),
					aSettings.iCertificates[i]->GetSubjectKeyId().Length() ) );
				
				EAP_TRACE_SETTINGS(aSettings.iCertificates[i]);

				view.PutL();
				}
		}
		
		CleanupStack::PopAndDestroy(colSet);
		CleanupStack::PopAndDestroy(&view);
		
		//CleanupStack::PopAndDestroy(certFetcher);
		
	} // End of if (aSettings.iCertificatesPresent)
	
	CleanupStack::PopAndDestroy(buf);
		
	/////////////////////
	// Encapsulated types
	/////////////////////
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL(): aSettings.iEnabledEncapsulatedEAPExpandedTypesPresent=%d \n"), aSettings.iEnabledEncapsulatedEAPExpandedTypesPresent ) );

	// Encapsulated types are only for EAP-PEAP, EAP-TTLS and EAP-FAST. Not for EAP-TLS.
	// This is just to be on safe side. In case if iEnabledEncapsulatedEAPExpandedTypesPresent is set true for EAP-TLS by the caller.
	if ( aEapType != eap_type_peap 
		 && aEapType != eap_type_ttls
#ifdef USE_FAST_EAP_TYPE
		 && aEapType != eap_type_fast
#endif		  		 
		  )
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL(): End - Since no encapsulated type for the EAP-type=0xfe%06x%08x\n"),
			aEapType.get_vendor_id(),
			aEapType.get_vendor_type()  ) );
			
		return; // No need to proceed. No encapsulated type for EAP-TLS..
	}
	
	if (aSettings.iEnabledEncapsulatedEAPExpandedTypesPresent)
	{
		RPointerArray<TEapExpandedType> enabledEAPTypes;
		// This is just for dummy. All EAP types available here are enabled as default.
		RPointerArray<TEapExpandedType> disabledEAPTypes;
		TEapExpandedType* expandedEAPTmp = 0;
	
		for (TInt i = 0; i < aSettings.iEnabledEncapsulatedEAPExpandedTypes.Count(); i++)
		{
			expandedEAPTmp = new TEapExpandedType;

			if (expandedEAPTmp == 0)
			{
				enabledEAPTypes.ResetAndDestroy();
				disabledEAPTypes.ResetAndDestroy();
				enabledEAPTypes.Close();
				disabledEAPTypes.Close();
				User::Leave(KErrNoMemory);				
			}

			// Now copy the 8 byte string to expandedEAPTmp.
			*expandedEAPTmp = aSettings.iEnabledEncapsulatedEAPExpandedTypes[i].GetValue();

			EAP_TRACE_DATA_DEBUG_SYMBIAN(
				("EapTlsPeapUtils::SetConfigurationL: Expanded EAP type string",
				expandedEAPTmp->GetValue().Ptr(), 
				expandedEAPTmp->GetValue().Size() ) );						

			TInt error = enabledEAPTypes.Append(expandedEAPTmp);
			if (error != KErrNone)
			{
				delete expandedEAPTmp;
				expandedEAPTmp = 0;
			}
		}	

		TRAPD(error, SetTunnelingExpandedEapDataL(
			aDatabase, 
			0, 
			enabledEAPTypes,
			disabledEAPTypes, 
			aIndexType,
			aIndex,
			aTunnelingType,
			aEapType));
			
		if( error != KErrNone )
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL(): ########### Setting Expanded Tunneling types in the DB failed ############ \n") ) );

			enabledEAPTypes.ResetAndDestroy();
			disabledEAPTypes.ResetAndDestroy();
			enabledEAPTypes.Close();
			disabledEAPTypes.Close();

			User::Leave(KErrArgument); // There could be some problem in the encapsulated EAP type argument.
		}

		enabledEAPTypes.ResetAndDestroy();
		disabledEAPTypes.ResetAndDestroy();
		enabledEAPTypes.Close();
		disabledEAPTypes.Close();

	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL(): End \n") ) );		

} // EapTlsPeapUtils::SetConfigurationL()


// ----------------------------------------------------------------------

TInt EapTlsPeapUtils::FilterEapMethods(
	RPointerArray<TEapExpandedType> * const aEAPTypes,
	RPointerArray<TEapExpandedType> * const aPlugins)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::FilterEapMethods(): aEAPTypes->Count()=%d, aPlugins->Count()=%d\n"),
		aEAPTypes->Count(),
		aPlugins->Count()));

	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::FilterEapMethods()\n"));

	for (TInt act_ind = 0; act_ind < aEAPTypes->Count(); ++act_ind)
	{
		const TEapExpandedType * eap_type = (*aEAPTypes)[act_ind];
		if (eap_type == 0)
		{
			return KErrNoMemory;
		}

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::FilterEapMethods(): aEAPTypes[%d] EAP-type=0xfe%06x%08x\n"),
			act_ind,
			eap_type->GetVendorId(),
			eap_type->GetVendorType()));

		bool exists(false);

		for (TInt plugin_ind = 0; plugin_ind < aPlugins->Count(); ++plugin_ind)
		{
			const TEapExpandedType * plugin_type = (*aPlugins)[plugin_ind];
			if (plugin_type == 0)
			{
				return KErrNoMemory;
			}

			EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::FilterEapMethods(): aPlugins[%d] EAP-type=0xfe%06x%08x\n"),
				plugin_ind,
				plugin_type->GetVendorId(),
				plugin_type->GetVendorType()));

			if (*eap_type == *plugin_type)
			{
				// OK, this active EAP-method have implementation.
				exists = true;

				EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::FilterEapMethods(): Removes from aPlugins EAP-type=0xfe%06x%08x\n"),
					eap_type->GetVendorId(),
					eap_type->GetVendorType()));

				// Remove this plugin EAP-method because it is in the list of EAP-methods.
				delete (*aPlugins)[plugin_ind];
				aPlugins->Remove(plugin_ind);

				break;
			}
		} // for()

		if (exists == false)
		{
			// Remove this EAP-method because there are no implementation.

			EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::FilterEapMethods(): Removes from aEAPTypes EAP-type=0xfe%06x%08x\n"),
				eap_type->GetVendorId(),
				eap_type->GetVendorType()));

			delete (*aEAPTypes)[act_ind];
			aEAPTypes->Remove(act_ind);

			--act_ind;
		}
	} // for()

	return KErrNone;
}

// ---------------------------------------------------------
// EapTlsPeapUtils::GetConfigurationL()
// ---------------------------------------------------------
//
void EapTlsPeapUtils::GetConfigurationL(
	RDbNamedDatabase& aDatabase,
	EAPSettings& aSettings, 
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::GetConfigurationL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x, aEapType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type(),
		aEapType.get_vendor_id(),
		aEapType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::GetConfigurationL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();	

	TPtrC settings;
	TPtrC usercerts;
	TPtrC cacerts;
	TPtrC ciphersuites;
	TPtrC maxSessionTime;
	
#ifdef USE_FAST_EAP_TYPE
	TPtrC fastSpecialSettings;		
#endif
	
	if (aEapType == eap_type_tls)
	{
		settings.Set(KTlsDatabaseTableName);
		usercerts.Set(KTlsAllowedUserCertsDatabaseTableName);
		cacerts.Set(KTlsAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KTlsAllowedCipherSuitesDatabaseTableName);
		maxSessionTime.Set(cf_str_EAP_TLS_max_session_validity_time_literal);
	}
	else if (aEapType == eap_type_peap)
	{
		settings.Set(KPeapDatabaseTableName);
		usercerts.Set(KPeapAllowedUserCertsDatabaseTableName);
		cacerts.Set(KPeapAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KPeapAllowedCipherSuitesDatabaseTableName);
		maxSessionTime.Set(cf_str_EAP_PEAP_max_session_validity_time_literal);
	}
	else if (aEapType == eap_type_ttls)
	{
		settings.Set(KTtlsDatabaseTableName);
		usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
		cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
		maxSessionTime.Set(cf_str_EAP_TTLS_max_session_validity_time_literal);
	}
#ifdef USE_FAST_EAP_TYPE
	else if (aEapType == eap_type_fast)
	{
		settings.Set(KFastGeneralSettingsDBTableName); // This is general settings for FAST.
		fastSpecialSettings.Set(KFastSpecialSettingsDBTableName);
		
		usercerts.Set(KFastAllowedUserCertsDatabaseTableName);
		cacerts.Set(KFastAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KFastAllowedCipherSuitesDatabaseTableName);
		maxSessionTime.Set(cf_str_EAP_FAST_max_session_validity_time_literal);
	}
#endif
	else if (aEapType == eap_expanded_type_ttls_plain_pap.get_type())
	{
		settings.Set( KTtlsDatabaseTableName );
		maxSessionTime.Set( cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal );
	}
	else
	{
		// Should never happen
		User::Leave(KErrArgument);
	}	
	
	RDbView view;

	// Form the query
	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	
	//////////////////////////////////////////
	// This is for settings for all EAP types.
	// For EAP-FAST it is General settings.
	//////////////////////////////////////////
	
	sqlStatement.Format(KSQL,
		&settings, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());

	// Evaluate view
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement)));
	
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());	

	// Get the first (and only) row
	view.FirstL();
	view.GetL();				
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	aSettings.iEAPExpandedType.SetValue(
		aEapType.get_vendor_id(),
		aEapType.get_vendor_type());

	EAP_TRACE_DATA_DEBUG_SYMBIAN(
		(EAPL("EapTlsPeapUtils::GetConfigurationL(): aSettings.iEAPExpandedType"),
		aSettings.iEAPExpandedType.GetValue().Ptr(),
		aSettings.iEAPExpandedType.GetValue().Length()));

	//////////////////////////////////////////
	// This is only for plain PAP settings. //
	//////////////////////////////////////////
	if ( aEapType == eap_expanded_type_ttls_plain_pap.get_type() )
	{		
	    // Username
	    TPtrC username = view.ColDes( colSet->ColNo(
	   		cf_str_EAP_TLS_PEAP_ttls_pap_username_literal ) );
	    aSettings.iUsername.Copy( username );
	    aSettings.iUsernamePresent = ETrue;

		// Password existence.
		aSettings.iPasswordExistPresent = ETrue;
		aSettings.iPasswordExist = ! view.IsColNull(colSet->ColNo(cf_str_EAP_TLS_PEAP_ttls_pap_password_literal));

		aSettings.iShowPassWordPromptPresent = ETrue;

		TUint aShow = view.ColUint( colSet->ColNo( cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal ) );
		if ( aShow == EPapPasswordPromptOn)
		{
			aSettings.iShowPassWordPrompt = ETrue;
		}
		else
		{
			aSettings.iShowPassWordPrompt = EFalse;
		}

#if defined(USE_EAP_PASSWORD_READ_FROM_DATABASE)
        // Password
	    TPtrC password = view.ColDes( colSet->ColNo(
    		cf_str_EAP_TLS_PEAP_ttls_pap_password_literal ) );
	    aSettings.iPassword.Copy( password );
	    aSettings.iPasswordPresent = ETrue;
#else
		EAP_TRACE_DEBUG_SYMBIAN((_L("WARNING: EapTlsPeapUtils::GetConfigurationL(): Password read is disabled\n")));
#endif //#if defined(USE_EAP_PASSWORD_READ_FROM_DATABASE)

	    // Session validity time	
	    TInt64 maxSessionTimeMicro = view.ColInt64( colSet->ColNo(
	    	cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal ) );
	
	    // Convert the time to minutes.	
	    TInt64 maxSessionTimeMin = maxSessionTimeMicro / KMicroSecsInAMinute;
	
	    aSettings.iSessionValidityTime = static_cast<TUint>( maxSessionTimeMin );
	    aSettings.iSessionValidityTimePresent = ETrue;
		
	    CleanupStack::PopAndDestroy(3); // view, colset, buf

		return;
	}


	{
		// For manual or automatic CA-certificate.
		TUint useAutomaticCACertificate = view.ColUint(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_automatic_ca_certificate_literal));

		aSettings.iUseAutomaticCACertificatePresent = ETrue;

		if(useAutomaticCACertificate == EEapDbTrue)
		{
			aSettings.iUseAutomaticCACertificate = ETrue;
		}
		else
		{
			aSettings.iUseAutomaticCACertificate = EFalse;
		}
	}

	{
		// For manual or automatic username.
		TUint useUsername = view.ColUint(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal));

		aSettings.iUseAutomaticUsernamePresent = ETrue;

		if(useUsername == EEapDbTrue)
		{
			aSettings.iUseAutomaticUsername = EFalse;		
		}
		else
		{
			aSettings.iUseAutomaticUsername = ETrue;		
		}
	}

	{
		// For manual or automatic realm.
		TUint useRealm = view.ColUint(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal));

		aSettings.iUseAutomaticRealmPresent = ETrue;

		if(useRealm == EEapDbTrue)
		{
			aSettings.iUseAutomaticRealm = EFalse;
		}
		else
		{
			aSettings.iUseAutomaticRealm = ETrue;
		}
	}

	{
		// Username
		TPtrC username = view.ColDes(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal));

		aSettings.iUsernamePresent = ETrue;

		aSettings.iUsername.Copy(username);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL(): Settings.iUsername=%S \n"), &(aSettings.iUsername) ) );

	{
		// Realm
		TPtrC realm = view.ColDes(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal));

		aSettings.iRealmPresent = ETrue;

		aSettings.iRealm.Copy(realm);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL(): aSettings.iRealm=%S \n"),&(aSettings.iRealm)) );

	{
		// Verify server realm	
		TInt verifyrealm = view.ColUint(colSet->ColNo(cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal));
		if (verifyrealm == 0)
		{
			aSettings.iVerifyServerRealm = EFalse;
		}
		else
		{
			aSettings.iVerifyServerRealm = ETrue;
		}
		aSettings.iVerifyServerRealmPresent = ETrue;
	}
	
	{
		// Require client authentication
		TInt requireclientauth = view.ColUint(colSet->ColNo(cf_str_TLS_server_authenticates_client_policy_in_client_literal));
		if (requireclientauth == 0)
		{
			aSettings.iRequireClientAuthentication = EFalse;
		}
		else
		{
			aSettings.iRequireClientAuthentication = ETrue;
		}
		aSettings.iRequireClientAuthenticationPresent = ETrue;
	}

	{
		// Session validity time	
		TInt64 maxSessionTimeMicro = view.ColInt64(colSet->ColNo(maxSessionTime));
		
		// Convert the time to minutes.	
		TInt64 maxSessionTimeMin = maxSessionTimeMicro / KMicroSecsInAMinute;
		
		aSettings.iSessionValidityTime = static_cast<TUint>(maxSessionTimeMin);
		aSettings.iSessionValidityTimePresent = ETrue;
	}

	// PEAP versions
	if (aEapType == eap_type_peap
		|| aEapType == eap_type_ttls
#ifdef USE_FAST_EAP_TYPE
		|| aEapType == eap_type_fast
#endif		
		)
	{
		TPtrC8 binaryValue = view.ColDes8(colSet->ColNo(cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal));
		
		const TInt* allowedVersions = reinterpret_cast<const TInt *>(binaryValue.Ptr());

		TInt i;
		for (i = 0; i < static_cast<TInt>(binaryValue.Length() / sizeof(TInt)); i++)
		{
			switch(allowedVersions[i])
			{
			case 0:
				aSettings.iPEAPv0Allowed = ETrue;
				break;
			case 1:
				aSettings.iPEAPv1Allowed = ETrue;			
				break;
			case 2:
				aSettings.iPEAPv2Allowed = ETrue;
				
				break;		
			}
		}
		aSettings.iPEAPVersionsPresent = ETrue;
	}
	
	{
		// Require client authentication
		TInt UseIdentityPrivacy = view.ColUint(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal));
		if (UseIdentityPrivacy == 0)
		{
			aSettings.iUseIdentityPrivacy = EFalse;
		}
		else
		{
			aSettings.iUseIdentityPrivacy = ETrue;
		}
		aSettings.iUseIdentityPrivacyPresent = ETrue;
	}

	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	
#ifdef USE_FAST_EAP_TYPE		

	///////////////////////////////////////////////////////
	// This is only for EAP-FAST specific, Special settings.
	///////////////////////////////////////////////////////	
	
	if(aEapType == eap_type_fast)
	{
		sqlStatement.Format(KSQL,
			&fastSpecialSettings, 
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex,
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());
	
		// Evaluate view
		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement)));
		
		CleanupClosePushL(view);
		
		User::LeaveIfError(view.EvaluateAll());	
	
		// Get the first (and only) row
		view.FirstL();
		view.GetL();				
		
		// Get column set so we get the correct column numbers
		CDbColSet* colSet = view.ColSetL();
		CleanupStack::PushL(colSet);
	
		// For provisioning modes.
		TUint authProvMode = view.ColUint(colSet->ColNo(cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal));
		if(authProvMode == EEapDbFalse)
		{
			aSettings.iAuthProvModeAllowed = EFalse;
		}
		else
		{
			aSettings.iAuthProvModeAllowed = ETrue;
		}
		
		aSettings.iAuthProvModeAllowedPresent = ETrue;

		TUint unauthProvMode = view.ColUint(colSet->ColNo(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal));
		if(unauthProvMode == EEapDbFalse)
		{
			aSettings.iUnauthProvModeAllowed = EFalse;
		}
		else
		{
			aSettings.iUnauthProvModeAllowed = ETrue;
		}
		
		aSettings.iUnauthProvModeAllowedPresent = ETrue;		
		
		// For no PAC warning	
		TUint warn = view.ColUint(colSet->ColNo(KFASTWarnADHPNoPAC));
		if(warn == EEapDbFalse)
		{
			aSettings.iWarnADHPNoPAC = EFalse;
		}
		else
		{
			aSettings.iWarnADHPNoPAC = ETrue;
		}
		
		aSettings.iWarnADHPNoPACPresent = ETrue;
		
		// For no matching PAC warning		
		warn = view.ColUint(colSet->ColNo(KFASTWarnADHPNoMatchingPAC));
		if(warn == EEapDbFalse)
		{
			aSettings.iWarnADHPNoMatchingPAC = EFalse;
		}
		else
		{
			aSettings.iWarnADHPNoMatchingPAC = ETrue;
		}
		
		aSettings.iWarnADHPNoMatchingPACPresent = ETrue;		
		
		// For no default server warning
		warn = view.ColUint(colSet->ColNo(KFASTWarnNotDefaultServer));
		if(warn == EEapDbFalse)
		{
			aSettings.iWarnNotDefaultServer = EFalse;
		}
		else
		{
			aSettings.iWarnNotDefaultServer = ETrue;
		}
		
		aSettings.iWarnNotDefaultServerPresent = ETrue;
		
		// For PAC group reference.
		TPtrC pacGroupRef = view.ColDes(colSet->ColNo(KFASTPACGroupImportReferenceCollection));
		if(pacGroupRef.Length())
		{
			aSettings.iPACGroupReference.Copy(pacGroupRef);
			
			aSettings.iPACGroupReferencePresent = ETrue;
		}
		
		CleanupStack::PopAndDestroy(colSet);
		CleanupStack::PopAndDestroy(&view);
				
	} // End: if(aEapType == eap_type_fast) 

#endif //#ifdef USE_FAST_EAP_TYPE		
		
	
	//////////////////
	// Cipher suites
	//////////////////
	
	sqlStatement.Format(KSQL,
		&ciphersuites, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());
	
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement)));
	
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());	
		
	// Get column set so we get the correct column numbers
	colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	if (view.FirstL())
	{		
		do {
			view.GetL();
			{				
				aSettings.iCipherSuites.AppendL(view.ColUint(colSet->ColNo(KCipherSuite)));
			}
		} while (view.NextL() != EFalse);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL(): Total cipher suites appended=%d \n"), aSettings.iCipherSuites.Count()) );
	
	aSettings.iCipherSuitesPresent = ETrue;
	
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	
	/////////////////
	// User Certificates
	/////////////////

	sqlStatement.Format(KSQL,
		&usercerts, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());
	
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement)));
	
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());	
		
	// Get column set so we get the correct column numbers
	colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	if (view.FirstL())
	{		
		do {
			view.GetL();
			{
				// This is big object.
				EapCertificateEntry * certEntry = new (ELeave) EapCertificateEntry;
				CleanupStack::PushL(certEntry);

				certEntry->SetCertType(EapCertificateEntry::EUser);
				
				certEntry->GetSubjectNameWritable()->Copy(view.ColDes(colSet->ColNo(KSubjectName)));
				if(certEntry->GetSubjectName()->Length())
				{
					certEntry->SetSubjectNamePresent();
				}
				
				certEntry->GetIssuerNameWritable()->Copy(view.ColDes(colSet->ColNo(KIssuerName)));
				if(certEntry->GetIssuerName()->Length())
				{
					certEntry->SetIssuerNamePresent();
				}

				certEntry->GetSerialNumberWritable()->Copy(view.ColDes(colSet->ColNo(KSerialNumber)));
				if(certEntry->GetSerialNumber()->Length())
				{
					certEntry->SetSerialNumberPresent();
				}

				certEntry->GetSubjectKeyIdWritable()->Copy(view.ColDes8(colSet->ColNo(KActualSubjectKeyIdentifier))); // This is the subjectkey id we got in SetConfigurationL
				if(certEntry->GetSubjectKeyId().Length())
				{
					certEntry->SetSubjectKeyIdPresent();
				}

				certEntry->GetThumbprintWritable()->Copy(view.ColDes8(colSet->ColNo(KThumbprint)));				
				if(certEntry->GetThumbprint()->Length())
				{
					certEntry->SetThumbprintPresent();
				}

				certEntry->SetIsEnabledPresent();
				certEntry->SetIsEnabled(ETrue);

				aSettings.iCertificates.AppendL(certEntry);
				aSettings.iCertificatesPresent = ETrue;

				EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "EapTlsPeapUtils::GetConfigurationL(): Filling User cert entry, SubjectKeyID:",
					certEntry->GetSubjectKeyId().Ptr(),
					certEntry->GetSubjectKeyId().Length() ) );

				CleanupStack::Pop(certEntry);
			}
		} while (view.NextL() != EFalse);
	}
	
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	
	/////////////////
	// CA Certificates
	/////////////////

	sqlStatement.Format(KSQL,
		&cacerts, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());
	
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement)));
	
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());	
		
	// Get column set so we get the correct column numbers
	colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	if (view.FirstL())
	{		
		do {
			view.GetL();
			{	
				// This is big object.
				EapCertificateEntry * certEntry = new (ELeave) EapCertificateEntry;
				CleanupStack::PushL(certEntry);

				certEntry->SetCertType(EapCertificateEntry::ECA);
				
				certEntry->GetSubjectNameWritable()->Copy(view.ColDes(colSet->ColNo(KSubjectName)));
				if(certEntry->GetSubjectName()->Length())
				{
					certEntry->SetSubjectNamePresent();
				}
				
				certEntry->GetIssuerNameWritable()->Copy(view.ColDes(colSet->ColNo(KIssuerName)));
				if(certEntry->GetIssuerName()->Length())
				{
					certEntry->SetIssuerNamePresent();
				}

				certEntry->GetSerialNumberWritable()->Copy(view.ColDes(colSet->ColNo(KSerialNumber)));
				if(certEntry->GetSerialNumber()->Length())
				{
					certEntry->SetSerialNumberPresent();
				}

				certEntry->GetSubjectKeyIdWritable()->Copy(view.ColDes8(colSet->ColNo(KActualSubjectKeyIdentifier))); // This is the subjectkey id we got in SetConfigurationL
				if(certEntry->GetSubjectKeyId().Length())
				{
					certEntry->SetSubjectKeyIdPresent();
				}

				certEntry->GetThumbprintWritable()->Copy(view.ColDes8(colSet->ColNo(KThumbprint)));				
				if(certEntry->GetThumbprint()->Length())
				{
					certEntry->SetThumbprintPresent();
				}
				
				certEntry->SetIsEnabledPresent();
				certEntry->SetIsEnabled(ETrue);

				aSettings.iCertificates.AppendL(certEntry);
				aSettings.iCertificatesPresent = ETrue;

				EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "EapTlsPeapUtils::GetConfigurationL(): Filling CA cert entry, SubjectKeyID:",
					certEntry->GetSubjectKeyId().Ptr(),
					certEntry->GetSubjectKeyId().Length() ) );

				EAP_TRACE_SETTINGS(certEntry);

				CleanupStack::Pop(certEntry);
			}
		} while (view.NextL() != EFalse);
	}
	
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);

	//////////////////////	
	// Encapsulated types
	//////////////////////
	
	// Encapsulated types are only for EAP-PEAP, EAP-TTLS and EAP-FAST. Not for EAP-TLS.
	if ( aEapType != eap_type_peap 
		 && aEapType != eap_type_ttls
#ifdef USE_FAST_EAP_TYPE
		 && aEapType != eap_type_fast
#endif		 
		 )
	{
		aSettings.iEnabledEncapsulatedEAPExpandedTypesPresent = EFalse;
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL(): End - Since no encapsulated type for the EAP-type=0xfe%06x%08x\n"),
			aEapType.get_vendor_id(),
			aEapType.get_vendor_type()));
		
		return; // No need to proceed. Nothing more to provide.
	}

	RPointerArray<TEapExpandedType> enabledEAPTypes;
	RPointerArray<TEapExpandedType> disabledEAPTypes;
	
	TRAPD(error, GetTunnelingExpandedEapDataL(
			aDatabase, 
			0, 
			enabledEAPTypes,
			disabledEAPTypes, 
			aIndexType,
			aIndex,
			aTunnelingType,
			aEapType));
			
	if( error != KErrNone )
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::GetConfigurationL(): ########### Getting Expanded Tunneling types from the DB failed ############ \n") ) );

		enabledEAPTypes.ResetAndDestroy();
		disabledEAPTypes.ResetAndDestroy();
		enabledEAPTypes.Close();
		disabledEAPTypes.Close();

		User::Leave(KErrGeneral);
	}


	{
		RPointerArray<TEapExpandedType> aPlugins;

		// This works if we do not leave from the block.
		PointerArrayResetAndDestroy<TEapExpandedType> aAutomaticPlugins(&aPlugins, EFalse);

		EapPluginTools aPluginTool;

		TEapExpandedType aSymbTunnelingType;
    
		error = CEapConversion::ConvertInternalTypeToExpandedEAPType(
			&aEapType,
			&aSymbTunnelingType);

		if (error == KErrNone)
		{
			TRAP(error, (aPluginTool.ListAllEapPluginsL(aIndexType, aSymbTunnelingType, aPlugins)));
			if (error != KErrNone)
			{
				EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::GetConfigurationL(): aPluginTool.ListAllEapPluginsL() failed, EAP-type=0xfe%06x%08x, index_type=%d, index=%d, error=%d.\n"),
					aEapType.get_vendor_id(),
					aEapType.get_vendor_type(),
					aIndexType,
					aIndex,
					error));
			}
		}

		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::GetConfigurationL(): ListImplementationsL(): No: of available EAP plugin implementations=%d, enabledEAPTypes.Count()=%d, disabledEAPTypes.Count()=%d\n"),
		 	aPlugins.Count(),
			enabledEAPTypes.Count(),
			disabledEAPTypes.Count()));

		if (error == KErrNone)
		{
			// Filter out unimplemented enabled EAP-methods.
			error = FilterEapMethods(
				&enabledEAPTypes,
				&aPlugins);
		}

		if (error == KErrNone)
		{
			// Filter out unimplemented disabled EAP-methods.
			error = FilterEapMethods(
				&disabledEAPTypes,
				&aPlugins);
		}

		if (error == KErrNone)
		{
			// Add rest of the implemented EAP-methods to array of disabled EAP-methods.
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("EapTlsPeapUtils::GetConfigurationL(): ListImplementationsL(): Before adding disabled, No: of available EAP plugin implementations=%d, enabledEAPTypes.Count()=%d, disabledEAPTypes.Count()=%d\n"),
		 		aPlugins.Count(),
				enabledEAPTypes.Count(),
				disabledEAPTypes.Count()));

			for (TInt plugin_ind = 0; plugin_ind < aPlugins.Count(); ++plugin_ind)
			{
				const TEapExpandedType * const plugin_type = aPlugins[plugin_ind];
				if (plugin_type == 0)
				{
					error = KErrNoMemory;
					break;
				}

				TEapExpandedType * const disabled_eap_type = new TEapExpandedType;
				if (disabled_eap_type != 0)
				{
					*disabled_eap_type = *plugin_type;

					EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL(): Adds disabled EAP-type=0xfe%06x%08x\n"),
						disabled_eap_type->GetVendorId(),
						disabled_eap_type->GetVendorType()));

					error = disabledEAPTypes.Append( disabled_eap_type );
					if (error != KErrNone)
					{
						break;
					}
				}
			} // for()

		}

		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::GetConfigurationL(): ListImplementationsL(): After adding disabled, No: of available EAP plugin implementations=%d, enabledEAPTypes.Count()=%d, disabledEAPTypes.Count()=%d\n"),
		 	aPlugins.Count(),
			enabledEAPTypes.Count(),
			disabledEAPTypes.Count()));

	}

	// This leave must be outside the previous block.
	User::LeaveIfError(error);


	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL(): No: of available tunneled types for this EAP=%d \n"),
		enabledEAPTypes.Count()));

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL(): No: of disabled tunneled types for this EAP=%d \n"),
		disabledEAPTypes.Count()));

	// enabledEAPTypes contains the EAP types now (expanded).
	// Fill aSettings.iEnabledEncapsulatedEAPExpandedTypes here.

	{
		TEapExpandedType EapType;

		for (TInt i = 0; i < enabledEAPTypes.Count(); i++)
		{
			error = EapType.SetValue(
				enabledEAPTypes[i]->GetValue().Ptr(),
				enabledEAPTypes[i]->GetValue().Length());
			if (error != KErrNone)
			{
				enabledEAPTypes.ResetAndDestroy();
				disabledEAPTypes.ResetAndDestroy();
				enabledEAPTypes.Close();
				disabledEAPTypes.Close();

				User::Leave(KErrNoMemory);				
			}

			error = aSettings.iEnabledEncapsulatedEAPExpandedTypes.Append(EapType);
			if (error != KErrNone)
			{
				enabledEAPTypes.ResetAndDestroy();
				disabledEAPTypes.ResetAndDestroy();
				enabledEAPTypes.Close();
				disabledEAPTypes.Close();

				User::Leave(KErrNoMemory);				
			}

			EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL(): enabled EAP-type=0xfe%06x%08x\n"),
				EapType.GetVendorId(),
				EapType.GetVendorType()));
		}

		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::GetConfigurationL(): aSettings.iEnabledEncapsulatedEAPExpandedTypes.Count()=%d \n"),
			aSettings.iEnabledEncapsulatedEAPExpandedTypes.Count()));

		aSettings.iEnabledEncapsulatedEAPExpandedTypesPresent = ETrue;
		
	}

	{
		TEapExpandedType EapType;

		for (TInt i = 0; i < disabledEAPTypes.Count(); i++)
		{
			error = EapType.SetValue(
				disabledEAPTypes[i]->GetValue().Ptr(),
				disabledEAPTypes[i]->GetValue().Length());
			if (error != KErrNone)
			{
				enabledEAPTypes.ResetAndDestroy();
				disabledEAPTypes.ResetAndDestroy();
				enabledEAPTypes.Close();
				disabledEAPTypes.Close();

				User::Leave(KErrNoMemory);				
			}

			error = aSettings.iDisabledEncapsulatedEAPExpandedTypes.Append(EapType);
			if (error != KErrNone)
			{
				enabledEAPTypes.ResetAndDestroy();
				disabledEAPTypes.ResetAndDestroy();
				enabledEAPTypes.Close();
				disabledEAPTypes.Close();

				User::Leave(KErrNoMemory);				
			}

			EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL(): disabled EAP-type=0xfe%06x%08x\n"),
				EapType.GetVendorId(),
				EapType.GetVendorType()));
		}

		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::GetConfigurationL(): aSettings.iDisabledEncapsulatedEAPExpandedTypes.Count()=%d \n"),
			aSettings.iDisabledEncapsulatedEAPExpandedTypes.Count()));

		aSettings.iDisabledEncapsulatedEAPExpandedTypesPresent = ETrue;
		
	}

	EAP_TRACE_SETTINGS(&aSettings);

	enabledEAPTypes.ResetAndDestroy();
	disabledEAPTypes.ResetAndDestroy();
	enabledEAPTypes.Close();
	disabledEAPTypes.Close();


} // EapTlsPeapUtils::GetConfigurationL()

// ---------------------------------------------------------

void EapTlsPeapUtils::CopySettingsL(
	RDbNamedDatabase& aDatabase,
	const TDesC& aTableName,
	const TIndexType aSrcIndexType,
	const TInt aSrcIndex,
	const eap_type_value_e aSrcTunnelingType,
	const TIndexType aDestIndexType,
	const TInt aDestIndex,
	const eap_type_value_e aDestTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CopySettingsL(): -Start- aSrcIndexType=%d, aSrcIndex=%d, aSrcTunnelingType=0xfe%06x%08x\n"),
		aSrcIndexType,
		aSrcIndex,
		aSrcTunnelingType.get_vendor_id(),
		aSrcTunnelingType.get_vendor_type()));
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::CopySettingsL(): -Start- aDestIndexType=%d, aDestTunnelingType=0xfe%06x%08x\n"),
		aDestIndexType,
		aDestIndex,
		aDestTunnelingType.get_vendor_id(),
		aDestTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::CopySettingsL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL,
		&aTableName, 
		&KServiceType,
		aDestIndexType,
		&KServiceIndex,
		aDestIndex,
		&KTunnelingTypeVendorId,
		aSrcTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aSrcTunnelingType.get_vendor_type());
	
	RDbView view;
	
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EUpdatable));
	
	// View must be closed when no longer needed
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());

	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	if (view.FirstL())
	{
		do
  		{
	  		view.GetL();

			if (view.ColUint(colSet->ColNo(KServiceType)) == static_cast<TUint>(aDestIndexType)
				&& view.ColUint(colSet->ColNo(KServiceIndex)) == static_cast<TUint>(aDestIndex)
				&& view.ColUint(colSet->ColNo(KTunnelingTypeVendorId)) == aDestTunnelingType.get_vendor_id()
				&& view.ColUint(colSet->ColNo(KTunnelingType)) == aDestTunnelingType.get_vendor_type())
				{  		
      				EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::CopySettingsL - Delete old records\n") ) );
      				view.DeleteL();
    			}
		} while (view.NextL() != EFalse);
	}
	
	view.Close();
	CleanupStack::PopAndDestroy(2); // view, colset
	
  	sqlStatement.Format(KSQL,
		&aTableName, 
        &KServiceType,
		aSrcIndexType,
		&KServiceIndex,
		aSrcIndex,
		&KTunnelingTypeVendorId,
		aSrcTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aSrcTunnelingType.get_vendor_type());

  	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited , RDbView::EUpdatable));

	// View must be closed when no longer needed
	CleanupClosePushL(view);

  	User::LeaveIfError(view.EvaluateAll());

	// Get column set so we get the correct column numbers
	colSet = view.ColSetL();
	CleanupStack::PushL(colSet);
			
	TDbBookmark bookmark;

	if (view.FirstL())
	{		
		do {
			// Get the next line
			view.GetL();

			// Check if it was already copied			
			if (view.ColUint(colSet->ColNo(KServiceType)) != static_cast<TUint>(aDestIndexType)
				|| view.ColUint(colSet->ColNo(KServiceIndex)) != static_cast<TUint>(aDestIndex)
				|| view.ColUint(colSet->ColNo(KTunnelingTypeVendorId)) != aDestTunnelingType.get_vendor_id()
				|| view.ColUint(colSet->ColNo(KTunnelingType)) != aDestTunnelingType.get_vendor_type())
			{
				bookmark = view.Bookmark();
				
				view.InsertCopyL();
				
				view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(aDestIndexType));
	    		view.SetColL(colSet->ColNo(KServiceIndex), static_cast<TUint>(aDestIndex));
				view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aDestTunnelingType.get_vendor_id());
				view.SetColL(colSet->ColNo(KTunnelingType), aDestTunnelingType.get_vendor_type());
				
				view.PutL();
			
				view.GotoL(bookmark);
			}
		} while (view.NextL() != EFalse);
	}
	else
		{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::CopySettingsL - Nothing to Copy\n")));
		
		}
	
	view.Close();
	
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);

} // EapTlsPeapUtils::CopySettingsL()


// ---------------------------------------------------------
// EapTlsPeapUtils::DeleteConfigurationL()
// ---------------------------------------------------------
//
void EapTlsPeapUtils::DeleteConfigurationL(	
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::DeleteConfigurationL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x, aEapType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type(),
		aEapType.get_vendor_id(),
		aEapType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::DeleteConfigurationL()\n"));
	
	TPtrC dbname;
	TPtrC settings;
	TPtrC usercerts;
	TPtrC cacerts;
	TPtrC ciphersuites;

#ifdef USE_FAST_EAP_TYPE
	TPtrC fastSpecialSettings;
#endif
	
	if (aEapType == eap_type_tls)
	{
		dbname.Set(KTlsDatabaseName);
		settings.Set(KTlsDatabaseTableName);
		usercerts.Set(KTlsAllowedUserCertsDatabaseTableName);
		cacerts.Set(KTlsAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KTlsAllowedCipherSuitesDatabaseTableName);
	}
	else if (aEapType == eap_type_peap)
	{
		dbname.Set(KPeapDatabaseName);
		settings.Set(KPeapDatabaseTableName);
		usercerts.Set(KPeapAllowedUserCertsDatabaseTableName);
		cacerts.Set(KPeapAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KPeapAllowedCipherSuitesDatabaseTableName);
	}
	else if (aEapType == eap_type_ttls)
	{
		dbname.Set(KTtlsDatabaseName);
		settings.Set(KTtlsDatabaseTableName);
		usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
		cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
	}
#ifdef USE_FAST_EAP_TYPE
	else if (aEapType == eap_type_fast)
	{
		dbname.Set(KFastDatabaseName);
		settings.Set(KFastGeneralSettingsDBTableName); // This is general settings for FAST.
		fastSpecialSettings.Set(KFastSpecialSettingsDBTableName);
		
		usercerts.Set(KFastAllowedUserCertsDatabaseTableName);
		cacerts.Set(KFastAllowedCACertsDatabaseTableName);
		ciphersuites.Set(KFastAllowedCipherSuitesDatabaseTableName);
	}
#endif
	else if (aEapType == eap_expanded_type_ttls_plain_pap.get_type())
	{
		dbname.Set( KTtlsDatabaseName );
		settings.Set( KTtlsDatabaseTableName );
	}
	else
	{
		// Should never happen
		User::Leave(KErrArgument);
	}	

	RDbNamedDatabase aDatabase;
	RFs aFileServerSession;

	TInt error(KErrNone);
	TFileName aPrivateDatabasePathName;
	
	error = aFileServerSession.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL(): - aFileServerSession.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	EapPluginTools::CreateDatabaseLC(
		aDatabase,
		aFileServerSession,
		error,
		dbname,
		aPrivateDatabasePathName);

	if(error == KErrNone)
	{
		// Database was created so it was empty. No need for further actions.
		aDatabase.Destroy();
		CleanupStack::PopAndDestroy(&aDatabase);
		CleanupStack::PopAndDestroy(&aFileServerSession);
		return;
	}
	else if (error != KErrAlreadyExists) 
	{
		User::LeaveIfError(error);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL(): - calls aDatabase.Open()\n")));

	error = aDatabase.Open(aFileServerSession, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL(): - Opened private DB for %S. error=%d\n"),
		&dbname,
		error));

	User::LeaveIfError(error);


	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::DeleteConfigurationL - Deleting the tables\n")));

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	
	//--------------------- Deletion 1 ----------------------------//
	
	// For all EAPs delete the settings table. 
	// For EAP-FAST, this is delting the general settings table.
	
	sqlStatement.Format(KSQL,
		&settings, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());
	
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());

	// Delete rows
	if (view.FirstL())
	{
		do {
			view.DeleteL();
		} while (view.NextL() != EFalse);
	}
	
	CleanupStack::PopAndDestroy(&view);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL(): Deleted %s (general) settings table"), settings.Ptr()));	

	//////////////////////////////////////////
	// This is only for plain PAP settings. //
	//////////////////////////////////////////
	if ( aEapType == eap_expanded_type_ttls_plain_pap.get_type() )
	{
		CleanupStack::PopAndDestroy(buf);
		CleanupStack::PopAndDestroy(&aDatabase);
		CleanupStack::PopAndDestroy(&aFileServerSession);
        EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL(): Return PAP")));	
        // we return here in case of pap because there is nothing to do else.
        return;
	}
	
	//--------------------- Deletion 2 ----------------------------//
	
	// For all EAPs delete the User cert table
	//	KSQL2 is "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d"
	
	sqlStatement.Format(KSQL,
		&usercerts, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());

	// Evaluate view
	
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	if (view.FirstL())
	{
		do {
			view.DeleteL();
		} while (view.NextL() != EFalse);
	}

	CleanupStack::PopAndDestroy(&view);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL(): Deleted USER certs table")));	

	//--------------------- Deletion 3 ----------------------------//
	
	// For all EAPs delete the CA cert table

	//	KSQL3 is "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d"
	
	sqlStatement.Format(KSQL,
		&cacerts, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());
	
	// Evaluate view
	
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	if (view.FirstL())
	{
		do {
			view.DeleteL();
		} while (view.NextL() != EFalse);
	}

	CleanupStack::PopAndDestroy(&view);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL(): Deleted CA certs table")));

	//--------------------- Deletion 4 ----------------------------//
	
	// For all EAPs delete the Cipher suite table

	//	KSQL4 is "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d"
	
	sqlStatement.Format(KSQL,
		&ciphersuites, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());

	// Evaluate view
	
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	if (view.FirstL())
	{
		do {
			view.DeleteL();
		} while (view.NextL() != EFalse);
	}
	
	CleanupStack::PopAndDestroy(&view);
		
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL(): Deleted cipher suits table")));	

	
#ifdef USE_FAST_EAP_TYPE	

	if(aEapType == eap_type_fast)
	{
		//--------------------- Deletion 5 ----------------------------//
		
		// For EAP-FAST, delete the special settings table
		
		sqlStatement.Format(KSQL,
			&fastSpecialSettings, 
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex,
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());
	
		// Evaluate view
		
		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
		CleanupClosePushL(view);
		User::LeaveIfError(view.EvaluateAll());
		
		if (view.FirstL())
		{
			do {
				view.DeleteL();
			} while (view.NextL() != EFalse);
		}
		
		CleanupStack::PopAndDestroy(&view);
			
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL(): Deleted EAP-FAST Special settings table")));	
				
	} // End: if(aEapVendorType == eap_type_fast)

#endif // End: #ifdef USE_FAST_EAP_TYPE	

	CleanupStack::PopAndDestroy(buf);
	CleanupStack::PopAndDestroy(&aDatabase);
	CleanupStack::PopAndDestroy(&aFileServerSession);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL: End")));	

} // EapTlsPeapUtils::DeleteConfigurationL()


// ---------------------------------------------------------
// EapTlsPeapUtils::AddExtraCertColumnsL()
// ---------------------------------------------------------
//
void EapTlsPeapUtils::AddExtraCertColumnsL(
	RDbNamedDatabase& aDatabase, 
	TDesC& aTableName)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::AddExtraCertColumnsL(): -Start- aTableName=\"%S\"\n"),
		&aTableName));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::AddExtraCertColumnsL()\n"));
	
	// Check if the EXTRA cert columns are already in the table.
	
	CDbColSet* colSetCertTable = aDatabase.ColSetL(aTableName);
	User::LeaveIfNull(colSetCertTable);
	CleanupStack::PushL(colSetCertTable);	
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::AddExtraCertColumnsL(): - Number of columns in %S table before addition=%d\n"),
		&aTableName,
		colSetCertTable->Count()));
		
	// Check if there is a column for Serial Number, for example.
	if(colSetCertTable->ColNo(KSerialNumber) == KDbNullColNo)
	{
		// The column is missing. Add all the EXTRA columns to the table.

		// EXTRA COLUMNS
		//// NAME //////////////// TYPE //////////// Constant /////////////////////
		//| ActualSubjectKeyId  | BINARY(20)	| KActualSubjectKeyIdentifier |//
		//| SubjectName			| VARCHAR(255)  | KSubjectName        |//	
		//| IssuerName			| VARCHAR(255)  | KIssuerName        |//	
		//| SerialNumber		| VARCHAR(255)  | KSerialNumber        |//	
		//| Thumbprint			| BINARY(64)	| KThumbprint        |//	
		//////////////////////////////////////////////////////////////////////////////
			
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::AddExtraCertColumnsL(): - EXTRA cert columns missing from the table %S. Adding now.\n"),
			&aTableName));			

		HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
		TPtr sqlStatement = buf->Des();
		
		_LIT(KSQLAlterTableForBin, "ALTER TABLE %S ADD %S BINARY(%d)");											 
	
		sqlStatement.Format(KSQLAlterTableForBin,
			&aTableName, 
			&KActualSubjectKeyIdentifier,
			KKeyIdentifierLength);
			
		User::LeaveIfError( aDatabase.Execute(sqlStatement));

		_LIT(KSQLAlterTableForVarChar, "ALTER TABLE %S ADD %S VARCHAR(%d)");											 
	
		sqlStatement.Format(KSQLAlterTableForVarChar,
			&aTableName, 
			&KSubjectName,
			KGeneralStringMaxLength);
			
		User::LeaveIfError( aDatabase.Execute(sqlStatement));

		sqlStatement.Format(KSQLAlterTableForVarChar,
			&aTableName, 
			&KIssuerName,
			KGeneralStringMaxLength);
			
		User::LeaveIfError( aDatabase.Execute(sqlStatement));
	
		sqlStatement.Format(KSQLAlterTableForVarChar,
			&aTableName, 
			&KSerialNumber,
			KGeneralStringMaxLength);
			
		User::LeaveIfError( aDatabase.Execute(sqlStatement));
	
		sqlStatement.Format(KSQLAlterTableForBin,
			&aTableName, 
			&KThumbprint,
			KThumbprintMaxLength);
			
		User::LeaveIfError( aDatabase.Execute(sqlStatement));
	
		CleanupStack::PopAndDestroy(buf);
	}

	CleanupStack::PopAndDestroy(colSetCertTable);

	CDbColSet* colSetCertTableAfterAdd = aDatabase.ColSetL(aTableName);
	User::LeaveIfNull(colSetCertTableAfterAdd);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::AddExtraCertColumnsL(): - Number of columns in %S table after addition=%d\n"),
		&aTableName,
		colSetCertTableAfterAdd->Count()));
	
	delete colSetCertTableAfterAdd;

} // EapTlsPeapUtils::AddExtraCertColumnsL()

	
// ---------------------------------------------------------
// EapTlsPeapUtils::GetEapSettingsDataL()
// ---------------------------------------------------------
//
void EapTlsPeapUtils::GetEapSettingsDataL(
	RDbNamedDatabase& aDatabase,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType,
	const TDesC& aDbColumnName,
	eap_variable_data_c * const aDbColumnValue)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::GetEapSettingsDataL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x, aEapType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type(),
		aEapType.get_vendor_id(),
		aEapType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::GetEapSettingsDataL()\n"));
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetEapSettingsDataL Get Column Name:%S \n"),
		&aDbColumnName));	

	TBufC<KMaxEapDbTableNameLength> generalSettingsTableName;
	
#if defined (USE_FAST_EAP_TYPE)	
	TBufC<KMaxEapDbTableNameLength> specialSettingsTableName;
#endif

	// Set the database table name based on the type
	if (aEapType == eap_type_tls)
	{
		generalSettingsTableName = KTlsDatabaseTableName;
	}
	else if (aEapType == eap_type_peap)
	{
		generalSettingsTableName = KPeapDatabaseTableName;	
	}
	else if (aEapType == eap_type_ttls
		|| aEapType == eap_expanded_type_ttls_plain_pap.get_type())
	{
		generalSettingsTableName = KTtlsDatabaseTableName;
	}
#if defined (USE_FAST_EAP_TYPE)
	else if (aEapType == eap_type_fast)
	{
		generalSettingsTableName = KFastGeneralSettingsDBTableName; // General settings
		specialSettingsTableName = KFastSpecialSettingsDBTableName; // Special settings  for only FAST
	}
#endif // #if defined (USE_FAST_EAP_TYPE)
	else
	{
		// Unsupported EAP type		
		// Should never happen
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::GetEapSettingsDataL(): Unsupported EAP type=0xfe%06x%08x"),
			aEapType.get_vendor_id(),
			aEapType.get_vendor_type()));

		User::Leave(KErrArgument);
	}
	
	if(aDbColumnName.Size() <= 0)	
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::GetEapSettingsDataL(): No Column Name!\n")));
		
		User::Leave(KErrArgument);
	}
	
	// Now do the database query
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");	
	
#if defined(USE_FAST_EAP_TYPE)
	
	// Unlike other EAP types, EAP-FAST has some settings in special settings table
	// (in KFastSpecialSettingsDBTableName)
	
	if(aEapType == eap_type_fast
	   && ((aDbColumnName.Compare(cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal) == 0)
	   || (aDbColumnName.Compare(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal) == 0)
	   || (aDbColumnName.Compare(KFASTWarnADHPNoPAC) == 0)
	   || (aDbColumnName.Compare(KFASTWarnADHPNoMatchingPAC) == 0)
	   || (aDbColumnName.Compare(KFASTWarnNotDefaultServer) == 0)
	   || (aDbColumnName.Compare(KFASTPACGroupImportReferenceCollection) == 0)
	   || (aDbColumnName.Compare(KFASTPACGroupDBReferenceCollection) == 0)))
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::GetEapSettingsDataL: This field will be read from EAP-FAST's special table")));

		sqlStatement.Format(KSQLQueryRow,
			&aDbColumnName,
			&specialSettingsTableName, 
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex,
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	}
	else
	{
		sqlStatement.Format(KSQLQueryRow,
			&aDbColumnName,
			&generalSettingsTableName, 
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex,
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	}

#else

	{
		sqlStatement.Format(KSQLQueryRow,
			&aDbColumnName,
			&generalSettingsTableName, 
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex,
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	}

#endif // End: #if defined(USE_FAST_EAP_TYPE)	

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetEapSettingsDataL - SQL query formated OK")));

	RDbView view;
	
	User::LeaveIfError(view.Prepare(
			aDatabase, 
			TDbQuery(sqlStatement), 
			TDbWindow::EUnlimited,
			RDbView::EReadOnly));	
		
    CleanupStack::PopAndDestroy(buf); // We don't need buf or sqlStatement any more.
    
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	
	eap_status_e status(eap_status_ok);
			
	if (view.FirstL())
	{
		view.GetL();
					
		switch (view.ColType(KDefaultColumnInView_One))
		{
		case EDbColText:				
			{
			EAP_TRACE_DEBUG_SYMBIAN(
					(_L("EapTlsPeapUtils::GetEapSettingsDataL: EDbColText\n")));	
		    if ( !view.IsColNull( KDefaultColumnInView_One ) )
		    	{
			    status = aDbColumnValue->set_copy_of_buffer(
				    view.ColDes(KDefaultColumnInView_One).Ptr(),
				    view.ColDes(KDefaultColumnInView_One).Size());
		    	}
		    else
		    	{
		    	aDbColumnValue->reset();
		    	}
     		}
			break;

		case EDbColBinary:
			{				
			EAP_TRACE_DEBUG_SYMBIAN(
					(_L("EapTlsPeapUtils::GetEapSettingsDataL: EDbColBinary\n")));
			if ( !view.IsColNull( KDefaultColumnInView_One ) )
		    	{			
		    	status = aDbColumnValue->set_copy_of_buffer(
		    		view.ColDes8(KDefaultColumnInView_One).Ptr(),
					view.ColDes8(KDefaultColumnInView_One).Size());
		    	}
		    else
		    	{
		    	aDbColumnValue->reset();
		    	}
			}
			break;
			
		case EDbColUint32:
			{
			EAP_TRACE_DEBUG_SYMBIAN(
					(_L("EapTlsPeapUtils::GetEapSettingsDataL: EDbColUint32\n")));			
		    if ( !view.IsColNull( KDefaultColumnInView_One ) )
		    	{			
			    TUint value;
				value = view.ColUint32(KDefaultColumnInView_One);
				status = aDbColumnValue->set_copy_of_buffer(&value, sizeof(value));
		    	}
		    else
		    	{
		    	aDbColumnValue->reset();
		    	}
		    }
			break;
			
		case EDbColInt64:
			{
			EAP_TRACE_DEBUG_SYMBIAN(
					(_L("EapTlsPeapUtils::GetEapSettingsDataL: EDbColInt64\n")));			
		    if ( !view.IsColNull( KDefaultColumnInView_One ) )
		    	{			
			    TInt64 value;
				value = view.ColInt64(KDefaultColumnInView_One);
				status = aDbColumnValue->set_copy_of_buffer(&value, sizeof(value));
		    	}
		    else
		    	{
		    	aDbColumnValue->reset();
		    	}
			}
			break;
			
		case EDbColLongBinary:
			{
			// This needs special handling. (readstream). Not needed in this DB yet.	
				EAP_TRACE_DEBUG_SYMBIAN(
					(_L("EapTlsPeapUtils::GetEapSettingsDataL: ERROR: EDbColLongBinary not supported in this DB!\n")));	
				
				User::Leave(KErrNotSupported);
			}
			break;			
			
		default:
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("EapTlsPeapUtils::GetEapSettingsDataL: ERROR: Unsupported DB field! \n")));	
			
			User::Leave(KErrNotSupported);
			break;
		}
	}

	CleanupStack::PopAndDestroy( &view );
	
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetEapSettingsDataL: Status=%d\n"), status));
	}
	
	EAP_TRACE_DATA_DEBUG_SYMBIAN(("GetEapSettingsDataL:DbColumnValue:",
		aDbColumnValue->get_data(aDbColumnValue->get_data_length()),
		aDbColumnValue->get_data_length()));

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetEapSettingsDataL: End \n")));

} // EapTlsPeapUtils::GetEapSettingsDataL()


// ---------------------------------------------------------
// EapTlsPeapUtils::SetEapSettingsDataL()
// ---------------------------------------------------------
//
void EapTlsPeapUtils::SetEapSettingsDataL(
	RDbNamedDatabase& aDatabase,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType,
	const TDesC& aDbColumnName,
	const eap_variable_data_c * const aDbColumnValue)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetEapSettingsDataL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x, aEapType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type(),
		aEapType.get_vendor_id(),
		aEapType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::SetEapSettingsDataL()\n"));
	
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetEapSettingsDataL Set Column Name:%S \n"),
		&aDbColumnName));	

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("SetEapSettingsDataL:DbColumnValue:",
		aDbColumnValue->get_data(aDbColumnValue->get_data_length()),
		aDbColumnValue->get_data_length()));
	
	TBufC<KMaxEapDbTableNameLength> generalSettingsTableName;
	
#if defined (USE_FAST_EAP_TYPE)	
	TBufC<KMaxEapDbTableNameLength> specialSettingsTableName;
#endif

	// Set the database table name based on the type
	if (aEapType == eap_type_tls)
	{
		generalSettingsTableName = KTlsDatabaseTableName;
	}
	else if (aEapType == eap_type_peap)
	{
		generalSettingsTableName = KPeapDatabaseTableName;
	}
	else if (aEapType == eap_type_ttls
		|| aEapType == eap_expanded_type_ttls_plain_pap.get_type())
	{
		generalSettingsTableName = KTtlsDatabaseTableName;
	}
#if defined (USE_FAST_EAP_TYPE)
	else if (aEapType == eap_type_fast)
	{
		generalSettingsTableName = KFastGeneralSettingsDBTableName; // General settings
		specialSettingsTableName = KFastSpecialSettingsDBTableName; // Special settings  for only FAST
	}
#endif // #if defined (USE_FAST_EAP_TYPE)
	else
	{
		// Unsupported EAP type		
		// Should never happen
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetEapSettingsDataL(): Unsupported EAP-type=0xfe%06x%08x"),
			aEapType.get_vendor_id(),
			aEapType.get_vendor_type()));

		User::Leave(KErrArgument);
	}

	if(aDbColumnName.Size() <= 0)	
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetEapSettingsDataL(): No Column Name!\n")));
		
		User::Leave(KErrArgument);
	}
	
	// Now do the database query
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");	
	
#if defined(USE_FAST_EAP_TYPE)
	
	// Unlike other EAP types, EAP-FAST has some settings in special settings table
	// (in KFastSpecialSettingsDBTableName)
	
	if(aEapType == eap_type_fast
	   && ((aDbColumnName.Compare(cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal) == 0)
	   || (aDbColumnName.Compare(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal) == 0)
	   || (aDbColumnName.Compare(KFASTWarnADHPNoPAC) == 0)
	   || (aDbColumnName.Compare(KFASTWarnADHPNoMatchingPAC) == 0)
	   || (aDbColumnName.Compare(KFASTWarnNotDefaultServer) == 0)
	   || (aDbColumnName.Compare(KFASTPACGroupImportReferenceCollection) == 0)
	   || (aDbColumnName.Compare(KFASTPACGroupDBReferenceCollection) == 0)))
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::SetEapSettingsDataL: This field will be read from EAP-FAST's special table")));

		sqlStatement.Format(KSQLQueryRow,
			&aDbColumnName,
			&specialSettingsTableName, 
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex,
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	}
	else
	{
		sqlStatement.Format(KSQLQueryRow,
			&aDbColumnName,
			&generalSettingsTableName, 
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex,
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	}

#else

	{
		sqlStatement.Format(KSQLQueryRow,
			&aDbColumnName,
			&generalSettingsTableName, 
			&KServiceType,
			aIndexType,
			&KServiceIndex,
			aIndex,
			&KTunnelingTypeVendorId,
			aTunnelingType.get_vendor_id(),
			&KTunnelingType, 
			aTunnelingType.get_vendor_type());		
	}

#endif // End: #if defined(USE_FAST_EAP_TYPE)	

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetEapSettingsDataL - SQL query formated OK")));

	RDbView view;
	
	User::LeaveIfError(view.Prepare(
			aDatabase, 
			TDbQuery(sqlStatement), 
			TDbWindow::EUnlimited,
			RDbView::EUpdatable));
	
	CleanupStack::PopAndDestroy(buf); // We don't need buf or sqlStatement any more.
   
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	
	if (view.FirstL())
	{
		view.UpdateL(); // Here it is update.
				
		if(view.ColCount() == KDefaultColumnInView_One)
		{
			// There should be one column (only one) with the specified column name.
			
			HBufC8* dbColVal8 = HBufC8::NewLC(aDbColumnValue->get_data_length());			
			TPtr8 dbColValPtr8 = dbColVal8->Des();

			dbColValPtr8.Copy(
				aDbColumnValue->get_data( aDbColumnValue->get_data_length() ),
				aDbColumnValue->get_data_length() );
			
			switch (view.ColType(KDefaultColumnInView_One))
			{
			case EDbColText:				
				{
					TPtr dbColValPtr(0,dbColValPtr8.Size());
					dbColValPtr.Copy(dbColValPtr8);

					view.SetColL(KDefaultColumnInView_One, dbColValPtr);
				}
				break;
	
			case EDbColBinary:
				{
					view.SetColL(KDefaultColumnInView_One, dbColValPtr8);
				}
				break;
				
			case EDbColUint32:
				{

#if defined (USE_FAST_EAP_TYPE)
					
					EAP_TRACE_DEBUG_SYMBIAN((_L("WARNING: eap_am_type_tls_peap_symbian_c::authentication_finishedL(): HACK to set Unauth Prov mode set to default (NO)!")));					
	
					view.SetColL(KDefaultColumnInView_One, EEapDbFalse);
				
#endif // End: #if defined (USE_FAST_EAP_TYPE)
				}
				break;
				
			case EDbColInt64:
				{
					// Do some lexical analysis to get TInt64 value here and set it in DB.
					
					EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetEapSettingsDataL(): EDbColInt64 not supported here yet!\n")));	
					
					User::Leave(KErrNotSupported);					
				}
				break;
				
			case EDbColLongBinary:
				{
					// This needs special handling. (readstream). Not needed in this DB yet.	
					EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetEapSettingsDataL(): EDbColLongBinary not supported in this DB!\n")));	
					
					User::Leave(KErrNotSupported);
				}
				break;			
				
			default:
				EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetEapSettingsDataL: Unsupported DB field! \n")));	
				
				User::Leave(KErrNotSupported);
				break;
			}
			
			CleanupStack::PopAndDestroy(dbColVal8);		
			
		} // End: if(view.ColCount() == KDefaultColumnInView_One)
		else
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapTlsPeapUtils::SetEapSettingsDataL(): Too many columns in DB view, count=%d \n"),
				view.ColCount()));	
			
			User::Leave(KErrNotFound);
		}
	} // End: if (view.FirstL())
	
	// Now it should go to the DB.
	view.PutL();	
	
	CleanupStack::PopAndDestroy( &view );	

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetEapSettingsDataL: End \n")));	
}

// ---------------------------------------------------------

/*
 * Alter table for added column, if doesn't exist
 * 
 */
void EapTlsPeapUtils::AlterTableL(
	RDbNamedDatabase& aDb,
	TAlterTableCmd aCmd,
	const TDesC& aTableName,
	const TDesC& aColumnName,
	const TDesC& aColumnDef )
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::AlterTableL(): -Start- aTableName=\"%S\", aColumnName=\"%S\", aColumnDef=\"%S\"\n"),
		&aTableName,
		&aColumnName,
		&aColumnDef));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapTlsPeapUtils::AlterTableL()\n"));

	CDbColSet* colSet = aDb.ColSetL( aTableName );
	User::LeaveIfNull( colSet );
	CleanupStack::PushL( colSet );	
		
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::AlterTableL() Number of columns in \"%S\" table is %d.\n" ),
		&aTableName,
		colSet->Count()));
	
	if ( aCmd == EAddColumn )
	    {
	    // Check if there is a target column
	    if( colSet->ColNo( aColumnName ) != KDbNullColNo )
	    	{
	    	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::AlterTableL() Column \"%S\" exists already in table \"%S\".\n" ),
	    		&aColumnName,
				&aTableName));
	    	CleanupStack::PopAndDestroy( colSet );
	    	return;
	    	}
	    }
	else
	    {
	    // Check if there is a target column
	    if( colSet->ColNo( aColumnName ) == KDbNullColNo )
	    	{
	    	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::AlterTableL() Column \"%S\" does not exists already in table \"%S\".\n" ),
	    		&aColumnName,
				&aTableName));
	    	CleanupStack::PopAndDestroy( colSet );
	    	return;
	    	}
	    }

	HBufC* buf = HBufC::NewLC( KMaxSqlQueryLength );
	TPtr sqlStatement = buf->Des();
		
	_LIT( KSqlAddCol, "ALTER TABLE %S ADD %S %S" );
	_LIT( KSqlRemoveCol, "ALTER TABLE %S DROP %S" );
	
	if ( aCmd == EAddColumn )
		{
		sqlStatement.Format(KSqlAddCol,
			&aTableName, 
			&aColumnName,
			&aColumnDef);
		}
	else
		{
		sqlStatement.Format(KSqlRemoveCol,
			&aTableName, 
		    &aColumnName);
		}
		
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::AlterTableL(): sqlStatement=%S\n"),
		&sqlStatement));
	
	User::LeaveIfError( aDb.Execute( sqlStatement ) );		
	CleanupStack::PopAndDestroy( buf );
	CleanupStack::PopAndDestroy( colSet );

	CDbColSet* alteredColSet = aDb.ColSetL( aTableName );
	User::LeaveIfNull( alteredColSet );

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::AlterTableL() Number of columns in %S table after adding is %d.\n" ),
		&aTableName,
		alteredColSet->Count()));

	delete alteredColSet;
		
} // EapTlsPeapUtils::AlterTableL()

// ---------------------------------------------------------

// End of file


