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
* %version: 76.1.1.1.6 %
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

#ifdef USE_FAST_EAP_TYPE
#include "pac_store_db_parameters.h"
#endif //#ifdef USE_FAST_EAP_TYPE

#include "eap_am_trace_symbian.h"
#include "EapTlsPeapCertFetcher.h"

const TUint KMaxSqlQueryLength = 2048;
const TInt	KMicroSecsInAMinute = 60000000; // 60000000 micro seconds is 1 minute.
const TInt	KDefaultColumnInView_One = 1; // For DB view.
const TInt 	KMaxEapDbTableNameLength = 64;
// ================= MEMBER FUNCTIONS =======================

void EapTlsPeapUtils::OpenDatabaseL(
	RDbNamedDatabase& aDatabase, 
	RDbs& aSession, 
	const TIndexType aIndexType,
	const TInt aIndex, 
	const eap_type_value_e aTunnelingType,
	eap_type_value_e aEapType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenDatabaseL -Start- aIndexType=%d, aIndex=%d, Tunneling vendor type=%d, Eap vendor type=%d \n"),
		aIndexType,aIndex, aTunnelingType.get_vendor_type(), aEapType.get_vendor_type()));
#else

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenDatabaseL -Start- aIndexType=%d, aIndex=%d, aTunnelingType=%d, aEapType=%d \n"),
		aIndexType,aIndex, aTunnelingType, aEapType));

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	if (aEapType == eap_type_tls)
	{
		OpenTlsDatabaseL(aDatabase, aSession, aIndexType, aIndex, aTunnelingType);
	} 
	else if (aEapType == eap_type_peap)
	{
		OpenPeapDatabaseL(aDatabase, aSession, aIndexType, aIndex, aTunnelingType);
	} 
#if defined(USE_TTLS_EAP_TYPE)
	else if (aEapType == eap_type_ttls)
	{
		OpenTtlsDatabaseL(aDatabase, aSession, aIndexType, aIndex, aTunnelingType);
	} 
#endif // #if defined(USE_TTLS_EAP_TYPE)
#if defined(USE_FAST_EAP_TYPE)
	else if (aEapType == eap_type_fast)
	{
		OpenFastDatabaseL(aDatabase, aSession, aIndexType, aIndex, aTunnelingType);
	} 
#endif // #if defined(USE_FAST_EAP_TYPE)
	
	else if ( aEapType == eap_type_ttls_plain_pap )
		{
		OpenTtlsDatabaseL( aDatabase, aSession, aIndexType, aIndex, aTunnelingType);
		}
	
	else
	{
		// Unsupported EAP type
		User::Leave(KErrNotSupported);
	}	
} // EapTlsPeapUtils::OpenDatabaseL()

void EapTlsPeapUtils::OpenTlsDatabaseL(
		RDbNamedDatabase& aDatabase, 
		RDbs& aSession, 
		const TIndexType aIndexType, 
		const TInt aIndex,
		const eap_type_value_e aTunnelingType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenTlsDatabaseL -Start- aIndexType=%d, aIndex=%d, Tunneling vendor type=%d \n"),
		aIndexType,aIndex, aTunnelingVendorType));

	// 1. Open/create a database	
	
	// Connect to the DBMS server.
	User::LeaveIfError(aSession.Connect());		
	CleanupClosePushL(aSession);	
	// aSession and aDatabase are pushed to the cleanup stack even though they may be member
	// variables of the calling class and would be closed in the destructor anyway. This ensures
	// that if they are not member variables they will be closed. Closing the handle twice
	// does no harm.	
	
#ifdef SYMBIAN_SECURE_DBMS
	
	// Create the secure shared database with the specified secure policy.
	// Database will be created in the data caging path for DBMS (C:\private\100012a5).
	
	TInt err = aDatabase.Create(aSession, KTlsDatabaseName, KSecureUIDFormat);
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTlsDatabaseL - Created Secure DB for eaptls.dat. err=%d\n"), err) );
	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	User::LeaveIfError(aDatabase.Open(aSession, KTlsDatabaseName, KSecureUIDFormat));
	CleanupClosePushL(aDatabase);		
		
#else
	// For non-secured database. The database will be created in the old location (c:\system\data).
	
	RFs fsSession;		
	User::LeaveIfError(fsSession.Connect());
	CleanupClosePushL(fsSession);	
	TInt err = aDatabase.Create(fsSession, KTlsDatabaseName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTlsDatabaseL - Created Non-Secure DB for eaptls.dat. err=%d\n"), err) );
	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	User::LeaveIfError(aDatabase.Open(fsSession, KTlsDatabaseName));
	
	CleanupStack::PopAndDestroy(); // close fsSession
	
	CleanupClosePushL(aDatabase);		
	    
#endif // #ifdef SYMBIAN_SECURE_DBMS

	// 2. Create the eaptls table to database (ignore error if exists)
	
// Table columns:
//// NAME ////////////////////////////////////////// TYPE //////////// Constant ////////////////////
//| ServiceType									| UNSIGNED INTEGER | KServiceType         |//
//| ServiceIndex								| UNSIGNED INTEGER | KServiceIndex        |//
//| TunnelingType								| UNSIGNED INTEGER | KTunnelingType		|//
//| EAP_TLS_PEAP_use_manual_realm				| UNSIGNED INTEGER | cf_str_EAP_TLS_PEAP_use_manual_realm_literal      |//
//| EAP_TLS_PEAP_manual_realm					| VARCHAR(255)     | cf_str_EAP_TLS_PEAP_manual_realm_literal				|//
//| EAP_TLS_PEAP_use_manual_username			| UNSIGNED INTEGER | cf_str_EAP_TLS_PEAP_use_manual_username_literal   |//
//| EAP_TLS_PEAP_manual_username				| VARCHAR(255)     | cf_str_EAP_TLS_PEAP_manual_username_literal			|//
//| EAP_TLS_PEAP_cipher_suite					| UNSIGNED INTEGER | cf_str_EAP_TLS_PEAP_cipher_suite_literal	    |//
//| EAP_TLS_server_authenticates_client			| UNSIGNED INTEGER | cf_str_TLS_server_authenticates_client_policy_in_client_literal |//
//| CA_cert_label								| VARCHAR(255)     | KCACertLabelOld	    |//
//| client_cert_label							| VARCHAR(255)     | KClientCertLabel	    |//
//| EAP_TLS_PEAP_saved_session_id				| BINARY(32)       | cf_str_EAP_TLS_PEAP_saved_session_id_literal		    |//
//| EAP_TLS_PEAP_saved_master_secret			| BINARY(48)       | cf_str_EAP_TLS_PEAP_saved_master_secret_literal	    |//
//| EAP_TLS_PEAP_saved_cipher_suite				| UNSIGNED INTEGER | cf_str_EAP_TLS_PEAP_saved_cipher_suite_literal    |//
//| EAP_TLS_PEAP_verify_certificate_realm		| UNSIGNED INTEGER | cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal		    |//
//| EAP_TLS_max_session_validity_time			| BIGINT	   	 	| cf_str_EAP_TLS_max_session_validity_time_literal   |//
//| EAP_TLS_last_full_authentication_time		| BIGINT	   		| KTLSLastFullAuthTime	   	|//	
//| EAP_TLS_PEAP_use_identity_privacy	    	| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_use_identity_privacy_literal|//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////	

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Table creation is divided into two parts because otherwise the SQL string would get too long
	_LIT(KSQLCreateTable1, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
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
											 %S UNSIGNED INTEGER)");
											 
	sqlStatement.Format(KSQLCreateTable1,
		&KTlsDatabaseTableName,
		&KServiceType,
		&KServiceIndex,
		&KTunnelingType,
		&cf_str_EAP_TLS_PEAP_use_manual_realm_literal,
		&cf_str_EAP_TLS_PEAP_manual_realm_literal, KMaxManualRealmLengthInDB,
		&cf_str_EAP_TLS_PEAP_use_manual_username_literal,
		&cf_str_EAP_TLS_PEAP_manual_username_literal, KMaxManualUsernameLengthInDB,
		&cf_str_EAP_TLS_PEAP_cipher_suite_literal, 
		&cf_str_TLS_server_authenticates_client_policy_in_client_literal,
		&KCACertLabelOld, KMaxCertLabelLengthInDB,
		&KClientCertLabel, KMaxCertLabelLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_session_id_literal, KMaxSessionIdLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_master_secret_literal, KMaxMasterSecretLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_cipher_suite_literal,
		&cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal,		
		&cf_str_EAP_TLS_max_session_validity_time_literal,
		&KTLSLastFullAuthTime,
		&cf_str_EAP_TLS_PEAP_use_identity_privacy_literal);	
	
	err = aDatabase.Execute(sqlStatement);
	if (err == KErrAlreadyExists)
	{
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTlsDatabaseL - Alter Table err=%d\n"), err) );
	_LIT( KColumnDef, "UNSIGNED INTEGER" );
	AlterTableL( aDatabase, EAddColumn , KTlsDatabaseTableName,
			cf_str_EAP_TLS_PEAP_use_identity_privacy_literal, KColumnDef);
	}
	else if (err != KErrNone)
		{
		User::Leave(err);
		}

	// Create table for _allowed_ user certificates
	
//// NAME ////////////////// TYPE ////////////// Constant ///////////
//| ServiceType			| UNSIGNED INTEGER | KServiceType        |//
//| ServiceIndex		| UNSIGNED INTEGER | KServiceIndex       |//
//| TunnelingType		| UNSIGNED INTEGER | KTunnelingType		|//
//| CertLabel			| VARCHAR(255)     | KCertLabel        |//	
//| SubjectKeyId		| BINARY(20)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
//| ActualSubjectKeyId  | BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
//| SubjectName			| VARCHAR(255)     | KSubjectName        |//	
//| IssuerName			| VARCHAR(255)     | KIssuerName        |//	
//| SerialNumber		| VARCHAR(255)     | KSerialNumber        |//	
//| Thumbprint			| BINARY(64)	   | KThumbprint        |//	
//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable2, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S VARCHAR(%d), \
											 %S BINARY(%d), \
											 %S BINARY(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S BINARY(%d))");											 
											 
	sqlStatement.Format(KSQLCreateTable2, &KTlsAllowedUserCertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex, 
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);
				
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}

	// Create table for _allowed_ CA certs

//// NAME ////////////////// TYPE ////////////// Constant ///////////
//| ServiceType		    | UNSIGNED INTEGER | KServiceType        |//
//| ServiceIndex		| UNSIGNED INTEGER | KServiceIndex       |//
//| TunnelingType		| UNSIGNED INTEGER | KTunnelingType		|//
//| CertLabel			| VARCHAR(255)     | KCACertLabel        |//	
//| SubjectKeyId		| BINARY(255)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
//| ActualSubjectKeyId  | BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
//| SubjectName			| VARCHAR(255)     | KSubjectName        |//	
//| IssuerName			| VARCHAR(255)     | KIssuerName        |//	
//| SerialNumber		| VARCHAR(255)     | KSerialNumber        |//	
//| Thumbprint			| BINARY(64)	   | KThumbprint        |//	
//////////////////////////////////////////////////////////////////////////////////////////////////////	

	_LIT(KSQLCreateTable3, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S VARCHAR(%d), \
											 %S BINARY(%d), \
											 %S BINARY(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S BINARY(%d))");											 
											 
	sqlStatement.Format(KSQLCreateTable3, &KTlsAllowedCACertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex, 
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);
		
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}

	// Create table for allowed cipher suites

//// NAME ///////////////// TYPE ////////////// Constant ///////////
//| ServiceType			| UNSIGNED INTEGER | KServiceType        |//
//| ServiceIndex		| UNSIGNED INTEGER | KServiceIndex       |//
//| TunnelingType		| UNSIGNED INTEGER | KTunnelingType		|//
//| CipherSuite			| UNSIGNED INTEGER | KCipherSuite        |//	
//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable4, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER)");

	sqlStatement.Format(KSQLCreateTable4, &KTlsAllowedCipherSuitesDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex, 
		&KTunnelingType, 
		&KCipherSuite);
		
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}
	
	// 4. Check if database table contains a row for this service type and id 
		
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	sqlStatement.Format(KSQLQueryRow, &cf_str_EAP_TLS_PEAP_cipher_suite_literal, &KTlsDatabaseTableName, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);	
	
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
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal), default_EAP_TLS_PEAP_use_manual_realm);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal), default_EAP_TLS_PEAP_manual_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal), default_EAP_TLS_PEAP_use_manual_username);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal), default_EAP_TLS_PEAP_manual_username);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_cipher_suite_literal), default_EAP_TLS_PEAP_cipher_suite);
		
		view.SetColL(colSet->ColNo(cf_str_TLS_server_authenticates_client_policy_in_client_literal), default_EAP_TLS_server_authenticates_client);
		
		view.SetColL(colSet->ColNo(KCACertLabelOld), default_CA_cert_label);
		view.SetColL(colSet->ColNo(KClientCertLabel), default_client_cert_label);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal), default_EAP_TLS_PEAP_verify_certificate_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_max_session_validity_time_literal), default_MaxSessionTime);		
		
		view.SetColL(colSet->ColNo(KTLSLastFullAuthTime), default_FullAuthTime);		

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal), default_EAP_TLS_PEAP_TLS_Privacy);		
		view.PutL();

		CleanupStack::PopAndDestroy( colSet ); // Delete colSet.		
		CleanupStack::PopAndDestroy( &view ); // Close view.
		
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
			view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);
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
	
	CleanupStack::PopAndDestroy( buf ); // Delete buf or sqlStatement	
	CleanupStack::Pop( &aDatabase );	
	CleanupStack::Pop( &aSession );	
	
	aDatabase.Compact();
}

void EapTlsPeapUtils::OpenPeapDatabaseL(
		RDbNamedDatabase& aDatabase, 
		RDbs& aSession, 
		const TIndexType aIndexType, 
		const TInt aIndex,
		const eap_type_value_e aTunnelingType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenPeapDatabaseL -Start- aIndexType=%d, aIndex=%d, Tunneling vendor type=%d \n"),
		aIndexType,aIndex, aTunnelingVendorType));

	// 1. Open/create a database	
	
	// Connect to the DBMS server.
	User::LeaveIfError(aSession.Connect());		
	CleanupClosePushL(aSession);	
	// aSession and aDatabase are pushed to the cleanup stack even though they may be member
	// variables of the calling class and would be closed in the destructor anyway. This ensures
	// that if they are not member variables they will be closed. Closing the handle twice
	// does no harm.	
	
#ifdef SYMBIAN_SECURE_DBMS
	
	// Create the secure shared database with the specified secure policy.
	// Database will be created in the data caging path for DBMS (C:\private\100012a5).
	
	TInt err = aDatabase.Create(aSession, KPeapDatabaseName, KSecureUIDFormat);
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenPeapDatabaseL - Created Secure DB for eappeap.dat. err=%d\n"), err) );
	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	User::LeaveIfError(aDatabase.Open(aSession, KPeapDatabaseName, KSecureUIDFormat));
	CleanupClosePushL(aDatabase);		
		
#else
	// For non-secured database. The database will be created in the old location (c:\system\data).
	
	RFs fsSession;		
	User::LeaveIfError(fsSession.Connect());
	CleanupClosePushL(fsSession);	
	TInt err = aDatabase.Create(fsSession, KPeapDatabaseName);
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenPeapDatabaseL - Created Non-Secure DB for eappeap.dat. err=%d\n"), err) );
	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	User::LeaveIfError(aDatabase.Open(fsSession, KPeapDatabaseName));
	
	CleanupStack::PopAndDestroy(); // close fsSession
	
	CleanupClosePushL(aDatabase);		
	    
#endif // #ifdef SYMBIAN_SECURE_DBMS

	// 2. Create the eappeap table to database (ignore error if exists)
	
// Table columns:
//// NAME /////////////////////////////////////////////// TYPE ////////////// Constant ///////////////////
//| ServiceType										| UNSIGNED INTEGER 	| KServiceType        |//
//| ServiceIndex									| UNSIGNED INTEGER 	| KServiceIndex       |//
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
//| CA_cert_label								    | VARCHAR(255)     	| KCACertLabelOld	   |//
//| client_cert_label							    | VARCHAR(255)     	| KClientCertLabel	   |//
//| EAP_TLS_PEAP_saved_session_id				    | BINARY(32)       	| cf_str_EAP_TLS_PEAP_saved_session_id_literal		   |//
//| EAP_TLS_PEAP_saved_master_secret			    | BINARY(48)       	| cf_str_EAP_TLS_PEAP_saved_master_secret_literal	   |//
//| EAP_TLS_PEAP_saved_cipher_suite				    | UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_saved_cipher_suite_literal   |//
//| EAP_TLS_PEAP_verify_certificate_realm			| UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal		   |//
//| EAP_PEAP_max_session_validity_time				| BIGINT	   		| cf_str_EAP_PEAP_max_session_validity_time_literal   |//
//| EAP_PEAP_last_full_authentication_time			| BIGINT	   		| KPEAPLastFullAuthTime	   	|//	
//| EAP_TLS_PEAP_use_identity_privacy	    	    | UNSIGNED INTEGER 	| cf_str_EAP_TLS_PEAP_use_identity_privacy_literal|//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////	

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Table creation is divided into two parts because otherwise the SQL string would get too long
	_LIT(KSQLCreateTable1, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
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
											 %S UNSIGNED INTEGER)");
	sqlStatement.Format(KSQLCreateTable1,
		&KPeapDatabaseTableName,
		&KServiceType,
		&KServiceIndex,
		&KTunnelingType,
		&cf_str_EAP_TLS_PEAP_use_manual_realm_literal,
		&cf_str_EAP_TLS_PEAP_manual_realm_literal, KMaxManualRealmLengthInDB,
		&cf_str_EAP_TLS_PEAP_use_manual_username_literal,
		&cf_str_EAP_TLS_PEAP_manual_username_literal, KMaxManualUsernameLengthInDB,
		&cf_str_EAP_TLS_PEAP_cipher_suite_literal,
		&cf_str_EAP_TLS_PEAP_used_PEAP_version_literal,
		&cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal, KMaxPEAPVersionsStringLengthInDB,
		&cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, KMaxTunneledTypeStringLengthInDB,
		&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal, KMaxTunneledTypeStringLengthInDB,
		&cf_str_TLS_server_authenticates_client_policy_in_client_literal,
		&KCACertLabelOld, KMaxCertLabelLengthInDB,
		&KClientCertLabel, KMaxCertLabelLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_session_id_literal, KMaxSessionIdLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_master_secret_literal,  KMaxMasterSecretLengthInDB,
		&cf_str_EAP_TLS_PEAP_saved_cipher_suite_literal,
		&cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal,
		&cf_str_EAP_PEAP_max_session_validity_time_literal,
		&KPEAPLastFullAuthTime,	
		&cf_str_EAP_TLS_PEAP_use_identity_privacy_literal);		
					
	err = aDatabase.Execute(sqlStatement);
	if (err == KErrAlreadyExists)
		{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenPeapDatabaseL - Alter Table err=%d\n"), err) );
		_LIT( KColumnDef, "UNSIGNED INTEGER" );
		AlterTableL( aDatabase, EAddColumn , KPeapDatabaseTableName,
				cf_str_EAP_TLS_PEAP_use_identity_privacy_literal, KColumnDef);
		}
		else if (err != KErrNone)
			{
			User::Leave(err);
			}

	// Create table for _allowed_ user certificates
	
//// NAME ////////////////// TYPE ////////////// Constant ///////////
//| ServiceType			| UNSIGNED INTEGER | KServiceType        |//
//| ServiceIndex		| UNSIGNED INTEGER | KServiceIndex       |//
//| TunnelingType		| UNSIGNED INTEGER | KTunnelingType		|//
//| CertLabel			| VARCHAR(255)     | KCACertLabel        |//	
//| SubjectKeyId		| BINARY(20)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
//| ActualSubjectKeyId  | BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
//| SubjectName			| VARCHAR(255)     | KSubjectName        |//	
//| IssuerName			| VARCHAR(255)     | KIssuerName        |//	
//| SerialNumber		| VARCHAR(255)     | KSerialNumber        |//	
//| Thumbprint			| BINARY(64)	   | KThumbprint        |//	
//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable2, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S VARCHAR(%d), \
											 %S BINARY(%d), \
											 %S BINARY(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S BINARY(%d))");											 
											 
	sqlStatement.Format(KSQLCreateTable2, &KPeapAllowedUserCertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex, 
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);
		
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}	

	// Create table for _allowed_ CA certs

//// NAME ////////////////// TYPE ////////////// Constant ///////////
//| ServiceType			| UNSIGNED INTEGER | KServiceType        |//
//| ServiceIndex		| UNSIGNED INTEGER | KServiceIndex       |//
//| TunnelingType		| UNSIGNED INTEGER | KTunnelingType		|//
//| CACertLabel			| VARCHAR(255)     | KCACertLabel        |//	
//| SubjectKeyId		| BINARY(20)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
//| ActualSubjectKeyId  | BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
//| SubjectName			| VARCHAR(255)     | KSubjectName        |//	
//| IssuerName			| VARCHAR(255)     | KIssuerName        |//	
//| SerialNumber		| VARCHAR(255)     | KSerialNumber        |//	
//| Thumbprint			| BINARY(64)	   | KThumbprint        |//	
//////////////////////////////////////////////////////////////////////////////////////////////////////	

	_LIT(KSQLCreateTable3, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S VARCHAR(%d), \
											 %S BINARY(%d), \
											 %S BINARY(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S BINARY(%d))");
											 											 
	sqlStatement.Format(KSQLCreateTable3, &KPeapAllowedCACertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex, 
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);
		
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}

	// Create table for _allowed_ cipher suites

//// NAME ///////////////// TYPE ////////////// Constant ///////////
//| ServiceType			| UNSIGNED INTEGER | KServiceType        |//
//| ServiceIndex		| UNSIGNED INTEGER | KServiceIndex       |//
//| TunnelingType		| UNSIGNED INTEGER | KTunnelingType		|//
//| CipherSuite			| UNSIGNED INTEGER | KCipherSuite        |//	
//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable4, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER)");

	sqlStatement.Format(KSQLCreateTable4, &KPeapAllowedCipherSuitesDatabaseTableName, 
		&KServiceType, &KServiceIndex, &KTunnelingType, &KCipherSuite);
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}

	// 4. Check if database table contains a row for this service type and id 
	 	
	_LIT(KSQLQueryRow, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	sqlStatement.Format(KSQLQueryRow, &KPeapDatabaseTableName, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
			
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
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal), default_EAP_TLS_PEAP_use_manual_realm);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal), default_EAP_TLS_PEAP_manual_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal), default_EAP_TLS_PEAP_use_manual_username);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal), default_EAP_TLS_PEAP_manual_username);
		
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
		view.SetColL(colSet->ColNo(KCACertLabelOld), default_CA_cert_label);
		view.SetColL(colSet->ColNo(KClientCertLabel), default_client_cert_label);	

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal), default_EAP_TLS_PEAP_verify_certificate_realm);

		view.SetColL(colSet->ColNo(cf_str_EAP_PEAP_max_session_validity_time_literal), default_MaxSessionTime);
		
		view.SetColL(colSet->ColNo(KPEAPLastFullAuthTime), default_FullAuthTime);

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal), default_EAP_TLS_PEAP_TLS_Privacy);						

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
			view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);
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
	tableName = KPeapAllowedUserCertsDatabaseTableName;	
	AddExtraCertColumnsL(aDatabase,tableName);
	
	// For the table _allowed_ CA certificates	
	tableName = KPeapAllowedCACertsDatabaseTableName;	
	AddExtraCertColumnsL(aDatabase,tableName);

	CleanupStack::PopAndDestroy( buf ); // Delete buf or sqlStatement
	CleanupStack::Pop( &aDatabase );	
	CleanupStack::Pop( &aSession );	
	
	aDatabase.Compact();
}

#if defined(USE_TTLS_EAP_TYPE)

// ---------------------------------------------------------
// EapTlsPeapUtils::OpenTtlsDatabaseL()
// ---------------------------------------------------------
//
void EapTlsPeapUtils::OpenTtlsDatabaseL(
		RDbNamedDatabase& aDatabase, 
		RDbs& aSession, 
		const TIndexType aIndexType, 
		const TInt aIndex,
		const eap_type_value_e aTunnelingType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenTtlsDatabaseL -Start- aIndexType=%d, aIndex=%d, Tunneling vendor type=%d \n"),
		aIndexType,aIndex, aTunnelingVendorType));

	// 1. Open/create a database	
	
	// Connect to the DBMS server.
	User::LeaveIfError(aSession.Connect());		
	CleanupClosePushL(aSession);	
	// aSession and aDatabase are pushed to the cleanup stack even though they may be member
	// variables of the calling class and would be closed in the destructor anyway. This ensures
	// that if they are not member variables they will be closed. Closing the handle twice
	// does no harm.	
	
#ifdef SYMBIAN_SECURE_DBMS
	
	// Create the secure shared database with the specified secure policy.
	// Database will be created in the data caging path for DBMS (C:\private\100012a5).
	
	TInt err = aDatabase.Create(aSession, KTtlsDatabaseName, KSecureUIDFormat);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL - Created Secure DB for eapttls.dat. err=%d\n"), err) );
	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	User::LeaveIfError(aDatabase.Open(aSession, KTtlsDatabaseName, KSecureUIDFormat));
	CleanupClosePushL(aDatabase);		
		
#else
	// For non-secured database. The database will be created in the old location (c:\system\data).
	
	RFs fsSession;		
	User::LeaveIfError(fsSession.Connect());
	CleanupClosePushL(fsSession);	
	TInt err = aDatabase.Create(fsSession, KTtlsDatabaseName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL - Created Non-Secure DB for eapttls.dat. err=%d\n"), err) );
	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	User::LeaveIfError(aDatabase.Open(fsSession, KTtlsDatabaseName));
	
	CleanupStack::PopAndDestroy(); // close fsSession
	
	CleanupClosePushL(aDatabase);		
	    
#endif // #ifdef SYMBIAN_SECURE_DBMS

	// 2. Create the eapttls table to database (ignore error if exists)
	
// Table columns:
//// NAME //////////////////////////////////////////// TYPE ////////////// Constant ///////////////////
//| ServiceType									| UNSIGNED INTEGER 	| KServiceType        |//
//| ServiceIndex								| UNSIGNED INTEGER 	| KServiceIndex       |//
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
//| CA_cert_label								| VARCHAR(255)     	| KCACertLabelOld	   |//
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


//////////////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
// Table creation is divided into two parts because otherwise the SQL string would get too long
	_LIT(KSQLCreateTable1,
		"CREATE TABLE %S (%S UNSIGNED INTEGER, \
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

    sqlStatement.Format( KSQLCreateTable1,
        &KTtlsDatabaseTableName,
        &KServiceType,
        &KServiceIndex,
        &KTunnelingType,
        &cf_str_EAP_TLS_PEAP_use_manual_realm_literal,
        &cf_str_EAP_TLS_PEAP_manual_realm_literal, KMaxManualRealmLengthInDB,
        &cf_str_EAP_TLS_PEAP_use_manual_username_literal,
        &cf_str_EAP_TLS_PEAP_manual_username_literal, KMaxManualUsernameLengthInDB,
        &cf_str_EAP_TLS_PEAP_cipher_suite_literal,
        &cf_str_EAP_TLS_PEAP_used_PEAP_version_literal,
        &cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal, KMaxPEAPVersionsStringLengthInDB,
        &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, KMaxTunneledTypeStringLengthInDB,
        &cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,	KMaxTunneledTypeStringLengthInDB,	
        &cf_str_TLS_server_authenticates_client_policy_in_client_literal,
        &KCACertLabelOld, KMaxCertLabelLengthInDB,
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
        &KTTLSPAPLastFullAuthTime );	


	
	err = aDatabase.Execute(sqlStatement);
	if (err == KErrAlreadyExists)
		{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenTtlsDatabaseL - Alter Table err=%d\n"), err) );
		
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
				
		}
	else if (err != KErrNone)
		{
		User::Leave(err);
		}

	// Create table for _allowed_ user certificates
	
//// NAME ////////////////// TYPE ////////////// Constant ///////////
//| ServiceType		  	| UNSIGNED INTEGER | KServiceType        |//
//| ServiceIndex		| UNSIGNED INTEGER | KServiceIndex       |//
//| TunnelingType		| UNSIGNED INTEGER | KTunnelingType		|//
//| CertLabel			| VARCHAR(255)     | KCACertLabel        |//	
//| SubjectKeyId		| BINARY(20)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
//| ActualSubjectKeyId  | BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
//| SubjectName			| VARCHAR(255)     | KSubjectName        |//	
//| IssuerName			| VARCHAR(255)     | KIssuerName        |//	
//| SerialNumber		| VARCHAR(255)     | KSerialNumber        |//	
//| Thumbprint			| BINARY(64)	   | KThumbprint        |//	
//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable2, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S VARCHAR(%d), \
											 %S BINARY(%d), \
											 %S BINARY(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S BINARY(%d))");											 
											 
	sqlStatement.Format(KSQLCreateTable2, &KTtlsAllowedUserCertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex, 
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);
		
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}	

	// Create table for _allowed_ CA certs

//// NAME ////////////////// TYPE ////////////// Constant ///////////
//| ServiceType			| UNSIGNED INTEGER | KServiceType        |//
//| ServiceIndex		| UNSIGNED INTEGER | KServiceIndex       |//
//| TunnelingType		| UNSIGNED INTEGER | KTunnelingType		|//
//| CACertLabel			| VARCHAR(255)     | KCACertLabel        |//	
//| SubjectKeyId		| BINARY(20)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
//| ActualSubjectKeyId  | BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
//| SubjectName			| VARCHAR(255)     | KSubjectName        |//	
//| IssuerName			| VARCHAR(255)     | KIssuerName        |//	
//| SerialNumber		| VARCHAR(255)     | KSerialNumber        |//	
//| Thumbprint			| BINARY(64)	   | KThumbprint        |//	
//////////////////////////////////////////////////////////////////////////////////////////////////////	

	_LIT(KSQLCreateTable3, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S VARCHAR(%d), \
											 %S BINARY(%d), \
											 %S BINARY(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S BINARY(%d))");
											 
	sqlStatement.Format(KSQLCreateTable3, &KTtlsAllowedCACertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex, 
		&KTunnelingType, 
		&KCertLabel, KMaxCertLabelLengthInDB,
		&KSubjectKeyIdentifier, KMaxSubjectKeyIdLengthInDB,
		&KActualSubjectKeyIdentifier, KKeyIdentifierLength,
		&KSubjectName, KGeneralStringMaxLength,
		&KIssuerName, KGeneralStringMaxLength,
		&KSerialNumber, KGeneralStringMaxLength,
		&KThumbprint, KThumbprintMaxLength);
		
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}

	// Create table for _allowed_ cipher suites

//// NAME ///////////////// TYPE ////////////// Constant ///////////
//| ServiceType			| UNSIGNED INTEGER | KServiceType        |//
//| ServiceIndex		| UNSIGNED INTEGER | KServiceIndex       |//
//| TunnelingType		| UNSIGNED INTEGER | KTunnelingType		|//
//| CipherSuite			| UNSIGNED INTEGER | KCipherSuite        |//	
//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable4, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER)");

	sqlStatement.Format(KSQLCreateTable4, &KTtlsAllowedCipherSuitesDatabaseTableName, 
		&KServiceType, &KServiceIndex, &KTunnelingType, &KCipherSuite);
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}

	// 4. Check if database table contains a row for this service type and id  	
	
	_LIT(KSQLQueryRow, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQLQueryRow, &KTtlsDatabaseTableName, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);	
			
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
		sqlStatement.Format(KSQLInsert, &KTtlsDatabaseTableName);	

		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly));
		CleanupClosePushL(view);
		view.InsertL();

		// Get column set so we get the correct column numbers
		CDbColSet* colSet = view.ColSetL();
		CleanupStack::PushL(colSet);

		// Set the default values. The other three tables (certs, ca certs & cipher suites) are empty by default.
		view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt>(aIndexType));
		view.SetColL(colSet->ColNo(KServiceIndex), aIndex);		
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal), default_EAP_TLS_PEAP_use_manual_realm);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal), default_EAP_TLS_PEAP_manual_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal), default_EAP_TLS_PEAP_use_manual_username);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal), default_EAP_TLS_PEAP_manual_username);
		
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
		view.SetColL(colSet->ColNo(KCACertLabelOld), default_CA_cert_label);
		
		view.SetColL(colSet->ColNo(KClientCertLabel), default_client_cert_label);	

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal), default_EAP_TLS_PEAP_verify_certificate_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TTLS_max_session_validity_time_literal), default_MaxSessionTime);
		
		view.SetColL(colSet->ColNo(KTTLSLastFullAuthTime), default_FullAuthTime);				

		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal), default_EAP_TLS_PEAP_TLS_Privacy);


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

		
		view.PutL();
		
		CleanupStack::PopAndDestroy(colSet); 
		CleanupStack::PopAndDestroy( &view ); // Close view.

		// Add default disabled cipher suites
		_LIT(KSQLInsert2, "SELECT * FROM %S");
		sqlStatement.Format(KSQLInsert2, &KTtlsAllowedCipherSuitesDatabaseTableName);
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
			view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);			
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
	tableName = KTtlsAllowedUserCertsDatabaseTableName;	
	AddExtraCertColumnsL(aDatabase,tableName);
	
	// For the table _allowed_ CA certificates	
	tableName = KTtlsAllowedCACertsDatabaseTableName;	
	AddExtraCertColumnsL(aDatabase,tableName);

	CleanupStack::PopAndDestroy( buf ); // Delete buf or sqlStatement
	CleanupStack::Pop( &aDatabase );	
	CleanupStack::Pop( &aSession );
	
	aDatabase.Compact();
	
} // EapTlsPeapUtils::OpenTtlsDatabaseL()

#endif // #if defined(USE_TTLS_EAP_TYPE)

#if defined(USE_FAST_EAP_TYPE)

// ---------------------------------------------------------
// EapTlsPeapUtils::OpenFastDatabaseL()
// ---------------------------------------------------------
//
void EapTlsPeapUtils::OpenFastDatabaseL(
	RDbNamedDatabase& aDatabase, 
	RDbs& aSession, 
	const TIndexType aIndexType, 
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
    {
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL -Start- aIndexType=%d, aIndex=%d, Tunneling vendor type=%d \n"),
		aIndexType,aIndex, aTunnelingVendorType));

	// 1. Open/create a database	
	
	// Connect to the DBMS server.
	User::LeaveIfError(aSession.Connect());		
	CleanupClosePushL(aSession);	
	// aSession and aDatabase are pushed to the cleanup stack even though they may be member
	// variables of the calling class and would be closed in the destructor anyway. This ensures
	// that if they are not member variables they will be closed. Closing the handle twice
	// does no harm.	
	
#ifdef SYMBIAN_SECURE_DBMS
	
	// Create the secure shared database with the specified secure policy.
	// Database will be created in the data caging path for DBMS (C:\private\100012a5).
	
	TInt err = aDatabase.Create(aSession, KFastDatabaseName, KSecureUIDFormat);

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL - Created Secure DB for eapfast.dat. err=%d (-11=DB created before)\n"),
		err) );
	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	User::LeaveIfError(aDatabase.Open(aSession, KFastDatabaseName, KSecureUIDFormat));
	CleanupClosePushL(aDatabase);		
		
#else
	// For non-secured database. The database will be created in the old location (c:\system\data).
	
	RFs fsSession;		
	User::LeaveIfError(fsSession.Connect());
	CleanupClosePushL(fsSession);	
	TInt err = aDatabase.Create(fsSession, KFastDatabaseName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::OpenFastDatabaseL - Created Non-Secure DB for eapfast.dat. err=%d\n"), err) );
	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	User::LeaveIfError(aDatabase.Open(fsSession, KFastDatabaseName));
	
	CleanupStack::PopAndDestroy(); // close fsSession
	
	CleanupClosePushL(aDatabase);		
	    
#endif // #ifdef SYMBIAN_SECURE_DBMS

	// 2. Create the eapfast tables to database (ignore error if exists)
	
	// Table 1: Create table for general settings of EAP-FAST.
	
// Table columns:
//// NAME //////////////////////////////////////////// TYPE ////////////// Constant ///////////////////
//| ServiceType									| UNSIGNED INTEGER 	| KServiceType        |//
//| ServiceIndex								| UNSIGNED INTEGER 	| KServiceIndex       |//
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
//////////////////////////////////////////////////////////////////////////////////////////////////////////////	

/** moved to PAC store db, because time is the same for all IAPs **/	
//| EAP_FAST_last_password_identity_time	| BIGINT	   		| KFASTLastPasswordIdentityTime	   	|//	
//////////////////////////////////////////////////////////////////////////////////////////////////////////////		
	
	
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL - Creating the tables for EAP-FAST\n")));
	
	_LIT(KSQLCreateTable1, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
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
											 %S UNSIGNED INTEGER)");
	
	sqlStatement.Format(KSQLCreateTable1, &KFastGeneralSettingsDBTableName,
		&KServiceType,
		&KServiceIndex,
		&KTunnelingType,
		&cf_str_EAP_TLS_PEAP_use_manual_realm_literal,
		&cf_str_EAP_TLS_PEAP_manual_realm_literal, KMaxManualRealmLengthInDB,
		&cf_str_EAP_TLS_PEAP_use_manual_username_literal,
		&cf_str_EAP_TLS_PEAP_manual_username_literal, KMaxManualUsernameLengthInDB,
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
		&cf_str_EAP_TLS_PEAP_use_identity_privacy_literal);		
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL - SQL query formated OK\n")));
	
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL Created General settings table\n")));

	// Table 2: Create table for Special settings of EAP-FAST.
	
// Table columns:
//// NAME //////////////////////////////////////////// TYPE ////////////// Constant ///////////////////
//| ServiceType									| UNSIGNED INTEGER 	| KServiceType        |//
//| ServiceIndex								| UNSIGNED INTEGER 	| KServiceIndex       |//
//| TunnelingType								| UNSIGNED INTEGER 	| KTunnelingType		|//
//| EAP_FAST_allow_server_authenticated_provisioning_mode| UNSIGNED INTEGER	| cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal	   	|//	
//| EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP| UNSIGNED INTEGER	| cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal	   	|//	
//| EAP_FAST_Warn_ADHP_No_PAC					| UNSIGNED INTEGER	| KFASTWarnADHPNoPACP|//	
//| EAP_FAST_Warn_ADHP_No_Matching_PAC			| UNSIGNED INTEGER	| KFASTWarnADHPNoMatchingPAC|//	
//| EAP_FAST_Warn_Not_Default_Server			| UNSIGNED INTEGER	| KFASTWarnNotDefaultServer|//	
//| EAP_FAST_PAC_Group_Import_Reference_Collection| VARCHAR(255)	| KFASTPACGroupImportReferenceCollection	   	|//	
//| EAP_FAST_PAC_Group_DB_Reference_Collection	| BINARY(255)		| KFASTPACGroupDBReferenceCollection	   	|//		
//////////////////////////////////////////////////////////////////////////////////////////////////////////////	

	
	_LIT(KSQLCreateTable2, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S VARCHAR(%d),     \
											 %S BINARY(%d)		  )");
											 
	sqlStatement.Format(KSQLCreateTable2, &KFastSpecialSettingsDBTableName,
		&KServiceType,
		&KServiceIndex,
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
	
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL Created Specific settings table\n")));
	
	// Table 3: Create table for _allowed_ user certificates
	
//// NAME ////////////////// TYPE ////////////// Constant ///////////
//| ServiceType		  	| UNSIGNED INTEGER | KServiceType        |//
//| ServiceIndex		| UNSIGNED INTEGER | KServiceIndex       |//
//| TunnelingType		| UNSIGNED INTEGER | KTunnelingType		|//
//| CertLabel			| VARCHAR(255)     | KCACertLabel        |//	
//| SubjectKeyId		| BINARY(20)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
//| ActualSubjectKeyId  | BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
//| SubjectName			| VARCHAR(255)     | KSubjectName        |//	
//| IssuerName			| VARCHAR(255)     | KIssuerName        |//	
//| SerialNumber		| VARCHAR(255)     | KSerialNumber        |//	
//| Thumbprint			| BINARY(64)	   | KThumbprint        |//	
//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable3, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S VARCHAR(%d), \
											 %S BINARY(%d), \
											 %S BINARY(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S BINARY(%d))");											 
											 
	sqlStatement.Format(KSQLCreateTable3, &KFastAllowedUserCertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex, 
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
	
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}	

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL Created User certificates table\n")));
	
	// Table 4: Create table for _allowed_ CA certs

//// NAME ////////////////// TYPE ////////////// Constant ///////////
//| ServiceType			| UNSIGNED INTEGER | KServiceType        |//
//| ServiceIndex		| UNSIGNED INTEGER | KServiceIndex       |//
//| TunnelingType		| UNSIGNED INTEGER | KTunnelingType		|//
//| CACertLabel			| VARCHAR(255)     | KCACertLabel        |//	
//| SubjectKeyId		| BINARY(20)	   | KSubjectKeyIdentifier |// This is Symbian subjectkey id
//| ActualSubjectKeyId  | BINARY(20)	   | KActualSubjectKeyIdentifier |// This is the actual subjectkeyid present in the certificate.
//| SubjectName			| VARCHAR(255)     | KSubjectName        |//	
//| IssuerName			| VARCHAR(255)     | KIssuerName        |//	
//| SerialNumber		| VARCHAR(255)     | KSerialNumber        |//	
//| Thumbprint			| BINARY(64)	   | KThumbprint        |//	
//////////////////////////////////////////////////////////////////////////////////////////////////////	

	_LIT(KSQLCreateTable4, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S VARCHAR(%d), \
											 %S BINARY(%d), \
											 %S BINARY(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S VARCHAR(%d), \
											 %S BINARY(%d))");
											 
	sqlStatement.Format(KSQLCreateTable4, &KFastAllowedCACertsDatabaseTableName, 
		&KServiceType, 
		&KServiceIndex, 
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
		
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL Created CA certificates table\n")));
	
	// Table 5: Create table for _allowed_ cipher suites

//// NAME ///////////////// TYPE ////////////// Constant ///////////
//| ServiceType			| UNSIGNED INTEGER | KServiceType        |//
//| ServiceIndex		| UNSIGNED INTEGER | KServiceIndex       |//
//| TunnelingType		| UNSIGNED INTEGER | KTunnelingType		|//
//| CipherSuite			| UNSIGNED INTEGER | KCipherSuite        |//	
//////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	_LIT(KSQLCreateTable5, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER)");

	sqlStatement.Format(KSQLCreateTable5, &KFastAllowedCipherSuitesDatabaseTableName, 
		&KServiceType, &KServiceIndex, &KTunnelingType, &KCipherSuite);
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::OpenFastDatabaseL Created Cipher suites table\n")));
	
	// 4. Check if database table contains a row for this service type and id  	
	
	_LIT(KSQLQueryRow, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQLQueryRow, &KFastGeneralSettingsDBTableName, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);	
			
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
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal), default_EAP_TLS_PEAP_use_manual_realm);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal), default_EAP_TLS_PEAP_manual_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal), default_EAP_TLS_PEAP_use_manual_username);
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal), default_EAP_TLS_PEAP_manual_username);
		
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
		
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal), default_EAP_TLS_PEAP_TLS_Privacy);		

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
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);

		view.SetColL(colSet->ColNo(cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal),
				default_EAP_FAST_Auth_Prov_Mode_Allowed);		
	 	view.SetColL(colSet->ColNo(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal),
	 			default_EAP_FAST_Unauth_Prov_Mode_Allowed);
	 	
        view.SetColL(colSet->ColNo(KFASTWarnADHPNoPAC),
                default_EAP_FAST_Warn_ADHP_No_PAC);

        view.SetColL(colSet->ColNo(KFASTWarnADHPNoMatchingPAC),
                default_EAP_FAST_Warn_ADHP_No_Matching_PAC);

        view.SetColL(colSet->ColNo(KFASTWarnNotDefaultServer),
                default_EAP_FAST_Warn_Not_Default_Server);

	 	
							
		view.PutL();
		
		CleanupStack::PopAndDestroy(colSet); 
		CleanupStack::PopAndDestroy( &view ); // Close view.		
		
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
			view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);			
			view.SetColL(colSet->ColNo(KCipherSuite), default_allowed_cipher_suites[i]);
			view.PutL();
			i++;
		}
		
		CleanupStack::PopAndDestroy( colSet ); // Delete colSet.		
		CleanupStack::PopAndDestroy( &view ); // Close view.
	}
	
	CleanupStack::PopAndDestroy( buf ); // Delete buf or sqlStatement
	CleanupStack::Pop( &aDatabase );	
	CleanupStack::Pop( &aSession );
	
	aDatabase.Compact();
	
    } // EapTlsPeapUtils::OpenFastDatabaseL()

#endif // #if defined(USE_FAST_EAP_TYPE)

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
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();
	TUint aNewTunnelingVendorType = aNewTunnelingType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);
	TUint aNewTunnelingVendorType = static_cast<TUint>(aNewTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetIndexL -Start- aIndexType=%d, aIndex=%d, Tunneling vendor type=%d \n"),
		aIndexType, aIndex, aTunnelingVendorType));
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetIndexL -Start- aNewIndexType=%d, aNewIndex=%d, New Tunneling vendor type=%d \n"),
		aNewIndexType, aNewIndex, aNewTunnelingVendorType));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// First delete the target
	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL, &aTableName, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);		

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

    			view.SetColL(colSet->ColNo(KTunnelingType), aNewTunnelingVendorType);
				
				view.PutL();
			}
		} while (view.NextL() != EFalse);
	}
			
    CleanupStack::PopAndDestroy(3); // view, colset
}

void EapTlsPeapUtils::ReadCertRowsToArrayL(
	RDbNamedDatabase& aDatabase,
	eap_am_tools_symbian_c * const /*aTools*/,
	const TDesC& aTableName, 
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	RArray<SCertEntry>& aArray)
{
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::ReadCertRowsToArrayL -Start")) );
	
	CleanupClosePushL( aArray );

	HBufC* buf = HBufC::NewLC(512);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	sqlStatement.Format(KSQLQueryRow, &aTableName, &KServiceType, 
		aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
	
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
				SCertEntry certInfo;
				// Store the line
				TPtrC ptr = view.ColDes(colSet->ColNo(KCertLabel));
	
				certInfo.iLabel.Copy(ptr);
				
				TPtrC8 ptr2 = view.ColDes8(colSet->ColNo(KSubjectKeyIdentifier)); // This is for authentication and uses Symbian subjectkey id.
				certInfo.iSubjectKeyId.Copy(ptr2);

				aArray.Append(certInfo);
				
				EAP_TRACE_DEBUG_SYMBIAN((_L("ReadCertRowsToArrayL - Appended Cert with label=%S\n"),
				&(certInfo.iLabel)));
				
				EAP_TRACE_DATA_DEBUG_SYMBIAN(("ReadCertRowsToArrayL - Appended Cert's SubjectKeyID:",
					certInfo.iSubjectKeyId.Ptr(), certInfo.iSubjectKeyId.Size()));
			}	

		} while (view.NextL() != EFalse);		
	}

	// Close database
	CleanupStack::PopAndDestroy(colSet); 
	CleanupStack::PopAndDestroy(2); // view, buf
	CleanupStack::Pop( &aArray );
}

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
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::ReadUintRowsToArrayL -Start")) );

	CleanupClosePushL( aArray );

	HBufC* buf = HBufC::NewLC(512);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	sqlStatement.Format(KSQLQueryRow, &aColumnName, &aTableName, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
	
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
					aArray.Append(tmp);
				}
				break;
			default:
				User::Leave(KErrArgument);
			}		

		} while (view.NextL() != EFalse);
	}

	// Close database
	CleanupStack::PopAndDestroy(2); // view, buf
	CleanupStack::Pop( &aArray );
}

// Don't use this finction as Label is not saved for certificates saved by SetConfigurationL().
// Provisioning (OMA DM etc) use SetConfigurationL() to save certificate details.

TBool EapTlsPeapUtils::CompareTCertLabels(const TCertLabel& item1, const TCertLabel& item2)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::CompareTCertLabels-Start")) );

	if (item1 == item2)
	{
		return ETrue;
	} 
	else
	{
		return EFalse;
	}
}

TBool EapTlsPeapUtils::CompareSCertEntries(const SCertEntry& item1, const SCertEntry& item2)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("\nEapTlsPeapUtils::CompareSCertEntries, Label_1=%S, Label_2=%S"),
	&(item1.iLabel), &(item2.iLabel)));

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::CompareSCertEntries, SubjectKeyID_1:",
		item1.iSubjectKeyId.Ptr(), item1.iSubjectKeyId.Size()));

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::CompareSCertEntries, SubjectKeyID_2:",
		item2.iSubjectKeyId.Ptr(), item2.iSubjectKeyId.Size()));

	if (item1.iLabel == item2.iLabel ||
		item1.iLabel.Length() == 0 ||
		item2.iLabel.Length() == 0 ) // Label is not saved when certs are saved using OMA DM.
	{
		if (item1.iSubjectKeyId == item2.iSubjectKeyId)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::CompareSCertEntries, Certs matched\n")));
		
			return ETrue;
		}
	}
	
	return EFalse;
}


#ifndef USE_EAP_EXPANDED_TYPES 
// There are separate functions (SetTunnelingExpandedEapDataL and GetTunnelingExpandedEapDataL) if USE_EAP_EXPANDED_TYPES is defined.

/**
* Sets EAP data to a binary string record in commsdat.
* The old format (NOT USED NOW) is "+123,- 34", + means enabled, - disabled, then id, id is always 3 characters for easy parsing.
* In the new format each EAP type is saved as an unsigned integer of 32 bits ( TUint).
* There is separate binary strings for accepted (enabled) and unaccepted (disabled) tunneled EAP types.
*/
 
void EapTlsPeapUtils::SetEapDataL(
	RDbNamedDatabase& aDatabase,
	eap_am_tools_symbian_c * const /*aTools*/,
	TEapArray &aEaps,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();
	TUint aEapVendorType = aEapType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);
	TUint aEapVendorType = static_cast<TUint>(aEapType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetEapDataL aIndexType=%d, aIndex=%d, Tunneling vendor type=%d, Eap vendor type=%d, No: of tunneled EAP types=%d \n"),
		aIndexType,aIndex, aTunnelingVendorType, aEapVendorType, aEaps.Count()) );

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	if (aEapType == eap_type_peap)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal,
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KPeapDatabaseTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 
#if defined(USE_TTLS_EAP_TYPE)
	else if (aEapType == eap_type_ttls)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KTtlsDatabaseTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 
#endif

	else if (aEapType == eap_type_ttls_plain_pap)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KTtlsDatabaseTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 

#if defined(USE_FAST_EAP_TYPE)
	else if (aEapType == eap_type_fast)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KFastGeneralSettingsDBTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 
#endif
	else
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::SetEapDataL - Unsupported EAP type =%d \n"),
			 aEapVendorType));
			 
		// Unsupported EAP type
		User::Leave(KErrNotSupported);
	}	
			
	RDbView view;
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());	
	User::LeaveIfError(view.FirstL());	
	view.UpdateL();

	TInt eapCount = aEaps.Count();
	
	HBufC8 *acceptedDbText = HBufC8::NewLC( (sizeof(TUint)) * eapCount ); // 4 bytes (32 bits) for an EAP type, Need to save as TUInt (4 bytes).
	HBufC8 *unacceptedDbText = HBufC8::NewLC( (sizeof(TUint)) * eapCount ); // 4 bytes (32 bits) for an EAP type, Need to save as TUInt (4 bytes).
	
	TPtr8 acceptedPtr(acceptedDbText->Des());
	TPtr8 unacceptedPtr(unacceptedDbText->Des());
	
	TBuf8<3> UidTmp;
		
	for(TInt i = 0 ; i< eapCount; i++)
	{
		UidTmp.Copy(aEaps[i]->UID);
		
		TLex8 eapUidLex( UidTmp.Right(2) ); // Only last two characters determines the EAP type.
		TUint eapTypeUint = 0;
		
		User::LeaveIfError( eapUidLex.Val(eapTypeUint, EDecimal) );	
		
		TPtrC8 tempEAPtype( reinterpret_cast<TUint8*>(&eapTypeUint), sizeof(TUint) );
		
		if( aEaps[i]->Enabled )
		{
			// Fill in accepted tunneled type.
			acceptedPtr.Append( tempEAPtype );			
		}
		else
		{
			// Fill in unaccepted tunneled type.
			unacceptedPtr.Append( tempEAPtype);			
		}			
	}
	
	// Save the strings in the DB.
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);			
	
	// Validate length of strings
	if(acceptedPtr.Length() > KMaxTunneledTypeStringLengthInDB 
		|| unacceptedPtr.Length() > KMaxTunneledTypeStringLengthInDB)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetEapDataL - Too long Tunneled EAP type string \n") ) );

		User::Leave(KErrArgument);		
	}
	
	view.SetColL(colSet->ColNo(cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal), acceptedPtr);
	view.SetColL(colSet->ColNo(cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal), unacceptedPtr);	

	CleanupStack::PopAndDestroy( colSet ); // Delete colSet.	

	view.PutL();

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::SetEapDataL- Enabled extended EAP type data added to DB:",
		acceptedPtr.Ptr(), 
		acceptedPtr.Size() ) );

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::SetEapDataL- Disabled extended EAP type data added to DB:",
		unacceptedPtr.Ptr(), 
		unacceptedPtr.Size() ) );

	CleanupStack::PopAndDestroy(unacceptedDbText); // Delete unacceptedDbText
	CleanupStack::PopAndDestroy(acceptedDbText); // Delete acceptedDbText	
	CleanupStack::PopAndDestroy(&view); // Close view
	CleanupStack::PopAndDestroy(buf); // Delete buf
}

/**
* Gets Eapdata from corresponding table in commdb
* see format in SetEapDAtaL
*/
void EapTlsPeapUtils::GetEapDataL(
	RDbNamedDatabase& aDatabase,
	eap_am_tools_symbian_c * const /*aTools*/,
	TEapArray &aEaps, 
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();
	TUint aEapVendorType = aEapType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);
	TUint aEapVendorType = static_cast<TUint>(aEapType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::GetEapDataL aIndexType=%d, aIndex=%d, Tunneling vendor type=%d, Eap vendor type=%d \n"),
		aIndexType,aIndex, aTunnelingVendorType, aEapVendorType));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");

	if (aEapType == eap_type_peap)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KPeapDatabaseTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 
#if defined(USE_TTLS_EAP_TYPE)
	else if (aEapType == eap_type_ttls)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KTtlsDatabaseTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 
#endif

	else if (aEapType == eap_type_ttls_plain_pap)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KTtlsDatabaseTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 
	
#if defined(USE_FAST_EAP_TYPE)
	else if (aEapType == eap_type_fast)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KFastGeneralSettingsDBTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 
#endif
	else
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::GetEapDataL - Unsupported EAP type=%d \n"),
			 aEapVendorType));
			 
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

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::GetEapDataL- Enabled extended EAP type data from DB:",
		acceptedEAPData.Ptr(), 
		acceptedEAPData.Size() ) );
	
	EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::GetEapDataL- Disabled extended EAP type data from DB:",
		unacceptedEAPData.Ptr(), 
		unacceptedEAPData.Size() ) );
	
	aEaps.ResetAndDestroy();
		
	TUint acceptedLength = acceptedEAPData.Length();
	TUint unacceptedLength = unacceptedEAPData.Length();
	
	TEap *eapTmp;

	TUint index = 0;
	
	_LIT8(KUIDFormat,"%u");
	
	// For accepted or enabled tunneled EAP types. 	
	while(index < acceptedLength)
	{		
		eapTmp = new (ELeave)TEap;

		eapTmp->Enabled=ETrue; // All EAP types in here are enabled.
		
		eapTmp->UID.Zero();

		// Get the UID from data from the DB.				
		TPtrC8 tempEAPtype( acceptedEAPData.Mid(index, sizeof(TUint)) );
		
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::GetEapDataL- extracted EAP type:",
			tempEAPtype.Ptr(), 
			tempEAPtype.Size() ) );
						
		TUint eapTypeUint = *(tempEAPtype.Ptr()); // All EAP types are saved as TUInt. 
		
		eapTmp->UID.Format(KUIDFormat,eapTypeUint);
				
		aEaps.Append(eapTmp);

		index = index + sizeof(TUint);
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetEapDataL - Appended enabled-EAP type=%s \n"),eapTmp->UID.Ptr()) );
	}
	
	index = 0;
	
	// For unaccepted or disabled tunneled EAP types. 	
	while(index < unacceptedLength)
	{		
		eapTmp = new (ELeave)TEap;

		eapTmp->Enabled=EFalse; // All EAP types in here are disabled.
		
		eapTmp->UID.Zero();

		// Get the UID from data from the DB.				
		TPtrC8 tempEAPtype( unacceptedEAPData.Mid(index, sizeof(TUint)) );
		
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapTlsPeapUtils::GetEapDataL- extracted EAP type:",
			tempEAPtype.Ptr(), 
			tempEAPtype.Size() ) );
						
		TUint eapTypeUint = *(tempEAPtype.Ptr()); // All EAP types are saved as TUint. 
		
		eapTmp->UID.Format(KUIDFormat,eapTypeUint);
				
		aEaps.Append(eapTmp);

		index = index + sizeof(TUint);
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetEapDataL - Appended disabled-EAP type=%s \n"),eapTmp->UID.Ptr()) );
	}
	
	CleanupStack::PopAndDestroy(&view); // Close view
	CleanupStack::PopAndDestroy(buf); // Delete buf	
}

#endif // #ifndef USE_EAP_EXPANDED_TYPES

//--------------------------------------------------

#ifdef USE_EAP_EXPANDED_TYPES

// Stores the tunneled EAP type (expanded) to the database.
void EapTlsPeapUtils::SetTunnelingExpandedEapDataL(
	RDbNamedDatabase& aDatabase,
	eap_am_tools_symbian_c * const /*aTools*/,
	RExpandedEapTypePtrArray &aEnabledEAPArrary,
	RExpandedEapTypePtrArray &aDisabledEAPArrary,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType)
{
	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();
	TUint aEapVendorType = aEapType.get_vendor_type();

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetTunnelingExpandedEapDataL:aIndexType=%d, aIndex=%d, Tunneling vendor type=%d, Eap vendor type=%d\n"),
		aIndexType,aIndex, aTunnelingVendorType, aEapVendorType));

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("Number of Tunneled EAP types: Enabled=%d, Disabled=%d\n"),
		aEnabledEAPArrary.Count(), aDisabledEAPArrary.Count()));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	if (aEapType == eap_type_peap)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal,
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KPeapDatabaseTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 
#if defined(USE_TTLS_EAP_TYPE)
	else if (aEapType == eap_type_ttls)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KTtlsDatabaseTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 
#endif
#if defined(USE_FAST_EAP_TYPE)
	else if (aEapType == eap_type_fast)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KFastGeneralSettingsDBTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 
#endif

	else if ( aEapType == eap_type_ttls_plain_pap )
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KTtlsDatabaseTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 

	else
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::SetTunnelingExpandedEapDataL - Unsupported EAP type =%d \n"),
			 aEapVendorType));
			 
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
	
	HBufC8 *acceptedDbText = HBufC8::NewLC( KExpandedEAPTypeSize * enabledEAPCount ); // 8 bytes (64 bits) for an EAP type.
	HBufC8 *unacceptedDbText = HBufC8::NewLC( KExpandedEAPTypeSize * disabledEAPCount ); // 8 bytes (64 bits) for an EAP type.
	
	TPtr8 acceptedPtr(acceptedDbText->Des());
	TPtr8 unacceptedPtr(unacceptedDbText->Des());
	
	// Fill in accepted tunneled type.		
	for(TInt i = 0 ; i< enabledEAPCount; i++)
	{
		acceptedPtr.Append(aEnabledEAPArrary[i]->iExpandedEAPType);					
	}
	
	// Fill in unaccepted tunneled type.		
	for(TInt i = 0 ; i< disabledEAPCount; i++)
	{
		unacceptedPtr.Append(aDisabledEAPArrary[i]->iExpandedEAPType);					
	}
	
	// Save the strings in the DB.
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);			
	
	// Validate length of strings
	if(acceptedPtr.Length() > KMaxTunneledTypeStringLengthInDB 
		|| unacceptedPtr.Length() > KMaxTunneledTypeStringLengthInDB)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetTunnelingExpandedEapDataL - Too long Tunneled EAP type string \n") ) );

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

// Retrieves the tunneled EAP type (expanded) from the database	.
void EapTlsPeapUtils::GetTunnelingExpandedEapDataL(
	RDbNamedDatabase& aDatabase,
	eap_am_tools_symbian_c * const /*aTools*/,
	RExpandedEapTypePtrArray &aEnabledEAPArrary,
	RExpandedEapTypePtrArray &aDisabledEAPArrary,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType)
{
	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();
	TUint aEapVendorType = aEapType.get_vendor_type();
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::GetTunnelingExpandedEapDataL aIndexType=%d, aIndex=%d, Tunneling vendor type=%d, Eap vendor type=%d \n"),
		aIndexType,aIndex, aTunnelingVendorType, aEapVendorType));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");

	if (aEapType == eap_type_peap)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KPeapDatabaseTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 
#if defined(USE_TTLS_EAP_TYPE)
	else if (aEapType == eap_type_ttls)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KTtlsDatabaseTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 
#endif
#if defined(USE_FAST_EAP_TYPE)
	else if (aEapType == eap_type_fast)
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KFastGeneralSettingsDBTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 
#endif

	else if (aEapType == eap_type_ttls_plain_pap )
	{
		sqlStatement.Format(KSQLQueryRow, &cf_str_PEAP_accepted_tunneled_client_types_hex_data_literal, 
			&cf_str_PEAP_unaccepted_tunneled_client_types_hex_data_literal,
			&KTtlsDatabaseTableName, &KServiceType, aIndexType, &KServiceIndex, aIndex, 
			&KTunnelingType, aTunnelingVendorType);		
	} 

	else
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::GetTunnelingExpandedEapDataL - Unsupported EAP type=%d \n"),
			 aEapVendorType));
			 
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
	
	SExpandedEAPType *expandedEAPTmp = 0;
	TUint index = 0;
	
	// For accepted or enabled tunneled EAP types. 	
	while(index < acceptedLength)
	{		
		expandedEAPTmp = new SExpandedEAPType;

		if (expandedEAPTmp == 0)
		{
			aEnabledEAPArrary.ResetAndDestroy();
			aDisabledEAPArrary.ResetAndDestroy();
			User::LeaveIfError(KErrNoMemory);
		}

		expandedEAPTmp->iExpandedEAPType = acceptedEAPData.Mid(index, KExpandedEAPTypeSize);
						
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("Extracted EAP type:",
			expandedEAPTmp->iExpandedEAPType.Ptr(), 
			expandedEAPTmp->iExpandedEAPType.Size() ) );

		aEnabledEAPArrary.Append(expandedEAPTmp);

		index = index + KExpandedEAPTypeSize;
	}
	
	index = 0;
	
	// For unaccepted or disabled tunneled EAP types.
	while(index < unacceptedLength)
	{		
		expandedEAPTmp = new SExpandedEAPType;

		if (expandedEAPTmp == 0)
		{
			aEnabledEAPArrary.ResetAndDestroy();
			aDisabledEAPArrary.ResetAndDestroy();
			User::LeaveIfError(KErrNoMemory);
		}

		expandedEAPTmp->iExpandedEAPType = unacceptedEAPData.Mid(index, KExpandedEAPTypeSize);
						
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("Extracted EAP type:",
			expandedEAPTmp->iExpandedEAPType.Ptr(), 
			expandedEAPTmp->iExpandedEAPType.Size() ) );

		aDisabledEAPArrary.Append(expandedEAPTmp);

		index = index + KExpandedEAPTypeSize;
	}

	CleanupStack::PopAndDestroy(&view); // Close view
	CleanupStack::PopAndDestroy(buf); // Delete buf
}

#endif //#ifdef USE_EAP_EXPANDED_TYPES

//--------------------------------------------------

TBool EapTlsPeapUtils::CipherSuiteUseRSAKeys(tls_cipher_suites_e aCipherSuite)
{
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
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();
	TUint aEapVendorType = aEapType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);
	TUint aEapVendorType = static_cast<TUint>(aEapType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

// The current values for TTLS-PAP:
// TTLS: aEapVendorType = TTLS, aTunnelingVendorType = None
// TTLS/plain-PAP: aEapVendorType = ttls_plain_pap, aTunnelingVendorType = TTLS
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetConfigurationL -Start- aIndexType=%d, aIndex=%d, Tunneling vendor type=%d, Eap vendor type=%d \n"),
		aIndexType,aIndex, aTunnelingVendorType, aEapVendorType));
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("*************************** SetConfigurationL - Set the below values: ***************************\n")) );
	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - Set these values for EAPType=%d"),aSettings.iEAPType) );
	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, Username=%S"),aSettings.iUsernamePresent, &(aSettings.iUsername)) );
	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, Password=%S"),aSettings.iPasswordPresent, &(aSettings.iPassword)) );
	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, Realm=%S"),aSettings.iRealmPresent, &(aSettings.iRealm)) );
	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, UsePseudonyms=%d"),aSettings.iUsePseudonymsPresent, aSettings.iUsePseudonyms) );
	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, VerifyServerRealm=%d"),
						aSettings.iVerifyServerRealmPresent, aSettings.iVerifyServerRealm) );

	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, RequireClientAuthentication=%d"),
						aSettings.iRequireClientAuthenticationPresent, aSettings.iRequireClientAuthentication) );
						
	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, SessionValidityTime=%d minutes"),
						aSettings.iSessionValidityTimePresent, aSettings.iSessionValidityTime) );

	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, CipherSuites Count=%d"),
						aSettings.iCipherSuitesPresent, aSettings.iCipherSuites.Count()) );
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, PEAPv0Allowed=%d, PEAPv1Allowed=%d, PEAPv2Allowed=%d"),
						aSettings.iPEAPVersionsPresent, aSettings.iPEAPv0Allowed,aSettings.iPEAPv1Allowed, aSettings.iPEAPv2Allowed ) );
	
	// Validate length of inputs.
	if(aSettings.iUsername.Length() > KMaxManualUsernameLengthInDB
		|| aSettings.iRealm.Length() > KMaxManualRealmLengthInDB )
	{
		// Some inputs are too long. Can not be stored in DB.
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL: Too long arguments\n")));
		
		User::Leave(KErrArgument);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, Certificates Count=%d"),
						aSettings.iCertificatesPresent, aSettings.iCertificates.Count()) );
						
	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - Certificate details below: \n")) );
	
	for( TInt n=0; n < aSettings.iCertificates.Count(); n++ )
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - Certificate type:%d \n"), aSettings.iCertificates[n].iCertType) );
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - certificates - present=%d, SubjectName=%S"),
						aSettings.iCertificates[n].iSubjectNamePresent, &(aSettings.iCertificates[n].iSubjectName) ) );
						
		EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - certificates - present=%d, IssuerName=%S"),
						aSettings.iCertificates[n].iIssuerNamePresent, &(aSettings.iCertificates[n].iIssuerName) ) );
						
		EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - certificates - present=%d, SerialNumber=%S"),
						aSettings.iCertificates[n].iSerialNumberPresent, &(aSettings.iCertificates[n].iSerialNumber) ) );
						
		EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - certificates - SubjectKeyID present=%d"),
						aSettings.iCertificates[n].iSubjectKeyIDPresent ) );						
						
		EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "SubjectKeyID:", aSettings.iCertificates[n].iSubjectKeyID.Ptr(), 
													aSettings.iCertificates[n].iSubjectKeyID.Size() ) );

		EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - certificates - Thumbprint present=%d"),
						aSettings.iCertificates[n].iThumbprintPresent ) );						
						
		EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "Thumbprint:", aSettings.iCertificates[n].iThumbprint.Ptr(), 
													aSettings.iCertificates[n].iThumbprint.Size() ) );
	}						

	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, EncapsulatedEAPTypes Count=%d"),
						aSettings.iEncapsulatedEAPTypesPresent, aSettings.iEncapsulatedEAPTypes.Count()) );
	
	for( TInt m=0; m < aSettings.iEncapsulatedEAPTypes.Count(); m++ )
	{	
		EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - EncapsulatedEAPTypes=%d"),
						aSettings.iEncapsulatedEAPTypes[m]) );
	}						

#ifdef USE_FAST_EAP_TYPE		

	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, AuthProvModeAllowed=%d"),
						aSettings.iAuthProvModeAllowedPresent, aSettings.iAuthProvModeAllowed) );

	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, UnauthProvModeAllowed=%d"),
						aSettings.iUnauthProvModeAllowedPresent, aSettings.iUnauthProvModeAllowed) );

	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, WarnADHPNoPAC=%d"),
			aSettings.iWarnADHPNoPACPresent, aSettings.iWarnADHPNoPAC) );

	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, WarnADHPNoMatchingPAC=%d"),
			aSettings.iWarnADHPNoMatchingPACPresent, aSettings.iWarnADHPNoMatchingPAC) );

	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, WarnNotDefaultServer=%d"),
			aSettings.iWarnNotDefaultServerPresent, aSettings.iWarnNotDefaultServer) );
	
	// Validate length of PAC Group Ref.
	if(aSettings.iPACGroupReference.Length() > KMaxPACGroupRefCollectionLengthInDB)
	{
		// Too long PAC Group Reference. Can not be stored in DB.
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL: Too long PAC Group Ref!\n")));
		
		User::Leave(KErrArgument);
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, PAC Group Ref=%S"),
						aSettings.iPACGroupReferencePresent, &(aSettings.iPACGroupReference)) );

#endif //#ifdef USE_FAST_EAP_TYPE		

	EAP_TRACE_DEBUG_SYMBIAN((_L("*************************** SetConfigurationL - Set the above values: ***************************\n")) );


	// Check if the settings are for the correct type
	if ((aSettings.iEAPType != EAPSettings::EEapTls
		&& aSettings.iEAPType != EAPSettings::EEapPeap
		&& aSettings.iEAPType != EAPSettings::EEapTtls
#ifdef USE_FAST_EAP_TYPE		
		&& aSettings.iEAPType != EAPSettings::EEapFast
#endif	
		&& aSettings.iEAPType != EAPSettings::ETtlsPlainPap
		)
		|| static_cast<TUint>(aSettings.iEAPType) != aEapVendorType)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - LEAVE - Unsupported EAP type\n")) );
		
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
	
	switch (aEapVendorType)
	{
	case eap_type_tls:
		{
			settings.Set(KTlsDatabaseTableName);
			usercerts.Set(KTlsAllowedUserCertsDatabaseTableName);
			cacerts.Set(KTlsAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KTlsAllowedCipherSuitesDatabaseTableName);
			maxSessionTime.Set(cf_str_EAP_TLS_max_session_validity_time_literal);
			lastFullAuthTime.Set(KTLSLastFullAuthTime);
		}
		break;

	case eap_type_peap:
		{
			settings.Set(KPeapDatabaseTableName);
			usercerts.Set(KPeapAllowedUserCertsDatabaseTableName);
			cacerts.Set(KPeapAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KPeapAllowedCipherSuitesDatabaseTableName);
			maxSessionTime.Set(cf_str_EAP_PEAP_max_session_validity_time_literal);
			lastFullAuthTime.Set(KPEAPLastFullAuthTime);
		}
		break;

	case eap_type_ttls:
		{
			settings.Set(KTtlsDatabaseTableName);
			usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
			cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
			maxSessionTime.Set(cf_str_EAP_TTLS_max_session_validity_time_literal);
			lastFullAuthTime.Set(KTTLSLastFullAuthTime);
		}
		break;

#ifdef USE_FAST_EAP_TYPE		
	case eap_type_fast:
		{
			settings.Set(KFastGeneralSettingsDBTableName); // This is general settings for FAST.
			fastSpecialSettings.Set(KFastSpecialSettingsDBTableName);
			
			usercerts.Set(KFastAllowedUserCertsDatabaseTableName);
			cacerts.Set(KFastAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KFastAllowedCipherSuitesDatabaseTableName);
			maxSessionTime.Set(cf_str_EAP_FAST_max_session_validity_time_literal);
			lastFullAuthTime.Set(KFASTLastFullAuthTime);
		}
		break;
#endif

	case eap_type_ttls_plain_pap:
		{
			settings.Set( KTtlsDatabaseTableName );
			maxSessionTime.Set( cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal );
			lastFullAuthTime.Set( KTTLSPAPLastFullAuthTime );
		}
		break;

	default:
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - LEAVE - Unsupported EAP type =%d\n"),
				aEapVendorType) );

			// Should never happen
			User::Leave(KErrArgument);
		}
	}	
	
	RDbView view;

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	//////////////////////////////////////////
	// This is for settings for all EAP types.
	// For EAP-FAST it is General settings.
	//////////////////////////////////////////
	
	sqlStatement.Format( KSQL, &settings, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex,
		&KTunnelingType, aTunnelingVendorType );		
		
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
	if ( aEapVendorType == eap_type_ttls_plain_pap )
		{
		// Username
		if ( aSettings.iUsernamePresent )
		    {
			// Validate length.
			if( aSettings.iUsername.Length() > KMaxPapUserNameLengthInDb )
			    {
				// Username too long. Can not be stored in DB.				
				EAP_TRACE_DEBUG_SYMBIAN( ( _L( 
					"EapTlsPeapUtils::SetConfigurationL: Too long Username. Length=%d \n" ),
				aSettings.iUsername.Length() ) );
				CleanupStack::PopAndDestroy( 3 ); // colset, view, buf
				User::Leave( KErrArgument );
			    }
			
			// Length is ok. Set the value in DB.
			view.SetColL( colSet->ColNo( cf_str_EAP_TLS_PEAP_ttls_pap_username_literal ),
				aSettings.iUsername);		
		    }
		// Password
		if ( aSettings.iPasswordPresent )
		    {
			// Validate length.
			if ( aSettings.iPassword.Length() > KMaxPapPasswordLengthInDb )
			    {
				// Password too long. Can not be stored in DB.				
				EAP_TRACE_DEBUG_SYMBIAN( ( _L(
					"EapTlsPeapUtils::SetConfigurationL: Too long Password. Length=%d \n" ),
				aSettings.iPassword.Length() ) );
				CleanupStack::PopAndDestroy( 3 ); // colset, view, buf
				User::Leave( KErrArgument );
			    }
						
			// Length is ok. Set the value in DB.	
			view.SetColL( colSet->ColNo(
				cf_str_EAP_TLS_PEAP_ttls_pap_password_literal ),
				aSettings.iPassword );
			
			// If password was supplied set password prompting off
			view.SetColL( colSet->ColNo(
				cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal ),
				EPapPasswordPromptOff );
		    }
				
		// Session validity time
		if ( aSettings.iSessionValidityTimePresent )
		    {
			// User or device management wants to store the session validity time.
			// Convert the time to micro seconds and save.			
			TInt64 validityInMicro =
			    ( aSettings.iSessionValidityTime )
			    *
			    KMicroSecsInAMinute;			
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
		EAP_TRACE_DEBUG_SYMBIAN( ( _L(
			"Session Validity: EAP-Type=%d, Resetting Full Auth Time since settings are modified\n" ),
			aSettings.iEAPType ));
	    
		view.PutL();		
		CleanupStack::PopAndDestroy( 3 ); // colset, view, buf
		
	    EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL - Return \n") ) );		
	    return; 
        } // if ( aEapVendorType == eap_type_ttls_plain_pap )
	
	// Manual username
	{
		// Set the value in DB. Value could be empty. It doesn't matter.
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal), aSettings.iUsername);
		
		// This is to set the automatic or manual status.
		TUint useManualUsernameStatus;
		
		if (aSettings.iUsernamePresent)
		{
			useManualUsernameStatus = ETLSPEAPUseManualUsernameYes;
		}
		else
		{
			useManualUsernameStatus = ETLSPEAPUseManualUsernameNo;
		}
		
		// Set the value.
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal), 
			useManualUsernameStatus);
		
	}
		
	// Manual realm
	{
		// Set the value in DB. Value could be empty. It doesn't matter.
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal), aSettings.iRealm);

		// This is to set the automatic or manual status.
		TUint useManualRealmStatus;
		
		if (aSettings.iRealmPresent)
		{
			useManualRealmStatus = ETLSPEAPUseManualRealmYes;
		}
		else
		{
			useManualRealmStatus = ETLSPEAPUseManualRealmNo;
		}
		
		// Set the value.
		view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal),
			useManualRealmStatus);	
	}
	
	// Verify server realm
	if (aSettings.iVerifyServerRealmPresent)
	{
		if (aSettings.iVerifyServerRealm)
		{
			view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal), 
				ETLSPEAPVerifyCertRealmYes);
		}
		else
		{			
			view.SetColL(colSet->ColNo(cf_str_EAP_TLS_PEAP_verify_certificate_realm_literal), 
				ETLSPEAPVerifyCertRealmNo);
		}
	}
	
	// Require client authentication
	if (aSettings.iRequireClientAuthenticationPresent)
	{
		if (aSettings.iRequireClientAuthentication)
		{
			view.SetColL(colSet->ColNo(cf_str_TLS_server_authenticates_client_policy_in_client_literal),
				ETLSPEAPServerAuthenticatesClientPolicyYes);
		}
		else
		{			
			view.SetColL(colSet->ColNo(cf_str_TLS_server_authenticates_client_policy_in_client_literal),
				ETLSPEAPServerAuthenticatesClientPolicyNo);
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

	EAP_TRACE_DEBUG_SYMBIAN((_L("Session Validity: EAP-Type=%d, Resetting Full Auth Time since settings are modified\n"),
								aSettings.iEAPType ));	
	
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
	
	view.PutL();
	
	CleanupStack::PopAndDestroy(2); // view, colset	
	
#ifdef USE_FAST_EAP_TYPE		

	///////////////////////////////////////////////////////
	// This is only for EAP-FAST specific, Special settings.
	///////////////////////////////////////////////////////
	
	if(aEapType == eap_type_fast)
	{
		sqlStatement.Format(KSQL, &fastSpecialSettings, 
			&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
		
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
					EFASTAuthProvModeAllowedYes);
			}
			else
			{			
				view.SetColL(colSet->ColNo(cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal), 
					EFASTAuthProvModeAllowedNo);
			}
		}
		
		if (aSettings.iUnauthProvModeAllowedPresent)
		{
			if (aSettings.iUnauthProvModeAllowed)
			{
				view.SetColL(colSet->ColNo(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal), 
					EFASTUnauthProvModeAllowedYes);
			}
			else
			{			
				view.SetColL(colSet->ColNo(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal), 
					EFASTUnauthProvModeAllowedNo);
			}
		}
		
		// For the warnings and prompts
		if (aSettings.iWarnADHPNoPACPresent)
		{
			if (aSettings.iWarnADHPNoPAC)
			{
				view.SetColL(colSet->ColNo(KFASTWarnADHPNoPAC), 
						EFASTWarnADHPNoPACYes);
			}
			else
			{			
				view.SetColL(colSet->ColNo(KFASTWarnADHPNoPAC), 
						EFASTWarnADHPNoPACNo);
			}
		}	
		
		if (aSettings.iWarnADHPNoMatchingPACPresent)
		{
			if (aSettings.iWarnADHPNoMatchingPAC)
			{
				view.SetColL(colSet->ColNo(KFASTWarnADHPNoMatchingPAC), 
						EFASTWarnADHPNoMatchingPACYes);
			}
			else
			{			
				view.SetColL(colSet->ColNo(KFASTWarnADHPNoMatchingPAC), 
						EFASTWarnADHPNoMatchingPACNo);
			}
		}	
		
		if (aSettings.iWarnNotDefaultServerPresent)
		{
			if (aSettings.iWarnADHPNoMatchingPAC)
			{
				view.SetColL(colSet->ColNo(KFASTWarnNotDefaultServer), 
						EFASTWarnNotDefaultServerYes);
			}
			else
			{			
				view.SetColL(colSet->ColNo(KFASTWarnNotDefaultServer), 
						EFASTWarnNotDefaultServerNo);
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
		
		CleanupStack::PopAndDestroy(2); // view, colset			
	
	} // End: if(aEapType == eap_type_fast)
	
#endif // #ifdef USE_FAST_EAP_TYPE		
	
	//////////////////
	// Cipher suites
	//////////////////
	
	if (aSettings.iCipherSuitesPresent)
	{
		sqlStatement.Format(KSQL, &ciphersuites, 
			&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
		
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
			view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);
			view.SetColL(colSet->ColNo(KCipherSuite), aSettings.iCipherSuites[i]);
			view.PutL();	
		}
		
		CleanupStack::PopAndDestroy(2); // view, colset
	}
	
	/////////////////////////
	// User + CA Certificates
	/////////////////////////
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL - aSettings.iCertificatesPresent=%d \n"), aSettings.iCertificatesPresent ) );
	
	if (aSettings.iCertificatesPresent)
	{
		// Needed for getting the Symbian's subject key id.
		CEapTlsPeapCertFetcher* certFetcher = CEapTlsPeapCertFetcher::NewL();
		CleanupStack::PushL(certFetcher);
				
		TBuf8<KKeyIdentifierLength> symbianSubjectKeyID;		
		
		// For USER certificate.		
		sqlStatement.Format(KSQL, &usercerts, 
			&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
			
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
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL - aSettings.iCertificates.Count()=%d \n"), aSettings.iCertificates.Count() ) );

		for (i = 0; i < aSettings.iCertificates.Count(); i++)
		{
			if (aSettings.iCertificates[i].iCertType == CertificateEntry::EUser)
			{	
				// Validate the length and save other certificate details to the DB.
				if(aSettings.iCertificates[i].iSubjectName.Length() > KKeyIdentifierLength
				   || aSettings.iCertificates[i].iIssuerName.Length() > KGeneralStringMaxLength
				   || aSettings.iCertificates[i].iSerialNumber.Length() > KGeneralStringMaxLength
				   || aSettings.iCertificates[i].iSubjectKeyID.Length() > KGeneralStringMaxLength
				   || aSettings.iCertificates[i].iThumbprint.Length() > KThumbprintMaxLength)
				{
					// Too long data. Can not be stored in DB.

					EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL : Too long USER cert details.\n")));
										
					User::Leave(KErrArgument);
				}					
						
				EAP_TRACE_DATA_DEBUG_SYMBIAN(("THIS IS SubjectKeyID:",
						aSettings.iCertificates[i].iSubjectKeyID.Ptr(), aSettings.iCertificates[i].iSubjectKeyID.Size()));

				// The cert label column is left empty

				view.InsertL();			
				view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(aIndexType));
				view.SetColL(colSet->ColNo(KServiceIndex), static_cast<TUint>(aIndex));
				view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);				
																
				view.SetColL(colSet->ColNo(KSubjectName), aSettings.iCertificates[i].iSubjectName);
				view.SetColL(colSet->ColNo(KIssuerName), aSettings.iCertificates[i].iIssuerName);
				view.SetColL(colSet->ColNo(KSerialNumber), aSettings.iCertificates[i].iSerialNumber);
				view.SetColL(colSet->ColNo(KActualSubjectKeyIdentifier), aSettings.iCertificates[i].iSubjectKeyID);					
				
				// Special for thumb print (finger print). Need to convert it to 8 bits before storing in DB
				TBuf8<KThumbprintMaxLength> thumbPrint8Bit;
				thumbPrint8Bit.Copy(aSettings.iCertificates[i].iThumbprint);
				
				view.SetColL(colSet->ColNo(KThumbprint), thumbPrint8Bit);
				
				view.SetColL(colSet->ColNo(KSubjectKeyIdentifier), aSettings.iCertificates[i].iSubjectKeyID);
			
				view.PutL();	
				}
		}
		CleanupStack::PopAndDestroy(2); // view, colset			

		// Do the same for CA certificates.		
		sqlStatement.Format(KSQL, &cacerts, 
			&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
		
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
			if (aSettings.iCertificates[i].iCertType == CertificateEntry::ECA)
			{
				// Validate the length and save other certificate details to the DB.
				if(aSettings.iCertificates[i].iSubjectName.Length() > KKeyIdentifierLength
				   || aSettings.iCertificates[i].iIssuerName.Length() > KGeneralStringMaxLength
				   || aSettings.iCertificates[i].iSerialNumber.Length() > KGeneralStringMaxLength
				   || aSettings.iCertificates[i].iSubjectKeyID.Length() > KGeneralStringMaxLength
				   || aSettings.iCertificates[i].iThumbprint.Length() > KThumbprintMaxLength)
				{
					// Too long data. Can not be stored in DB.

					EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL:Too long CA cert details.\n")));
										
					User::Leave(KErrArgument);
				}					
					
				// The cert label column is left empty
				
				view.InsertL();			
				view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(aIndexType));
				view.SetColL(colSet->ColNo(KServiceIndex), static_cast<TUint>(aIndex));				
				view.SetColL(colSet->ColNo(KTunnelingType),aTunnelingVendorType);
								
				view.SetColL(colSet->ColNo(KSubjectName), aSettings.iCertificates[i].iSubjectName);
				view.SetColL(colSet->ColNo(KIssuerName), aSettings.iCertificates[i].iIssuerName);
				view.SetColL(colSet->ColNo(KSerialNumber), aSettings.iCertificates[i].iSerialNumber);
				view.SetColL(colSet->ColNo(KActualSubjectKeyIdentifier), aSettings.iCertificates[i].iSubjectKeyID);					
				
				// Special for thumb print (finger print). Need to convert it to 8 bits before storing in DB
				TBuf8<KThumbprintMaxLength> thumbPrint8Bit;
				thumbPrint8Bit.Copy(aSettings.iCertificates[i].iThumbprint);
				
				view.SetColL(colSet->ColNo(KThumbprint), thumbPrint8Bit);
				
				// Get the "symbian's subject key id" using symbian API.
				// We use this subject key id for authentication.

				view.SetColL(colSet->ColNo(KSubjectKeyIdentifier), aSettings.iCertificates[i].iSubjectKeyID);

				EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "EapTlsPeapUtils::SetConfigurationL - Adding CA cert to DB, Supplied (Actual) SubjectKeyID:",
					aSettings.iCertificates[i].iSubjectKeyID.Ptr(), aSettings.iCertificates[i].iSubjectKeyID.Size() ) );				
				
				view.PutL();
				}
		}
		
		CleanupStack::PopAndDestroy(2); // view, colset	
		
		CleanupStack::PopAndDestroy(certFetcher);
		
	} // End of if (aSettings.iCertificatesPresent)
	
	CleanupStack::PopAndDestroy(); // buf
		
	/////////////////////
	// Encapsulated types
	/////////////////////
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL - aSettings.iEncapsulatedEAPTypesPresent=%d \n"), aSettings.iEncapsulatedEAPTypesPresent ) );

	// Encapsulated types are only for EAP-PEAP, EAP-TTLS and EAP-FAST. Not for EAP-TLS.
	// This is just to be on safe side. In case if iEncapsulatedEAPTypesPresent is set true for EAP-TLS by the caller.
	if ( aEapType != eap_type_peap 
		 && aEapType != eap_type_ttls
#ifdef USE_FAST_EAP_TYPE
		 && aEapType != eap_type_fast
#endif		  		 
		  )
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::SetConfigurationL - End - Since no encapsulated type for the EAPType =%d \n"),
			aEapVendorType  ) );
			
		return; // No need to proceed. No encapsulated type for EAP-TLS..
	}
	
#ifdef USE_EAP_EXPANDED_TYPES

	if (aSettings.iEncapsulatedEAPTypesPresent)
	{
		RExpandedEapTypePtrArray enabledEAPTypes;
		// This is just for dummy. All EAP types available here are enabled as default.
		RExpandedEapTypePtrArray disabledEAPTypes;
		SExpandedEAPType* expandedEAPTmp = 0;
	
		for (TInt i = 0; i < aSettings.iEncapsulatedEAPTypes.Count(); i++)
		{
			expandedEAPTmp = new SExpandedEAPType;

			if (expandedEAPTmp == 0)
			{
				enabledEAPTypes.ResetAndDestroy();
				disabledEAPTypes.ResetAndDestroy();
				enabledEAPTypes.Close();
				disabledEAPTypes.Close();
				User::Leave(KErrNoMemory);				
			}
			
			// This fills the needed values for vendor id etc.
			eap_expanded_type_c tmpExpEAP(static_cast <eap_type_ietf_values_e> (aSettings.iEncapsulatedEAPTypes[i]));
			
			// This is only for plain-MSCHAPv2 as long as we are using the value 99 for it.
			if(aSettings.iEncapsulatedEAPTypes[i] == EAPSettings::EPlainMschapv2)
			{
				tmpExpEAP.set_eap_type_values(
					eap_type_vendor_id_hack,
					eap_type_vendor_type_plain_MSCHAPv2_hack);
			}
			
			// And this is for TTLS-PAP as long as we are using the value 98 for it.
			if(aSettings.iEncapsulatedEAPTypes[i] == EAPSettings::ETtlsPlainPap)
			{
				tmpExpEAP.set_eap_type_values(
					eap_type_vendor_id_hack,
					eap_type_vendor_type_ttls_plain_pap_hack);
			}
			
			// Some indirect way of forming the 8 byte string of an EAP type is needed here.
			TUint8 tmpExpBuffer[KExpandedEAPTypeSize]; // This is for the eap_expanded_type_c::write_type
			
			// This copies the 8 byte string of EAP type to tmpExpBuffer. 
			eap_status_e status = eap_expanded_type_c::write_type(0,
											0, // index should be zero here.
											tmpExpBuffer,
											KExpandedEAPTypeSize,
											true,
											tmpExpEAP);
											
			// Now copy the 8 byte string to expandedEAPTmp.
			expandedEAPTmp->iExpandedEAPType.Copy(tmpExpBuffer, KExpandedEAPTypeSize);
			
			EAP_TRACE_DATA_DEBUG_SYMBIAN(
				("EapTlsPeapUtils::SetConfigurationL: Expanded EAp type string",
				expandedEAPTmp->iExpandedEAPType.Ptr(), 
				expandedEAPTmp->iExpandedEAPType.Size() ) );						
														

			enabledEAPTypes.Append(expandedEAPTmp);
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
			EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL - ########### Setting Expanded Tunneling types in the DB failed ############ \n") ) );

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

#else // For normal unexpanded EAP type.
	
	if (aSettings.iEncapsulatedEAPTypesPresent)
	{
		TEapArray eapArray;
		
		TEap *eap;
		for (TInt i = 0; i < aSettings.iEncapsulatedEAPTypes.Count(); i++)
		{
			eap = new TEap;
			if (eap == 0)
			{
				eapArray.ResetAndDestroy();
				eapArray.Close();
				User::Leave(KErrNoMemory);				
			}
			
			eap->UID.NumFixedWidth(aSettings.iEncapsulatedEAPTypes[i], EDecimal, 2);
			eap->Enabled = ETrue;
			eapArray.Append(eap);
		}	
	
		TInt err(KErrNone);
		TRAP(err, SetEapDataL(
			aDatabase,
			0,
			eapArray,
			aIndexType,
			aIndex,
			aTunnelingType,
			aEapType));

		if( err != KErrNone )
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL - ########### Setting Tunneling types in the DB failed ############ \n") ) );

			eapArray.ResetAndDestroy();
			eapArray.Close();			

			User::Leave(KErrArgument); // There could be some problem in the encapsulated EAP type argument.
		}

		eapArray.ResetAndDestroy();
		eapArray.Close();			
	}

#endif //#ifdef USE_EAP_EXPANDED_TYPES
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::SetConfigurationL - End \n") ) );		

} // EapTlsPeapUtils::SetConfigurationL()


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
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();
	TUint aEapVendorType = aEapType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);
	TUint aEapVendorType = static_cast<TUint>(aEapType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES
		
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::GetConfigurationL aIndexType=%d, aIndex=%d, Tunneling vendor type=%d, Eap vendor type=%d \n"),
		aIndexType,aIndex, aTunnelingVendorType, aEapVendorType));

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
	
	switch (aEapVendorType)
	{
	case eap_type_tls:
		{
			settings.Set(KTlsDatabaseTableName);
			usercerts.Set(KTlsAllowedUserCertsDatabaseTableName);
			cacerts.Set(KTlsAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KTlsAllowedCipherSuitesDatabaseTableName);
			maxSessionTime.Set(cf_str_EAP_TLS_max_session_validity_time_literal);
		}
		break;

	case eap_type_peap:
		{
			settings.Set(KPeapDatabaseTableName);
			usercerts.Set(KPeapAllowedUserCertsDatabaseTableName);
			cacerts.Set(KPeapAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KPeapAllowedCipherSuitesDatabaseTableName);
			maxSessionTime.Set(cf_str_EAP_PEAP_max_session_validity_time_literal);
		}
		break;

	case eap_type_ttls:
		{
			settings.Set(KTtlsDatabaseTableName);
			usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
			cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
			maxSessionTime.Set(cf_str_EAP_TTLS_max_session_validity_time_literal);
		}
		break;

#ifdef USE_FAST_EAP_TYPE
	case eap_type_fast:
		{
			settings.Set(KFastGeneralSettingsDBTableName); // This is general settings for FAST.
			fastSpecialSettings.Set(KFastSpecialSettingsDBTableName);
			
			usercerts.Set(KFastAllowedUserCertsDatabaseTableName);
			cacerts.Set(KFastAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KFastAllowedCipherSuitesDatabaseTableName);
			maxSessionTime.Set(cf_str_EAP_FAST_max_session_validity_time_literal);
		}
		break;
#endif


	case eap_type_ttls_plain_pap:
		{
		settings.Set( KTtlsDatabaseTableName );
		maxSessionTime.Set( cf_str_EAP_TLS_PEAP_ttls_pap_max_session_validity_time_literal );
		}
		break;
		
	default:
		// Should never happen
		User::Leave(KErrArgument);
	}	
	
	RDbView view;

	// Form the query
	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	//////////////////////////////////////////
	// This is for settings for all EAP types.
	// For EAP-FAST it is General settings.
	//////////////////////////////////////////
	
	sqlStatement.Format(KSQL, &settings, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);

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

	aSettings.iEAPType = static_cast<EAPSettings::TEapType>(aEapVendorType);
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL - aSettings.iEAPType=%d \n"),aSettings.iEAPType) );
	
	//////////////////////////////////////////
	// This is only for plain PAP settings. //
	//////////////////////////////////////////
	if ( aEapType == eap_type_ttls_plain_pap )
		{		
	    // Username
	    TPtrC username = view.ColDes( colSet->ColNo(
	   		cf_str_EAP_TLS_PEAP_ttls_pap_username_literal ) );
	    aSettings.iUsername.Copy( username );
	    aSettings.iUsernamePresent = ETrue;
	
        // Password
	    TPtrC password = view.ColDes( colSet->ColNo(
    		cf_str_EAP_TLS_PEAP_ttls_pap_password_literal ) );
	    aSettings.iPassword.Copy( password );
	    aSettings.iPasswordPresent = ETrue;

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

	
	// Username
	TPtrC username = view.ColDes(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal));
	aSettings.iUsername.Copy(username);

	// For manual or automatic status.
	TUint useUsername = view.ColUint(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal));
	if(useUsername == ETLSPEAPUseManualUsernameNo)
	{
		aSettings.iUsernamePresent = EFalse;		
	}
	else
	{
		aSettings.iUsernamePresent = ETrue;		
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL - Settings.iUsername=%S \n"), &(aSettings.iUsername) ) );
		
	// Realm
	TPtrC realm = view.ColDes(colSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal));
	aSettings.iRealm.Copy(realm);

	// For manual or automatic status.
	TUint useRealm = view.ColUint(colSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal));
	if(useRealm == ETLSPEAPUseManualRealmNo)
	{
		aSettings.iRealmPresent = EFalse;
	}
	else
	{
		aSettings.iRealmPresent = ETrue;
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL - aSettings.iRealm=%S \n"),&(aSettings.iRealm)) );

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

	// Session validity time	
	TInt64 maxSessionTimeMicro = view.ColInt64(colSet->ColNo(maxSessionTime));
	
	// Convert the time to minutes.	
	TInt64 maxSessionTimeMin = maxSessionTimeMicro / KMicroSecsInAMinute;
	
	aSettings.iSessionValidityTime = static_cast<TUint>(maxSessionTimeMin);
	aSettings.iSessionValidityTimePresent = ETrue;

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
	
	CleanupStack::PopAndDestroy(2); // view, colset
	
#ifdef USE_FAST_EAP_TYPE		

	///////////////////////////////////////////////////////
	// This is only for EAP-FAST specific, Special settings.
	///////////////////////////////////////////////////////	
	
	if(aEapType == eap_type_fast)
	{
		sqlStatement.Format(KSQL, &fastSpecialSettings, 
			&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
	
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
		if(authProvMode == EFASTAuthProvModeAllowedNo)
		{
			aSettings.iAuthProvModeAllowed = EFalse;
		}
		else
		{
			aSettings.iAuthProvModeAllowed = ETrue;
		}
		
		aSettings.iAuthProvModeAllowedPresent = ETrue;

		TUint unauthProvMode = view.ColUint(colSet->ColNo(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal));
		if(unauthProvMode == EFASTUnauthProvModeAllowedNo)
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
		if(warn == EFASTWarnADHPNoPACNo)
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
		if(warn == EFASTWarnADHPNoMatchingPACNo)
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
		if(warn == EFASTWarnNotDefaultServerNo)
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
		
		CleanupStack::PopAndDestroy(2); // view, colset		
				
	} // End: if(aEapType == eap_type_fast) 

#endif //#ifdef USE_FAST_EAP_TYPE		
		
	
	//////////////////
	// Cipher suites
	//////////////////
	
	sqlStatement.Format(KSQL, &ciphersuites, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
	
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
				aSettings.iCipherSuites.Append(view.ColUint(colSet->ColNo(KCipherSuite)));
			}
		} while (view.NextL() != EFalse);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL - Total cipher suites appended=%d \n"),aSettings.iCipherSuites.Count()) );
	
	aSettings.iCipherSuitesPresent = ETrue;
	
	CleanupStack::PopAndDestroy(2); // view, colset
	
	/////////////////
	// User Certificates
	/////////////////

	sqlStatement.Format(KSQL, &usercerts, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
	
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
				CertificateEntry * certEntry = new (ELeave) CertificateEntry;
				CleanupStack::PushL(certEntry);

				certEntry->iCertType = CertificateEntry::EUser;
				
				certEntry->iSubjectName.Copy(view.ColDes(colSet->ColNo(KSubjectName)));
				if(certEntry->iSubjectName.Length())
				{
					certEntry->iSubjectNamePresent = ETrue;
				}
				
				certEntry->iIssuerName.Copy(view.ColDes(colSet->ColNo(KIssuerName)));
				if(certEntry->iIssuerName.Length())
				{
					certEntry->iIssuerNamePresent = ETrue;
				}

				certEntry->iSerialNumber.Copy(view.ColDes(colSet->ColNo(KSerialNumber)));
				if(certEntry->iSerialNumber.Length())
				{
					certEntry->iSerialNumberPresent = ETrue;
				}

				certEntry->iSubjectKeyID.Copy(view.ColDes8(colSet->ColNo(KActualSubjectKeyIdentifier))); // This is the subjectkey id we got in SetConfigurationL
				if(certEntry->iSubjectKeyID.Length())
				{
					certEntry->iSubjectKeyIDPresent = ETrue;
				}

				certEntry->iThumbprint.Copy(view.ColDes8(colSet->ColNo(KThumbprint)));				
				if(certEntry->iThumbprint.Length())
				{
					certEntry->iThumbprintPresent = ETrue;
				}

				aSettings.iCertificates.AppendL(*certEntry);

				EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "EapTlsPeapUtils::GetConfigurationL - Filling User cert entry, SubjectKeyID:",
					certEntry->iSubjectKeyID.Ptr(), certEntry->iSubjectKeyID.Size() ) );

				CleanupStack::PopAndDestroy(certEntry);
			}
		} while (view.NextL() != EFalse);
	}
	
	CleanupStack::PopAndDestroy(2); // view, colset
	
	/////////////////
	// CA Certificates
	/////////////////

	sqlStatement.Format(KSQL, &cacerts, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
	
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
				CertificateEntry * certEntry = new (ELeave) CertificateEntry;
				CleanupStack::PushL(certEntry);

				certEntry->iCertType = CertificateEntry::ECA;
				
				certEntry->iSubjectName.Copy(view.ColDes(colSet->ColNo(KSubjectName)));
				if(certEntry->iSubjectName.Length())
				{
					certEntry->iSubjectNamePresent = ETrue;
				}
				
				certEntry->iIssuerName.Copy(view.ColDes(colSet->ColNo(KIssuerName)));
				if(certEntry->iIssuerName.Length())
				{
					certEntry->iIssuerNamePresent = ETrue;
				}

				certEntry->iSerialNumber.Copy(view.ColDes(colSet->ColNo(KSerialNumber)));
				if(certEntry->iSerialNumber.Length())
				{
					certEntry->iSerialNumberPresent = ETrue;
				}

				certEntry->iSubjectKeyID.Copy(view.ColDes8(colSet->ColNo(KActualSubjectKeyIdentifier))); // This is the subjectkey id we got in SetConfigurationL
				if(certEntry->iSubjectKeyID.Length())
				{
					certEntry->iSubjectKeyIDPresent = ETrue;
				}

				certEntry->iThumbprint.Copy(view.ColDes8(colSet->ColNo(KThumbprint)));				
				if(certEntry->iThumbprint.Length())
				{
					certEntry->iThumbprintPresent = ETrue;
				}
				
				aSettings.iCertificates.AppendL(*certEntry);

				EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "EapTlsPeapUtils::GetConfigurationL - Filling CA cert entry, SubjectKeyID:",
					certEntry->iSubjectKeyID.Ptr(), certEntry->iSubjectKeyID.Size() ) );

				CleanupStack::PopAndDestroy(certEntry);
			}
		} while (view.NextL() != EFalse);
	}
	
	CleanupStack::PopAndDestroy(3); // view, colset, buf
	
	aSettings.iCertificatesPresent = ETrue;
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("**************** GetConfigurationL - Returning the below values: ***************\n")) );
	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - Return these values for EAPType=%d"),aSettings.iEAPType) );
	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, Username=%S"),aSettings.iUsernamePresent, &(aSettings.iUsername)) );
	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, Password=%S"),aSettings.iPasswordPresent, &(aSettings.iPassword)) );
	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, Realm=%S"),aSettings.iRealmPresent, &(aSettings.iRealm)) );
	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, UsePseudonyms=%d"),aSettings.iUsePseudonymsPresent, aSettings.iUsePseudonyms) );
	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, VerifyServerRealm=%d"),
						aSettings.iVerifyServerRealmPresent, aSettings.iVerifyServerRealm) );

	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, RequireClientAuthentication=%d"),
						aSettings.iRequireClientAuthenticationPresent, aSettings.iRequireClientAuthentication) );
						
	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, SessionValidityTime=%d minutes"),
						aSettings.iSessionValidityTimePresent, aSettings.iSessionValidityTime) );
						
	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, CipherSuites Count=%d"),
						aSettings.iCipherSuitesPresent, aSettings.iCipherSuites.Count()) );
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, PEAPv0Allowed=%d, PEAPv1Allowed=%d, PEAPv2Allowed=%d"),
						aSettings.iPEAPVersionsPresent, aSettings.iPEAPv0Allowed,aSettings.iPEAPv1Allowed, aSettings.iPEAPv2Allowed ) );
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, Certificates Count=%d"),
						aSettings.iCertificatesPresent, aSettings.iCertificates.Count()) );
						
	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - Certificate details below: \n")) );
	for( TInt n=0; n < aSettings.iCertificates.Count(); n++ )
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - Certificate type:%d \n"), aSettings.iCertificates[n].iCertType) );
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - certificates - present=%d, SubjectName=%S"),
						aSettings.iCertificates[n].iSubjectNamePresent, &(aSettings.iCertificates[n].iSubjectName)) );
						
		EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - certificates - present=%d, IssuerName=%S"),
						aSettings.iCertificates[n].iIssuerNamePresent, &(aSettings.iCertificates[n].iIssuerName)) );
						
		EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - certificates - present=%d, SerialNumber=%S"),
						aSettings.iCertificates[n].iSerialNumberPresent, &(aSettings.iCertificates[n].iSerialNumber)) );
						
		EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - certificates - SubjectKeyID present=%d"),
						aSettings.iCertificates[n].iSubjectKeyIDPresent ) );
						
		EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "SubjectKeyID:", aSettings.iCertificates[n].iSubjectKeyID.Ptr(), 
													aSettings.iCertificates[n].iSubjectKeyID.Size() ) );						

		EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - certificates - Thumbprint present=%d"),
						aSettings.iCertificates[n].iThumbprintPresent ) );
						
		EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "Thumbprint:", aSettings.iCertificates[n].iThumbprint.Ptr(), 
													aSettings.iCertificates[n].iThumbprint.Size() ) );						
	}
	
#ifdef USE_FAST_EAP_TYPE		

	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, AuthProvModeAllowed=%d"),
						aSettings.iAuthProvModeAllowedPresent, aSettings.iAuthProvModeAllowed) );

	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, UnauthProvModeAllowed=%d"),
						aSettings.iUnauthProvModeAllowedPresent, aSettings.iUnauthProvModeAllowed) );

	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, WarnADHPNoPAC=%d"),
			aSettings.iWarnADHPNoPACPresent, aSettings.iWarnADHPNoPAC) );

	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, WarnADHPNoMatchingPAC=%d"),
			aSettings.iWarnADHPNoMatchingPACPresent, aSettings.iWarnADHPNoMatchingPAC) );

	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, WarnNotDefaultServer=%d"),
			aSettings.iWarnNotDefaultServerPresent, aSettings.iWarnNotDefaultServer) );
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("GetConfigurationL - present=%d, PAC Group Ref=%S"),
						aSettings.iPACGroupReferencePresent, &(aSettings.iPACGroupReference)) );

#endif //#ifdef USE_FAST_EAP_TYPE		
					
	EAP_TRACE_DEBUG_SYMBIAN((_L("**************** GetConfigurationL - Returning the above values: ***************\n")) );

	
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
		aSettings.iEncapsulatedEAPTypesPresent = EFalse;
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::GetConfigurationL - End - Since no encapsulated type for the EAPType =%d \n"),
			aEapVendorType));
		
		return; // No need to proceed. Nothing more to provide.
	}
		
#ifdef USE_EAP_EXPANDED_TYPES

	RExpandedEapTypePtrArray enabledEAPTypes;
	RExpandedEapTypePtrArray disabledEAPTypes;
	
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
			EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL - ########### Getting Expanded Tunneling types from the DB failed ############ \n") ) );

			enabledEAPTypes.ResetAndDestroy();
			disabledEAPTypes.ResetAndDestroy();
			enabledEAPTypes.Close();
			disabledEAPTypes.Close();

			User::Leave(KErrGeneral);
		}

	// There should be some enabled EAP types (atleast one).
	if (enabledEAPTypes.Count() == 0)
	{
		// Nothing enabled. Some problem. 
		// We should get all the available EAP plugins on the device and make them enabled as default.
		
		RImplInfoPtrArray eapImplArray;

		TRAP(error, REComSession::ListImplementationsL(KEapTypeInterfaceUid, eapImplArray));
		if (error != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL - ########### Getting Expanded Tunneling types - Listing ECOM plugins failed ############ \n") ) );

			enabledEAPTypes.ResetAndDestroy();
			disabledEAPTypes.ResetAndDestroy();
			enabledEAPTypes.Close();
			disabledEAPTypes.Close();

			User::Leave(KErrNotFound);
		}
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("GetConfigurationL - ListImplementationsL - No: of available EAP plugin implementations=%d \n"),
		 	eapImplArray.Count() ) );
		
		SExpandedEAPType* expandedEAPTmp;
		
		// Add the EAP types to enabledEAPTypes array now.
		
		for (TInt i = 0; i < eapImplArray.Count(); i++)
		{		
			if (aEapType == eap_type_peap)
			{
				// Some EAP types are not allowed inside EAP-PEAP.
				if (CEapType::IsDisallowedInsidePEAP(*eapImplArray[i]))
				{			
					continue;	
				}
				
				expandedEAPTmp = new SExpandedEAPType;
				if (expandedEAPTmp == 0)
				{
					enabledEAPTypes.ResetAndDestroy();
					disabledEAPTypes.ResetAndDestroy();
					enabledEAPTypes.Close();
					disabledEAPTypes.Close();

					eapImplArray.ResetAndDestroy();
					eapImplArray.Close();				

					User::Leave(KErrNoMemory);				
				}
				
				CleanupStack::PushL(expandedEAPTmp);
				
				expandedEAPTmp->iExpandedEAPType.Copy(eapImplArray[i]->DataType());

				enabledEAPTypes.Append(expandedEAPTmp);				
				
				CleanupStack::Pop(expandedEAPTmp);
			}

			if (aEapType == eap_type_ttls)
			{
				// Some EAP types are not allowed inside EAP-TTLS.
				if (CEapType::IsDisallowedInsideTTLS(*eapImplArray[i]))
				{			
					continue;	
				}
				
				expandedEAPTmp = new SExpandedEAPType;
				if (expandedEAPTmp == 0)
				{
					enabledEAPTypes.ResetAndDestroy();
					disabledEAPTypes.ResetAndDestroy();
					enabledEAPTypes.Close();
					disabledEAPTypes.Close();

					eapImplArray.ResetAndDestroy();
					eapImplArray.Close();				

					User::Leave(KErrNoMemory);				
				}
				
				CleanupStack::PushL(expandedEAPTmp);
				
				expandedEAPTmp->iExpandedEAPType.Copy(eapImplArray[i]->DataType());

				enabledEAPTypes.Append(expandedEAPTmp);				
				
				CleanupStack::Pop(expandedEAPTmp);
			}

#ifdef USE_FAST_EAP_TYPE

			if (aEapType == eap_type_fast)
			{
				// Some EAP types are not allowed inside EAP-FAST.
				if (CEapType::IsDisallowedInsidePEAP(*eapImplArray[i]))
				{			
					continue;	
				}
				
				expandedEAPTmp = new SExpandedEAPType;
				if (expandedEAPTmp == 0)
				{
					enabledEAPTypes.ResetAndDestroy();
					disabledEAPTypes.ResetAndDestroy();
					enabledEAPTypes.Close();
					disabledEAPTypes.Close();

					eapImplArray.ResetAndDestroy();
					eapImplArray.Close();				

					User::Leave(KErrNoMemory);				
				}
				
				CleanupStack::PushL(expandedEAPTmp);
				
				expandedEAPTmp->iExpandedEAPType.Copy(eapImplArray[i]->DataType());

				enabledEAPTypes.Append(expandedEAPTmp);				
				
				CleanupStack::Pop(expandedEAPTmp);
			}
#endif // #ifdef USE_FAST_EAP_TYPE

		} // End: for (TInt i = 0; i < eapImplArray.Count(); i++)
		
		eapImplArray.ResetAndDestroy();
		eapImplArray.Close();
							
	} // End: if (enabledEAPTypes.Count() == 0)

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::GetConfigurationL - No: of available tunneled types for this EAP=%d \n"),
		enabledEAPTypes.Count()));

	// enabledEAPTypes contains the EAP types now (expanded).
	// Fill aSettings.iEncapsulatedEAPTypes here.
	
	for (TInt i = 0; i < enabledEAPTypes.Count(); i++)
	{
		eap_expanded_type_c expEAPTmp;
		
		// This will read the expanded EAP from enabledEAPTypes[i]->iExpandedEAPType to expEAPTmp.
		// This makes easy to get the vendor type.
		eap_expanded_type_c::read_type( 0,
										0,
										enabledEAPTypes[i]->iExpandedEAPType.Ptr(),
										KExpandedEAPTypeSize,
										&expEAPTmp);
	
		// We need to fill only the vendor type to aSettings.iEncapsulatedEAPTypes
		aSettings.iEncapsulatedEAPTypes.Append(expEAPTmp.get_vendor_type());
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::GetConfigurationL - Available encapsulated type for this EAP(%d)=%d\n"),
			aEapVendorType, expEAPTmp.get_vendor_type()));
	}
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::GetConfigurationL - aSettings.iEncapsulatedEAPTypes.Count()=%d \n"),
		aSettings.iEncapsulatedEAPTypes.Count()));

	enabledEAPTypes.ResetAndDestroy();
	disabledEAPTypes.ResetAndDestroy();
	enabledEAPTypes.Close();
	disabledEAPTypes.Close();

	aSettings.iEncapsulatedEAPTypesPresent = ETrue;

#else // for Normal EAP types.
			
	TEapArray eapArray;
		
	TRAPD(err, GetEapDataL(
		aDatabase,
		0,
		eapArray, 
		aIndexType,
		aIndex,
		aTunnelingType,	
		aEapType));
	if (err != KErrNone)
	{
		eapArray.ResetAndDestroy();
		eapArray.Close();
		User::Leave(KErrGeneral);
	}
	
	RImplInfoPtrArray eapImplArray;
	
	if (eapArray.Count() == 0)
	{
		// The array was empty. By default all types are enabled.
		TRAP(err, REComSession::ListImplementationsL(KEapTypeInterfaceUid, eapImplArray));
		if (err != KErrNone)
		{
			eapArray.ResetAndDestroy();
			eapArray.Close();
			User::Leave(KErrGeneral);
		}
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL - ListImplementationsL - No: of available implementations=%d \n"), eapImplArray.Count() ) );
		
		TEap *eap;
		for (TInt i = 0; i < eapImplArray.Count(); i++)
		{
			if (CEapType::IsDisallowedInsidePEAP(*eapImplArray[i]))
			{			
				continue;	
			}
			
			eap = new TEap;
			if (eap == 0)
			{
				eapArray.ResetAndDestroy();
				eapArray.Close();
				eapImplArray.ResetAndDestroy();
				eapImplArray.Close();				
				User::Leave(KErrGeneral);				
			}
			eap->UID.Copy(eapImplArray[i]->DataType());
			eap->Enabled = ETrue;
			eapArray.Append(eap);
		}	
	}

	TInt i(0);

	for (i = 0; i < eapArray.Count(); i++)
	{
		if (eapArray[i]->Enabled)
		{
			TLex8 tmp(eapArray[i]->UID);
			TUint val(0);
			tmp.Val(val);
			aSettings.iEncapsulatedEAPTypes.Append(val);

			EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL - Available encapsulated type for this EAP =%d \n"), val ) );
		}	
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL - eapArray.Count()=%d \n"),eapArray.Count() ) );
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL - aSettings.iEncapsulatedEAPTypes.Count()=%d \n"),aSettings.iEncapsulatedEAPTypes.Count() ) );	

	eapArray.ResetAndDestroy();
	eapArray.Close();
	eapImplArray.ResetAndDestroy();
	eapImplArray.Close();				
		
	aSettings.iEncapsulatedEAPTypesPresent = ETrue;
	
#endif //#ifdef USE_EAP_EXPANDED_TYPES
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::GetConfigurationL - End \n") ) );	

} // EapTlsPeapUtils::GetConfigurationL()


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
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aSrcTunnelingVendorType = aSrcTunnelingType.get_vendor_type();
	TUint aDestTunnelingVendorType = aDestTunnelingType.get_vendor_type();

#else

	TUint aSrcTunnelingVendorType = static_cast<TUint>(aSrcTunnelingType);
	TUint aDestTunnelingVendorType = static_cast<TUint>(aDestTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

    EAP_TRACE_DEBUG_SYMBIAN(
        (_L("EapTlsPeapUtils::CopySettingsL table=%s, aSrcIndexType=%d, aDestIndexType=%d, aSrcIndex=%d, aDestIndex=%d, SrcTunneling vendor type=%d, DestTunneling vendor type=%d \n"),
                aTableName.Ptr(), aSrcIndexType, aDestIndexType, aSrcIndex, aDestIndex, aSrcTunnelingVendorType, aDestTunnelingVendorType));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL, &aTableName, 
		&KServiceType, aDestIndexType, &KServiceIndex, aDestIndex, &KTunnelingType, aDestTunnelingVendorType);
	
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
				&& view.ColUint(colSet->ColNo(KTunnelingType)) == aDestTunnelingVendorType)
				{  		
      			EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::CopySettingsL - Delete old records\n") ) );
      			view.DeleteL();
    			}
      		} while (view.NextL() != EFalse);
  		}
	
	view.Close();
	CleanupStack::PopAndDestroy(2); // view, colset
	
  	sqlStatement.Format(KSQL, &aTableName, 
        &KServiceType, aSrcIndexType, &KServiceIndex, aSrcIndex, &KTunnelingType, aSrcTunnelingVendorType);

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
				|| view.ColUint(colSet->ColNo(KTunnelingType)) != aDestTunnelingVendorType)
			{
				bookmark = view.Bookmark();
				
				view.InsertCopyL();
				
				view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(aDestIndexType));
    
	    		view.SetColL(colSet->ColNo(KServiceIndex), static_cast<TUint>(aDestIndex));

	    		view.SetColL(colSet->ColNo(KTunnelingType), aDestTunnelingVendorType);
				
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
	
	CleanupStack::PopAndDestroy(3); // view, colset, buf

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
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();
	TUint aEapVendorType = aEapType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);
	TUint aEapVendorType = static_cast<TUint>(aEapType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL:Start:aIndexType=%d,aIndex=%d,aTunnelingVendorType=%d,aEapVendorType=%d"),
			aIndexType, aIndex, aTunnelingVendorType, aEapVendorType));
	
	TPtrC dbname;
	TPtrC settings;
	TPtrC usercerts;
	TPtrC cacerts;
	TPtrC ciphersuites;

#ifdef USE_FAST_EAP_TYPE
	TPtrC fastSpecialSettings;
#endif
	
	switch (aEapVendorType)
	{
	case eap_type_tls:
		{
			dbname.Set(KTlsDatabaseName);
			settings.Set(KTlsDatabaseTableName);
			usercerts.Set(KTlsAllowedUserCertsDatabaseTableName);
			cacerts.Set(KTlsAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KTlsAllowedCipherSuitesDatabaseTableName);
		}
		break;

	case eap_type_peap:
		{
			dbname.Set(KPeapDatabaseName);
			settings.Set(KPeapDatabaseTableName);
			usercerts.Set(KPeapAllowedUserCertsDatabaseTableName);
			cacerts.Set(KPeapAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KPeapAllowedCipherSuitesDatabaseTableName);
		}
		break;

	case eap_type_ttls:
		{
			dbname.Set(KTtlsDatabaseName);
			settings.Set(KTtlsDatabaseTableName);
			usercerts.Set(KTtlsAllowedUserCertsDatabaseTableName);
			cacerts.Set(KTtlsAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KTtlsAllowedCipherSuitesDatabaseTableName);
		}
		break;

#ifdef USE_FAST_EAP_TYPE

	case eap_type_fast:
		{
			dbname.Set(KFastDatabaseName);
			settings.Set(KFastGeneralSettingsDBTableName); // This is general settings for FAST.
			fastSpecialSettings.Set(KFastSpecialSettingsDBTableName);
			
			usercerts.Set(KFastAllowedUserCertsDatabaseTableName);
			cacerts.Set(KFastAllowedCACertsDatabaseTableName);
			ciphersuites.Set(KFastAllowedCipherSuitesDatabaseTableName);
		}
		break;
#endif

	case eap_type_ttls_plain_pap:
		{
			dbname.Set( KTtlsDatabaseName );
			settings.Set( KTtlsDatabaseTableName );
		}
	break;
	
	default:
		// Should never happen
		User::Leave(KErrArgument);
	}	

	RDbs session;
	RDbNamedDatabase database;
	
	// Connect to the DBMS server.
	User::LeaveIfError(session.Connect());
	CleanupClosePushL(session);	
		
#ifdef SYMBIAN_SECURE_DBMS
	
	// Create the secure shared database with the specified secure policy.
	// Database will be created in the data caging path for DBMS (C:\private\100012a5).
	
	TInt err = database.Create(session, dbname, KSecureUIDFormat);
	
	if(err == KErrNone)
	{
		// Database was created so it was empty. No need for further actions.
		database.Destroy();
		CleanupStack::PopAndDestroy();
		return;
		
	} 
	else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	// Database existed, open it.
	User::LeaveIfError(database.Open(session, dbname, KSecureUIDFormat));
	CleanupClosePushL(database);
		
#else
	// For non-secured database. The database will be created in the old location (c:\system\data).
	
	RFs fsSession;		
	User::LeaveIfError(fsSession.Connect());
	CleanupClosePushL(fsSession);	
	TInt err = database.Create(fsSession, dbname);

	if(err == KErrNone)
	{
		// Database was created so it was empty. No need for further actions.
		database.Destroy();
		CleanupStack::PopAndDestroy(2); // fsSession, database session
		return;
		
	} 
	else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	CleanupStack::PopAndDestroy(); // close fsSession
	
	User::LeaveIfError(database.Open(session, dbname));
	CleanupClosePushL(database);		
	    
#endif // #ifdef SYMBIAN_SECURE_DBMS

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::DeleteConfigurationL - Deleting the tables\n")));

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	//--------------------- Deletion 1 ----------------------------//
	
	// For all EAPs delete the settings table. 
	// For EAP-FAST, this is delting the general settings table.
	
	sqlStatement.Format(KSQL, &settings, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
	
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());

	// Delete rows
	if (view.FirstL())
	{		
		do {
			view.DeleteL();
		} while (view.NextL() != EFalse);
	}
	
	CleanupStack::PopAndDestroy(); // view
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL: Deleted %s (general) settings table"), settings.Ptr()));	

	//////////////////////////////////////////
	// This is only for plain PAP settings. //
	//////////////////////////////////////////
	if ( aEapVendorType == eap_type_ttls_plain_pap )
		{
        CleanupStack::PopAndDestroy(3); // buf, database, session
        EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL: Return")));	
        // we return here in case of pap because there is nothing to do else.
        return;
		}
	
	//--------------------- Deletion 2 ----------------------------//
	
	// For all EAPs delte the User cert table

//	KSQL2 is "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d"
	
	sqlStatement.Format(KSQL, &usercerts, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);

	// Evaluate view
	
	User::LeaveIfError(view.Prepare(database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	if (view.FirstL())
	{		
		do {
			view.DeleteL();
		} while (view.NextL() != EFalse);
	}

	CleanupStack::PopAndDestroy(); // view

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL: Deleted USER certs table")));	

	//--------------------- Deletion 3 ----------------------------//
	
	// For all EAPs delete the CA cert table

//	KSQL3 is "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d"
	
	sqlStatement.Format(KSQL, &cacerts, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
	
	// Evaluate view
	
	User::LeaveIfError(view.Prepare(database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	if (view.FirstL())
	{		
		do {
			view.DeleteL();
		} while (view.NextL() != EFalse);
	}

	CleanupStack::PopAndDestroy(); // view

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL: Deleted CA certs table")));

	//--------------------- Deletion 4 ----------------------------//
	
	// For all EAPs delete the Cipher suite table

//	KSQL4 is "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d"
	
	sqlStatement.Format(KSQL, &ciphersuites, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);

	// Evaluate view
	
	User::LeaveIfError(view.Prepare(database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	if (view.FirstL())
	{		
		do {
			view.DeleteL();
		} while (view.NextL() != EFalse);
	}
	
	CleanupStack::PopAndDestroy(&view); // Close view
		
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL: Deleted cipher suits table")));	

	
#ifdef USE_FAST_EAP_TYPE	

	if(aEapVendorType == eap_type_fast)
	{
		//--------------------- Deletion 5 ----------------------------//
		
		// For EAP-FAST, delete the special settings table
		
		sqlStatement.Format(KSQL, &fastSpecialSettings, 
			&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
	
		// Evaluate view
		
		User::LeaveIfError(view.Prepare(database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
		CleanupClosePushL(view);
		User::LeaveIfError(view.EvaluateAll());
		
		if (view.FirstL())
		{		
			do {
				view.DeleteL();
			} while (view.NextL() != EFalse);
		}
		
		CleanupStack::PopAndDestroy(&view); // Close view
			
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::DeleteConfigurationL: Deleted EAP-FAST Special settings table")));	
				
	} // End: if(aEapVendorType == eap_type_fast)

#endif // End: #ifdef USE_FAST_EAP_TYPE	
	
	// Close database
	CleanupStack::PopAndDestroy(3); // buf, database, session
	
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
	// Check if the EXTRA cert columns are already in the table.
	
	CDbColSet* colSetCertTable = aDatabase.ColSetL(aTableName);
	User::LeaveIfNull(colSetCertTable);
	CleanupStack::PushL(colSetCertTable);	
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::AddExtraCertColumnsL - Number of columns in %S table before addition=%d\n"),
	&aTableName, colSetCertTable->Count()));
		
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
			
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::AddExtraCertColumnsL - EXTRA cert columns missing from the table %S. Adding now.\n"),
		&aTableName));			

		HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
		TPtr sqlStatement = buf->Des();
		
		_LIT(KSQLAlterTableForBin, "ALTER TABLE %S ADD %S BINARY(%d)");											 
	
		sqlStatement.Format(KSQLAlterTableForBin, &aTableName, 
			&KActualSubjectKeyIdentifier, KKeyIdentifierLength);
			
		User::LeaveIfError( aDatabase.Execute(sqlStatement));

		_LIT(KSQLAlterTableForVarChar, "ALTER TABLE %S ADD %S VARCHAR(%d)");											 
	
		sqlStatement.Format(KSQLAlterTableForVarChar, &aTableName, 
			&KSubjectName, KGeneralStringMaxLength);
			
		User::LeaveIfError( aDatabase.Execute(sqlStatement));

		sqlStatement.Format(KSQLAlterTableForVarChar, &aTableName, 
			&KIssuerName, KGeneralStringMaxLength);
			
		User::LeaveIfError( aDatabase.Execute(sqlStatement));
	
		sqlStatement.Format(KSQLAlterTableForVarChar, &aTableName, 
			&KSerialNumber, KGeneralStringMaxLength);
			
		User::LeaveIfError( aDatabase.Execute(sqlStatement));
	
		sqlStatement.Format(KSQLAlterTableForBin, &aTableName, 
			&KThumbprint, KThumbprintMaxLength);
			
		User::LeaveIfError( aDatabase.Execute(sqlStatement));
	
		CleanupStack::PopAndDestroy( buf ); // Delete buf or sqlStatement
	}

	CleanupStack::PopAndDestroy( colSetCertTable ); // Delete colSetCertTable.

	CDbColSet* colSetCertTableAfterAdd = aDatabase.ColSetL(aTableName);
	User::LeaveIfNull(colSetCertTableAfterAdd);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapTlsPeapUtils::AddExtraCertColumnsL - Number of columns in %S table after addition=%d\n"),
	&aTableName, colSetCertTableAfterAdd->Count()));
	
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
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();
	TUint aEapVendorType = aEapType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);
	TUint aEapVendorType = static_cast<TUint>(aEapType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	
	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("EapTlsPeapUtils::GetEapSettingsDataL-Start- aIndexType=%d, aIndex=%d, Tunneling vendor type=%d, Eap vendor type=%d \n"),
	aIndexType,aIndex, aTunnelingVendorType, aEapVendorType));
	
	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("EapTlsPeapUtils::GetEapSettingsDataL Get Column Name:%S \n"),
	&aDbColumnName));	

	TBufC<KMaxEapDbTableNameLength> generalSettingsTableName;
	
#if defined (USE_FAST_EAP_TYPE)	
	TBufC<KMaxEapDbTableNameLength> specialSettingsTableName;
#endif

	// Set the database table name based on the type
	switch (aEapVendorType)
	{
		case eap_type_tls:
			generalSettingsTableName = KTlsDatabaseTableName;
			break;
		
		case eap_type_peap:
			generalSettingsTableName = KPeapDatabaseTableName;	
			break;
				
		case eap_type_ttls:
		case eap_type_ttls_plain_pap:
			generalSettingsTableName = KTtlsDatabaseTableName;
			break;
			
#if defined (USE_FAST_EAP_TYPE)
		case eap_type_fast:
			generalSettingsTableName = KFastGeneralSettingsDBTableName; // General settings
			specialSettingsTableName = KFastSpecialSettingsDBTableName; // Special settings  for only FAST
			break;
#endif // #if defined (USE_FAST_EAP_TYPE)

		default:
			{
				// Unsupported EAP type		
				// Should never happen
				
				EAP_TRACE_DEBUG_SYMBIAN(
					(_L("EapTlsPeapUtils::GetEapSettingsDataL: ERROR: Unsupported EAP type=%d"),
					aEapVendorType));

				User::Leave(KErrArgument);
			}
	}
	
	if(aDbColumnName.Size() <= 0)	
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::GetEapSettingsDataL: ERROR: No Column Name!\n")));
		
		User::Leave(KErrArgument);
	}
	
	// Now do the database query
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");	
	
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

		sqlStatement.Format(KSQLQueryRow, &aDbColumnName, &specialSettingsTableName, 
			&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);		
	}
	else
	{
		sqlStatement.Format(KSQLQueryRow, &aDbColumnName, &generalSettingsTableName, 
			&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);		
	}

#else

	{
		sqlStatement.Format(KSQLQueryRow, &aDbColumnName, &generalSettingsTableName, 
			&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);		
	}

#endif // End: #if defined(USE_FAST_EAP_TYPE)	

	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("EapTlsPeapUtils::GetEapSettingsDataL - SQL query formated OK")));

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

	CleanupStack::PopAndDestroy( &view ); // Close view.
	
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG_SYMBIAN(
				(_L("EapTlsPeapUtils::GetEapSettingsDataL: Status=%d\n"), status));
	}
	
	EAP_TRACE_DATA_DEBUG_SYMBIAN(("GetEapSettingsDataL:DbColumnValue:",
		aDbColumnValue->get_data(aDbColumnValue->get_data_length()),
		aDbColumnValue->get_data_length()));

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::GetEapSettingsDataL: End \n")));

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
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();
	TUint aEapVendorType = aEapType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);
	TUint aEapVendorType = static_cast<TUint>(aEapType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES
	
	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("EapTlsPeapUtils::SetEapSettingsDataL-Start- aIndexType=%d, aIndex=%d, Tunneling vendor type=%d, Eap vendor type=%d \n"),
	aIndexType,aIndex, aTunnelingVendorType, aEapVendorType));
	
	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("EapTlsPeapUtils::SetEapSettingsDataL Set Column Name:%S \n"),
	&aDbColumnName));	

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("SetEapSettingsDataL:DbColumnValue:",
		aDbColumnValue->get_data(aDbColumnValue->get_data_length()),
		aDbColumnValue->get_data_length()));
	
	TBufC<KMaxEapDbTableNameLength> generalSettingsTableName;
	
#if defined (USE_FAST_EAP_TYPE)	
	TBufC<KMaxEapDbTableNameLength> specialSettingsTableName;
#endif

	// Set the database table name based on the type
	switch (aEapVendorType)
	{
		case eap_type_tls:
			generalSettingsTableName = KTlsDatabaseTableName;	
			break;
		
		case eap_type_peap:
			generalSettingsTableName = KPeapDatabaseTableName;
			break;
				
		case eap_type_ttls:
		case eap_type_ttls_plain_pap:
			generalSettingsTableName = KTtlsDatabaseTableName;
			break;
			
#if defined (USE_FAST_EAP_TYPE)
		case eap_type_fast:
			generalSettingsTableName = KFastGeneralSettingsDBTableName; // General settings
			specialSettingsTableName = KFastSpecialSettingsDBTableName; // Special settings  for only FAST
			break;
#endif // #if defined (USE_FAST_EAP_TYPE)
			
		default:
			{
				// Unsupported EAP type		
				// Should never happen
				
				EAP_TRACE_DEBUG_SYMBIAN(
					(_L("EapTlsPeapUtils::SetEapSettingsDataL: ERROR: Unsupported EAP type=%d"),
					aEapVendorType));

				User::Leave(KErrArgument);
			}
	}
	
	if(aDbColumnName.Size() <= 0)	
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("EapTlsPeapUtils::SetEapSettingsDataL: ERROR: No Column Name!\n")));
		
		User::Leave(KErrArgument);
	}
	
	// Now do the database query
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");	
	
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

		sqlStatement.Format(KSQLQueryRow, &aDbColumnName, &specialSettingsTableName, 
			&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);		
	}
	else
	{
		sqlStatement.Format(KSQLQueryRow, &aDbColumnName, &generalSettingsTableName, 
			&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);		
	}

#else

	{
		sqlStatement.Format(KSQLQueryRow, &aDbColumnName, &generalSettingsTableName, 
			&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);		
	}

#endif // End: #if defined(USE_FAST_EAP_TYPE)	

	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("EapTlsPeapUtils::SetEapSettingsDataL - SQL query formated OK")));

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
					
					EAP_TRACE_DEBUG_SYMBIAN(
							(_L("eap_am_type_tls_peap_symbian_c::authentication_finishedL WARNING, HACK to set Unauth Prov mode set to default (NO)!")));					
	
					view.SetColL(KDefaultColumnInView_One, EFASTUnauthProvModeAllowedNo);
				
#endif // End: #if defined (USE_FAST_EAP_TYPE)
				}
				break;
				
			case EDbColInt64:
				{
					// Do some lexical analysis to get TInt64 value here and set it in DB.
					
					EAP_TRACE_DEBUG_SYMBIAN(
						(_L("EapTlsPeapUtils::SetEapSettingsDataL: ERROR: EDbColInt64 not supported here yet!\n")));	
					
					User::Leave(KErrNotSupported);					
				}
				break;
				
			case EDbColLongBinary:
				{
					// This needs special handling. (readstream). Not needed in this DB yet.	
					EAP_TRACE_DEBUG_SYMBIAN(
						(_L("EapTlsPeapUtils::SetEapSettingsDataL: ERROR: EDbColLongBinary not supported in this DB!\n")));	
					
					User::Leave(KErrNotSupported);
				}
				break;			
				
			default:
				EAP_TRACE_DEBUG_SYMBIAN(
					(_L("EapTlsPeapUtils::SetEapSettingsDataL: ERROR: Unsupported DB field! \n")));	
				
				User::Leave(KErrNotSupported);
				break;
			}
			
			CleanupStack::PopAndDestroy(dbColVal8);		
			
		} // End: if(view.ColCount() == KDefaultColumnInView_One)
		else
		{
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("EapTlsPeapUtils::SetEapSettingsDataL: ERROR: Too many columns in DB view, count=%d \n"),
				view.ColCount()));	
			
			User::Leave(KErrNotFound);
		}
	} // End: if (view.FirstL())
	
	// Now it should go to the DB.
	view.PutL();	
	
	CleanupStack::PopAndDestroy( &view ); // Close view.		

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapTlsPeapUtils::SetEapSettingsDataL: End \n")));	
}

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
	
		CDbColSet* colSet = aDb.ColSetL( aTableName );
		User::LeaveIfNull( colSet );
		CleanupStack::PushL( colSet );	
			
		EAP_TRACE_DEBUG_SYMBIAN( ( _L(
	        "EapTlsPeapUtils::AlterTableL() \
	        Number of columns in %S table is %d.\n" ),
			&aTableName, colSet->Count() ) );
		
	    if ( aCmd == EAddColumn )
	    	{
	    	// Check if there is a target column
	    	if( colSet->ColNo( aColumnName ) != KDbNullColNo )
	    		{
	    		EAP_TRACE_DEBUG_SYMBIAN( ( _L(
	   		        "EapTlsPeapUtils::AlterTableL() \
	   		        Column %S exists already in table %S.\n" ),
	    			&aColumnName, &aTableName ) );
	    		CleanupStack::PopAndDestroy( colSet );
	    		return;
	    		}
	    	}
	    else
	    	{
	    	// Check if there is a target column
	    	if( colSet->ColNo( aColumnName ) == KDbNullColNo )
	    		{
	    		EAP_TRACE_DEBUG_SYMBIAN( ( _L(
	   		        "EapTlsPeapUtils::AlterTableL() \
	   		        Column %S does not exists already in table %S.\n" ),
	    			&aColumnName, &aTableName ) );
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
			sqlStatement.Format( KSqlAddCol, &aTableName, 
			    &aColumnName, &aColumnDef );
			}
		else
			{
			sqlStatement.Format( KSqlRemoveCol, &aTableName, 
		        &aColumnName );
			}
			
		EAP_TRACE_DEBUG_SYMBIAN( ( _L(
			"EapTlsPeapUtils::AlterTableL(): sqlStatement=%S\n"),
			&sqlStatement ) );
		
		User::LeaveIfError( aDb.Execute( sqlStatement ) );		
		CleanupStack::PopAndDestroy( buf );
		CleanupStack::PopAndDestroy( colSet );

		CDbColSet* alteredColSet = aDb.ColSetL( aTableName );
		User::LeaveIfNull( alteredColSet );
		EAP_TRACE_DEBUG_SYMBIAN( ( _L(
	        "EapTlsPeapUtils::AlterTableL() \
	        Number of columns in %S table after adding is %d.\n" ),
			&aTableName, alteredColSet->Count() ) );
		delete alteredColSet;
			
		} // EapTlsPeapUtils::AlterTableL()

// End of file


