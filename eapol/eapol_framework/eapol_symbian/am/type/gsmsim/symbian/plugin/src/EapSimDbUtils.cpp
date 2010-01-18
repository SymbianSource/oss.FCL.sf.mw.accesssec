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
* %version: 31.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 209 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDES
#include "EapSimDbUtils.h"
#include "EapSimDbDefaults.h"
#include "EapSimDbParameterNames.h"

#include "eap_am_trace_symbian.h"

const TInt KMaxSqlQueryLength = 2048;
const TInt KMicroSecsInAMinute = 60000000; // 60000000 micro seconds is 1 minute.

// ================= MEMBER FUNCTIONS =======================

void EapSimDbUtils::OpenDatabaseL(RDbNamedDatabase& aDatabase, RDbs& aSession, const TIndexType aIndexType,
	const TInt aIndex, const eap_type_value_e aTunnelingType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::OpenDatabaseL -Start- aIndexType=%d, aIndex=%d, aTunnelingVendorType=%d \n"),
	aIndexType,aIndex,aTunnelingVendorType) );

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
	
	TInt err = aDatabase.Create(aSession, KDatabaseName, KSecureUIDFormat);
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::OpenDatabaseL - Created Secure DB for eapsim.dat. err=%d\n"), err));

	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	User::LeaveIfError(aDatabase.Open(aSession, KDatabaseName, KSecureUIDFormat));
	CleanupClosePushL(aDatabase);		
		
#else
	// Non secured database. The database will be created in the old location (c:\system\data).
	
	RFs fsSession;		
	User::LeaveIfError(fsSession.Connect());
	CleanupClosePushL(fsSession);	
	TInt err = aDatabase.Create(fsSession, KDatabaseName);
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::OpenDatabaseL - Created Non-Secure DB for eapsim.dat. err=%d\n"), err));
	
	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	CleanupStack::PopAndDestroy( &fsSession ); // close fsSession
	
	User::LeaveIfError(aDatabase.Open(aSession, KDatabaseName));
	CleanupClosePushL(aDatabase);		
	    
#endif // #ifdef SYMBIAN_SECURE_DBMS

	// 2. Create the eapsim table to database (ignore error if exists)
	
// Table columns:
//// NAME ///////////////////////////////////////////////// TYPE ////////////// Constant /////////
//| ServiceType									| UNSIGNED INTEGER | KServiceType      |//
//| ServiceIndex								| UNSIGNED INTEGER | KServiceIndex     |//
//| TunnelingType								| UNSIGNED INTEGER | KTunnelingType    |//
//| EAP_GSMSIM_use_manual_realm					| UNSIGNED INTEGER | cf_str_EAP_GSMSIM_use_manual_realm_literal   |//
//| EAP_GSMSIM_manual_realm						| VARCHAR(255)	   | cf_str_EAP_GSMSIM_manual_realm_literal			   |//
//| EAP_GSMSIM_use_manual_username				| UNSIGNED INTEGER | cf_str_EAP_GSMSIM_use_manual_username_literal|//
//| EAP_GSMSIM_manual_username					| VARCHAR(255)	   | cf_str_EAP_GSMSIM_manual_username_literal		   |//
//| PseudonymId									| LONG VARBINARY   | KPseudonymId      |//
//| XKEY										| BINARY(20)       | KXKey             |//
//| K_aut										| BINARY(16)       | KK_aut            |//
//| K_encr										| BINARY(16)       | KK_encr           |//
//| ReauthCounter								| UNSIGNED INTEGER | KReauthCounter    |//
//| ReauthId									| LONG VARBINARY   | KReauthId         |//
//| PreviousIMSI								| VARBINARY(15)	   | KPreviousIMSI	   |//
//| EAP_GSMSIM_use_pseudonym_identity 			| UNSIGNED INTEGER | cf_str_EAP_GSMSIM_use_pseudonym_identity_literal	   	|//
//| EAP_GSMSIM_max_session_validity_time		| BIGINT		   | cf_str_EAP_GSMSIM_max_session_validity_time_literal   |//
//| EAP_GSMSIM_last_full_authentication_time	| BIGINT		   | KGSMSIMLastFullAuthTime	|//
//////////////////////////////////////////////////////////////////////////////////////////////////

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLCreateTable, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
												 %S UNSIGNED INTEGER, \
												 %S UNSIGNED INTEGER, \
												 %S UNSIGNED INTEGER, \
												 %S VARCHAR(%d), \
												 %S UNSIGNED INTEGER, \
												 %S VARCHAR(%d), \
												 %S LONG VARBINARY, \
												 %S BINARY(%d), \
												 %S BINARY(%d), \
												 %S BINARY(%d), \
												 %S UNSIGNED INTEGER, \
												 %S LONG VARBINARY, \
												 %S VARBINARY(%d), \
												 %S UNSIGNED INTEGER, \
												 %S BIGINT, \
												 %S BIGINT)");
												 
	sqlStatement.Format(KSQLCreateTable, &KSimTableName, &KServiceType,
														 &KServiceIndex, 
														 &KTunnelingType,
														 &cf_str_EAP_GSMSIM_use_manual_realm_literal, 
														 &cf_str_EAP_GSMSIM_manual_realm_literal, KMaxManualRealmLengthInDB, 
														 &cf_str_EAP_GSMSIM_use_manual_username_literal, 
														 &cf_str_EAP_GSMSIM_manual_username_literal, KMaxManualUsernameLengthInDB, 
														 &KPseudonymId,
														 &KXKey, KMaxXKeyLengthInDB, 
														 &KK_aut, KMaxK_autLengthInDB, 
														 &KK_encr, KMaxK_encrLengthInDB, 
														 &KReauthCounter, 
														 &KReauthId, 
														 &KPreviousIMSI, KMaxIMSILengthInDB,
														 &cf_str_EAP_GSMSIM_use_pseudonym_identity_literal,														 
														 &cf_str_EAP_GSMSIM_max_session_validity_time_literal, 
														 &KGSMSIMLastFullAuthTime);
																					
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}
	
	// 4. Check if database table contains a row for this service type and id  
	
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLQueryRow, &cf_str_EAP_GSMSIM_manual_realm_literal, &KSimTableName, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
		
	RDbView view;
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	// View must be closed when no longer needed
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	
	// 5. If row is not found then add it
	
	TInt rows = view.CountL();
	CleanupStack::PopAndDestroy( &view ); // Close view.
	if (rows == 0)
	{
		_LIT(KSQLInsert, "SELECT * FROM %S");
		sqlStatement.Format(KSQLInsert, &KSimTableName);	
										
		User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly));
		CleanupClosePushL(view);
		
		// Get column set so we get the correct column numbers
		CDbColSet* colSet = view.ColSetL();		
		CleanupStack::PushL(colSet);
		
		view.InsertL();
		view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt>(aIndexType));
		view.SetColL(colSet->ColNo(KServiceIndex), aIndex);
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_manual_realm_literal), default_EAP_GSMSIM_use_manual_realm);	
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_manual_realm_literal), default_EAP_GSMSIM_manual_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_manual_username_literal), default_EAP_GSMSIM_use_manual_username);
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_manual_username_literal), default_EAP_GSMSIM_manual_username);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_pseudonym_identity_literal), default_EAP_GSMSIM_use_pseudonym_identity);			
		
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_max_session_validity_time_literal), default_MaxSessionTime);
		
		view.SetColL(colSet->ColNo(KGSMSIMLastFullAuthTime), default_FullAuthTime);				

		view.PutL();
		
		CleanupStack::PopAndDestroy( colSet ); // Delete colSet.
		
		CleanupStack::PopAndDestroy( &view ); // Close view.
	}
	
	CleanupStack::PopAndDestroy( buf ); // Delete buf	
	CleanupStack::Pop( &aDatabase );	
	CleanupStack::Pop( &aSession );	
	
	aDatabase.Compact();
}

void EapSimDbUtils::SetIndexL(
	RDbNamedDatabase& aDatabase, 		
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

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL, &KSimTableName, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
	
	RDbView view;
	
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	
	// View must be closed when no longer needed
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
			
	TInt rows = view.CountL();
	
	if (rows == 0)
	{
		User::Leave(KErrNotFound);
	}
	
	// Get the first (and only) row
	view.FirstL();
	view.GetL();				
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);
	
	view.UpdateL();
	
    view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(aNewIndexType));
    
    view.SetColL(colSet->ColNo(KServiceIndex), aNewIndex);
    
    view.SetColL(colSet->ColNo(KTunnelingType), aNewTunnelingVendorType);

    view.PutL();
    	
	CleanupStack::PopAndDestroy(3); // view, colset, buf
}

void EapSimDbUtils::SetConfigurationL(
	RDbNamedDatabase& aDatabase,
	const EAPSettings& aSettings, 
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::SetConfigurationL -Start- aIndexType=%d, aIndex=%d, aTunnelingVendorType=%d\n"),
						aIndexType,aIndex, aTunnelingVendorType));
	
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
						
		EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - certificates - present=%d, Thumbprint=%S"),
						aSettings.iCertificates[n].iThumbprintPresent, &(aSettings.iCertificates[n].iThumbprint) ) );
	}						

	EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - present=%d, EncapsulatedEAPTypes Count=%d"),
						aSettings.iEncapsulatedEAPTypesPresent, aSettings.iEncapsulatedEAPTypes.Count()) );
	for( TInt m=0; m < aSettings.iEncapsulatedEAPTypes.Count(); m++ )
	{	
		EAP_TRACE_DEBUG_SYMBIAN((_L("SetConfigurationL - EncapsulatedEAPTypes=%d"),
						aSettings.iEncapsulatedEAPTypes[m]) );
	}						

	EAP_TRACE_DEBUG_SYMBIAN((_L("*************************** SetConfigurationL - Set the above values: ***************************\n")) );

	// Check if the settings are for the correct type
	if (aSettings.iEAPType != EAPSettings::EEapSim)
	{
		User::Leave(KErrNotSupported);
	}
	
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();	

	RDbView view;

	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLQuery, &KSimTableName, 
		&KServiceType, aIndexType, &KServiceIndex, aIndex, &KTunnelingType, aTunnelingVendorType);
	
	// Evaluate view
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement)));
	
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());	

	view.FirstL();
	
	view.UpdateL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	// Manual username
	//if (aSettings.iUsernamePresent) // no need to check as there may be empty usernames with the present status is EFlase.
	{
		// Check if length of username is less than the max length.
		if(aSettings.iUsername.Length() > KMaxManualUsernameLengthInDB)
		{
			// Username too long. Can not be stored in DB.
			
			EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::SetConfigurationL: Too long Username. Length=%d \n"),
			aSettings.iUsername.Length()));
			
			User::Leave(KErrArgument);
		}
		
		// Length is ok. Set the value in DB. Value could be empty. It doesn't matter.
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_manual_username_literal), aSettings.iUsername);
		
		// This is to set the automatic or manual status.
		TUint useManualUsernameStatus;
		
		if (aSettings.iUsernamePresent)
		{
			useManualUsernameStatus = EGSMSIMUseManualUsernameYes;
		}
		else
		{
			useManualUsernameStatus = EGSMSIMUseManualUsernameNo;
		}
		
		// Set the value.
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_manual_username_literal), useManualUsernameStatus);
	}
		
	// Manual realm
	//if (aSettings.iRealmPresent)  // no need to check as there may be empty realms with the present status is EFlase.
	{
		// Check if length of realm is less than the max length.
		if(aSettings.iRealm.Length() > KMaxManualRealmLengthInDB)
		{
			// Realm too long. Can not be stored in DB.

			EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::SetConfigurationL: Too long Realm. Length=%d \n"),
			aSettings.iRealm.Length()));
			
			User::Leave(KErrArgument);
		}

		// Length is ok. Set the value in DB. Value could be empty. It doesn't matter.
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_manual_realm_literal), aSettings.iRealm);
		
		// This is to set the automatic or manual status.
		TUint useManualRealmStatus;
		
		if (aSettings.iRealmPresent)
		{
			useManualRealmStatus = EGSMSIMUseManualRealmYes;
		}
		else
		{
			useManualRealmStatus = EGSMSIMUseManualRealmNo;
		}
		
		// Set the value.
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_manual_realm_literal), useManualRealmStatus);	
	}
	
	// UsePseudonym
	if (aSettings.iUsePseudonymsPresent)
	{
		if (aSettings.iUsePseudonyms)
		{
			// Use pseudonym.
			view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_pseudonym_identity_literal), EGSMSIMUsePseudonymIdYes);
		}
		else
		{			
			// Don't use pseudonym.
			view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_pseudonym_identity_literal), EGSMSIMUsePseudonymIdNo);			
		}
	}
	else
	{
		// Value is not configured. Value is read from config file if needed.
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_pseudonym_identity_literal), EGSMSIMUsePseudonymIdNotValid);		
	}
	
	// Session validity time
	if (aSettings.iSessionValidityTimePresent)
	{
		// User or device management wants to store the session validity time.
		// Convert the time to micro seconds and save.
		
		TInt64 validityInMicro = (aSettings.iSessionValidityTime) *  KMicroSecsInAMinute;
		
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_max_session_validity_time_literal), validityInMicro);
	}
	
	if (aIndexType != EVpn) // This allows current VPN IF to use reauthentication. VPN does not zero last full authentication time.
	{
		// Last full authentication time should be made zero when EAP configurations are modified.
		// This makes sure that the next authentication with this EAP would be full authentication
		// instead of reauthentication even if the session is still valid.
		
		view.SetColL(colSet->ColNo(KGSMSIMLastFullAuthTime), default_FullAuthTime);

		EAP_TRACE_DEBUG_SYMBIAN((_L("Session Validity: EAP-Type=%d, Resetting Full Auth Time since settings are modified\n"),
									aSettings.iEAPType ));
	}
	
	view.PutL();
	CleanupStack::PopAndDestroy(3); // view, colset, buf
}

void EapSimDbUtils::GetConfigurationL(
	RDbNamedDatabase& aDatabase,
	EAPSettings& aSettings, 
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();	

	RDbView view;

	// Form the query
	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLQuery, &KSimTableName, 
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

	aSettings.iEAPType = EAPSettings::EEapSim;
	
	// Username
	TPtrC username = view.ColDes(colSet->ColNo(cf_str_EAP_GSMSIM_manual_username_literal));
	aSettings.iUsername.Copy(username);
	
	// For manual or automatic status.
	TUint useUsername = view.ColUint(colSet->ColNo(cf_str_EAP_GSMSIM_use_manual_username_literal));
	if(useUsername == EGSMSIMUseManualUsernameNo)
	{
		aSettings.iUsernamePresent = EFalse;		
	}
	else
	{
		aSettings.iUsernamePresent = ETrue;		
	}
	
	// Realm
	TPtrC realm = view.ColDes(colSet->ColNo(cf_str_EAP_GSMSIM_manual_realm_literal));
	aSettings.iRealm.Copy(realm);
	
	// For manual or automatic status.
	TUint useRealm = view.ColUint(colSet->ColNo(cf_str_EAP_GSMSIM_use_manual_realm_literal));
	if(useRealm == EGSMSIMUseManualRealmNo)
	{
		aSettings.iRealmPresent = EFalse;
	}
	else
	{
		aSettings.iRealmPresent = ETrue;
	}
	
	TInt usePseudonym = view.ColUint(colSet->ColNo(cf_str_EAP_GSMSIM_use_pseudonym_identity_literal));
	
	if (usePseudonym == EGSMSIMUsePseudonymIdNotValid)
	{
		aSettings.iUsePseudonymsPresent = EFalse;
	}
	else
	{
		if (usePseudonym == EGSMSIMUsePseudonymIdNo)
		{
			aSettings.iUsePseudonyms = EFalse;
		}
		else
		{
			aSettings.iUsePseudonyms = ETrue;
		}
		
		aSettings.iUsePseudonymsPresent = ETrue;		
	}	
	
	// Session validity time	
	TInt64 maxSessionTimeMicro = view.ColInt64(colSet->ColNo(cf_str_EAP_GSMSIM_max_session_validity_time_literal));
	
	// Convert the time to minutes.	
	TInt64 maxSessionTimeMin = maxSessionTimeMicro / KMicroSecsInAMinute;
	
	aSettings.iSessionValidityTime = static_cast<TUint>(maxSessionTimeMin);
	aSettings.iSessionValidityTimePresent = ETrue;
	
	CleanupStack::PopAndDestroy(3); // view, colset, buf
}

void EapSimDbUtils::CopySettingsL(
	RDbNamedDatabase& aDatabase, 		
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

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL, &KSimTableName, 
		&KServiceType, aSrcIndexType, &KServiceIndex, aSrcIndex, &KTunnelingType, aSrcTunnelingVendorType);
	
	RDbView view;
	
	User::LeaveIfError(view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	
	// View must be closed when no longer needed
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
			
	TInt rows = view.CountL();
	
	if (rows == 0)
	{
		User::Leave(KErrNotFound);
	}
	
	// Get the first (and only) row
	view.FirstL();
	
	view.GetL();
		
	view.InsertCopyL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	
	CleanupStack::PushL(colSet);
		
	view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(aDestIndexType));
    
    view.SetColL(colSet->ColNo(KServiceIndex), aDestIndex);
    
    view.SetColL(colSet->ColNo(KTunnelingType), aDestTunnelingVendorType);

    view.PutL();
    	
	CleanupStack::PopAndDestroy(3); // view, colset, buf
}

void EapSimDbUtils::DeleteConfigurationL(	
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	RDbs session;
	RDbNamedDatabase database;
	// Connect to the DBMS server.
	User::LeaveIfError(session.Connect());
	CleanupClosePushL(session);	
		
#ifdef SYMBIAN_SECURE_DBMS
	
	// Create the secure shared database with the specified secure policy.
	// Database will be created in the data caging path for DBMS (C:\private\100012a5).
	
	TInt err = database.Create(session, KDatabaseName, KSecureUIDFormat);
	
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
	User::LeaveIfError(database.Open(session, KDatabaseName, KSecureUIDFormat));
	CleanupClosePushL(database);
		
#else
	// For non-secured database. The database will be created in the old location (c:\system\data).
	
	RFs fsSession;		
	User::LeaveIfError(fsSession.Connect());
	CleanupClosePushL(fsSession);	
	TInt err = database.Create(fsSession, KDatabaseName);

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
	
	User::LeaveIfError(database.Open(session, KDatabaseName));
	CleanupClosePushL(database);		
	    
#endif // #ifdef SYMBIAN_SECURE_DBMS

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Main settings table
	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQL, &KSimTableName, 
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

	// Close database
	CleanupStack::PopAndDestroy(4); // view, buf, database, session
}

// End of file
