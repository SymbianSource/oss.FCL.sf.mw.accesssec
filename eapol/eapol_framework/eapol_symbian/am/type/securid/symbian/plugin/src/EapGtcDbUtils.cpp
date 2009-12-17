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


// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 337 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "EapGtcDbUtils.h"
#include "EapGtcDbDefaults.h"
#include "EapGtcDbParameterNames.h"
#include "EapSecurIDDbParameterNames.h"

#include "eap_am_trace_symbian.h"

const TUint KMaxSqlQueryLength = 512;
const TInt KMicroSecsInAMinute = 60000000; // 60000000 micro seconds is 1 minute.

// ================= MEMBER FUNCTIONS =======================

void EapGtcDbUtils::OpenDatabaseL(RDbNamedDatabase& aDatabase, RDbs& aSession, const TIndexType aIndexType,
	const TInt aIndex, const eap_type_value_e aTunnelingType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL -Start- aIndexType=%d, aIndex=%d, aTunnelingVendorType=%d \n"),
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
	
	TInt err = aDatabase.Create(aSession, KGtcDatabaseName, KGtcSecureUIDFormat);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL - Created Secure DB for eapgtc.dat. err=%d\n"), err));

	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	
	User::LeaveIfError(aDatabase.Open(aSession, KGtcDatabaseName, KGtcSecureUIDFormat));
	CleanupClosePushL(aDatabase);		
		
#else
	// For non-secured database. The database will be created in the old location (c:\system\data).
	
	RFs fsSession;		
	User::LeaveIfError(fsSession.Connect());
	CleanupClosePushL(fsSession);	
	TInt err = aDatabase.Create(fsSession, KGtcDatabaseName);
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL - Created Non-Secure DB for eapgtc.dat. err=%d\n"), err));
	
	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	CleanupStack::PopAndDestroy(); // close fsSession
	
	User::LeaveIfError(aDatabase.Open(aSession, KGtcDatabaseName));
	CleanupClosePushL(aDatabase);		
	    
#endif // #ifdef SYMBIAN_SECURE_DBMS

	// 2. Create the eap-securid table to database (ignore error if exists)
	
// Table columns:
//// NAME ///////////////////////////////////////////////// TYPE ////////////// Constant /////////
//| ServiceType								| UNSIGNED INTEGER 	| KServiceType      |//
//| ServiceIndex							| UNSIGNED INTEGER 	| KServiceIndex     |//
//| TunnelingType							| UNSIGNED INTEGER 	| KTunnelingType    |//
//| EAP_GTC_identity				    	| VARCHAR(255)     	| cf_str_EAP_GTC_identity_literal	|//
//| EAP_GTC_max_session_validity_time	    | BIGINT		   	| cf_str_EAP_GTC_max_session_validity_time_literal   |//
//| EAP_GTC_last_full_authentication_time	| BIGINT		   	| KGTCLastFullAuthTime	|//
	//////////////////////////////////////////////////////////////////////////////////////////////////

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLCreateTable1, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S VARCHAR(255), \
											 %S BIGINT, \
											 %S BIGINT)");
											 
	sqlStatement.Format(KSQLCreateTable1, 
						&KGtcTableName, 
						&KServiceType, 
						&KServiceIndex, 
						&KTunnelingType, 
						&cf_str_EAP_GTC_identity_literal,
						&cf_str_EAP_GTC_max_session_validity_time_literal, 
						&KGTCLastFullAuthTime);

	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}

	// 4. Check if database table contains a row for this service type and id  
	
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLQueryRow, &cf_str_EAP_GTC_identity_literal, &KGtcTableName, 
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
		sqlStatement.Format(KSQLInsert, &KGtcTableName);		
		
		view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly);
		CleanupClosePushL(view);
		
		// Get column set so we get the correct column numbers
		CDbColSet* colSet = view.ColSetL();		
		CleanupStack::PushL(colSet);
		
		view.InsertL();
		view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt> (aIndexType));
		view.SetColL(colSet->ColNo(KServiceIndex), aIndex);
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);
		view.SetColL(colSet->ColNo(cf_str_EAP_GTC_identity_literal), default_EAP_GTC_identity);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_GTC_max_session_validity_time_literal), default_MaxSessionTime);
		
		view.SetColL(colSet->ColNo(KGTCLastFullAuthTime), default_FullAuthTime);		
				
		view.PutL();

		CleanupStack::PopAndDestroy( colSet ); // Delete colSet.
		
		CleanupStack::PopAndDestroy( &view ); // Close view.
		
	}
	
	CleanupStack::PopAndDestroy( buf ); // Delete buf	
	CleanupStack::Pop( &aDatabase );	
	CleanupStack::Pop( &aSession );	
	
	aDatabase.Compact();
}


void EapGtcDbUtils::SetIndexL(
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

	sqlStatement.Format(KSQL, &KGtcTableName, 
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

void EapGtcDbUtils::SetConfigurationL(
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

	// Check if the settings are for the correct type
	if (aSettings.iEAPType != EAPSettings::EEapGtc)
	{
		User::Leave(KErrNotSupported);
	}
	
	
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();	

	RDbView view;

	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLQuery, &KGtcTableName, 
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

	// Username
	if (aSettings.iUsernamePresent)
	{
		// Validate length.
		if(aSettings.iUsername.Length() > KMaxIdentityLengthInDB)
		{
			// Username too long. Can not be stored in DB.
			
			EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::SetConfigurationL: Too long Username. Length=%d \n"),
			aSettings.iUsername.Length()));
			
			User::Leave(KErrArgument);
		}
		
		// Length is ok. Set the value in DB.
		view.SetColL(colSet->ColNo(cf_str_EAP_GTC_identity_literal), aSettings.iUsername);		
	}		
	
	// Session validity time
	if (aSettings.iSessionValidityTimePresent)
	{
		// User or device management wants to store the session validity time.
		// Convert the time to micro seconds and save.
		
		TInt64 validityInMicro = (aSettings.iSessionValidityTime) *  KMicroSecsInAMinute;
		
		view.SetColL(colSet->ColNo(cf_str_EAP_GTC_max_session_validity_time_literal), validityInMicro);
	}
	
	// Last full authentication time should be made zero when EAP configurations are modified.
	// This makes sure that the next authentication with this EAP would be full authentication
	// instead of reauthentication even if the session is still valid.
	
	view.SetColL(colSet->ColNo(KGTCLastFullAuthTime), default_FullAuthTime);

	EAP_TRACE_DEBUG_SYMBIAN((_L("Session Validity: EAP-Type=%d, Resetting Full Auth Time since settings are modified\n"),
								aSettings.iEAPType ));
			
	view.PutL();
	CleanupStack::PopAndDestroy(3); // view, colset, buf

}

void EapGtcDbUtils::GetConfigurationL(
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
	sqlStatement.Format(KSQLQuery, &KGtcTableName, 
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

	aSettings.iEAPType = EAPSettings::EEapGtc;
	
	// Username
	TPtrC username = view.ColDes(colSet->ColNo(cf_str_EAP_GTC_identity_literal));
	aSettings.iUsername.Copy(username);
	aSettings.iUsernamePresent = ETrue;
	
	// Session validity time	
	TInt64 maxSessionTimeMicro = view.ColInt64(colSet->ColNo(cf_str_EAP_GTC_max_session_validity_time_literal));
	
	// Convert the time to minutes.	
	TInt64 maxSessionTimeMin = maxSessionTimeMicro / KMicroSecsInAMinute;
	
	aSettings.iSessionValidityTime = static_cast<TUint>(maxSessionTimeMin);
	aSettings.iSessionValidityTimePresent = ETrue;
	
	CleanupStack::PopAndDestroy(3); // view, colset, buf
}

void EapGtcDbUtils::CopySettingsL(
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

	sqlStatement.Format(KSQL, &KGtcTableName, 
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

void EapGtcDbUtils::DeleteConfigurationL(	
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
	
	TInt err = database.Create(session, KGtcDatabaseName, KGtcSecureUIDFormat);
	
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
	User::LeaveIfError(database.Open(session, KGtcDatabaseName, KGtcSecureUIDFormat));
	CleanupClosePushL(database);
		
#else
	// For non-secured database. The database will be created in the old location (c:\system\data).
	
	RFs fsSession;		
	User::LeaveIfError(fsSession.Connect());
	CleanupClosePushL(fsSession);	
	TInt err = database.Create(fsSession, KGtcDatabaseName);

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
	
	User::LeaveIfError(database.Open(session, KGtcDatabaseName));
	CleanupClosePushL(database);		
	    
#endif // #ifdef SYMBIAN_SECURE_DBMS

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Main settings table
	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQL, &KGtcTableName, 
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

// End of File
