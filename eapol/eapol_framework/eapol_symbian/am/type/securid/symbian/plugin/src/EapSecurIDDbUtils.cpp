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
* %version: 14.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 349 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "EapSecurIDDbUtils.h"
#include "EapSecurIDDbDefaults.h"
#include "EapSecurIDDbParameterNames.h"

#include "eap_am_trace_symbian.h"

const TUint KMaxSqlQueryLength = 512;

// ================= MEMBER FUNCTIONS =======================

void EapSecurIDDbUtils::OpenDatabaseL(RDbNamedDatabase& aDatabase, RDbs& aSession, const TIndexType aIndexType,
	const TInt aIndex, const eap_type_value_e aTunnelingType)
{
#ifdef USE_EAP_EXPANDED_TYPES

	TUint aTunnelingVendorType = aTunnelingType.get_vendor_type();

#else

	TUint aTunnelingVendorType = static_cast<TUint>(aTunnelingType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

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

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapSecurIDDbUtils::OpenDatabaseL - Created Secure DB for eapsecurid.dat. err=%d\n"), err));

	
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
	// For non-secured database. The database will be created in the old location (c:\system\data).
	
	RFs fsSession;		
	User::LeaveIfError(fsSession.Connect());
	CleanupClosePushL(fsSession);	
	TInt err = aDatabase.Create(fsSession, KDatabaseName);
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapSecurIDDbUtils::OpenDatabaseL - Created Non-Secure DB for eapsecurid.dat. err=%d\n"), err));
	
	
	if(err == KErrNone)
	{
		aDatabase.Close();
		
	} else if (err != KErrAlreadyExists) 
	{
		User::LeaveIfError(err);
	}
	CleanupStack::PopAndDestroy(); // close fsSession
	
	User::LeaveIfError(aDatabase.Open(aSession, KDatabaseName));
	CleanupClosePushL(aDatabase);		
	    
#endif // #ifdef SYMBIAN_SECURE_DBMS

	// 2. Create the eap-securid table to database (ignore error if exists)
	// Table columns:
	//// NAME ///////////////////////////////////////////////// TYPE ////////////// Constant /////////
	//| ServiceType											| UNSIGNED INTEGER | KServiceType      |//
	//| ServiceIndex										| UNSIGNED INTEGER | KServiceIndex     |//
	//| TunnelingType										| UNSIGNED INTEGER | KTunnelingType    |//
	//| EAP_SECURID_identity				        		| VARCHAR(255)     | cf_str_EAP_SECURID_identity_literal         |//
	//////////////////////////////////////////////////////////////////////////////////////////////////

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLCreateTable1, "CREATE TABLE %S (%S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S UNSIGNED INTEGER, \
											 %S VARCHAR(255))");
	sqlStatement.Format(KSQLCreateTable1, &KSecurIDTableName, &KServiceType, &KServiceIndex, &KTunnelingType, &cf_str_EAP_SECURID_identity_literal);
	err = aDatabase.Execute(sqlStatement);
	if (err != KErrNone && err != KErrAlreadyExists)
	{
		User::Leave(err);
	}

	// 4. Check if database table contains a row for this service type and id  
	
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLQueryRow, &cf_str_EAP_SECURID_identity_literal, &KSecurIDTableName, 
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
		sqlStatement.Format(KSQLInsert, &KSecurIDTableName);		
		
		view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly);
		CleanupClosePushL(view);
		
		// Get column set so we get the correct column numbers
		CDbColSet* colSet = view.ColSetL();		
		CleanupStack::PushL(colSet);
		
		view.InsertL();
		view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt> (aIndexType));
		view.SetColL(colSet->ColNo(KServiceIndex), aIndex);
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingVendorType);
		view.SetColL(colSet->ColNo(cf_str_EAP_SECURID_identity_literal), default_EAP_SECURID_identity);
		view.PutL();
		
		CleanupStack::PopAndDestroy( colSet ); // Delete colSet.
		
		CleanupStack::PopAndDestroy( &view ); // Close view.
	} 
	
	CleanupStack::PopAndDestroy(); // sqlStatement
	CleanupStack::Pop(2); // database, session
	aDatabase.Compact();
}

// End of File
