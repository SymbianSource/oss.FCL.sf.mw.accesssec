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
* %version: 29 %
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

#include <EapTraceSymbian.h>
#include "EapPluginTools.h"

const TUint KMaxSqlQueryLength = 512;

// ================= MEMBER FUNCTIONS =======================

void EapSecurIDDbUtils::OpenDatabaseL(
	RDbNamedDatabase& aDatabase,
	RFs& aFileServerSession,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapSecurIDDbUtils::OpenDatabaseL(): - Start - aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapSecurIDDbUtils::OpenDatabaseL()\n"));

	// 1. Open/create a database	

	TInt error(KErrNone);
	TFileName aPrivateDatabasePathName;

	EapPluginTools::CreateDatabaseLC(
		aDatabase,
		aFileServerSession,
		error,
		KSecurIDDatabaseName,
		aPrivateDatabasePathName);

	if(error == KErrNone)
	{
		aDatabase.Close();
	}
	else if (error != KErrAlreadyExists) 
	{
		User::LeaveIfError(error);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapSecurIDDbUtils::OpenDatabaseL(): - calls aDatabase.Open()\n")));

	error = aDatabase.Open(aFileServerSession, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapSecurIDDbUtils::OpenDatabaseL(): - Opened private DB for EAP-SecurID. error=%d\n"), error));

	User::LeaveIfError(error);

	// 2. Create the eap-securid table to database (ignore error if exists)
	// Table columns:
	//// NAME ///////////////////////////////////////////////// TYPE ////////////// Constant /////////
	//| ServiceType											| UNSIGNED INTEGER | KServiceType      |//
	//| ServiceIndex										| UNSIGNED INTEGER | KServiceIndex     |//
	//| TunnelingTypeVendorId                               | UNSIGNED INTEGER  | KTunnelingTypeVendorId    |//
	//| TunnelingType										| UNSIGNED INTEGER | KTunnelingType    |//
	//| EAP_SECURID_identity				        		| VARCHAR(255)     | cf_str_EAP_SECURID_identity_literal         |//
	//////////////////////////////////////////////////////////////////////////////////////////////////

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLCreateTable1, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(255))");

	sqlStatement.Format(KSQLCreateTable1,
		&KSecurIDTableName,
		&KServiceType,
		&KServiceIndex,
		&KTunnelingTypeVendorId,
		&KTunnelingType,
		&cf_str_EAP_SECURID_identity_literal);

	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}

	// 4. Check if database table contains a row for this service type and id  
	
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQLQueryRow,
		&cf_str_EAP_SECURID_identity_literal,
		&KSecurIDTableName, 
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
	CleanupStack::PopAndDestroy(&view);
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
		view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
		view.SetColL(colSet->ColNo(cf_str_EAP_SECURID_identity_literal), default_EAP_SECURID_identity);
		view.PutL();
		
		CleanupStack::PopAndDestroy( colSet ); // Delete colSet.
		
		CleanupStack::PopAndDestroy( &view ); // Close view.
	} 
	
	aDatabase.Compact();

	CleanupStack::PopAndDestroy( buf );
	CleanupStack::Pop( &aDatabase );	
	CleanupStack::Pop( &aFileServerSession );
}

// End of File
