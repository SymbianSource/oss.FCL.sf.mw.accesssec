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
* %version: 47 %
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

#include <EapTraceSymbian.h>
#include "EapPluginTools.h"

const TUint KMaxSqlQueryLength = 512;
const TInt KMicroSecsInAMinute = 60000000; // 60000000 micro seconds is 1 minute.

// ================= MEMBER FUNCTIONS =======================

void EapGtcDbUtils::OpenDatabaseL(
	RDbNamedDatabase& aDatabase,
	RFs& aFileServerSession,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapGtcDbUtils::OpenDatabaseL(): - Start - aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapGtcDbUtils::OpenDatabaseL()\n"));

	// 1. Open/create a database	
	
	TInt error(KErrNone);
	TFileName aPrivateDatabasePathName;

	EapPluginTools::CreateDatabaseLC(
		aDatabase,
		aFileServerSession,
		error,
		KEapGtcDatabaseName,
		aPrivateDatabasePathName);

	if(error == KErrNone)
	{
		aDatabase.Close();
	}
	else if (error != KErrAlreadyExists) 
	{
		User::LeaveIfError(error);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): - calls aDatabase.Open()\n")));

	error = aDatabase.Open(aFileServerSession, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): - Opened private DB for EAP-GTC. error=%d\n"), error));

	User::LeaveIfError(error);

	// 2. Create the eap-securid table to database (ignore error if exists)
	
	// Table columns:
	//// NAME ///////////////////////////////////////////////// TYPE ////////////// Constant /////////
	//| ServiceType								| UNSIGNED INTEGER 	| KServiceType      |//
	//| ServiceIndex							| UNSIGNED INTEGER 	| KServiceIndex     |//
	//| TunnelingTypeVendorId                   | UNSIGNED INTEGER  | KTunnelingTypeVendorId    |//
	//| TunnelingType							| UNSIGNED INTEGER 	| KTunnelingType    |//
	//| EAP_GTC_identity				    	| VARCHAR(255)     	| cf_str_EAP_GTC_identity_literal	|//
	//| EAP_GTC_max_session_validity_time	    | BIGINT		   	| cf_str_EAP_GTC_max_session_validity_time_literal   |//
	//| EAP_GTC_last_full_authentication_time	| BIGINT		   	| KGTCLastFullAuthTime	|//
	//| EAP_GTC_password_prompt                        | UNSIGNED INTEGER  | cf_str_EAP_GTC_passcode_prompt_literal   |//
	//| EAP_GTC_password                               | VARCHAR(255)      | cf_str_EAP_GTC_passcode_literal         |//
	//////////////////////////////////////////////////////////////////////////////////////////////////

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): calls HBufC::NewLC()\n")));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	_LIT(KSQLCreateTable1, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(255), \
		 %S BIGINT, \
		 %S BIGINT, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(255))");
											 
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): calls sqlStatement.Format()\n")));

	sqlStatement.Format(KSQLCreateTable1, 
						&KGtcTableName, 
						&KServiceType, 
						&KServiceIndex, 
						&KTunnelingTypeVendorId,
						&KTunnelingType, 
						&cf_str_EAP_GTC_identity_literal,
						&cf_str_EAP_GTC_max_session_validity_time_literal, 
						&KGTCLastFullAuthTime,
						&cf_str_EAP_GTC_passcode_prompt_literal,
						&cf_str_EAP_GTC_passcode_literal);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): calls aDatabase.Execute()\n")));

	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapGtcDbUtils::OpenDatabaseL(): aDatabase.Execute() error=%d\n"),
			error));

		User::Leave(error);
	}

	// 4. Check if database table contains a row for this service type and id  

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): calls sqlStatement.Format()\n")));

	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQLQueryRow,
		&cf_str_EAP_GTC_identity_literal,
		&KGtcTableName, 
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());
			
	RDbView view;

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): calls view.Prepare()\n")));

	error = view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): view.Prepare() error=%d\n"),
		error));

	User::LeaveIfError(error);
	// View must be closed when no longer needed
	CleanupClosePushL(view);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): calls view.EvaluateAll()\n")));

	error = view.EvaluateAll();

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): view.EvaluateAll() error=%d\n"),
		error));

	User::LeaveIfError(error);
	
	// 5. If row is not found then add it
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): calls view.CountL()\n")));

	TInt rows = view.CountL();

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): view.CountL() rows=%d\n"),
		rows));

	CleanupStack::PopAndDestroy(&view);
	if (rows == 0)
	{		
		_LIT(KSQLInsert, "SELECT * FROM %S");
		sqlStatement.Format(KSQLInsert, &KGtcTableName);		

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): calls view.Prepare()\n")));

		error = view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly);

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): view.Prepare() error=%d\n"),
			error));

		CleanupClosePushL(view);
		
		// Get column set so we get the correct column numbers
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): calls view.ColSetL()\n")));

		CDbColSet* colSet = view.ColSetL();		
		CleanupStack::PushL(colSet);
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): calls view.InsertL()\n")));

		view.InsertL();
		view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt> (aIndexType));
		view.SetColL(colSet->ColNo(KServiceIndex), aIndex);
		view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
		view.SetColL(colSet->ColNo(cf_str_EAP_GTC_identity_literal), default_EAP_identity);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_GTC_max_session_validity_time_literal), default_MaxSessionTime);
		
		view.SetColL(colSet->ColNo(KGTCLastFullAuthTime), default_FullAuthTime);		
		view.SetColL(colSet->ColNo(cf_str_EAP_GTC_passcode_prompt_literal), default_EAP_password_prompt);
		view.SetColL(colSet->ColNo(cf_str_EAP_GTC_passcode_literal), default_EAP_password);
				
		view.PutL();

		CleanupStack::PopAndDestroy( colSet );
		
		CleanupStack::PopAndDestroy( &view );
		
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::OpenDatabaseL(): calls aDatabase.Compact()\n")));

	aDatabase.Compact();

	CleanupStack::PopAndDestroy( buf );
	CleanupStack::Pop( &aDatabase );	
	CleanupStack::Pop( &aFileServerSession );
}

// ----------------------------------------------------------

void EapGtcDbUtils::SetIndexL(
	RDbNamedDatabase& aDatabase, 		
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const TIndexType aNewIndexType,
	const TInt aNewIndex,
	const eap_type_value_e aNewTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapGtcDbUtils::SetIndexL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapGtcDbUtils::SetIndexL(): -Start- aNewIndexType=%d, aNewIndex=%d, aNewTunnelingType=0xfe%06x%08x\n"),
		aNewIndexType,
		aNewIndex,
		aNewTunnelingType.get_vendor_id(),
		aNewTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapGtcDbUtils::SetIndexL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL,
		&KGtcTableName, 
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
	view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aNewTunnelingType.get_vendor_id());
	view.SetColL(colSet->ColNo(KTunnelingType), aNewTunnelingType.get_vendor_type());

    view.PutL();
    	
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);
}

// ----------------------------------------------------------

void EapGtcDbUtils::SetConfigurationL(
	RDbNamedDatabase& aDatabase,
	const EAPSettings& aSettings, 
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapGtcDbUtils::SetConfigurationL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapGtcDbUtils::SetConfigurationL()\n"));

	EAP_TRACE_SETTINGS(&aSettings);

	// Check if the settings are for the correct type
	if (aSettings.iEAPExpandedType != (*EapExpandedTypeGtc.GetType()))
	{
		User::Leave(KErrNotSupported);
	}
	
	
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();	

	RDbView view;

	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQLQuery,
		&KGtcTableName, 
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

	// Username
	if (aSettings.iUsernamePresent)
	{
		// Validate length.
		if(aSettings.iUsername.Length() > KMaxIdentityLengthInDB)
		{
			// Username too long. Can not be stored in DB.
			
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapGtcDbUtils::SetConfigurationL(): Too long Username. Length=%d \n"),
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

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::SetConfigurationL(): Session Validity: Resetting Full Auth Time since settings are modified\n")));

	// Password existence.
	if (aSettings.iPasswordExistPresent
		&& !aSettings.iPasswordExist)
	{
		// Clear password from database.
		view.SetColL(colSet->ColNo(cf_str_EAP_GTC_passcode_literal), KNullPasswordData);
		view.SetColNullL(colSet->ColNo(cf_str_EAP_GTC_passcode_literal));
	}

	// Password
	if (aSettings.iPasswordPresent)
	{
		// Validate length.
		if(aSettings.iPassword.Length() > KMaxPasswordLengthInDB)
		{
			// Password too long. Can not be stored in DB.
			
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapGtcDbUtils::SetConfigurationL(): Too long Password. Length=%d \n"),
				aSettings.iPassword.Length()));
			
			User::Leave(KErrArgument);
		}
					
		// Length is ok. Set the value in DB.	
		view.SetColL(colSet->ColNo(cf_str_EAP_GTC_passcode_literal), aSettings.iPassword);
		
	}
			
	if (aSettings.iShowPassWordPromptPresent)
		{	
		// If password was supplied set password prompting off
		if (aSettings.iShowPassWordPrompt != EFalse)
			view.SetColL(colSet->ColNo(cf_str_EAP_GTC_passcode_prompt_literal), EEapDbTrue);		
		else
			view.SetColL(colSet->ColNo(cf_str_EAP_GTC_passcode_prompt_literal), EEapDbFalse);		
		}
		
	view.PutL();

	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);
}

// ----------------------------------------------------------

void EapGtcDbUtils::GetConfigurationL(
	RDbNamedDatabase& aDatabase,
	EAPSettings& aSettings, 
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapGtcDbUtils::GetConfigurationL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapGtcDbUtils::GetConfigurationL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();	

	RDbView view;

	// Form the query
	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQLQuery,
		&KGtcTableName, 
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

	aSettings.iEAPExpandedType = *EapExpandedTypeGtc.GetType();
	
	// Username
	TPtrC username = view.ColDes(colSet->ColNo(cf_str_EAP_GTC_identity_literal));
	aSettings.iUsername.Copy(username);
	aSettings.iUsernamePresent = ETrue;
	
	// Password existence.
	aSettings.iPasswordExistPresent = ETrue;
	aSettings.iPasswordExist = ! view.IsColNull(colSet->ColNo(cf_str_EAP_GTC_passcode_literal));

#if defined(USE_EAP_PASSWORD_READ_FROM_DATABASE)
	// Password
	TPtrC password = view.ColDes(colSet->ColNo(cf_str_EAP_GTC_passcode_literal));
	aSettings.iPassword.Copy(password);
	aSettings.iPasswordPresent = ETrue;
#else
	EAP_TRACE_DEBUG_SYMBIAN((_L("WARNING: EapGtcDbUtils::GetConfigurationL(): Password read is disabled\n")));
#endif //#if defined(USE_EAP_PASSWORD_READ_FROM_DATABASE)

	aSettings.iShowPassWordPromptPresent = ETrue;

	TUint aShow = view.ColUint(colSet->ColNo(cf_str_EAP_GTC_passcode_prompt_literal));
	if(aShow == EEapDbFalse)
	{
		aSettings.iShowPassWordPrompt = EFalse;
	}
	else
	{
		aSettings.iShowPassWordPrompt = ETrue;
	}

	// Session validity time	
	TInt64 maxSessionTimeMicro = view.ColInt64(colSet->ColNo(cf_str_EAP_GTC_max_session_validity_time_literal));
	
	// Convert the time to minutes.	
	TInt64 maxSessionTimeMin = maxSessionTimeMicro / KMicroSecsInAMinute;
	
	aSettings.iSessionValidityTime = static_cast<TUint>(maxSessionTimeMin);
	aSettings.iSessionValidityTimePresent = ETrue;
	
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);

	EAP_TRACE_SETTINGS(&aSettings);
}

// ----------------------------------------------------------

void EapGtcDbUtils::CopySettingsL(
	RDbNamedDatabase& aDatabase, 		
	const TIndexType aSrcIndexType,
	const TInt aSrcIndex,
	const eap_type_value_e aSrcTunnelingType,
	const TIndexType aDestIndexType,
	const TInt aDestIndex,
	const eap_type_value_e aDestTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapGtcDbUtils::CopySettingsL(): -Start- aSrcIndexType=%d, aSrcIndex=%d, aSrcTunnelingType=0xfe%06x%08x\n"),
		aSrcIndexType,
		aSrcIndex,
		aSrcTunnelingType.get_vendor_id(),
		aSrcTunnelingType.get_vendor_type()));
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapGtcDbUtils::CopySettingsL(): -Start- aDestIndexType=%d, aDestTunnelingType=0xfe%06x%08x\n"),
		aDestIndexType,
		aDestIndex,
		aDestTunnelingType.get_vendor_id(),
		aDestTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapGtcDbUtils::CopySettingsL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL,
		&KGtcTableName, 
		&KServiceType,
		aSrcIndexType,
		&KServiceIndex,
		aSrcIndex,
		&KTunnelingTypeVendorId,
		aSrcTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aSrcTunnelingType.get_vendor_type());
	
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
	view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aDestTunnelingType.get_vendor_id());
	view.SetColL(colSet->ColNo(KTunnelingType), aDestTunnelingType.get_vendor_type());

    view.PutL();
    	
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);
}

// ----------------------------------------------------------

void EapGtcDbUtils::DeleteConfigurationL(	
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapGtcDbUtils::DeleteConfigurationL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapGtcDbUtils::DeleteConfigurationL()\n"));

	RDbNamedDatabase aDatabase;
	RFs aFileServerSession;

	TInt error(KErrNone);
	TFileName aPrivateDatabasePathName;
	
	error = aFileServerSession.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::DeleteConfigurationL(): - aFileServerSession.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	EapPluginTools::CreateDatabaseLC(
		aDatabase,
		aFileServerSession,
		error,
		KEapGtcDatabaseName,
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
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::DeleteConfigurationL(): - calls aDatabase.Open()\n")));

	error = aDatabase.Open(aFileServerSession, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapGtcDbUtils::DeleteConfigurationL(): - Opened private DB for EAP-GTC. error=%d\n"), error));

	User::LeaveIfError(error);

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Main settings table
	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL,
		&KGtcTableName, 
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
	User::LeaveIfError(view.Prepare(aDatabase,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
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
	CleanupStack::PopAndDestroy(buf);
	CleanupStack::PopAndDestroy(&aDatabase);
	CleanupStack::PopAndDestroy(&aFileServerSession);
}

// ----------------------------------------------------------

// End of File
