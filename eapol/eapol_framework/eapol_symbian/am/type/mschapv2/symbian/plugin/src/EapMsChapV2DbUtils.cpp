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
* %version: 56 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 294 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "EapMsChapV2DbUtils.h"
#include "EapMsChapV2DbDefaults.h"
#include "EapMsChapV2DbParameterNames.h"

#include <EapTraceSymbian.h>
#include "EapPluginTools.h"

const TUint KMaxSqlQueryLength = 512;
const TInt KMicroSecsInAMinute = 60000000; // 60000000 micro seconds is 1 minute.

// ================= MEMBER FUNCTIONS =======================

void EapMsChapV2DbUtils::OpenDatabaseL(
	RDbNamedDatabase& aDatabase,
	RFs& aFileServerSession,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapMsChapV2DbUtils::OpenDatabaseL(): - Start - aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapMsChapV2DbUtils::OpenDatabaseL()\n"));

	// 1. Open/create a database	
	
	TInt error(KErrNone);
	TFileName aPrivateDatabasePathName;

	EapPluginTools::CreateDatabaseLC(
		aDatabase,
		aFileServerSession,
		error,
		KEapMsChapV2DatabaseName,
		aPrivateDatabasePathName);

	if(error == KErrNone)
	{
		aDatabase.Close();
	}
	else if (error != KErrAlreadyExists) 
	{
		User::LeaveIfError(error);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): - calls aDatabase.Open()\n")));

	error = aDatabase.Open(aFileServerSession, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): - Opened private DB for EAP-MsChapV2. error=%d\n"), error));

	User::LeaveIfError(error);

	// 2. Create the MSCHAPv2 table to database (ignore error if database exists)
	// Table columns:
	//// NAME ///////////////////////////////////////////////// TYPE ////////////// Constant /////////
	//| ServiceType                                         | UNSIGNED INTEGER  | KServiceType      |//
	//| ServiceIndex                                        | UNSIGNED INTEGER  | KServiceIndex     |//
	//| TunnelingTypeVendorId                               | UNSIGNED INTEGER  | KTunnelingTypeVendorId    |//
	//| TunnelingType                                       | UNSIGNED INTEGER  | KTunnelingType    |//
	//| EAP_MSCHAPV2_password_prompt                        | UNSIGNED INTEGER  | cf_str_EAP_MSCHAPV2_password_prompt_literal   |//
	//| EAP_MSCHAPV2_username                               | VARCHAR(255)      | cf_str_EAP_MSCHAPV2_username_literal         |//
	//| EAP_MSCHAPV2_password                               | VARCHAR(255)      | cf_str_EAP_MSCHAPV2_password_literal         |//
	//| EAP_MSCHAPv2_max_session_validity_time				      | BIGINT		   	    | cf_str_EAP_MSCHAPv2_max_session_validity_time_literal   |//
	//| EAP_MSCHAPv2_last_full_authentication_time			    | BIGINT		   	    | KMSCHAPv2LastFullAuthTime	|//
	//////////////////////////////////////////////////////////////////////////////////////////////////

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): calls HBufC::NewLC()\n")));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLCreateTable1, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
		 %S VARCHAR(255), \
		 %S VARCHAR(255), \
		 %S BIGINT, \
		 %S BIGINT)");

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): calls sqlStatement.Format()\n")));

	sqlStatement.Format(KSQLCreateTable1,
						&KMsChapV2TableName,
						&KServiceType,
						&KServiceIndex,
						&KTunnelingTypeVendorId,
						&KTunnelingType,
						&cf_str_EAP_MSCHAPV2_password_prompt_literal,
						&cf_str_EAP_MSCHAPV2_username_literal,
						&cf_str_EAP_MSCHAPV2_password_literal,
						&cf_str_EAP_MSCHAPv2_max_session_validity_time_literal, 
						&KMSCHAPv2LastFullAuthTime);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): calls aDatabase.Execute()\n")));

	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapMsChapV2DbUtils::OpenDatabaseL(): aDatabase.Execute() error=%d\n"),
			error));

		User::Leave(error);
	}

	// 4. Check if database table contains a row for this service type and id  

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): calls sqlStatement.Format()\n")));

	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLQueryRow,
		&cf_str_EAP_MSCHAPV2_username_literal,
		&KMsChapV2TableName,
		&KServiceType,
		aIndexType,
		&KServiceIndex,
		aIndex,
		&KTunnelingTypeVendorId,
		aTunnelingType.get_vendor_id(),
		&KTunnelingType, 
		aTunnelingType.get_vendor_type());

	RDbView view;

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): calls view.Prepare()\n")));

	error = view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): view.Prepare() error=%d\n"),
		error));

	User::LeaveIfError(error);
	// View must be closed when no longer needed
	CleanupClosePushL(view);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): calls view.EvaluateAll()\n")));

	error = view.EvaluateAll();

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): view.EvaluateAll() error=%d\n"),
		error));

	User::LeaveIfError(error);
	
	// 5. If row is not found then add it
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): calls view.CountL()\n")));

	TInt rows = view.CountL();

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): view.CountL() rows=%d\n"),
		rows));

	CleanupStack::PopAndDestroy(&view);
	if (rows == 0)
	{
		_LIT(KSQLInsert, "SELECT * FROM %S");
		sqlStatement.Format(KSQLInsert, &KMsChapV2TableName);		
		
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): calls view.Prepare()\n")));

		error = view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EInsertOnly);

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): view.Prepare() error=%d\n"),
			error));

		User::LeaveIfError(error);
		CleanupClosePushL(view);

		// Get column set so we get the correct column numbers
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): calls view.ColSetL()\n")));

		CDbColSet* colSet = view.ColSetL();		
		CleanupStack::PushL(colSet);

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::OpenDatabaseL(): calls view.InsertL()\n")));

		view.InsertL();
		view.SetColL(colSet->ColNo(KServiceType), static_cast<TInt> (aIndexType));
		view.SetColL(colSet->ColNo(KServiceIndex), aIndex);
		view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
		
		view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_prompt_literal), default_EAP_password_prompt);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPV2_username_literal), default_EAP_username);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_literal), default_EAP_password);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPv2_max_session_validity_time_literal), default_MaxSessionTime);
		
		view.SetColL(colSet->ColNo(KMSCHAPv2LastFullAuthTime), default_FullAuthTime);		
		
		view.PutL();
				
		CleanupStack::PopAndDestroy(colSet);
		CleanupStack::PopAndDestroy(&view);
	} 

	aDatabase.Compact();

	CleanupStack::PopAndDestroy( buf );
	CleanupStack::Pop( &aDatabase );	
	CleanupStack::Pop( &aFileServerSession );
}


void EapMsChapV2DbUtils::SetIndexL(
	RDbNamedDatabase& aDatabase, 		
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const TIndexType aNewIndexType,
	const TInt aNewIndex,
	const eap_type_value_e aNewTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapMsChapV2DbUtils::SetIndexL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapMsChapV2DbUtils::SetIndexL(): -Start- aNewIndexType=%d, aNewIndex=%d, aNewTunnelingType=0xfe%06x%08x\n"),
		aNewIndexType,
		aNewIndex,
		aNewTunnelingType.get_vendor_id(),
		aNewTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapMsChapV2DbUtils::SetIndexL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL,
		&KMsChapV2TableName, 
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

void EapMsChapV2DbUtils::SetConfigurationL(
	RDbNamedDatabase& aDatabase,
	const EAPSettings& aSettings, 
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapMsChapV2DbUtils::SetConfigurationL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapMsChapV2DbUtils::SetConfigurationL()\n"));

	EAP_TRACE_SETTINGS(&aSettings);

	// Check if the settings are for the correct type
	if (aSettings.iEAPExpandedType != (*EapExpandedTypeMsChapv2.GetType())
		&& aSettings.iEAPExpandedType != (*EapExpandedPlainMsChapv2.GetType()))
	{
		User::Leave(KErrNotSupported);
	}
	
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();	

	RDbView view;

	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQLQuery,
		&KMsChapV2TableName, 
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
		if(aSettings.iUsername.Length() > KMaxUsernameLengthInDB)
		{
			// Username too long. Can not be stored in DB.
			
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapMsChapV2DbUtils::SetConfigurationL(): Too long Username. Length=%d \n"),
			aSettings.iUsername.Length()));
			
			User::Leave(KErrArgument);
		}
		
		// Length is ok. Set the value in DB.
		view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPV2_username_literal), aSettings.iUsername);		
	}
		
	// Password existence.
	if (aSettings.iPasswordExistPresent
		&& !aSettings.iPasswordExist)
	{
		// Clear password from database.
		view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_literal), KNullPasswordData);
		view.SetColNullL(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_literal));
	}

	// Password
	if (aSettings.iPasswordPresent)
	{
		// Validate length.
		if(aSettings.iPassword.Length() > KMaxPasswordLengthInDB)
		{
			// Password too long. Can not be stored in DB.
			
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapMsChapV2DbUtils::SetConfigurationL(): Too long Password. Length=%d \n"),
			aSettings.iPassword.Length()));
			
			User::Leave(KErrArgument);
		}
					
		// Length is ok. Set the value in DB.	
		view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_literal), aSettings.iPassword);
		
	}
			
	if (aSettings.iShowPassWordPromptPresent)
		{	
		// If password was supplied set password prompting off
		if (aSettings.iShowPassWordPrompt == EFalse)
			{
				view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_prompt_literal), EEapDbFalse );
			}
		else
			{
				view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_prompt_literal), EEapDbTrue );
			}		
		}

	// Session validity time
	if (aSettings.iSessionValidityTimePresent)
	{
		// User or device management wants to store the session validity time.
		// Convert the time to micro seconds and save.
		
		TInt64 validityInMicro = (aSettings.iSessionValidityTime) *  KMicroSecsInAMinute;
		
		view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPv2_max_session_validity_time_literal), validityInMicro);
		
		// If max session validity time is supplied and non-zero, set password prompting ON.
		// It doesn't matter even if the password is supplied. If max session validity is supplied,
		// it means user needs to provide a password hence prompt should appear.
		
		if( validityInMicro != 0)
		{
			view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_prompt_literal), EEapDbTrue);
		}		
	}
	
	// Last full authentication time should be made zero when EAP configurations are modified.
	// This makes sure that the next authentication with this EAP would be full authentication
	// instead of reauthentication even if the session is still valid.

	view.SetColL(colSet->ColNo(KMSCHAPv2LastFullAuthTime), default_FullAuthTime);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::SetConfigurationL(): Session Validity: Resetting Full Auth Time since settings are modified\n")));

	view.PutL();

	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);
}

void EapMsChapV2DbUtils::GetConfigurationL(
	RDbNamedDatabase& aDatabase,
	EAPSettings& aSettings, 
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapMsChapV2DbUtils::GetConfigurationL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapMsChapV2DbUtils::GetConfigurationL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();	

	RDbView view;

	// Form the query
	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQLQuery,
		&KMsChapV2TableName, 
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

	aSettings.iEAPExpandedType = *EapExpandedTypeMsChapv2.GetType(); 
	
	// Username
	TPtrC username = view.ColDes(colSet->ColNo(cf_str_EAP_MSCHAPV2_username_literal));
	aSettings.iUsername.Copy(username);
	aSettings.iUsernamePresent = ETrue;
	
	// Password existence.
	aSettings.iPasswordExistPresent = ETrue;
	aSettings.iPasswordExist = ! view.IsColNull(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_literal));

#if defined(USE_EAP_PASSWORD_READ_FROM_DATABASE)
	// Password
	TPtrC password = view.ColDes(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_literal));
	aSettings.iPassword.Copy(password);
	aSettings.iPasswordPresent = ETrue;
#else
	EAP_TRACE_DEBUG_SYMBIAN((_L("WARNING: EapMsChapV2DbUtils::GetConfigurationL(): Password read is disabled\n")));
#endif //#if defined(USE_EAP_PASSWORD_READ_FROM_DATABASE)

	aSettings.iShowPassWordPromptPresent = ETrue;

	TUint aShow = view.ColUint(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_prompt_literal));
	if(aShow == EEapDbFalse)
	{
		aSettings.iShowPassWordPrompt = EFalse;
	}
	else
	{
		aSettings.iShowPassWordPrompt = ETrue;
	}
	
	// Session validity time	
	TInt64 maxSessionTimeMicro = view.ColInt64(colSet->ColNo(cf_str_EAP_MSCHAPv2_max_session_validity_time_literal));
	
	// Convert the time to minutes.	
	TInt64 maxSessionTimeMin = maxSessionTimeMicro / KMicroSecsInAMinute;
	
	aSettings.iSessionValidityTime = static_cast<TUint>(maxSessionTimeMin);
	aSettings.iSessionValidityTimePresent = ETrue;
		
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);

	EAP_TRACE_SETTINGS(&aSettings);
}

void EapMsChapV2DbUtils::CopySettingsL(
	RDbNamedDatabase& aDatabase, 		
	const TIndexType aSrcIndexType,
	const TInt aSrcIndex,
	const eap_type_value_e aSrcTunnelingType,
	const TIndexType aDestIndexType,
	const TInt aDestIndex,
	const eap_type_value_e aDestTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapMsChapV2DbUtils::CopySettingsL(): -Start- aSrcIndexType=%d, aSrcIndex=%d, aSrcTunnelingType=0xfe%06x%08x\n"),
		aSrcIndexType,
		aSrcIndex,
		aSrcTunnelingType.get_vendor_id(),
		aSrcTunnelingType.get_vendor_type()));
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapMsChapV2DbUtils::CopySettingsL(): -Start- aDestIndexType=%d, aDestTunnelingType=0xfe%06x%08x\n"),
		aDestIndexType,
		aDestIndex,
		aDestTunnelingType.get_vendor_id(),
		aDestTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapMsChapV2DbUtils::CopySettingsL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL,
		&KMsChapV2TableName, 
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

void EapMsChapV2DbUtils::DeleteConfigurationL(	
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapMsChapV2DbUtils::DeleteConfigurationL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapMsChapV2DbUtils::DeleteConfigurationL()\n"));

	RDbNamedDatabase aDatabase;
	RFs aFileServerSession;

	TInt error(KErrNone);
	TFileName aPrivateDatabasePathName;
	
	error = aFileServerSession.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::DeleteConfigurationL(): - aFileServerSession.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	EapPluginTools::CreateDatabaseLC(
		aDatabase,
		aFileServerSession,
		error,
		KEapMsChapV2DatabaseName,
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
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::DeleteConfigurationL(): - calls aDatabase.Open()\n")));

	error = aDatabase.Open(aFileServerSession, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapMsChapV2DbUtils::DeleteConfigurationL(): - Opened private DB for EAP-MsChapV2. error=%d\n"), error));

	User::LeaveIfError(error);

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Main settings table
	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL,
		&KMsChapV2TableName, 
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

// End of File
