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
* %version: 57 %
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

#include <EapTraceSymbian.h>
#include "EapPluginTools.h"

const TInt KMaxSqlQueryLength = 2048;
const TInt KMicroSecsInAMinute = 60000000; // 60000000 micro seconds is 1 minute.

// ================= MEMBER FUNCTIONS =======================

void EapSimDbUtils::OpenDatabaseL(
	RDbNamedDatabase& aDatabase,
	RFs& aFileServerSession,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapSimDbUtils::OpenDatabaseL(): Start - aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapSimDbUtils::OpenDatabaseL()\n"));

	// 1. Open/create a database	
	
	TInt error(KErrNone);
	TFileName aPrivateDatabasePathName;

	EapPluginTools::CreateDatabaseLC(
		aDatabase,
		aFileServerSession,
		error,
		KEapSimDatabaseName,
		aPrivateDatabasePathName);

	if(error == KErrNone)
	{
		aDatabase.Close();
	}
	else if (error != KErrAlreadyExists) 
	{
		User::LeaveIfError(error);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::OpenDatabaseL(): calls aDatabase.Open()\n")));

	error = aDatabase.Open(aFileServerSession, aPrivateDatabasePathName);

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::OpenDatabaseL(): Opened private DB for EAP-SIM. error=%d\n"), error));

	User::LeaveIfError(error);

	// 2. Create the eapsim table to database (ignore error if exists)
	
	// Table columns:
	//// NAME ///////////////////////////////////////////////// TYPE ////////////// Constant /////////
	//| ServiceType									| UNSIGNED INTEGER | KServiceType      |//
	//| ServiceIndex								| UNSIGNED INTEGER | KServiceIndex     |//
	//| TunnelingTypeVendorId                       | UNSIGNED INTEGER  | KTunnelingTypeVendorId    |//
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
	
	_LIT(KSQLCreateTable, "CREATE TABLE %S \
		(%S UNSIGNED INTEGER, \
		 %S UNSIGNED INTEGER, \
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
												 
	sqlStatement.Format(KSQLCreateTable,
		&KSimTableName,
		&KServiceType,
		&KServiceIndex, 
		&KTunnelingTypeVendorId,
		&KTunnelingType,
		&cf_str_EAP_GSMSIM_use_manual_realm_literal, 
		&cf_str_EAP_GSMSIM_manual_realm_literal, KMaxRealmLengthInDB, 
		&cf_str_EAP_GSMSIM_use_manual_username_literal, 
		&cf_str_EAP_GSMSIM_manual_username_literal, KMaxUsernameLengthInDB, 
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
																					
	error = aDatabase.Execute(sqlStatement);
	if (error != KErrNone && error != KErrAlreadyExists)
	{
		User::Leave(error);
	}
	
	// 4. Check if database table contains a row for this service type and id  
	
	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQLQueryRow,
		&cf_str_EAP_GSMSIM_manual_realm_literal,
		&KSimTableName, 
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
		view.SetColL(colSet->ColNo(KTunnelingTypeVendorId), aTunnelingType.get_vendor_id());
		view.SetColL(colSet->ColNo(KTunnelingType), aTunnelingType.get_vendor_type());
		
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_manual_realm_literal), default_EAP_GSMSIM_use_manual_realm);	
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_manual_realm_literal), default_EAP_realm);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_manual_username_literal), default_EAP_GSMSIM_use_manual_username);
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_manual_username_literal), default_EAP_username);
		
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_pseudonym_identity_literal), default_EAP_GSMSIM_use_pseudonym_identity);			
		
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_max_session_validity_time_literal), default_MaxSessionTime);
		
		view.SetColL(colSet->ColNo(KGSMSIMLastFullAuthTime), default_FullAuthTime);				

		view.PutL();
		
		CleanupStack::PopAndDestroy( colSet );
		
		CleanupStack::PopAndDestroy( &view );
	}
	
	aDatabase.Compact();

	CleanupStack::PopAndDestroy( buf );
	CleanupStack::Pop( &aDatabase );	
	CleanupStack::Pop( &aFileServerSession );
}

// ----------------------------------------------------------

void EapSimDbUtils::SetIndexL(
	RDbNamedDatabase& aDatabase, 		
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const TIndexType aNewIndexType,
	const TInt aNewIndex,
	const eap_type_value_e aNewTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapSimDbUtils::SetIndexL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapSimDbUtils::SetIndexL(): -Start- aNewIndexType=%d, aNewIndex=%d, aNewTunnelingType=0xfe%06x%08x\n"),
		aNewIndexType,
		aNewIndex,
		aNewTunnelingType.get_vendor_id(),
		aNewTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapSimDbUtils::SetIndexL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL,
		&KSimTableName, 
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

void EapSimDbUtils::SetConfigurationL(
	RDbNamedDatabase& aDatabase,
	const EAPSettings& aSettings, 
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapSimDbUtils::SetConfigurationL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapSimDbUtils::SetConfigurationL()\n"));

	EAP_TRACE_DEBUG_SYMBIAN((_L("*************************** SetConfigurationL(): Set the below values: ***************************\n")) );

	EAP_TRACE_SETTINGS(&aSettings);

	EAP_TRACE_DEBUG_SYMBIAN((_L("*************************** SetConfigurationL(): Set the above values: ***************************\n")) );

	// Check if the settings are for the correct type
	if (aSettings.iEAPExpandedType != (*EapExpandedTypeSim.GetType()))
	{
		User::Leave(KErrNotSupported);
	}
	
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();	

	RDbView view;

	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQLQuery,
		&KSimTableName, 
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
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_manual_username_literal), useManualUsernameStatus);
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
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_manual_realm_literal), useManualRealmStatus);
	}


	// Manual username
	if (aSettings.iUsernamePresent) // no need to check as there may be empty usernames with the present status is EFlase.
	{
		// Check if length of username is less than the max length.
		if(aSettings.iUsername.Length() > KMaxUsernameLengthInDB)
		{
			// Username too long. Can not be stored in DB.
			
			EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::SetConfigurationL: Too long Username. Length=%d \n"),
			aSettings.iUsername.Length()));
			
			User::Leave(KErrArgument);
		}
		
		// Length is ok. Set the value in DB. Value could be empty. It doesn't matter.
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_manual_username_literal), aSettings.iUsername);
	}
		
	// Manual realm
	if (aSettings.iRealmPresent)  // no need to check as there may be empty realms with the present status is EFlase.
	{
		// Check if length of realm is less than the max length.
		if(aSettings.iRealm.Length() > KMaxRealmLengthInDB)
		{
			// Realm too long. Can not be stored in DB.

			EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::SetConfigurationL: Too long Realm. Length=%d \n"),
			aSettings.iRealm.Length()));
			
			User::Leave(KErrArgument);
		}

		// Length is ok. Set the value in DB. Value could be empty. It doesn't matter.
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_manual_realm_literal), aSettings.iRealm);
	}
	
	// UsePseudonym
	if (aSettings.iUsePseudonymsPresent)
	{
		if (aSettings.iUsePseudonyms)
		{
			// Use pseudonym.
			view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_pseudonym_identity_literal), EEapDbTrue);
		}
		else
		{			
			// Don't use pseudonym.
			view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_pseudonym_identity_literal), EEapDbFalse);			
		}
	}
	else
	{
		// Value is not configured. Value is read from config file if needed.
		view.SetColL(colSet->ColNo(cf_str_EAP_GSMSIM_use_pseudonym_identity_literal), EEapDbNotValid);		
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

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::SetConfigurationL(): Session Validity: Resetting Full Auth Time since settings are modified\n")));
	}

	view.PutL();

	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);
}

// ----------------------------------------------------------

void EapSimDbUtils::GetConfigurationL(
	RDbNamedDatabase& aDatabase,
	EAPSettings& aSettings, 
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapSimDbUtils::GetConfigurationL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapSimDbUtils::GetConfigurationL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();	

	RDbView view;

	// Form the query
	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQLQuery,
		&KSimTableName, 
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

	aSettings.iEAPExpandedType = *EapExpandedTypeSim.GetType();

	{
		// For manual or automatic username.
		TUint useUsername = view.ColUint(colSet->ColNo(cf_str_EAP_GSMSIM_use_manual_username_literal));

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
		TUint useRealm = view.ColUint(colSet->ColNo(cf_str_EAP_GSMSIM_use_manual_realm_literal));

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
		TPtrC username = view.ColDes(colSet->ColNo(cf_str_EAP_GSMSIM_manual_username_literal));

		aSettings.iUsernamePresent = ETrue;

		aSettings.iUsername.Copy(username);
	}

	{
		// Realm
		TPtrC realm = view.ColDes(colSet->ColNo(cf_str_EAP_GSMSIM_manual_realm_literal));

		aSettings.iRealmPresent = ETrue;

		aSettings.iRealm.Copy(realm);
	}

	{
		TInt usePseudonym = view.ColUint(colSet->ColNo(cf_str_EAP_GSMSIM_use_pseudonym_identity_literal));
		
		if (usePseudonym == EEapDbNotValid)
		{
			aSettings.iUsePseudonymsPresent = EFalse;
		}
		else
		{
			if (usePseudonym == EEapDbFalse)
			{
				aSettings.iUsePseudonyms = EFalse;
			}
			else
			{
				aSettings.iUsePseudonyms = ETrue;
			}
			
			aSettings.iUsePseudonymsPresent = ETrue;		
		}	
	}

	{
		// Session validity time	
		TInt64 maxSessionTimeMicro = view.ColInt64(colSet->ColNo(cf_str_EAP_GSMSIM_max_session_validity_time_literal));
		
		// Convert the time to minutes.	
		TInt64 maxSessionTimeMin = maxSessionTimeMicro / KMicroSecsInAMinute;
		
		aSettings.iSessionValidityTime = static_cast<TUint>(maxSessionTimeMin);
		aSettings.iSessionValidityTimePresent = ETrue;
	}

	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);

	EAP_TRACE_SETTINGS(&aSettings);
}

// ----------------------------------------------------------

void EapSimDbUtils::CopySettingsL(
	RDbNamedDatabase& aDatabase, 		
	const TIndexType aSrcIndexType,
	const TInt aSrcIndex,
	const eap_type_value_e aSrcTunnelingType,
	const TIndexType aDestIndexType,
	const TInt aDestIndex,
	const eap_type_value_e aDestTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapSimDbUtils::CopySettingsL(): -Start- aSrcIndexType=%d, aSrcIndex=%d, aSrcTunnelingType=0xfe%06x%08x\n"),
		aSrcIndexType,
		aSrcIndex,
		aSrcTunnelingType.get_vendor_id(),
		aSrcTunnelingType.get_vendor_type()));
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapSimDbUtils::CopySettingsL(): -Start- aDestIndexType=%d, aDestTunnelingType=0xfe%06x%08x\n"),
		aDestIndexType,
		aDestIndex,
		aDestTunnelingType.get_vendor_id(),
		aDestTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapSimDbUtils::CopySettingsL()\n"));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQL,
		&KSimTableName, 
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

void EapSimDbUtils::DeleteConfigurationL(	
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType)
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("EapSimDbUtils::DeleteConfigurationL(): -Start- aIndexType=%d, aIndex=%d, aTunnelingType=0xfe%06x%08x\n"),
		aIndexType,
		aIndex,
		aTunnelingType.get_vendor_id(),
		aTunnelingType.get_vendor_type()));

    EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapSimDbUtils::DeleteConfigurationL()\n"));

	RDbNamedDatabase aDatabase;
	RFs aFileServerSession;

	TInt error(KErrNone);
	TFileName aPrivateDatabasePathName;
	
	error = aFileServerSession.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::DeleteConfigurationL(): - aFileServerSession.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	EapPluginTools::CreateDatabaseLC(
		aDatabase,
		aFileServerSession,
		error,
		KEapSimDatabaseName,
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
	
	error = aDatabase.Open(aFileServerSession, aPrivateDatabasePathName);

	User::LeaveIfError(error);

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Main settings table
	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(
		KSQL,
		&KSimTableName, 
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

	error = view.Prepare(aDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited);

	User::LeaveIfError(error);

	CleanupClosePushL(view);

	error = view.EvaluateAll();

	User::LeaveIfError(error);

	// Delete rows
	if (view.FirstL())
	{		
		do
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::DeleteConfigurationL(): calls view.DeleteL()\n")));

			view.DeleteL();
		}
		while (view.NextL() != EFalse);

		EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::DeleteConfigurationL(): All rows deleted.\n")));
	}
	else
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapSimDbUtils::DeleteConfigurationL(): No rows to delete.\n")));
	}

	CleanupStack::PopAndDestroy(&view);
	CleanupStack::PopAndDestroy(buf);
	CleanupStack::PopAndDestroy(&aDatabase);
	CleanupStack::PopAndDestroy(&aFileServerSession);
}

// ----------------------------------------------------------

// End of file
