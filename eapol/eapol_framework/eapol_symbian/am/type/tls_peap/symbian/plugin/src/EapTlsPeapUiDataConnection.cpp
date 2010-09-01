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
* %version: 36.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 430 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include <e32base.h>
#include "EapTlsPeapUtils.h"
#include "EapTlsPeapDbParameterNames.h"
#include "EapTlsPeapDbDefaults.h"
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiDataConnection.h>
#include <EapTlsPeapUiTlsPeapData.h>
#include "eap_am_trace_symbian.h"

#ifdef USE_PAC_STORE
#include "pac_store_db_symbian.h"
#endif

const TUint KMaxSqlQueryLength = 256;

// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::CEapTlsPeapUiDataConnection()
// ---------------------------------------------------------
// 
CEapTlsPeapUiDataConnection::CEapTlsPeapUiDataConnection(CEapTlsPeapUiConnection * aUiConn)
: iIsOpened(EFalse)
, iUiConn(aUiConn)
, iColSet(NULL)
, iDataPtr(NULL)
, iFastSpecificColSet(NULL)
{
}


// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::~CEapTlsPeapUiDataConnection()
// ---------------------------------------------------------
// 
CEapTlsPeapUiDataConnection::~CEapTlsPeapUiDataConnection()
{
    if (iUiConn)
    {
        Close();
        iUiConn = NULL;
    }
}


// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::Open()
// ---------------------------------------------------------
// 
TInt CEapTlsPeapUiDataConnection::Open()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::Open: Start EAP-Type=%d\n"),
		iUiConn->GetEapType()));

    if (iIsOpened)
    {
        return KErrAlreadyExists;
    }

    TInt err = iUiConn->GetDatabase(iDatabase);
    if (err != KErrNone)
    {
        return err;
    }
    
    iIsOpened = ETrue;

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::Open: End\n")));
	
    return KErrNone;
}


// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::GetData()
// ---------------------------------------------------------
// 
TInt CEapTlsPeapUiDataConnection::GetData(CEapTlsPeapUiTlsPeapData ** aDataPtr)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::GetData: Start EAP-Type=%d\n"),
		iUiConn->GetEapType()));

    if (aDataPtr == NULL)
    {
        return KErrArgument;
    }
    
    if (iIsOpened == EFalse)
    {
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiDataConnection::GetData: Data Connection not opened\n")));
    
        return KErrSessionClosed;
    }
    
    if (iDataPtr != 0)
    {
    	*aDataPtr = iDataPtr;
    	return KErrNone;
    }
    
    iDataPtr = new CEapTlsPeapUiTlsPeapData();
    if (!iDataPtr)
    {
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiDataConnection::GetData: ERROR: NO MEMORY!\n")));    	
		
        return KErrNoMemory;
    }

    TRAPD(err, FetchDataL());
    if (err != KErrNone)
    {
        delete iDataPtr;
        iDataPtr = NULL;
        
        delete iColSet;
        iColSet = NULL;
        
		delete iFastSpecificColSet;
		iFastSpecificColSet = NULL;
        
        iView.Close();
        iFastSpecificView.Close();
        
        return err;
    }

    *aDataPtr = iDataPtr;

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::GetData: End\n")));
	
    return KErrNone;
} // CEapTlsPeapUiDataConnection::GetData()


// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::Update()
// ---------------------------------------------------------
// 
TInt CEapTlsPeapUiDataConnection::Update()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::Update: Start EAP-Type=%d\n"),
		iUiConn->GetEapType()));
    
    // Do the length checks first.
	// Check if length of username and realm are less than the max length possible in DB.
	if(iDataPtr->GetManualUsername().Length() > KMaxManualUsernameLengthInDB
		|| iDataPtr->GetManualRealm().Length() > KMaxManualRealmLengthInDB)
	{
		// Username or realm too long. Can not be stored in DB.
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiDataConnection::Update: Too long username or realm. Length: UN=%d, Realm=%d\n"),
			iDataPtr->GetManualUsername().Length(),
			iDataPtr->GetManualRealm().Length()));
		
		return KErrOverflow;
	}

#ifdef USE_FAST_EAP_TYPE	
	// Check the length of PAC store password.

	if(iDataPtr->GetPacStorePassword().Size() > KMaxPasswordLengthInDB)
	{
		// PAC store password too long. Can not be stored in DB.
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiDataConnection::Update: Too long PAC store PW. Size:%d\n"),
			iDataPtr->GetPacStorePassword().Size()));
		
		return KErrOverflow;
	}

#endif 
	
    TRAPD(err, UpdateDataL());

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::Update: End, err=%d\n"),
		err));    

	return err;
} // CEapTlsPeapUiDataConnection::Update()


// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::Close()
// ---------------------------------------------------------
// 
TInt CEapTlsPeapUiDataConnection::Close()
{
    if (iIsOpened == EFalse)
    {
        return KErrNone;
    }

    delete iDataPtr;
    iDataPtr = NULL;
    
    delete iColSet;
    iColSet = NULL;

    delete iFastSpecificColSet;
    iFastSpecificColSet = NULL;
    
    iView.Close();    
    
    iFastSpecificView.Close();

    iUiConn = NULL;
    
    return KErrNone;
} // CEapTlsPeapUiDataConnection::Close()


// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::FetchDataL()
// ---------------------------------------------------------
// 
void CEapTlsPeapUiDataConnection::FetchDataL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::FetchDataL: Start EAP-Type=%d\n"),
		iUiConn->GetEapType()));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Form the general query for TLS, PEAP, TTLS and FAST. Query everything.
	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");

	if (iUiConn->GetEapType() == eap_type_tls)
	{
		sqlStatement.Format(KSQLQuery,
							&KTlsDatabaseTableName,
							&KServiceType,
							iUiConn->GetIndexType(),
							&KServiceIndex,
							iUiConn->GetIndex(),
							&KTunnelingType, 
							iUiConn->GetTunnelingType());
	}
	else if (iUiConn->GetEapType() == eap_type_peap)
	{
		sqlStatement.Format(KSQLQuery,
							&KPeapDatabaseTableName,
							&KServiceType,
							iUiConn->GetIndexType(),
							&KServiceIndex,
							iUiConn->GetIndex(),
							&KTunnelingType, 
							iUiConn->GetTunnelingType());
	}
	else if (iUiConn->GetEapType() == eap_type_ttls || iUiConn->GetEapType() == eap_type_ttls_plain_pap)
	{
		sqlStatement.Format(KSQLQuery,
							&KTtlsDatabaseTableName,
							&KServiceType,
							iUiConn->GetIndexType(),
							&KServiceIndex,
							iUiConn->GetIndex(),
							&KTunnelingType, 
							iUiConn->GetTunnelingType());
	}
	
#ifdef USE_FAST_EAP_TYPE	
	else if (iUiConn->GetEapType() == eap_type_fast)
	{
		// Unlike other EAP types, EAP-FAST has two settings tables. 
		// General settings and special settings
		
		// This is for the General settings. The special settings are read below.
		
		sqlStatement.Format(KSQLQuery,
							&KFastGeneralSettingsDBTableName,
							&KServiceType,
							iUiConn->GetIndexType(),
							&KServiceIndex,
							iUiConn->GetIndex(),
							&KTunnelingType, 
							iUiConn->GetTunnelingType());							
	}	
#endif
	else
	{
		// Unknown EAP type
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAP-Type=%d - ERROR: Unknown EAP type!\n"),
			iUiConn->GetEapType()));
			
		User::Leave(KErrNotSupported);
	}	
		
	// Evaluate view
	User::LeaveIfError(iView.Prepare(iDatabase, TDbQuery(sqlStatement)));
	User::LeaveIfError(iView.EvaluateAll());
		
	// Get the first (and only) row
	iView.FirstL();
	iView.GetL();
	
	// Get column set so we get the correct column numbers
	delete iColSet;
	iColSet = NULL;
	iColSet = iView.ColSetL();

	// Start fetching the values

	
	/**************** only for TTLS PAP ****************/
	
	if ( iUiConn->GetEapType() == eap_type_ttls_plain_pap )
		{
		// Prompt password
		TUint intValue = iView.ColUint( iColSet->ColNo(
			cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal ) );
	    if ( intValue == 0 )
	        {
	        *( iDataPtr->GetPapPasswordPrompt() ) = EFalse;
	        }
	    else
	        {
	        *( iDataPtr->GetPapPasswordPrompt() ) = ETrue;
	        }

		// username
	    iDataPtr->GetPapUserName().Copy( iView.ColDes16( iColSet->ColNo(
	    	cf_str_EAP_TLS_PEAP_ttls_pap_username_literal ) ) );

		// password
		iDataPtr->GetPapPassword().Copy( iView.ColDes16( iColSet->ColNo(
			cf_str_EAP_TLS_PEAP_ttls_pap_password_literal ) ) );

	    CleanupStack::PopAndDestroy(buf);

		EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::FetchDataL: Return\n")));
        return;
		}
		
	// Get use manual username
	TUint intValue = iView.ColUint(iColSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal));
    if (intValue == 0)
    {
        *(iDataPtr->GetUseManualUsername()) = EFalse;
    }
    else
    {
        *(iDataPtr->GetUseManualUsername()) = ETrue;
    }

	// Get use manual realm
	intValue = iView.ColUint(iColSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal));
    if (intValue == 0)
    {
        *(iDataPtr->GetUseManualRealm()) = EFalse;
    }
    else
    {
        *(iDataPtr->GetUseManualRealm()) = ETrue;
    }

	// Get Username
    iDataPtr->GetManualUsername().Copy(iView.ColDes16(iColSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal)));

	// Get Realm
    iDataPtr->GetManualRealm().Copy(iView.ColDes16(iColSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal)));

	// Get PEAP/TTLS versions
	if (iUiConn->GetEapType() == eap_type_peap
		|| iUiConn->GetEapType() == eap_type_ttls
#ifdef USE_FAST_EAP_TYPE
		|| iUiConn->GetEapType() == eap_type_fast
#endif
		)
	{
		TPtrC8 binaryValue = iView.ColDes8(iColSet->ColNo(cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal));
	
		const TInt* allowedVersions = reinterpret_cast<const TInt *>(binaryValue.Ptr());

		TInt i;
		for (i = 0; i < static_cast<TInt>(binaryValue.Length() / sizeof(TInt)); i++)
		{
			switch(allowedVersions[i])
			{
			case 0:
				*(iDataPtr->GetAllowVersion0()) = ETrue;
				break;
			case 1:
				*(iDataPtr->GetAllowVersion1()) = ETrue;
				break;
			case 2:
				*(iDataPtr->GetAllowVersion2()) = ETrue;
				break;		
			}
		}
	}


	intValue = iView.ColUint(iColSet->ColNo(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal));

    if (intValue == 0)
    {
        *(iDataPtr->GetTlsPrivacy()) = EFalse;
    }
    else
    {
        *(iDataPtr->GetTlsPrivacy()) = ETrue;
    }

	
#ifdef USE_FAST_EAP_TYPE
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("Fetching EAP-FAST specific Special settings!\n")));

	if(iUiConn->GetEapType() == eap_type_fast)
	{		
		// This is for the EAP-FAST specific Special settings.
		
		sqlStatement.Format(KSQLQuery,
							&KFastSpecialSettingsDBTableName,
							&KServiceType,
							iUiConn->GetIndexType(),
							&KServiceIndex,
							iUiConn->GetIndex(),
							&KTunnelingType, 
							iUiConn->GetTunnelingType());
							
		// Evaluate view
		User::LeaveIfError(iFastSpecificView.Prepare(iDatabase, TDbQuery(sqlStatement)));
		User::LeaveIfError(iFastSpecificView.EvaluateAll());
			
		// Get the first (and only) row
		iFastSpecificView.FirstL();
		iFastSpecificView.GetL();
		
		// Get column set so we get the correct column numbers
		delete iFastSpecificColSet;
		iFastSpecificColSet = NULL;
		iFastSpecificColSet = iFastSpecificView.ColSetL();

		// Start fetching the values							
	    // The below uses EAP-FAST Specific settings table. So use the specific view and colset.
		
		// Get provisioning modes
		intValue = iFastSpecificView.ColUint(iFastSpecificColSet->ColNo(cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal));
	    if (intValue == 0)
	    {
	        *(iDataPtr->GetAuthProvModeAllowed()) = EFalse;
	    }
	    else
	    {
	        *(iDataPtr->GetAuthProvModeAllowed()) = ETrue;
	    }
	
		intValue = iFastSpecificView.ColUint(iFastSpecificColSet->ColNo(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal));
	    if (intValue == 0)
	    {
	        *(iDataPtr->GetUnauthProvModeAllowed()) = EFalse;
	    }
	    else
	    {
	        *(iDataPtr->GetUnauthProvModeAllowed()) = ETrue;
	    } 

#ifdef USE_PAC_STORE	    
		// Get PAC store Password
	    // PAC store password is in a different database, pac store db.
	    // We can use the PacStoreDbUtils to get the PAC store password.
	    
	    TBuf8<KMaxPasswordLengthInDB> tmpPacStorePw8;

	    iUiConn->GetPacStoreDb()->GetPacStoreDataL(
	    		cf_str_EAP_FAST_PAC_store_password_literal(),
	    		tmpPacStorePw8);	    	
	    
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
		("CEapTlsPeapUiDataConnection::FetchDataL: PW from PAC store DB(8 bits)",
		tmpPacStorePw8.Ptr(), 
		tmpPacStorePw8.Size()));
	    
	    /***** Convert the 8 bit password to 16 bits for the UI ***************/	    
	    
		iDataPtr->GetPacStorePassword().Copy(tmpPacStorePw8);  // This takes care of the conversion automatically.
		
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
		("CEapTlsPeapUiDataConnection::FetchDataL: PW to UI (16 bits)",
		iDataPtr->GetPacStorePassword().Ptr(), 
		iDataPtr->GetPacStorePassword().Size()));
		
		/*****************TEST*************/

#endif // End: #ifdef USE_PAC_STORE
	    
	} // End: if(iUiConn->GetEapType() == eap_type_fast)
    
#endif // End: #ifdef USE_FAST_EAP_TYPE	
	
    CleanupStack::PopAndDestroy(buf);

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::FetchDataL: End\n")));

} // CEapTlsPeapUiDataConnection::FetchDataL()


// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::UpdateDataL()
// ---------------------------------------------------------
// 
void CEapTlsPeapUiDataConnection::UpdateDataL()
{
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeapUiDataConnection::UpdateDataL: Start\n")));
	
    iView.UpdateL();
	
    iView.SetColL(
    	iColSet->ColNo(cf_str_EAP_TLS_PEAP_manual_username_literal),
    	iDataPtr->GetManualUsername());

    iView.SetColL(
    	iColSet->ColNo(cf_str_EAP_TLS_PEAP_manual_realm_literal),
    	iDataPtr->GetManualRealm());

    if (*(iDataPtr->GetUseManualUsername()))
    {
        iView.SetColL(
        	iColSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal),
        	ETLSPEAPUseManualUsernameYes);
    }
    else
    {
        iView.SetColL(
        	iColSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_username_literal),
        	ETLSPEAPUseManualUsernameNo);
    }
	
    if (*(iDataPtr->GetUseManualRealm()))
    {
        iView.SetColL(
        	iColSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal),
        	ETLSPEAPUseManualRealmYes);
    }
    else
    {
        iView.SetColL(
        	iColSet->ColNo(cf_str_EAP_TLS_PEAP_use_manual_realm_literal),
        	ETLSPEAPUseManualRealmNo);
    }
	
	// PEAP/TTLS versions
	if (iUiConn->GetEapType() == eap_type_peap
		|| iUiConn->GetEapType() == eap_type_ttls
#ifdef USE_FAST_EAP_TYPE	
		|| iUiConn->GetEapType() == eap_type_fast
#endif		
		)
	{
		TBuf8<KMaxPEAPVersionsStringLengthInDB> acceptedVersions;
		
		if (*(iDataPtr->GetAllowVersion0()))
		{
			TInt tmp(0);
			acceptedVersions.Append(reinterpret_cast<const TUint8*>(&tmp), sizeof(TInt));
		}
		if (*(iDataPtr->GetAllowVersion1()))
		{
			TInt tmp(1);
			acceptedVersions.Append(reinterpret_cast<const TUint8*>(&tmp), sizeof(TInt));
		}
		if (*(iDataPtr->GetAllowVersion2()))
		{
			TInt tmp(2);
			acceptedVersions.Append(reinterpret_cast<const TUint8*>(&tmp), sizeof(TInt));
		}

		iView.SetColL(
			iColSet->ColNo(cf_str_EAP_TLS_PEAP_accepted_PEAP_versions_literal),
			acceptedVersions);
	}	

	// Last full authentication time should be made zero when EAP configurations are modified.
	// This makes sure that the next authentication with this EAP would be full authentication
	// instead of reauthentication even if the session is still valid.
	
	TPtrC lastFullAuthTimeString;

	switch (iUiConn->GetEapType())
	{
	case eap_type_tls:
		{
			lastFullAuthTimeString.Set(KTLSLastFullAuthTime);
		}
		break;

	case eap_type_peap:
		{
			lastFullAuthTimeString.Set(KPEAPLastFullAuthTime);
		}
		break;

	case eap_type_ttls:
		{
			lastFullAuthTimeString.Set(KTTLSLastFullAuthTime);
		}
		break;

#ifdef USE_FAST_EAP_TYPE	
	case eap_type_fast:
		{
			lastFullAuthTimeString.Set(KFASTLastFullAuthTime);
		}
		break;
#endif		

	case eap_type_ttls_plain_pap:
		{
			lastFullAuthTimeString.Set( KTTLSPAPLastFullAuthTime );
		}
		break;

	default:
		{
			// Should never happen. Don't return error here as this is just to reset the auth time only.
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("Session Validity: EAP-Type=%d - ERROR: Unknown EAP type!\n"),
				iUiConn->GetEapType() ));
		}
	}
	
	iView.SetColL(
		iColSet->ColNo(lastFullAuthTimeString),
		default_FullAuthTime);

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("Session Validity: EAP-Type=%d, Resetting Full Auth Time since settings are modified\n"),
		iUiConn->GetEapType() ));
	

	// Update TLS Privacy
    if (*(iDataPtr->GetTlsPrivacy()))
    	{
    	iView.SetColL(
    	iColSet->ColNo(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal),
        ETLSPEAPTLSPrivacyYes);
        }
        else
        {
        iView.SetColL(
        iColSet->ColNo(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal),
        ETLSPEAPTLSPrivacyNo);
        }
	
	

	
	/************** only for TTLS PAP **************/
	
	if( iUiConn->GetEapType() == eap_type_ttls_plain_pap )
		{
        // PAP user name
        iView.SetColL( iColSet->ColNo( cf_str_EAP_TLS_PEAP_ttls_pap_username_literal ),
        	iDataPtr->GetPapUserName() );
        // PAP password
        iView.SetColL( iColSet->ColNo( cf_str_EAP_TLS_PEAP_ttls_pap_password_literal ),
        	iDataPtr->GetPapPassword() );
        // PAP password prompt
        if ( *( iDataPtr->GetPapPasswordPrompt() ) )
            {
            iView.SetColL( iColSet->ColNo( cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal ),
            	EPapPasswordPromptOn );
            }
        else
            {
            iView.SetColL( iColSet->ColNo( cf_str_EAP_TLS_PEAP_ttls_pap_password_prompt_literal ),
            	EPapPasswordPromptOff );
            }
    
		} // if( iUiConn->GetEapType() == eap_type_ttls_plain_pap )

	
	
	// Now put all the updated values in DB table.
	iView.PutL();	

#ifdef USE_FAST_EAP_TYPE

	if(iUiConn->GetEapType() == eap_type_fast)
	{
		// Make the view ready for updation. This is important!
	    iFastSpecificView.UpdateL();
   	
		// Update Authentication modes
	    if (*(iDataPtr->GetAuthProvModeAllowed()))
        {
            iFastSpecificView.SetColL(
            	iFastSpecificColSet->ColNo(cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal),
            	EFASTAuthProvModeAllowedYes);
        }
        else
        {
            iFastSpecificView.SetColL(
            	iFastSpecificColSet->ColNo(cf_str_EAP_FAST_allow_server_authenticated_provisioning_mode_literal),
            	EFASTAuthProvModeAllowedNo);
        }
	    
	    if (*(iDataPtr->GetUnauthProvModeAllowed()))
        {
            iFastSpecificView.SetColL(
            	iFastSpecificColSet->ColNo(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal),
            	EFASTUnauthProvModeAllowedYes);
        }
        else
        {
            iFastSpecificView.SetColL(
            	iFastSpecificColSet->ColNo(cf_str_EAP_FAST_allow_server_unauthenticated_provisioning_mode_ADHP_literal),
            	EFASTUnauthProvModeAllowedNo);
        }
	    
	   	// Now put all the updated values in DB table.
		iFastSpecificView.PutL();	    
	
	    
#ifdef USE_PAC_STORE
	    
		// Update PAC store password.
	    // PAC store password should be stored in a different database, pac store db.
	    // We can use the UI connection to save the PAC store password.

		EAP_TRACE_DATA_DEBUG_SYMBIAN(
		("CEapTlsPeapUiDataConnection::UpdateDataL: PW from UI(16 bits)",
		iDataPtr->GetPacStorePassword().Ptr(), 
		iDataPtr->GetPacStorePassword().Size()));
		
		TBuf8<KMaxPasswordLengthInDB> tmpSetPacStorePw8;
		tmpSetPacStorePw8.Copy(iDataPtr->GetPacStorePassword());		
		
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
		("CEapTlsPeapUiDataConnection::UpdateDataL: PW to PAC store DB(8 bits)",
		tmpSetPacStorePw8.Ptr(), 
		tmpSetPacStorePw8.Size()));

	    iUiConn->GetPacStoreDb()->SetPacStoreDataL(
	    	cf_str_EAP_FAST_PAC_store_password_literal(),
	    	tmpSetPacStorePw8);	    
			    
/*****************TEST*************/
	    
#ifdef   PAC_STORE_DATA_HACK

		TBuf<4> tmpSetPacStoreData1;
		TBuf<4> tmpSetPacStoreData2;
		TBuf<4> tmpSetPacStoreData3;
		TBuf<4> tmpSetPacStoreData4;
		TBuf<4> tmpSetPacStoreData5;
		TBuf<4> tmpSetPacStoreData6;
		RArray<SInfoEntry> infoarray1;
		RArray<SInfoEntry> infoarray2;

		tmpSetPacStoreData1.Copy(iDataPtr->GetUsePAC_Store_Group_Reference());		
		tmpSetPacStoreData2.Copy(iDataPtr->GetUsePAC_Store_Group_Value());		
		tmpSetPacStoreData3.Copy(iDataPtr->GetUsePAC_Store_AID_Reference());		
		tmpSetPacStoreData4.Copy(iDataPtr->GetUsePAC_Store_AID_Value());		
		tmpSetPacStoreData6.Copy(iDataPtr->GetUsePAC_Store_PAC_Reference());		
		tmpSetPacStoreData6.Copy(iDataPtr->GetUsePAC_Store_PAC_Value());		
		
			EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::UpdateDataL: tmpSetPacStoreData=%S\n"),
					&tmpSetPacStorePw));

	    iUiConn->GetPacStoreDb()->SetPacStoreDataL(
	    		KPacStoreGroupReference,
	    		tmpSetPacStoreData1,
	    		KPacStoreGroupReference);	    
	    iUiConn->GetPacStoreDb()->SetPacStoreDataL(
	    		KPacStoreGroupValue,
	    		tmpSetPacStoreData2,
	    		KPacStoreGroupReference);	    
	    iUiConn->GetPacStoreDb()->SetPacStoreDataL(
	    		KPacStoreAIDReference,
	    		tmpSetPacStoreData3,
	    		KPacStoreAIDReference);	    
	    iUiConn->GetPacStoreDb()->SetPacStoreDataL(
	    		KPacStoreAIDValue,
	    		tmpSetPacStoreData4,
	    		KPacStoreAIDReference);	    
	    iUiConn->GetPacStoreDb()->SetPacStoreDataL(
	    		KPacStorePACReference,
	    		tmpSetPacStoreData5,
	    		KPacStorePACValue);	    
	    iUiConn->GetPacStoreDb()->SetPacStoreDataL(
	    		KPacStorePACValue,
	    		tmpSetPacStoreData6,
	    		KPacStorePACReference);	    
		
#endif
	    
		/*****************TEST*************/	    
	    
#endif // End: #ifdef USE_PAC_STORE	    
	    
	} // End: if(iUiConn->GetEapType() == eap_type_fast)    
    
#endif // End: #ifdef USE_FAST_EAP_TYPE

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::UpdateDataL: End\n")));    

} // CEapTlsPeapUiDataConnection::UpdateDataL()

// End of file
