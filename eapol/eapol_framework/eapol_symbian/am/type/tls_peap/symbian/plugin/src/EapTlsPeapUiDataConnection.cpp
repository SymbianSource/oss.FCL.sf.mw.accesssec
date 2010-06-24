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
	#define EAP_FILE_NUMBER_ENUM 430 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include <e32base.h>
//#include "EapTlsPeapUtils.h"
#include "EapTlsPeapDbParameterNames.h"
#include "EapTlsPeapDbDefaults.h"
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiDataConnection.h>
#include <EapTlsPeapUiTlsPeapData.h>
#include <EapTraceSymbian.h>
#include <EapType.h>

#ifdef USE_PAC_STORE
#include "pac_store_db_symbian.h"
#endif

//const TUint KMaxSqlQueryLength = 256;

// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::CEapTlsPeapUiDataConnection()
// ---------------------------------------------------------
// 
CEapTlsPeapUiDataConnection::CEapTlsPeapUiDataConnection(CEapTlsPeapUiConnection * aUiConn)
: iIsOpened(EFalse)
, iUiConn(aUiConn)
, iDataPtr(NULL)
, iFastSpecificColSet(NULL)
, iEapTypeConnection(NULL)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::CEapTlsPeapUiDataConnection()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiDataConnection::CEapTlsPeapUiDataConnection()\n"));
}


// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::~CEapTlsPeapUiDataConnection()
// ---------------------------------------------------------
// 
CEapTlsPeapUiDataConnection::~CEapTlsPeapUiDataConnection()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::~CEapTlsPeapUiDataConnection()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiDataConnection::~CEapTlsPeapUiDataConnection()\n"));

    if (iUiConn)
    {
        Close();
        iUiConn = NULL;
    }

	delete iEapTypeConnection;
	iEapTypeConnection = 0;
}


// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::Open()
// ---------------------------------------------------------
// 
TInt CEapTlsPeapUiDataConnection::Open()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::Open(): Start EAP-Type=0xfe%06x%08x\n"),
		iUiConn->GetEapType().GetVendorId(),
		iUiConn->GetEapType().GetVendorType()));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiDataConnection::Open()\n"));

    if (iIsOpened)
    {
        return KErrAlreadyExists;
    }

	TEapExpandedType aEapType(iUiConn->GetEapType());

    TRAPD(error, iEapTypeConnection = CEapType::NewL(iUiConn->GetIndexType(), iUiConn->GetIndex(), aEapType));
    if (error != KErrNone)
        {
        EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapLeapUiDataConnection::Open() CEapType::NewL() error=%d\n"),error));
        return error;
        }
    
    iEapTypeConnection->SetTunnelingType(iUiConn->GetTunnelingType());
    
    iIsOpened = ETrue;

    return KErrNone;
}


// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::GetData()
// ---------------------------------------------------------
// 
TInt CEapTlsPeapUiDataConnection::GetData(CEapTlsPeapUiTlsPeapData ** aDataPtr)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::GetData(): Start EAP-Type=0xfe%06x%08x\n"),
		iUiConn->GetEapType().GetVendorId(),
		iUiConn->GetEapType().GetVendorType()));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiDataConnection::GetData()\n"));

    if (aDataPtr == NULL)
    {
        return KErrArgument;
    }
    
    if (iIsOpened == EFalse)
    {
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("ERROR: CEapTlsPeapUiDataConnection::GetData(): Data Connection not opened\n")));
    
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
			(_L("ERROR: CEapTlsPeapUiDataConnection::GetData(): NO MEMORY!\n")));
		
        return KErrNoMemory;
    }

    EAPSettings aSettings;
    
	TRAPD(error,iEapTypeConnection->GetConfigurationL(aSettings));
	if (error)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiDataConnection::GetData() GetConfigurationL(): failed %d\n"), error));
		return error;
	}

	/**************** only for TTLS PAP ****************/

	if ( iUiConn->GetEapType() == *EapExpandedTypeTtlsPap.GetType() )
	{
		if (aSettings.iShowPassWordPromptPresent)
		{
			if (aSettings.iShowPassWordPrompt)
			{
				*( iDataPtr->GetPapPasswordPrompt() ) = ETrue;
			}
			else
			{
				*( iDataPtr->GetPapPasswordPrompt() ) = EFalse;
			}
		}

		if (aSettings.iUsernamePresent)
		{
			iDataPtr->GetPapUserName().Copy(aSettings.iUsername);
		}

		if (aSettings.iPasswordPresent)
		{
			iDataPtr->GetPapPassword().Copy(aSettings.iPassword);
		}

		return KErrNone;
	}

	// Get use manual username
	if (aSettings.iUsernamePresent)
	{
	    *(iDataPtr->GetUseManualUsername()) = ETrue;
		iDataPtr->GetManualUsername().Copy(aSettings.iUsername);
	}
	else
	{
		*(iDataPtr->GetUseManualUsername()) = EFalse;
	}

	// Get use manual realm
	if (aSettings.iRealmPresent)
	{
	    *(iDataPtr->GetUseManualRealm()) = ETrue;
		iDataPtr->GetManualRealm().Copy(aSettings.iRealm);
	}
	else
	{
		*(iDataPtr->GetUseManualRealm()) = EFalse;
	}

	// Get PEAP/TTLS versions
	if (iUiConn->GetEapType() == *EapExpandedTypePeap.GetType()
		|| iUiConn->GetEapType() == *EapExpandedTypeTtls.GetType()
#ifdef USE_FAST_EAP_TYPE
		|| iUiConn->GetEapType() == *EapExpandedTypeFast.GetType()
#endif
		)
	{
		if (aSettings.iPEAPVersionsPresent)
		{
			if (aSettings.iPEAPv0Allowed)
			{
				*(iDataPtr->GetAllowVersion0()) = ETrue;
			}

			if (aSettings.iPEAPv1Allowed)
			{
				*(iDataPtr->GetAllowVersion1()) = ETrue;
			}

			if (aSettings.iPEAPv2Allowed)
			{
				*(iDataPtr->GetAllowVersion2()) = ETrue;
			}
		}
	}

	if (aSettings.iUseIdentityPrivacyPresent)
	{
		if (aSettings.iUseIdentityPrivacy)
		{
			*(iDataPtr->GetTlsPrivacy()) = ETrue;
		}
		else
		{
			*(iDataPtr->GetTlsPrivacy()) = EFalse;
		}
	}

#ifdef USE_FAST_EAP_TYPE
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("Fetching EAP-FAST specific Special settings!\n")));

	if(iUiConn->GetEapType() == *EapExpandedTypeFast.GetType())
	{
		// Get provisioning modes
		if (aSettings.iAuthProvModeAllowedPresent)
		{
			if (aSettings.iAuthProvModeAllowed)
			{
				*(iDataPtr->GetAuthProvModeAllowed()) = ETrue;
			}
			else
			{
				*(iDataPtr->GetAuthProvModeAllowed()) = EFalse;
			}
		}

		if (aSettings.iUnauthProvModeAllowedPresent)
		{
			if (aSettings.iUnauthProvModeAllowed)
			{
				*(iDataPtr->GetUnauthProvModeAllowed()) = ETrue;
			}
			else
			{
				*(iDataPtr->GetUnauthProvModeAllowed()) = EFalse;
			}
		}

		if (aSettings.iShowPassWordPromptPresent)
		{
			if (aSettings.iShowPassWordPrompt)
			{
				*( iDataPtr->GetUsePacStorePasswordPrompt() ) = ETrue;
			}
			else
			{
				*( iDataPtr->GetUsePacStorePasswordPrompt() ) = EFalse;
			}
		}

#ifdef USE_PAC_STORE

		{
			// Get PAC store Password
			// PAC store password is in a different database, pac store db.
			// We can use the PacStoreDbUtils to get the PAC store password.
			
			TBuf8<KMaxPasswordLengthInDB> tmpPacStorePw8;

			TRAPD(err, iUiConn->GetPacStorePasswordL(tmpPacStorePw8));
			if (err)
				{
				EAP_TRACE_DEBUG_SYMBIAN((_L("couldn't get GetPacStorePasswordL!\n")));
				}	    	
			
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
		}

#endif // End: #ifdef USE_PAC_STORE

	} // End: if(iUiConn->GetEapType() == *EapExpandedTypeFast.GetType())

#endif // End: #ifdef USE_FAST_EAP_TYPE	

    *aDataPtr = iDataPtr;

    return KErrNone;
} // CEapTlsPeapUiDataConnection::GetData()


// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::Update()
// ---------------------------------------------------------
// 
TInt CEapTlsPeapUiDataConnection::Update()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::Update(): Start EAP-Type=0xfe%06x%08x\n"),
		iUiConn->GetEapType().GetVendorId(),
		iUiConn->GetEapType().GetVendorType()));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiDataConnection::Update()\n"));
    
    // Do the length checks first.
	// Check if length of username and realm are less than the max length possible in DB.
	if(iDataPtr->GetManualUsername().Length() > KMaxUsernameLengthInDB
		|| iDataPtr->GetManualRealm().Length() > KMaxRealmLengthInDB)
	{
		// Username or realm too long. Can not be stored in DB.
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("ERROR: CEapTlsPeapUiDataConnection::Update(): Too long username or realm. Length: UN=%d, Realm=%d\n"),
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
			(_L("ERROR: CEapTlsPeapUiDataConnection::Update(): Too long PAC store PW. Size:%d\n"),
			iDataPtr->GetPacStorePassword().Size()));
		
		return KErrOverflow;
	}

#endif 

	EAPSettings aSettings;

	if( iUiConn->GetEapType() == *EapExpandedTypeTtlsPap.GetType() )
	{
		/************** only for TTLS PAP **************/

		aSettings.iShowPassWordPromptPresent = ETrue;

		if (*(iDataPtr->GetPapPasswordPrompt()))
		{
			aSettings.iShowPassWordPrompt = ETrue;
		}
		else
		{
			aSettings.iShowPassWordPrompt = EFalse;
		}

		aSettings.iUsernamePresent = ETrue;
		aSettings.iUsername.Copy(iDataPtr->GetPapUserName());

		aSettings.iPasswordPresent = ETrue;
		aSettings.iPassword.Copy(iDataPtr->GetPapPassword());

	} // if( iUiConn->GetEapType() == *EapExpandedTypeTtlsPap.GetType() )
	else
	{
		if (*(iDataPtr->GetUseManualUsername()))
		{
			aSettings.iUsernamePresent = ETrue;
			aSettings.iUsername = iDataPtr->GetManualUsername();
		}
		else
		{
			aSettings.iUsernamePresent = EFalse;
		}
	}

    if (*(iDataPtr->GetUseManualRealm()))
    {
		aSettings.iRealmPresent = ETrue;
		aSettings.iRealm = iDataPtr->GetManualRealm();
    }
    else
    {
		aSettings.iRealmPresent = EFalse;
    }
	
	// PEAP/TTLS versions
	if (iUiConn->GetEapType() == *EapExpandedTypePeap.GetType()
		|| iUiConn->GetEapType() == *EapExpandedTypeTtls.GetType()
#ifdef USE_FAST_EAP_TYPE	
		|| iUiConn->GetEapType() == *EapExpandedTypeFast.GetType()
#endif		
		)
	{
		if (*(iDataPtr->GetAllowVersion0()))
		{
			aSettings.iPEAPv0Allowed = ETrue;
		}

		if (*(iDataPtr->GetAllowVersion1()))
		{
			aSettings.iPEAPv1Allowed = ETrue;
		}

		if (*(iDataPtr->GetAllowVersion2()))
		{
			aSettings.iPEAPv2Allowed = ETrue;
		}
	}	


	// Update TLS Privacy
	aSettings.iUseIdentityPrivacyPresent = ETrue;

	if (*(iDataPtr->GetTlsPrivacy()))
	{
		aSettings.iUseIdentityPrivacy = ETrue;
	}
	else
	{
		aSettings.iUseIdentityPrivacy = EFalse;
	}


#ifdef USE_FAST_EAP_TYPE

	if(iUiConn->GetEapType() == *EapExpandedTypeFast.GetType())
	{
		// Update Authentication modes
		aSettings.iAuthProvModeAllowedPresent = ETrue;

		if (*(iDataPtr->GetAuthProvModeAllowed()))
		{
			aSettings.iAuthProvModeAllowed = ETrue;
		}
		else
		{
			aSettings.iAuthProvModeAllowed = EFalse;
		}

		aSettings.iUnauthProvModeAllowedPresent = ETrue;

		if (*(iDataPtr->GetUnauthProvModeAllowed()))
		{
			aSettings.iUnauthProvModeAllowed = ETrue;
		}
		else
		{
			aSettings.iUnauthProvModeAllowed = EFalse;
		}

		if (*(iDataPtr->GetUsePacStorePasswordPrompt()))
		{
			aSettings.iShowPassWordPrompt = ETrue;
		}
		else
		{
			aSettings.iShowPassWordPrompt = EFalse;
		}

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

	  TRAPD(err, iUiConn->SetPacStorePasswordL(tmpSetPacStorePw8));

          if (err)
               return err;
	  	  	    
	  EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::Update(): SetPacStorePassword error = %d\n"),err));
			    
#endif // End: #ifdef USE_PAC_STORE	    
	    
	} // End: if(iUiConn->GetEapType() == *EapExpandedTypeFast.GetType())    
    
#endif // End: #ifdef USE_FAST_EAP_TYPE

	TRAPD(error,iEapTypeConnection->SetConfigurationL(aSettings));

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::Update(): SetConfiguration error = %d\n"),error));

	return error;

} // CEapTlsPeapUiDataConnection::Update()


// ---------------------------------------------------------
// CEapTlsPeapUiDataConnection::Close()
// ---------------------------------------------------------
// 
TInt CEapTlsPeapUiDataConnection::Close()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::Close()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiDataConnection::Close()\n"));

    if (iIsOpened == EFalse)
    {
        return KErrNone;
    }

    delete iDataPtr;
    iDataPtr = NULL;
    
    delete iFastSpecificColSet;
    iFastSpecificColSet = NULL;
    
    iUiConn = NULL;
    
    return KErrNone;
} // CEapTlsPeapUiDataConnection::Close()

// ---------------------------------------------------------
// End of file
