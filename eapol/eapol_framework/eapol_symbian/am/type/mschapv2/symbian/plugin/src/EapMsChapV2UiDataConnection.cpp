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
	#define EAP_FILE_NUMBER_ENUM 300 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include <e32base.h>
#include "EapMsChapV2DbUtils.h"
#include "EapMsChapV2DbParameterNames.h"
#include "EapMsChapV2DbDefaults.h"
#include <EapMsChapV2UiConnection.h>
#include <EapMsChapV2UiDataConnection.h>
#include <EapMsChapV2UiMsChapV2Data.h>
#include "eap_am_trace_symbian.h"

const TUint KMaxSqlQueryLength = 256;


CEapMsChapV2UiDataConnection::CEapMsChapV2UiDataConnection(CEapMsChapV2UiConnection * aUiConn)
: iIsOpened(EFalse)
, iUiConn(aUiConn)
, iColSet(NULL)
, iDataPtr(NULL)
{
}


CEapMsChapV2UiDataConnection::~CEapMsChapV2UiDataConnection()
{
    if (iUiConn)
    {
        Close();
        iUiConn = NULL;
    }
}


TInt CEapMsChapV2UiDataConnection::Open()
{
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
    return KErrNone;
}


TInt CEapMsChapV2UiDataConnection::GetData(CEapMsChapV2UiMsChapV2Data ** aDataPtr)
{
    if (aDataPtr == NULL)
    {
        return KErrArgument;
    }
    if (iIsOpened == EFalse)
    {
        return KErrSessionClosed;
    }
    iDataPtr = new CEapMsChapV2UiMsChapV2Data();
    if (!iDataPtr)
    {
        return KErrNoMemory;
    }

    TRAPD(err, FetchDataL());
    if (err != KErrNone)
    {
        delete iDataPtr;
        iDataPtr = NULL;
        
        delete iColSet;
        iColSet = NULL;
        
        iView.Close();
        
        return err;
    }

    *aDataPtr = iDataPtr;

    return KErrNone;
}


TInt CEapMsChapV2UiDataConnection::Update()
{
    TRAPD(err, iView.UpdateL());
    if (err != KErrNone)
    {
        return err;
    }
    
	// Validate the length of username and password.
	if(iDataPtr->GetUsername().Length() > KMaxUsernameLengthInDB
		|| iDataPtr->GetPassword().Length() > KMaxPasswordLengthInDB)
	{
		// Username or password too long. Can not be stored in DB.
		EAP_TRACE_DEBUG_SYMBIAN((_L("CEapMsChapV2UiDataConnection::Update: Too long username or password. Length: UN=%d, PW=%d\n"),
			iDataPtr->GetUsername().Length(),
			iDataPtr->GetPassword().Length()));
		
		return KErrArgument;
	}
    
    TRAP(err, iView.SetColL(iColSet->ColNo(cf_str_EAP_MSCHAPV2_username_literal), iDataPtr->GetUsername()));
    if (err != KErrNone)
    {
        return err;
    }

    TRAP(err, iView.SetColL(iColSet->ColNo(cf_str_EAP_MSCHAPV2_password_literal), iDataPtr->GetPassword()));
    if (err != KErrNone)
    {
        return err;
    }
    
    if (*(iDataPtr->GetPasswordPrompt()))
    {
        TRAP(err, iView.SetColL(iColSet->ColNo(cf_str_EAP_MSCHAPV2_password_prompt_literal), EMSCHAPV2PasswordPromptOn));
		if (err != KErrNone)
		{
			return err;
		}
    }
    else
    {
        TRAP(err, iView.SetColL(iColSet->ColNo(cf_str_EAP_MSCHAPV2_password_prompt_literal), EMSCHAPV2PasswordPromptOff));
		if (err != KErrNone)
		{
			return err;
		}
    }
    
	// Last full authentication time should be made zero when EAP configurations are modified.
	// This makes sure that the next authentication with this EAP would be full authentication
	// instead of reauthentication even if the session is still valid.
	
	TRAP(err, iView.SetColL(iColSet->ColNo(KMSCHAPv2LastFullAuthTime), default_FullAuthTime));
    if (err != KErrNone)
    {
        return err;
    }

	EAP_TRACE_DEBUG_SYMBIAN((_L("Session Validity: EAP-Type=MSCHAPv2 (or plain), Resetting Full Auth Time since settings are modified\n")));

    TRAP(err, iView.PutL());

    return err;
}


TInt CEapMsChapV2UiDataConnection::Close()
{
    if (iIsOpened == EFalse)
    {
        return KErrNone;
    }

	delete iDataPtr;
	iDataPtr = NULL;
	
	delete iColSet;
	iColSet = NULL;

    iView.Close();

    iUiConn = NULL;
    
    return KErrNone;
}


void CEapMsChapV2UiDataConnection::FetchDataL()
{
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Form the query. Query everything.
	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLQuery,
						&KMsChapV2TableName,
						&KServiceType,
						iUiConn->GetIndexType(),
						&KServiceIndex,
						iUiConn->GetIndex(),
						&KTunnelingType, 
						iUiConn->GetTunnelingType());
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

	// Prompt password
	TUint intValue = iView.ColUint(iColSet->ColNo(cf_str_EAP_MSCHAPV2_password_prompt_literal));
    if (intValue == 0)
    {
        *(iDataPtr->GetPasswordPrompt()) = EFalse;
    }
    else
    {
        *(iDataPtr->GetPasswordPrompt()) = ETrue;
    }

	// username
    iDataPtr->GetUsername().Copy(iView.ColDes16(iColSet->ColNo(cf_str_EAP_MSCHAPV2_username_literal)));

	// password
	iDataPtr->GetPassword().Copy(iView.ColDes16(iColSet->ColNo(cf_str_EAP_MSCHAPV2_password_literal)));

    CleanupStack::PopAndDestroy(buf);
}

// End of file
