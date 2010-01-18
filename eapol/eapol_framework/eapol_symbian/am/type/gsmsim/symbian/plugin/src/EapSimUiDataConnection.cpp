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
* %version: 14.1.3.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 215 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include <e32base.h>
#include "EapSimDbUtils.h"
#include "EapSimDbParameterNames.h"
#include "EapSimDbDefaults.h"
#include <EapSimUiConnection.h>
#include <EapSimUiDataConnection.h>
#include <EapSimUiSimData.h>
#include "eap_am_trace_symbian.h"

const TUint KMaxSqlQueryLength = 256;

CEapSimUiDataConnection::CEapSimUiDataConnection(CEapSimUiConnection * aUiConn)
: iIsOpened(EFalse)
, iUiConn(aUiConn)
, iColSet(NULL)
, iDataPtr(NULL)
{
}


CEapSimUiDataConnection::~CEapSimUiDataConnection()
{
    if (iUiConn)
    {
        Close();
        iUiConn = NULL;
    }
}


TInt CEapSimUiDataConnection::Open()
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


TInt CEapSimUiDataConnection::GetData(CEapSimUiSimData ** aDataPtr)
{
    if (aDataPtr == NULL)
    {
        return KErrArgument;
    }
    if (iIsOpened == EFalse)
    {
        return KErrSessionClosed;
    }
    iDataPtr = new CEapSimUiSimData();
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


TInt CEapSimUiDataConnection::Update()
{
    TRAPD(err, iView.UpdateL());
    if (err != KErrNone)
    {
        return err;
    }
    
	// Check if length of username and realm are less than the max length possible in DB.
	if(iDataPtr->GetManualUsername().Length() > KMaxManualUsernameLengthInDB
		|| iDataPtr->GetManualRealm().Length() > KMaxManualRealmLengthInDB)
	{
		// Username or realm too long. Can not be stored in DB.
		EAP_TRACE_DEBUG_SYMBIAN((_L("CEapSimUiDataConnection::Update: Too long username or realm. Length: UN=%d, Realm=%d\n"),
			iDataPtr->GetManualUsername().Length(),
			iDataPtr->GetManualRealm().Length()));
		
		return KErrArgument;
	}
    
    TRAP(err, iView.SetColL(iColSet->ColNo(cf_str_EAP_GSMSIM_manual_username_literal), iDataPtr->GetManualUsername()));
    if (err != KErrNone)
    {
        return err;
    }

    TRAP(err, iView.SetColL(iColSet->ColNo(cf_str_EAP_GSMSIM_manual_realm_literal), iDataPtr->GetManualRealm()));
    if (err != KErrNone)
    {
        return err;
    }

    if (*(iDataPtr->GetUseManualUsername()))
    {
        TRAP(err, iView.SetColL(iColSet->ColNo(cf_str_EAP_GSMSIM_use_manual_username_literal), EGSMSIMUseManualUsernameYes));
		if (err != KErrNone)
		{
			return err;
		}
    }
    else
    {
        TRAP(err, iView.SetColL(iColSet->ColNo(cf_str_EAP_GSMSIM_use_manual_username_literal), EGSMSIMUseManualUsernameNo));
		if (err != KErrNone)
		{
			return err;
		}
    }

    if (*(iDataPtr->GetUseManualRealm()))
    {
        TRAP(err, iView.SetColL(iColSet->ColNo(cf_str_EAP_GSMSIM_use_manual_realm_literal), EGSMSIMUseManualRealmYes));
		if (err != KErrNone)
		{
			return err;
		}
    }
    else
    {
        TRAP(err, iView.SetColL(iColSet->ColNo(cf_str_EAP_GSMSIM_use_manual_realm_literal), EGSMSIMUseManualRealmNo));
		if (err != KErrNone)
		{
			return err;
		}
    }

	// Last full authentication time should be made zero when EAP configurations are modified.
	// This makes sure that the next authentication with this EAP would be full authentication
	// instead of reauthentication even if the session is still valid.
	
	TRAP(err, iView.SetColL(iColSet->ColNo(KGSMSIMLastFullAuthTime), default_FullAuthTime));
	if (err != KErrNone)
	{
		return err;
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("Session Validity: Resetting Full Auth Time since EAP-SIM settings are modified\n")));

    TRAP(err, iView.PutL());
        
    return err;
}


TInt CEapSimUiDataConnection::Close()
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


void CEapSimUiDataConnection::FetchDataL()
{
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Form the query. Query everything.
	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLQuery,
						&KSimTableName,
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

	// use manual username
	TUint intValue = iView.ColUint(iColSet->ColNo(cf_str_EAP_GSMSIM_use_manual_username_literal));
    if (intValue == 0)
    {
        *(iDataPtr->GetUseManualUsername()) = EFalse;
    }
    else
    {
        *(iDataPtr->GetUseManualUsername()) = ETrue;
    }

	// use manual realm
	intValue = iView.ColUint(iColSet->ColNo(cf_str_EAP_GSMSIM_use_manual_realm_literal));
    if (intValue == 0)
    {
        *(iDataPtr->GetUseManualRealm()) = EFalse;
    }
    else
    {
        *(iDataPtr->GetUseManualRealm()) = ETrue;
    }

    // manual username
    iDataPtr->GetManualUsername().Copy(iView.ColDes16(iColSet->ColNo(cf_str_EAP_GSMSIM_manual_username_literal)));

	// manual realm
	iDataPtr->GetManualRealm().Copy(iView.ColDes16(iColSet->ColNo(cf_str_EAP_GSMSIM_manual_realm_literal)));

    CleanupStack::PopAndDestroy(buf);
}

// End of file
