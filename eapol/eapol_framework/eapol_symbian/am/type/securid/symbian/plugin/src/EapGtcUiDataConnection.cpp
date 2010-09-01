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
* %version: 14.1.2.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 341 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include <e32base.h>
#include "EapGtcDbUtils.h"
#include "EapSecurIDDbParameterNames.h"
#include "EapGtcDbParameterNames.h"
#include "EapGtcDbDefaults.h"
#include <EapGtcUiConnection.h>
#include <EapGtcUiDataConnection.h>
#include <EapGtcUiGtcData.h>
#include "eap_am_trace_symbian.h"

const TUint KMaxSqlQueryLength = 256;


CEapGtcUiDataConnection::CEapGtcUiDataConnection(CEapGtcUiConnection * aUiConn)
: iIsOpened(EFalse)
, iUiConn(aUiConn)
, iColSet(NULL)
, iDataPtr(NULL)
{
}


CEapGtcUiDataConnection::~CEapGtcUiDataConnection()
{
    if (iUiConn)
    {
        Close();
        iUiConn = NULL;
    }
}


TInt CEapGtcUiDataConnection::Open()
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


TInt CEapGtcUiDataConnection::GetData(CEapGtcUiGtcData ** aDataPtr)
{
    if (aDataPtr == NULL)
    {
        return KErrArgument;
    }
    if (iIsOpened == EFalse)
    {
        return KErrSessionClosed;
    }
    iDataPtr = new CEapGtcUiGtcData();
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


TInt CEapGtcUiDataConnection::Update()
{
    TRAPD(err, iView.UpdateL());
    if (err != KErrNone)
    {
        return err;
    }
    
	// Validate the length of username/identity.
	if(iDataPtr->GetIdentity().Length() > KMaxIdentityLengthInDB)
	{
		// Username or identity too long. Can not be stored in DB.
		EAP_TRACE_DEBUG_SYMBIAN((_L("CEapGtcUiDataConnection::Update: Too long username/identity. length =%d\n"),
			iDataPtr->GetIdentity().Length()));
		
		return KErrArgument;
	}
    
	TRAP(err, iView.SetColL(iColSet->ColNo(cf_str_EAP_GTC_identity_literal), iDataPtr->GetIdentity()));
    if (err != KErrNone)
    {
        return err;
    }

	// Last full authentication time should be made zero when EAP configurations are modified.
	// This makes sure that the next authentication with this EAP would be full authentication
	// instead of reauthentication even if the session is still valid.
	
	TRAP(err, iView.SetColL(iColSet->ColNo(KGTCLastFullAuthTime), default_FullAuthTime));
    if (err != KErrNone)
    {
        return err;
    }

	EAP_TRACE_DEBUG_SYMBIAN((_L("Session Validity: Resetting Full Auth Time since EAP-GTC settings are modified\n")));

    TRAP(err, iView.PutL());
        
    return err;
}


TInt CEapGtcUiDataConnection::Close()
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


void CEapGtcUiDataConnection::FetchDataL()
{
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Form the query. Query everything.
	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(KSQLQuery,
						&KGtcTableName,
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

	// identity
    iDataPtr->GetIdentity().Copy(iView.ColDes16(iColSet->ColNo(cf_str_EAP_GTC_identity_literal)));

    CleanupStack::PopAndDestroy(buf);
}

// End of File
