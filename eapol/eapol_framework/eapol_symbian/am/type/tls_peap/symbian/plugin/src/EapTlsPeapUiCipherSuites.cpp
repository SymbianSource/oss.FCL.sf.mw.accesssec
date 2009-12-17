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
	#define EAP_FILE_NUMBER_ENUM 426 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES
#include <e32base.h>
#include "EapTlsPeapUtils.h"
#include "EapTlsPeapDbParameterNames.h"
#include "EapTlsPeapDbDefaults.h"
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiCipherSuites.h>
#include <EapTlsPeapUiCipherSuite.h>

const TUint KMaxSqlQueryLength = 256;

CEapTlsPeapUiCipherSuites::CEapTlsPeapUiCipherSuites(CEapTlsPeapUiConnection * const aUiConn)
: iIsOpened(EFalse)
, iUiConn(aUiConn)
, iDataPtr(NULL)
{
}


CEapTlsPeapUiCipherSuites::~CEapTlsPeapUiCipherSuites()
{
    if (iUiConn)
    {
        Close();
        iUiConn = NULL;
    }
}


TInt CEapTlsPeapUiCipherSuites::Open()
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


TInt CEapTlsPeapUiCipherSuites::GetCipherSuites(CArrayFixFlat<TEapTlsPeapUiCipherSuite> ** aDataPtr)
{
    if (aDataPtr == NULL)
    {
        return KErrArgument;
    }
    if (iIsOpened == EFalse)
    {
        return KErrSessionClosed;
    }
    
    if (iDataPtr != 0)
    {
    	*aDataPtr = iDataPtr;
    	return KErrNone;
    }
    iDataPtr = new CArrayFixFlat<TEapTlsPeapUiCipherSuite>(8);
    if (!iDataPtr)
    {
        return KErrNoMemory;
    }
    
    TInt i(0);
	while (available_cipher_suites[i] != 0)
	{		
		TEapTlsPeapUiCipherSuite tmp;
		tmp.iCipherSuite = available_cipher_suites[i];
		tmp.iIsEnabled = EFalse;

		TRAPD(err, iDataPtr->AppendL(tmp));
		if (err != KErrNone)
		{
			return err;
		}

		i++;
	}
		
    

    TRAPD(err, FetchDataL());
    
    if (err != KErrNone)
    {
        delete iDataPtr;
        return err;
    }

   	*aDataPtr = iDataPtr;

    return KErrNone;
}


TInt CEapTlsPeapUiCipherSuites::Update()
{
	TRAPD(err, UpdateL());
	return err;
}

void CEapTlsPeapUiCipherSuites::UpdateL()
{
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Form the query. Query everything.
	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");

	if (iUiConn->GetEapType() == eap_type_tls)
	{
		sqlStatement.Format(KSQLQuery,
							&KTlsAllowedCipherSuitesDatabaseTableName,
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
							&KPeapAllowedCipherSuitesDatabaseTableName,
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
							&KTtlsAllowedCipherSuitesDatabaseTableName,
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
		sqlStatement.Format(KSQLQuery,
							&KFastAllowedCipherSuitesDatabaseTableName,
							&KServiceType,
							iUiConn->GetIndexType(),
							&KServiceIndex,
							iUiConn->GetIndex(),
							&KTunnelingType, 
							iUiConn->GetTunnelingType());
	}
#endif //#ifdef USE_FAST_EAP_TYPE
	
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(iDatabase, TDbQuery(sqlStatement)));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());	

	// Delete old rows
	if (view.FirstL())
	{		
		do {
			view.DeleteL();
		} while (view.NextL() != EFalse);
	}	

	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);
	
	TInt i(0);
	
	for (i = 0; i < iDataPtr->Count(); i++)
	{
		if (iDataPtr->At(i).iIsEnabled)
		{
			view.InsertL();			
			view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(iUiConn->GetIndexType()));
			view.SetColL(colSet->ColNo(KServiceIndex), static_cast<TUint>(iUiConn->GetIndex()));
			view.SetColL(colSet->ColNo(KTunnelingType), static_cast<TUint>(iUiConn->GetTunnelingType()));
			view.SetColL(colSet->ColNo(KCipherSuite), static_cast<TUint>(iDataPtr->At(i).iCipherSuite));
			view.PutL();
		}
	}
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(); // view
	CleanupStack::PopAndDestroy(buf);    
}

TInt CEapTlsPeapUiCipherSuites::Close()
{
    if (iIsOpened == EFalse)
    {
        return KErrNone;
    }

    delete iDataPtr;
    iDataPtr = 0;
    
    iUiConn = NULL;
    return KErrNone;
}


void CEapTlsPeapUiCipherSuites::FetchDataL()
{
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Form the query. Query everything.
	_LIT(KSQLQuery, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");

	if (iUiConn->GetEapType() == eap_type_tls)
	{
		sqlStatement.Format(KSQLQuery,
							&KCipherSuite,
							&KTlsAllowedCipherSuitesDatabaseTableName,
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
							&KCipherSuite,
							&KPeapAllowedCipherSuitesDatabaseTableName,
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
							&KCipherSuite,
							&KTtlsAllowedCipherSuitesDatabaseTableName,
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
		sqlStatement.Format(KSQLQuery,
							&KCipherSuite,
							&KFastAllowedCipherSuitesDatabaseTableName,
							&KServiceType,
							iUiConn->GetIndexType(),
							&KServiceIndex,
							iUiConn->GetIndex(),
							&KTunnelingType, 
							iUiConn->GetTunnelingType());
	}
#endif //#ifdef USE_FAST_EAP_TYPE
	
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(iDatabase, TDbQuery(sqlStatement)));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());	
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	if (view.FirstL())
	{		
		do {
			view.GetL();

			switch (view.ColType(colSet->ColNo(KCipherSuite)))
			{
			case EDbColUint32:
				{
					// Find the corresponding cipher suite in the list
					TInt j(0);
					TUint id = view.ColUint(colSet->ColNo(KCipherSuite));
					for (j = 0; j < iDataPtr->Count(); j++)
					{
						if (iDataPtr->At(j).iCipherSuite == id)
						{
							iDataPtr->At(j).iIsEnabled = ETrue;
							break;
						}
					}
				}
				break;
			default:
				User::Leave(KErrArgument);
			}
		} while (view.NextL() != EFalse);
	}
	
	CleanupStack::PopAndDestroy(colSet);					
	
	CleanupStack::PopAndDestroy(); // view
    CleanupStack::PopAndDestroy(buf);
}

// End of file
