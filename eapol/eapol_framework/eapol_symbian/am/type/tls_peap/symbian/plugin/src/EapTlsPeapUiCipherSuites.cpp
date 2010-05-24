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
* %version: %
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
//#include "EapTlsPeapUtils.h"
#include "EapTlsPeapDbParameterNames.h"
#include "EapTlsPeapDbDefaults.h"
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiCipherSuites.h>
#include <EapTlsPeapUiCipherSuite.h>
#include <EapTraceSymbian.h>
#include <EapType.h>

//const TUint KMaxSqlQueryLength = 256;

CEapTlsPeapUiCipherSuites::CEapTlsPeapUiCipherSuites(CEapTlsPeapUiConnection * const aUiConn)
: iIsOpened(EFalse)
, iUiConn(aUiConn)
, iDataPtr(NULL)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCipherSuites::CEapTlsPeapUiCipherSuites()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCipherSuites::CEapTlsPeapUiCipherSuites()\n"));
}


CEapTlsPeapUiCipherSuites::~CEapTlsPeapUiCipherSuites()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCipherSuites::~CEapTlsPeapUiCipherSuites()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCipherSuites::~CEapTlsPeapUiCipherSuites()\n"));

	if (iUiConn)
    {
        Close();
        iUiConn = NULL;
    }
}


TInt CEapTlsPeapUiCipherSuites::Open()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCipherSuites::Open()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCipherSuites::Open()\n"));

    if (iIsOpened)
    {
        return KErrAlreadyExists;
    }

	TEapExpandedType aEapType(iUiConn->GetEapType());

    TRAPD(err, iEapTypeConnection = CEapType::NewL(iUiConn->GetIndexType(), iUiConn->GetIndex(), aEapType));
    if (err != KErrNone)
        {
        EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCipherSuites::Open() CEapType::NewL err=%d\n"),err));
        return err;
        }
    
    iEapTypeConnection->SetTunnelingType(iUiConn->GetTunnelingType());

    iIsOpened = ETrue;

    return KErrNone;
}


TInt CEapTlsPeapUiCipherSuites::GetCipherSuites(RPointerArray<TEapTlsPeapUiCipherSuite> ** aDataPtr)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCipherSuites::GetCipherSuites()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCipherSuites::GetCipherSuites()\n"));

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

    iDataPtr = new RPointerArray<TEapTlsPeapUiCipherSuite>(8);
    if (!iDataPtr)
    {
        return KErrNoMemory;
    }
    
    TInt i_ind(0);
	while (available_cipher_suites[i_ind] != 0)
	{		
		TEapTlsPeapUiCipherSuite * const tmp = new TEapTlsPeapUiCipherSuite;
		if (tmp == 0)
		{
	        return KErrNoMemory;
		}

		tmp->SetCipherSuite(available_cipher_suites[i_ind]);
		tmp->SetIsEnabled(EFalse);

		TRAPD(err, iDataPtr->AppendL(tmp));
		if (err != KErrNone)
		{
			return err;
		}

		i_ind++;
	}
		
    EAPSettings aSettings;
    
	TRAPD(error,iEapTypeConnection->GetConfigurationL(aSettings));
	if (error)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCipherSuites::GetCipherSuites() GetConfigurationL(): failed %d\n"), error));
		return error;
	}

	if (aSettings.iCipherSuitesPresent)
	{
		TInt i_ind(0);

		for (i_ind = 0; i_ind < aSettings.iCipherSuites.Count(); ++i_ind)
		{
			TUint aCipherSuite = aSettings.iCipherSuites[i_ind];
			TInt j_ind(0);

			for (j_ind = 0; j_ind < iDataPtr->Count(); j_ind++)
			{
				if ((*iDataPtr)[j_ind]->GetCipherSuite() == aCipherSuite)
				{
					(*iDataPtr)[j_ind]->SetIsEnabled(ETrue);
					break;
				}
			}
		}
	}
    
   	*aDataPtr = iDataPtr;

    return KErrNone;
}


TInt CEapTlsPeapUiCipherSuites::Update()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCipherSuites::Update()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCipherSuites::Update()\n"));

	EAPSettings aSettings;

	aSettings.iCipherSuitesPresent = ETrue;

	TInt i_ind(0);
	
	for (i_ind = 0; i_ind < iDataPtr->Count(); i_ind++)
	{
		if ((*iDataPtr)[i_ind]->GetIsEnabled())
		{
			TInt error = aSettings.iCipherSuites.Append((*iDataPtr)[i_ind]->GetCipherSuite());
			if (error != KErrNone)
			{
				return error;
			}
		}
	}

	TRAPD(error,iEapTypeConnection->SetConfigurationL(aSettings));

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiDataConnection::Update(): error = %d\n"),error));

	return error;
}



TInt CEapTlsPeapUiCipherSuites::Close()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCipherSuites::Close()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCipherSuites::Close()\n"));

    if (iIsOpened == EFalse)
    {
        return KErrNone;
    }

    delete iDataPtr;
    iDataPtr = 0;
    
    iUiConn = NULL;
    return KErrNone;
}

// End of file
