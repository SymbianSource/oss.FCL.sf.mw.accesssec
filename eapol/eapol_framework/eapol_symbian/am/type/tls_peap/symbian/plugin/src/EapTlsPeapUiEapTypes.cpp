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
	#define EAP_FILE_NUMBER_ENUM 433 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES
#include <e32base.h>
//#include "EapTlsPeapUtils.h"
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiEapTypes.h>
#include <EapTlsPeapUiEapType.h>
#include <EapTraceSymbian.h>
#include "EapConversion.h"
#include <EapType.h>

const TUint KNumberOfSupportedEAPTypes = 10; //Now 10, including EAP-FAST & TTLS-PAP

CEapTlsPeapUiEapTypes::CEapTlsPeapUiEapTypes(CEapTlsPeapUiConnection * const aUiConn)
: iIsOpened(EFalse)
, iUiConn(aUiConn)
, iDataPtr(NULL)
, iEapTypeConnection(NULL)
{
}


CEapTlsPeapUiEapTypes::~CEapTlsPeapUiEapTypes()
{
    Close();
}


TInt CEapTlsPeapUiEapTypes::Open()
{
    if (iIsOpened)
    {
        return KErrAlreadyExists;
    }

	TEapExpandedType aEapType(iUiConn->GetEapType());

	TRAPD(error, iEapTypeConnection = CEapType::NewL(iUiConn->GetIndexType(), iUiConn->GetIndex(), aEapType));
	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiEapTypes::Open() CEapType::NewL() error=%d\n"),error));
		return error;
	}
    
    iEapTypeConnection->SetTunnelingType(iUiConn->GetTunnelingType());
    
    iIsOpened = ETrue;

    return KErrNone;
}


TInt CEapTlsPeapUiEapTypes::GetEapTypes(RPointerArray<TEapTlsPeapUiEapType> ** aDataPtr)
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

    iDataPtr = new RPointerArray<TEapTlsPeapUiEapType>(KNumberOfSupportedEAPTypes);
    if (!iDataPtr)
    {
        return KErrNoMemory;
    }

    TRAPD(err, FetchExpandedDataL());
    if (err != KErrNone)
    {
        delete iDataPtr;
        return err;
    }

   	*aDataPtr = iDataPtr;

    return KErrNone;
}


TInt CEapTlsPeapUiEapTypes::Update()
{

	TRAPD(err, UpdateExpandedDataL());

	return err;
}

TInt CEapTlsPeapUiEapTypes::Close()
{
    if (iIsOpened == EFalse)
    {
        return KErrNone;
    }
    
    delete iDataPtr;
    iDataPtr = 0;
		
    iUiConn = NULL;

	if (iEapTypeConnection)
	{
		delete iEapTypeConnection;
		iEapTypeConnection = 0;
	}

	iIsOpened = EFalse;

    return KErrNone;
}

void CEapTlsPeapUiEapTypes::FetchExpandedDataL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiEapTypes::FetchExpandedDataL: Start\n")));

    EAPSettings aSettings;
    
	TRAPD(error,iEapTypeConnection->GetConfigurationL(aSettings));
	if (error)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiEapTypes::FetchExpandedDataL(): GetConfigurationL() failed %d\n"), error));
		User::Leave(error);
	}

	TInt i(0);

	{
		TEapExpandedType enabledEAPType(*EapExpandedTypeNone.GetType());

		if (aSettings.iEnabledEncapsulatedEAPExpandedTypesPresent)
		{
			// First fill the enabled EAP types.	
			for	(i = 0; i < aSettings.iEnabledEncapsulatedEAPExpandedTypes.Count(); i++)	
			{
				TEapTlsPeapUiEapType * tmpEAP = new (ELeave) TEapTlsPeapUiEapType;
				if (tmpEAP == 0)
				{
					User::Leave(KErrNoMemory);
				}

				tmpEAP->SetIsEnabled(ETrue); // All EAP types here are enabled.
				
				tmpEAP->SetEapType(aSettings.iEnabledEncapsulatedEAPExpandedTypes[i]);
				
				TRAPD(err, iDataPtr->AppendL(tmpEAP));
				if (err != KErrNone)
				{
					User::Leave(err);
				}
				
				EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeapUiEapTypes::FetchExpandedDataL(): Appended ENABLED EAP type:",
					tmpEAP->GetEapType().GetValue().Ptr(), 
					tmpEAP->GetEapType().GetValue().Length() ) );		
			}
		}
	}

	{
		TEapExpandedType disabledEAPType(*EapExpandedTypeNone.GetType());

		if (aSettings.iDisabledEncapsulatedEAPExpandedTypesPresent)
		{
			// Now fill the disabled EAP types.	
			for	(i = 0; i < aSettings.iDisabledEncapsulatedEAPExpandedTypes.Count(); i++)	
			{
				TEapTlsPeapUiEapType * tmpEAP = new (ELeave) TEapTlsPeapUiEapType;
				if (tmpEAP == 0)
				{
					User::Leave(KErrNoMemory);
				}

				tmpEAP->SetIsEnabled(EFalse); // All EAP types here are disabled.
				
				tmpEAP->SetEapType(aSettings.iDisabledEncapsulatedEAPExpandedTypes[i]);
				
				TRAPD(err, iDataPtr->AppendL(tmpEAP));
				if (err != KErrNone)
				{
					User::Leave(err);
				}
				
				EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeapUiEapTypes::FetchExpandedDataL(): Appended DISABLED EAP type:",
					tmpEAP->GetEapType().GetValue().Ptr(), 
					tmpEAP->GetEapType().GetValue().Length() ) );		
			}
		}
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiEapTypes::FetchExpandedDataL(): End\n")));	
}

void CEapTlsPeapUiEapTypes::UpdateExpandedDataL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiEapTypes::UpdateExpandedDataL(): Start\n")));

	if (iDataPtr == 0)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiEapTypes::UpdateExpandedDataL(): iDataPtr == 0\n")));
		User::Leave(KErrArgument);
	}

    EAPSettings aSettings;

	for(TInt i=0 ; i < iDataPtr->Count(); i++)
	{
		if ((*iDataPtr)[i] != 0)
		{
			TEapExpandedType expandedEAPTmp = (*iDataPtr)[i]->GetEapType();
			
			if((*iDataPtr)[i]->GetIsEnabled())
			{
				// Enabled
				TInt error = aSettings.iEnabledEncapsulatedEAPExpandedTypes.Append(expandedEAPTmp);

				if (error != KErrNone)
				{
					User::LeaveIfError(error);
				}
			
				aSettings.iEnabledEncapsulatedEAPExpandedTypesPresent = ETrue;

				EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeapUiEapTypes::UpdateExpandedDataL(): Appended ENABLED EAP type:",
					expandedEAPTmp.GetValue().Ptr(), 
					expandedEAPTmp.GetValue().Size() ) );
			}
			else
			{
				// Disabled
				TInt error = aSettings.iDisabledEncapsulatedEAPExpandedTypes.Append(expandedEAPTmp);

				if (error != KErrNone)
				{
					User::LeaveIfError(error);
				}

				aSettings.iDisabledEncapsulatedEAPExpandedTypesPresent = ETrue;

				EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeapUiEapTypes::UpdateExpandedDataL(): Appended DISABLED EAP type:",
					expandedEAPTmp.GetValue().Ptr(), 
					expandedEAPTmp.GetValue().Size() ) );
			}
		}
	} // for()

	TRAPD(error,iEapTypeConnection->SetConfigurationL(aSettings));

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiEapTypes::UpdateExpandedDataL(): error = %d\n"),error));

	User::LeaveIfError(error);
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiEapTypes::UpdateExpandedDataL(): End\n")));	
}

// End of file
