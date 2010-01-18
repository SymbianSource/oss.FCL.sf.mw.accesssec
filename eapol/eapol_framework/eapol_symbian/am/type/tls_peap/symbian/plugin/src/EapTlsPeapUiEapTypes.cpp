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
* %version: 16 %
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
#include "EapTlsPeapUtils.h"
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiEapTypes.h>
#include <EapTlsPeapUiEapType.h>
#include "eap_am_trace_symbian.h"

const TUint KNumberOfSupportedEAPTypes = 10; //Now 10, including EAP-FAST & TTLS-PAP

CEapTlsPeapUiEapTypes::CEapTlsPeapUiEapTypes(CEapTlsPeapUiConnection * const aUiConn)
: iIsOpened(EFalse)
, iUiConn(aUiConn)
, iDataPtr(NULL)
{
}


CEapTlsPeapUiEapTypes::~CEapTlsPeapUiEapTypes()
{
    if (iUiConn)
    {
        Close();
        iUiConn = NULL;
    }
}


TInt CEapTlsPeapUiEapTypes::Open()
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


TInt CEapTlsPeapUiEapTypes::GetEapTypes(CArrayFixFlat<TEapTlsPeapUiEapType> ** aDataPtr)
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
    iDataPtr = new CArrayFixFlat<TEapTlsPeapUiEapType>(KNumberOfSupportedEAPTypes);
    if (!iDataPtr)
    {
        return KErrNoMemory;
    }

#ifdef USE_EAP_EXPANDED_TYPES

    TRAPD(err, FetchExpandedDataL());

#else

    TRAPD(err, FetchDataL());

#endif //#ifdef USE_EAP_EXPANDED_TYPES
        
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

#ifdef USE_EAP_EXPANDED_TYPES

	TRAPD(err, UpdateExpandedDataL());

#else

	TRAPD(err, UpdateL());

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	return err;
}

#ifndef USE_EAP_EXPANDED_TYPES

void CEapTlsPeapUiEapTypes::UpdateL()
{
	TEapArray eapTypes;
	TEap* eapTmp; 	
	
	TInt i(0);
	
	for(i = 0; i < iDataPtr->Count(); i++)
	{
		eapTmp = new (ELeave) TEap;
		CleanupStack::PushL(eapTmp);
		eapTmp->Enabled	= iDataPtr->At(i).iIsEnabled;
		eapTmp->UID.Copy(iDataPtr->At(i).iEapType);
		User::LeaveIfError(eapTypes.Append(eapTmp));
		CleanupStack::Pop(eapTmp);
	}	

	TRAPD(err, EapTlsPeapUtils::SetEapDataL(
			iDatabase, 
			0, 
			eapTypes, 
			iUiConn->GetIndexType(),
			iUiConn->GetIndex(),
			static_cast<eap_type_value_e>(iUiConn->GetTunnelingType()),
			static_cast<eap_type_value_e>(iUiConn->GetEapType())));

	eapTypes.ResetAndDestroy();	
	if (err != KErrNone)
	{
		User::Leave(err);
	}
}
#endif // #ifndef USE_EAP_EXPANDED_TYPES


TInt CEapTlsPeapUiEapTypes::Close()
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

#ifndef USE_EAP_EXPANDED_TYPES

void CEapTlsPeapUiEapTypes::FetchDataL()
{		
	TEapArray eapTypes;
	
	TRAPD(err, EapTlsPeapUtils::GetEapDataL(
			iDatabase, 
			0, 
			eapTypes, 
			iUiConn->GetIndexType(), 
			iUiConn->GetIndex(), 
			static_cast<eap_type_value_e>(iUiConn->GetTunnelingType()),
			static_cast<eap_type_value_e>(iUiConn->GetEapType())));

	if (err != KErrNone)
	{
		eapTypes.ResetAndDestroy();
		User::Leave(err);
	}
	
	TInt i(0);
	for	(i = 0; i < eapTypes.Count(); i++)	
	{
		TEapTlsPeapUiEapType tmp;

		tmp.iIsEnabled = eapTypes[i]->Enabled;
		
		tmp.iEapType.Copy(eapTypes[i]->UID);
		
		TRAPD(err, iDataPtr->AppendL(tmp));
		if (err != KErrNone)
		{
			eapTypes.ResetAndDestroy();
			User::Leave(err);
		}
	}
	eapTypes.ResetAndDestroy();	
}
#endif // #ifndef USE_EAP_EXPANDED_TYPES

#ifdef USE_EAP_EXPANDED_TYPES

void CEapTlsPeapUiEapTypes::FetchExpandedDataL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiEapTypes::FetchExpandedDataL: Start\n")));

	RExpandedEapTypePtrArray enabledEAPTypes;
	RExpandedEapTypePtrArray disabledEAPTypes;

	eap_type_value_e tunnelingType(static_cast<eap_type_ietf_values_e>(iUiConn->GetTunnelingType()));
	eap_type_value_e eapType(static_cast<eap_type_ietf_values_e>(iUiConn->GetEapType()));

	TRAPD(err, EapTlsPeapUtils::GetTunnelingExpandedEapDataL(
			iDatabase, 
			0, 
			enabledEAPTypes,
			disabledEAPTypes, 
			iUiConn->GetIndexType(), 
			iUiConn->GetIndex(), 
			tunnelingType,
			eapType));

	if (err != KErrNone)
	{
		enabledEAPTypes.ResetAndDestroy();
		disabledEAPTypes.ResetAndDestroy();
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiEapTypes::FetchExpandedDataL: Error from GetTunnelingExpandedEapDataL:%d\n"),
			err));		
		
		User::Leave(err);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("CEapTlsPeapUiEapTypes::FetchExpandedDataL: Got tunneling EAPs from DB: enabled=%d,disabled=%d\n"),
		enabledEAPTypes.Count(), disabledEAPTypes.Count()));		
	
	TInt i(0);
	
	// First fill the enabled EAP types.	
	for	(i = 0; i < enabledEAPTypes.Count(); i++)	
	{
		TEapTlsPeapUiEapType tmpEAP;

		tmpEAP.iIsEnabled = ETrue; // All EAP types here are enabled.
		
		tmpEAP.iEapType.Copy(enabledEAPTypes[i]->iExpandedEAPType);
		
		TRAPD(err, iDataPtr->AppendL(tmpEAP));
		if (err != KErrNone)
		{
			enabledEAPTypes.ResetAndDestroy();
			User::Leave(err);
		}
		
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeapUiEapTypes::FetchExpandedDataL:Appended ENABLED EAP type:",
			tmpEAP.iEapType.Ptr(), 
			tmpEAP.iEapType.Size() ) );		
	}

	// Now fill the disabled EAP types.	
	for	(i = 0; i < disabledEAPTypes.Count(); i++)	
	{
		TEapTlsPeapUiEapType tmpEAP;

		tmpEAP.iIsEnabled = EFalse; // All EAP types here are disabled.
		
		tmpEAP.iEapType.Copy(disabledEAPTypes[i]->iExpandedEAPType);
		
		TRAPD(err, iDataPtr->AppendL(tmpEAP));
		if (err != KErrNone)
		{
			disabledEAPTypes.ResetAndDestroy();
			User::Leave(err);
		}
		
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeapUiEapTypes::FetchExpandedDataL:Appended DISABLED EAP type:",
			tmpEAP.iEapType.Ptr(), 
			tmpEAP.iEapType.Size() ) );		
	}
	
	enabledEAPTypes.ResetAndDestroy();		
	disabledEAPTypes.ResetAndDestroy();
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiEapTypes::FetchExpandedDataL: End\n")));	
}

void CEapTlsPeapUiEapTypes::UpdateExpandedDataL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiEapTypes::UpdateExpandedDataL: Start\n")));

	RExpandedEapTypePtrArray enabledEAPTypes;
	RExpandedEapTypePtrArray disabledEAPTypes;
	SExpandedEAPType* expandedEAPTmp;
	
	for(TInt i=0 ; i < iDataPtr->Count(); i++)
	{
		expandedEAPTmp = new (ELeave) SExpandedEAPType;
		CleanupStack::PushL(expandedEAPTmp);
		
		expandedEAPTmp->iExpandedEAPType.Copy(iDataPtr->At(i).iEapType);
		
		if(iDataPtr->At(i).iIsEnabled)
		{
			// Enabled
			TInt error = enabledEAPTypes.Append(expandedEAPTmp);

			if (error != KErrNone)
			{
				enabledEAPTypes.ResetAndDestroy();
				disabledEAPTypes.ResetAndDestroy();
				User::LeaveIfError(error);
			}
		
			EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeapUiEapTypes::UpdateExpandedDataL:Appended ENABLED EAP type:",
				expandedEAPTmp->iExpandedEAPType.Ptr(), 
				expandedEAPTmp->iExpandedEAPType.Size() ) );
		}
		else
		{
			// Disabled
			TInt error = disabledEAPTypes.Append(expandedEAPTmp);

			if (error != KErrNone)
			{
				enabledEAPTypes.ResetAndDestroy();
				disabledEAPTypes.ResetAndDestroy();
				User::LeaveIfError(error);
			}

			EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTlsPeapUiEapTypes::UpdateExpandedDataL:Appended DISABLED EAP type:",
				expandedEAPTmp->iExpandedEAPType.Ptr(), 
				expandedEAPTmp->iExpandedEAPType.Size() ) );
		}
		
		CleanupStack::Pop(expandedEAPTmp);	
	}	

	eap_type_value_e tunnelingType(static_cast<eap_type_ietf_values_e>(iUiConn->GetTunnelingType()));
	eap_type_value_e eapType(static_cast<eap_type_ietf_values_e>(iUiConn->GetEapType()));

	TRAPD(err, EapTlsPeapUtils::SetTunnelingExpandedEapDataL(
			iDatabase, 
			0, 
			enabledEAPTypes,
			disabledEAPTypes, 
			iUiConn->GetIndexType(),
			iUiConn->GetIndex(),
			tunnelingType,
			eapType));

	enabledEAPTypes.ResetAndDestroy();
	disabledEAPTypes.ResetAndDestroy();
		
	if (err != KErrNone)
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiEapTypes::UpdateExpandedDataL: Error from SetTunnelingExpandedEapDataL:%d\n"),
			err));		
	
		User::Leave(err);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiEapTypes::UpdateExpandedDataL: End\n")));	
}
    
#endif // #ifdef USE_EAP_EXPANDED_TYPES

// End of file
