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
* %version: 35 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 428 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

//#include "EapTlsPeapUtils.h"
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiDataConnection.h>
#include <EapTlsPeapUiCipherSuites.h>
#include <EapTlsPeapUiEapTypes.h>
#include <EapTlsPeapUiCertificates.h>
#include <AbsEapTlsPeapUiCertificates.h>
#include "EapTraceSymbian.h"

#ifdef USE_PAC_STORE
#include "EapFastPacStore.h"
#endif

// ----------------------------------------------------------

CEapTlsPeapUiConnection::CEapTlsPeapUiConnection(
    const TIndexType aIndexType,
    const TInt aIndex,
    const TEapExpandedType aTunnelingType,
	const TEapExpandedType aEapType)
    : iIndexType(aIndexType)
    , iIndex(aIndex)
    , iTunnelingType(aTunnelingType)
    , iEapType(aEapType)
    , iDataConn(NULL)
    , iCipherSuites(NULL)
    , iEapTypes(NULL)
    , iCertificates(NULL)
    , iPacStoreDb(NULL)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::CEapTlsPeapUiConnection()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::CEapTlsPeapUiConnection()\n"));

}

// ----------------------------------------------------------

CEapTlsPeapUiConnection::~CEapTlsPeapUiConnection()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::~CEapTlsPeapUiConnection()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::~CEapTlsPeapUiConnection()\n"));

#ifdef USE_PAC_STORE
	delete iPacStoreDb;
#endif
}

// ----------------------------------------------------------

TInt CEapTlsPeapUiConnection::Connect()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::Connect()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::Connect()\n"));

	TRAPD(err, ConnectL());
	if(err == KErrNone)
	{
	}
	
	return err;
}

// ----------------------------------------------------------

void CEapTlsPeapUiConnection::ConnectL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::ConnectL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::ConnectL()\n"));

#ifdef USE_PAC_STORE
#ifdef USE_FAST_EAP_TYPE
	
	if(iEapType == *EapExpandedTypeFast.GetType() && iPacStoreDb == NULL)
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiConnection::ConnectL() CEapFastPacStore::NewL()")));	
		iPacStoreDb = CEapFastPacStore::NewL();
		User::LeaveIfNull(iPacStoreDb);
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiConnection::Connect Created PAC store")));	
		
		iPacStoreDb->OpenPacStoreL();

		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiConnection::Connect Opened PAC store")));	

		iPacStoreDb->CreateDeviceSeedL();

		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiConnection::Connect Created device seed")));	
	}
	
#endif	// End: #ifdef USE_FAST_EAP_TYPE
#endif // End: 	#ifdef USE_PAC_STORE

}

// ----------------------------------------------------------

TInt CEapTlsPeapUiConnection::Close()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::Close()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::Close()\n"));

#ifdef USE_PAC_STORE    	

#ifdef USE_FAST_EAP_TYPE
	
	if(iEapType == *EapExpandedTypeFast.GetType()
		&& iPacStoreDb != NULL)
	{
		delete iPacStoreDb;
		iPacStoreDb = NULL;
	}

#endif	// End: #ifdef USE_FAST_EAP_TYPE		
	
#endif	// End: #ifdef USE_PAC_STORE
    
    return KErrNone;
}

// ----------------------------------------------------------

CEapTlsPeapUiDataConnection * CEapTlsPeapUiConnection::GetDataConnection()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::GetDataConnection()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::GetDataConnection()\n"));

    if (!iDataConn)
    {
        iDataConn = new CEapTlsPeapUiDataConnection(this);
    }

    return iDataConn;
}

// ----------------------------------------------------------

CEapTlsPeapUiCipherSuites * CEapTlsPeapUiConnection::GetCipherSuiteConnection()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::GetCipherSuiteConnection()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::GetCipherSuiteConnection()\n"));

    if (!iCipherSuites)
    {
        iCipherSuites = new CEapTlsPeapUiCipherSuites(this);
    }

    return iCipherSuites;
}
	
// ----------------------------------------------------------

CEapTlsPeapUiCertificates * CEapTlsPeapUiConnection::GetCertificateConnection(MEapTlsPeapUiCertificates * const aParent)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::GetCertificateConnection()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::GetCertificateConnection()\n"));

    if (!iCertificates)
    {
        iCertificates = new CEapTlsPeapUiCertificates(this, aParent);
    }

    return iCertificates;
}
	
// ----------------------------------------------------------


CEapTlsPeapUiEapTypes * CEapTlsPeapUiConnection::GetEapTypeConnection()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::GetEapTypeConnection()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::GetEapTypeConnection()\n"));

    if (!iEapTypes)
    {
        iEapTypes = new CEapTlsPeapUiEapTypes(this);
    }

    return iEapTypes;
}
	
// ----------------------------------------------------------

TIndexType CEapTlsPeapUiConnection::GetIndexType()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::GetIndexType()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::GetIndexType()\n"));

    return iIndexType;
}

// ----------------------------------------------------------

TInt CEapTlsPeapUiConnection::GetIndex()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::GetIndex()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::GetIndex()\n"));

    return iIndex;
}

// ----------------------------------------------------------

TEapExpandedType CEapTlsPeapUiConnection::GetTunnelingType()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::GetTunnelingType()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::GetTunnelingType()\n"));

    return iTunnelingType;
}

// ----------------------------------------------------------

TEapExpandedType CEapTlsPeapUiConnection::GetEapType()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::GetEapType()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::GetEapType()\n"));

    return iEapType;
}

// ----------------------------------------------------------

TBool CEapTlsPeapUiConnection::IsPacStoreMasterKeyPresentL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::IsPacStoreMasterKeyPresentL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::IsPacStoreMasterKeyPresentL()\n"));

	TBool status(EFalse);
		
#ifdef USE_FAST_EAP_TYPE	
	
	if(iEapType == *EapExpandedTypeFast.GetType())
	{
	    if (iPacStoreDb == 0)
	    {
	        User::Leave(KErrSessionClosed);
	    }
	    
	    status = iPacStoreDb->IsMasterKeyPresentL();
		
		if (status)
		{
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeapUiConnection::IsPacStoreMasterKeyPresentL Master key present! \n")));				
		}
		
		return status;
	}
	else
#endif	// End: #ifdef USE_FAST_EAP_TYPE		
	{
		User::Leave(KErrNotSupported);
	}
	
	return status;
}

// ----------------------------------------------------------

TInt CEapTlsPeapUiConnection::DestroyPacStore()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::DestroyPacStore()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::DestroyPacStore()\n"));

#ifdef USE_FAST_EAP_TYPE
	
	if(iEapType == *EapExpandedTypeFast.GetType())
	{
	    if (iPacStoreDb == 0)
	    {
	        return KErrSessionClosed;
	    }
	    
	    TInt error = iPacStoreDb->DestroyPacStore();	    

	    return error;
	}
	else
#endif	// End: #ifdef USE_FAST_EAP_TYPE		
	{
		return KErrNotSupported;
	}	
}
	
// ----------------------------------------------------------

TBool CEapTlsPeapUiConnection::VerifyPacStorePasswordL(
	const TDesC& aPacStorePw)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::VerifyPacStorePasswordL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::VerifyPacStorePasswordL()\n"));

	if(aPacStorePw.Length() <= 0)	
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("ERROR: CEapTlsPeapUiConnection::VerifyPacStorePasswordL(): PAC store PW can not be EMPTY!")));				
		
		User::Leave(KErrArgument);
	}
	
	TBool status(EFalse);
		
#ifdef USE_FAST_EAP_TYPE	
	
	if(iEapType == *EapExpandedTypeFast.GetType())
	{
	    if (iPacStoreDb == 0)
	    {
	        User::Leave(KErrSessionClosed);
	    }
	    
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
		("CEapTlsPeapUiConnection::VerifyPacStorePasswordL(): PW from caller (16bits)",
		aPacStorePw.Ptr(), 
		aPacStorePw.Size()));
		
		HBufC8* pacStorePWBuf8 = HBufC8::NewLC(aPacStorePw.Size());
		TPtr8 pacStorePWPtr8 = pacStorePWBuf8->Des();
		pacStorePWPtr8.Copy(aPacStorePw);
	    
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
		("CEapTlsPeapUiConnection::VerifyPacStorePasswordL(): PW used for masterkey verification (8bits)",
		pacStorePWPtr8.Ptr(), 
		pacStorePWPtr8.Size()));	    
	    
	    status = iPacStoreDb->IsMasterKeyAndPasswordMatchingL(pacStorePWPtr8);
	    
	    CleanupStack::PopAndDestroy(pacStorePWBuf8);
		
		if (status)
		{
			// Password and master key are matching.
			// Means, This is the password used to create the master key.
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeapUiConnection::VerifyPacStorePasswordL(): PAC store PW verified OK (true) \n")));				
		}
	}
	else
#endif	// End: #ifdef USE_FAST_EAP_TYPE		
	{
		User::Leave(KErrNotSupported);
	}
	
	return status;
}

// ----------------------------------------------------------

TInt CEapTlsPeapUiConnection::CreatePacStoreMasterKey(
	const TDesC& aPacStorePw)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::CreatePacStoreMasterKey()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::CreatePacStoreMasterKey()\n"));

	if(aPacStorePw.Length() <= 0)	
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("ERROR: CEapTlsPeapUiConnection::CreatePacStoreMasterKey(): PAC store PW can not be EMPTY!")));				
		
		return KErrArgument;
	}
		
#ifdef USE_FAST_EAP_TYPE	
	
	if(iEapType == *EapExpandedTypeFast.GetType())
	{
	    if (iPacStoreDb == 0)
	    {
	        return KErrSessionClosed;
	    }
	    
		TInt creationStatus(KErrNone);
	  	  
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
			("CEapTlsPeapUiConnection::CreatePacStoreMasterKey(): PW from caller (16bits)",
			aPacStorePw.Ptr(), 
			aPacStorePw.Size()));
		
		HBufC8* pacStorePWBuf8 = NULL;
		TRAPD(err, pacStorePWBuf8 = HBufC8::NewL(aPacStorePw.Size()));
		if (err != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeapUiConnection::CreatePacStoreMasterKey(): Allocation failed\n")));
			return KErrNoMemory;
		}
		
		TPtr8 pacStorePWPtr8 = pacStorePWBuf8->Des();
		pacStorePWPtr8.Copy(aPacStorePw);
	    
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
			("CEapTlsPeapUiConnection::CreatePacStoreMasterKey(): PW used for masterkey creation (8bits)",
			pacStorePWPtr8.Ptr(), 
			pacStorePWPtr8.Size()));
		
		TRAPD(error, creationStatus = iPacStoreDb->CreateAndSaveMasterKeyL(pacStorePWPtr8));
	    
		delete pacStorePWBuf8;
		
		if(error != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeapUiConnection::CreatePacStoreMasterKey(): Creation failed %d\n"), error));
		}
				
		if (creationStatus == KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeapUiConnection::CreatePacStoreMasterKey(): Master key created OK\n")));				
		}
		return creationStatus;
	}
	else
#endif	// End: #ifdef USE_FAST_EAP_TYPE		
	{
		return KErrNotSupported;
	}
}

// ----------------------------------------------------------

void CEapTlsPeapUiConnection::GetPacStorePasswordL(
	TDes8 & /* aPassword8 */)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::GetPacStorePasswordL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::GetPacStorePasswordL()\n"));

#ifdef USE_FAST_EAP_TYPE	
	if(iEapType == *EapExpandedTypeFast.GetType())
	{
		//iPacStoreDb->GetPacStorePasswordL(aPassword8);
	}
	else
#endif	// End: #ifdef USE_FAST_EAP_TYPE		
	{
		User::Leave(KErrNotSupported);
	}
}

// ----------------------------------------------------------

void CEapTlsPeapUiConnection::SetPacStorePasswordL(
	const TDesC8 & aPassword8)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiConnection::SetPacStorePasswordL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiConnection::SetPacStorePasswordL()\n"));

	if(aPassword8.Length() <= 0)	
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("ERROR: CEapTlsPeapUiConnection::SetPacStorePasswordL(): PAC store PW can not be EMPTY!")));				
		return;
		//User::Leave(KErrArgument);
	}

#ifdef USE_FAST_EAP_TYPE	
	if(iEapType == *EapExpandedTypeFast.GetType())
	{
		iPacStoreDb->SetPacStorePasswordL(aPassword8);
	}
	else
#endif	// End: #ifdef USE_FAST_EAP_TYPE		
	{
		User::Leave(KErrNotSupported);
	}
}


// ----------------------------------------------------------
// End of file
