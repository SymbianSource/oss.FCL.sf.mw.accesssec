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
* %version: 24.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 428 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "EapTlsPeapUtils.h"
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiDataConnection.h>
#include <EapTlsPeapUiCipherSuites.h>
#include <EapTlsPeapUiEapTypes.h>
#include <EapTlsPeapUiCertificates.h>
#include <AbsEapTlsPeapUiCertificates.h>
#include "eap_am_trace_symbian.h"

#ifdef USE_PAC_STORE
#include "pac_store_db_symbian.h"
#endif

CEapTlsPeapUiConnection::CEapTlsPeapUiConnection(
    const TIndexType aIndexType,
    const TInt aIndex,
    const TInt aTunnelingType,
	const TInt aEapType)
    : iIndexType(aIndexType)
    , iIndex(aIndex)
    , iTunnelingType(aTunnelingType)
    , iEapType(aEapType)
    , iIsConnected(EFalse)
    , iDataConn(NULL)
    , iCipherSuites(NULL)
    , iEapTypes(NULL)
    , iCertificates(NULL)
    , iPacStoreDb(NULL)
{
}


CEapTlsPeapUiConnection::~CEapTlsPeapUiConnection()
{
#ifdef USE_PAC_STORE
	delete iPacStoreDb;
#endif
}

TInt CEapTlsPeapUiConnection::Connect()
{
	if(iIsConnected)
	{
		// Already connected.
		return KErrNone;
	}
	
	TRAPD(err, ConnectL());
	if(err == KErrNone)
	{
		iIsConnected = ETrue;
	}
	
	return err;
}

void CEapTlsPeapUiConnection::ConnectL()
{
#ifdef USE_EAP_EXPANDED_TYPES

	eap_type_value_e tunnelingType(static_cast<eap_type_ietf_values_e>(iTunnelingType));
	eap_type_value_e eapType(static_cast<eap_type_ietf_values_e>(iEapType));

#else

	eap_type_value_e tunnelingType = static_cast<eap_type_value_e>(iTunnelingType);
	eap_type_value_e eapType = static_cast<eap_type_value_e>(iEapType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

#ifdef USE_PAC_STORE
#ifdef USE_FAST_EAP_TYPE
	
	if(iEapType == eap_type_fast && iPacStoreDb == NULL)
	{
		iPacStoreDb = CPacStoreDatabase::NewL();
		User::LeaveIfNull(iPacStoreDb);
		
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiConnection::Connect Created PAC store")));	
		
		iPacStoreDb->OpenPacStoreL();
		iPacStoreDb->CreateDeviceSeed( NULL );
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiConnection::Connect Opened PAC store")));	
	}
	
#endif	// End: #ifdef USE_FAST_EAP_TYPE
#endif // End: 	#ifdef USE_PAC_STORE

	// Open or create the databse where all the settings are stored.
	EapTlsPeapUtils::OpenDatabaseL(
		iDbNamedDatabase, 
		iDbs, 
		iIndexType,
		iIndex, 
		tunnelingType, 
		eapType);
}


TInt CEapTlsPeapUiConnection::Close()
{
    if (iIsConnected)
    {    	

#ifdef USE_PAC_STORE    	

#ifdef USE_FAST_EAP_TYPE
	
		if(iEapType == eap_type_fast && iPacStoreDb != NULL)
		{
			iPacStoreDb->Close();
		}
#endif	// End: #ifdef USE_FAST_EAP_TYPE		
	
#endif	// End: #ifdef USE_PAC_STORE
	
        iDbNamedDatabase.Close();
        
        iDbs.Close(); // Both the Dbs are closed and server can be closed now.
    }
    
    iIsConnected = EFalse;

    return KErrNone;
}


CEapTlsPeapUiDataConnection * CEapTlsPeapUiConnection::GetDataConnection()
{
    if (!iDataConn)
    {
        iDataConn = new CEapTlsPeapUiDataConnection(this);
    }

    return iDataConn;
}


CEapTlsPeapUiCipherSuites * CEapTlsPeapUiConnection::GetCipherSuiteConnection()
{
    if (!iCipherSuites)
    {
        iCipherSuites = new CEapTlsPeapUiCipherSuites(this);
    }

    return iCipherSuites;
}
	
	
CEapTlsPeapUiCertificates * CEapTlsPeapUiConnection::GetCertificateConnection(MEapTlsPeapUiCertificates * const aParent)
{
    if (!iCertificates)
    {
        iCertificates = new CEapTlsPeapUiCertificates(this, aParent);
    }

    return iCertificates;
}
	
	
CEapTlsPeapUiEapTypes * CEapTlsPeapUiConnection::GetEapTypeConnection()
{
    if (!iEapTypes)
    {
        iEapTypes = new CEapTlsPeapUiEapTypes(this);
    }

    return iEapTypes;
}
	
	
TInt CEapTlsPeapUiConnection::GetDatabase(RDbNamedDatabase & aDatabase)
{
    if (iIsConnected == EFalse)
    {
        return KErrSessionClosed;
    }

    aDatabase = iDbNamedDatabase;
    return KErrNone;
}


TIndexType CEapTlsPeapUiConnection::GetIndexType()
{
    return iIndexType;
}


TInt CEapTlsPeapUiConnection::GetIndex()
{
    return iIndex;
}

TInt CEapTlsPeapUiConnection::GetTunnelingType()
{
    return iTunnelingType;
}

TInt CEapTlsPeapUiConnection::GetEapType()
{
    return iEapType;
}


TBool CEapTlsPeapUiConnection::IsPacStoreMasterKeyPresentL()
{
	TBool status(EFalse);
		
#ifdef USE_FAST_EAP_TYPE	
	
	if(iEapType == eap_type_fast)
	{
	    if (iIsConnected == EFalse)
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

TInt CEapTlsPeapUiConnection::DestroyPacStore()
{
#ifdef USE_FAST_EAP_TYPE
	
	if(iEapType == eap_type_fast)
	{
	    if (iIsConnected == EFalse)
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
	
TBool CEapTlsPeapUiConnection::VerifyPacStorePasswordL(
	const TDesC& aPacStorePw)
{
	if(aPacStorePw.Size() <= 0)	
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiConnection::VerifyPacStorePasswordL: PAC store PW can not be EMPTY!")));				
		
		User::Leave(KErrArgument);
	}
	
	TBool status(EFalse);
		
#ifdef USE_FAST_EAP_TYPE	
	
	if(iEapType == eap_type_fast)
	{
	    if (iIsConnected == EFalse)
	    {
	        User::Leave(KErrSessionClosed);
	    }
	    
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
		("CEapTlsPeapUiConnection::VerifyPacStorePasswordL:PW from caller (16bits)",
		aPacStorePw.Ptr(), 
		aPacStorePw.Size()));
		
		HBufC8* pacStorePWBuf8 = HBufC8::NewLC(aPacStorePw.Size());
		TPtr8 pacStorePWPtr8 = pacStorePWBuf8->Des();
		pacStorePWPtr8.Copy(aPacStorePw);
	    
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
		("CEapTlsPeapUiConnection::VerifyPacStorePasswordL:PW used for masterkey verification (8bits)",
		pacStorePWPtr8.Ptr(), 
		pacStorePWPtr8.Size()));	    
	    
	    status = iPacStoreDb->IsMasterKeyAndPasswordMatchingL(pacStorePWPtr8);
	    
	    CleanupStack::PopAndDestroy(pacStorePWBuf8);
		
		if (status)
		{
			// Password and master key are matching.
			// Means, This is the password used to create the master key.
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeapUiConnection::VerifyPacStorePasswordL PAC store PW verified OK (true) \n")));				
		}
	}
	else
#endif	// End: #ifdef USE_FAST_EAP_TYPE		
	{
		User::Leave(KErrNotSupported);
	}
	
	return status;
}

TInt CEapTlsPeapUiConnection::CreatePacStoreMasterKey(
	const TDesC& aPacStorePw)
{
	if(aPacStorePw.Size() <= 0)	
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("CEapTlsPeapUiConnection::CreatePacStoreMasterKey PAC store PW can not be EMPTY!")));				
		
		return KErrArgument;
	}
		
#ifdef USE_FAST_EAP_TYPE	
	
	if(iEapType == eap_type_fast)
	{
	    if (iIsConnected == EFalse)
	    {
	        return KErrSessionClosed;
	    }
	    
	  TInt creationStatus(KErrNone);
	  	  
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
		("CEapTlsPeapUiConnection::CreatePacStoreMasterKey:PW from caller (16bits)",
		aPacStorePw.Ptr(), 
		aPacStorePw.Size()));
		
		HBufC8* pacStorePWBuf8 = NULL;
		TRAPD(err, pacStorePWBuf8 = HBufC8::NewL(aPacStorePw.Size()));
		if (err != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeapUiConnection::CreatePacStoreMasterKey:Allocation failed\n")));
			return KErrNoMemory;
		}
		
		TPtr8 pacStorePWPtr8 = pacStorePWBuf8->Des();
		pacStorePWPtr8.Copy(aPacStorePw);
	    
		EAP_TRACE_DATA_DEBUG_SYMBIAN(
		("CEapTlsPeapUiConnection::CreatePacStoreMasterKey:PW used for masterkey creation (8bits)",
		pacStorePWPtr8.Ptr(), 
		pacStorePWPtr8.Size()));
		
		TRAPD(err1, creationStatus = iPacStoreDb->CreateAndSaveMasterKeyL(pacStorePWPtr8));
	    
		delete pacStorePWBuf8;
		
		if(err1 != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeapUiConnection::CreatePacStoreMasterKey:Creation failed %d\n"), err1));
		}
				
		if (creationStatus == KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN(
				(_L("CEapTlsPeapUiConnection::CreatePacStoreMasterKey Master key created OK\n")));				
		}
		return creationStatus;
	}
	else
#endif	// End: #ifdef USE_FAST_EAP_TYPE		
	{
		return KErrNotSupported;
	}
}

CPacStoreDatabase * CEapTlsPeapUiConnection::GetPacStoreDb()
{
#ifdef USE_FAST_EAP_TYPE
	
	if(iEapType == eap_type_fast)
	{
	    return iPacStoreDb;
	}
	else
#endif	// End: #ifdef USE_FAST_EAP_TYPE		
	{
		return NULL;
	}	
}

// End of file
