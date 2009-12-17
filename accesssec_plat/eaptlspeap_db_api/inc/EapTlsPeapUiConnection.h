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


#ifndef _EAPTLSPEAPUICONNECTION_H_
#define _EAPTLSPEAPUICONNECTION_H_

#include <e32std.h>
#include <e32base.h>
#include <d32dbms.h>
#include <EapType.h>

class CEapTlsPeapUiDataConnection;
class CEapTlsPeapUiCipherSuites;
class CEapTlsPeapUiCertificates;
class CEapTlsPeapUiEapTypes;
class MEapTlsPeapUiCertificates;
class CPacStoreDatabase;

class CEapTlsPeapUiConnection : public CBase
{

public:

	// This creates a connection between EAP plugin and the EAP UI.
	// aTunnelingType - the Vendor-Type of Tunneling EAP type.
	// aEapType - the Vendor-Type of the EAP type 
	// Supported Vendor-ID here is 0x 0 (3 bytes) for both.

    CEapTlsPeapUiConnection(
        const TIndexType aIndexType,
        const TInt aIndex,
        const TInt aTunnelingType,
        const TInt aEapType);

    ~CEapTlsPeapUiConnection();

    TInt Connect();

    TInt Close();

    CEapTlsPeapUiDataConnection * GetDataConnection();

	CEapTlsPeapUiCipherSuites * GetCipherSuiteConnection();
	
	CEapTlsPeapUiCertificates * GetCertificateConnection(MEapTlsPeapUiCertificates * const aParent);
	
	CEapTlsPeapUiEapTypes * GetEapTypeConnection();

    TIndexType GetIndexType();

    TInt GetIndex();

	// Returns the Vendor-Type of Tunneling EAP type, in this EAP type.
	// Supported Vendor-ID here is 0x 0 (3 bytes).
    TInt GetTunnelingType();

	// Returns the Vendor-Type of this EAP type.
	// Supported Vendor-ID here is 0x 0 (3 bytes).
    TInt GetEapType();

    TInt GetDatabase(RDbNamedDatabase & aDatabase);
    
    // Check if there's the PAC store master key.
    // Call Connect() before doing this and Close() after.	
    // Returns ETrue if there is master key. EFalse if there is not.
	TBool IsPacStoreMasterKeyPresentL();

    // This destroys the PAC store if it is created already.
    // Call Connect() before doing this and Close() after.
    // Returns KErrNone if successful. Symbian error code otherwise.
	TInt DestroyPacStore();
	
    // This check if the PAC store (or PAC store master key) can be decrypted 
	// with the password provided.
    // Call Connect() before doing this and Close() after.	
    // Returns ETrue if successful.
	TBool VerifyPacStorePasswordL(const TDesC& aPacStorePw);
	
    // This creates the PAC store master key with the password provided.
    // Call Connect() before doing this and Close() after.	
    // Returns KErrNone if successful. Symbian error code otherwise.
	TInt CreatePacStoreMasterKey(const TDesC& aPacStorePw);
	
	CPacStoreDatabase * GetPacStoreDb();
	
protected:

    // Bearer type
	TIndexType iIndexType;
	
	// Unique index
	TInt iIndex;

	// This stores the Vendor-Type of Tunneling EAP type. Supported Vendor-ID here is 0x 0 (3 bytes).
	TInt iTunnelingType;

	// This stores the Vendor-Type of the EAP type. Supported Vendor-ID here is 0x 0 (3 bytes).
	TInt iEapType;
	
    TBool iIsConnected;

    // database names, handlers etc...

    CEapTlsPeapUiDataConnection * iDataConn;

	CEapTlsPeapUiCipherSuites * iCipherSuites;
		
	CEapTlsPeapUiEapTypes * iEapTypes;
	
	CEapTlsPeapUiCertificates * iCertificates;	
	
    RDbNamedDatabase iDbNamedDatabase;

    RDbs iDbs;
    
private:
	
    void ConnectL();
    
private:
	
	CPacStoreDatabase * iPacStoreDb;
	
};

#endif

// End of file
