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
* %version: 21 %
*/

#ifndef _EAPTLSPEAPUICONNECTION_H_
#define _EAPTLSPEAPUICONNECTION_H_

#include <e32std.h>
#include <e32base.h>
#include <d32dbms.h>
//#include <EapType.h>
#include <EapTypeDefinitions.h>
#include <EapExpandedType.h>

class CEapTlsPeapUiDataConnection;
class CEapTlsPeapUiCipherSuites;
class CEapTlsPeapUiCertificates;
class CEapTlsPeapUiEapTypes;
class MEapTlsPeapUiCertificates;
class CEapFastPacStore;

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
        const TEapExpandedType aTunnelingType,
        const TEapExpandedType aEapType);

    ~CEapTlsPeapUiConnection();

    TInt Connect();

    TInt Close();

    CEapTlsPeapUiDataConnection * GetDataConnection();

	CEapTlsPeapUiCipherSuites * GetCipherSuiteConnection();
	
	CEapTlsPeapUiCertificates * GetCertificateConnection(MEapTlsPeapUiCertificates * const aParent);
	
	CEapTlsPeapUiEapTypes * GetEapTypeConnection();

    TIndexType GetIndexType();

    TInt GetIndex();

	// Returns the Tunneling EAP type of this EAP type.
    TEapExpandedType GetTunnelingType();

	// Returns the EAP type.
    TEapExpandedType GetEapType();

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
	
    void GetPacStorePasswordL(
		TDes8 & aPassword8);

    void SetPacStorePasswordL(
		const TDesC8 & aPassword8);

protected:

    // Bearer type
	TIndexType iIndexType;
	
	// Unique index
	TInt iIndex;

	// This stores the Vendor-Type of Tunneling EAP type. Supported Vendor-ID here is 0x 0 (3 bytes).
	TEapExpandedType iTunnelingType;

	// This stores the Vendor-Type of the EAP type. Supported Vendor-ID here is 0x 0 (3 bytes).
	TEapExpandedType iEapType;
	
    // database names, handlers etc...

    CEapTlsPeapUiDataConnection * iDataConn;

	CEapTlsPeapUiCipherSuites * iCipherSuites;
		
	CEapTlsPeapUiEapTypes * iEapTypes;
	
	CEapTlsPeapUiCertificates * iCertificates;	
	
private:
	
    void ConnectL();
    
private:
	
	CEapFastPacStore * iPacStoreDb;
};

#endif

// End of file
