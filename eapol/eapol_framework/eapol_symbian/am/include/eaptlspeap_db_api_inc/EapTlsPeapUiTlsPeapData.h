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
* %version: 18 %
*/

#ifndef _EAPTLSPEAPUITLSPEAPDATA_H_
#define _EAPTLSPEAPUITLSPEAPDATA_H_

#include <e32std.h>
#include <e32base.h>

const TInt KMaxLengthOfUsername=255;
const TInt KMaxLengthOfPassword=255;

const TInt KMaxLengthOfPapUserName = 253; // according to UI spec
const TInt KMaxLengthOfPapPassword = 128; // according to UI spec

class CEapTlsPeapUiTlsPeapData : public CBase
{
public:

    CEapTlsPeapUiTlsPeapData();

    ~CEapTlsPeapUiTlsPeapData();

    TDes& GetManualUsername();

    TBool * GetUseManualUsername();

    TDes& GetManualRealm();

    TBool * GetUseManualRealm();
    
    TBool * GetAllowVersion0();
    
    TBool * GetAllowVersion1();
    
    TBool * GetAllowVersion2();
    
    // New member functions for EAP-FAST 
    
    TBool * GetTlsPrivacy();
    
    TBool * GetAuthProvModeAllowed();

    TBool * GetUnauthProvModeAllowed();
    
    TDes& GetPacStorePassword();
    
    TBool* GetUsePacStorePasswordPrompt();

public: // new, for TTLS PAP
    
    TDes& GetPapUserName();

    TDes& GetPapPassword();

    TBool* GetPapPasswordPrompt();

private:

    TBuf<KMaxLengthOfUsername> iManualUsername;

    TBool iUseManualUsername;

    TBuf<KMaxLengthOfUsername> iManualRealm;

    TBool iUseManualRealm;
    
    TBool iAllowVersion0;
    
    TBool iAllowVersion1;
    
    TBool iAllowVersion2;
    
    // New member variables for EAP-FAST
    TBool iTlsPrivacy;
    
    TBool iAuthProvModeAllowed;

    TBool iUnauthProvModeAllowed;
    
    TBuf<KMaxLengthOfPassword> iPacStorePassword;
    
    TBuf<KMaxLengthOfPapUserName> iPapUserName;

    TBuf<KMaxLengthOfPapPassword> iPapPassword;

    TBool iPapPasswordPrompt;

    TBool iPasswordPrompt;
    
};

#endif

// End of file
