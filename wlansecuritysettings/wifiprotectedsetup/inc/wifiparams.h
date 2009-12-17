/*
* Copyright (c) 2001-2009 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: Declares the common used constants and types for Wi-Fi Protected Setup. 
*
*/


#ifndef T_WIFIPARAMS_H
#define T_WIFIPARAMS_H

#include <e32base.h>
#include <wlanmgmtcommon.h>
#include <wifiprotreturn.h>

namespace WiFiProt
    {
    struct TWiFiInputParams
        {
        // ssid of the network we want to configure        
        TWlanSsid iSSid;
        // a flag to indicate that a connection is needed
        // when setup is complete
        TBool iConnectionNeeded;
        // constructor to initialise input parameters data
        inline TWiFiInputParams( const TDesC8& aInitBuf,
                                 const TBool aConnectionNeeded );
        };
        
    const TInt KMaxNumberOfUids = 30; //to be specified    
    
    struct TWiFiOutputParams
        {
        // returned iapids of the configured connection methods
        TBuf8<KMaxNumberOfUids*sizeof(TUint32)> iIapIds;
        // return value, see TWiFiReturn
        TWiFiReturn iReturn;
        // constructor to initialise output parameters data
        inline TWiFiOutputParams( const TDesC8& aInitBuf );
        };
        
    struct TWiFiConnOutputParams
        {
        // returned iapids of the configured connection methods
        TWlanProtectedSetupCredentialAttribute iNetworkSettings;
        // return value, see TWiFiReturn
        TWiFiReturn iReturn;
        // constructor to initialise output parameters data
        inline TWiFiConnOutputParams(
            const TWlanProtectedSetupCredentialAttribute& aNetworkSettings );
        // default constructor            
        inline TWiFiConnOutputParams( );
        };        
    }
#include "wifiparams.inl"    
#endif  // T_WIFIPARAMS_H


// End of File
