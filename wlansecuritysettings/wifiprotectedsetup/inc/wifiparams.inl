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
* Description: Declares inline functions for input/output parameter sructures 
*
*/


#ifndef WIFIPARAMS_INL
#define WIFIPARAMS_INL

using namespace WiFiProt;

WiFiProt::TWiFiInputParams::TWiFiInputParams(const TDesC8& aInitBuf,
                                             const TBool aConnectionNeeded):
    iSSid(aInitBuf),
    iConnectionNeeded(aConnectionNeeded)
    {
       
    }
        
    
WiFiProt::TWiFiOutputParams::TWiFiOutputParams(const TDesC8& aInitBuf):
    iIapIds(aInitBuf),
    iReturn(EWiFiCancel)
    {
        
    }

WiFiProt::TWiFiConnOutputParams::TWiFiConnOutputParams(
            const TWlanProtectedSetupCredentialAttribute& aNetworkSettings):
    iNetworkSettings(aNetworkSettings),
    iReturn(EWiFiCancel)
    {
        
    }
    
WiFiProt::TWiFiConnOutputParams::TWiFiConnOutputParams( ):
    iNetworkSettings( TWlanProtectedSetupCredentialAttribute() ),
    iReturn(EWiFiCancel)
    {
    
    }
#endif  // WIFIPARAMS_INL
// End of File
