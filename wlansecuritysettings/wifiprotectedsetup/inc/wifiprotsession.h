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
* Description: RWiFiProtSession class.
*
*/

/*
* %version: tr1cfwln#7 %
*/

#ifndef R_WIFIPROTSESSION_H
#define R_WIFIPROTSESSION_H

// INCLUDES
#include <e32std.h>

#include "wifiparams.h"
#include "wifiprotactiveresp.h"

// CLASS DECLARATION

/**
 * RWiFiProtSession
 * Session class to handle communication with Notifier Framework
 */
class RWiFiProtSession : public RSessionBase
    {
    public:
    
        /**
        * Constructor.
        */
        RWiFiProtSession();

        /**
        * Destructor.
        */
        ~RWiFiProtSession();

        /**
        * Connect to the notifier server. Must be called before any other 
        * function.
        * @return KErrNone if connection succeeded and a standard error code
        * otherwise.
        */
        TInt Connect();

        /**
        * Disconnect from the notifier server.
        */
        void Close();

        /**
        * Starts WiFi Protected Setup sequence
        * @param aSSid contains SSid of the network we want to configure 
        * @param aConnectionNeeded not used anymore 
        * @param aUidsReturned uids of the configured connection methods
        * @param aReturnValue - possible return values are ok, cancel
        * process and not use protected setup (No Automatic Setup).
        * @param aStatus - Request status of the client
        */      
        void StartWiFiProtL( const TWlanSsid& aSSid, TBool aConnectionNeeded,
            RArray<TUint32>& aUidsReturned,
            WiFiProt::TWiFiReturn& aReturnValue,
             TRequestStatus& aStatus );
             
        /**
        * Starts WiFi Protected Setup sequence in Connection initiation mode
        * (WPS phase 2 implementation)
        * @param aSSid contains SSid of the network we want to configure 
        * @param aNetworkSettings configuration settings of the network to use
        * for the connection (returned as the result of Protected Setup)      
        * @param aReturnValue - possible return values are ok, cancel
        * process and not use protected setup (No Automatic Setup).
        * @param aStatus - Request status of the client       
        */
        void StartWiFiProtConnL( const TWlanSsid& aSSid,
                                      TWlanProtectedSetupCredentialAttribute&
                                        aNetworkSettings,
                                      WiFiProt::TWiFiReturn& aReturnValue,
                                      TRequestStatus& aStatus );        
        /**
        * Cancels WiFi Protected Setup sequence
        */
        void CancelWiFiProt();

    private:
        // Pointer to the client interface
        RNotifier* iNotifier;
        // Active object used to get TDesC data from the Notifier Framework
        //  message
        CWiFiProtActiveResp* iWiFiProtActiveResp;
    };

#endif /* R_WIFIPROTSESSION_H */

// End of File

