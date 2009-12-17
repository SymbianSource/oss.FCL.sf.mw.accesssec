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
* Description: CWiFiProtSyncClient class.
*
*/


#ifndef C_WIFIPROTSYNCCLIENT_H
#define C_WIFIPROTSYNCCLIENT_H

// INCLUDES
#include <e32base.h>

#include "wifiprotsession.h"

/**
* CWiFiProtSyncClient
* Active object to convert a sychronous client call asynchronous, and
* return only when the request is completed
*/
class CWiFiProtSyncClient : public CActive
    {
    public:
        /**
        * Two phased constructor
        * @param aClient RWiFiProtSession class to handle communication with
        * Notifier Framework
        * @param aPriority Active object priority
        **/
        static CWiFiProtSyncClient* NewL( RWiFiProtSession& aClient,
            TInt aPriority = CActive::EPriorityStandard );
        /**
        * Destructor
        **/            
        ~CWiFiProtSyncClient();

        /**
        * Starts WiFi Protected Setup sequence
        * @param aSSid contains SSid of the network we want to configure 
        * @param aConnectionNeeded ETrue if we need a connection via the
        * configured network 
        * @param aUidsReturned uids of the configured connection methods
        * @return possible return values are ok, cancel process and not use 
        * protected setup (No Automatic Setup).
        */
        WiFiProt::TWiFiReturn StartWiFiProtL(  const TWlanSsid& aSSid, 
                                  TBool aConnectionNeeded,
                                  RArray<TUint32>& aUidsReturned
                                  );
        
    private:
        // Each Notifier Framework call has a corresponding enum,
        // and CWiFiProtSyncClient uses it to keep track of the
        // currently active call
        // The only one is ERunWiFiProt at the moment
        enum TWiFiState
            {
            ENoState = 0,
            // StartWiFiProtL was called
            ERunWiFiProt
            };

    private:
        /**
        * Constructor
        * @param aClient RWiFiProtSession class to handle communication
        * with Notifier Framework
        * @param aPriority Active object priority
        **/    
        CWiFiProtSyncClient( RWiFiProtSession& aClient, TInt aPriority );
        
        /**
        * Second phase constructor
        **/           
        void ConstructL();
        
        /**
        * Calls CActive::SetActive() and sets TWiFiState also
        * @param aState identifier of the active call
        **/           
        void SetActive( TWiFiState aState );

        /** From CActive */
        
        /**
        * @see CActive::DoCancel
        **/ 
        virtual void DoCancel();
 
        /**
        * @see CActive::RunL
        **/        
        virtual void RunL();

    private:
        // RWiFiProtSession class to handle communication with Notifier
        // Framework
        RWiFiProtSession& iClient;
        // identifier of the active call
        CWiFiProtSyncClient::TWiFiState iState;
        // Active Scheduler Waiter class to halt the process until the
        // call is completed
        CActiveSchedulerWait iWait;
    };


#endif //C_WIFIPROTSYNCCLIENT_H

// End of File
