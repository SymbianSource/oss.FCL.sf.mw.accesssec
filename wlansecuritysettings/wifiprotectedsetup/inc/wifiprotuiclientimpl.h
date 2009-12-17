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
* Description: Declaration of class CWiFiProtUiClientImpl.  
*
*/


#ifndef C_WIFIPROTUICLIENTIMPL_H
#define C_WIFIPROTUICLIENTIMPL_H

// INCLUDES
#include <e32base.h>
#include <wifiprotuiclient.h>

#include "wifiparams.h"
#include "wifiprotsyncclient.h"

// FORWARD DECLARATIONS
class CCommsDatabase;
class TConnectionPrefs;
class CAknGlobalNote;


// CLASS DECLARATION

/**
* Wi-Fi Protected Setup.
* Implementation behind proxy class CWiFiProt.
*/
NONSHARABLE_CLASS( CWiFiProtUiClientImpl ) : public CBase
    {
    public:

        /**
        * Two-phased constructor. Leaves on failure.
        * @return The constructed CConnectionUiUtilities object.
        */
        static CWiFiProtUiClientImpl* NewL();

        /**
        * Destructor.
        */
        virtual ~CWiFiProtUiClientImpl();

    public:
        /**
        * Starts WiFi Protected Setup sequence - async version
        * @param aSSid contains SSid of the network we want to configure 
        * @param aConnectionNeeded not used anymore
        * @param aUidsReturned uids of the configured connection methods
        * @param aReturnValue - possible return values are ok, cancel
        * process and not use 
        * protected setup (No Automatic Setup).
        */
        void StartWiFiProtL ( const TWlanSsid& aSSid,
         TBool aConnectionNeeded, RArray<TUint32>& aUidsReturned,
          WiFiProt::TWiFiReturn& aReturnValue, TRequestStatus& aStatus );
        
        /**
        * Starts WiFi Protected Setup sequence - sync version, returns
        * when completed
        * @param aSSid contains SSid of the network we want to configure 
        * @param aConnectionNeeded not used anymore 
        * @param aUidsReturned uids of the configured connection methods
        * @return  possible return values are ok, cancel process and not use 
        * protected setup (No Automatic Setup).
        * We can return a value since the call is sychronous.
        */
        WiFiProt::TWiFiReturn StartWiFiProtSyncL( const TWlanSsid& aSSid,
                                                 TBool aConnectionNeeded,
                                          RArray<TUint32>& aUidsReturned );
        
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
        void CancelWiFiProt( );        

    private:  // Constructors

        /**
        * Constructor.
        */
        CWiFiProtUiClientImpl();

        /**
        * Second-phase constructor.
        */
        void ConstructL();
  
                                  
    // Data
    private:     
        // notifier client
        RWiFiProtSession iNotif; 
        // Synchronously callable client
        CWiFiProtSyncClient* iWiFiProtSyncClient;
    };


#endif  // C_WIFIPROTUICLIENTIMPL_H

// End of File

