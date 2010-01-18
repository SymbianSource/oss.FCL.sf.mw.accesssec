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
* Description: Declares the main handler, CWiFiProtUiClient and public API for the Wi-Fi Protected Settings. 
*
*/

/*
* %version: tr1cfwln#6 %
*/

#ifndef C_WIFIPROTUICLIENT_H
#define C_WIFIPROTUICLIENT_H

// INCLUDES

#include <e32base.h>
#include <wlanmgmtcommon.h>
#include <wifiprotreturn.h>

// FORWARD DECLARATIONS
class CWiFiProtUiClientImpl;

// CLASS DECLARATION
/*
* WiFi Protected Setup , used to show the user a sequence of dialogs to setup
* a wlan network automatically
* This class is just a proxy, the real implementation is in
* CWiFiProtUiClientImpl. 
* No details of the actual data are exposed.
*/
class CWiFiProtUiClient  : public CBase
    {
    public: // Constructors and destructor
        /**
        * Two-phased constructor. Leaves on failure.
        * @return The constructed CWiFiProtUiClient object.
        */
        IMPORT_C static CWiFiProtUiClient* NewL();

        /**
        * Destructor.
        */
        IMPORT_C ~CWiFiProtUiClient();

        // New methods

        /**
        * Starts WiFi Protected Setup sequence
        * @param aSSid contains SSid of the network we want to configure 
        * @param aConnectionNeeded - This parameter is not used anymore in
        * the current implementation. It is just there to preserve
        * compatibility. Please use StartWiFiProtConnL to configure a
        * connection using Wi-Fi Protected Setup.
        * @param aUidsReturned uids of the configured connection methods        
        * @param aReturnValue - possible return values are ok, cancel
        * process and not use protected setup (No Automatic Setup).
        * @param aStatus - Request status of the client       
        */
        IMPORT_C void StartWiFiProtL( const TWlanSsid& aSSid,
                                      TBool aConnectionNeeded,
                                      RArray<TUint32>& aUidsReturned,
                                      WiFiProt::TWiFiReturn& aReturnValue,
                                      TRequestStatus& aStatus );

        /**
        * Starts WiFi Protected Setup sequence - sync version
        * @param aSSid contains SSid of the network we want to configure 
        * @param aConnectionNeeded - This parameter is not used anymore in
        * the current implementation. It is just there to preserve
        * compatibility. Please use StartWiFiProtConnL to configure a
        * connection using Wi-Fi Protected Setup.
        * @param aUidsReturned uids of the configured connection methods        
        * @return  - possible return values are ok, cancel process
        * and not use protected setup (No Automatic Setup).
        * We can return a value since the call is sychronous.
        */
        IMPORT_C WiFiProt::TWiFiReturn StartWiFiProtSyncL(
                                          const TWlanSsid& aSSid,
                                          TBool aConnectionNeeded,
                                          RArray<TUint32>& aUidsReturned );

        /**
        * Cancels WiFi Protected Setup sequence
        */
        IMPORT_C void CancelWiFiProt( );
        
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
        IMPORT_C void StartWiFiProtConnL( const TWlanSsid& aSSid,
                                      TWlanProtectedSetupCredentialAttribute&
                                        aNetworkSettings,
                                      WiFiProt::TWiFiReturn& aReturnValue,
                                      TRequestStatus& aStatus );

    private:    // Data 
        CWiFiProtUiClientImpl* iImpl;  ///< Implementation. Owned.
    };

#endif //C_WIFIPROTUICLIENT_H

// End of File
