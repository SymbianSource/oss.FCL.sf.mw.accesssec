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
* Description: CWiFiProtActiveResp class
*
*/

/*
* %version: tr1cfwln#7 %
*/

#ifndef C_WIFIPROTACTIVERESP_H
#define C_WIFIPROTACTIVERESP_H

// INCLUDES
#include <e32base.h>
#include "wifiparams.h"

// CLASS DECLARATION

/**
* ActiveObject for asynchronous operations
*/
NONSHARABLE_CLASS( CWiFiProtActiveResp ) : public CActive
    {
    public:  // Constructors and destructor
        /**
        * Two-phased constructor.
        * @param aSSid contains SSid of the network we want to configure 
        * @param aConnectionNeeded ETrue if we need a connection
        * via the configured network 
        * @param aUidsReturned uids of the configured connection methods
        * @param aReturnValue - possible return values are ok, cancel
        * process and not use 
        * protected setup (No Automatic Setup).
        */
        static CWiFiProtActiveResp* NewL(   const TWlanSsid& aSSid,
             TBool aConnectionNeeded, RArray<TUint32>& aUidsReturned, 
             WiFiProt::TWiFiReturn& aReturnValue );
             
        /**
        * Two-phased constructor.
        * @param aSSid contains SSid of the network we want to configure 
        * via the configured network 
        * @param aNetworkSettings the configured network settings
        * to be returned
        * @param aReturnValue - possible return values are ok, cancel
        * process and not use 
        * protected setup (No Automatic Setup).
        */
        static CWiFiProtActiveResp* NewL(   const TWlanSsid& aSSid,
             TWlanProtectedSetupCredentialAttribute& aNetworkSettings, 
             WiFiProt::TWiFiReturn& aReturnValue );             

        /**
        * Destructor.
        */
        virtual ~CWiFiProtActiveResp();

    public: // From base class
        /**
        * This function is called when the scheduled function ends.
        */
        void RunL();

        /**
        * Cancel operations.
        */
        void DoCancel();


    public: // New functions
        /**
        * Add this class on the ActiveScheduler and puts itself active.
        * @param aStatus The status that is checked by the caller of the 
        *                Authenticate dialog.
        */
        void Observe( TRequestStatus &aStatus );

        /**
        * Returns the TWiFiInputParams 
        * @return A pointer to iWiFiInputParams.
        */
        TPckgBuf<WiFiProt::TWiFiInputParams>* InputBuffer();

        /**
        * Returns the TWiFiOutputParams 
        * @return A pointer to iWiFiOutputParams.
        */
        TPckgBuf<WiFiProt::TWiFiOutputParams>* OutputBuffer();
        
        /**
        * Returns the TWiFiConnOutputParams 
        * @return A pointer to iConnWiFiOutputParams.
        */
        TPckgBuf<WiFiProt::TWiFiConnOutputParams>* ConnOutputBuffer();         

    private:
        /**
        * C++ default constructor.
        * @param aSSid contains SSid of the network we want to configure 
        * @param aConnectionNeeded ETrue if we need a connection via the
        * configured network 
        * @param aUidsReturned uids of the configured connection methods
        * @param aReturnValue - possible return values are ok, cancel
        * process and not use 
        * protected setup (No Automatic Setup).
        */
        CWiFiProtActiveResp(   const TWlanSsid& aSSid,
             TBool aConnectionNeeded, RArray<TUint32>& aUidsReturned,
             WiFiProt::TWiFiReturn& aReturnValue );
             
        /**
        * C++ default constructor.
        * @param aSSid contains SSid of the network we want to configure 
        * @param aNetworkSettings network settings to be returned
        * @param aReturnValue - possible return values are ok, cancel
        * process and not use 
        * protected setup (No Automatic Setup).
        */
        CWiFiProtActiveResp(   const TWlanSsid& aSSid,
             TWlanProtectedSetupCredentialAttribute& aNetworkSettings,
             WiFiProt::TWiFiReturn& aReturnValue );
        /**
        * By default Symbian 2nd phase constructor is private.
        */
        void ConstructL( );

    private:    // Data
        // The status that is checked by the caller of the Wi-Fi
        // Protected Setup ui. Not owned.
        TRequestStatus* iRequestStatus;    

        // The address of the area where the caller of the Wi-Fi
        // Protected Setup ui expects the value for iap list. Not owned.
        RArray<TUint32>* iIapIds;
        
        //Contains the return value passed to the client
        WiFiProt::TWiFiReturn& iReturnValue;

        // Packed buffer containing Wi-Fi Protected Setup output parameters.
        TPckgBuf<WiFiProt::TWiFiOutputParams> iWiFiOutputParams;
        // Packed buffer containing Wi-Fi Protected Setup input parameters.
        TPckgBuf<WiFiProt::TWiFiInputParams> iWiFiInputParams;
        // Packed buffer containing Wi-Fi Protected Setup output parameters
        // for connection creation mode.
        TPckgBuf<WiFiProt::TWiFiConnOutputParams> iWiFiConnOutputParams;
        // network settings to be returned
        // used only for connection creation
        TWlanProtectedSetupCredentialAttribute* iNetworkSettings;
    };


#endif //C_WIFIPROTACTIVERESP_H

// End of File
