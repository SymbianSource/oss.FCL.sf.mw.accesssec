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
* Description: Declaration of CWiFiProtDlgsPlugin
*
*/

/*
* %version: tr1cfwln#11 %
*/

#ifndef C_WIFIPROTDLGSPLUGIN_H
#define C_WIFIPROTDLGSPLUGIN_H


// INCLUDES
#include <cmmanagerext.h>
#include <wlanmgmtcommon.h>
#include <wifiprotreturn.h>
#include <eiknotapi.h>

using namespace WiFiProt;

class TWiFiOutputParams;
class CWiFiProtActiveRunner;





/**
 * CWiFiProtDlgsPlugin class
 * Notifier Framework plugin for Wi-Fi Protected Setup
 */
class CWiFiProtDlgsPlugin : public CBase, public MEikSrvNotifierBase2

    {
    
public:
    
    /**
    * NewL function
    * @param  aResourceFileResponsible - ETrue if the plugin handles the
    * resource file
    * @param  aCmManagerExt - CmManager to use during Wi-Fi Protected Setup
    * return CWiFiProtDlgsPlugin*
    */
    static CWiFiProtDlgsPlugin* NewL( const TBool aResourceFileResponsible,
                                              RCmManagerExt* aCmManagerExt );

    /**
    * NewL function
    * @param  aResourceFileResponsible - ETrue if the plugin handles the
    * resource file
    * return CWiFiProtDlgsPlugin*
    */
    static CWiFiProtDlgsPlugin* NewL( const TBool aResourceFileResponsible );


    /**
    * Destructor
    */
    ~CWiFiProtDlgsPlugin( );

    // From MEikSrvNotifierBase

    /**
    * Get Notifier information
    * return TNotifierInfo Notifier info
    */
    TNotifierInfo Info() const;

    /**
    * Start the Notifier
    * @param  aBuffer   Not used
    * return TPtrC8     Always NULL
    */
    TPtrC8 StartL( const TDesC8& aBuffer );

    /**
    * Cancel() the notifier
    * @param  -
    * return -
    */
    void Cancel();

    /**
    * Release the notifier
    * @param  -
    * return -
    */
    void Release();

    /**
    * Update Notifier
    * @param  aBuffer   Not used
    * return TPtrC8     Always NULL
    */
    TPtrC8 UpdateL( const TDesC8& aBuffer );

    /**
    * CompleteL the notifier is complete
    * @param  aStatus status
    * return  -
    */
    void CompleteL( TInt aStatus );

    /**
    * Sets iCancelled flag that indicates that the notifier was cancelled
    * @param  aCancelled   Not used
    */
    void SetCancelledFlag( TBool aCancelled );
    
    /**
    * RegisterL register the client notifier function
    * return TNotifierInfo Contains uid, channel and priority of
    * the registered notifier
    */
    TNotifierInfo RegisterL();

    /**
    * Start the Notifier
    * @param  aBuffer    Buffer that stores parameters from client side
    * @param  aReplySlot Identifies which message argument to use for the 
    *                    reply. This message argument will refer to a 
    *                    modifiable descriptor, a TDes8 type, into which data
    *                    can be returned. 
    * @param  aMessage   Message
    */
    void StartL( const TDesC8& aBuffer, TInt aReplySlot, 
                 const RMessagePtr2& aMessage );

    /**
    * Asynchronous notifier dialog sequence is completed by calling this function.
    * @param aReturnValue - possible return values are ok, cancel
    * process and not use protected setup (No Automatic Setup).
    */
    void CompleteProcessL( WiFiProt::TWiFiReturn aReturnValue );
    
    /**
    * Starts Wi-Fi Protected Setup
    * Private interface to be used by applications with ui
    * runs in the same process, so pointers can be passed
    * @param aSSid contains SSid of the network we want to configure 
    * @param aConnectionNeeded ETrue if we need a connection via the
    * configured network 
    * @param aUidsReturned uids of the configured connection methods
    * @return aReturnValue - possible return values are ok, cancel
    * process and not use protected setup (No Automatic Setup).
    */  
    
    WiFiProt::TWiFiReturn StartFromUiL( const TWlanSsid& aSSid,
                                        TBool aConnectionNeeded,
                                        RArray<TUint32>& aUidsReturned);


private:

    /**
    * Returns the correct RCmManagerExt instance's reference
    * it can be an own instance, or a passed reference in case
    * StartFromUiL was called (we are in the same process as the caller)
    * This is necessary because we can't open two CmManagers the same time
    * and the client is possibly using one already.
    * @return a passed or an own RCmManagerExt& instance, based on the 
    * method of calling CWiFiProtDlgsPlugin 
    */
    RCmManagerExt& CmManagerToUse();
    
private:    

    /**
    * Constructor
    */
    CWiFiProtDlgsPlugin( );
    
    /**
    * CWiFiProtDlgsPlugin second level constructor
    * @param  aResourceFileName Resource file to open
    * @param  aResourceFileResponsible ETrue if this notifier is
    * responsible for the resource file
    * @param aCmManagerExt CmManager to use
    * @see CWiFiProtDlgsPlugin::CmManagerToUse
    */
    void ConstructL( const TDesC& aResourceFileName,
                     const TBool aResourceFileResponsible,
                      RCmManagerExt* aCmManagerExt = NULL );


                  
private:

    RCmManagerExt iCmManagerExt;        // own CmManager
    RCmManagerExt* iPassedCmManagerExt; // passed CmManager, not owned
    CWiFiProtActiveRunner* iRunner;     // Active Runner object
    TWiFiReturn iReturn;                // return value towards the client 
    RArray<TUint32> iUids;              // uids of created connection methods
    TNotifierInfo iInfo;                // Notifier info
    RMessagePtr2 iMessage;              // Message
    TInt iReplySlot;                    // Reply slot
    TBool iCancelled;                   // ETrue if WPS process is cancelled
    TInt iResource;                     // Resource
    TBool   iConnMode;                  // ETrue if creating a connection
    // network settings to be returned if WPS is used for connection creation
    TWlanProtectedSetupCredentialAttribute iNetworkSettings;
    TBool iCancelledFromInside;               // ETrue if user or WLAN engine has cancelled
    TBool iClientCancelled;		// ETrue if the notifier client has called Cancel()
    };


#endif // C_WIFIPROTDLGSPLUGIN_H

// End of File
