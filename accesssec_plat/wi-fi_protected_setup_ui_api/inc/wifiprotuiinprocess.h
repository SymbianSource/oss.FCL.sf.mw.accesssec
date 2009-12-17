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
* Description: Declaration of CWifiProtUiInProcess
*
*/



#ifndef C_WIFIPROTUIINPROCESS_H
#define C_WIFIPROTUIINPROCESS_H


// INCLUDES
#include <cmmanagerext.h>
#include <wlanmgmtcommon.h>
#include <wifiprotreturn.h>

class CWiFiProtDlgsPlugin;

/**
 * CWifiProtUiInProcess class
 * Private interface class that allows the client to run
 * Wi-Fi Protected Setup directly, without using the
 * Notifier Framework
 */
class CWifiProtUiInProcess : public CBase
    {
    
public:
    
    /**
    * NewL function
    * @param  aCmManagerExt Cm Manager to use during Wi-Fi Protected Setup
    * return CWifiProtUiInProcess*
    */
    IMPORT_C static CWifiProtUiInProcess* NewL( RCmManagerExt*
                                                aCmManagerExt );

    /**
    * Destructor
    */
    ~CWifiProtUiInProcess( );

    /**
    * Starts Wi-Fi Protected Setup
    * Private interface to be used by applications with ui
    * runs in the same process, so pointers can be passed
    * @param aSSid contains SSid of the network we want to configure 
    * @param aConnectionNeeded ETrue if we need a connection via the
    * configured network 
    * @return  possible return values are ok, cancel process and not use 
    * protected setup (No Auto).        
    */    
    IMPORT_C WiFiProt::TWiFiReturn StartFromUiL( const TWlanSsid& aSSid,
                                             TBool aConnectionNeeded,
                                             RArray<TUint32>& aUidsReturned);

private:    

    /**
    * Constructor
    */
    CWifiProtUiInProcess( );
    
    /**
    * Second phase constructor
    * @param aCmManagerExt CmManager to use
    */
    void ConstructL( RCmManagerExt* aCmManagerExt = NULL );
                  
private:
    CWiFiProtDlgsPlugin* iWiFiProtDlgsPlugin; // notifier plugin class
    };


#endif // C_WIFIPROTUIINPROCESS_H

// End of File
