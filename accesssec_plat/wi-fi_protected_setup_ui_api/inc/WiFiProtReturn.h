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


#ifndef T_WIFIRETURN_H
#define T_WIFIRETURN_H

namespace WiFiProt
    {
    // Return value of Wi-Fi Protected Setup ( WPS ) Ui process
    enum TWiFiReturn 
        {
        // WPS has been cancelled
        EWiFiCancel,
        // WPS has completed without any errors
        EWiFiOK,
        // User has selected the option not to use WPS
        EWifiNoAuto
        };
    }

#endif  // T_WIFIRETURN_H


// End of File
