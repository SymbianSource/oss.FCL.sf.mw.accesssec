/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP-server and client definitions.
*
*/

/*
* %version: 20 %
*/


#ifndef EAPSERVERCLIENTDEF_H_
#define EAPSERVERCLIENTDEF_H_

#include <e32base.h>

enum TEapPanic // both client-side and server-side - see category to distinguish
    {
    ECannotStartServer,
    EBadRequest,
    EBadDescriptor,
    EListenAlreadyListening,
    EErrorFromNonClientObject,
    EReceiveReceiveAlreadyActive,
    };

enum TEapRequests
    {
    EEapNone                 =  0,
    EEapCoreIfNew            =  1,
    EEapPluginNew            =  2,
    EEapSettingsNew          =  3,
    EEapCoreProcessData      =  4,
    EEapPluginProcessData    =  5,
    EEapSettingsProcessData  =  6,
    EEapCoreSendData         =  7,
    EEapPluginSendData       =  8,
    EEapSettingsSendData     =  9,
    EEapIfReqReceive         = 10,
    EEapIfCancelReceive      = 11,
    EEapPacStoreNew          = 12,
    EEapPacStoreProcessData  = 13,
    EEapPacStoreSendData     = 14,
    EWapiCoreIfNew           = 15,
    EWapiSettingsNew         = 16,
    EWapiCoreProcessData     = 17,
    EWapiSettingsProcessData = 18,
    EWapiCoreSendData        = 19,
    EWapiSettingsSendData    = 20,
    };

//the server version. A version must be specifyed when creating a session with the server
const TUint KEapMajorVersionNumber = 0;
const TUint KEapMinorVersionNumber = 1;
const TUint KEapBuildVersionNumber = 1;

_LIT(KEapAuthServerSemaphore,   "EapAuthServerSemaphore");
const TInt KMaxServerExe = 24;
const TInt KEapShutdownInterval=5000000; // 5 seconds.
const TInt KMaxCategoryLength = 16;
const TInt KMaxEapData = 30000;
const TInt KMaxEapMessageSlots = 50;

#endif /* EAPSERVERCLIENTDEF_H_ */
