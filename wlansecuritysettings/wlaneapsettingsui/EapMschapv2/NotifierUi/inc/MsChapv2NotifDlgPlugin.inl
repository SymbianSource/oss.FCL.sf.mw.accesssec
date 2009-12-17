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
* Description: Inline functions of MsChapv2Notif Dialog Plugins
*
*/



#ifndef __MSCHAPV2NOTIFDLGPLUGIN_INL__
#define __MSCHAPV2NOTIFDLGPLUGIN_INL__


// ---------------------------------------------------------
// CMsChapv2DialogPlugin::GetUsername
// ---------------------------------------------------------
//
inline TDes& CMsChapv2DialogPlugin::GetUsername() 
    { 
    return iDataPtr->iUsername;
    }


// ---------------------------------------------------------
// CMsChapv2DialogPlugin::GetPassword
// ---------------------------------------------------------
//
inline TDes& CMsChapv2DialogPlugin::GetPassword() 
    { 
    return iDataPtr->iPassword;
    }


// ---------------------------------------------------------
// CMsChapv2DialogPlugin::SetOldPassword
// ---------------------------------------------------------
//
inline void CMsChapv2DialogPlugin::SetOldPassword( const TDesC& aOldPwd ) 
    { 
    iDataPtr->iOldPassword = aOldPwd; 
    }

#endif  // __MSCHAPV2NOTIFDLGPLUGIN_INL__


// End of File
