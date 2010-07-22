/*
* Copyright (c) 2008 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: %
*/

// INCLUDE FILES
#include <e32base.h>
#include "eap_am_async_wait_symbian.h"

// ---------------------------------------------------------
// eap_am_async_wait_symbian_c::eap_am_async_wait_symbian_c()
// ---------------------------------------------------------
//
eap_am_async_wait_symbian_c::eap_am_async_wait_symbian_c() : CActive(0)
    {
    CActiveScheduler::Add(this);
    }

// ---------------------------------------------------------
// eap_am_async_wait_symbian_c::~eap_am_async_wait_symbian_c()
// ---------------------------------------------------------
//
eap_am_async_wait_symbian_c::~eap_am_async_wait_symbian_c() 
    {
    Cancel() ;
    }

// ---------------------------------------------------------
// eap_am_async_wait_symbian_c::Wait() 
// ---------------------------------------------------------
//
void eap_am_async_wait_symbian_c::Wait() 
{
    SetActive();
    iActiveWait.Start();
}

// ---------------------------------------------------------
// eap_am_async_wait_symbian_c::RunL()
// ---------------------------------------------------------
//
void eap_am_async_wait_symbian_c::RunL()
{
    iActiveWait.AsyncStop() ;
}

// ---------------------------------------------------------
// eap_am_async_wait_symbian_c::DoCancel()
// ---------------------------------------------------------
//
void eap_am_async_wait_symbian_c::DoCancel()
{
    if( iStatus == KRequestPending )
        {
        TRequestStatus * reqStat = &iStatus;
        User::RequestComplete(reqStat, KErrCancel);
        }
}

// End of File
