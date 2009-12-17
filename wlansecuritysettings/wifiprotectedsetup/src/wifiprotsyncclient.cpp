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
* Description: Implementation of class CWiFiProtSyncClient.
*
*/


// INCLUDE FILES
#include "wifiprotsyncclient.h"
#include "wifiprotlogger.h"

//
// WiFiProtSyncClient definitions
//
// --------------------------------------------------------------------------
// NewL
// --------------------------------------------------------------------------
//
CWiFiProtSyncClient* CWiFiProtSyncClient::NewL( RWiFiProtSession& aClient,
                    TInt aPriority )
    {
    CWiFiProtSyncClient* self = new(ELeave) CWiFiProtSyncClient( aClient,
                                                                aPriority );
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop(); // self
    return self;
    }

// --------------------------------------------------------------------------
// CWiFiProtSyncClient
// --------------------------------------------------------------------------
//
CWiFiProtSyncClient::CWiFiProtSyncClient( RWiFiProtSession& aClient,
                                          TInt aPriority ) 
                                         : CActive( aPriority ),
                                           iClient( aClient )
    {
    }

// --------------------------------------------------------------------------
// ConstructL
// --------------------------------------------------------------------------
//
void CWiFiProtSyncClient::ConstructL()
    {
    CActiveScheduler::Add( this );
    iState = ENoState;
    }

// --------------------------------------------------------------------------
// ~CWiFiProtSyncClient
// --------------------------------------------------------------------------
//
CWiFiProtSyncClient::~CWiFiProtSyncClient()
    {
    Cancel();
    }

// --------------------------------------------------------------------------
// StartWiFiProtL
// --------------------------------------------------------------------------
//
WiFiProt::TWiFiReturn
    CWiFiProtSyncClient::StartWiFiProtL( const TWlanSsid& aSSid, 
                                         TBool aConnectionNeeded,
                                         RArray<TUint32>& aUidsReturned )
    {
    WiFiProt::TWiFiReturn ret;
    iClient.StartWiFiProtL( aSSid, aConnectionNeeded, aUidsReturned, ret,
                            iStatus );
    SetActive( ERunWiFiProt );
    iWait.Start(); //wait for request to complete
    return ret;
    }


    
// --------------------------------------------------------------------------
// SetActive
// --------------------------------------------------------------------------
//
void CWiFiProtSyncClient::SetActive( TWiFiState aState )
    {
    iState = aState;
    CActive::SetActive();
    }

// --------------------------------------------------------------------------
// RunL
// --------------------------------------------------------------------------
//
void CWiFiProtSyncClient::RunL()
    {
    const TWiFiState state = iState;
    iState = ENoState;

    switch (state)
        {
        case ERunWiFiProt:
            {
            iWait.AsyncStop();
            break;
            }
        default:
            {
            User::Leave(KErrGeneral);
            break;
            }
        }
    }

// --------------------------------------------------------------------------
// DoCancel
// --------------------------------------------------------------------------
//
void CWiFiProtSyncClient::DoCancel()
    { 
    switch (iState)
        {
        case ERunWiFiProt:
            {
            CLOG_WRITE( "CWiFiProtSyncClient::DoCancel()" );
            iClient.CancelWiFiProt();
            break;
            }
        default:
            {
            break;
            }
        }
    iState = ENoState;
    }
// End of File  
