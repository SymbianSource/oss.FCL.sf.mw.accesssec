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
* Description: Implementation of RWiFiProtSession
*
*/


// INCLUDE FILES
#include "wifiprotsession.h"
#include "e32ver.h"
#include <wifiprotuiddefs.h>
#include "wifiprotlogger.h"

using namespace WiFiProt;

// --------------------------------------------------------------------------
// RWiFiProtSession::RWiFiProtSession()
// --------------------------------------------------------------------------
//
RWiFiProtSession::RWiFiProtSession() :
                        RSessionBase(),
                        iNotifier( NULL ),
                        iWiFiProtActiveResp( NULL )
    {
    CLOG_ENTERFN( "RWiFiProtSession::RWiFiProtSession" );
    CLOG_LEAVEFN( "RWiFiProtSession::RWiFiProtSession" );
    }


// --------------------------------------------------------------------------
// ~RWiFiProtSession
// --------------------------------------------------------------------------
//
RWiFiProtSession::~RWiFiProtSession()
    {
    CLOG_ENTERFN( "RWiFiProtSession::~RWiFiProtSession" );
    Close();
    CLOG_LEAVEFN( "RWiFiProtSession::~RWiFiProtSession" );
    }


// --------------------------------------------------------------------------
// Connect
//
// Create a session to the extended notifier framework
// --------------------------------------------------------------------------
//
TInt RWiFiProtSession::Connect()
    {
    CLOG_ENTERFN( "RWiFiProtSession::Connect" );

    TInt error( KErrNone );
    if ( !iNotifier )
        {
        TRAP( error, iNotifier = new (ELeave) RNotifier() );
        }
    if ( !error && iNotifier )
        {
        error = iNotifier->Connect();
        }
    CLOG_LEAVEFN( "RWiFiProtSession::Connect" ); 
    return error;
    }
    
// --------------------------------------------------------------------------
// Close
// --------------------------------------------------------------------------
//
void RWiFiProtSession::Close()
    {
    CLOG_ENTERFN( "RWiFiProtSession::Close" );

    RSessionBase::Close();
    
    if (iWiFiProtActiveResp)
        {
        iWiFiProtActiveResp->Cancel();
        delete iWiFiProtActiveResp;  
        iWiFiProtActiveResp = NULL;
        }
    if ( iNotifier ) 
        {
        iNotifier->Close();
        delete iNotifier;    
        iNotifier = NULL;
        }

    CLOG_LEAVEFN( "RWiFiProtSession::Close" );
    }
    
// --------------------------------------------------------------------------
// StartWiFiProtL
// --------------------------------------------------------------------------
//
void RWiFiProtSession::StartWiFiProtL( const TWlanSsid& aSSid,
                                       TBool aConnectionNeeded,
                                       RArray<TUint32>& aUidsReturned,
                                       WiFiProt::TWiFiReturn& aReturnValue,
                                       TRequestStatus& aStatus )
    {
    CLOG_ENTERFN( "RWiFiProtSession::StartWiFiProtL" );

    aConnectionNeeded = EFalse; // this parameter is not supported anymore
                                // to be set from the API, but it is used
                                // internally from StartWiFiProtConnL
    TRAPD( err, iWiFiProtActiveResp =
     CWiFiProtActiveResp::NewL( aSSid,
                                aConnectionNeeded,
                                aUidsReturned,
                                aReturnValue ) );

    
    if ( err != KErrNone )
        {
        TRequestStatus* pS = &aStatus;
        User::RequestComplete( pS, err );
        }
    else
        {
        iWiFiProtActiveResp->Observe( aStatus );

        TPckgBuf<TWiFiOutputParams>* outputParams =
             iWiFiProtActiveResp->OutputBuffer();
        TPckgBuf<TWiFiInputParams>* inputParams = 
             iWiFiProtActiveResp->InputBuffer();

        if ( iNotifier )
            {
            TRequestStatus& status = iWiFiProtActiveResp->iStatus;
            iNotifier->StartNotifierAndGetResponse( status,
                                                    KUidWiFiProtSetup,
                                                    *inputParams,
                                                    *outputParams );
            }
        }

    CLOG_LEAVEFN( "RWiFiProtSession::StartWiFiProtL" );
    }

// --------------------------------------------------------------------------
// StartWiFiProtConnL
// --------------------------------------------------------------------------
//
void RWiFiProtSession::StartWiFiProtConnL( const TWlanSsid& aSSid,
                                      TWlanProtectedSetupCredentialAttribute&
                                        aNetworkSettings,
                                      WiFiProt::TWiFiReturn& aReturnValue,
                                      TRequestStatus& aStatus )
    {
    CLOG_ENTERFN( "RWiFiProtSession::StartWiFiProtConnL" );

    TRAPD( err, iWiFiProtActiveResp =
     CWiFiProtActiveResp::NewL( aSSid,
                                aNetworkSettings,
                                aReturnValue ) );

    
    if ( err != KErrNone )
        {
        TRequestStatus* pS = &aStatus;
        User::RequestComplete( pS, err );
        }
    else
        {
        iWiFiProtActiveResp->Observe( aStatus );

        TPckgBuf<TWiFiConnOutputParams>* connoutputParams =
             iWiFiProtActiveResp->ConnOutputBuffer();
        TPckgBuf<TWiFiInputParams>* inputParams = 
             iWiFiProtActiveResp->InputBuffer();

        if ( iNotifier )
            {
            TRequestStatus& status = iWiFiProtActiveResp->iStatus;
            iNotifier->StartNotifierAndGetResponse( status,
                                                    KUidWiFiProtSetup,
                                                    *inputParams,
                                                    *connoutputParams );
            }
        }

    CLOG_LEAVEFN( "RWiFiProtSession::StartWiFiProtConnL" );
    }    
    
// --------------------------------------------------------------------------
// CancelWiFiProt
// --------------------------------------------------------------------------
//
void RWiFiProtSession::CancelWiFiProt()
    {
    CLOG_ENTERFN( "RWiFiProtSession::CancelWiFiProt()" );
    iNotifier->CancelNotifier( KUidWiFiProtSetup );
    iWiFiProtActiveResp->Cancel();
    delete iWiFiProtActiveResp ; 
    iWiFiProtActiveResp = NULL; 
    CLOG_LEAVEFN( "RWiFiProtSession::CancelWiFiProt()" );
    }    

// End of File
