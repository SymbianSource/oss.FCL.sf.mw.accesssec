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
* Description: Implementation of CWiFiProtActiveResp class
*
*/

/*
* %version: tr1cfwln#9 %
*/

// INCLUDE FILES
#include "wifiprotactiveresp.h"
#include "wifiprotlogger.h"

//CONSTS
_LIT( KActiveRespPanic , "WPS Active Resp");
// ================= MEMBER FUNCTIONS =======================


// --------------------------------------------------------------------------
// CWiFiProtActiveResp::NewL
// --------------------------------------------------------------------------
//
CWiFiProtActiveResp* CWiFiProtActiveResp::NewL(  const TWlanSsid& aSSid,
                                         TBool aConnectionNeeded,
                                         RArray<TUint32>& aUidsReturned,
                                         WiFiProt::TWiFiReturn&
                                         aReturnValue )
    {
    CLOG_ENTERFN( "CWiFiProtActiveResp::NewL" );
    CWiFiProtActiveResp* self =
     new( ELeave )CWiFiProtActiveResp( aSSid , aConnectionNeeded,
                                       aUidsReturned,
                                       aReturnValue );
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self );

    CLOG_LEAVEFN( "CWiFiProtActiveResp::NewL" );
    return self;
    }
    
// --------------------------------------------------------------------------
// CWiFiProtActiveResp::NewL
// --------------------------------------------------------------------------
//
CWiFiProtActiveResp* CWiFiProtActiveResp::NewL(  const TWlanSsid& aSSid,
                                     TWlanProtectedSetupCredentialAttribute&
                                                            aNetworkSettings,
                                         WiFiProt::TWiFiReturn&
                                         aReturnValue )
    {
    CLOG_ENTERFN( "CWiFiProtActiveResp::NewL" );
    CWiFiProtActiveResp* self =
     new( ELeave )CWiFiProtActiveResp( aSSid , 
                                       aNetworkSettings,
                                       aReturnValue );
    CleanupStack::PushL( self );
    self->ConstructL();
    CleanupStack::Pop( self );

    CLOG_LEAVEFN( "CWiFiProtActiveResp::NewL" );
    return self;
    }
    
// ----------------------------------------------------
// CWiFiProtActiveResp::~CWiFiProtActiveResp()
// ----------------------------------------------------
//
CWiFiProtActiveResp::~CWiFiProtActiveResp()
    {
    CLOG_ENTERFN( "CWiFiProtActiveResp::~CWiFiProtActiveResp" );
    Cancel();
    CLOG_LEAVEFN( "CWiFiProtActiveResp::~CWiFiProtActiveResp" );
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveResp::RunL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveResp::RunL()
    {
    CLOG_ENTERFN( "CWiFiProtActiveResp::RunL");

    if ( iWiFiInputParams().iConnectionNeeded )
        {
        *iNetworkSettings = iWiFiConnOutputParams().iNetworkSettings;
        iReturnValue = iWiFiConnOutputParams().iReturn;
        }
    else
        {
        if ( iStatus.Int() == KErrNone )
            {            
            //CM creation mode (WPS phase 1), return iap id array    
            const TInt elementSize = sizeof( TUint32 );
            const TInt elementCount = iWiFiOutputParams().iIapIds.Length()
                                                            / elementSize;
            const TUint8* ptr = iWiFiOutputParams().iIapIds.Ptr();
            
            for ( TInt i = 0; i < elementCount; i++)
                {
                iIapIds->Append( *( (TUint32*) &( ptr[elementSize*i] ) ) );
                }
            }
        iReturnValue = iWiFiOutputParams().iReturn;
        }

    TRequestStatus* pS = iRequestStatus;
    User::RequestComplete( pS, iStatus.Int() );

    CLOG_LEAVEFN( "CWiFiProtActiveResp::RunL");
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveResp::DoCancel
// --------------------------------------------------------------------------
//
void CWiFiProtActiveResp::DoCancel()
    {
    CLOG_ENTERFN( "CWiFiProtActiveResp:DoCancel");
    TRequestStatus* pS = iRequestStatus;
    User::RequestComplete( pS, KErrCancel );
    CLOG_LEAVEFN( "CWiFiProtActiveResp::DoCancel");
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveResp::Observe
// --------------------------------------------------------------------------
//
void CWiFiProtActiveResp::Observe( TRequestStatus &aStatus )
    {
    CLOG_ENTERFN( "CWiFiProtActiveResp::Observe");
    CActiveScheduler::Add( this );

    iRequestStatus = &aStatus;
    *iRequestStatus = KRequestPending;

    SetActive();
    CLOG_LEAVEFN( "CWiFiProtActiveResp::Observe");
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveResp::InputBuffer
// --------------------------------------------------------------------------
//
TPckgBuf<WiFiProt::TWiFiInputParams>* CWiFiProtActiveResp::InputBuffer() 
    { 
    return &iWiFiInputParams; 
    }
        
// --------------------------------------------------------------------------
// CWiFiProtActiveResp::OutputBuffer
// --------------------------------------------------------------------------
//
TPckgBuf<WiFiProt::TWiFiOutputParams>* CWiFiProtActiveResp::OutputBuffer() 
    {
    if ( iWiFiInputParams().iConnectionNeeded )
        {
        // Should use ConnOutputBuffer() if configuring a connection!
        User::Panic( KActiveRespPanic , KErrNotSupported);
        }
    return &iWiFiOutputParams; 
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveResp::ConnOutputBuffer
// --------------------------------------------------------------------------
//
TPckgBuf<WiFiProt::TWiFiConnOutputParams>* CWiFiProtActiveResp::ConnOutputBuffer() 
    { 
    if ( !(iWiFiInputParams().iConnectionNeeded) )
        {
        // Should use OutputBuffer() if not configuring a connection!
        User::Panic( KActiveRespPanic , KErrNotSupported);
        }
    return &iWiFiConnOutputParams; 
    }

// --------------------------------------------------------------------------
// CWiFiProtActiveResp::CWiFiProtActiveResp
// --------------------------------------------------------------------------
//
CWiFiProtActiveResp::CWiFiProtActiveResp(
                     const TWlanSsid& aSSid, TBool aConnectionNeeded,
                     RArray<TUint32>& aUidsReturned,
                     WiFiProt::TWiFiReturn& aReturnValue )
                     : CActive( CActive::EPriorityUserInput ),
                     iIapIds( &aUidsReturned ),
                     iReturnValue( aReturnValue ),
                     iWiFiOutputParams( KNullDesC8() ),
                     iWiFiInputParams( TPckgBuf<WiFiProt::TWiFiInputParams>
                     ( WiFiProt::TWiFiInputParams( aSSid, 
                                                   aConnectionNeeded ) ) ),
              iWiFiConnOutputParams(TPckgBuf<WiFiProt::TWiFiConnOutputParams>
                     ( WiFiProt::TWiFiConnOutputParams(
                      TWlanProtectedSetupCredentialAttribute() ) )  )
    {
    }
    
// --------------------------------------------------------------------------
// CWiFiProtActiveResp::CWiFiProtActiveResp
// --------------------------------------------------------------------------
//
CWiFiProtActiveResp::CWiFiProtActiveResp(
                     const TWlanSsid& aSSid,
                     TWlanProtectedSetupCredentialAttribute&
                                              aNetworkSettings,
                     WiFiProt::TWiFiReturn& aReturnValue )
                     : CActive( CActive::EPriorityUserInput ),
                     iIapIds( NULL ),
                     iReturnValue( aReturnValue ),
                     iWiFiOutputParams( KNullDesC8() ),
                     iWiFiInputParams( TPckgBuf<WiFiProt::TWiFiInputParams>
                     ( WiFiProt::TWiFiInputParams( aSSid, 
                                                   ETrue ) ) ),
              iWiFiConnOutputParams(TPckgBuf<WiFiProt::TWiFiConnOutputParams>
                     ( WiFiProt::TWiFiConnOutputParams(
                      TWlanProtectedSetupCredentialAttribute() ) ) ),
                     iNetworkSettings( &aNetworkSettings )
                                                   
    {
    }
    
// --------------------------------------------------------------------------
// CWiFiProtActiveResp::ConstructL
// --------------------------------------------------------------------------
//
void CWiFiProtActiveResp::ConstructL()
    {
    }
    
// End of File  
