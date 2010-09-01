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
* Description: Implementation of CWiFiProtDlgsPlugin.
*
*/

/*
* %version: tr1cfwln#10 %
*/

// INCLUDE FILES
#include <e32property.h>         // For RProperty 
#include <wifiprotuiddefs.h>
#include <bautils.h>
#include <eikenv.h>
#include <data_caging_path_literals.hrh>

#include "wifiprotdlgsplugin.h"
#include "wifiprotplugin.h"
#include "wifiprotlogger.h"
#include "wifiprotactiverunner.h"



using namespace WiFiProt;

// CONSTS
_LIT( KDriveZ, "z:" );

// ============================ MEMBER FUNCTIONS ============================
    
// --------------------------------------------------------------------------
// CWiFiProtDlgsPlugin* CWiFiProtDlgsPlugin::NewL()
// --------------------------------------------------------------------------
//
CWiFiProtDlgsPlugin* CWiFiProtDlgsPlugin::NewL( 
                             const TBool aResourceFileResponsible,
                                      RCmManagerExt* aCmManagerExt )

    {
    CLOG_ENTERFN( "CWiFiProtDlgsPlugin::NewL" );
    
    CWiFiProtDlgsPlugin* self = new ( ELeave ) CWiFiProtDlgsPlugin();
    CleanupStack::PushL( self );
    self->ConstructL( KResourceFileName,
                      aResourceFileResponsible, aCmManagerExt );
    CleanupStack::Pop( self );
    
    CLOG_LEAVEFN( "CWiFiProtDlgsPlugin::NewL" );
    
    return self;
    }
    
// --------------------------------------------------------------------------
// CWiFiProtDlgsPlugin* CWiFiProtDlgsPlugin::NewL()
// --------------------------------------------------------------------------
//
CWiFiProtDlgsPlugin* CWiFiProtDlgsPlugin::NewL( 
                                       const TBool aResourceFileResponsible )
    {
    CLOG_ENTERFN( "CWiFiProtDlgsPlugin::NewL (without passed CmManager)" );
    
    CWiFiProtDlgsPlugin* ret =  NewL( aResourceFileResponsible, NULL );
    
    CLOG_LEAVEFN( "CWiFiProtDlgsPlugin::NewL (without passed CmManager)" );
    
    return ret;
    }

// --------------------------------------------------------------------------
// CWiFiProtDlgsPlugin::~CWiFiProtDlgsPlugin
// --------------------------------------------------------------------------
//
CWiFiProtDlgsPlugin::~CWiFiProtDlgsPlugin( )

    {    
    CLOG_ENTERFN( "CWiFiProtDlgsPlugin::~CWiFiProtDlgsPlugin" );
    
    delete iRunner;

    //we didn't get a cmManager from the client, so use our own
    if (iPassedCmManagerExt == NULL)
        {
        iCmManagerExt.Close();
        }    

    iUids.Close();

    if ( iResource )
        {
        CCoeEnv::Static()->DeleteResourceFile( iResource );        
        }

    CLOG_LEAVEFN( "CWiFiProtDlgsPlugin::~CWiFiProtDlgsPlugin" );
    
    }  

// --------------------------------------------------------------------------
// CWiFiProtDlgsPlugin::TNotifierInfo 
//                                  CWiFiProtDlgsPlugin::Info() const
// --------------------------------------------------------------------------
//
CWiFiProtDlgsPlugin::TNotifierInfo CWiFiProtDlgsPlugin::Info() const
    {
    return iInfo;
    }

// --------------------------------------------------------------------------
// TPtrC8 CWiFiProtDlgsPlugin::StartL()
// --------------------------------------------------------------------------
//
TPtrC8 CWiFiProtDlgsPlugin::StartL( const TDesC8& /*aBuffer*/ )
    {
    CLOG_WRITE( "CWiFiProtDlgsPlugin::StartL" );
    return KNullDesC8().Ptr();
    }

// --------------------------------------------------------------------------
// void CWiFiProtDlgsPlugin::Cancel()
// --------------------------------------------------------------------------
//
void CWiFiProtDlgsPlugin::Cancel()
    {
    CLOG_ENTERFN( "CWiFiProtDlgsPlugin::Cancel" );
    
    if ( !iCancelled )
        {
        if ( iRunner && !iCancelledFromInside )
            {
            iClientCancelled = ETrue;
            iRunner->CancelByClient();
            }
        iCancelled = ETrue;
        if ( !iMessage.IsNull() )
            {
            if ( iConnMode )
                {
                TRAP_IGNORE( iMessage.WriteL( iReplySlot,
                         TPckg<WiFiProt::TWiFiConnOutputParams>( 
                                TWlanProtectedSetupCredentialAttribute() )
                         ));
                }
            else
                {
                TRAP_IGNORE( iMessage.WriteL( iReplySlot,
                         TPckg<WiFiProt::TWiFiOutputParams>( KNullDesC8() )
                         ));
                }
            iMessage.Complete( KErrCancel );
            }
        }
        
    CLOG_LEAVEFN( "CWiFiProtDlgsPlugin::Cancel" );
    
    }
    
// --------------------------------------------------------------------------
// void CWiFiProtDlgsPlugin::Release()
// --------------------------------------------------------------------------
//
void CWiFiProtDlgsPlugin::Release()
    {
    CLOG_ENTERFN( "CWiFiProtDlgsPlugin::Release" );

    delete this;

    CLOG_LEAVEFN( "CWiFiProtDlgsPlugin::Release" );
    }

// --------------------------------------------------------------------------
// TPtrC8 CWiFiProtDlgsPlugin::UpdateL()
// --------------------------------------------------------------------------
//
TPtrC8 CWiFiProtDlgsPlugin::UpdateL(const TDesC8& /*aBuffer*/)
    {
    return KNullDesC8().Ptr();
    }

// --------------------------------------------------------------------------
// void CWiFiProtDlgsPlugin::CompleteL()
// --------------------------------------------------------------------------
//
void CWiFiProtDlgsPlugin::CompleteL( TInt aStatus )
    {    
    CLOG_ENTERFN( "CWiFiProtDlgsPlugin::CompleteL" );
    
    CLOG_WRITEF( _L( "aStatus:" ), aStatus );
    iCancelled = ETrue;
    if ( !iMessage.IsNull() )
        {
        if ( iConnMode )
            {
            // return a different kind of message
            // for connection creation 
            WiFiProt::TWiFiConnOutputParams connOutputParams =
            WiFiProt::TWiFiConnOutputParams( iNetworkSettings );
            connOutputParams.iReturn = iReturn;            
            iMessage.WriteL( iReplySlot,
                            TPckg<WiFiProt::TWiFiConnOutputParams>( connOutputParams ) );            
            }
        else
            {
            // ... or iap(s) creation
            const TInt elementSize = sizeof(TUint32);
            TBuf8<(KMaxNumberOfUids * elementSize)> buf;
            TInt uidsCount = iUids.Count();
            if ( uidsCount > KMaxNumberOfUids )
                {
                uidsCount = KMaxNumberOfUids;
                }
            // copy data from the array to iIapIds in TWiFiOutputParams
            buf.Append((const TUint8 *)(&iUids[0]), uidsCount *elementSize);
            //append return value
            WiFiProt::TWiFiOutputParams outputParams =
                WiFiProt::TWiFiOutputParams(buf);
            outputParams.iReturn = iReturn;
            iMessage.WriteL( iReplySlot,
                            TPckg<WiFiProt::TWiFiOutputParams>( outputParams ) );
            }
        iMessage.Complete( aStatus );
        }
        
    CLOG_LEAVEFN( "CWiFiProtDlgsPlugin::CompleteL" );
    
    }
    
// --------------------------------------------------------------------------
// CWiFiProtDlgsPlugin::SetCancelledFlag
// --------------------------------------------------------------------------
//
void CWiFiProtDlgsPlugin::SetCancelledFlag( TBool aCancelled )
    { 
    iCancelled = aCancelled; 
    }

// --------------------------------------------------------------------------
// CWiFiProtDlgsPlugin::TNotifierInfo CWiFiProtDlgsPlugin::RegisterL()
// --------------------------------------------------------------------------
//
CWiFiProtDlgsPlugin::TNotifierInfo CWiFiProtDlgsPlugin::RegisterL()
    {
    CLOG_ENTERFN( "CWiFiProtDlgsPlugin::RegisterL" );

    iInfo.iUid = KUidWiFiProtSetup;
    iInfo.iPriority = ENotifierPriorityHigh;
    iInfo.iChannel = KUidWiFiProtSetup;
    
    CLOG_LEAVEFN( "CWiFiProtDlgsPlugin::RegisterL" );
    
    return iInfo;
    }

// --------------------------------------------------------------------------
// void CWiFiProtDlgsPlugin::StartL
// --------------------------------------------------------------------------
//
void CWiFiProtDlgsPlugin::StartL( const TDesC8& aBuffer, 
                                  TInt aReplySlot,
                                  const RMessagePtr2& aMessage )
    {
    CLOG_ENTERFN( "CWiFiProtDlgsPlugin::StartL" );
    
    TPckgBuf<TWiFiInputParams> pckgParams(
                    TPckgBuf<TWiFiInputParams>(TWiFiInputParams(KNullDesC8(),
                    EFalse))); 
    pckgParams.Copy( *((TPckgBuf<TWiFiInputParams>*) (&aBuffer)));
    TWiFiInputParams params((pckgParams)());
    iConnMode = params.iConnectionNeeded;
    TWlanSsid ssid;
    ssid.Copy( params.iSSid );
    
    iCancelled = EFalse;

    iReplySlot = aReplySlot;
    iMessage = aMessage;

    if ( iConnMode )
        {
        // no need for uid array to return, but we need a single network 
        // settings struct
        iRunner->StartProtectedSetupConnL( ssid, iNetworkSettings,
                                                       CmManagerToUse());
        }
    else
        {
        iRunner->StartProtectedSetupAsyncL( ssid, iUids, CmManagerToUse() );
        }
        
    CLOG_LEAVEFN( "CWiFiProtDlgsPlugin::StartL" );
    }

// --------------------------------------------------------------------------
// WiFiProt::TWiFiReturn CWiFiProtDlgsPlugin::CompleteProcessL
// --------------------------------------------------------------------------
//
void CWiFiProtDlgsPlugin::CompleteProcessL( WiFiProt::TWiFiReturn aReturnValue )
    {
    CLOG_ENTERFN( "WiFiProtDlgsPlugin::CompleteProcessL" );
    iReturn = aReturnValue;
    switch ( aReturnValue )
        {
        case EWiFiOK:
            {
            CLOG_WRITE("StartProtectedSetupL returned EWiFiOK");
            CompleteL( KErrNone );
            break;
            }
        case EWifiNoAuto:
            {
            CLOG_WRITE("StartProtectedSetupL returned EWifiNoAuto");
            CompleteL( KErrNone );
            break;
            }
        case EWiFiCancel:
            {
            CLOG_WRITE("StartProtectedSetupL returned EWiFiCancel");
            iCancelledFromInside = ETrue;
            Cancel();
            break;
            }
        default:
            {
            //should never happen
            CLOG_WRITE("Unhandled exit value, leaving...");
            User::Leave( KErrGeneral );
            break;
            }
        }
    CLOG_WRITEF( _L( "Uids returned:" ), iUids.Count() );
    for ( TInt i = 0;i<iUids.Count();i++ )
        {
        CLOG_WRITEF( _L( "Uid:" ), iUids[i] );
        }
        
    CLOG_LEAVEFN( "CWiFiProtDlgsPlugin::CompleteProcessL" );
    }

    
// --------------------------------------------------------------------------
// WiFiProt::TWiFiReturn CWiFiProtDlgsPlugin::StartFromUiL
// --------------------------------------------------------------------------
//

WiFiProt::TWiFiReturn CWiFiProtDlgsPlugin::StartFromUiL(
                                        const TWlanSsid& aSSid,
                                       TBool aConnectionNeeded,
                                RArray<TUint32>& aUidsReturned)
    {
    CLOG_ENTERFN( "CWiFiProtDlgsPlugin::StartFromUiL" );
    
    CLOG_WRITE("Input params:");
    CLOG_WRITE("SSid:");
    
    TBuf<KWlanMaxSsidLength> buf;
    buf.Copy(aSSid); 
    CLOG_WRITEF( buf );
    CLOG_WRITE("Connection needed:");
    if ( aConnectionNeeded )
        {
        CLOG_WRITE("ETrue");
        }
     else
        {
        CLOG_WRITE("EFalse");
        }
    //use passed CmManager if present
    WiFiProt::TWiFiReturn ret = iRunner->StartProtectedSetupL( 
                  aSSid, aUidsReturned, CmManagerToUse());
    
    CLOG_LEAVEFN( "CWiFiProtDlgsPlugin::StartFromUiL" );
    return ret;
    }

// --------------------------------------------------------------------------
// void CWiFiProtDlgsPlugin::CmManagerToUse()
// --------------------------------------------------------------------------
//
RCmManagerExt& CWiFiProtDlgsPlugin::CmManagerToUse()
    {
    CLOG_ENTERFN( "CWiFiProtDlgsPlugin::CmManagerToUse" );
    
    if (iPassedCmManagerExt == NULL )
        {
        CLOG_WRITE("Own CmManagerExt used");
        
        CLOG_LEAVEFN( "CWiFiProtDlgsPlugin::CmManagerToUse" );
        
        return iCmManagerExt;
        }
     else
        {
        CLOG_WRITE("Passed CmManagerExt used");
        
        CLOG_LEAVEFN( "CWiFiProtDlgsPlugin::CmManagerToUse" );
        
        return *iPassedCmManagerExt;
        }
    }

// --------------------------------------------------------------------------
// CWiFiProtDlgsPlugin::CWiFiProtDlgsPlugin()
// --------------------------------------------------------------------------
//
CWiFiProtDlgsPlugin::CWiFiProtDlgsPlugin()
: iCancelled( EFalse ),
  iResource( 0 ),
  iCancelledFromInside( EFalse )

    {
    CLOG_WRITE("CWiFiProtDlgsPlugin::CWiFiProtDlgsPlugin");
    }
    
// --------------------------------------------------------------------------
// void CWiFiProtDlgsPlugin::ConstructL( )
// --------------------------------------------------------------------------
//
void CWiFiProtDlgsPlugin::ConstructL(const TDesC& aResourceFileName,
                                     const TBool aResourceFileResponsible,
                                     RCmManagerExt* aCmManagerExt )
    {
    CLOG_ENTERFN( "CWiFiProtDlgsPlugin::ConstructL" );
    
    if ( aResourceFileResponsible )
        {
        // Since this is a .DLL, resource files that are to be used by the
        // notifier aren't added automatically so we do that here.
        TFileName fileName;

        fileName.Append( KDriveZ );
        fileName.Append( KDC_RESOURCE_FILES_DIR );   
        fileName.Append( aResourceFileName );

        BaflUtils::NearestLanguageFile( CCoeEnv::Static()->FsSession(),
                                        fileName );
        iResource = CCoeEnv::Static()->AddResourceFileL( fileName );
        }
    
    iPassedCmManagerExt = aCmManagerExt;
    //we didn't get a cmManager from the client, so use our own
    if (iPassedCmManagerExt == NULL)
        {
        iCmManagerExt.OpenL();
        }
    iRunner = CWiFiProtActiveRunner::NewL( this );
    
    CLOG_LEAVEFN( "CWiFiProtDlgsPlugin::ConstructL" );
    
    }

// End of File
