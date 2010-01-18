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
* Description: Implementation of ecom plugin
*
*/

/*
* %version: tr1cfwln#9 %
*/

// INCLUDE FILES
#include "eapnotifierdialoguiddefs.h"

#include <ecom/implementationproxy.h>
#include <AknNotifierWrapper.h> // link against aknnotifierwrapper.lib


// CONSTANTS
const TInt KMyPriority =  MEikSrvNotifierBase2::ENotifierPriorityLow;
const TInt KArrayGranularity = 4;
 

// ---------------------------------------------------------
// CleanupArray()
// ---------------------------------------------------------
//
void CleanupArray( TAny* aArray )
    {
    CArrayPtrFlat<MEikSrvNotifierBase2>*     
        subjects = static_cast<CArrayPtrFlat<MEikSrvNotifierBase2>*>( aArray );
    TInt lastInd = subjects->Count()-1;
    for ( TInt i = lastInd; i >= 0; i-- )
        {
        subjects->At( i )->Release();
        }

    delete subjects;
    }
    
    
// ---------------------------------------------------------
// DoCreateNotifierArrayL()
// ---------------------------------------------------------
//
CArrayPtr<MEikSrvNotifierBase2>* DoCreateNotifierArrayL()
    {
    CArrayPtrFlat<MEikSrvNotifierBase2>* subjects =
        new ( ELeave )CArrayPtrFlat<MEikSrvNotifierBase2>( KArrayGranularity );
    
    CleanupStack::PushL( TCleanupItem( CleanupArray, subjects ) );

    // Create Wrappers
    CAknCommonNotifierWrapper* master = NULL;

    // EAP-MSCHAPv2
    _LIT( KMsChapv2NotifierPluginName, "mschapv2notifdlg.dll" );
    master = CAknCommonNotifierWrapper::NewL( KUidMsChapv2Dialog,
                                              KUidMsChapv2Dialog,
                                              KMyPriority,
                                              KMsChapv2NotifierPluginName,
                                              1 );

    CleanupStack::PushL( master );   
    subjects->AppendL( master );
    CleanupStack::Pop( master );



    // EAP-GTC
    _LIT( KGtcNotifierPluginName, "gtcnotifdlg.dll" );

    // Session owning notifier(if default implementation is enough)
    master = CAknCommonNotifierWrapper::NewL( KUidGtcDialog,
                                         KUidGtcDialog,
                                         KMyPriority,
                                         KGtcNotifierPluginName,
                                         1 ); // we don't use synch reply

    CleanupStack::PushL( master );   
    subjects->AppendL( master );
    CleanupStack::Pop( master );

  
    // PAP
    _LIT( KPapNotifierPluginName, "papnotifdlg.dll" );
    master = CAknCommonNotifierWrapper::NewL( KUidPapDialog,
                                              KUidPapDialog,
                                              KMyPriority,
                                              KPapNotifierPluginName,
                                              1 );
                                              
    CleanupStack::PushL( master );   
    subjects->AppendL( master );
    CleanupStack::Pop( master );
                                                


#ifdef FF_WLAN_EXTENSIONS
    
    // EAP-LEAP
    _LIT( KLeapNotifierPluginName, "leapnotifdlg.dll" );
    master = CAknCommonNotifierWrapper::NewL( KUidLeapDialog,
                                              KUidLeapDialog,
                                              KMyPriority,
                                              KLeapNotifierPluginName,
                                              1 );

    CleanupStack::PushL( master );   
    subjects->AppendL( master );
    CleanupStack::Pop( master );

#endif
                                            
    CleanupStack::Pop();    // array cleanup
    
    return subjects;
    }


// ---------------------------------------------------------
// NotifierArray()
// ---------------------------------------------------------
//
CArrayPtr<MEikSrvNotifierBase2>* NotifierArray()
    // old Lib main entry point
    {
    CArrayPtr<MEikSrvNotifierBase2>* array = 0;
    TRAP_IGNORE( array = DoCreateNotifierArrayL() );
    return array;
    }


// ---------------------------------------------------------
// ImplementationTable
// ---------------------------------------------------------
//
const TImplementationProxy ImplementationTable[] =
    {
#ifdef __EABI__
    {{0x2000cf2f}, ( TFuncPtr )NotifierArray}
#else
    {{0x2000cf2f}, NotifierArray}
#endif
    };

// ---------------------------------------------------------
// ImplementationGroupProxy
// entry point
// ---------------------------------------------------------
//
EXPORT_C const TImplementationProxy* ImplementationGroupProxy( 
                                                            TInt& aTableCount )
    {
    aTableCount = sizeof( ImplementationTable ) / 
                  sizeof( TImplementationProxy ) ;
    return ImplementationTable;
    }


// End of File
