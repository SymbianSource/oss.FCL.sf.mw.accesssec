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
* Description: Implementation of base plugin.
*
*/


// INCLUDE FILES

#include "wifiprotplugin.h"
#include "wifiprotdlgsplugin.h"


// CONSTANTS

LOCAL_D const TInt KPluginGranularity = 4;

// FORWARD DECLARATIONS

LOCAL_C void CreateNotifiersL( 
                           CArrayPtrFlat<MEikSrvNotifierBase2>* aNotifiers );

// --------------------------------------------------------------------------
// NotifierArray()
// Lib main entry point
// --------------------------------------------------------------------------
//
EXPORT_C CArrayPtr<MEikSrvNotifierBase2>* NotifierArray()
    {
    
    CArrayPtrFlat<MEikSrvNotifierBase2>* array = NULL;
    TRAPD(err, array = new (ELeave) 
                   CArrayPtrFlat<MEikSrvNotifierBase2>( KPluginGranularity ));
    if (err || array == NULL)
        {
        return array;
        }
    TRAPD( err1, CreateNotifiersL( array ) );
    if( err1 )
        {
        TInt count = array->Count();
        while( count-- )
            {
            (*array)[count]->Release();
            }
        delete array;
        array = NULL;
        }

    return( array );
    }

// --------------------------------------------------------------------------
// CreateNotifiersL()
// --------------------------------------------------------------------------
//
LOCAL_C void CreateNotifiersL( 
                            CArrayPtrFlat<MEikSrvNotifierBase2>* aNotifiers )
    {
    MEikSrvNotifierBase2 *serNotify;
    TBool resourceFileResponsible = ETrue;

    serNotify = CWiFiProtDlgsPlugin::NewL( resourceFileResponsible );
    CleanupStack::PushL( serNotify );
    aNotifiers->AppendL( serNotify );
    CleanupStack::Pop( serNotify );
    }
    
// End of File
