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
* Description: Implementation of class CEAPPlugInConfigurationModel
*
*/



// INCLUDE FILES
#include "EAPPluginConfigurationModel.h"
#include "EAPPluginList.h"
#include <ecom/ecom.h>


// CONSTANTS

// Format text for MdcaPoint when Enabled
_LIT( KFormatEnabled, "%d\t%S\t%d\t" );

// Format text for MdcaPoint when Disabled
_LIT( KFormatDisabled, "\t%S\t\t" );


/**
* Maximum length of the formatted text excluding the name.
* (I.e. if the name is trimmed to this length, there will not be overflow.)
* Includes the formatting tabs (3), the icon index length (1) plus maximum
* length of an integer (11).
*/
LOCAL_D const TInt KMaxLenForEmptyName = 15;


// ============================ MEMBER FUNCTIONS ===============================

// ---------------------------------------------------------
// CEAPPluginConfigurationModel::MdcaCount
// ---------------------------------------------------------
//
TInt CEAPPluginConfigurationModel::MdcaCount() const
    {
    return iPlugins.Count();
    }


// ---------------------------------------------------------
// CEAPPluginConfigurationModel::MdcaPoint
// ---------------------------------------------------------
//
TPtrC16 CEAPPluginConfigurationModel::MdcaPoint( TInt aIndex ) const
    {
    // Oddly enough, MdcaPoint is const. We need to use MUTABLE_CAST.
    TInt maxName = EBufSize - KMaxLenForEmptyName;
    TPtrC name( iPlugins[aIndex].iInfo->DisplayName() );
    if ( name.Length() > maxName )
        {
        name.Set( name.Left( maxName ) );
        }

    if ( iPlugins[aIndex].iEnabled )
        {
        MUTABLE_CAST( TBuf<EBufSize>&, iBuf ).Format( KFormatEnabled, 
                                                      aIndex+1, &name, 0 );
        }
    else
        {
        MUTABLE_CAST( TBuf<EBufSize>&, iBuf ).Format( KFormatDisabled, &name );
        }

    return iBuf;
    }


// ---------------------------------------------------------
// CEAPPluginConfigurationModel::MdcaEnabledCount
// ---------------------------------------------------------
//
TInt CEAPPluginConfigurationModel::MdcaEnabledCount() const
    {
    TInt index;
    TInt nPlugins = MdcaCount();
    TInt numEnabled = 0;

    for ( index = 0; index < nPlugins; index++ )
        {
        if ( iPlugins[index].iEnabled )
            {
            numEnabled++;
            }
        }

    return numEnabled;
    }


//  End of File
