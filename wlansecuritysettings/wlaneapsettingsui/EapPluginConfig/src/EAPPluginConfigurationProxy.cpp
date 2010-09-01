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
* Description: Some functions that ECom needs.
*
*/

/*
* %version: 12 %
*/

// INCLUDE FILES
#include "EAPPluginConfiguration.h"
#include "EAPPluginConfigUid.h"

#include <e32base.h>
#include <ecom/implementationproxy.h>


const TImplementationProxy ImplementationTable[] = 
    {
    {{EAP_PLUGIN_CONFIG_IMPLEMENTATION_UID}, 
        reinterpret_cast<TProxyNewLPtr>( CEAPPluginConfiguration::NewL ) }
    };


// ================= OTHER EXPORTED FUNCTIONS ==============

// -----------------------------------------------------------------------------
// ImplementationGroupProxy
// -----------------------------------------------------------------------------
//
EXPORT_C const TImplementationProxy* ImplementationGroupProxy( 
                                                          TInt& aTableCount )
    {
    aTableCount = sizeof( ImplementationTable ) / 
                  sizeof( TImplementationProxy );

    return ImplementationTable;
    }


// End of file