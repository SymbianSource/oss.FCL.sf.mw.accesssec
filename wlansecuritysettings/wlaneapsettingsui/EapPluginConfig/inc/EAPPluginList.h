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
* Description: Declaration of class REAPPluginList.
*
*/

/*
* %version: 11 %
*/

#ifndef __EAP_PLUGIN_LIST_H__
#define __EAP_PLUGIN_LIST_H__

// INCLUDES
#include <e32base.h>
#include "EAPPluginInfo.h"


// CLASS DECLARATION

/**
* Plugin info list.
*/
class REAPPluginList: public RArray<TEAPPluginInfo>
    {
    public:     // New methods
        /**
        * Change plugin position (reorder).
        * @param aOldPos Current position of plugin. Must be a valid index.
        * @param aOldPos New position of plugin. Must be a valid index.
        */
        void MovePos( TInt aOldPos, TInt aNewPos );
    };

#endif  // __EAP_PLUGIN_LIST_H__


//  End of File
