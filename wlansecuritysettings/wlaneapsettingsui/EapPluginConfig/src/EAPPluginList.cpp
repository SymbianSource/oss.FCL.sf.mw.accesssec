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
* Description: Implementation of class REAPPluginList.
*
*/



// INCLUDE FILES
#include "EAPPluginList.h"


// ============================ MEMBER FUNCTIONS ===============================

// ---------------------------------------------------------
// REAPPluginList::MovePos
// ---------------------------------------------------------
//
void REAPPluginList::MovePos( TInt aOldPos, TInt aNewPos )
    {
    TEAPPluginInfo temp;
    TInt i;
    if ( aNewPos > aOldPos )
        {
        temp = (*this)[aOldPos];
        for ( i = aOldPos; i < aNewPos; i++ )
            {
            (*this)[i] = (*this)[i + 1];
            }
        (*this)[aNewPos] = temp;
        }
    else if ( aNewPos < aOldPos )
        {
        temp = (*this)[aOldPos];
        for ( i = aOldPos; i > aNewPos; i-- )
            {
            (*this)[i] = (*this)[i - 1];
            }
        (*this)[aNewPos] = temp;
        }
    }


//  End of File
