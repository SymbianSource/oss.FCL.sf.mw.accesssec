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
* Description: Declaration of class TEAPPluginInfo.
*
*/

/*
* %version: 11 %
*/

#ifndef __EAPPLUGININFO_H__
#define __EAPPLUGININFO_H__

// INCLUDES
#include <e32base.h>


// FORWARD DECLARATIONS
class CImplementationInformation;


// CLASS DECLARATION

/**
* Information for EAP plug-ins.
*/
struct TEAPPluginInfo
    {
    public:     // Data 
        const CImplementationInformation* iInfo;    ///< Impl. info. Not own.
        TBool iEnabled;                             ///< ETrue if enabled.
    };

#endif  // __EAPPLUGININFO_H__

//  End of File
