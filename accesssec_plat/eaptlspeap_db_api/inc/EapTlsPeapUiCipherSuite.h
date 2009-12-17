/*
* Copyright (c) 2001-2006 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP and WLAN authentication protocols.
*
*/


#ifndef _EAPTLSPEAPUICIPHERSUITE_H_
#define _EAPTLSPEAPUICIPHERSUITE_H_

#include <e32std.h>

class TEapTlsPeapUiCipherSuite
{
public:

    TBool                           iIsEnabled;        
    TUint							iCipherSuite;
};

#endif //_EAPTLSPEAPUICIPHERSUITE_H_

// End of file
