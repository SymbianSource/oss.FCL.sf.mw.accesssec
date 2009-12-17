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


#ifndef _EAPTLSPEAPUIEAPTYPE_H_
#define _EAPTLSPEAPUIEAPTYPE_H_

#include <e32std.h>

class TEapTlsPeapUiEapType
{
public:
    TBool		iIsEnabled;        
    TBuf8<8>  	iEapType;      // UID of Expanded EAP type.
};

#endif // _EAPTLSPEAPUIEAPTYPE_H_

// End of file
