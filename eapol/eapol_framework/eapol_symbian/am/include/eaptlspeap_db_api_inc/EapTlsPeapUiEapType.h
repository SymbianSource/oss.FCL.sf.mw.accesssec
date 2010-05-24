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

/*
* %version: %
*/

#ifndef _EAPTLSPEAPUIEAPTYPE_H_
#define _EAPTLSPEAPUIEAPTYPE_H_

#include <e32std.h>
#include "EapExpandedType.h"

class TEapTlsPeapUiEapType
: public CBase
{
public:

	TEapTlsPeapUiEapType()
	{
	}

	virtual ~TEapTlsPeapUiEapType()
	{
	}

	void SetIsEnabled(TBool aIsEnabled)
	{
		iIsEnabled = aIsEnabled;
	}

	void SetEapType(TEapExpandedType & aEapType)
	{
		iEapType = aEapType;
	}

	TBool GetIsEnabled()
	{
		return iIsEnabled;
	}

	TEapExpandedType & GetEapType()
	{
		return iEapType;
	}

private:

    TBool            iIsEnabled;
    TEapExpandedType iEapType;
};

#endif // _EAPTLSPEAPUIEAPTYPE_H_

// End of file
