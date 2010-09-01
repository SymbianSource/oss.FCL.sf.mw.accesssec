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
* %version: 9 %
*/

#ifndef _EAPSIMUISIMDATA_H_
#define _EAPSIMUISIMDATA_H_

#include <e32std.h>
#include <e32base.h>

const TInt KMaxLengthOfManualUsername = 255;
const TInt KMaxLengthOfManualRealm = 255;

class CEapSimUiSimData : public CBase
{
public:

    CEapSimUiSimData();

    ~CEapSimUiSimData();

    TDes& GetManualUsername();

    TDes& GetManualRealm();

    TBool * GetUseManualUsername();

    TBool * GetUseManualRealm();

private:

    TBuf<KMaxLengthOfManualUsername> iManualUsername;

    TBuf<KMaxLengthOfManualRealm> iManualRealm;

    TBool iUseManualUsername;

    TBool iUseManualRealm;
};

#endif