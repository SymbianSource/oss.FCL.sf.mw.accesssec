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


#ifndef _EAPMSCHAPV2UIMSCHAPV2DATA_H_
#define _EAPMSCHAPV2UIMSCHAPV2DATA_H_

#include <e32std.h>
#include <e32base.h>

const TInt KMaxLengthOfUsername=255;
const TInt KMaxLengthOfPassword=255;

class CEapMsChapV2UiMsChapV2Data : public CBase
{
public:

    CEapMsChapV2UiMsChapV2Data();

    ~CEapMsChapV2UiMsChapV2Data();

    TDes& GetUsername();

    TDes& GetPassword();

    TBool * GetPasswordPrompt();

private:

    TBuf<KMaxLengthOfUsername> iUsername;

    TBuf<KMaxLengthOfPassword> iPassword;

    TBool iPasswordPrompt;
};

#endif
