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
* %version: 6.1.2 %
*/

#ifndef _EAPMSCHAPV2UIDATACONNECTION_H_
#define _EAPMSCHAPV2UIDATACONNECTION_H_

#include <e32base.h>

class CEapMsChapV2UiConnection;
class CEapMsChapV2UiMsChapV2Data;


class CEapMsChapV2UiDataConnection : public CBase
{

public:

    CEapMsChapV2UiDataConnection(CEapMsChapV2UiConnection * aUiConn);

    ~CEapMsChapV2UiDataConnection();

    TInt Open();

    TInt GetData(CEapMsChapV2UiMsChapV2Data ** aDataPtr);

   	TInt Update();

    TInt Close();

protected:

    TBool iIsOpened;

    CEapMsChapV2UiConnection * iUiConn;

    RDbNamedDatabase iDatabase;

    RDbView iView;

    CDbColSet* iColSet;

    CEapMsChapV2UiMsChapV2Data * iDataPtr;

private:

    void FetchDataL();
};


#endif
