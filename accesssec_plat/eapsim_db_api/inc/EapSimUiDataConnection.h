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

#ifndef _EAPSIMUIDATACONNECTION_H_
#define _EAPSIMUIDATACONNECTION_H_

#include <e32base.h>

class CEapSimUiConnection;
class CEapSimUiSimData;


class CEapSimUiDataConnection : public CBase
{

public:

    CEapSimUiDataConnection(CEapSimUiConnection * aUiConn);

    ~CEapSimUiDataConnection();

    TInt Open();

    TInt GetData(CEapSimUiSimData ** aDataPtr);

   	TInt Update();

    TInt Close();

protected:

    TBool iIsOpened;

    CEapSimUiConnection * iUiConn;

    RDbNamedDatabase iDatabase;

    RDbView iView;

    CDbColSet* iColSet;

    CEapSimUiSimData * iDataPtr;

private:

    void FetchDataL();
};


#endif
