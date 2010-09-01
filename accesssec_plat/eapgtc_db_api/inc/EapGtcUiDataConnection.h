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

#ifndef _EAPGTCUIDATACONNECTION_H_
#define _EAPGTCUIDATACONNECTION_H_

#include <e32base.h>

class CEapGtcUiConnection;
class CEapGtcUiGtcData;


class CEapGtcUiDataConnection : public CBase
{

public:

    CEapGtcUiDataConnection(CEapGtcUiConnection * aUiConn);

    ~CEapGtcUiDataConnection();

    TInt Open();

    TInt GetData(CEapGtcUiGtcData ** aDataPtr);

   	TInt Update();

    TInt Close();

protected:

    TBool iIsOpened;

    CEapGtcUiConnection * iUiConn;

    RDbNamedDatabase iDatabase;

    RDbView iView;

    CDbColSet* iColSet;

    CEapGtcUiGtcData * iDataPtr;

private:

    void FetchDataL();
};


#endif
