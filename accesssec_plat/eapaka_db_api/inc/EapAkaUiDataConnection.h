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


#ifndef _EAPAKAUIDATACONNECTION_H_
#define _EAPAKAUIDATACONNECTION_H_

#include <e32base.h>
class CEapAkaUiConnection;
class CEapAkaUiAkaData;


class CEapAkaUiDataConnection : public CBase
{

public:

    CEapAkaUiDataConnection(CEapAkaUiConnection * aUiConn);

    ~CEapAkaUiDataConnection();

    TInt Open();

    TInt GetData(CEapAkaUiAkaData ** aDataPtr);

   	TInt Update();

    TInt Close();

protected:

    TBool iIsOpened;

    CEapAkaUiConnection * iUiConn;

    RDbNamedDatabase iDatabase;

    RDbView iView;

    CDbColSet* iColSet;

    CEapAkaUiAkaData * iDataPtr;

private:

    void FetchDataL();
};


#endif
