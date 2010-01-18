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

#ifndef _EAPLEAPUIDATACONNECTION_H_
#define _EAPLEAPUIDATACONNECTION_H_

#include <e32base.h>

class CEapLeapUiConnection;
class CEapLeapUiLeapData;


class CEapLeapUiDataConnection : public CBase
{

public:

    CEapLeapUiDataConnection(CEapLeapUiConnection * aUiConn);

    ~CEapLeapUiDataConnection();

    TInt Open();

    TInt GetData(CEapLeapUiLeapData ** aDataPtr);

   	TInt Update();

    TInt Close();

protected:

    TBool iIsOpened;

    CEapLeapUiConnection * iUiConn;

    RDbNamedDatabase iDatabase;

    RDbView iView;

    CDbColSet* iColSet;

    CEapLeapUiLeapData * iDataPtr;

private:

    void FetchDataL();
};


#endif
