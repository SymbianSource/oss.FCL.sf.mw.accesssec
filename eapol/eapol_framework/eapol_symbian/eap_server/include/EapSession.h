/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP-session inside the EAP-server.
*
*/

/*
* %version: 17 %
*/


#ifndef EAPSESSION_H_
#define EAPSESSION_H_

#include <e32base.h>
#include <e32svr.h>
#include <ecom/implementationinformation.h>
#include <ecom/ecom.h>
#include "AbsEapProcessSendInterface.h"


class CEapServer;
class CEapServerProcessHandler;
class EapMessageBuffer;

class CEapSession
: public CSession2
, public AbsEapProcessSendInterface
    {

public:

    CEapSession();

    void ConstructL(CEapServer& aServer, abs_eap_am_tools_c * const tools);

    virtual ~CEapSession();

    // service dispatcher - from CSession2
    void ServiceL(const RMessage2& aMessage);

    void ReceiveAll();

    void Receive(RMessage2& aBuffer);

    void CancelReceive();

    eap_status_e SendData(EapMessageBuffer * const message);

	TBool GetReceiveActive();

	TInt AddReadyHandler(CEapServerProcessHandler * const handler);

	TInt CompleteReadyHandler(CEapServerProcessHandler * const handler);

	TInt CancelReadyHandler(CEapServerProcessHandler * const handler);

private:

    CEapServer* Server() const;

	void CheckCapabilityL(
		const RMessage2& aMessage,
		const TBool aMustHaveCapabilityWhenTrue,
		const TCapability aCapability,
		const char *aDiagnostic);

    // receive support
    TBool iReceiveActive;

    RMessage2 iReceiveMessage;

    CEapServerProcessHandler* iEapProcessHandler;

    TRequestStatus iStatus;

    abs_eap_am_tools_c * iTools;
    };

#endif /* EAPSESSION_H_ */
