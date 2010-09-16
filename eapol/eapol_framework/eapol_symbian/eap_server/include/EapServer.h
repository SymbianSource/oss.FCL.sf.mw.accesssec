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
* Description:  EAP-server class.
*
*/

/*
* %version: 14 %
*/


#ifndef EAPAUTHSERVER_H_
#define EAPAUTHSERVER_H_

#include <e32base.h>
#include <e32svr.h>
#include <ecom/implementationinformation.h>
#include <ecom/ecom.h>
#include "EapServerClientDef.h"
#include "EapScheduler.h"
#include "EapSession.h"
#include "abs_eap_am_tools.h"
#include "EapClientIf.h"
#include "EapServerBackup.h"
#include "EapServerProcessHandler.h"

class CEapDelayedShutdown;

class CEapServer
: public CServer2
, public EapClientIf
, public AbsEapserverBackup
    {

public:

    // construct
    CEapServer();
    void ConstructL();
    static CEapServer* NewL();
    virtual ~CEapServer();
    // from CServer2
    CSession2* NewSessionL(const TVersion& aVersion, const RMessage2 &aMessage ) const;
    // session counting
    void IncrementSessions();
    void DecrementSessions();
    // utility
    void PanicClient(TInt aPanic) const;

	void StopL();

	void BackupOrRestoreCompleteL();

	void BackupOrRestoreStartingL();

	TInt AddReadyHandler(CEapServerProcessHandler * const handler);

	TInt CompleteReadyHandler(CEapServerProcessHandler * const handler);

	TInt CancelReadyHandler(CEapServerProcessHandler * const handler);

private:

    TInt RunError(TInt aErr);
    CEapDelayedShutdown* iShutdown;
	CEapserverBackup * iBackupRestore;

	RArray<CEapServerProcessHandler *> iReadyHandlers;

    TInt iSessionCount;
    abs_eap_am_tools_c * iTools;
    TBool iIsValid;
    };


// Handles timer that stops EAP-server after some idle time.
class CEapDelayedShutdown : public CActive
    {
public:
    CEapDelayedShutdown(abs_eap_am_tools_c * const tools, CEapServer * const aServer);
    void ConstructL();
    virtual ~CEapDelayedShutdown();
    void Start();
private:
    void DoCancel();
    void RunL();
	TInt RunError(TInt aError);

private:
	abs_eap_am_tools_c * const iTools;
    RTimer iTimer;
	CEapServer * const iServer;
    };


#endif /* EAPAUTHSERVER_H_ */
