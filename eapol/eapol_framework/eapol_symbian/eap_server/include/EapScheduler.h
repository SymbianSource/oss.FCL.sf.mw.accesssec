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
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: 10 %
*/


#ifndef EAPSCHEDULER_H_
#define EAPSCHEDULER_H_

#include "EapServerClientDef.h"
#include "abs_eap_am_tools.h"
#include "EapClientIf.h"
#include <e32math.h>

class CEapServer;

// -------------------------------------------------------------------------

class CEapScheduler
: public CActiveScheduler
, public EapClientIf
{

public:

	EAP_FUNC_IMPORT static CEapScheduler* NewL();

	EAP_FUNC_IMPORT static TInt LaunchFromClient(const TBuf<KMaxServerExe> Server);

	class TServerStart
	{

	public:

		TServerStart(TRequestStatus& aStatus);

		TPtrC AsCommand() const;

		inline TServerStart() {};

		void SignalL();

	private:

		TThreadId iId;

		TRequestStatus* iStatus;

	};

public:

#ifdef __WINS__
    static TInt ThreadFunction(TAny* aThreadParms);
#endif

    EAP_FUNC_IMPORT static TInt ThreadStart(TServerStart& aSignal);

    static void ConstructL(TServerStart& aStart);

    virtual ~CEapScheduler();

    void Error(TInt aError) const; // from CActiveScheduler

private:

    CEapServer* iServer;

};

// -------------------------------------------------------------------------

inline CEapScheduler::TServerStart::TServerStart(TRequestStatus& aStatus)
    : iId(RThread().Id())
	, iStatus(&aStatus)
{
	aStatus=KRequestPending;
}

// -------------------------------------------------------------------------

inline TPtrC CEapScheduler::TServerStart::AsCommand() const
{
	return TPtrC(reinterpret_cast<const TText*>(this),sizeof(TServerStart)/sizeof(TText));
}

// -------------------------------------------------------------------------

#endif /* EAPSCHEDULER_H_ */

// -------------------------------------------------------------------------
// End of file.
