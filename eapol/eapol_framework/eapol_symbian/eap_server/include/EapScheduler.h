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
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPSCHEDULER_H)
	#define EAP_CLASS_VISIBILITY_EAPSCHEDULER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPSCHEDULER_H 
	#define EAP_C_FUNC_VISIBILITY_EAPSCHEDULER_H 
	#define EAP_FUNC_EXPORT_EAPSCHEDULER_H 
	#define EAP_C_FUNC_EXPORT_EAPSCHEDULER_H 
#elif defined(EAP_EXPORT_EAPSCHEDULER_H)
	#define EAP_CLASS_VISIBILITY_EAPSCHEDULER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPSCHEDULER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPSCHEDULER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPSCHEDULER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPSCHEDULER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPSCHEDULER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPSCHEDULER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPSCHEDULER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPSCHEDULER_H 
	#define EAP_C_FUNC_EXPORT_EAPSCHEDULER_H 
#endif
// End: added by script change_export_macros.sh.


class CEapServer;

// -------------------------------------------------------------------------

class CEapScheduler
: public CActiveScheduler
, public EapClientIf
{

public:

	EAP_FUNC_VISIBILITY_EAPSCHEDULER_H static CEapScheduler* NewL();

	EAP_FUNC_VISIBILITY_EAPSCHEDULER_H static TInt LaunchFromClient(const TBuf<KMaxServerExe> Server);

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

    EAP_FUNC_VISIBILITY_EAPSCHEDULER_H static TInt ThreadStart(TServerStart& aSignal);

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
