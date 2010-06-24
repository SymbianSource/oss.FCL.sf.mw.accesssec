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
* Description:  scheduler of EAP-server.
*
*/

/*
* %version: 18 %
*/

#include "EapScheduler.h"
#include "EapTraceSymbian.h"
#include "EapServer.h"

void CEapScheduler::TServerStart::SignalL()
//
// Signal the owning thread that the server has started successfully
// This may itself fail
//
    {
    EAP_TRACE_DEBUG_SYMBIAN((_L("TServerStart::SignalL()")));
    TBuf<KMaxServerExe> ServerName;
    TBuf<KMaxServerExe> ServerExe;
    
    //EapClientIf * aClientIf = new (ELeave)EapClientIf();
    
    GetServerNameAndExe(&ServerName, &ServerExe);
    TFindThread aProcess(ServerName);
    TFullName result;

   while(aProcess.Next(result) == KErrNone) 
      {
      RThread starter;
      User::LeaveIfError(starter.Open(aProcess));
      starter.RequestComplete(iStatus,KErrNone);
      starter.Close();
      }
    EAP_TRACE_DEBUG_SYMBIAN((_L("TServerStart::SignalL(): end")));           
    }

/*
    class CEapScheduler
*/

EAP_FUNC_EXPORT CEapScheduler* CEapScheduler::NewL()
    {
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapScheduler::NewL()")));

    CEapScheduler* self = new(ELeave)CEapScheduler();
    CleanupStack::PushL(self);

    TRequestStatus started;
    TServerStart start(started);

    self->ConstructL(start);

    CleanupStack::Pop(self);
    return self;

    }

EAP_FUNC_EXPORT TInt CEapScheduler::LaunchFromClient(const TBuf<KMaxServerExe> Server)
    {
    TRequestStatus started;
    TServerStart start(started);
    
    EAP_TRACE_DEBUG_SYMBIAN((_L("TServerStart::LaunchFromClient()")));           

    //
    // EPOC is easy, we just create a new server process. Simultaneous
    // launching of two such processes should be detected when the
    // second one attempts to create the server object, failing with
    // KErrAlreadyExists.
    //
    RProcess server;
    TInt r=server.Create(Server,KNullDesC);

    if (r!=KErrNone)
        {
        EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: TServerStart::LaunchFromClient(): server create error")));
        return r;
        }
    EAP_TRACE_DEBUG_SYMBIAN((_L("TServerStart::LaunchFromClient(): server created")));

    EAP_TRACE_DEBUG_SYMBIAN((_L("TServerStart::LaunchFromClient(): server.SetPriority(EPriorityHigh)")));
	server.SetPriority(EPriorityHigh);

    TRequestStatus stat;
    server.Rendezvous( stat );
    EAP_TRACE_DEBUG_SYMBIAN((_L("TServerStart::LaunchFromClient(): server.Rendezvous(), stat.Int()=%d"),
		stat.Int()));
    if ( stat!=KRequestPending )
        {
	    EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: TServerStart::LaunchFromClient(): server.Kill()")));
        server.Kill(0);     // abort startup
        }
    else
        {
	    EAP_TRACE_DEBUG_SYMBIAN((_L("TServerStart::LaunchFromClient(): server.Resume(), OK")));
        server.Resume();    // logon OK - start the server
        }
        
    
    User::WaitForRequest(stat);
    EAP_TRACE_DEBUG_SYMBIAN((_L("TServerStart::LaunchFromClient(): User::WaitForRequest(stat), stat.Int()=%d"),
		stat.Int()));

    r = ( server.ExitType()==EExitPanic ) ? KErrGeneral : stat.Int();

    server.Close();

    return r;
    }

EAP_FUNC_EXPORT TInt CEapScheduler::ThreadStart(TServerStart& aStart)
    {
    // get cleanup stack
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapScheduler::ThreadStart()")));           

#if defined(USE_EAP_HEAP_CHECK)
    __UHEAP_MARK;
#endif //#if defined(USE_EAP_HEAP_CHECK)

    CTrapCleanup* cleanup=CTrapCleanup::New();

    // initialize all up to and including starting scheduler
    TInt err = KErrNoMemory;
    if (cleanup)
		{
		TRAP(err, ConstructL(aStart));
		delete cleanup;
		}

#if defined(USE_EAP_HEAP_CHECK)
    __UHEAP_MARKEND;
#endif //#if defined(USE_EAP_HEAP_CHECK)

    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapScheduler::ThreadStart end err=%d"), err));           
    return err;
    }

void CEapScheduler::ConstructL(TServerStart& aStart)
    {
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapScheduler::ConstructL()")));           

    // construct active scheduler
    CEapScheduler* self=new(ELeave) CEapScheduler;
    CleanupStack::PushL(self);
    CActiveScheduler::Install(self);

    // construct server
    self->iServer=new(ELeave) CEapServer;
    self->iServer->ConstructL();

    // Let the client know we've started OK
    aStart.SignalL();

    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapScheduler::ThreadStart Rendezvous")));           
    RProcess::Rendezvous(KErrNone);
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapScheduler::ThreadStart Rendezvous end")));           

    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapScheduler::ConstructL(): CActiveScheduler::Start() starts")));
    CActiveScheduler::Start();
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapScheduler::ConstructL(): CActiveScheduler::Start() ends")));

    // Destroy the scheduler
    CleanupStack::PopAndDestroy(self);
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapScheduler::ConstructL(): end")));
    }

CEapScheduler::~CEapScheduler()
    {
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapScheduler::~CEapScheduler()")));

    delete iServer;
    }

void CEapScheduler::Error(TInt aError) const
    {
    EAP_UNREFERENCED_PARAMETER(aError);
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapScheduler::Error(): aError=%d"),
		aError));

    __DEBUGGER();
//    PanicServer(EErrorFromNonClientObject);
    }
