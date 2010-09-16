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
* %version: 41 %
*/

#include "EapServer.h"
#include "EapTraceSymbian.h"
#include <ecom.h>
#include "eap_automatic_variable.h"

/*
    class CEapServer
*/

//----------------------------------------------------------------------------

CEapServer::CEapServer()
    : CServer2(0, EGlobalSharableSessions) // //ESharableSessions
    {
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapServer::CEapServer(): this=0x%08x"),
		this));

	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapServer::CEapServer()"));
    }

//----------------------------------------------------------------------------

void CEapServer::ConstructL()
    {
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapServer::ConstructL(): start")));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    iIsValid = EFalse;
    iTools = abs_eap_am_tools_c::new_abs_eap_am_tools_c();

    // Check if creation went ok and the the iIsValid variable
    if (iTools == 0
		|| iTools->get_is_valid() == false)
	{
		if (iTools != 0)
		{
			iTools->am_cancel_all_timers();
		}
		abs_eap_am_tools_c::delete_abs_eap_am_tools_c(iTools);
		User::Leave(KErrNoMemory);
	}
	else
	{
		iIsValid = iTools->get_is_valid();
	}

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServer::ConstructL()");

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e status(eap_status_ok);

	{
		const u8_t DEFAULT_PREFIX[] = "EAP-SERVER";
		eap_variable_data_c tmp_prefix(iTools);

		if (tmp_prefix.get_is_valid() == false)
		{
			status = eap_status_allocation_error;
			(void) EAP_STATUS_RETURN(iTools, status);
		}

		if (status == eap_status_ok)
		{
			status = tmp_prefix.set_copy_of_buffer(DEFAULT_PREFIX, sizeof(DEFAULT_PREFIX)-1ul);;
			if (status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(iTools, status);
			}
		}

		if (status == eap_status_ok)
		{
			status = tmp_prefix.add_end_null();
			if (status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(iTools, status);
			}
		}

		if (status == eap_status_ok)
		{
			status = iTools->set_trace_prefix(&tmp_prefix);
			if (status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(iTools, status);
			}
		}
	}

	if (status != eap_status_ok)
	{
		iTools->am_cancel_all_timers();
		abs_eap_am_tools_c::delete_abs_eap_am_tools_c(iTools);
		User::Leave(KErrGeneral);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		TInt error;
		RFs aFileServerSession;

		// Open file server session
		EAP_TRACE_DEBUG(
			iTools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("CEapServer::ConstructL(): - calls aFileServerSession.Connect()\n")));

		error = aFileServerSession.Connect();

		EAP_TRACE_DEBUG(
			iTools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("CEapServer::ConstructL(): - aFileServerSession.Connect(), error=%d\n"),
			error));

		User::LeaveIfError(error);

		// Create the private path - it is not automatically created by Symbian OS.
		EAP_TRACE_DEBUG(
			iTools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("CEapServer::ConstructL(): - calls aFileServerSession.CreatePrivatePath(%d)\n"),
			RFs::GetSystemDrive()));

		error = aFileServerSession.CreatePrivatePath(RFs::GetSystemDrive());

		EAP_TRACE_DEBUG(
			iTools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("CEapServer::ConstructL(): - aFileServerSession.CreatePrivatePath(%d), error=%d\n"),
			RFs::GetSystemDrive(),
			error));

		User::LeaveIfError(error);

		// Set the session path to the private directory
		EAP_TRACE_DEBUG(
			iTools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("CEapServer::ConstructL(): - calls aFileServerSession.SetSessionToPrivate(%d)\n"),
			RFs::GetSystemDrive()));

		error = aFileServerSession.SetSessionToPrivate(RFs::GetSystemDrive());

		EAP_TRACE_DEBUG(
			iTools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("CEapServer::ConstructL(): - aFileServerSession.SetSessionToPrivate(%d), error=%d\n"),
			RFs::GetSystemDrive(),
			error));

		User::LeaveIfError(error);

		// Close the session with the file server.
		aFileServerSession.Close();
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    {
		// construct shutdown timer
		iShutdown = new(ELeave) CEapDelayedShutdown(iTools, this);
		iShutdown->ConstructL();
		// identify ourselves and open for service
		TBuf<KMaxServerExe> ServerName;
		TBuf<KMaxServerExe> ServerExe;
    
		GetServerNameAndExe(&ServerName, &ServerExe);

		StartL(ServerName);

		// Initiates shut down timer. Timer will close server unless we get client connections.
		iShutdown->Start();
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    {
		// construct backup and restore observer
		iBackupRestore = new(ELeave) CEapserverBackup(this);
		iBackupRestore->ConstructL();
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

   }

//----------------------------------------------------------------------------

CEapServer* CEapServer::NewL()
    {
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapServer::NewL(): starts")));

	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapServer::NewL()"));

    CEapServer* self = new(ELeave)CEapServer();
    CleanupStack::PushL(self);

    self->ConstructL();

    CleanupStack::Pop(self);

    return self;
    }

//----------------------------------------------------------------------------

CEapServer::~CEapServer()
	{
	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapServer::~CEapServer(): this=0x%08x\n"),
		this));

	// Do not use iTools, because it will be destroyed before return.
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapServer::~CEapServer()"));

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	TInt aCount = iReadyHandlers.Count();

	while (aCount > 0)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapServer::~CEapServer(): Removes iReadyHandlers[0]=0x%08x\n"),
			iReadyHandlers[0]));

		iReadyHandlers.Remove(0);

		aCount = iReadyHandlers.Count();
	}

	iReadyHandlers.Close();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	delete iShutdown;
	delete iBackupRestore;
	
	if (iTools) 
	{
		iTools->am_cancel_all_timers();
		abs_eap_am_tools_c::delete_abs_eap_am_tools_c(iTools);
	}

    EAP_TRACE_DEBUG_SYMBIAN((_L("REComSession::FinalClose(): start")));

	REComSession::FinalClose();

    EAP_TRACE_DEBUG_SYMBIAN((_L("REComSession::FinalClose(): ready")));

	}

//----------------------------------------------------------------------------

// from CServer

CSession2* CEapServer::NewSessionL(const TVersion& /* aVersion */, const RMessage2& /* aMessage */) const
    {
	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapServer::NewSessionL(): starts\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServer::NewSessionL()");

    CEapSession* session = new(ELeave) CEapSession();
    CleanupStack::PushL(session);

	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapServer::NewSessionL(): session=0x%08x\n"),
		session));

    EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapServer::NewSessionL(): session->ConstructL() starts")));

    session->ConstructL(*const_cast<CEapServer*>(this), iTools);

    EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapServer::NewSessionL(): session->ConstructL() ends")));

    CleanupStack::Pop(session);

    const_cast<CEapServer*>(this)->IncrementSessions();

	return session;
    }

//----------------------------------------------------------------------------

TInt CEapServer::RunError(TInt aErr)
    /**
       Handle leaves from ServiceL.

       Any leave from a ServiceL() will land up here.
    */
    {
	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapServer::RunError(), aErr=%d\n"),
		aErr));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServer::RunError()");

    // if it's a bad descriptor, panic the client
    if (aErr==KErrBadDescriptor)    // client had a bad descriptor
        {
        PanicClient(EBadDescriptor);
        }

    // anyway, complete the outstanding message
    Message().Complete(aErr);
    ReStart(); // really means just continue reading client requests
    return KErrNone;
    }

//----------------------------------------------------------------------------

/**
   session count support
*/
void CEapServer::IncrementSessions()
{   
	iSessionCount++;

	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapServer::IncrementSessions(): iSessionCount=%d\n"),
		iSessionCount));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServer::IncrementSessions()");

	iShutdown->Cancel();
}

//----------------------------------------------------------------------------

void CEapServer::DecrementSessions()
{
	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapServer::DecrementSessions(): iSessionCount=%d\n"),
		iSessionCount));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServer::DecrementSessions()");

	iSessionCount--;
	if (iSessionCount>0)
		return;

	iShutdown->Start();
}

//----------------------------------------------------------------------------

void CEapServer::PanicClient(TInt aPanic) const
{
	EAP_UNREFERENCED_PARAMETER(aPanic);
	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapServer::PanicClient(): aPanic=%d\n"),
		aPanic));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServer::PanicClient()");

	// let's have a look before we panic the client
	__DEBUGGER()
	// ok, go for it

	const TBufC<KMaxCategoryLength> aCategory; 
	Message().Panic(aCategory, EBadRequest);
}

//----------------------------------------------------------------------------

void CEapServer::StopL()
{
	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapServer::StopL()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServer::StopL()");

	for (iSessionIter.SetToFirst(); iSessionIter; iSessionIter++)
	{
		CSession2 * aSession = iSessionIter;

		EAP_TRACE_DEBUG(
			iTools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("CEapServer::StopL(): aSession=0x%08x calls CancelReceive()\n"),
			aSession));

		if (static_cast<CEapSession *>(aSession) != NULL)
			{
			static_cast<CEapSession *>(aSession)->CancelReceive();
			}
	}
}

//----------------------------------------------------------------------------

void CEapServer::BackupOrRestoreCompleteL()
{
	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("ERROR: CEapServer::BackupOrRestoreCompleteL(): Do something\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServer::BackupOrRestoreCompleteL()");
}

//----------------------------------------------------------------------------

void CEapServer::BackupOrRestoreStartingL()
{
	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("WARNING: CEapServer::BackupOrRestoreStartingL(): Terminates EAP-SERVER. All sessions are also closed. All files are unlocked for backup or restore.\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServer::BackupOrRestoreStartingL()");

    StopL();
}

// -----------------------------------------------------------------------------------------

TInt CEapServer::AddReadyHandler(CEapServerProcessHandler * const handler)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServer::AddReadyHandler(): this=0x%08x: handler=0x%08x\n"),
		this,
		handler));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServer::AddReadyHandler()");

	TInt aCount = iReadyHandlers.Count();

	if (aCount > 0)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapServer::AddReadyHandler(): this=0x%08x: iReadyHandlers[0]=0x%08x\n"),
			this,
			iReadyHandlers[0]));
	}

	TInt error = iReadyHandlers.Append(handler);
	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: CEapServer::AddReadyHandler(): Cannot append handler, error = %d\n"),
			error));
	}

	if (aCount == 0
		&& error == KErrNone)
	{
			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapServer::AddReadyHandler(): this=0x%08x: Activates handler=0x%08x\n"),
				this,
				handler));

		// Acticate the first handler.
		handler->Activate(EapServerProcessHandlerState_All);
	}

	return error;
}

// -----------------------------------------------------------------------------------------

TInt CEapServer::CompleteReadyHandler(CEapServerProcessHandler * const handler)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServer::CompleteReadyHandler(): this=0x%08x: handler=0x%08x\n"),
		this,
		handler));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServer::CompleteReadyHandler()");

	TInt aCount = iReadyHandlers.Count();

	TInt error(KErrNone);

	if (aCount == 0)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapServer::CompleteReadyHandler(): this=0x%08x, no handlers ready.\n"),
			this,
			handler));
	}
	else if (iReadyHandlers[0] != handler)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: CEapServer::CompleteReadyHandler(): this=0x%08x, handler=0x%08x is not the first one 0x%08x\n"),
			this,
			handler,
			iReadyHandlers[0]));

		error = KErrGeneral;
	}
	else
	{
		iReadyHandlers.Remove(0);

		aCount = iReadyHandlers.Count();

		if (aCount > 0)
		{
			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapServer::CompleteReadyHandler(): this=0x%08x, Activates handler=0x%08x\n"),
				this,
				iReadyHandlers[0]));

			// Activate the next handler.
			iReadyHandlers[0]->Activate(EapServerProcessHandlerState_All);
		}
	}

	return error;
}

// -----------------------------------------------------------------------------------------

TInt CEapServer::CancelReadyHandler(CEapServerProcessHandler * const handler)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServer::CancelReadyHandler(): this=0x%08x: handler=0x%08x\n"),
		this,
		handler));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServer::CancelReadyHandler()");

	TInt index(0);
	TInt aCount = iReadyHandlers.Count();

	while (index < aCount)
	{
		if (iReadyHandlers[index] != handler)
		{
			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapServer::CancelReadyHandler(): Removes iReadyHandlers[%d]=0x%08x\n"),
				index,
				iReadyHandlers[index]));

			iReadyHandlers.Remove(index);

			aCount = iReadyHandlers.Count();
		}
		else
		{
			++index;
		}
	} // while()

	return KErrNone;
}

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------

/*
    class CEapDelayedShutdown
*/

CEapDelayedShutdown::CEapDelayedShutdown(abs_eap_am_tools_c * const tools, CEapServer * const aServer)
    : CActive(0)
	, iTools(tools)
	, iServer(aServer)
    {
    }

//----------------------------------------------------------------------------

void CEapDelayedShutdown::ConstructL()
    {
	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapDelayedShutdown::ConstructL()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapDelayedShutdown::ConstructL()");

    CActiveScheduler::Add(this);
    User::LeaveIfError(iTimer.CreateLocal());
    }

//----------------------------------------------------------------------------

CEapDelayedShutdown::~CEapDelayedShutdown()
    {
	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapDelayedShutdown::~CEapDelayedShutdown()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapDelayedShutdown::~CEapDelayedShutdown()");

    Cancel();
    iTimer.Close();
    }

//----------------------------------------------------------------------------

void CEapDelayedShutdown::Start()
    {
	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapDelayedShutdown::Start()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapDelayedShutdown::Start()");

    iTimer.After(iStatus, KEapShutdownInterval);
    SetActive();
    }

//----------------------------------------------------------------------------

void CEapDelayedShutdown::DoCancel()
{
	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapDelayedShutdown::DoCancel()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapDelayedShutdown::DoCancel()");

	iTimer.Cancel();
}

//----------------------------------------------------------------------------

TInt CEapDelayedShutdown::RunError(TInt aError)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapDelayedShutdown::RunError(): aError=%d, this=0x%08x\n"),
		aError,
		this));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapDelayedShutdown::RunError()");

	iTimer.Cancel();

	return aError;
}

//----------------------------------------------------------------------------

void CEapDelayedShutdown::RunL()
{
	EAP_TRACE_DEBUG(
		iTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapDelayedShutdown::RunL(), calls CActiveScheduler::Stop()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapDelayedShutdown::RunL()");

	CActiveScheduler::Stop();
}

//----------------------------------------------------------------------------

// end
