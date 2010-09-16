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
* %version: 35 %
*/

#include "REapSession.h"
#include <e32base.h>
#include "EapTraceSymbian.h"
#include "EapCoreInterfaceImplementation.h"
#include "EapServerStrings.h"
#include "eap_automatic_variable.h"

//----------------------------------------------------------------

void Panic(TInt aPanic)
    {
    _LIT(KPanicCategory,"Eapol Client");
    User::Panic(KPanicCategory, aPanic);
    }

//----------------------------------------------------------------

TVersion REapSession::Version() const
    {
    return( TVersion(
            KEapMajorVersionNumber,
            KEapMinorVersionNumber,
            KEapBuildVersionNumber ) );
    }

//----------------------------------------------------------------

EAP_FUNC_EXPORT REapSession::~REapSession()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::~REapSession()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: REapSession::~REapSession()");

	delete iEapMessageQueue;
	iEapMessageQueue = 0;
}

//----------------------------------------------------------------

EAP_FUNC_EXPORT void REapSession::ConnectL(
	abs_eap_am_tools_c * const tools,
	MSendPacketHandler * Client,
	TBuf<KMaxServerExe> ServerName,
	TBuf<KMaxServerExe> ServerExe,
	const void * const aConfigurationData,
	const TInt aConfigurationDataLength,
	const TEapRequests aIfRequest)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::ConnectL()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: REapSession::ConnectL()");

	iClient = Client;
	iTools = tools;
	iEapMessageQueue = new(ELeave) EapMessageQueue(iTools);

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::ConnectL(): iEapMessageQueue=0x%08x\n"),
		iEapMessageQueue));


	// connect to iServer
	TInt error=KErrNone;


	TFindServer findServer(ServerName);
	TFullName name;

	error = findServer.Next( name );

	if ( error == KErrNone )
	{
		// Server already running
	}
	else
	{
		error = iServer.Create(ServerExe,KNullDesC);

		if (error != KErrNone)
		{
			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("REapSession::ConnectL(): create iServer error=%d\n"),
				error));
			User::Leave(error);
		}

		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("REapSession::ConnectL(): iServer successfully created\n")));

		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("REapSession::ConnectL(): iServer.SetPriority(EPriorityHigh)\n")));

		iServer.SetPriority(EPriorityHigh);

		TRequestStatus stat;

		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("REapSession::ConnectL(): iServer.Rendezvous\n")));

		iServer.Rendezvous( stat );

		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("REapSession::ConnectL(): iServer.Rendezvous stat = %d\n"),
			stat.Int()));

		if ( stat!=KRequestPending )
		{
			iServer.Kill(0);     // abort startup

			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: REapSession::ConnectL(): iServer killed\n")));
		}
		else
		{
			iServer.Resume();    // logon OK - start the iServer

			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("REapSession::ConnectL(): iServer started OK\n")));
		}


		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("REapSession::ConnectL(): WaitForRequest\n")));

		User::WaitForRequest(stat);

		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("REapSession::ConnectL(): WaitForRequest got, stat.Int()=%d\n"),
			stat.Int()));

		error = ( iServer.ExitType()==EExitPanic ) ? KErrGeneral : stat.Int();
		iServer.Close();

		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("REapSession::ConnectL(): Server closed, error=%d\n"),
			error));
	}


	// create active object receive handler and add it to scheduler
	CleanupClosePushL(*this);  // Close if next operations leave

	User::LeaveIfError(error);

	iSendHandler = new (ELeave) CSendHandler(iTools, *this); //*aHandler,
	CActiveScheduler::Add(iSendHandler);

	iProcessHandler = new (ELeave) CEapClientProcessHandler(iTools, *this); //*aHandler,
	CleanupStack::Pop(this);
	CActiveScheduler::Add(iProcessHandler);

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::ConnectL(): calls CreateSession()\n")));

	error = CreateSession(ServerName,Version(), KMaxEapMessageSlots);

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::ConnectL(): CreateSession(), error=%d\n"),
		error));

	if (error != KErrNone)
	{
		User::Leave(error);
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("REapSession::ConnectL(): calls process_data(%d)"),
		aIfRequest));

	eap_status_e status = process_data(aIfRequest, aConfigurationData, aConfigurationDataLength);

	EAP_TRACE_DEBUG_SYMBIAN((_L("REapSession::ConnectL(): process_data(%d) returns status=%d, iStatus.Int()=%d"),
		aIfRequest,
		status,
		iStatus.Int()));

	EAP_TRACE_DEBUG_SYMBIAN((_L("REapSession::ConnectL(): calls iSendHandler->Receive()")));

	iSendHandler->Receive();
}

//----------------------------------------------------------------

EAP_FUNC_EXPORT void REapSession::Close()
	{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::Close()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: REapSession::Close()");

	// destroy receiver-handler
	delete iSendHandler;
	iSendHandler = 0;

	delete iProcessHandler;
	iProcessHandler = 0;

	// destroy iServer session
	iServer.Close();
	RSessionBase::Close();
	}

//----------------------------------------------------------------

/**
 * From eap_am_message_if_c 
 * Initialize interface to EAPOL or WAPI.
 * @since S60 v9.2
 */

EAP_FUNC_EXPORT bool REapSession::get_is_valid()
    {
    EAP_TRACE_DEBUG_SYMBIAN((_L("REapSession::get_is_valid")));           
	EAP_TRACE_RETURN_STRING(iTools, "returns: REapSession::get_is_valid()");

    return ETrue;    
    }

//----------------------------------------------------------------

/// Function receives the data message from lower layer.
/// Data is formatted to Attribute-Value Pairs.
/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
EAP_FUNC_EXPORT eap_status_e REapSession::process_data(const TEapRequests aMessageType, const void * const data, const u32_t length)
    {
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::process_data(): calls iEapMessageQueue->AddMessage(): iEapMessageQueue=0x%08x\n"),
		iEapMessageQueue));

	EAP_TRACE_RETURN_STRING(iTools, "returns: REapSession::process_data()");

	EAP_TRACE_DATA_DEBUG(
		iTools,
		EAP_TRACE_FLAGS_NEVER,
		(EAPL("REapSession::process_data()"),
		data,
		length));

	TInt error = iEapMessageQueue->AddMessage(aMessageType, data, length);

	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: REapSession::process_data(): failed = %d\n"),
			error));
		return EAP_STATUS_RETURN(iTools, iTools->convert_am_error_to_eapol_error(error));
	}

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::process_data(): calls iProcessHandler->Activate(): iProcessHandler=0x%08x\n"),
		iProcessHandler));

	iProcessHandler->Activate();

    return EAP_STATUS_RETURN(iTools, iTools->convert_am_error_to_eapol_error(error));
    }

//----------------------------------------------------------------

void REapSession::Receive(TDes8& aBuffer, TRequestStatus& aStatus)
    {
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::Receive()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: REapSession::Receive()");

    TIpcArgs args( &aBuffer );

    SendReceive( EEapIfReqReceive, args, aStatus );
    }

//----------------------------------------------------------------

void REapSession::CancelReceive()
    {
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::CancelReceive()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: REapSession::CancelReceive()");

    SendReceive(EEapIfCancelReceive, iStatus);
    }

//----------------------------------------------------------------

const EapMessageBuffer * REapSession::GetFirstMessage()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::GetFirstMessage()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: REapSession::GetFirstMessage()");

	return iEapMessageQueue->GetFirstMessage();
}

//----------------------------------------------------------------

TInt REapSession::DeleteFirstMessage()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::DeleteFirstMessage()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: REapSession::DeleteFirstMessage()");

	return iEapMessageQueue->DeleteFirstMessage();
}

//----------------------------------------------------------------

void REapSession::Process(const EapMessageBuffer * const buffer, TRequestStatus &aStatus) const
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::Process(): calls SendReceive(), aRequestType=%d=%s\n"),
		buffer->GetRequestType(),
		EapServerStrings::GetEapRequestsString(buffer->GetRequestType())));

	EAP_TRACE_RETURN_STRING(iTools, "returns: REapSession::Process()");

	TIpcArgs args( buffer->GetData() );

	SendReceive(buffer->GetRequestType(), args, aStatus);

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("REapSession::Process(): end iStatus=%d\n"),
		iStatus.Int()));
}

//----------------------------------------------------------------
//----------------------------------------------------------------
//----------------------------------------------------------------

/*
    CSendHandler
*/

// construct/destruct

CSendHandler::CSendHandler(
	abs_eap_am_tools_c * const tools,
	REapSession& aSession)
    : CActive(0)
	, iTools(tools)
	, iSession(aSession)
    {
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CSendHandler::CSendHandler()\n")));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CSendHandler::CSendHandler()");

    }

//----------------------------------------------------------------

CSendHandler::~CSendHandler()
    {
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CSendHandler::~CSendHandler()\n")));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CSendHandler::~CSendHandler()");

    Cancel();
    }

//----------------------------------------------------------------

// operation

void CSendHandler::Receive()
    {
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CSendHandler::Receive()\n")));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CSendHandler::Receive()");

    iSession.Receive(iBuffer, iStatus);

	if(!IsActive())
		{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CSendHandler::Receive(): calls SetActive()\n")));

	    SetActive();
		}
    }

//----------------------------------------------------------------

// from CActive

void CSendHandler::RunL()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CSendHandler::RunL(): iStatus=%d\n"),
		iStatus.Int()));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CSendHandler::RunL()");

	if (iStatus.Int() == KErrNone)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CSendHandler::RunL(): iStatus = KErrNone, calls send_data()\n")));

		iSession.iClient->send_data(iBuffer);

		// initiate next receive
		Receive();
	}
	else if (iStatus.Int() == KErrCancel)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CSendHandler::RunL(): iStatus = KErrCancel, calls Close()\n")));

		iSession.Close();
	}
	else
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CSendHandler::RunL(): does nothing\n")));

	}
}

//----------------------------------------------------------------

void CSendHandler::DoCancel()
    {
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CSendHandler::DoCancel()\n")));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CSendHandler::DoCancel()");

    iSession.CancelReceive();
    }

//----------------------------------------------------------------------------

TInt CSendHandler::RunError(TInt aError)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CSendHandler::RunError(): aError=%d, this=0x%08x\n"),
		aError,
		this));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CSendHandler::RunError()");

	Cancel();

	return aError;
}

//----------------------------------------------------------------
//----------------------------------------------------------------
//----------------------------------------------------------------

void CEapolPacketHandler::EapolHandleL(const TDesC8& /* data */)
    {
    EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapolPacketHandler::EapolHandleL(): (do nothing now)")));           
    }

//----------------------------------------------------------------
//----------------------------------------------------------------
//----------------------------------------------------------------

CEapClientProcessHandler::CEapClientProcessHandler(
	abs_eap_am_tools_c * const tools,
	REapSession& aSession)
	: CActive(0)
	, iTools(tools)
	, iSession(aSession)
	, iProcessPending(false)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapClientProcessHandler::CEapClientProcessHandler()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapClientProcessHandler::CEapClientProcessHandler()");

}

//----------------------------------------------------------------

CEapClientProcessHandler::~CEapClientProcessHandler()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapClientProcessHandler::~CEapClientProcessHandler()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapClientProcessHandler::~CEapClientProcessHandler()");

	Cancel();
}

//----------------------------------------------------------------

// from CActive
void CEapClientProcessHandler::RunL()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("=start=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=\n")));

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapClientProcessHandler::RunL()\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapClientProcessHandler::RunL()");

	TInt error(KErrNone);

	if (iProcessPending == true)
	{
		error = iSession.DeleteFirstMessage();
		if (error != KErrNone)
		{
			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: CEapClientProcessHandler::RunL(): iSession.DeleteFirstMessage() failed = %d\n"),
				error));

			User::Leave(error);
		}
	}

	const EapMessageBuffer * buffer = iSession.GetFirstMessage();

	if (buffer != 0)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapClientProcessHandler::RunL(): calls SendReceive(), buffer->GetRequestType()=%d=%s\n"),
			buffer->GetRequestType(),
			EapServerStrings::GetEapRequestsString(buffer->GetRequestType())));

		TIpcArgs args( buffer->GetData() );

		iSession.Process( buffer, iStatus );

		SetActive();

		iProcessPending = true;
	}
	else
	{
		iProcessPending = false;
	}

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapClientProcessHandler::RunL(): end error=%d, iStatus=%d\n"),
		error,
		iStatus.Int()));

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("=end=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=c=\n")));
}

//----------------------------------------------------------------

void CEapClientProcessHandler::Activate()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapClientProcessHandler::Activate()\n")));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapClientProcessHandler::Activate()");

	if(!IsActive())
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapClientProcessHandler::Activate(): calls User::RequestComplete()\n")));

		TRequestStatus* status = &iStatus;
		User::RequestComplete(status, KErrNone);

		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapClientProcessHandler::Activate(): calls SetActive()\n")));

		SetActive();
	}
	else
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapClientProcessHandler::Activate(): Already active.\n")));
	}
}

//----------------------------------------------------------------

void CEapClientProcessHandler::DoCancel()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapClientProcessHandler::DoCancel()\n")));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapClientProcessHandler::DoCancel()");
}

//----------------------------------------------------------------------------

TInt CEapClientProcessHandler::RunError(TInt aError)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapClientProcessHandler::RunError(): aError=%d, this=0x%08x\n"),
		aError,
		this));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapClientProcessHandler::RunError()");

	Cancel();

	return aError;
}

//----------------------------------------------------------------
//----------------------------------------------------------------
//----------------------------------------------------------------

/*
    DLL harness
*/
#ifndef EKA2
EAP_FUNC_EXPORT TInt E32Dll(TDllReason)
    {
    return KErrNone;
    }
#endif

//----------------------------------------------------------------
// end

