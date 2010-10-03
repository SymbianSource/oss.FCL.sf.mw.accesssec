/*
* Copyright (c) 2009-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP-session inside EAP-server.
*
*/

/*
* %version: 34 %
*/


#define __REFERENCE_CAPABILITY_NAMES__
#define __INCLUDE_CAPABILITY_NAMES__

#include "EapSession.h"
#include "EapServerStrings.h"
#include "EapServer.h"
#include "EapServerProcessHandler.h"
#include "EapServerClientDef.h"
#include "abs_eap_am_tools.h"
#include "EapTraceSymbian.h"

#include "eap_automatic_variable.h"

/*
    CEapSession
*/

const TInt KMaxMessageLength = 1000000;

// -----------------------------------------------------------------------------------------

// construct/destruct

CEapSession::CEapSession()
: iReceiveActive(EFalse)
, iEapProcessHandler(0)
, iTools(0)
    {
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapSession::CEapSession(): this=0x%08x"),
		this));

	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapSession::CEapSession()"));

    }

// -----------------------------------------------------------------------------------------

void CEapSession::ConstructL(CEapServer& /* aServer */, abs_eap_am_tools_c * const tools)
    {
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::ConstructL(): this=0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(tools, "returns: CEapSession::ConstructL()");

    iTools = tools;

    iEapProcessHandler = CEapServerProcessHandler::NewL();
    iEapProcessHandler->ConstructL(this, iTools);
	CActiveScheduler::Add(iEapProcessHandler);
    }

// -----------------------------------------------------------------------------------------

CEapSession::~CEapSession()
    {
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::~CEapSession(): this=0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapSession::~CEapSession()");

    // cancel any receive
    CancelReceive();
    if (iEapProcessHandler != 0)
        {
        delete iEapProcessHandler;
        iEapProcessHandler = 0;
        }
    // decrement session count, so server may terminate if no longer needed
    Server()->DecrementSessions();
    }

// -----------------------------------------------------------------------------------------

CEapServer* CEapSession::Server() const
    /**
       Return the EAP-server.

       This deliberately hides the ugly casts around the code.
    */
    {
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::Server(): this=0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapSession::Server()");

    return const_cast<CEapServer*>(static_cast<const CEapServer*>(CSession2::Server()));
    }

// -----------------------------------------------------------------------------------------

void CEapSession::CheckCapabilityL(
	const RMessage2& aMessage,
	const TBool aMustHaveCapabilityWhenTrue,
	const TCapability aCapability,
	const char *aDiagnostic)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::CheckCapabilityL(): this=0x%08x: aMessage.Function()=%d=%s\n"),
		this,
		aMessage.Function(),
		EapServerStrings::GetEapRequestsString(aMessage.Function())));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapSession::CheckCapabilityL()");

	if (aMustHaveCapabilityWhenTrue != aMessage.HasCapability(aCapability, aDiagnostic))
	{
		// Capability check failed.
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: CEapSession::CheckCapability(): aMessage.Function()=%d=%s, failed capability check: %d=%s, %s\n"),
			aMessage.Function(),
			EapServerStrings::GetEapRequestsString(aMessage.Function()),
			aCapability,
			CapabilityNames[aCapability],
			aDiagnostic));
		Server()->PanicClient(EBadRequest);
		User::Leave(EBadRequest);
	}
	else
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapSession::CheckCapability(): aMessage.Function()=%d=%s, OK capability check: %d=%s\n"),
			aMessage.Function(),
			EapServerStrings::GetEapRequestsString(aMessage.Function()),
			aCapability,
			CapabilityNames[aCapability]));
	}
}

// -----------------------------------------------------------------------------------------

// service dispatcher - from CSharableSession

void CEapSession::ServiceL(const RMessage2& aMessage)
    {

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("-start--------------------------------------------------------------------\n")));

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::ServiceL(): this=0x%08x: starts, aMessage.Function()=%d=%s\n"),
		this,
		aMessage.Function(),
		EapServerStrings::GetEapRequestsString(aMessage.Function())));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapSession::ServiceL()");


	{
#if 0
		// Add this later.
		CheckCapabilityL(
			aMessage,
			ETrue,
			ECapabilityNetworkControl,
			"EAP-SERVER: Missing ECapabilityNetworkControl");
#endif

		CheckCapabilityL(
			aMessage,
			ETrue,
			ECapabilityReadDeviceData,
			"EAP-SERVER: Missing ECapabilityReadDeviceData");

		CheckCapabilityL(
			aMessage,
			ETrue,
			ECapabilityWriteDeviceData,
			"EAP-SERVER: Missing ECapabilityWriteDeviceData");
	}


	if (aMessage.Function() == EEapIfCancelReceive)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapSession::ServiceL(): aMessage.Function()=%d=%s, calls CancelReceive()\n"),
			aMessage.Function(),
			EapServerStrings::GetEapRequestsString(aMessage.Function())));
        CancelReceive();
		return;
	}

	// length of passed descriptor (1st parameter passed from client)
	TInt deslen = aMessage.GetDesLength(0);

	if (deslen > KMaxMessageLength)
	{
		Server()->PanicClient(EBadRequest);
		return;
	}

	// Passed data will be saved in this descriptor.
	RBuf8 buffer;

	// Max length set to the value of "deslen", but current length is zero
	buffer.CreateL(deslen);

	// Do the right cleanup if anything subsequently goes wrong
	buffer.CleanupClosePushL();

	// Copy the client's descriptor data into our buffer.
	aMessage.ReadL(0,buffer,0);

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::ServiceL(): calls buffer.Length()\n")));

	TUint aLength = buffer.Length();

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::ServiceL(): calls buffer.Ptr(): aLength=%d\n"),
		aLength));

	const void * aData = buffer.Ptr();

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::ServiceL(): aData=0x%08x, aLength=%d\n"),
		aData,
		aLength));

	EAP_TRACE_DATA_DEBUG(
		iTools,
		EAP_TRACE_FLAGS_NEVER,
		(EAPL("CEapSession::ServiceL()"),
		aData,
		aLength));

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::ServiceL(): switch aMessage.Function()=%d=%s, iEapProcessHandler=0x%08x\n"),
		aMessage.Function(),
		EapServerStrings::GetEapRequestsString(aMessage.Function()),
		iEapProcessHandler));


    switch (aMessage.Function())
        {
    case EEapCoreIfNew:
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapSession::ServiceL(): EEapCoreIfNew\n")));
        ReceiveAll();
        iEapProcessHandler->SaveMessage(EEapCoreIfNew, aData, aLength);
        aMessage.Complete(KErrNone);
        break;
    case EEapPluginNew:
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapSession::ServiceL(): EEapPluginNew\n")));
        iEapProcessHandler->SaveMessage(EEapPluginNew, aData, aLength);
        aMessage.Complete(KErrNone);
        break;
    case EEapSettingsNew:
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapSession::ServiceL(): EEapSettingsNew\n")));
        iEapProcessHandler->SaveMessage(EEapSettingsNew, aData, aLength);
        aMessage.Complete(KErrNone);
        break;
    case EEapPacStoreNew:
        EAP_TRACE_DEBUG(
            iTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("CEapSession::ServiceL(): EEapPacStoreNew\n")));
        iEapProcessHandler->SaveMessage(EEapPacStoreNew, aData, aLength);
        aMessage.Complete(KErrNone);
        break;
    case EWapiCoreIfNew:
        EAP_TRACE_DEBUG(
            iTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("CEapSession::ServiceL(): EWapiCoreIfNew\n")));
        ReceiveAll();
        iEapProcessHandler->SaveMessage(EWapiCoreIfNew, aData, aLength);
        aMessage.Complete(KErrNone);
        break;
    case EWapiSettingsNew:
        EAP_TRACE_DEBUG(
            iTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("CEapSession::ServiceL(): EWapiSettingsNew\n")));
        ReceiveAll();
        iEapProcessHandler->SaveMessage(EWapiSettingsNew, aData, aLength);
        aMessage.Complete(KErrNone);
        break;
    case EEapCoreProcessData:
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapSession::ServiceL(): EEapCoreProcessData\n")));
        // Read message
        iEapProcessHandler->SaveMessage(EEapCoreProcessData, aData, aLength);
        aMessage.Complete(KErrNone);
        break;
    case EEapPluginProcessData:
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapSession::ServiceL(): EEapPluginProcessData\n")));
        iEapProcessHandler->SaveMessage(EEapPluginProcessData, aData, aLength);
        aMessage.Complete(KErrNone);
        break;
    case EEapSettingsProcessData:
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapSession::ServiceL(): EEapSettingsProcessData\n")));
        iEapProcessHandler->SaveMessage(EEapSettingsProcessData, aData, aLength);
        aMessage.Complete(KErrNone);
        break;
    case EEapPacStoreProcessData:
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapSession::ServiceL(): EEapPacStoreProcessData\n")));
        iEapProcessHandler->SaveMessage(EEapPacStoreProcessData, aData, aLength);
        aMessage.Complete(KErrNone);
        break;
    case EWapiCoreProcessData:
        EAP_TRACE_DEBUG(
            iTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("CEapSession::ServiceL(): EWapiCoreProcessData\n")));
        iEapProcessHandler->SaveMessage(EWapiCoreProcessData, aData, aLength);
        aMessage.Complete(KErrNone);
        break;
    case EWapiSettingsProcessData:
        EAP_TRACE_DEBUG(
            iTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("CEapSession::ServiceL(): EWapiSettingsProcessData\n")));
        iEapProcessHandler->SaveMessage(EWapiSettingsProcessData, aData, aLength);
        aMessage.Complete(KErrNone);
        break;
    case EEapIfReqReceive: // TAny& aBuffer - async
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapSession::ServiceL(): EEapIfReqReceive, iReceiveMessage=0x%08x\n"),
			&iReceiveMessage));

        __ASSERT_DEBUG(!iReceiveActive, Server()->PanicClient(EReceiveReceiveAlreadyActive));

        // remember receive request
        iReceiveMessage = aMessage;
        iReceiveActive=ETrue;

		iEapProcessHandler->Activate(EapServerProcessHandlerState_Send);

        break;
    case EEapIfCancelReceive:
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapSession::ServiceL(): EEapIfCancelReceive\n")));
        CancelReceive();
        break;
    default:
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: CEapSession::ServiceL(): unknown aMessage.Function()=%d=%s, calls Server()->PanicClient()\n"),
			aMessage.Function(),
			EapServerStrings::GetEapRequestsString(aMessage.Function())));

		Server()->PanicClient(EBadRequest);
        };

	CleanupStack::PopAndDestroy(&buffer);

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::ServiceL(): ends aMessage.Function()=%d=%s\n"),
		aMessage.Function(),
		EapServerStrings::GetEapRequestsString(aMessage.Function())));

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("-end----------------------------------------------------------------------\n")));
    }

// -----------------------------------------------------------------------------------------

void CEapSession::ReceiveAll()
    {
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::ReceiveAll(): this=0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapSession::ReceiveAll()");

    }

// -----------------------------------------------------------------------------------------

void CEapSession::Receive(RMessage2& aBuffer)
    {
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::Receive(): this=0x%08x, iReceiveMessage=0x%08x\n"),
		this,
		&iReceiveMessage));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapSession::Receive()");

    __ASSERT_DEBUG(!iReceiveActive,Server()->PanicClient(EReceiveReceiveAlreadyActive));

    // remember receive request
    iReceiveMessage = aBuffer;
    iReceiveActive=ETrue;
    }

// -----------------------------------------------------------------------------------------

void CEapSession::CancelReceive()
    {
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::CancelReceive(): this=0x%08x, iReceiveMessage=0x%08x\n"),
		this,
		&iReceiveMessage));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapSession::CancelReceive()");

    if (!iReceiveActive)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapSession::CancelReceive(): No receive active\n")));
        return;
	}

    iReceiveMessage.Complete(KErrCancel);
    iReceiveActive=EFalse;
    }

// -----------------------------------------------------------------------------------------

TBool CEapSession::GetReceiveActive()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::GetReceiveActive(): this=0x%08x: iReceiveActive=%d\n"),
		this,
		iReceiveActive));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapSession::GetReceiveActive()");

	return iReceiveActive;
}

// -----------------------------------------------------------------------------------------

eap_status_e CEapSession::SendData(EapMessageBuffer * const message)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::SendData(): this=0x%08x: message->GetRequestType()=%d=%s, message->GetData()->Length()=%d\n"),
		this,
		message->GetRequestType(),
		EapServerStrings::GetEapRequestsString(message->GetRequestType()),
		message->GetData()->Length()));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapSession::SendData()");

	if (!iReceiveActive)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapSession::SendData(): No receive active\n")));
		return EAP_STATUS_RETURN(iTools, iTools->convert_am_error_to_eapol_error(KErrCancel));
	}

	TInt error(KErrNone);

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::SendData(): calls iReceiveMessage.Write()\n")));

	error = iReceiveMessage.Write(0, message->GetData()->Des());

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::SendData(): calls iReceiveMessage.Complete(): Write() error=%d, iReceiveMessage=0x%08x\n"),
		error,
		&iReceiveMessage));

	iReceiveMessage.Complete(KErrNone);
	iReceiveActive=EFalse;

	return EAP_STATUS_RETURN(iTools, iTools->convert_am_error_to_eapol_error(error));
}

// -----------------------------------------------------------------------------------------

TInt CEapSession::AddReadyHandler(CEapServerProcessHandler * const handler)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::AddReadyHandler(): this=0x%08x: handler=0x%08x\n"),
		this,
		handler));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapSession::AddReadyHandler()");

	return Server()->AddReadyHandler(handler);
}

// -----------------------------------------------------------------------------------------

TInt CEapSession::CompleteReadyHandler(CEapServerProcessHandler * const handler)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::CompleteReadyHandler(): this=0x%08x: handler=0x%08x\n"),
		this,
		handler));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapSession::CompleteReadyHandler()");

	return Server()->CompleteReadyHandler(handler);
}

// -----------------------------------------------------------------------------------------

TInt CEapSession::CancelReadyHandler(CEapServerProcessHandler * const handler)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapSession::CancelReadyHandler(): this=0x%08x: handler=0x%08x\n"),
		this,
		handler));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapSession::CancelReadyHandler()");

	return Server()->CancelReadyHandler(handler);
}

// -----------------------------------------------------------------------------------------
// end
