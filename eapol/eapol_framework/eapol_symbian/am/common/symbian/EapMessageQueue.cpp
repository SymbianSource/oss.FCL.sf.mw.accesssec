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
* Description:  Message queue for EAP-server and -clients.
*
*/

/*
* %version: 16 %
*/


#include "EapMessageQueue.h"
#include "eap_am_tools.h"
#include "EapServerStrings.h"
#include "eap_automatic_variable.h"

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT EapMessageBuffer::EapMessageBuffer(abs_eap_am_tools_c * const tools)
	: iTools(tools)
	, iRequestType(EEapNone)
	, iData(0)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EapMessageBuffer::EapMessageBuffer(): this=0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(iTools, "returns: EapMessageBuffer::EapMessageBuffer()");
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT EapMessageBuffer::~EapMessageBuffer()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EapMessageBuffer::~EapMessageBuffer(): this=0x%08x, iData=0x%08x\n"),
		this,
		iData));

	EAP_TRACE_RETURN_STRING(iTools, "returns: EapMessageBuffer::~EapMessageBuffer()");

	iRequestType = EEapNone;
	delete iData;
	iData = 0;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapMessageBuffer::CopyData(TEapRequests message, const void * const data, const TUint length)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EapMessageBuffer::CopyData(): this=0x%08x, iData=0x%08x, message=%d, data=0x%08x, length=%d\n"),
		this,
		iData,
		message,
		data,
		length));

	EAP_TRACE_RETURN_STRING(iTools, "returns: EapMessageBuffer::CopyData()");

	iRequestType = message;

	TUint buffer_size = length;
	if (buffer_size == 0)
	{
		// Allocate at least one byte.
		++buffer_size;
	}

	delete iData;
	iData = HBufC8::New(buffer_size);

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EapMessageBuffer::CopyData(): this=0x%08x, iData=0x%08x\n"),
		this,
		iData));

	if (iData == 0)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: EapMessageBuffer::CopyData(): iData == 0\n")));

		return KErrNoMemory;
	}
	else
	{
		if (data != 0
		&& length > 0ul)
		{
			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EapMessageBuffer::CopyData(): copies data\n")));

			TPtr8 aDataPtr = iData->Des();
			aDataPtr.Copy(reinterpret_cast<const unsigned char*>(data), length);
		}
		else
		{
			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EapMessageBuffer::CopyData(): set length zero\n")));

			iData->Des().SetLength(0ul);
		}
	}

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EapMessageBuffer::CopyData(): ends\n")));

	return KErrNone;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT HBufC8 * EapMessageBuffer::GetData() const
{
	return iData;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT TEapRequests EapMessageBuffer::GetRequestType() const
{
	return iRequestType;
}

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------

EAP_FUNC_EXPORT EapMessageQueue::EapMessageQueue(abs_eap_am_tools_c * const tools)
	: iTools(tools)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EapMessageQueue::EapMessageQueue(): this=0x%08x, iEapMessageQueue.Count()=%d\n"),
		this,
		iEapMessageQueue.Count()));

	EAP_TRACE_RETURN_STRING(iTools, "returns: EapMessageQueue::EapMessageQueue()");

}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT EapMessageQueue::~EapMessageQueue()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EapMessageQueue::~EapMessageQueue(): this=0x%08x, iEapMessageQueue.Count()=%d\n"),
		this,
		iEapMessageQueue.Count()));

	EAP_TRACE_RETURN_STRING(iTools, "returns: EapMessageQueue::~EapMessageQueue()");

	TInt aCount = iEapMessageQueue.Count();

	while (aCount > 0)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EapMessageQueue::~EapMessageQueue(): Removes iEapMessageQueue[0].iRequestType=%d=%s, iEapMessageQueue.Count()=%d\n"),
			iEapMessageQueue[0]->GetRequestType(),
			EapServerStrings::GetEapRequestsString(iEapMessageQueue[0]->GetRequestType()),
			iEapMessageQueue.Count()));

		delete iEapMessageQueue[0];
		iEapMessageQueue.Remove(0);

		aCount = iEapMessageQueue.Count();
	}

	iEapMessageQueue.Close();
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapMessageQueue::AddMessage(TEapRequests message, const void * const data, const TUint length)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EapMessageQueue::AddMessage(): this=0x%08x, message=%d=%s, data=0x%08x, length=%d, iEapMessageQueue.Count()=%d\n"),
		this,
		message,
		EapServerStrings::GetEapRequestsString(message),
		data,
		length,
		iEapMessageQueue.Count()));

	EAP_TRACE_RETURN_STRING(iTools, "returns: EapMessageQueue::AddMessage()");

	EapMessageBuffer * const buffer = new EapMessageBuffer(iTools);

	if (buffer == 0)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: EapMessageQueue::AddMessage(): buffer == 0\n")));

		return KErrNoMemory;
	}

	TInt error = buffer->CopyData(message, data, length);
	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: EapMessageQueue::AddMessage(): buffer->CopyData() failed = %d\n"),
			error));

		delete buffer;

		return error;
	}

	error = iEapMessageQueue.Append(buffer);
	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: EapMessageQueue::AddMessage(): iEapMessageQueue.Append() failed = %d\n"),
			error));

		delete buffer;
	}

	return error;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT EapMessageBuffer * EapMessageQueue::GetFirstMessage()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EapMessageQueue::GetFirstMessage(): this=0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(iTools, "returns: EapMessageQueue::GetFirstMessage()");

	TInt aCount = iEapMessageQueue.Count();
	if (aCount > 0)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EapMessageQueue::GetFirstMessage(): iEapMessageQueue[0].iRequestType=%d=%s, iEapMessageQueue.Count()=%d\n"),
			iEapMessageQueue[0]->GetRequestType(),
			EapServerStrings::GetEapRequestsString(iEapMessageQueue[0]->GetRequestType()),
			iEapMessageQueue.Count()));

		return iEapMessageQueue[0];
	}
	else
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EapMessageQueue::GetFirstMessage(): Empty array\n")));
		return 0;
	}
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapMessageQueue::DeleteFirstMessage()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EapMessageQueue::DeleteFirstMessage(): this=0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(iTools, "returns: EapMessageQueue::DeleteFirstMessage()");

	TInt aCount = iEapMessageQueue.Count();
	if (aCount > 0)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EapMessageQueue::DeleteFirstMessage(): iEapMessageQueue[0].iRequestType=%d=%s, iEapMessageQueue.Count()=%d\n"),
			iEapMessageQueue[0]->GetRequestType(),
			EapServerStrings::GetEapRequestsString(iEapMessageQueue[0]->GetRequestType()),
			iEapMessageQueue.Count()));

		delete iEapMessageQueue[0];
		iEapMessageQueue.Remove(0);
	}
	else
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EapMessageQueue::DeleteFirstMessage(): Empty array\n")));
	}

	return KErrNone;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapMessageQueue::DeleteFirstMessage(const EapMessageBuffer * const verify_message)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EapMessageQueue::DeleteFirstMessage(0x%08x): this=0x%08x\n"),
		verify_message,
		this));

	EAP_TRACE_RETURN_STRING(iTools, "returns: EapMessageQueue::DeleteFirstMessage(verify_message)");

	TInt aCount = iEapMessageQueue.Count();
	if (aCount > 0)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EapMessageQueue::DeleteFirstMessage(): iEapMessageQueue[0].iRequestType=%d=%s, iEapMessageQueue.Count()=%d, iEapMessageQueue[0]=0x%08x, verify_message=0x%08x\n"),
			iEapMessageQueue[0]->GetRequestType(),
			EapServerStrings::GetEapRequestsString(iEapMessageQueue[0]->GetRequestType()),
			iEapMessageQueue.Count(),
			iEapMessageQueue[0],
			verify_message));

		if (iEapMessageQueue[0] == verify_message)
		{
			delete iEapMessageQueue[0];
			iEapMessageQueue.Remove(0);
		}
		else
		{
			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: EapMessageQueue::DeleteFirstMessage(0x%08x): this=0x%08x, does not delete other message\n"),
				verify_message,
				this));
		}
	}
	else
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("EapMessageQueue::DeleteFirstMessage(): Empty array\n")));
	}

	return KErrNone;
}

//----------------------------------------------------------------------------
// end

