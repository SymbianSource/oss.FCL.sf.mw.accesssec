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
* %version: 11 %
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
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT EapMessageBuffer::~EapMessageBuffer()
{
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
		(EAPL("EapMessageBuffer::CopyData(): message=%d, data=0x%08x, length=%d\n"),
		message,
		data,
		length));

	EAP_TRACE_RETURN_STRING(iTools, "returns: EapMessageBuffer::CopyData()");

	iRequestType = message;

	TUint buffer_size = length;
	if (buffer_size == 0)
	{
		buffer_size = 1;
	}

	iData = HBufC8::New(buffer_size);

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
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT EapMessageQueue::~EapMessageQueue()
{
    DeleteFirstMessage();
	iEapMessageQueue.Close();
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapMessageQueue::AddMessage(TEapRequests message, const void * const data, const TUint length)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EapMessageQueue::AddMessage(): message=%d, data=0x%08x, length=%d, iEapMessageQueue.Count()=%d\n"),
		message,
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

		return error;
	}

	return error;
}

//----------------------------------------------------------------------------

EAP_FUNC_EXPORT EapMessageBuffer * EapMessageQueue::GetFirstMessage()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EapMessageQueue::GetFirstMessage()\n")));

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
		(EAPL("EapMessageQueue::DeleteFirstMessage()\n")));

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
// end

