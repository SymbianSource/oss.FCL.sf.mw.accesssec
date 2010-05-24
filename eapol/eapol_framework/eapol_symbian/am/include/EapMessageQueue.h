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
* %version:  5 %
*/

#ifndef EAPMESSAGEQUEU_H_
#define EAPMESSAGEQUEU_H_

#include "EapServerClientDef.h"
#include "abs_eap_am_tools.h"
#include "eap_am_export.h"

class EAP_EXPORT EapMessageBuffer
{
public:

	EAP_FUNC_IMPORT EapMessageBuffer(abs_eap_am_tools_c * const tools);

	EAP_FUNC_IMPORT virtual ~EapMessageBuffer();

	EAP_FUNC_IMPORT TInt CopyData(TEapRequests type, const void * const data, const TUint length);

	EAP_FUNC_IMPORT HBufC8 * GetData() const;

	EAP_FUNC_IMPORT TEapRequests GetRequestType() const;

private:

	abs_eap_am_tools_c * const iTools;

	TEapRequests iRequestType;

	HBufC8 * iData;

};

    
class EAP_EXPORT EapMessageQueue
{
public:

	EAP_FUNC_IMPORT EapMessageQueue(abs_eap_am_tools_c * const tools);

	EAP_FUNC_IMPORT virtual ~EapMessageQueue();

	EAP_FUNC_IMPORT TInt AddMessage(TEapRequests type, const void * const data, const TUint length);

	EAP_FUNC_IMPORT EapMessageBuffer * GetFirstMessage();

	EAP_FUNC_IMPORT TInt DeleteFirstMessage();

private:

	abs_eap_am_tools_c * const iTools;

	RArray<EapMessageBuffer *> iEapMessageQueue;

};
    
#endif /* EAPMESSAGEQUEU_H_ */
