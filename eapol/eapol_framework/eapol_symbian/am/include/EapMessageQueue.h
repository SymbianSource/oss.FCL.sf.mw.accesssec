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
* %version:  8 %
*/

#ifndef EAPMESSAGEQUEU_H_
#define EAPMESSAGEQUEU_H_

#include "EapServerClientDef.h"
#include "abs_eap_am_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPMESSAGEQUEUE_H)
	#define EAP_CLASS_VISIBILITY_EAPMESSAGEQUEUE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H 
	#define EAP_C_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H 
	#define EAP_FUNC_EXPORT_EAPMESSAGEQUEUE_H 
	#define EAP_C_FUNC_EXPORT_EAPMESSAGEQUEUE_H 
#elif defined(EAP_EXPORT_EAPMESSAGEQUEUE_H)
	#define EAP_CLASS_VISIBILITY_EAPMESSAGEQUEUE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPMESSAGEQUEUE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPMESSAGEQUEUE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPMESSAGEQUEUE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPMESSAGEQUEUE_H 
	#define EAP_C_FUNC_EXPORT_EAPMESSAGEQUEUE_H 
#endif
// End: added by script change_export_macros.sh.

class EAP_CLASS_VISIBILITY_EAPMESSAGEQUEUE_H EapMessageBuffer
{
public:

	EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H EapMessageBuffer(abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H virtual ~EapMessageBuffer();

	EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H TInt CopyData(TEapRequests type, const void * const data, const TUint length);

	EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H HBufC8 * GetData() const;

	EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H TEapRequests GetRequestType() const;

private:

	abs_eap_am_tools_c * const iTools;

	TEapRequests iRequestType;

	HBufC8 * iData;

};

    
class EAP_CLASS_VISIBILITY_EAPMESSAGEQUEUE_H EapMessageQueue
{
public:

	EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H EapMessageQueue(abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H virtual ~EapMessageQueue();

	EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H TInt AddMessage(TEapRequests type, const void * const data, const TUint length);

	EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H EapMessageBuffer * GetFirstMessage();

	EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H TInt DeleteFirstMessage();

	EAP_FUNC_VISIBILITY_EAPMESSAGEQUEUE_H TInt DeleteFirstMessage(const EapMessageBuffer * const verify_message);

private:

	abs_eap_am_tools_c * const iTools;

	RArray<EapMessageBuffer *> iEapMessageQueue;

};
    
#endif /* EAPMESSAGEQUEU_H_ */
