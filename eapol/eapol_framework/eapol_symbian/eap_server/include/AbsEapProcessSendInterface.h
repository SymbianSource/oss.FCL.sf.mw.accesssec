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
* %version: 8 %
*/

#ifndef ABSEAPPROCESSSENDINTERFACE_H_
#define ABSEAPPROCESSSENDINTERFACE_H_

#include "eap_am_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABSEAPPROCESSSENDINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_ABSEAPPROCESSSENDINTERFACE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABSEAPPROCESSSENDINTERFACE_H 
	#define EAP_C_FUNC_VISIBILITY_ABSEAPPROCESSSENDINTERFACE_H 
	#define EAP_FUNC_EXPORT_ABSEAPPROCESSSENDINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_ABSEAPPROCESSSENDINTERFACE_H 
#elif defined(EAP_EXPORT_ABSEAPPROCESSSENDINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_ABSEAPPROCESSSENDINTERFACE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABSEAPPROCESSSENDINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABSEAPPROCESSSENDINTERFACE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABSEAPPROCESSSENDINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABSEAPPROCESSSENDINTERFACE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABSEAPPROCESSSENDINTERFACE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABSEAPPROCESSSENDINTERFACE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABSEAPPROCESSSENDINTERFACE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABSEAPPROCESSSENDINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_ABSEAPPROCESSSENDINTERFACE_H 
#endif
// End: added by script change_export_macros.sh.

class EapMessageBuffer;
class CEapServerProcessHandler;

class EAP_CLASS_VISIBILITY_ABSEAPPROCESSSENDINTERFACE_H AbsEapProcessSendInterface
    {

private:

public:

    virtual ~AbsEapProcessSendInterface()
        {
        }

    /// Function sends the data message to lower layer.
    /// Data is formatted to Attribute-Value Pairs.
    /// Look at eap_tlv_header_c and eap_tlv_message_data_c.
    virtual eap_status_e SendData(EapMessageBuffer * const message) = 0;

	virtual TBool GetReceiveActive() = 0;

	virtual TInt AddReadyHandler(CEapServerProcessHandler * const handler) = 0;

	virtual TInt CompleteReadyHandler(CEapServerProcessHandler * const handler) = 0;

	virtual TInt CancelReadyHandler(CEapServerProcessHandler * const handler) = 0;

    };

#endif /* ABSEAPPROCESSSENDINTERFACE_H_ */
