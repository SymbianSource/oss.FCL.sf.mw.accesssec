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
* %version: 5 %
*/

#ifndef ABSEAPSENDINTERFACE_H_
#define ABSEAPSENDINTERFACE_H_

#include "eap_am_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABSEAPSENDINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_ABSEAPSENDINTERFACE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABSEAPSENDINTERFACE_H 
	#define EAP_C_FUNC_VISIBILITY_ABSEAPSENDINTERFACE_H 
	#define EAP_FUNC_EXPORT_ABSEAPSENDINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_ABSEAPSENDINTERFACE_H 
#elif defined(EAP_EXPORT_ABSEAPSENDINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_ABSEAPSENDINTERFACE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABSEAPSENDINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABSEAPSENDINTERFACE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABSEAPSENDINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABSEAPSENDINTERFACE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABSEAPSENDINTERFACE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABSEAPSENDINTERFACE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABSEAPSENDINTERFACE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABSEAPSENDINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_ABSEAPSENDINTERFACE_H 
#endif
// End: added by script change_export_macros.sh.
#include "EapServerClientDef.h"

class EAP_CLASS_VISIBILITY_ABSEAPSENDINTERFACE_H AbsEapSendInterface
    {

private:

public:

    virtual ~AbsEapSendInterface()
        {
        }

    /// Function sends the data message to lower layer.
    /// Data is formatted to Attribute-Value Pairs.
    /// Look at eap_tlv_header_c and eap_tlv_message_data_c.
    virtual eap_status_e SendData(const void * const data, const u32_t length, TEapRequests message) = 0;

    };
#endif /* ABSEAPSENDINTERFACE_H_ */
