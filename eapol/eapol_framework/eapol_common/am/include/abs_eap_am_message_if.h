/*
* Copyright (c) 2001-2006 Nokia Corporation and/or its subsidiary(-ies).
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
* %version: %
*/

#if !defined(_ABS_EAP_AM_MESSAGE_IF_H_)
#define _ABS_EAP_AM_MESSAGE_IF_H_

#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_MESSAGE_IF_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_MESSAGE_IF_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_MESSAGE_IF_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_MESSAGE_IF_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_MESSAGE_IF_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_MESSAGE_IF_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_MESSAGE_IF_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_MESSAGE_IF_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_MESSAGE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_MESSAGE_IF_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_MESSAGE_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_MESSAGE_IF_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_MESSAGE_IF_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_MESSAGE_IF_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_MESSAGE_IF_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_MESSAGE_IF_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_MESSAGE_IF_H 
#endif
// End: added by script change_export_macros.sh.

//--------------------------------------------------

/** @file */

/// This class is abstract interface to send data messages through abstract interface.
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_MESSAGE_IF_H abs_eap_am_message_if_c
{

private:
	//--------------------------------------------------

	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~abs_eap_am_message_if_c()
	{
	}

	/// Function sends the data message to lower layer.
	/// Data is formatted to Attribute-Value Pairs.
	/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
	virtual eap_status_e send_data(const void * const data, const u32_t length) = 0;

}; // class abs_eap_am_message_if_c


#endif //#if !defined(_ABS_EAP_AM_MESSAGE_IF_H_)

//--------------------------------------------------


// End.
