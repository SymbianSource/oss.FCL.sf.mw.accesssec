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
* Description:  Message interface on client side.
*
*/

/*
* %version: 9 %
*/

#ifndef _EAP_AM_MESSAGE_IF_SYMBIAN_H_
#define _EAP_AM_MESSAGE_IF_SYMBIAN_H_

// INCLUDES
#include <e32std.h>
#include "REapSession.h"
#include "SendPacketHandler.h"
#include "EapSendInterface.h"
#include "abs_eap_am_tools.h"
#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "EapClientIf.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_MESSAGE_IF_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_MESSAGE_IF_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MESSAGE_IF_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_MESSAGE_IF_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_MESSAGE_IF_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MESSAGE_IF_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_MESSAGE_IF_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MESSAGE_IF_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.


class EapMessageBuffer;

/**
 * Message interface on client side.
 */
class EAP_CLASS_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H eap_am_message_if_symbian_c
: public eap_am_message_if_c
, public MSendPacketHandler
, public EapClientIf
{

public:

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Functions from CWlanEapolClient.

    /**
     * C++ default constructor.
     */
    EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H eap_am_message_if_symbian_c(
		abs_eap_am_tools_c * const tools,
		const TEapRequests if_request);

	/**
	 * Destructor.
	 */
    EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H virtual ~eap_am_message_if_symbian_c();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Functions from eap_am_message_if_c.

    EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H bool get_is_valid();

    EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H void set_partner(abs_eap_am_message_if_c * const client);

	/// Function receives the data message from lower layer.
	/// Data is formatted to Attribute-Value Pairs.
	/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
    EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H eap_status_e process_data(const void * const data, const u32_t length);

	// This is documented in abs_eap_stack_interface_c::configure().
    EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H eap_status_e configure(
		const eap_variable_data_c * const client_configuration);

	// This is documented in abs_eap_stack_interface_c::shutdown().
    EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H eap_status_e shutdown();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Functions from MSendPacketHandler.

	/// Function sends the data message to lower layer.
	/// Data is formatted to Attribute-Value Pairs.
	/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
    EAP_FUNC_VISIBILITY_EAP_AM_MESSAGE_IF_SYMBIAN_H eap_status_e send_data(const TDesC8& message);


private:

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	abs_eap_am_tools_c * const m_am_tools;

	abs_eap_am_message_if_c * m_partner;

	const TEapRequests m_if_request;

	REapSession iSession;

	bool m_is_valid;
	
};


#endif // _EAP_AM_MESSAGE_IF_SYMBIAN_H_

// End of file.
