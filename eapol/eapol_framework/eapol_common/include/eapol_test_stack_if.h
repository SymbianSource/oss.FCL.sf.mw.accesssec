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

#if !defined(_EAPOL_TEST_STACK_IF_H_)
#define _EAPOL_TEST_STACK_IF_H_

#include "eap_header.h"
#include "eap_array.h"


class EAP_EXPORT eapol_test_stack_if_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~eapol_test_stack_if_c()
	{
	}

	// 
	eapol_test_stack_if_c()
	{
	}

	virtual eap_status_e packet_process(
		const eap_am_network_id_c * const receive_network_id,
		eap_general_header_base_c * const packet_data,
		const u32_t packet_length) = 0;

	virtual u32_t get_wrong_send_packet_index() = 0;

	virtual void reset_authentication_can_succeed() = 0;

	virtual void set_authentication_can_succeed() = 0;

	virtual void restore_authentication_can_succeed() = 0;

	virtual void set_authentication_must_not_succeed(
        const u32_t wrong_packet_index,
        const u32_t packet_index,
        const void * const wrong_packet_stack) = 0;

	//--------------------------------------------------
}; // class eapol_test_stack_if_c

#endif //#if !defined(_EAPOL_TEST_STACK_IF_H_)

//--------------------------------------------------



// End.
