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
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_TEST_STACK_IF_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_TEST_STACK_IF_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_TEST_STACK_IF_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_TEST_STACK_IF_H 
	#define EAP_FUNC_EXPORT_EAPOL_TEST_STACK_IF_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_TEST_STACK_IF_H 
#elif defined(EAP_EXPORT_EAPOL_TEST_STACK_IF_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_TEST_STACK_IF_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_TEST_STACK_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_TEST_STACK_IF_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_TEST_STACK_IF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_TEST_STACK_IF_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_TEST_STACK_IF_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_TEST_STACK_IF_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_TEST_STACK_IF_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_TEST_STACK_IF_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_TEST_STACK_IF_H 
#endif
// End: added by script change_export_macros.sh.



class EAP_CLASS_VISIBILITY_EAPOL_TEST_STACK_IF_H eapol_test_stack_if_c
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
