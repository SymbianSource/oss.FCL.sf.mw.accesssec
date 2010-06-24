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
* %version: 8.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 165 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


//#include "eap_test_timer.h"
#include "abs_eap_am_mutex.h"
#include "eap_am_tools_symbian.h"


LOCAL_C TInt mainL(TAny *lpParam)
{ 
	if (lpParam == 0)
	{
		return eap_status_process_general_error;
	}

	abs_eap_am_tools_c * const tools = reinterpret_cast<abs_eap_am_tools_c *>(lpParam);

	eap_status_e status = tools->timer_thread_function();
	return status;
} 


_LIT(K_eap_test_timer,"eap_test_timer");


EAP_FUNC_EXPORT eap_status_e eap_am_tools_symbian_c::start_timer_thread()
{ 
	EAP_TRACE_DEBUG(this, TRACE_FLAGS_DEFAULT, (EAPL("Create timer thread.\n")));

	RThread thread;

	set_use_timer_queue();

	TInt res=thread.Create(K_eap_test_timer,   // create new server thread
		mainL, // thread's main function
		KDefaultStackSize,
		KDefaultStackSize,
		KDefaultStackSize,
		this, // passed as TAny* argument to thread function
		EOwnerProcess 
		);

	if (res == KErrNone)
	{
		thread.SetPriority(EPriorityMuchMore);
		thread.Resume(); // start it going
	}
	else
	{
		thread.Close(); // therefore we've no further interest in it
		return eap_status_process_general_error;
	}
	return eap_status_ok;
}


EAP_FUNC_EXPORT eap_status_e eap_am_tools_symbian_c::stop_timer_thread()
{
	EAP_TRACE_DEBUG(this, TRACE_FLAGS_DEFAULT, (EAPL("Trigger timer thread stops.\n")));

	m_run_thread = false;

	bool sleep_more = true;

	sleep(0u);

	while(get_thread_stopped() == false)
	{
		sleep(get_timer_resolution_ms());
		sleep_more = false;
	}

	if (sleep_more == true)
	{
		// This is not absolute indication that the thread is really finished,
		// so we sleep a while to make it more probable.
		sleep(get_timer_resolution_ms());
	}

	EAP_TRACE_DEBUG(this, TRACE_FLAGS_DEFAULT, (EAPL("Trigger timer thread returns.\n")));
	return eap_status_ok;
}

// End.
