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

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 164 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES
#include "eap_am_memory.h"
#include "EapolTimer.h"
#include "eap_tools.h"
#include "eap_am_tools.h"
#include "abs_eap_am_tools.h"
#include "abs_eap_am_mutex.h"
#include "eap_am_tools_symbian.h"

// ================= MEMBER FUNCTIONS =======================

CEapolTimer::CEapolTimer(abs_eap_am_tools_c * const aTools) 
: CTimer(CTimer::EPriorityStandard)
, iTools(aTools)
{
	// Set a flag in EAPOL that specifies that timer queue can be used.
	reinterpret_cast<eap_am_tools_symbian_c *>(iTools)->set_use_timer_queue();
}


//--------------------------------------------------

void CEapolTimer::ConstructL()
{
	CTimer::ConstructL();
}

//--------------------------------------------------

CEapolTimer* CEapolTimer::NewL(abs_eap_am_tools_c * const aTools)
{
	CEapolTimer* self = new (ELeave) CEapolTimer(aTools);
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop(self);
	return self;
}

//--------------------------------------------------

CEapolTimer::~CEapolTimer()
{
	Cancel();
}

//--------------------------------------------------

void CEapolTimer::StartTimer(const TUint aInterval)
{	
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_TIMER_QUEUE,
		(EAPL("CEapolTimer::StartTimer().\n")));

	iInterval = aInterval;
	iStartTime = iTools->get_clock_ticks();
	
	iLastTime = iStartTime;
	
	// Start the timer
	After(iInterval*1000);
}

//--------------------------------------------------
void CEapolTimer::StopTimer()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_TIMER_QUEUE,
		(EAPL("CEapolTimer::StopTimer().\n")));

	Cancel();
}
//--------------------------------------------------

TBool CEapolTimer::TimerRunning()
{
	if (!IsActive())
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_TIMER_QUEUE,
			(EAPL("CEapolTimer::TimerRunning(): EFalse.\n")));

		return EFalse;
	}
	else
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_TIMER_QUEUE,
			(EAPL("CEapolTimer::TimerRunning(): ETrue.\n")));

		return ETrue;
	}
}

void CEapolTimer::RunL()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_TIMER_QUEUE,
		(EAPL("CEapolTimer::RunL().\n")));

	u64_t currentTime = iTools->get_clock_ticks();

	iLastTime = currentTime;

	u32_t next_sleep_time = iInterval;

	iTools->enter_global_mutex();
	if (iTools->get_is_timer_thread_active())
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_TIMER_QUEUE,
			(EAPL("CEapolTimer::RunL(): pulse_timer().\n")));

		next_sleep_time = iTools->pulse_timer(next_sleep_time);
	}
	iTools->leave_global_mutex();

	// Setup timer again (if somebody inside pulse_timer has not already done it...)
	if (!IsActive())
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_TIMER_QUEUE,
			(EAPL("CEapolTimer::RunL(): After().\n")));

		After(next_sleep_time*1000);
	}
	else
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_TIMER_QUEUE,
			(EAPL("CEapolTimer::RunL(): is active.\n")));
	}
}
//--------------------------------------------------

void CEapolTimer::DoCancel()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_TIMER_QUEUE,
		(EAPL("CEapolTimer::DoCancel().\n")));

	  // Base class
	CTimer::DoCancel();
}

// End of file
