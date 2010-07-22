/*
* Copyright (c) 2003 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: Active object timer for EAPOL.
*
*/

/*
* %version: %
*/

// INCLUDE FILES
#include "eap_am_memory.h"
#include "eap_vpn_if_timer.h"
#include "eap_tools.h"
#include "eap_am_tools.h"
#include "abs_eap_am_tools.h"
#include "abs_eap_am_mutex.h"
#include "eap_am_tools_symbian.h"

// ================= MEMBER FUNCTIONS =======================

CEapVpnInterfaceTimer::CEapVpnInterfaceTimer(abs_eap_am_tools_c * const aTools) 
: CTimer(CTimer::EPriorityStandard)
, iTools(aTools)
, iInterval(0)
, iStartTime(0)
, iLastTime(0)
{
	// Set a flag in EAPOL that specifies that timer queue can be used.
	reinterpret_cast<eap_am_tools_symbian_c *>(iTools)->set_use_timer_queue();
}


//--------------------------------------------------

void CEapVpnInterfaceTimer::ConstructL()
{
	CTimer::ConstructL();
}

//--------------------------------------------------

CEapVpnInterfaceTimer* CEapVpnInterfaceTimer::NewL(abs_eap_am_tools_c * const aTools)
{
	CEapVpnInterfaceTimer* self = new (ELeave) CEapVpnInterfaceTimer(aTools);
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop(self);
	return self;
}

//--------------------------------------------------

CEapVpnInterfaceTimer::~CEapVpnInterfaceTimer()
{
	Cancel();
}

//--------------------------------------------------

void CEapVpnInterfaceTimer::StartTimer(const TUint aInterval)
{	
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_TIMER_QUEUE,
		(EAPL("CEapVpnInterfaceTimer::StartTimer().\n")));

	iInterval = aInterval;
	iStartTime = iTools->get_clock_ticks();
	
	iLastTime = iStartTime;
	
	// Start the timer
	After(iInterval*1000);
}

//--------------------------------------------------
void CEapVpnInterfaceTimer::StopTimer()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_TIMER_QUEUE,
		(EAPL("CEapVpnInterfaceTimer::StopTimer().\n")));

	Cancel();
}
//--------------------------------------------------

TBool CEapVpnInterfaceTimer::TimerRunning()
{
	if (!IsActive())
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_TIMER_QUEUE,
			(EAPL("CEapVpnInterfaceTimer::TimerRunning(): EFalse.\n")));

		return EFalse;
	}
	else
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_TIMER_QUEUE,
			(EAPL("CEapVpnInterfaceTimer::TimerRunning(): ETrue.\n")));

		return ETrue;
	}
}

void CEapVpnInterfaceTimer::RunL()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_TIMER_QUEUE,
		(EAPL("CEapVpnInterfaceTimer::RunL().\n")));

	u64_t currentTime = iTools->get_clock_ticks();

	iLastTime = currentTime;

	u32_t next_sleep_time = iInterval;

	iTools->enter_global_mutex();
	if (iTools->get_is_timer_thread_active())
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_TIMER_QUEUE,
			(EAPL("CEapVpnInterfaceTimer::RunL(): pulse_timer().\n")));

		next_sleep_time = iTools->pulse_timer(next_sleep_time);
	}
	iTools->leave_global_mutex();

	// Setup timer again (if somebody inside pulse_timer has not already done it...)
	if (!IsActive())
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_TIMER_QUEUE,
			(EAPL("CEapVpnInterfaceTimer::RunL(): After().\n")));

		After(next_sleep_time*1000);
	}
	else
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_TIMER_QUEUE,
			(EAPL("CEapVpnInterfaceTimer::RunL(): is active.\n")));
	}
}
//--------------------------------------------------

void CEapVpnInterfaceTimer::DoCancel()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_TIMER_QUEUE,
		(EAPL("CEapVpnInterfaceTimer::DoCancel().\n")));

	  // Base class
	CTimer::DoCancel();
}

// End of file
