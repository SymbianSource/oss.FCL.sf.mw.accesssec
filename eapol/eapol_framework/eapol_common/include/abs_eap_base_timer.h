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

#if !defined(_ABS_EAP_BASE_TIMER_H_)
#define _ABS_EAP_BASE_TIMER_H_

#include "eap_status.h"
#include "eap_am_export.h"


/// An interface class of timer events.
/// Each class whishing to use timer must be derived from class abs_eap_base_timer_c.
class EAP_EXPORT abs_eap_base_timer_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the abs_eap_base_timer_c class does nothing special.
	 */
	virtual ~abs_eap_base_timer_c()
	{
	}

	/**
	 * The constructor of the abs_eap_base_timer_c class does nothing special.
	 */
	abs_eap_base_timer_c()
	{
	}

	/**
	 * Function timer_expired() is called after the timer is elapsed.
	 * @param id and data are set by caller of abs_eap_am_tools::set_timer() function.
	 * @param id could be used to separate different timer events.
	 * @param data could be pointer to any data that is needed in timer processing.
	 */
	virtual eap_status_e timer_expired(
		const u32_t id, void *data) = 0;

	/**
	 * This function is called when timer event is deleted.
	 * Initialiser of the data must delete the data.
	 * Only the initializer knows the real type of data.
	 * @param id could be used to separate different timer events.
	 * @param data could be pointer to any data that is needed in timer processing.
	 */
	virtual eap_status_e timer_delete_data(
		const u32_t id, void *data) = 0;

	//--------------------------------------------------
}; // class abs_eap_base_timer_c

#endif //#if !defined(_ABS_EAP_BASE_TIMER_H_)

//--------------------------------------------------



// End.
