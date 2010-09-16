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
* %version: 3.1.3 %
*/

#if !defined(_EAPOL_TIMER_H_)
#define _EAPOL_TIMER_H_

// INCLUDES
#include <e32base.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_VPN_IF_TIMER_H)
	#define EAP_CLASS_VISIBILITY_EAP_VPN_IF_TIMER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_VPN_IF_TIMER_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_VPN_IF_TIMER_H 
	#define EAP_FUNC_EXPORT_EAP_VPN_IF_TIMER_H 
	#define EAP_C_FUNC_EXPORT_EAP_VPN_IF_TIMER_H 
#elif defined(EAP_EXPORT_EAP_VPN_IF_TIMER_H)
	#define EAP_CLASS_VISIBILITY_EAP_VPN_IF_TIMER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_VPN_IF_TIMER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_VPN_IF_TIMER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_VPN_IF_TIMER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_VPN_IF_TIMER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_VPN_IF_TIMER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_VPN_IF_TIMER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_VPN_IF_TIMER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_VPN_IF_TIMER_H 
	#define EAP_C_FUNC_EXPORT_EAP_VPN_IF_TIMER_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_am_types.h"

// FORWARD DECLARATIONS
class abs_eap_am_tools_c;

// CLASS DECLARATION
class EAP_CLASS_VISIBILITY_EAP_VPN_IF_TIMER_H CEapVpnInterfaceTimer
: public CTimer
{
public:
	static CEapVpnInterfaceTimer* NewL(abs_eap_am_tools_c * const aTools);
	virtual ~CEapVpnInterfaceTimer();
	void StartTimer(const TUint aInterval);
	void StopTimer();
	TBool TimerRunning();
	void RunL();
	void DoCancel();
protected:
	CEapVpnInterfaceTimer(abs_eap_am_tools_c * const aTools);
	void ConstructL();
	
private:
	abs_eap_am_tools_c* const iTools;

	TUint iInterval;	

	u64_t iStartTime;
	u64_t iLastTime;

}; 

#endif //#if !defined(_EAPOL_TIMER_H_)

// End of file
