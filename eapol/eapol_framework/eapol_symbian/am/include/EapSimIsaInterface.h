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
* %version: 6.1.3 %
*/

#ifndef _EAPSIMISAINTERFACE_H_
#define _EAPSIMISAINTERFACE_H_

// INCLUDES
#include <e32base.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPSIMISAINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_EAPSIMISAINTERFACE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPSIMISAINTERFACE_H 
	#define EAP_C_FUNC_VISIBILITY_EAPSIMISAINTERFACE_H 
	#define EAP_FUNC_EXPORT_EAPSIMISAINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_EAPSIMISAINTERFACE_H 
#elif defined(EAP_EXPORT_EAPSIMISAINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_EAPSIMISAINTERFACE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPSIMISAINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPSIMISAINTERFACE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPSIMISAINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPSIMISAINTERFACE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPSIMISAINTERFACE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPSIMISAINTERFACE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPSIMISAINTERFACE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPSIMISAINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_EAPSIMISAINTERFACE_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_tools.h"
#include "eap_am_type_gsmsim_symbian.h"
#include "isaapi.h"

// CLASS DECLARATION
/**
* Class (active object) that handles the communications with the SIM.
*/
class EAP_CLASS_VISIBILITY_EAPSIMISAINTERFACE_H CEapSimIsaInterface 
: public CActive
{
public:
	/**
	* Initialisation function.
	* @param aTools Tools class pointer.
	* @param aParent Pointer to the parent class.
	*/
	static CEapSimIsaInterface* NewL(
		abs_eap_am_tools_c* const aTools, 
		eap_am_type_gsmsim_symbian_c* const aParent);	

	/**
	* Destructor
	*/ 
	virtual ~CEapSimIsaInterface();

	/**
	* This function queries the IMSI from SIM. After the request has been completed
	* complete_SIM_imsi is called in the parent.
	*/
	void QueryIMSIL();

	/**
	* This function queries Kc and SRES from SIM. After the request has been completed
	* complete_SIM_kc_and_sres is called in the parent.
	* @param aRand Random value
	*/
	void QueryKcAndSRESL(const TDesC8& aRand);

	/**
	* Checks whether the device is in GSM online mode. Leaves with KErrNotSupported if
	* the device is in pda or flight mode.
	*/	
	void CheckSystemModeL();

protected:

	CEapSimIsaInterface(abs_eap_am_tools_c* const aTools, eap_am_type_gsmsim_symbian_c* const aParent);

	void ConstructL();
	
	void RunL();
	
	void DoCancel();

private:

	eap_am_type_gsmsim_symbian_c * const iParent;
	
	abs_eap_am_tools_c * const m_am_tools;
	
	/// ISA API handle
	RIsaApi iIsaApi;
	
	/// Buffer for received ISA API messages
	CPnMsg *iMsgReceiveBuffer;
	
	/// Buffer for sent ISA API messages
	CPnMsg *iMsgSendBuffer;
	
	TPnReceiveAllocationLengthPckg iMsgReceiveBufferLength;
	
	/// Stores the last queried IMSI
	eap_variable_data_c iLastIMSI;
}; 

#endif // _EAPSIMISAINTERFACE_H_

// End of file
