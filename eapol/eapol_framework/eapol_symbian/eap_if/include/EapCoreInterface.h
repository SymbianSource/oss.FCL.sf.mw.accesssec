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
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: 10 %
*/

#ifndef EAPCOREINTERFACE_H_
#define EAPCOREINTERFACE_H_


#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPCOREINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_EAPCOREINTERFACE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPCOREINTERFACE_H 
	#define EAP_C_FUNC_VISIBILITY_EAPCOREINTERFACE_H 
	#define EAP_FUNC_EXPORT_EAPCOREINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_EAPCOREINTERFACE_H 
#elif defined(EAP_EXPORT_EAPCOREINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_EAPCOREINTERFACE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPCOREINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPCOREINTERFACE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPCOREINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPCOREINTERFACE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPCOREINTERFACE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPCOREINTERFACE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPCOREINTERFACE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPCOREINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_EAPCOREINTERFACE_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "EapSendInterface.h"
#include "EapProcessInterface.h"
#include "EapServerClientDef.h"

class EAP_CLASS_VISIBILITY_EAPCOREINTERFACE_H CEapCoreInterface : 
    public CBase,
    public MEapSendInterface,
    public eap_am_message_if_c

    {
public:
    /**
     * Two-phased constructor.
     */
    EAP_FUNC_VISIBILITY_EAPCOREINTERFACE_H CEapCoreInterface(const u32_t MTU);
    
    /**
     * Destructor.
     */
    EAP_FUNC_VISIBILITY_EAPCOREINTERFACE_H virtual ~CEapCoreInterface();

public: // New functions
    
    /**
     * From eap_am_message_if_c 
     * Initialize interface to EAPOL or WAPI.
     * @since S60 v9.2
     */

    EAP_FUNC_VISIBILITY_EAPCOREINTERFACE_H bool get_is_valid();
 
    /// Function receives the data message from lower layer.
    /// Data is formatted to Attribute-Value Pairs.
    /// Look at eap_tlv_header_c and eap_tlv_message_data_c.
    EAP_FUNC_VISIBILITY_EAPCOREINTERFACE_H eap_status_e process_data(const void * const data, const u32_t length);

    // This is documented in abs_eap_stack_interface_c::configure().
    EAP_FUNC_VISIBILITY_EAPCOREINTERFACE_H eap_status_e configure(
		const eap_variable_data_c * const client_configuration);

    // This is documented in abs_eap_stack_interface_c::shutdown().
    EAP_FUNC_VISIBILITY_EAPCOREINTERFACE_H eap_status_e shutdown();

    EAP_FUNC_VISIBILITY_EAPCOREINTERFACE_H void set_partner(abs_eap_am_message_if_c * const client);
    
    /**
  * from MEapSendInterface 
     */
    EAP_FUNC_VISIBILITY_EAPCOREINTERFACE_H TInt SendData(
        const void * const aData, 
        const TInt aLength );

    EAP_FUNC_VISIBILITY_EAPCOREINTERFACE_H CEapProcessInterface* ConstrucL(abs_eap_am_tools_c * const tools );

private:
    
    
    abs_eap_am_message_if_c* iClient;
    TBool iIsValid;
    abs_eap_am_tools_c* iTools;
    CEapCoreInterface* iEapCoreInterface;
    CEapProcessInterface* iServer;
    TUint32 iMTU;
    };

#endif /* EAPCOREINTERFACE_H_ */
