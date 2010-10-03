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
* %version: 12 %
*/

#ifndef EAP_CORE_INTERFACE_IMPLEMENTATION_H_
#define EAP_CORE_INTERFACE_IMPLEMENTATION_H_

// INCLUDES
#include <e32std.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPCOREINTERFACEIMPLEMENTATION_H)
	#define EAP_CLASS_VISIBILITY_EAPCOREINTERFACEIMPLEMENTATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPCOREINTERFACEIMPLEMENTATION_H 
	#define EAP_C_FUNC_VISIBILITY_EAPCOREINTERFACEIMPLEMENTATION_H 
	#define EAP_FUNC_EXPORT_EAPCOREINTERFACEIMPLEMENTATION_H 
	#define EAP_C_FUNC_EXPORT_EAPCOREINTERFACEIMPLEMENTATION_H 
#elif defined(EAP_EXPORT_EAPCOREINTERFACEIMPLEMENTATION_H)
	#define EAP_CLASS_VISIBILITY_EAPCOREINTERFACEIMPLEMENTATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPCOREINTERFACEIMPLEMENTATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPCOREINTERFACEIMPLEMENTATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPCOREINTERFACEIMPLEMENTATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPCOREINTERFACEIMPLEMENTATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPCOREINTERFACEIMPLEMENTATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPCOREINTERFACEIMPLEMENTATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPCOREINTERFACEIMPLEMENTATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPCOREINTERFACEIMPLEMENTATION_H 
	#define EAP_C_FUNC_EXPORT_EAPCOREINTERFACEIMPLEMENTATION_H 
#endif
// End: added by script change_export_macros.sh.
#include "EapProcessInterface.h"
#include "REapSession.h"
#include "SendPacketHandler.h"
#include "EapSendInterface.h"
#include "abs_eap_am_tools.h"
#include "EapClientIf.h"

class MEapSendInterface;
class EapMessageBuffer;


/**
 * Implementation for MWlanEapolInterface interface.
 *
 * @lib wlaneapolif.dll
 * @since S60 v3.2
 */
class EAP_CLASS_VISIBILITY_EAPCOREINTERFACEIMPLEMENTATION_H CEapCoreInterfaceImplementation
: public CEapProcessInterface
, public MSendPacketHandler
, public EapClientIf
{

public:

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Functions from CWlanEapolClient.

	/**
	 * Static constructor.
	 * @param aPartner Pointer to callback instance.
	 * @return Pointer to the constructed instance.
	 */
	static CEapProcessInterface* NewL(MEapSendInterface * aPartner);


	/**
	 * Destructor.
	 */
	virtual ~CEapCoreInterfaceImplementation();

	/**
	 * Configure plugin implementation.
	 *
	 * @since S60 v3.2
	 * @param aHeaderOffset Offset of EAP-header in packet_send.
	 * @param aMTU Maximum transfer unit (MTU).
	 * @param aTrailerLength Length of trailer needed by lower levels..
	 * @return Return value is specified in interface specification.
	 */
	TInt Configure(
		const TInt aHeaderOffset,
		const TInt aMTU,
		const TInt aTrailerLength,
		const void * const aConfigurationData,
		const TInt aConfigurationDataLength);

	TInt SetEnv(abs_eap_am_tools_c * const tools, const u32_t MTU);
	 
	/**
	 * Shutdown plugin implementation.
	 *
	 * @since S60 v3.2
	 * @return Return value is specified in interface specification.
	 */        
	TInt Shutdown();

	/**
	 * Send data to EAPOL.
	 *
	 * @since S60 v3.2
	 * @param aData Pointer to the data to be sent.
	 * @param aLength Length of the data to be sent.
	 * @return Return value is specified in interface specification.
	 */
	TInt ProcessData(
		const void * const aData, 
		const TInt aLength );

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Functions from MSendPacketHandler.

	/// Function sends the data message to lower layer.
	/// Data is formatted to Attribute-Value Pairs.
	/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
	eap_status_e send_data(const TDesC8& message);


private:

    /**
     * C++ default constructor.
     */
    CEapCoreInterfaceImplementation();

    /**
     * Symbian 2nd phase constructor.
     */
    void ConstructL(MEapSendInterface * aPartner);

	/**
	 * The get_is_valid() function returns the status of the CEapCoreInterfaceImplementation object.
	 * @return True indicates the object is initialized.
	 */
	bool get_is_valid();
	
//	eap_status_e SendData(const void * const data, const u32_t length);
	
//	static TInt GetServerNameAndExe(TBuf<KMaxServerExe> * const ServerName, TBuf<KMaxServerExe> * const ServerExe);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	MEapSendInterface * m_partner;

	REapSession iSession;

	bool m_is_valid;
	
	TUint32 iMTU;
	
	abs_eap_am_tools_c * iTools;
};


#endif // EAP_CORE_INTERFACE_IMPLEMENTATION_H_

// End of file.
