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
* Description:  Wrapper class for instantiating an implementation of
*                MWlanEapolInterface via ECom framework.
*
*/

/*
* %version: 9 %
*/

#ifndef EAP_PROCESS_INTERFACE_H
#define EAP_PROCESS_INTERFACE_H

#include <ecom/ecom.h>
#include "abs_eap_am_tools.h"
#include "EapSendInterface.h"

//const TInt KCWlanEapolClientUid = 0x2000B05C;
//const TInt KCWlanWapiClientUid = 0x200195A1;

/**
 * @brief Class for instantiating an implementation of MWlanEapolInterface 
 *
 * @since S60 v3.2
 */
class CEapProcessInterface: public CBase
    {

public:

    /**
     * Static constructor.
     * @param aUid UID of implementation to instantiate.
     * @param aPartner Pointer to callback instance.
     * @return Pointer to the constructed instance.
     */
    inline static CEapProcessInterface* NewL(
        TInt aUid,
        MEapSendInterface* aPartner);

    /**
     * Destructor.
     */
    inline virtual ~CEapProcessInterface();


		virtual TInt SetEnv(abs_eap_am_tools_c * const tools, const u32_t MTU) = 0;

    /**
      * Configure plugin implementation.
      *
      * @since S60 v3.2
      * @param aHeaderOffset Offset of EAP-header in packet_send.
      * @param aMTU Maximum transfer unit (MTU).
      * @param aTrailerLength Length of trailer needed by lower levels..
      * @return Return value is specified in interface specification.
      */
	virtual TInt Configure(
		const TInt aHeaderOffset,
		const TInt aMTU,
		const TInt aTrailerLength,
		const void * const aConfigurationData,
		const TInt aConfigurationDataLength
		) = 0;

     /**
      * Shutdown plugin implementation.
      *
      * @since S60 v3.2
      * @return Return value is specified in interface specification.
      */        
     virtual TInt Shutdown() = 0;

     /**
      * Send data to EAPOL.
      *
      * @since S60 v3.2
      * @param aData Pointer to the data to be sent.
      * @param aLength Length of the data to be sent.
      * @return Return value is specified in interface specification.
      */
     virtual TInt ProcessData(
         const void * const aData, 
         const TInt aLength ) = 0;

  private: // data

     /**
      * Identifies the instance of an implementation created by
      * the ECOM framework.
      */
     TUid iInstanceIdentifier;

    };

#include "EapProcessInterface.inl"

#endif // EAP_PROCESS_INTERFACE_H
