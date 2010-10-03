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
* %version: 23 %
*/

// INCLUDES
#include <e32std.h>
#include <implementationproxy.h>
#include "EapCoreInterfaceImplementation.h"
#include "EapolUID.h"
#include "EapTraceSymbian.h"
//-----------------------------------------------------------------------------------------

/**
 * Pairs ECom implementation UIDs with a pointer to the instantiation 
 * method for that implementation. Required for all ECom implementation
 * collections.
 */
const TImplementationProxy ImplementationTable[] =
{
    {{ EAP_CORE_INTERFACEIMPLEMENTATION_IMPLEMENTATION_UID }, reinterpret_cast<TProxyNewLPtr>(CEapCoreInterfaceImplementation::NewL)}
};

//-----------------------------------------------------------------------------------------

/**
 * Static constructor.
 * @param aPartner Pointer to callback instance.
 * @return Pointer to the constructed instance.
 */
CEapProcessInterface* CEapCoreInterfaceImplementation::NewL(MEapSendInterface * aPartner)
    {
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapCoreInterfaceImplementation::NewL")));  

    CEapCoreInterfaceImplementation* self = new (ELeave) CEapCoreInterfaceImplementation();
	
	CleanupStack::PushL(self);

	self->ConstructL(aPartner);

	if (self->get_is_valid() != true)
	{
		User::Leave(KErrGeneral);
	}

	CleanupStack::Pop(self);

    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapCoreInterfaceImplementation::NewL end")));  
	return self;
    }

//-----------------------------------------------------------------------------------------

/**
 * C++ default constructor.
*/ 
CEapCoreInterfaceImplementation::CEapCoreInterfaceImplementation()
	{
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapCoreInterfaceImplementation::CEapCoreInterfaceImplementation")));  
	m_partner = 0;
	m_is_valid = false;
	iMTU = 0;
	iTools = 0;
	}

//-----------------------------------------------------------------------------------------

/**
 * Destructor.
 */
CEapCoreInterfaceImplementation::~CEapCoreInterfaceImplementation()
    {
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapCoreInterfaceImplementation::~CEapCoreInterfaceImplementation")));  
	m_partner = 0;
	iTools = 0;
	iMTU = 0;
//	iSession.Close();
    }

//-----------------------------------------------------------------------------------------
TInt CEapCoreInterfaceImplementation::SetEnv(abs_eap_am_tools_c * const tools, const u32_t MTU)
    {
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapCoreInterfaceImplementation::SetEnv")));  
	iTools = tools;
	iMTU = MTU;
	return KErrNone;
    }

/**
 * Configure plugin implementation.
 *
 * @since S60 v3.2
 * @param aHeaderOffset Offset of EAP-header in packet_send.
 * @param aMTU Maximum transfer unit (MTU).
 * @param aTrailerLength Length of trailer needed by lower levels..
 * @return Return value is specified in interface specification.
 */
TInt CEapCoreInterfaceImplementation::Configure(
	const TInt /* aHeaderOffset */,
	const TInt /* aMTU */,
	const TInt /* aTrailerLength */,
	const void * const aConfigurationData,
	const TInt aConfigurationDataLength)
	{
	EAP_TRACE_DEBUG_SYMBIAN(
	(_L("CEapCoreInterfaceImplementation::Configure")));  

	TBuf<KMaxServerExe> ServerName;
	TBuf<KMaxServerExe> ServerExe;

	GetServerNameAndExe(&ServerName, &ServerExe);

	TRAPD(err, iSession.ConnectL(iTools, this, ServerName, ServerExe, aConfigurationData, aConfigurationDataLength, EEapCoreIfNew));

	if(err)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapCoreInterfaceImplementation::Configure - iSession.ConnectL err=%d\n"), err ));
		return err;
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapCoreInterfaceImplementation::Configure end")));

	return err;
	}

//-----------------------------------------------------------------------------------------

/**
 * Shutdown plugin implementation.
 *
 * @since S60 v3.2
 * @return Return value is specified in interface specification.
 */        
TInt CEapCoreInterfaceImplementation::Shutdown()
    {
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapCoreInterfaceImplementation::Shutdown")));  
    iSession.Close();

	return 0;
    }

//-----------------------------------------------------------------------------------------

/**
 * Send data to EAPOL.
 *
 * @since S60 v3.2
 * @param aData Pointer to the data to be sent.
 * @param aLength Length of the data to be sent.
 * @return Return value is specified in interface specification.
 */
TInt CEapCoreInterfaceImplementation::ProcessData(
        const void * const aData, 
        const TInt aLength )
    {
    EAP_TRACE_DEBUG(
            iTools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("CEapCoreInterfaceImplementation::ProcessData()\n")));

	EAP_TRACE_DATA_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapCoreInterfaceImplementation::ProcessData()"),
		aData,
		aLength));

    return iSession.process_data(EEapCoreProcessData, aData, aLength);
    }

//-----------------------------------------------------------------------------------------

/**
 * Symbian 2nd phase constructor.
 */
void CEapCoreInterfaceImplementation::ConstructL(MEapSendInterface * aPartner)
    {
	m_partner = aPartner;
	m_is_valid = true;
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapCoreInterfaceImplementation::ConstructL")));  
	
//    RWapiSession session;
//    __UHEAP_MARK;
//    CTestPacketHandler* tph = new (ELeave) CTestPacketHandler;
//    CleanupStack::PushL( tph );

//    CleanupStack::Pop( tph );
    
//    delete tph;

    }

//-----------------------------------------------------------------------------------------

bool CEapCoreInterfaceImplementation::get_is_valid()
    {
    EAP_TRACE_DEBUG_SYMBIAN(
      (_L("CEapCoreInterfaceImplementation::get_is_valid = %d"),m_is_valid ));  
    
	return m_is_valid;
    }

//-----------------------------------------------------------------------------------------

/// Function sends the data message to lower layer.
/// Data is formatted to Attribute-Value Pairs.
/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
eap_status_e CEapCoreInterfaceImplementation::send_data(const TDesC8& message)
    {
    EAP_TRACE_DEBUG(
            iTools,
        TRACE_FLAGS_DEFAULT,
    (EAPL("CEapCoreInterfaceImplementation::send_data \n")));

	return EAP_STATUS_RETURN(iTools, iTools->convert_am_error_to_eapol_error(
		m_partner->SendData(
            message.Ptr(), 
            message.Length())));
    }

//-----------------------------------------------------------------------------------------

// ======== GLOBAL FUNCTIONS ========

// ---------------------------------------------------------
// Returns an instance of the proxy table.
// Returns: KErrNone
// ---------------------------------------------------------
//
EXPORT_C const TImplementationProxy* ImplementationGroupProxy( TInt& aTableCount )
    {
    EAP_TRACE_DEBUG_SYMBIAN(
            (_L("TImplementationProxy* ImplementationGroupProxy")));  

    aTableCount = sizeof( ImplementationTable) / sizeof( TImplementationProxy );
    return ImplementationTable;
    }

//-----------------------------------------------------------------------------------------

// End of file.

