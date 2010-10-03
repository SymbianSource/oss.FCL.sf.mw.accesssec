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
* %version: 22 %
*/

#include "EapCoreInterface.h"
#include "eap_am_tools.h"
#include "EapolUID.h"
#include "EapPluginTools.h"
#include "eap_am_message_if.h"

EAP_FUNC_EXPORT CEapCoreInterface::CEapCoreInterface(const u32_t MTU):
  iClient(NULL)
  ,iIsValid(FALSE)
  ,iTools(0)
  ,iEapCoreInterface(0)
  ,iServer(0)
  ,iMTU(MTU)
     {
     }

EAP_FUNC_EXPORT CEapCoreInterface::~CEapCoreInterface()
    {
    delete iEapCoreInterface;
    }

EAP_FUNC_EXPORT CEapProcessInterface* CEapCoreInterface::ConstrucL(abs_eap_am_tools_c * const tools)
    {
    iTools = tools;

    //TInt implementationUid( EAP_CORE_INTERFACEIMPLEMENTATION_IMPLEMENTATION_UID );

	const TUid KimplementationInterfaceUid = { EAP_CORE_INTERFACEIMPLEMENTATION_INTERFACE_UID };
		
    RImplInfoPtrArray aImplInfoArray;

	CleanupStack::PushL( TCleanupItem( EapPluginTools::CleanupImplArray, &aImplInfoArray ) );

    REComSession::ListImplementationsL(KimplementationInterfaceUid,
            aImplInfoArray);

	   	EAP_TRACE_DEBUG(
	      tools, 
	      TRACE_FLAGS_DEFAULT, 
	      (EAPL("CEapCoreInterface::ConstrucL Implementation %d\n"),aImplInfoArray[0]->ImplementationUid().iUid));

    iServer = CEapProcessInterface::NewL(
            aImplInfoArray[0]->ImplementationUid().iUid,
            this);

    EAP_TRACE_DEBUG(
      tools, 
      TRACE_FLAGS_DEFAULT, 
      (EAPL("CEapCoreInterface::ConstrucL CEapProcessInterface::NewL done\n")));

    iIsValid = TRUE;

	CleanupStack::PopAndDestroy(&aImplInfoArray);

    return iServer;
    
    }


EAP_C_FUNC_EXPORT eap_am_message_if_c * new_eap_am_client_message_if_c(
        abs_eap_am_tools_c * const tools,
        const bool /* is_client_when_true */,
        const u32_t MTU)
    {   
     CEapCoreInterface * aEapCoreInterface = 0;
     CEapProcessInterface* aServer =0;
     
	   	EAP_TRACE_DEBUG(
	      tools, 
	      TRACE_FLAGS_DEFAULT, 
	      (EAPL("new_eap_am_client_message_if_c()\n")));
	      
     aEapCoreInterface = new CEapCoreInterface(MTU);
     if (aEapCoreInterface != 0)
         {
		 TRAPD( err, aServer = aEapCoreInterface->ConstrucL(tools));
         if (err)
             {    
             	EAP_TRACE_DEBUG(
				        tools, 
				        TRACE_FLAGS_DEFAULT, 
				        (EAPL("new_eap_am_client_message_if_c() NO SERVER IF, err = %d\n"),err));

               return 0;
             }
         else if(aServer == NULL)
            {
             	EAP_TRACE_DEBUG(
				        tools, 
				        TRACE_FLAGS_DEFAULT, 
				        (EAPL("new_eap_am_client_message_if_c() SERVER IF == 0\n")));
          	}   
         else
  	       {
	    	   aServer->SetEnv(tools, MTU);
  	       }
          
         }
       else
       		{
          EAP_TRACE_DEBUG(
				        tools, 
				        TRACE_FLAGS_DEFAULT, 
				        (EAPL("new_eap_am_client_message_if_c() new(ELeave) CEapCoreInterface(MTU) failed\n")));
       	 	return 0;
					}
     return aEapCoreInterface;

    }

EAP_FUNC_EXPORT bool CEapCoreInterface::get_is_valid()
    {
    EAP_TRACE_DEBUG(
             iTools, 
             TRACE_FLAGS_DEFAULT, 
             (EAPL("CEapCoreInterface::get_is_valid() = %d\n"),iIsValid ));
      return iIsValid;
    }

EAP_FUNC_EXPORT eap_status_e CEapCoreInterface::process_data(const void * const data, const u32_t length)
    {
    EAP_TRACE_DEBUG(
            iTools, 
            TRACE_FLAGS_DEFAULT, 
            (EAPL("CEapCoreInterface::process_data()\n")));

    TInt err = iServer->ProcessData(data, length);

    return EAP_STATUS_RETURN(iTools, iTools->convert_am_error_to_eapol_error(err));
    }


EAP_FUNC_EXPORT eap_status_e CEapCoreInterface::configure(
	const eap_variable_data_c * const client_configuration)
    {
    EAP_TRACE_DEBUG(
            iTools, 
            TRACE_FLAGS_DEFAULT, 
            (EAPL("CEapCoreInterface::configure()\n")));

    TInt err = iServer->Configure(0,0,0, client_configuration->get_data(), client_configuration->get_data_length());

    return EAP_STATUS_RETURN(iTools, iTools->convert_am_error_to_eapol_error(err));
    }

// This is documented in abs_eap_stack_interface_c::shutdown().
EAP_FUNC_EXPORT eap_status_e CEapCoreInterface::shutdown()
    {
    EAP_TRACE_DEBUG(
            iTools, 
            TRACE_FLAGS_DEFAULT, 
            (EAPL("CEapCoreInterface::shutdown()\n")));

    TInt err = iServer->Shutdown();

    return EAP_STATUS_RETURN(iTools, iTools->convert_am_error_to_eapol_error(err));
    }

EAP_FUNC_EXPORT void CEapCoreInterface::set_partner(abs_eap_am_message_if_c * const client)
    {
    EAP_TRACE_DEBUG(
            iTools, 
            TRACE_FLAGS_DEFAULT, 
            (EAPL("CEapCoreInterface::set_partner()\n")));
    iClient = client;
    }

EAP_FUNC_EXPORT TInt CEapCoreInterface::SendData(
    const void * const aData, 
    const TInt aLength )
    {
    EAP_TRACE_DEBUG(
            iTools, 
            TRACE_FLAGS_DEFAULT, 
            (EAPL("CEapCoreInterface::SendData()\n")));
    if (iClient != NULL)
        {
        return iClient->send_data( aData, aLength);
        }
    else
        {
        return KErrNone;
        }
    }

