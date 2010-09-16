/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_symbian/wapi_server/include/WapiCoreIf.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 3 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2010 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.2
*/

#ifndef WAPICOREIF_H_
#define WAPICOREIF_H_

#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "eap_tools.h"
#include "AbsEapSendInterface.h"
//#include "wapi_security_settings_server_message_if.h"

//class eap_file_config_c;

//--------------------------------------------------

//--------------------------------------------------

/** @file */

class TWapiCoreIfParameters
{
    public:
        abs_eap_am_tools_c * iTools;
        AbsEapSendInterface * iClient;
};


/// This class is the common part of EAP message interface.
/// This class is interface to the message creation and parsing function.
class CWapiCoreIf
: public CBase
, public abs_eap_am_message_if_c
{
public:

    // ----------------------------------------------------------------------

    inline static CWapiCoreIf* NewL(
            abs_eap_am_tools_c * const tools,
            AbsEapSendInterface * client);

    virtual ~CWapiCoreIf();

    //bool get_is_valid();

    //eap_status_e configure(
	//	const eap_variable_data_c * const client_configuration);

    virtual eap_status_e send_data(const void * const data, const u32_t length) = 0;

    virtual eap_status_e process_data(const void * const data, const u32_t length) = 0;

    //eap_status_e shutdown();

    // ------------------------------------------------------

private:

    // ----------------------------------------------------------------------

	/// ECom uses this key to keep track of DLL usage.
		TUid iDtor_ID_Key;

    // ----------------------------------------------------------------------

    // ----------------------------------------------------------------------
};

#include "WapiCoreIf.inl"

#endif /* WAPICOREIF_H_ */
