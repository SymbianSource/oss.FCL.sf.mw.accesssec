/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_symbian/wapi_server/include/WapiCoreIf.inl
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 2 % << Don't touch! Updated by Synergy at check-out.
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

#include <e32base.h>
#include <ecom/ecom.h>

inline CWapiCoreIf::~CWapiCoreIf()
{
	// Unload DLL
    REComSession::DestroyedImplementation(iDtor_ID_Key);
}

inline CWapiCoreIf* CWapiCoreIf::NewL(abs_eap_am_tools_c * const tools, AbsEapSendInterface * client)
{
    RDebug::Print(_L("CWapiCoreIf::NewL(Wapi): start (tools=0x%08x, client=0x%08x)"), tools, client);

    TWapiCoreIfParameters params;
    params.iTools = tools;
    params.iClient = client;
    
    // This call finds and loads the correct DLL and after that calls the
    // entry function in the interface implementation in the DLL.
    TAny* ptr = 0;

    const TUid KimplementationUid = { 0x2002E6F0 };

    TRAPD( err, ptr = REComSession::CreateImplementationL(
            KimplementationUid,
            _FOFF(CWapiCoreIf, iDtor_ID_Key),
            (TAny*) &params));

    RDebug::Print(_L("CWapiCoreIf::NewL(Wapi): CreateImplementationL(Uid=0x%08x), err=%d, returns ptr=0x%08x\n"),
        KimplementationUid.iUid,
        err,
        ptr);


    User::LeaveIfError(err);

    return (CWapiCoreIf *) ptr;
}
