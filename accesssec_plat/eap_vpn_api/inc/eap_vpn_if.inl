/*
* Copyright (c) 2005 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: EAP and WLAN authentication protocols.
*
*/

/*
* %version: 10.1.2 %
*/

// Interface's (abstract base class's) static factory method implementation.
// Asks ECOM plugin framework to instantiate appropriate concret plugin
// implementation.
inline CEapVpnInterface* CEapVpnInterface::NewL(MAbsEapVpnInterface* aCaller, TBool aClient)
	{
    // Parameters for the implementation 
    TAbsEapVpnInterfaceParams params;
    params.iCaller = aCaller;
    params.iClient = aClient;
	// Find implementation for our interface.
    // - KCEapVpnInterfaceUid is the UID of our custom ECOM
    //   interface.
    // - This call will leave, if the plugin architecture cannot find
    //   implementation.
    // - The returned pointer points to one of our interface implementation
    //   instances.
	TAny* interface = REComSession::CreateImplementationL (
		KCEapVpnInterfaceImplementationUid, _FOFF (CEapVpnInterface, iDtor_ID_Key), (TAny*) &params);

	return reinterpret_cast <CEapVpnInterface*> (interface);
	}

// Interface's (abstract base class's) static factory method implementation.
// Asks ECOM plugin framework to instantiate appropriate concret plugin
// implementation.
    inline CEapVpnInterface* CEapVpnInterface::NewL(const TDesC8& aType, MAbsEapVpnInterface* aCaller, TBool aClient)
        {
        TEComResolverParams resolverParams;
        // Only one interface type
        // Remove these lines and uncomment line resolverParams.SetDataType (aType);
        // if you really have many possible intance types
        // ---------------------------------------
        (void) aType;
        _LIT8 (KEapPluginText,"EAPVPNIF");
        resolverParams.SetDataType (KEapPluginText);
        // ---------------------------------------
        // +++++++++++++++++++++++++++++++++++++++
        //resolverParams.SetDataType (aType);
        // +++++++++++++++++++++++++++++++++++++++
        resolverParams.SetWildcardMatch (ETrue);

    // Parameters for the implementation 
        TAbsEapVpnInterfaceParams params;
        params.iCaller = aCaller;
        params.iClient = aClient;
    // Find implementation for our interface.
    // - KCEapVpnInterfaceUid is the UID of our custom ECOM
    //   interface. It is defined in EComInterfaceDefinition.h
    // - This call will leave, if the plugin architecture cannot find
    //   implementation.
    // - The returned pointer points to one of our interface implementation
    //   instances.
        TAny* interface = REComSession::CreateImplementationL (KCEapVpnInterfaceUid,
            _FOFF (CEapVpnInterface, iDtor_ID_Key), (TAny*) &params, resolverParams, KCEapVpnInterfaceResolverUid);

        return reinterpret_cast <CEapVpnInterface*> (interface);
        }

// Interface's (abstract base class's) destructor
inline CEapVpnInterface::~CEapVpnInterface()
	{
	// If in the NewL some memory is reserved for member data, it must be
	// released here. This interface does not have any instance variables so
	// no need to delete anything.

	// Inform the ECOM framework that this specific instance of the
    // interface has been destroyed.
	REComSession::DestroyedImplementation (iDtor_ID_Key);
	}   

// Interface's (abstract base class's) constructor
inline CEapVpnInterface::CEapVpnInterface()
: CActive(CActive::EPriorityStandard)
    {
    iDtor_ID_Key.Uid(0);
    }

// End
