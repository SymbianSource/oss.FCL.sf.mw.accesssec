/*
* Copyright (c) 2001-2009 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: Inline functions of CEAPPluginConfigurationIf
*
*/



#ifndef __EAPPLUGINCONFIGURATIONIF_INL__
#define __EAPPLUGINCONFIGURATIONIF_INL__


// ---------------------------------------------------------
// CEAPPluginConfigurationIf::NewL
// ---------------------------------------------------------
//
inline CEAPPluginConfigurationIf* CEAPPluginConfigurationIf::NewL( 
                                                  const TDesC8& aMatchString )
	{
	TEComResolverParams resolverParams; 
	resolverParams.SetDataType(aMatchString);
	
	TAny* ptr = REComSession::CreateImplementationL( 
                            KEapPluginConfigInterfaceUid, 
                            _FOFF( CEAPPluginConfigurationIf, iDtor_ID_Key ),
                            resolverParams );

	return REINTERPRET_CAST( CEAPPluginConfigurationIf*, ptr );
    }


// ---------------------------------------------------------
// CEAPPluginConfigurationIf::~CEAPPluginConfigurationIf
// ---------------------------------------------------------
//
inline CEAPPluginConfigurationIf::~CEAPPluginConfigurationIf()
	{
	// Unload DLL
	REComSession::DestroyedImplementation( iDtor_ID_Key );
	}


#endif  // __EAPPLUGINCONFIGURATIONIF_INL__

// End of file.
