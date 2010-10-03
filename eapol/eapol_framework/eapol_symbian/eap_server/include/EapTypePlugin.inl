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
* %version: 7 %
*/

/* The meaning and bit positions used in "opaque_data" field in ECOM implementation

 0 0 0 0 0 0 0 0 ---->All 0 means allowed both inside (encapsulated EAP) and outside (Outer EAP)
 | | | | | | | |
 | | | | | | | |_____ 1 means NOT_INSIDE_TUNNEL (NOT allowed as encapsulated EAP)
 | | | | | | |
 | | | | | | |_______ 1 means NOT_OUTSIDE_TUNNEL (only allowed as encapsulated EAP, NOT as outer EAP)
 | | | | | |  
 | | | | | |_________ 1 means NOT_INSIDE_PEAP
 | | | | |  
 | | | | |___________ 1 means NOT_OUTSIDE_PEAP  
 | | | | 
 | | | |_____________ 1 means NOT_INSIDE_TTLS
 | | | 
 | | |_______________ 1 means NOT_OUTSIDE_TTLS
 | | 
 | |_________________ 1 means NOT_INSIDE_FAST
 |
 |___________________ 1 means NOT_OUTSIDE_FAST
 
 
 // For historical reasons NOT_OUTSIDE_PEAP is used instead of NOT_OUTSIDE_TUNNEL
 // Both of these convey the same meaning. It means if an EAP is not allowed outside PEAP
 // (DisallowedOutsidePEAP), it can be used only as an encapsulated EAP.
 // EAP-MSCHAPv2 is an example for this.

 // The bits can be ORed. 
 // "NOT_OUTSIDE|NOT_OUTSIDE_PEAP" is 0x0A (0000 1010).
 // "NOT_OUTSIDE|NOT_OUTSIDE_PEAP|NOT_INSIDE_PEAP|NOT_INSIDE_FAST" is 0x4E (0100 1110).
 // "NOT_INSIDE|NOT_INSIDE_PEAP|NOT_INSIDE_TTLS|NOT_INSIDE_FAST" is 0x55 (0101 0101).
 // "NOT_INSIDE|NOT_INSIDE_PEAP|NOT_INSIDE_TTLS|NOT_INSIDE_FAST|NOT_OUTSIDE_PEAP|NOT_OUTSIDE" is 0x5F (0101 1111).
 
*/

#include "EapTraceSymbian.h"


const TUint8 KNotInsideTunnel = 0x01; // Only the last bit position is 1. 		(0000 0001)
const TUint8 KNotOutsideTunnel = 0x02; // Only the 2nd last bit positions is 1. (0000 0010)

const TUint8 KNotInsidePEAP = 0x04; // Only the 3rd last bit position is 1. 	(0000 0100)
const TUint8 KNotOutsidePEAP = 0x08; // Only the 4th last bit positions is 1. 	(0000 1000)

const TUint8 KNotInsideTTLS = 0x10; // Only the 5th last bit position is 1. 	(0001 0000)
const TUint8 KNotOutsideTTLS = 0x20; // Only the 6th last bit position is 1. 	(0010 0000)

const TUint8 KNotInsideFAST = 0x40; // Only the 7th last bit position is 1. 	(0100 0000)
const TUint8 KNotOutsideFAST = 0x80;  // Only the first bit position is 1. 		(1000 0000)

// Used By Server
inline CEapTypePlugin* CEapTypePlugin::NewL(const TDesC8& aCue, TIndexType aIndexType, TInt aIndex, abs_eap_am_tools_c * const aTools)
{
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTypePlugin::NewL(): start")));

	// The EAP type id (aCue) is passed to ECom as resolver parameters
    TEComResolverParams resolverParams;
    resolverParams.SetDataType(aCue);
	
	// The arguments are stored to a iapInfo struct.
	SPluginInfo iapInfo;
	iapInfo.indexType = aIndexType;
	iapInfo.index = aIndex;
	iapInfo.aEapType = aCue;
	iapInfo.aTools = aTools;

	EAP_TRACE_DATA_DEBUG_SYMBIAN(("CEapTypePlugin::NewL(): resolverParams.DataType()",
		resolverParams.DataType().Ptr(),
		resolverParams.DataType().Size()));

    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTypePlugin::NewL(): iapInfo.aEapType=0xfe%06x%08x\n"),
		iapInfo.aEapType.GetVendorId(),
		iapInfo.aEapType.GetVendorType()));

	// This call finds and loads the correct DLL and after that calls the
	// entry function in the interface implementation in the DLL.
	TAny* ptr = 0;

    TRAPD( err, ptr = REComSession::CreateImplementationL(
        KEapTypeInterfaceUid,
        _FOFF(CEapTypePlugin, iDtor_ID_Key), 
		&iapInfo,
        resolverParams));

    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTypePlugin::NewL(): ends, err=%d, returns ptr=0x%08x\n"),
		err,
		ptr));

	User::LeaveIfError(err);

    return (CEapTypePlugin *) ptr;
}

inline CEapTypePlugin::~CEapTypePlugin()
{
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTypePlugin::~CEapTypePlugin(): this=0x%08x"),
		this));

	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTypePlugin::~CEapTypePlugin()"));

	// Unload DLL
    REComSession::DestroyedImplementation(iDtor_ID_Key);
}

inline TBool CEapTypePlugin::IsDisallowedOutsidePEAP(const CImplementationInformation& aImplInfo)
{
	
	const TUint8 pluginOpaqueData = *(aImplInfo.OpaqueData().Ptr());
	
	if(pluginOpaqueData & KNotOutsidePEAP)
	{
		return ETrue;
	}
	return EFalse;
	
}

inline TBool CEapTypePlugin::IsDisallowedInsidePEAP(const CImplementationInformation& aImplInfo)
{
	const TUint8 pluginOpaqueData = *(aImplInfo.OpaqueData().Ptr());
	
	if(pluginOpaqueData & KNotInsidePEAP)
	{
		return ETrue;
	}
	return EFalse;

}

inline TBool CEapTypePlugin::IsDisallowedInsideTTLS(const CImplementationInformation& aImplInfo)
{
	const TUint8 pluginOpaqueData = *(aImplInfo.OpaqueData().Ptr());
	
	if(pluginOpaqueData & KNotInsideTTLS)
	{
		return ETrue;
	}
	return EFalse;
}

// End of file
