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
* Description: Standard enrty point for a DLL.
*
*/

/*
* %version: %
*/

// INCLUDE FILES
#include <ecom/ecom.h>
#include <ecom/ecomerrorcodes.h>
#include <ecom/ecomresolverparams.h>
#include <ecom/implementationinformation.h>
#include <ecom/publicregistry.h>

#include "eap_vpn_if_resolver.h"

/// Creates an instance of CEapVpnInterfaceResolver
CEapVpnInterfaceResolver* CEapVpnInterfaceResolver::NewL (MPublicRegistry& aRegistry)
	{
	return new(ELeave) CEapVpnInterfaceResolver (aRegistry);
	}

// Destructor.
CEapVpnInterfaceResolver::~CEapVpnInterfaceResolver()
	{
	}

/// Constructor of CEapVpnInterfaceResolver
CEapVpnInterfaceResolver::CEapVpnInterfaceResolver (MPublicRegistry& aRegistry) :
	CResolver (aRegistry)
	{
	}

/// This method determines if it can find an appriate implementation
/// requested
TUid CEapVpnInterfaceResolver::IdentifyImplementationL(TUid aInterfaceUid,
	const TEComResolverParams& aAdditionalParameters) const
	{
	// Aquire a list of implementations for a specific implementation defintion
	RImplInfoArray& implementationsInfo = iRegistry.ListImplementationsL (
		aInterfaceUid);
	TUid found = KNullUid;

	if (implementationsInfo.Count())
		{
		found = Resolve (implementationsInfo, aAdditionalParameters);
		}
	return found;
	}

/// This method iterates through a list of RImplInfoArray() objects to
/// find the most appropriate implementation.
TUid CEapVpnInterfaceResolver::Resolve(const RImplInfoArray& aImplementationsInfo,
	const TEComResolverParams& aAdditionalParameters) const
	{
	const TInt count = aImplementationsInfo.Count();
	for (TInt i = 0; i < count; ++i)
		{
		const CImplementationInformation& impData = *aImplementationsInfo[i];

		// Checks each item in the list to see if theres a match.
		if (Match (impData.DataType(), aAdditionalParameters.DataType(),
			aAdditionalParameters.IsWildcardMatch()))
			{
			// Returns the Uid of the interface
			return impData.ImplementationUid();
			}
		}

	// Nothing found
	return KNullUid;
	}

/// Lists all the implementations of the specified interface definition that
/// satisfy the supplied resolution parameters.
RImplInfoArray* CEapVpnInterfaceResolver::ListAllL(TUid aInterfaceUid,
	const TEComResolverParams& aAdditionalParameters) const
	{
	RImplInfoArray* retList = new(ELeave) RImplInfoArray;
	CleanupStack::PushL (retList);

	RImplInfoArray& fullList = iRegistry.ListImplementationsL (aInterfaceUid);

	const TBool useWildcards = aAdditionalParameters.IsWildcardMatch();
	const TDesC8& matchType = aAdditionalParameters.DataType();
	const TInt numImps = fullList.Count();

	// Iterates through each item in the list to determine the correct
	// interfaces to select.
	for (TInt i = 0; i < numImps; ++i)
		{
		if (Match (fullList[i]->DataType(), matchType, useWildcards))
			{
			// Adds interface to the list.
			User::LeaveIfError (retList->Append (fullList[i]));
			}
		}

	CleanupStack::Pop (retList);

	return retList;
	}

/// The first two parameters is used for comparaison between the two interfaces
/// and the third parameter is used to determine the use of wild cards or not.
TBool CEapVpnInterfaceResolver::Match(const TDesC8& aImplementationType,
	const TDesC8& aMatchType, TBool aUseWildcards) const
	{
	TInt matchPos = KErrNotFound;

	// If wild cards have been set, it will use the correct method to determine
	// the correct interface.
	if (aUseWildcards)
			matchPos = aImplementationType.MatchF (aMatchType);
	else
			matchPos = aImplementationType.CompareF (aMatchType);

	return matchPos != KErrNotFound;
	}

