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
* Description: 
*     Impelementation of a custom resolver.
*
*/

/*
* %version: %
*/

#ifndef __EAPPLUGINRESOLVER_H__
#define __EAPPLUGINRESOLVER_H__

// INCLUDES
#include <ecom/resolver.h>


/**
 * Class:       CEapVpnInterfaceResolver
 *
 * Description: An implementation of the CResolver definition. This controls
 *              the identification, (resolution), of which implementation
 *              will be used to satisfy an interface implementation
 *              instantiation.
 */
class CEapVpnInterfaceResolver : public CResolver
	{
public:
	/**
     * Function:    NewL
     *
     * Description: Create instance of concrete implementation. The method
	 *              takes a MPublicRegistry, allowing access to a list of
	 *              implementations for a particular interface
     *
     * @param       aRegistry provides a list of implementations of a specified
	 *              interface.
     *
	 * @return      Instance of this class.
     *
     */
	static CEapVpnInterfaceResolver* NewL (MPublicRegistry& aRegistry);

	/**
     * Function:    ~CEapVpnInterfaceResolver
     *
     * Description: Destroy the object
     */ 
	virtual ~CEapVpnInterfaceResolver();

public: // CResolver
	/**
     * Function:    IdentifyImplementationL
     *
     * Description: Identifies the most appropriate implementation of a
	 *              specified interface.
	 *
	 * @param       aInterfaceUid is a unique id specific to definition
	 *              interface.
	 * @param       aAdditionalParameters The parameters which must match for an
	 *              implementation to be suitable.
	 *
	 * @return      The UID of the implementation which satisfies the
	 *              specified parameters. If there is no suitable
	 *              implementation, then KNullUid is returned.
     */
	virtual TUid IdentifyImplementationL(TUid aInterfaceUid,
		const TEComResolverParams& aAdditionalParameters) const;

	/**
     * Function:    ListAllL
     *
     * Description: Lists all the implementations of the specified interface
	 *              definition that satisfy the supplied resolution parameters.
	 *
	 * @param       aInterfaceUid The UID of the interface of which to list
	 *              implementations
	 * @param       aAdditionalParameters The parameters that must match for an
	 *              implementation to be suitable
	 *              implementation to be suitable
	 *
	 * @return      Pointer to an array of suitable implementations. Ownership
	 *              of this array is passed to the calling function, which
	 *              should close and delete the array when its use is complete
     */
	virtual RImplInfoArray* ListAllL(TUid aInterfaceUid,
		const TEComResolverParams& aAdditionalParameters) const;

private:
	/**
     * Function:   CEapVpnInterfaceResolver
     *
     * Discussion: Constructor for this object.
	 *
	 * @param      aRegistry provides a list of implementations of a specified
	 *             interface.
     */
	CEapVpnInterfaceResolver(MPublicRegistry& aRegistry);

	/**
     * Function:    Resolve
     *
     * Description: Search algorithm implemented to find the requested
	 *              interface implementation.
	 *
	 * @param       aImplementationsInfo Information on the potential
	 *              implementations
	 * @param       aAdditionalParameters The data to match against to detemine
	 *              the implementation
	 *
	 * @return      If found returns the Uid of the implementation, else it
	 *              returns KNullUid
     */
	TUid Resolve(const RImplInfoArray& aImplementationsInfo,
		const TEComResolverParams& aAdditionalParameters) const;

	/**
     * Function:    IdentifyImplementationL
     *
     * Description: Method used to find a match between two implementation
	 *              types
	 *
	 * @param       aImplementationType The implementation data type to search
	 *              for a match
	 * @param       aMatchType The data to search against
	 * @param       aUseWildcards ETrue if wildcard matching should be allowed
	 *
	 * @return      ETrue is returned if found else EFalse
     */
	TBool Match(const TDesC8& aImplementationType, const TDesC8& aMatchType,
		TBool aUseWildcards) const;
	};

#endif
