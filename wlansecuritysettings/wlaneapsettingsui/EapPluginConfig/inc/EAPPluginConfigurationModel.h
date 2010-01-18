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
* Description: Declaration of class CEAPPluginConfigurationModel.
*
*/

/*
* %version: 12 %
*/

#ifndef __EAPPLUGINCONFIGURATIONMODEL_H__
#define __EAPPLUGINCONFIGURATIONMODEL_H__

// INCLUDES
#include <e32base.h>
#include <bamdesca.h>


// FORWARD DECLARATION
class REAPPluginList;


// CLASS DECLARATION

/**
* UI model for WPA Security Settings UI.
* This class formats real data so it can be displayed in the listbox.
*/
class CEAPPluginConfigurationModel : public CBase,
                                     public MDesCArray
    {
    public:     // Constructors and destructor
        /**
        * Constructor.
        * @param aPlugins Plugin list.
        */
        inline CEAPPluginConfigurationModel( const REAPPluginList& aPlugins );


    public:     // from MDesCArray
        /**
        * Get number of elements in the descriptor array.
        * @return The number of elements in the descriptor array.
        */
        TInt MdcaCount() const;

        /**
        * Index into the descriptor array.
        * @param aIndex Index.
        * @return Descriptor at position aIndex.
        */
        TPtrC16 MdcaPoint( TInt aIndex ) const;


    public:     // new functions
        TInt MdcaEnabledCount() const;


    private:    // types
        enum
            {
            EBufSize = 128  ///< Formatting buffer size.
            };

    private:    // data
        const REAPPluginList& iPlugins;   ///< Plugins.
        __MUTABLE TBuf<EBufSize> iBuf;    ///< Formatting buffer.

    };

#include "EAPPluginConfigurationModel.inl"

#endif  // __EAPPLUGINCONFIGURATIONMODEL_H__

//  End of File
