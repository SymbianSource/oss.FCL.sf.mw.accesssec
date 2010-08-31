/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
 * All rights reserved.
 * This component and the accompanying materials are made available
 * under the terms of "Eclipse Public License v1.0"
 * which accompanies this distribution, and is available
 * at the URL "http://www.eclipse.org/legal/epl-v10.html".
 *
 * Initial Contributors:
 * Nokia Corporation - initial contribution.
 *
 * Contributors:
 *
 * Description: 
 *    Control Panel QT UI for WPA/WPA2/802_Dot_1x configuration
 *
 */

/*
 * %version: tr1cfwln#15 %
 */

#ifndef CPWPACMNUI_H
#define CPWPACMNUI_H

// System includes
#include <cmmanagerdefines_shim.h>

// User includes
#include "cpwpacmnui_global.h"

// Forward Declarations
class CpItemDataHelper;
class CpSettingFormItemData;
class EapQtConfigInterface;
class CpWpaCmnUiPrivate;

/*! 
 * Implements the Ui for WPA/WPA2/802.1x Security Mode  
 */

// Class declaration
class WPAUI_EXPORT CpWpaCmnUi
{
    public:
    
        CpWpaCmnUi(CMManagerShim::WlanSecMode securityMode, CpItemDataHelper &dataHelpper);
        ~CpWpaCmnUi();

        CpSettingFormItemData* createUi(
                EapQtConfigInterface *mEapQtConfigInterface,
                CmConnectionMethodShim *cmCM);

        bool validateSettings();
    
    private:
        
        Q_DISABLE_COPY(CpWpaCmnUi)
        
        // Pointer to Private Implementation
        CpWpaCmnUiPrivate* d_ptr;
 
};



#endif//CPWPACMNUI_H
