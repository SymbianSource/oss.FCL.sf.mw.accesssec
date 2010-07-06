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
 *   Control Panel Inner EAP Entry item for TLS-based EAP methods
 *
 */

/*
 * %version: 3 %
 */

#ifndef CPEAPTLSMETHODSINNEREAPUI_H
#define CPEAPTLSMETHODSINNEREAPUI_H

// System includes
#include <cpsettingformentryitemdata.h>

// User includes

// Forward declarations
class CpEapTlsMethodsUi;

// External data types

// Constants

/*!
 * @addtogroup group_eap_ui_plugin_eap_tlsmethods
 * @{
 */

class EapInnerMethodEntryItemData : public CpSettingFormEntryItemData
{
public:
    EapInnerMethodEntryItemData(
        CpEapTlsMethodsUi* tlsUi, 
        CpItemDataHelper &itemDataHelper,
        const QString &text);
    
    virtual ~EapInnerMethodEntryItemData();

    virtual CpBaseSettingView *createSettingView() const;

private:
    CpEapTlsMethodsUi* mTlsUi;
    CpItemDataHelper& mItemDataHelper;
};

/*! @} */

#endif
