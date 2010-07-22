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
 *    Control Panel WLAN Security EAP Entry item for WPA(2)/802.1x
 *
 */

/*
 * %version: tr1cfwln#8 %
 */

#ifndef CPWPACMNEAPUI_H_
#define CPWPACMNEAPUI_H_

// System includes
#include <cpsettingformentryitemdata.h>

// User includes

// Forward declarations
class CpWpaCmnUiPrivate;

class EapEntryItemData : public CpSettingFormEntryItemData
{
public:
    EapEntryItemData(
        CpWpaCmnUiPrivate* wpa, 
        CpItemDataHelper &itemDataHelper,
        const QString &text = QString());

    virtual ~EapEntryItemData();

    virtual CpBaseSettingView *createSettingView() const;

private:
    //! Pointer to WPA/WPA2/802.1x UI. 
    CpWpaCmnUiPrivate* mUi;
    // Dataitem helpper
    CpItemDataHelper& itemdatahelper;
};

#endif /* CPWPACMNEAPUI_H_ */
