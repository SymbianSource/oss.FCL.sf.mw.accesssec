/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
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
 *    Control Panel QT EAP view for WPA/WPA2/802_Dot_1x/WPA2 only configuration
 *
 */

/*
 * %version: 4 %
 */

#ifndef CPWPACMNEAPUI_H_
#define CPWPACMNEAPUI_H_

class CpWpaCmnUi;
#include <cpsettingformentryitemdata.h>
/*! 
 * Implements the Ui EAP Plugin Loader for WPA/WPA2/802_Dot_1x/WPA2 only Security Modes  
 */
class EapEntyItemData : public CpSettingFormEntryItemData
{
public:
    EapEntyItemData(CpWpaCmnUi* wpa, CpItemDataHelper &itemDataHelper,
            const QString &text = QString(), const QString &description =
                    QString(), const HbIcon &icon = HbIcon(),
            const HbDataFormModelItem *parent = 0);

    virtual ~EapEntyItemData();

    /*!
     Implement CpSettingFormEntryItemData::createSettingView
     */
    virtual CpBaseSettingView *createSettingView() const;

private:

    CpWpaCmnUi* mUi;
    CpItemDataHelper& itemdatahelper;
};

#endif /* CPWPACMNEAPUI_H_ */
