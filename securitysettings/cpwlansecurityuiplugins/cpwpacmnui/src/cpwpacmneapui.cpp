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

#include "cpwpacmneapui.h"
#include "cpwpacmnui.h"

#include <HbDataFormModelItem>
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cpwpacmneapuiTraces.h"
#endif

EapEntyItemData::EapEntyItemData(CpWpaCmnUi* wpa,
        CpItemDataHelper &itemDataHelper, const QString &text,
        const QString &description, const HbIcon &icon,
        const HbDataFormModelItem *parent) :
    CpSettingFormEntryItemData(itemDataHelper, text, description, icon,
            parent),itemdatahelper(itemDataHelper)
{
    mUi = wpa;

}

EapEntyItemData::~EapEntyItemData()
{
    OstTraceFunctionEntry1(EAPENTRYITEMDATA_EAPENTRYITEMDATA_ENTRY,this); 
    OstTraceFunctionExit1(EAPENTRYITEMDATA_EAPENTRYITEMDATA_EXIT,this);
}

/*!
 Implement CpSettingFormEntryItemData::createSettingView
 */
CpBaseSettingView* EapEntyItemData::createSettingView() const
{
    OstTraceFunctionEntry1(EAPENTRYITEMDATA_CREATESETTING_VIEW_ENTRY,this); 
    OstTraceFunctionExit1(EAPENTRYITEMDATA_CREATESETTING_VIEW_EXIT,this);

    return mUi->eapUiInstance();
}

