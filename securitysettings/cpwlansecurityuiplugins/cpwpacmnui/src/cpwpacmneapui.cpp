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
 *    Control Panel QT EAP view for WPA/WPA2/802_Dot_1x/WPA2 only configuration
 *
 */

/*
 * %version: tr1cfwln#10 %
 */

// System includes
#include <HbDataFormModelItem>


// User includes
#include "cpwpacmneapui.h"
#include "cpwpacmnui_p.h"

//Trace Definition
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cpwpacmneapuiTraces.h"
#endif

/*!
  \class  
  Implements the Ui EAP Plugin Loader for WPA/WPA2/802_Dot_1x/WPA2 only Security Modes  
 */

/*!
   Constructor
   
   @param wpa Pointer to UI object
   @param itemDataHelpper Control Panel Item data helpper object
   @param text Text for entry button
 */
EapEntryItemData::EapEntryItemData(
    CpWpaCmnUiPrivate* wpa,
    CpItemDataHelper &itemDataHelper, 
    const QString &text) :
    CpSettingFormEntryItemData(CpSettingFormEntryItemData::ButtonEntryItem, 
        itemDataHelper, text),
    mUi(wpa),
    itemdatahelper(itemDataHelper)
{
}

/*!
   Desctructor.
 */
EapEntryItemData::~EapEntryItemData()
{
    OstTraceFunctionEntry1(EAPENTRYITEMDATA_EAPENTRYITEMDATA_ENTRY,this); 
    OstTraceFunctionExit1(EAPENTRYITEMDATA_EAPENTRYITEMDATA_EXIT,this);
}

/*!
 Implement CpSettingFormEntryItemData::createSettingView
 */
CpBaseSettingView* EapEntryItemData::createSettingView() const
{
    OstTraceFunctionEntry1(EAPENTRYITEMDATA_CREATESETTING_VIEW_ENTRY,this); 
    OstTraceFunctionExit1(EAPENTRYITEMDATA_CREATESETTING_VIEW_EXIT,this);

    return mUi->eapUiInstance();
}

