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
 *   Control Panel Inner EAP methods Entry Item for TLS-based 
 *   EAP methods 
 *
 */

/*
 * %version: 3 %
 */

// System includes
#include <HbDataFormModelItem>


// User includes
#include "cpeaptlsmethodsinnereapui.h"
#include "cpeaptlsmethodsui.h"


/*!
 * \class  EapInnerMethodEntryItemData
 * \brief  Implements Inner EAP method Entry Item
 */

// External function prototypes

// Local constants

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor
 * 
 * @param tlsUi Pointer to TLS-methods UI object
 * @param itemDataHelpper Control Panel Item data helpper object
 * @param text Text for entry button
 */
EapInnerMethodEntryItemData::EapInnerMethodEntryItemData(
    CpEapTlsMethodsUi* tlsUi, 
    CpItemDataHelper &itemDataHelper,
    const QString &text,
    bool secondInnerEap) :
        CpSettingFormEntryItemData(CpSettingFormEntryItemData::ButtonEntryItem,
            itemDataHelper, text), 
        mTlsUi(tlsUi),
        mItemDataHelper(itemDataHelper),
        mSecondInnerEap(secondInnerEap)
{
}

/*!
 * Desctructor.
 */
EapInnerMethodEntryItemData::~EapInnerMethodEntryItemData()
{
    qDebug("EapInnerMethodEntryItemData::~EapInnerMethodEntryItemData()");
}

/*!
 * Implements CpSettingFormEntryItemData::createSettingView
 */
CpBaseSettingView* EapInnerMethodEntryItemData::createSettingView() const
{
    qDebug("EapInnerMethodEntryItemData::createSettingView()");
    if (mSecondInnerEap) {
        return mTlsUi->secondInnerUiInstance();
    }
    else {
        return mTlsUi->innerUiInstance();
    }
}
