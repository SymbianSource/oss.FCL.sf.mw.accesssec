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
*   Control Panel QT UI for TLS ciphersuite configiration in EAP methods
*
*/

/*
* %version: 5 %
*/

// System includes
#include <cpsettingformitemdata.h>
#include <eapqtconfig.h>

// User includes
#include "cpeapciphersuiteui_p.h"

/*!
 * \class CpEapCiphersuiteUiPrivate
 * \brief Control Panel QT UI for TLS ciphersuite configiration in EAP methods. 
 */

// External function prototypes

// Local constants

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 */ 
CpEapCiphersuiteUiPrivate::CpEapCiphersuiteUiPrivate()
{

}

/*!
 * Destructor.
 */
CpEapCiphersuiteUiPrivate::~CpEapCiphersuiteUiPrivate()
{

}

/*!
 * Tells the caller is requested cipher suite selected
 * 
 * @param suites List of selected cipher suites
 * @param id Index of requested cipher suite
 * 
 * @return Qt::Checked if requested cipher suite is found from the list
 *         Qt::Unchecked otherwise
 */
int CpEapCiphersuiteUiPrivate::ciphersuiteSelected(QVariant suites, int id)
{
    QList<QVariant> suiteList(suites.toList());
    int ret = Qt::Unchecked;
    for (int i = 0; i < suiteList.count(); ++i) {
        
        if (suiteList.at(i).toInt() == id) {
            ret = Qt::Checked;
            break;
        }
    } 
    
    return ret;
}

/*!
 * Creates Cipher suite group item
 * 
 * @param suites List of selected cipher suites
 * @param name Localisation string of the cipher suite
 * @param id Index of the cipher suite
 * 
 * @return CpSettingFormItemData: Cipher suite check box
 */
CpSettingFormItemData* CpEapCiphersuiteUiPrivate::createGroupItem(
    QVariant &suites, QString name, int id)
{
    qDebug("CpEapCiphersuiteUiPrivate::createGroupItem - id: 0x%04x", id);
    QScopedPointer<CpSettingFormItemData> mItem;
    mItem.reset(
        new CpSettingFormItemData(
        HbDataFormModelItem::CheckBoxItem, QString("")));
        
    mItem->setContentWidgetData("objectName", name);
    mItem->setContentWidgetData("text", name);
    mItem->setContentWidgetData(
        "checkState", 
        ciphersuiteSelected(suites, id));
    mSuiteMapper[mItem.data()] = id;
    
    CpSettingFormItemData* tmp = mItem.data();
    mItem.take();
    return tmp;
}
