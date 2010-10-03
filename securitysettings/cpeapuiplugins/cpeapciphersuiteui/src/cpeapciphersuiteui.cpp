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
* %version: 9 %
*/

// System includes
#include <qlist.h>
#include <eapqtconfig.h>

// User includes
#include "cpeapciphersuiteui.h"
#include "cpeapciphersuiteui_p.h"
#include "eapuidefs.h"

/*!
 * \class CpEapCiphersuiteUi
 * \brief Control Panel QT UI for TLS ciphersuite configiration in EAP methods. 
 */

// External function prototypes

// Local constants

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

/*!
 * Constructor.
 * 
 * @param suites List of selected cipher suites
 */ 
CpEapCiphersuiteUi::CpEapCiphersuiteUi( QVariant &suites ) :
    CpSettingFormItemData(HbDataFormModelItem::GroupItem, hbTrId(
        "txt_occ_subhead_cipher_suites"))
{ 
    qDebug("CpEapCiphersuiteUi::CpEapCiphersuiteUi()");
    d_ptr.reset(new CpEapCiphersuiteUiPrivate());

    setContentWidgetData("objectName", "CpEapCipherSuiteUi");
    
    appendChild(d_ptr->createGroupItem(
        suites, 
        EapQtUiConstants::EapCipher_RSA_AES_SHA,
        EapQtConfig::TLS_RSA_WITH_AES_128_CBC_SHA));

    appendChild(d_ptr->createGroupItem(
        suites, 
        EapQtUiConstants::EapCipher_DHE_RSA_AES_SHA,
        EapQtConfig::TLS_DHE_RSA_WITH_AES_128_CBC_SHA));

    appendChild(d_ptr->createGroupItem(
        suites, 
        EapQtUiConstants::EapCipher_DHE_DSS_AES_SHA,
        EapQtConfig::TLS_DHE_DSS_WITH_AES_128_CBC_SHA));

    appendChild(d_ptr->createGroupItem(
        suites, 
        EapQtUiConstants::EapCipher_RSA_3DES_SHA,
        EapQtConfig::TLS_RSA_WITH_3DES_EDE_CBC_SHA));

    appendChild(d_ptr->createGroupItem(
        suites, 
        EapQtUiConstants::EapCipher_DHE_RSA_3DES_SHA,
        EapQtConfig::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA));

    appendChild(d_ptr->createGroupItem(
        suites, 
        EapQtUiConstants::EapCipher_DHE_DSS_3DES_SHA,
        EapQtConfig::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA));

    appendChild(d_ptr->createGroupItem(
        suites, 
        EapQtUiConstants::EapCipher_RSA_RC4_MD5,
        EapQtConfig::TLS_RSA_WITH_RC4_128_MD5));

    appendChild(d_ptr->createGroupItem(
        suites, 
        EapQtUiConstants::EapCipher_RSA_RC4_SHA,
        EapQtConfig::TLS_RSA_WITH_RC4_128_SHA));
    
    qDebug("CpEapCiphersuiteUi::CpEapCiphersuiteUi() - complete");
}

/*!
 * Destructor.
 */
CpEapCiphersuiteUi::~CpEapCiphersuiteUi()
{

}

/*!
 * Creates list of selected cipher suites
 * 
 * @return List of selected cipher suites
 */
QVariant CpEapCiphersuiteUi::ciphersuites()
{ 
    QList<QVariant> suites;

    for (int i = 0; i < childCount(); ++i) {
        QVariant state(childAt(i)->contentWidgetData("checkState"));
        if (state.toInt() == Qt::Checked) {
            qDebug("Cipher suite selected: 0x%04x", d_ptr->mSuiteMapper[childAt(i)]);
            suites.append(QVariant(d_ptr->mSuiteMapper[childAt(i)]));           
        }
        else {
            qDebug("Cipher suite not selected: 0x%04x", d_ptr->mSuiteMapper[childAt(i)]);
        }
    }
    
    return QVariant(suites);
}
