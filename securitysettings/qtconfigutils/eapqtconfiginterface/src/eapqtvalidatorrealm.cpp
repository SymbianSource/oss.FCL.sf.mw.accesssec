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
 *   EAP method validator: realm
 *
 */

/*
 * %version: 5 %
 */

#include <HbEditorInterface>
#include <HbLineEdit>

#include "eapqtvalidatorrealm.h"
#include "eapqtconfiginterface_p.h"

EapQtValidatorRealm::EapQtValidatorRealm(EapQtExpandedEapType type) :
    mEapType(type)
{
}

EapQtValidatorRealm::~EapQtValidatorRealm()
{
}

EapQtValidator::Status EapQtValidatorRealm::validate(QVariant value)
{
    Status status(StatusOk);

    switch (mEapType.type()) {
    case EapQtExpandedEapType::TypeEapAka:
    case EapQtExpandedEapType::TypeEapFast:
    case EapQtExpandedEapType::TypeEapGtc:
    case EapQtExpandedEapType::TypeEapMschapv2:
    case EapQtExpandedEapType::TypeEapSim:
    case EapQtExpandedEapType::TypeEapTls:
    case EapQtExpandedEapType::TypeEapTtls:
    case EapQtExpandedEapType::TypeLeap:
    case EapQtExpandedEapType::TypePeap:
        status = validateGeneral(value);
        break;
    default:
        // for methods that do not have a realm
        status = StatusInvalid;
    }

    return status;
}

EapQtValidator::Status EapQtValidatorRealm::validateGeneral(QVariant value)
{
    Status status(StatusOk);
    QString str = value.toString();

    // input must be of correct type
    if (value.type() != QVariant::String) {
        status = StatusInvalid;
    }
    // zero length realm is ok
    else if (str.length() > EapQtConfigInterfacePrivate::StringMaxLength) {
        status = StatusTooLong;
    }
    // username and realm are separated with @, not allowed to be part of realm
    else if (str.contains(QChar('@'), Qt::CaseInsensitive)) {
        status = StatusInvalidCharacters;
    }

    qDebug("EapQtValidatorRealm::validateGeneral - return status: %d", status);

    return status;
}

void EapQtValidatorRealm::updateEditor(HbLineEdit *edit)
{
    switch (mEapType.type()) {
    case EapQtExpandedEapType::TypeEapAka:
    case EapQtExpandedEapType::TypeEapFast:
    case EapQtExpandedEapType::TypeEapGtc:
    case EapQtExpandedEapType::TypeEapMschapv2:
    case EapQtExpandedEapType::TypeEapSim:
    case EapQtExpandedEapType::TypeEapTls:
    case EapQtExpandedEapType::TypeEapTtls:
    case EapQtExpandedEapType::TypeLeap:
    case EapQtExpandedEapType::TypePeap:
        updateEditorGeneral(edit);
        // falls through on purpose
    default:
        // no realm for other types
        break;
    }
}

void EapQtValidatorRealm::updateEditorGeneral(HbLineEdit *edit)
{
    qDebug("EapQtValidatorRealm::updateEditorGeneral()");

    edit->setMaxLength(EapQtConfigInterfacePrivate::StringMaxLength);
    edit->setInputMethodHints(Qt::ImhNoAutoUppercase | Qt::ImhPreferLowercase
        | Qt::ImhNoPredictiveText);

    HbEditorInterface editInterface(edit);
    editInterface.setEditorClass(HbInputEditorClassNetworkDomain);

    HbEditorConstraints constraints = HbEditorConstraintAutoCompletingField;
    editInterface.setInputConstraints(constraints);

    // no smileys :)
    editInterface.setSmileyTheme(HbSmileyTheme());
}
