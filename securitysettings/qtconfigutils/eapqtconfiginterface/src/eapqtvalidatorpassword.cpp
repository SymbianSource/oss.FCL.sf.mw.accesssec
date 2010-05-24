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
 *   EAP method validator: password
 *
 */

/*
 * %version: 6 %
 */

#include <HbEditorInterface>
#include <HbLineEdit>

#include "eapqtvalidatorpassword.h"
#include "eapqtconfiginterface_p.h"

EapQtValidatorPassword::EapQtValidatorPassword(EapQtExpandedEapType type) :
    mEapType(type)
{
    qDebug("EapQtValidatorPassword::EapQtValidatorPassword()");
}

EapQtValidatorPassword::~EapQtValidatorPassword()
{
    qDebug("EapQtValidatorPassword::~EapQtValidatorPassword()");
}

EapQtValidator::Status EapQtValidatorPassword::validate(QVariant value)
{
    Status status(StatusOk);

    switch (mEapType.type()) {
    case EapQtExpandedEapType::TypeEapGtc:
    case EapQtExpandedEapType::TypeEapMschapv2:
    case EapQtExpandedEapType::TypeLeap:
    case EapQtExpandedEapType::TypePap:
    case EapQtExpandedEapType::TypePlainMschapv2:
        status = validateGeneral(value);
        break;
    default:
        // for methods that do not have a password
        status = StatusInvalid;
    }

    return status;
}

EapQtValidator::Status EapQtValidatorPassword::validateGeneral(QVariant value)
{
    Status status(StatusOk);
    QString str = value.toString();

    // input must be of correct type
    if (value.type() != QVariant::String) {
        status = StatusInvalid;
    }
    // zero length password is not ok
    else if (str.length() == 0) {
        status = StatusTooShort;
    }
    // check maximum length
    else if (str.length() > EapQtConfigInterfacePrivate::StringMaxLength) {
        status = StatusTooLong;
    }

    // any character is ok for passwords
    qDebug("EapQtValidatorPassword::validateGeneral - return status: %d", status);

    return status;
}

void EapQtValidatorPassword::updateEditor(HbLineEdit *edit)
{
    switch (mEapType.type()) {
    case EapQtExpandedEapType::TypeEapGtc:
    case EapQtExpandedEapType::TypeEapMschapv2:
    case EapQtExpandedEapType::TypeLeap:
    case EapQtExpandedEapType::TypePap:
    case EapQtExpandedEapType::TypePlainMschapv2:
        updateEditorGeneral(edit);
        // falls through on purpose
    default:
        // nothing for methods that do not have a password
        break;
    }
}

void EapQtValidatorPassword::updateEditorGeneral(HbLineEdit *edit)
{
    qDebug("EapQtValidatorPassword::updateEditorGeneral()");

    edit->setMaxLength(EapQtConfigInterfacePrivate::StringMaxLength);
    edit->setInputMethodHints(Qt::ImhNoAutoUppercase | Qt::ImhPreferLowercase
        | Qt::ImhNoPredictiveText);

    // do not set editor class or auto completing since they might leak the pwd
    HbEditorInterface editInterface(edit);
    editInterface.setSmileyTheme(HbSmileyTheme());
}
