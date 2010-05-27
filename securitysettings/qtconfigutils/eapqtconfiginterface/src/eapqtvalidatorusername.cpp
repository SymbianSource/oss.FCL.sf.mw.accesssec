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
 *   EAP method validator: username
 *
 */

/*
 * %version: 7 %
 */

#include <HbEditorInterface>
#include <HbLineEdit>

#include "eapqtvalidatorusername.h"
#include "eapqtconfiginterface_p.h"

EapQtValidatorUsername::EapQtValidatorUsername(EapQtExpandedEapType type) :
    mEapType(type)
{
}

EapQtValidatorUsername::~EapQtValidatorUsername()
{
}

EapQtValidator::Status EapQtValidatorUsername::validate(QVariant value)
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

EapQtValidator::Status EapQtValidatorUsername::validateGeneral(QVariant value)
{
    Status status(StatusOk);
    QString str = value.toString();

    // input must be of correct type
    if (value.type() != QVariant::String) {
        status = StatusInvalid;
    }
    // zero length username is ok
    else if (str.length() > EapQtConfigInterfacePrivate::StringMaxLength) {
        status = StatusTooLong;
    }
    else if (!validateCharacters(str)) {
        status = StatusInvalidCharacters;
    }

    qDebug("EapQtValidatorUsername::validateGeneral - return status: %d", status);

    return status;
}

bool EapQtValidatorUsername::validateCharacters(QString& str)
{
    bool ret(true);

    switch (mEapType.type()) {
    case EapQtExpandedEapType::TypeEapAka:
    case EapQtExpandedEapType::TypeEapFast:
    case EapQtExpandedEapType::TypeEapSim:
    case EapQtExpandedEapType::TypeEapTls:
    case EapQtExpandedEapType::TypeEapTtls:
    case EapQtExpandedEapType::TypePeap:
        // these methods have a separate UI setting for realm,
        // hence @ is not allowed in username field
        ret = !(str.contains(QChar('@'), Qt::CaseInsensitive));
        break;
    default:
        // username field can contain realm separated with @
        break;
    }

    return ret;
}

void EapQtValidatorUsername::updateEditor(HbLineEdit *edit)
{
    Q_ASSERT(edit);
    if(edit == NULL) {
        return;
    }

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

void EapQtValidatorUsername::updateEditorGeneral(HbLineEdit *edit)
{
    qDebug("EapQtValidatorUsername::updateEditorGeneral()");

    Q_ASSERT(edit);

    edit->setMaxLength(EapQtConfigInterfacePrivate::StringMaxLength);
    edit->setInputMethodHints(Qt::ImhNoAutoUppercase | Qt::ImhPreferLowercase
        | Qt::ImhNoPredictiveText);

    HbEditorInterface editInterface(edit);
    editInterface.setEditorClass(HbInputEditorClassUsername);

    HbEditorConstraints constraints = HbEditorConstraintAutoCompletingField;
    editInterface.setInputConstraints(constraints);

    // no smileys :)
    editInterface.setSmileyTheme(HbSmileyTheme());
}
