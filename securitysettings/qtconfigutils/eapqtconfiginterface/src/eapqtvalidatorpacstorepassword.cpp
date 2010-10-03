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
 *   EAP-FAST PAC store password format validator
 *
 */

/*
 * %version: 8 %
 */

// System includes
#include <HbEditorInterface>
#include <HbLineEdit>

// User includes
#include "eapqtvalidatorpacstorepassword.h"
#include "eapqtconfiginterface_p.h"

/*!
 *  \class EapQtValidatorPacStorePassword
 *  \brief EAP-FAST PAC store password format validator
 */

// External function prototypes

// Local constants
static const unsigned int MinPacStorePasswordSize = 6;

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

EapQtValidatorPacStorePassword::EapQtValidatorPacStorePassword()
{
    // nothing to do
}

EapQtValidatorPacStorePassword::~EapQtValidatorPacStorePassword()
{
    // nothing to do
}

EapQtValidator::Status EapQtValidatorPacStorePassword::validate(const QVariant& value)
{
    Status status(StatusOk);
    const QString str = value.toString();

    // input must be of correct type
    if (value.type() != QVariant::String) {
        status = StatusInvalid;
    }
    // check minimum length
    else if (str.length() < MinPacStorePasswordSize) {
        status = StatusTooShort;
    }
    // check maximum length
    else if (str.length() > EapQtConfigInterfacePrivate::PacPasswordMaxLength) {
        status = StatusTooLong;
    }

    // any character is ok for passwords
    qDebug("EapQtValidatorPacStorePassword::validate - return status: %d", status);

    return status;
}

void EapQtValidatorPacStorePassword::updateEditor(HbLineEdit* const edit)
{
    qDebug("EapQtValidatorPacStorePassword::updateEditor()");

    Q_ASSERT(edit);

    edit->setMaxLength(EapQtConfigInterfacePrivate::PacPasswordMaxLength);
    edit->setInputMethodHints(Qt::ImhNoAutoUppercase | Qt::ImhPreferLowercase
        | Qt::ImhNoPredictiveText);

    // do not set editor class or auto completing since they might leak the pwd
    HbEditorInterface editInterface(edit);
    editInterface.setSmileyTheme(HbSmileyTheme());
}
