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
 * %version: 6 %
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

EapQtValidator::Status EapQtValidatorPacStorePassword::validate(const QVariant& /* value */)
{
    qDebug("EapQtValidatorPacStorePassword::validate()");
    // not supported
    return EapQtValidator::StatusInvalidCharacters;
}

void EapQtValidatorPacStorePassword::updateEditor(HbLineEdit* const edit)
{
    qDebug("EapQtValidatorPacStorePassword::updateEditor()");

    Q_ASSERT(edit);

    edit->setMaxLength(EapQtConfigInterfacePrivate::StringMaxLength);
    edit->setInputMethodHints(Qt::ImhNoAutoUppercase | Qt::ImhPreferLowercase
        | Qt::ImhNoPredictiveText);

    // do not set editor class or auto completing since they might leak the pwd
    HbEditorInterface editInterface(edit);
    editInterface.setSmileyTheme(HbSmileyTheme());
}
