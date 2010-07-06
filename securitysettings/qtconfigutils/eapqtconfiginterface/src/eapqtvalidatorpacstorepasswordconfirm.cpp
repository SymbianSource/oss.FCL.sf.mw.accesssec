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
 *   EAP-FAST PAC store password correctness validator
 *
 */

/*
 * %version: 5 %
 */

// System includes
#include <HbEditorInterface>
#include <HbLineEdit>

// User includes
#include "eapqtvalidatorpacstorepasswordconfirm.h"
#include "eapqtconfiginterface_p.h"

/*!
 *  \class EapQtValidatorPacStorePasswordConfirm
 *  \brief EAP-FAST PAC store password correctness validator, checks if the
 *         supplied password can be used for opening the existing PAC store
 */

// External function prototypes

// Local constants

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

EapQtValidatorPacStorePasswordConfirm::EapQtValidatorPacStorePasswordConfirm()
{
    // nothing to do
}

EapQtValidatorPacStorePasswordConfirm::~EapQtValidatorPacStorePasswordConfirm()
{
    // nothing to do
}

EapQtValidator::Status EapQtValidatorPacStorePasswordConfirm::validate(const QVariant& /* value */)
{
    qDebug("EapQtValidatorPacStorePasswordConfirm::validate()");
    // not supported
    return EapQtValidator::StatusInvalid;
}

void EapQtValidatorPacStorePasswordConfirm::updateEditor(HbLineEdit* const edit)
{
    qDebug("EapQtValidatorPacStorePasswordConfirm::updateEditor()");

    Q_ASSERT(edit);

    edit->setMaxLength(EapQtConfigInterfacePrivate::StringMaxLength);
    edit->setInputMethodHints(Qt::ImhNoAutoUppercase | Qt::ImhPreferLowercase
        | Qt::ImhNoPredictiveText);

    // do not set editor class or auto completing since they might leak the pwd
    HbEditorInterface editInterface(edit);
    editInterface.setSmileyTheme(HbSmileyTheme());
}
