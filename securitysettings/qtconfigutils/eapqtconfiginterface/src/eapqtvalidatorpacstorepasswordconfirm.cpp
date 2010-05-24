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
 *   EAP method validator: PAC Store password confirmation
 *
 */

/*
 * %version: 3 %
 */

#include <HbEditorInterface>
#include <HbLineEdit>
#include "eapqtvalidatorpacstorepasswordconfirm.h"

EapQtValidatorPacStorePasswordConfirm::EapQtValidatorPacStorePasswordConfirm()
{
}

EapQtValidatorPacStorePasswordConfirm::~EapQtValidatorPacStorePasswordConfirm()
{
}

EapQtValidator::Status EapQtValidatorPacStorePasswordConfirm::validate(QVariant value)
{
    // TODO: implement this
    if (value == QVariant("1234")){
        return EapQtValidator::StatusOk;
    }
    return EapQtValidator::StatusInvalid;
}

void EapQtValidatorPacStorePasswordConfirm::updateEditor(HbLineEdit *edit)
{
    HbEditorInterface editInterface(edit);
    editInterface.setInputConstraints(HbEditorConstraintLatinAlphabetOnly);
    edit->setInputMethodHints(Qt::ImhNoPredictiveText | Qt::ImhPreferLowercase);
    // TODO:
    edit->setMaxLength(1000);
}
