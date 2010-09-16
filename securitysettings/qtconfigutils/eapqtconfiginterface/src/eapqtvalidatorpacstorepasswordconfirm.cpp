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
 * %version: 7 %
 */

// System includes
#include <HbEditorInterface>
#include <HbLineEdit>
#include <QDebug>

// User includes
#include "eapqtvalidatorpacstorepasswordconfirm.h"
#include "eapqtconfiginterface_p.h"
#include "EapFastPacStore.h"

/*!
 *  \class EapQtValidatorPacStorePasswordConfirm
 *  \brief EAP-FAST PAC store password correctness validator, checks if the
 *         supplied password can be used for opening the existing PAC store
 */

// External function prototypes

// Local constants

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

EapQtValidatorPacStorePasswordConfirm::EapQtValidatorPacStorePasswordConfirm() :
    mPacStoreIf(NULL)
{
    qDebug("EapQtValidatorPacStorePasswordConfirm() - starts");

    // try to create PAC store instance,
    // this will throw if EAP-FAST is not supported
    CEapFastPacStore* tmpPacStoreIf = NULL;
    QT_TRAP_THROWING(tmpPacStoreIf = CEapFastPacStore::NewL());

    Q_ASSERT(tmpPacStoreIf);

    // move the result to scoped member pointer
    mPacStoreIf.reset(tmpPacStoreIf);

    qDebug("EapQtValidatorPacStorePasswordConfirm() - ends");
}

EapQtValidatorPacStorePasswordConfirm::~EapQtValidatorPacStorePasswordConfirm()
{
    qDebug("~EapQtValidatorPacStorePasswordConfirm()");
    // mPacStoreIf deleted automatically
}

EapQtValidator::Status EapQtValidatorPacStorePasswordConfirm::validate(const QVariant& value)
{
    qDebug("EapQtValidatorPacStorePasswordConfirm::validate()");

    Status status(StatusOk);
    const QString str = value.toString();

    // input must be of correct type
    if (value.type() != QVariant::String) {
        status = StatusInvalid;
    }
    else if (str.length() > EapQtConfigInterfacePrivate::PacPasswordMaxLength) {
        status = StatusTooLong;
    }
    else {
        TBool match(EFalse);
        // TBufC8 must be twice as long as QString
        TBufC8<EapQtConfigInterfacePrivate::StringMaxLength> tmpPassword;
        QByteArray tmp = str.toUtf8();

        // Convert to suitable format
        tmpPassword.Des().Copy(reinterpret_cast<const TUint8*> (tmp.data()), tmp.count());

        // check if given password can be used to open the PAC store,
        // this will fail in all other cases except if PAC store exists
        // and the password can open it
        TRAPD(err, match = mPacStoreIf->IsMasterKeyAndPasswordMatchingL(tmpPassword));

        qDebug() << "EapQtValidatorPacStorePasswordConfirm::validate() -"
            << "IsMasterKeyAndPasswordMatchingL trap returned:" << err;

        if (err == KErrNone && match != EFalse) {
            qDebug() << "EapQtValidatorPacStorePasswordConfirm::validate() - password matches";
            status = StatusOk;
        }
        else {
            qDebug()
                << "EapQtValidatorPacStorePasswordConfirm::validate() - password does not match";
            status = StatusInvalid;
        }
    }

    qDebug("EapQtValidatorPacStorePasswordConfirm::validate - return status: %d", status);
    return status;
}

void EapQtValidatorPacStorePasswordConfirm::updateEditor(HbLineEdit* const edit)
{
    qDebug("EapQtValidatorPacStorePasswordConfirm::updateEditor()");

    Q_ASSERT(edit);

    edit->setMaxLength(EapQtConfigInterfacePrivate::PacPasswordMaxLength);
    edit->setInputMethodHints(Qt::ImhNoAutoUppercase | Qt::ImhPreferLowercase
        | Qt::ImhNoPredictiveText);

    // do not set editor class or auto completing since they might leak the pwd
    HbEditorInterface editInterface(edit);
    editInterface.setSmileyTheme(HbSmileyTheme());
}
