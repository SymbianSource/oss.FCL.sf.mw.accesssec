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
 *   EAP method validator: PAC Store password confirmation
 *
 */

/*
 * %version: 6 %
 */

#ifndef EAPQTVALIDATORPACSTOREPASSWORDCONFIRM_H
#define EAPQTVALIDATORPACSTOREPASSWORDCONFIRM_H

// System includes
#include <eapqtvalidator.h>

// User includes

// Forward declarations
class CEapFastPacStore;

// External data types

// Constants

// Class declaration
class EapQtValidatorPacStorePasswordConfirm : public EapQtValidator
{

public:

    // Data types

    EapQtValidatorPacStorePasswordConfirm();
    ~EapQtValidatorPacStorePasswordConfirm();

    virtual EapQtValidator::Status validate(const QVariant& value);
    virtual void updateEditor(HbLineEdit* const edit);
    
private:

    Q_DISABLE_COPY(EapQtValidatorPacStorePasswordConfirm)

private: // data

    QScopedPointer<CEapFastPacStore> mPacStoreIf;

};

#endif // EAPQTVALIDATORPACSTOREPASSWORDCONFIRM_H
