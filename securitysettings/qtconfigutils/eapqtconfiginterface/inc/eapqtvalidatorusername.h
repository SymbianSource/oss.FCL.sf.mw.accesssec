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
 *   EAP method validator: username
 *
 */

/*
 * %version: 7 %
 */

#ifndef EAPQTVALIDATORUSERNAME_H
#define EAPQTVALIDATORUSERNAME_H

// System includes
#include <eapqtvalidator.h>
#include <eapqtexpandedeaptype.h>

// User includes

// Forward declarations

// External data types

// Constants

// Class declaration
class EapQtValidatorUsername: public EapQtValidator
{

public:

    // Data types

    explicit EapQtValidatorUsername(const EapQtExpandedEapType& type);
    ~EapQtValidatorUsername();

    // from EapQtValidator
    EapQtValidator::Status validate(const QVariant& value);
    void updateEditor(HbLineEdit* const edit);

private:

    EapQtValidatorUsername();
    Q_DISABLE_COPY(EapQtValidatorUsername)

    EapQtValidator::Status validateGeneral(const QVariant& value);
    bool validateCharacters(const QString& str);
    void updateEditorGeneral(HbLineEdit* const edit);
    bool isEmptyAllowed();

private: // data

    EapQtExpandedEapType mEapType;

};

#endif // EAPQTVALIDATORUSERNAME_H
