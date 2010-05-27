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
 * %version: 5 %
 */

#ifndef EAPQTVALIDATOR_USERNAME_H
#define EAPQTVALIDATOR_USERNAME_H

#include <eapqtvalidator.h>
#include <eapqtexpandedeaptype.h>

/*!
 * @addtogroup group_eap_config_if_impl
 * @{
 */
/*!
 */
class EapQtValidatorUsername: public EapQtValidator
{
public:

    explicit EapQtValidatorUsername(EapQtExpandedEapType type);
    ~EapQtValidatorUsername();

    // from EapQtValidator
    EapQtValidator::Status validate(QVariant value);
    void updateEditor(HbLineEdit *edit);

private:

    EapQtValidatorUsername();
    Q_DISABLE_COPY(EapQtValidatorUsername)

    EapQtValidator::Status validateGeneral(QVariant value);
    bool validateCharacters(QString& str);
    void updateEditorGeneral(HbLineEdit *edit);

private:
    EapQtExpandedEapType mEapType;

};

/*! @} */

#endif

