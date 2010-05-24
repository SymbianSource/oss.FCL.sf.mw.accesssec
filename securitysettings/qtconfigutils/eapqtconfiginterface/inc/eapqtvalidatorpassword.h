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
 * %version: 3 %
 */

#ifndef EAPQTVALIDATOR_PASSWORD_H
#define EAPQTVALIDATOR_PASSWORD_H

#include <eapqtvalidator.h>
#include <eapqtexpandedeaptype.h>

/*!
 * @addtogroup group_eap_config_if_impl
 * @{
 */
/*!
 */
class EapQtValidatorPassword : public EapQtValidator
{
public:

    EapQtValidatorPassword(EapQtExpandedEapType type);
    ~EapQtValidatorPassword();

    // from EapQtValidator
    EapQtValidator::Status validate(QVariant value);
    void updateEditor(HbLineEdit *edit);

private:

    EapQtValidatorPassword();
    Q_DISABLE_COPY(EapQtValidatorPassword)

    EapQtValidator::Status validateGeneral(QVariant value);
    void updateEditorGeneral(HbLineEdit *edit);

private:
    EapQtExpandedEapType mEapType;

};

/*! @} */

#endif

