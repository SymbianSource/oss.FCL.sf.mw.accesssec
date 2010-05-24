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

#ifndef EAPQTVALIDATOR_PACSTOREPASSWORDCONFIRM_H
#define EAPQTVALIDATOR_PACSTOREPASSWORDCONFIRM_H

#include <eapqtvalidator.h>

/*!
 * @addtogroup group_eap_config_if_impl
 * @{
 */
/*!
 */
class EapQtValidatorPacStorePasswordConfirm : public EapQtValidator
{
public:
    EapQtValidatorPacStorePasswordConfirm();
    ~EapQtValidatorPacStorePasswordConfirm();

    virtual EapQtValidator::Status validate(QVariant value);
    
    virtual void updateEditor(HbLineEdit *edit);
private:
    Q_DISABLE_COPY(EapQtValidatorPacStorePasswordConfirm)
    // TODO: handle to some object to validate password with EAP Server
};

/*! @} */

#endif

