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
 *   EAP method validator: PAC Store password
 *
 */

/*
 * %version: 4 %
 */

#ifndef EAPQTVALIDATOR_PACSTOREPASSWORD_H
#define EAPQTVALIDATOR_PACSTOREPASSWORD_H

#include <eapqtvalidator.h>

/*!
 * @addtogroup group_eap_config_if_impl
 * @{
 */
/*!
 */
class EapQtValidatorPacStorePassword : public EapQtValidator
{
public:
    EapQtValidatorPacStorePassword();
    ~EapQtValidatorPacStorePassword();

    virtual EapQtValidator::Status validate(QVariant value);
    
    virtual void updateEditor(HbLineEdit *edit);
private:
    Q_DISABLE_COPY(EapQtValidatorPacStorePassword)
    // TODO: handle to some object to validate password with EAP Server
};

/*! @} */

#endif

