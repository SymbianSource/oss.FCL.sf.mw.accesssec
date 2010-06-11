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
 *   EAP QT configuration validator interface
 *
 */

/*
 * %version: 2 %
 */

#ifndef EAPQTVALIDATOR_H
#define EAPQTVALIDATOR_H

#include <QVariant>
#include <eapqtconfigdefs.h>

/*!
 * @addtogroup group_eap_config_api
 * @{
 */

class HbLineEdit;

/*!
 * Eap Qt Validator interface. This interface provides a method to configure
 * the editor to use required constraints, hints, editor classes and so one
 * depending on the EAP type and the configuration identifier.
 * See updateEditor() method for further details.
 * 
 * Another important method of this class is the validate() method. With
 * that method you can check that the content and format is valid for 
 * given configuration compination.
 * 
 * An instance of validator can be created with 
 * EapQtConfigInterface::validatorEap() method.
 */

class EAP_QT_CONFIG_INTERFACE_EXPORT EapQtValidator
{
public:

    /*!
     * Validation status.
     */
    enum Status {
        /// Ok
        StatusOk,
        /// Content is invalid
        StatusInvalid,
        /// The length is not valid
        StatusInvalidLength,
        /// Invalid characters detected
        StatusInvalidCharacters,
        /// Input is too short
        StatusTooShort, 
        /// Input is too long
        StatusTooLong,  
    };
    
public:

    EapQtValidator() {};
    virtual ~EapQtValidator() {};

    /*!
     * Processes validation to the given input \a value.
     *
     * @param value Value to be validated
     * 
     * @return Status code.
     * 
     * - EapQtConfig::Username: All values 
     * - EapQtConfig::Password: All values
     * - EapQtConfig::Realm: All values
     * - EapQtConfig::ServerName: All values
     * - EapQtConfig::PacStorePassword: All values  
     * - EapQtConfig::PacStorePasswordConfirmation: StatusOk and StatusInvalid
     */
    virtual Status validate(QVariant value) = 0;
   
    /*!
     * Sets required configurations to the lineedit such as:
     * - Constraints
     * - HbInputFilter
     * - HbValidator
     * - inputMethodsHints
     * - maximum length
     * - predictive input mode
     * - number/text mode
     * 
     * Configurations depends on the Expanded EAP type and the configuration id
     * which were used to instantiate the validator.
     * 
     * @param edit LineEdit to be updated.
     */
    virtual void updateEditor(HbLineEdit* edit) = 0;
    
private:

    Q_DISABLE_COPY(EapQtValidator)
};

/*! @} */

#endif
