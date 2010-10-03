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
 *   EAP-FAST PAC store configuration data
 *
 */

/*
 * %version: 7 %
 */

#ifndef EAPQTPACSTORECONFIG_H
#define EAPQTPACSTORECONFIG_H

// System includes
#include <QVariant>
#include <eapqtconfigexport.h>

// User includes

// Forward declarations
class EapQtPacStoreConfigPrivate;

// External data types

// Constants

// Class declaration
class EAP_QT_CONFIG_INTERFACE_EXPORT EapQtPacStoreConfig
{

public:

    // PAC store is global, i.e. only a single PAC store exists in a device

    // Data types

    enum PacStoreStatus
    {
        // PAC store does not exist and needs to be created
        // (status also reverts to PacStoreStateStoreNotExists if the PAC store is
        // corrupted, i.e. it gets deleted automatically)
        PacStoreStateStoreNotExists = 0,
        // PAC store exists but the password has not been stored and
        // is needed to access the PAC store
        PacStoreStatePasswordRequired,
        // PAC store password has been stored to settings database
        // and is not needed to use the PAC store
        PacStoreStatePasswordStored,
        // marker for the last item
        PacStoreStateLast
    };

    enum PacStoreSettings
    {
        /*! write-only: QString
         *      password to be used for accessing the PAC store
         *      - must be new password if the read PacStoreState is PacStoreStateStoreNotExists
         *      - must be password of the existing PAC store if the PacStoreState state is
         *        PacStoreStatePasswordRequired */
        PacStorePassword = 0,
        /*! write-only: bool
         *      true: saves the password given in settings
         *      false: clears the earlier stored password from database, i.e. password
         *        will be prompted when needed, PAC store itself remains valid
         *      QVariant::Invalid: no actions */
        PacStoreSavePassword,
        /*! write-only: bool
         *      true: deletes PAC store, i.e. clears everything related to the
         *        existing PAC store including saved password
         *      false/QVariant::Invalid: no actions */
        PacStoreReset,
        /*! read-only: int (PacStoreStatus) */
        PacStoreState,
        /*! no write nor read operation, for validator usage only
         *  - uses the validator to check if the given password
         *      can open the existing PAC store */
        PacStorePasswordConfirmation,
        // marker for the last item
        PacStoreLast
    };

    // default constructor
    EapQtPacStoreConfig();
    // destructor
    ~EapQtPacStoreConfig();

    // gets the configuration field referred to by an id from PacStoreSettings
    // returns QVariant::Invalid is the field has not been set
    QVariant value(const PacStoreSettings id) const;

    // sets the configuration field referred to by an id from PacStoreSettings
    // does nothing if newValue >= PacStoreLast
    void setValue(const PacStoreSettings id, const QVariant &newValue) const;

    // resets the object i.e. any successive call to
    // value() returns QVariant::Invalid
    void clear() const;

private:

    Q_DISABLE_COPY(EapQtPacStoreConfig)

private: // data

    QScopedPointer<EapQtPacStoreConfigPrivate> d_ptr;

};

#endif // EAPQTPACSTORECONFIG_H
