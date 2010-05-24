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
 *   PAC store configuration data
 *
 */

/*
 * %version: 1 %
 */

#ifndef EAPQTPACSTORECONFIG_H
#define EAPQTPACSTORECONFIG_H

#include <QList>
#include <QVariant>

#ifdef BUILD_EAP_QT_CONFIG_INTERFACE_DLL
#define EAP_QT_CONFIG_EXPORT Q_DECL_EXPORT
#else
#define EAP_QT_CONFIG_EXPORT Q_DECL_IMPORT
#endif

class EapQtPacStoreConfigPrivate;

class EAP_QT_CONFIG_EXPORT EapQtPacStoreConfig
{
public:

    enum PacStoreState {
        PacStoreStateNotExists = 0,
        PacStoreStatePasswordConfirmationRequired,
        PacStoreStateConfirmed,
    };

    enum PacStoreSettings {
        /*! TODO: PAC Store API, see EapFastPacStore.h */
        /*! write-only: QString, sets the state to PacStoreStateConfirmed */
        PacStorePassword,
        /*! write-only: invalid QVariant */
        PacStoreReset,
        /*! read-only: int (PacStoreState) */
        PacStoreState,
        /*! no write nor read operation. for validator only */
        PacStorePasswordConfirmation,
    };

public:
    EapQtPacStoreConfig();
    ~EapQtPacStoreConfig();

    QVariant value(PacStoreSettings id);
    void setValue(PacStoreSettings id, QVariant newValue);
    void clear();

private:
    Q_DISABLE_COPY(EapQtPacStoreConfig)
    QScopedPointer<EapQtPacStoreConfigPrivate> d_ptr;
};

#endif
