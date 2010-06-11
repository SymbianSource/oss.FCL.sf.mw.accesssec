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
 *   Expanded EAP type QT data structure
 *
 */

/*
 * %version: 2 %
 */

#ifndef EAPQTEXPANDEDEAPTYPE_H
#define EAPQTEXPANDEDEAPTYPE_H

#include <QByteArray>
#include <QMetaType>
#include <eapqtconfigdefs.h>


class EapQtExpandedEapTypePrivate;

class EAP_QT_PLUGIN_INFO_EXPORT EapQtExpandedEapType
{
public:
    enum Type
    {
        TypeUndefined = 0,
        TypeEapAka,
        TypeEapFast,
        TypeEapGtc,
        TypeLeap,
        TypeEapMschapv2,
        TypePeap,
        TypeEapSim,
        TypeEapTls,
        TypeEapTtls,
        TypeProtectedSetup,
        TypePap,
        TypePlainMschapv2,
        // keep this as the last one
        TypeLast
    };

    EapQtExpandedEapType();
    EapQtExpandedEapType(const Type type);
    EapQtExpandedEapType(const QByteArray data);
    EapQtExpandedEapType(const EapQtExpandedEapType& type);
    ~EapQtExpandedEapType();

    QByteArray eapExpandedData() const;
    Type type() const;

    EapQtExpandedEapType &operator=(const EapQtExpandedEapType &type);
    bool operator ==(const EapQtExpandedEapType &right_type_value) const;
    bool operator !=(const EapQtExpandedEapType &right_type_value) const;

private:
    QScopedPointer<EapQtExpandedEapTypePrivate> d_ptr;
};

// Make the class known to QMetaType to support using QVariant
Q_DECLARE_METATYPE(EapQtExpandedEapType)

#endif /* EAPQTEXTENDEDEAPTYPE_H */
