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
 *   EAP UI plugin handle
 *
 */

/*
 * %version: 7 %
 */

#ifndef EAPQTPLUGINHANDLE_H
#define EAPQTPLUGINHANDLE_H

// System includes
#include <qglobal.h>
#include <QMetaType>
#include <eapqtconfigexport.h>

// User includes

// Forward declarations
class EapQtExpandedEapType;
class EapQtPluginHandlePrivate;

// External data types

// Constants

// Class declaration
class EAP_QT_PLUGIN_INFO_EXPORT EapQtPluginHandle
{

public:
    
    // Data types

    enum Plugin
    {
        PluginUndefined = 0,
        PluginEapAka,
        PluginEapFast,
        PluginEapGtc,
        PluginLeap,
        PluginEapMschapv2,
        PluginPeap,
        PluginEapSim,
        PluginEapTls,
        PluginEapTtls,
        PluginPap,
        PluginPlainMschapv2,
        PluginLast
    };

    // default constructor
    EapQtPluginHandle();

    // constructs an instance from an EapQtPluginHandle::Plugin value
    EapQtPluginHandle(const Plugin id);

    // constructs an instance from an EapQtExpandedEapType object,
    // maps the supplied type to UIDs of default EAP protocol implementations
    EapQtPluginHandle(const EapQtExpandedEapType &type);

    // copy constructor
    EapQtPluginHandle(const EapQtPluginHandle &handle);

    // constructs an instance from an EapQtExpandedEapType object and
    // supplied EAP protocol implementation UID
    EapQtPluginHandle(const EapQtExpandedEapType &type, int uid);

    // destructor
    ~EapQtPluginHandle();

    // returns EapQtExpandedEapType of the handle instance
    EapQtExpandedEapType type() const;

    // returns EAP protocol implementation UID of the handle instance
    int protocolImplementationUid() const;

    // returns EapQtPluginHandle::Plugin of the handle instance
    Plugin pluginId() const;

    // assignment
    EapQtPluginHandle &operator=(const EapQtPluginHandle &handle);

    // comparisons
    bool operator ==(const EapQtPluginHandle &right_type_value) const;
    bool operator !=(const EapQtPluginHandle &right_type_value) const;

private: // data

    QScopedPointer<EapQtPluginHandlePrivate> d_ptr;

};

// Make the class known to QMetaType to support using QVariant
Q_DECLARE_METATYPE(EapQtPluginHandle)

#endif // EAPQTPLUGINHANDLE_H
