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
 *   Control Panel EAP plugin information
 *
 */

/*
 * %version: 3 %
 */

#ifndef EAPQTPLUGINHANDLE_H
#define EAPQTPLUGINHANDLE_H

#include <qglobal.h>
#include <QMetaType>

#ifdef BUILD_EAP_QT_PLUGIN_INFO_DLL
#define EAP_QT_PLUGIN_HANDLE_EXPORT Q_DECL_EXPORT
#else
#define EAP_QT_PLUGIN_HANDLE_EXPORT Q_DECL_IMPORT
#endif

class EapQtExpandedEapType;
class EapQtPluginHandlePrivate;

class EAP_QT_PLUGIN_HANDLE_EXPORT EapQtPluginHandle
{
public:
    
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

public:

    EapQtPluginHandle();
    EapQtPluginHandle(Plugin id);
    EapQtPluginHandle(EapQtExpandedEapType type); // maps type to default UIDs
    EapQtPluginHandle(EapQtExpandedEapType type, int uid);
    EapQtPluginHandle(const EapQtPluginHandle& handle);
    ~EapQtPluginHandle();

    EapQtExpandedEapType type() const;
    int protocolImplementationUid() const;
    Plugin pluginId() const;

    EapQtPluginHandle &operator=(const EapQtPluginHandle &handle);
    bool operator ==(const EapQtPluginHandle &right_type_value) const;

private:

    QScopedPointer<EapQtPluginHandlePrivate> d_ptr;

};

// Make the class known to QMetaType to support using QVariant
Q_DECLARE_METATYPE(EapQtPluginHandle)

#endif /* EAPQTPLUGINHANDLE_H */
