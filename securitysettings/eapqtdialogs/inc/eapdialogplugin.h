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
* Description: Eap Dialog Plugin
*
*/

/*
* %version: 4 %
*/

#ifndef ____EAPDIALOG_H__PLUGIN_H__
#define ____EAPDIALOG_H__PLUGIN_H__

// System includes
#include <QObject>
#include <hbdevicedialogplugin.h>

// User includes

// Forward declarations

// External data types

// Constants

/*!
   @addtogroup group_eap_dialog_plugin
   @{
 */

// Class declaration

class EapDialogPlugin : public HbDeviceDialogPlugin
{
    Q_OBJECT

public:
    
    /* Constructor */
    EapDialogPlugin();
    /* Destructor */
    ~EapDialogPlugin();
    
    /* Check whether access is allowed, true is always returned. 
       (from HbDeviceDialogPlugin) */
    bool accessAllowed(const QString &deviceDialogType,
        const QVariantMap &parameters, const QVariantMap &securityInfo) const;
    
    /* Creates the dialog widget. (from HbDeviceDialogPluginInterface) */
    HbDeviceDialogInterface *createDeviceDialog(const QString &deviceDialogType,
        const QVariantMap &parameters);
    
    /* Returns the device dialog type. (from HbDeviceDialogPlugin)*/
    bool deviceDialogInfo(const QString &deviceDialogType,
        const QVariantMap &parameters, DeviceDialogInfo *info) const;
    
    /* Returns a list of dialog types that this plugin implements.
     * Only one dialog type is supported. (from HbDeviceDialogPlugin)
     */
    QStringList deviceDialogTypes() const;
    
    /* Returns the possible plugin flags, there are none. 
       (from HbDeviceDialogPlugin) */
    PluginFlags pluginFlags() const;
    
    /* Not supported. (from HbDeviceDialogPlugin)*/
    int error() const;

private:
    Q_DISABLE_COPY(EapDialogPlugin)

};

/*! @} */

#endif // ___EAPDIALOG_H__
