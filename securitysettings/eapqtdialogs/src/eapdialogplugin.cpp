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
* Description: Eap Dialog Plugin implementation
*
*/

/*
* %version: 8 %
*/

#include <hbdevicedialoginterface.h>
#include <QVariantMap>
#include "eapdialogplugin.h"
#include "eapusernamepwddialog.h"
#include "eapquerydialog.h"
#include "eappasswordquerydialog.h"
#include "eapfastinstallpacquerydialog.h"
#include "eapfastpacstorepwquerydialog.h"
#include "eapfastpacfilepwquerydialog.h"
#include "eapfastcreatemasterkeyquerydialog.h"
#include "eapfastprovwaitnotedialog.h"
#include "eapmschapv2pwdexpirednotedialog.h"
#include "eapmschapv2oldpwddialog.h"
#include "eapmschapv2newpwddialog.h"
#include "eapfastprovnotsuccessnotedialog.h"
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#endif


Q_EXPORT_PLUGIN2(eapdialogplugin, EapDialogPlugin)


// This plugin implements one device dialog type
static const struct {
    const char *mTypeString;
} dialogInfos[] = {
    {"com.nokia.eap.usernamepassworddialog/1.0"},
    {"com.nokia.eap.querydialog/1.0"},
    {"com.nokia.eap.passwordquerydialog/1.0"},
    {"com.nokia.eap.fastinstallpacquerydialog/1.0"},
    {"com.nokia.eap.fastpacstorepwquerydialog/1.0"},
    {"com.nokia.eap.fastcreatemasterkeyquerydialog/1.0"},
    {"com.nokia.eap.fastpacfilepwquerydialog/1.0"},
    {"com.nokia.eap.fastprovwaitnotedialog/1.0"},
    {"com.nokia.eap.mschapv2passwordexpirednotedialog/1.0"},
    {"com.nokia.eap.mschapv2oldpassworddialog/1.0"},
    {"com.nokia.eap.mschapv2newpassworddialog/1.0"},
    {"com.nokia.eap.fastshowprovnotsuccessnotedialog/1.0"}
};

/**
 * Constructor
 */ 
EapDialogPlugin::EapDialogPlugin()
{
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_EAPDIALOGPLUGIN_ENTRY );
    qDebug("EapDialogPlugin::EapDialogPlugin");
        
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_EAPDIALOGPLUGIN_EXIT );
}

/**
 * Destructor
 */ 
EapDialogPlugin::~EapDialogPlugin()
{
    OstTraceFunctionEntry0( DUP1_EAPDIALOGPLUGIN_DEAPDIALOGPLUGIN_ENTRY );
      
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_DEAPDIALOGPLUGIN_EXIT );
}

/**
 * Create device dialog widget
 */ 
HbDeviceDialogInterface *EapDialogPlugin::createDeviceDialog(
    const QString &deviceDialogType,
    const QVariantMap &parameters)
{  
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_CREATEDEVICEDIALOG_ENTRY );
    qDebug("EapDialogPlugin::createDeviceDialog ENTER");
        
    if ( deviceDialogType.compare("com.nokia.eap.usernamepassworddialog/1.0") == 0 ) 
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapUsernamePwdDialog");
        return ( new EapUsernamePwdDialog(parameters) );
        }
    else if ( deviceDialogType.compare("com.nokia.eap.querydialog/1.0") == 0 ) 
        { 
        qDebug("EapDialogPlugin::createDeviceDialog: new EapQueryDialog");
        return ( new EapQueryDialog(parameters) );
        }
    else if ( deviceDialogType.compare("com.nokia.eap.passwordquerydialog/1.0") == 0 ) 
        { 
        qDebug("EapDialogPlugin::createDeviceDialog: new EapPasswordQueryDialog");
        return ( new EapPasswordQueryDialog(parameters) );
        }
    else if ( deviceDialogType.compare("com.nokia.eap.fastinstallpacquerydialog/1.0") == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapFastInstallPacQueryDialog");
        return ( new EapFastInstallPacQueryDialog(parameters) );
        }
    else if ( deviceDialogType.compare("com.nokia.eap.fastpacstorepwquerydialog/1.0") == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapFastPacStorePwQueryDialog");
        return ( new EapFastPacStorePwQueryDialog(parameters));
        }   
    else if ( deviceDialogType.compare("com.nokia.eap.fastcreatemasterkeyquerydialog/1.0") == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapFastCreateMasterKeyQueryDialog");
        return ( new EapFastCreateMasterKeyQueryDialog(parameters) );
        }  
    else if ( deviceDialogType.compare("com.nokia.eap.fastpacfilepwquerydialog/1.0") == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapFastPacFilePwQueryDialog");
        return ( new EapFastPacFilePwQueryDialog(parameters) );
        }
    else if ( deviceDialogType.compare("com.nokia.eap.fastprovwaitnotedialog/1.0") == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapFastProvWaitNoteDialog");
        return ( new EapFastProvWaitNoteDialog(parameters) );
        }  
    else if ( deviceDialogType.compare("com.nokia.eap.mschapv2passwordexpirednotedialog/1.0") == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapMschapv2PwdExpNoteDialog");
        return ( new EapMschapv2PwdExpNoteDialog(parameters) );
        }  
    else if ( deviceDialogType.compare("com.nokia.eap.mschapv2oldpassworddialog/1.0") == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapMschapv2OldPwdDialog");
        return ( new EapMschapv2OldPwdDialog(parameters) );
        }  
    else if ( deviceDialogType.compare("com.nokia.eap.mschapv2newpassworddialog/1.0") == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapMschapv2NewPwdDialog");
        return ( new EapMschapv2NewPwdDialog(parameters) );
        }  
    else if ( deviceDialogType.compare("com.nokia.eap.fastshowprovnotsuccessnotedialog/1.0") == 0 )
        {
        qDebug("EapDialogPlugin::createDeviceDialog: new EapFastProvNotSuccessNoteDialog");
        return ( new EapFastProvNotSuccessNoteDialog(parameters) );
        }   
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_CREATEDEVICEDIALOG_EXIT );
    qDebug("EapDialogPlugin::createDeviceDialog EXIT");
    
    return NULL;
}

/**
 * Check if client is allowed to use device dialog widget
 */
bool EapDialogPlugin::accessAllowed(const QString &deviceDialogType,
    const QVariantMap &parameters, const QVariantMap &securityInfo) const
{
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_ACCESSALLOWED_ENTRY );
    
    Q_UNUSED(deviceDialogType)
    Q_UNUSED(parameters)
    Q_UNUSED(securityInfo)

    // This plugin doesn't perform operations that may compromise security.
    // All clients are allowed to use.
    return true;
}

/**
 * Return information of device dialog the plugin creates
 */ 
bool EapDialogPlugin::deviceDialogInfo(const QString &deviceDialogType,
    const QVariantMap &parameters, DeviceDialogInfo *info) const
{
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_DEVICEDIALOGINFO_ENTRY );
    qDebug("EapDialogPlugin::deviceDialogInfo");
    
    Q_UNUSED(parameters)
    Q_UNUSED(deviceDialogType)
    
    info->group = GenericDeviceDialogGroup;
    info->flags = NoDeviceDialogFlags;
    info->priority = DefaultPriority;
    
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_DEVICEDIALOGINFO_EXIT );
    qDebug("EapDialogPlugin::deviceDialogInfo EXIT");
    return true;
}

/**
 * Return device dialog types this plugin implements
 */ 
QStringList EapDialogPlugin::deviceDialogTypes() const
{
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_DEVICEDIALOGTYPES_ENTRY );
    qDebug("EapDialogPlugin::deviceDialogTypes");
    
    QStringList types;
    const int numTypes = sizeof(dialogInfos) / sizeof(dialogInfos[0]);
    for(int i = 0; i < numTypes; i++) {
        types.append(dialogInfos[i].mTypeString);
    }
    
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_DEVICEDIALOGTYPES_EXIT );
    return types;
}

/**
 * Return plugin flags
 */ 
EapDialogPlugin::PluginFlags EapDialogPlugin::pluginFlags() const
{
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_PLUGINFLAGS_ENTRY );   
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_PLUGINFLAGS_EXIT );
    return NoPluginFlags;
}

/**
 * The last error is not stored, not supported
 */ 
int EapDialogPlugin::error() const
{
    OstTraceFunctionEntry0( EAPDIALOGPLUGIN_ERROR_ENTRY );
    OstTraceFunctionExit0( EAPDIALOGPLUGIN_ERROR_EXIT );
    return 0;
}

